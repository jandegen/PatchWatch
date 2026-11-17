# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from patchwatch import __version__
from patchwatch.agent.profile import PROFILE_TEMPLATE, initialize_profile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("packaging_build", ROOT / "packaging" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class VersionAndProfile(unittest.TestCase):
    def test_package_version_matches_project_version(self):
        declared = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
        self.assertEqual(declared, __version__)

    def test_example_profile_is_the_template(self):
        self.assertEqual(json.loads((ROOT / "agent/agent.example.json").read_text()), PROFILE_TEMPLATE)

    def test_service_units_start_the_packaged_launcher(self):
        self.assertIn("ExecStart=/usr/bin/patchwatch-agent --config /etc/patchwatch/agent.json",
                      (ROOT / "agent/systemd/patchwatch-agent.service").read_text())
        self.assertIn("/usr/local/bin/patchwatch-agent", (ROOT / "agent/launchd/eu.patchwatch.agent.plist").read_text())

    def test_init_profile_generates_identity_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "etc" / "agent.json"
            self.assertTrue(initialize_profile(path, syft="/opt/syft", host_name="Build-Host"))
            profile = json.loads(path.read_text())
            self.assertEqual((profile["hostname"], profile["syft"]), ("build-host", "/opt/syft"))
            self.assertNotEqual(profile["host_id"], PROFILE_TEMPLATE["host_id"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(initialize_profile(path))  # never overwritten
            self.assertEqual(json.loads(path.read_text()), profile)


class Artifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        cls.out = Path(cls.folder.name)
        cls.pyz = build.build_pyz(cls.out / build.PYZ_NAME)

    def test_zipapp_contains_only_agent_and_core(self):
        with zipfile.ZipFile(self.pyz) as archive:
            names = archive.namelist()
        self.assertIn("patchwatch/agent/cli.py", names)
        self.assertIn("patchwatch/core/sbom.py", names)
        for name in names:
            self.assertRegex(name, r"^(__main__\.py|LICENSE|patchwatch/(__init__\.py|agent/|core/))")

    def test_zipapp_runs_without_the_source_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder) / "agent.json"
            run = subprocess.run([sys.executable, "-I", str(self.pyz), "--init-config", "--config", str(profile)],
                                 cwd=folder, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue(profile.exists())
            failing = subprocess.run([sys.executable, "-I", str(self.pyz), "--config", str(Path(folder) / "missing.json")],
                                     cwd=folder, capture_output=True, text=True)
            self.assertEqual(failing.returncode, 1)
            self.assertIn("Agent failed: FileNotFoundError", failing.stderr)

    def test_build_is_reproducible(self):
        again = build.build_pyz(self.out / "again" / build.PYZ_NAME)
        self.assertEqual(again.read_bytes(), self.pyz.read_bytes())

    @staticmethod
    def members(deb):
        """The members of the ``ar`` container of a .deb file by name."""
        members, data, position = {}, deb.read_bytes(), 8
        assert data.startswith(b"!<arch>\n")
        while position < len(data):
            name = data[position:position + 16].decode().strip()
            size = int(data[position + 48:position + 58])
            members[name] = data[position + 60:position + 60 + size]
            position += 60 + size + size % 2
        return members

    def test_deb_layout(self):
        deb = build.build_deb(self.out, self.pyz)
        self.assertEqual(deb.name, f"patchwatch-agent_{__version__}_all.deb")
        members = self.members(deb)
        self.assertEqual(list(members), ["debian-binary", "control.tar.gz", "data.tar.gz"])
        with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"])) as archive:
            files = {m.name: m for m in archive if m.isfile()}
        for expected in ("./usr/bin/patchwatch-agent", "./usr/lib/patchwatch/patchwatch-agent.pyz",
                         "./usr/lib/systemd/system/patchwatch-agent.service",
                         "./usr/lib/systemd/system/patchwatch-agent.timer"):
            self.assertIn(expected, files)
        self.assertEqual(files["./usr/bin/patchwatch-agent"].mode, 0o755)
        with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"])) as archive:
            control = archive.extractfile("./control").read().decode()
            self.assertEqual(archive.getmember("./postinst").mode, 0o755)
        self.assertIn(f"Version: {__version__}", control)
        self.assertIn("Depends: python3 (>= 3.12)", control)

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_deb_is_accepted_by_dpkg(self):
        deb = build.build_deb(self.out, self.pyz)
        info = subprocess.run(["dpkg-deb", "-I", str(deb)], capture_output=True, text=True, check=True).stdout
        self.assertIn("Package: patchwatch-agent", info)

    def test_bundled_syft_makes_package_architecture_specific(self):
        syft = self.out / "syft"
        syft.write_bytes(b"#!/bin/sh\n")
        deb = build.build_deb(self.out, self.pyz, syft=syft, architecture="amd64")
        self.assertTrue(deb.name.endswith("_amd64.deb"))
        with tarfile.open(fileobj=io.BytesIO(self.members(deb)["control.tar.gz"])) as archive:
            self.assertIn("--syft /usr/lib/patchwatch/bin/syft", archive.extractfile("./postinst").read().decode())
        layout = build.layout("/usr/local", self.pyz, launchd=True, syft=syft)
        self.assertIn("/Library/LaunchDaemons/eu.patchwatch.agent.plist", layout)
        self.assertIn("/usr/local/lib/patchwatch/bin/syft", layout)


if __name__ == "__main__":
    unittest.main()
