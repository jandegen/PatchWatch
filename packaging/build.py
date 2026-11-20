#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build installable agent artifacts from this checkout using only the standard library.

    python3 packaging/build.py pyz            dist/patchwatch-agent.pyz  (agent + core only)
    python3 packaging/build.py deb            dist/patchwatch-agent_<version>_<arch>.deb
    python3 packaging/build.py pkg            dist/patchwatch-agent-<version>.pkg   (macOS only)
    python3 packaging/build.py templates      dist/patchwatch-ci-templates.tar.gz   (GitLab CI templates)

The agent ships as a zipapp: ``patchwatch/agent`` and ``patchwatch/core`` are the only packages in
it (``tests/test_boundaries.py`` guarantees they do not import anything else). Packages install it
as ``<prefix>/lib/patchwatch/patchwatch-agent.pyz`` plus a ``patchwatch-agent`` launcher. Pass
``--syft PATH`` to bundle a Syft binary next to it. The package never enables the timer: rollout
tooling creates the profile and key, runs ``patchwatch-agent`` once and then enables the schedule.

The output is reproducible: file times come from ``SOURCE_DATE_EPOCH`` (default 0).
"""
import argparse
import gzip
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from patchwatch import __version__  # noqa: E402

PACKAGE = "patchwatch-agent"
PYZ_NAME = "patchwatch-agent.pyz"
EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
SHIPPED_PACKAGES = ("patchwatch/__init__.py", "patchwatch/core", "patchwatch/agent")
PYTHON_MINIMUM = "3.12"

LAUNCHER = """#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
exec python3 {prefix}/lib/patchwatch/{pyz} "$@"
"""

DEB_CONTROL = """Package: {package}
Version: {version}
Architecture: {architecture}
Maintainer: Patchwatch contributors <noreply@invalid>
Section: admin
Priority: optional
Depends: python3 (>= {python})
Description: Patchwatch host inventory agent
 Scans installed software with Syft, reduces the result to a privacy-minimized
 CycloneDX SBOM and uploads it to Dependency-Track. The daily timer is installed
 but not enabled; see /usr/share/doc/{package}/README.
"""

DEB_POSTINST = """#!/bin/sh
set -e
if [ "$1" = configure ]; then
    install -d -m 0700 /etc/patchwatch /var/lib/patchwatch
    /usr/bin/patchwatch-agent --init-config{syft}
    if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
fi
exit 0
"""

DEB_PRERM = """#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = upgrade ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop patchwatch-agent.timer patchwatch-agent.service 2>/dev/null || true
        systemctl disable patchwatch-agent.timer 2>/dev/null || true
    fi
fi
exit 0
"""

DEB_POSTRM = """#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf /etc/patchwatch /var/lib/patchwatch
fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
exit 0
"""

PKG_POSTINSTALL = """#!/bin/sh
install -d -m 0700 /etc/patchwatch /var/lib/patchwatch
/usr/local/bin/patchwatch-agent --init-config{syft}
exit 0
"""

README = """Patchwatch agent
================
1. Edit /etc/patchwatch/agent.json (url, tags) and store the upload key in
   /etc/patchwatch/api-key (mode 0600).
2. Test: sudo patchwatch-agent
3. Enable the daily run: {enable}
Full documentation: docs/usage/agent.md of the Patchwatch repository.
"""


# -- zipapp ---------------------------------------------------------------------------------------

def _shipped_files():
    """``(archive name, bytes)`` of the agent and core packages, sorted for reproducible output."""
    files = {}
    for item in SHIPPED_PACKAGES:
        source = ROOT / item
        paths = [source] if source.is_file() else [p for p in source.rglob("*") if p.is_file()]
        for path in paths:
            if "__pycache__" not in path.parts and path.suffix != ".pyc":
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    files["LICENSE"] = (ROOT / "LICENSE").read_bytes()
    files["__main__.py"] = b"from patchwatch.agent.cli import main\n\nmain()\n"
    return sorted(files.items())


def build_pyz(destination: Path) -> Path:
    """Zipapp with the agent and core packages only; ``python3 patchwatch-agent.pyz`` runs the agent."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in _shipped_files():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"#!/usr/bin/env python3\n" + buffer.getvalue())
    destination.chmod(0o755)
    return destination


# -- file layout shared by all packages ----------------------------------------------------------

def layout(prefix: str, pyz: Path, systemd_dir=None, launchd=False, syft=None) -> dict:
    """``{absolute install path: (bytes, mode)}`` of the files a package installs."""
    files = {
        f"{prefix}/bin/{PACKAGE}": (LAUNCHER.format(prefix=prefix, pyz=PYZ_NAME).encode(), 0o755),
        f"{prefix}/lib/patchwatch/{PYZ_NAME}": (pyz.read_bytes(), 0o755),
        f"{prefix}/share/doc/{PACKAGE}/copyright": ((ROOT / "LICENSE").read_bytes(), 0o644),
        f"{prefix}/share/doc/{PACKAGE}/NOTICE": ((ROOT / "NOTICE").read_bytes(), 0o644),
        f"{prefix}/share/doc/{PACKAGE}/agent.example.json": ((ROOT / "agent/agent.example.json").read_bytes(), 0o644),
    }
    enable = "sudo systemctl enable --now patchwatch-agent.timer"
    if systemd_dir:
        for name in ("patchwatch-agent.service", "patchwatch-agent.timer"):
            files[f"{systemd_dir}/{name}"] = ((ROOT / "agent/systemd" / name).read_bytes(), 0o644)
    if launchd:
        plist = "eu.patchwatch.agent.plist"
        files[f"/Library/LaunchDaemons/{plist}"] = ((ROOT / "agent/launchd" / plist).read_bytes(), 0o644)
        enable = f"sudo launchctl bootstrap system /Library/LaunchDaemons/{plist}"
    files[f"{prefix}/share/doc/{PACKAGE}/README"] = (README.format(enable=enable).encode(), 0o644)
    if syft:
        files[f"{prefix}/lib/patchwatch/bin/syft"] = (Path(syft).read_bytes(), 0o755)
    return files


# -- .deb ----------------------------------------------------------------------------------------

def _tar(entries: dict, directories=()) -> bytes:
    """Deterministic gzip-compressed tar owned by root; directories are created for every parent."""
    parents = set(directories)
    for name in entries:
        parts = Path(name).parts
        parents.update("/".join(parts[:i]) for i in range(2, len(parts)))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for directory in sorted(p.lstrip("/") for p in parents):
            info = tarfile.TarInfo("./" + directory)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, EPOCH
            archive.addfile(info)
        for name, (data, mode) in sorted(entries.items()):
            info = tarfile.TarInfo("./" + name.lstrip("/"))
            info.size, info.mode, info.mtime = len(data), mode, EPOCH
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def _ar(members: list) -> bytes:
    """Minimal ``ar`` archive (the container format of .deb files)."""
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += f"{name:<16}{EPOCH:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode() + data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


def build_deb(destination_dir: Path, pyz: Path, syft=None, architecture=None) -> Path:
    # A bundled Syft binary makes the package architecture specific; without it the package is pure Python.
    architecture = architecture or (_deb_architecture() if syft else "all")
    files = layout("/usr", pyz, systemd_dir="/usr/lib/systemd/system", syft=syft)
    syft_option = " --syft /usr/lib/patchwatch/bin/syft" if syft else ""
    scripts = {"postinst": DEB_POSTINST.format(syft=syft_option), "prerm": DEB_PRERM, "postrm": DEB_POSTRM}
    control = {"control": (DEB_CONTROL.format(package=PACKAGE, version=__version__, architecture=architecture,
                                              python=PYTHON_MINIMUM).encode(), 0o644)}
    control.update({name: (text.encode(), 0o755) for name, text in scripts.items()})
    destination = destination_dir / f"{PACKAGE}_{__version__}_{architecture}.deb"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(_ar([("debian-binary", b"2.0\n"),
                                 ("control.tar.gz", _tar(control)),
                                 ("data.tar.gz", _tar(files))]))
    return destination


def _deb_architecture() -> str:
    machine = platform.machine()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)


# -- macOS .pkg ----------------------------------------------------------------------------------

def build_pkg(destination_dir: Path, pyz: Path, syft=None) -> Path:
    """Stage the payload and call ``pkgbuild`` (macOS). Signing/notarization is done by the release job."""
    if shutil.which("pkgbuild") is None:
        raise SystemExit("pkgbuild not found: build the .pkg on macOS")
    destination_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        payload, scripts = Path(folder) / "root", Path(folder) / "scripts"
        for name, (data, mode) in layout("/usr/local", pyz, launchd=True, syft=syft).items():
            target = payload / name.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(mode)
        scripts.mkdir()
        postinstall = scripts / "postinstall"
        postinstall.write_text(PKG_POSTINSTALL.format(
            syft=" --syft /usr/local/lib/patchwatch/bin/syft" if syft else ""))
        postinstall.chmod(0o755)
        destination = destination_dir / f"{PACKAGE}-{__version__}.pkg"
        subprocess.run(["pkgbuild", "--root", str(payload), "--scripts", str(scripts), "--identifier", "eu.patchwatch.agent",
                        "--version", __version__, "--install-location", "/", str(destination)], check=True)
    return destination


# -- CI templates ---------------------------------------------------------------------------------

TEMPLATES_NAME = "patchwatch-ci-templates.tar.gz"


def build_templates(destination: Path, image=None) -> Path:
    """Archive of ``ci-templates/*.yml`` for scripts/setup-gitlab-project.sh.

    Besides the templates it holds ``VERSION`` and, when ``image`` is given, ``IMAGE``: the public job
    image (``ghcr.io/<owner>/<repo>/ci:vX.Y.Z``) the generated GitLab configuration passes as the
    ``image`` input. The templates themselves are shipped unchanged.
    """
    entries = {f"ci-templates/{path.name}": (path.read_bytes(), 0o644)
               for path in (ROOT / "ci-templates").glob("*.yml")}
    if not entries:
        raise SystemExit("ci-templates/ contains no templates")
    entries["VERSION"] = (f"{__version__}\n".encode(), 0o644)
    if image:
        entries["IMAGE"] = (f"{image}\n".encode(), 0o644)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(_tar(entries))
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", choices=("pyz", "deb", "pkg", "templates"))
    parser.add_argument("--output", default=str(ROOT / "dist"), help="output directory (default: dist/)")
    parser.add_argument("--syft", help="Syft binary to bundle (makes the package architecture specific)")
    parser.add_argument("--image", help="public CI job image recorded in the templates archive (target templates)")
    args = parser.parse_args(argv)
    output = Path(args.output)
    if args.target == "templates":
        print(build_templates(output / TEMPLATES_NAME, args.image))
        return
    with tempfile.TemporaryDirectory() as folder:
        pyz = build_pyz(output / PYZ_NAME if args.target == "pyz" else Path(folder) / PYZ_NAME)
        if args.target == "deb":
            pyz = build_deb(output, pyz, args.syft)
        elif args.target == "pkg":
            pyz = build_pkg(output, pyz, args.syft)
    print(pyz)


if __name__ == "__main__":
    main()
