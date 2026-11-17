# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from patchwatch.agent.config import AgentConfig, DEFAULT_ROOTS
from patchwatch.agent.runner import collect_boms, single_instance, upload_fields


def profile(**overrides):
    base = {"url": "https://dtrack.example", "host_id": "asset-1", "hostname": "Dev-Station.",
            "api_key_file": "/nonexistent/key"}
    return {**base, **overrides}


class ConfigValidation(unittest.TestCase):
    def test_defaults_and_normalization(self):
        config = AgentConfig.from_dict(profile())
        self.assertEqual(config.host_name, "dev-station")
        self.assertEqual(config.roots, DEFAULT_ROOTS)
        self.assertEqual(config.url, "https://dtrack.example")
        self.assertIn("managed-by:patchwatch", config.tags)
        self.assertIsNone(config.project_uuid)

    def test_invalid_profiles_are_rejected_without_echoing_values(self):
        cases = [profile(url="http://dtrack.example"), profile(url="https://dtrack.example/?token=secret"),
                 profile(host_id=""), profile(hostname="bad host"), profile(project_uuid="not-a-uuid"),
                 profile(roots="/usr"), profile(images=[1]), profile(scan_timeout=0), profile(poll_attempts=True),
                 profile(api_key_file=""), {k: v for k, v in profile().items() if k != "url"}]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError) as caught:
                    AgentConfig.from_dict(raw)
                self.assertNotIn("secret", str(caught.exception))

    def test_http_requires_explicit_opt_in(self):
        self.assertEqual(AgentConfig.from_dict(profile(url="http://internal:8080/", allow_http=True)).url,
                         "http://internal:8080")

    def test_api_key_file_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"
            key.write_text("secret-key\n")
            key.chmod(0o600)
            self.assertEqual(AgentConfig.from_dict(profile(api_key_file=str(key))).read_api_key(), "secret-key")
            key.chmod(0o640)
            with self.assertRaises(ValueError):
                AgentConfig.from_dict(profile(api_key_file=str(key))).read_api_key()
            key.chmod(0o600)
            key.write_text("two\nlines")
            with self.assertRaises(ValueError):
                AgentConfig.from_dict(profile(api_key_file=str(key))).read_api_key()

    def test_extension_options_are_passed_through(self):
        config = AgentConfig.from_dict(profile(scan_extensions=False, extension_homes=["/home/a"]))
        self.assertEqual(dict(config.extension_options), {"scan_extensions": False, "extension_homes": ["/home/a"]})


class UploadFields(unittest.TestCase):
    def test_registered_host_binds_to_project(self):
        project = str(uuid.uuid4())
        fields = upload_fields(AgentConfig.from_dict(profile(project_uuid=project)))
        self.assertEqual((fields["autoCreate"], fields["project"]), ("false", project))

    def test_unregistered_host_creates_its_project(self):
        fields = upload_fields(AgentConfig.from_dict(profile()))
        self.assertEqual(fields["autoCreate"], "true")
        self.assertNotIn("project", fields)
        self.assertEqual(fields["projectName"], "dev-station")


class Runner(unittest.TestCase):
    def test_second_instance_does_not_acquire_the_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            lock = Path(folder) / "state" / "agent.lock"
            with single_instance(lock) as first, single_instance(lock) as second:
                self.assertTrue(first)
                self.assertFalse(second)
            with single_instance(lock) as again:
                self.assertTrue(again)

    def test_extensions_are_reconciled_only_with_directory_roots(self):
        config = AgentConfig.from_dict(profile(roots=["/opt"], images=["alpine:3"]))
        with tempfile.TemporaryDirectory() as folder, \
                patch("patchwatch.agent.runner.scan", return_value={"components": []}) as scan, \
                patch("patchwatch.agent.runner.reconcile_extensions") as reconcile:
            boms = collect_boms(config, {"components": []}, Path(folder))
        self.assertEqual([c.args[1] for c in scan.call_args_list], ["dir:" + str(Path("/opt").resolve()), "alpine:3"])
        reconcile.assert_called_once()
        self.assertEqual(len(boms), 3)  # one per source plus the extension inventory


if __name__ == "__main__":
    unittest.main()
