# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from patchwatch.agent import run
from patchwatch.core.http import check_url


class AgentTests(unittest.TestCase):
    def test_transport(self):
        for url in ("http://example.org", "https://user:pass@example.org", "file:///etc/passwd", "https://example.org/#secret"):
            with self.assertRaises(ValueError):
                check_url(url)
        self.assertEqual(check_url("http://localhost", True), "http://localhost")

    def test_scan_upload_and_poll(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"; key.write_text("test-key"); key.chmod(0o600)
            cfg = {"url": "https://example.org", "api_key_file": str(key), "host_id": "asset-1", "hostname": "asset-1",
                   "extension_homes": [], "roots": [folder], "lock_file": folder + "/lock", "tags": ["team:test"]}
            def scan(args, **kwargs):
                output = next(a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json="))
                Path(output).write_text(json.dumps({"components": [{"type": "library", "name": "pkg", "version": "1"}]}))
                self.assertIn("--exclude", args)
                self.assertIn("+javascript-package-cataloger", args)
            token = str(uuid.uuid4())
            with patch("patchwatch.agent.scanner.subprocess.run", side_effect=scan), patch("patchwatch.agent.runner.request", side_effect=[({"token": token}, {}), ({"processing": False}, {})]) as client:
                run(cfg)
            self.assertEqual(client.call_count, 2)
            upload = client.call_args_list[0].args
            self.assertIn(b"asset-1", upload[1])
            self.assertIn(b"team:test", upload[1])
            self.assertNotIn(b"test-key", upload[1])
            self.assertEqual(upload[2]["X-Api-Key"], "test-key")
            self.assertFalse(any(Path(folder).glob("*.json")))

    def test_world_readable_key_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"; key.write_text("key"); key.chmod(0o644)
            with self.assertRaises(ValueError):
                run({"url": "https://example.org", "host_id": "x", "api_key_file": str(key)})

    def test_registered_host_upload_is_bound_to_existing_uuid(self):
        with tempfile.TemporaryDirectory() as folder:
            key=Path(folder)/'key'; key.write_text('test-key'); key.chmod(0o600)
            project=str(uuid.uuid4()); token=str(uuid.uuid4())
            config={'url':'https://example.org','api_key_file':str(key),'host_id':'asset-1',
                    'hostname':'dev-station','project_uuid':project,'extension_homes':[],'roots':[folder],'lock_file':folder+'/lock'}
            def scan(args,**kwargs):
                output=next(a.split('=',1)[1] for a in args if a.startswith('cyclonedx-json='))
                Path(output).write_text(json.dumps({'components':[{'type':'library','name':'pkg','version':'1'}]}))
            with patch('patchwatch.agent.scanner.subprocess.run',side_effect=scan), patch('patchwatch.agent.runner.request',side_effect=[({'token':token},{}),({'processing':False},{})]) as client:
                run(config)
            body=client.call_args_list[0].args[1]
            self.assertIn(project.encode(),body)
            self.assertIn(b'dev-station',body)
            self.assertIn(b'managed-by:patchwatch',body)
            self.assertIn(b'name="autoCreate"\r\n\r\nfalse',body)


if __name__ == "__main__":
    unittest.main()
