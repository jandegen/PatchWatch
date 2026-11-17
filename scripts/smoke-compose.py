#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a configured Compose stack with real Syft, upload permissions and read-only inventory.

Set DT_URL (default localhost:8080) and SYFT (default syft). Uses synthetic packages only.
Run patchwatch.dtrack.setup first. Creates/updates patchwatch-smoke, version current.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from patchwatch.agent import run
from patchwatch.core.http import request
from patchwatch.dtrack.monitor import stale_projects

url = os.getenv("DT_URL", "http://localhost:8080")
folder = Path(".secrets")
key = (folder / "upload_key").resolve()
key.chmod(0o600)
with tempfile.TemporaryDirectory(prefix="patchwatch-fixture-") as temp:
    root = Path(temp)
    package = root / "node_modules" / "patchwatch-smoke"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "patchwatch-smoke", "version": "1.2.3", "license": "Apache-2.0"}))
    run({"url": url, "allow_http": True, "host_id": "patchwatch-smoke", "hostname": "patchwatch-smoke", "api_key_file": str(key),
         "roots": [temp], "tags": ["team:smoke"], "syft": os.getenv("SYFT", "syft"), "lock_file": temp + "/lock"})
    headers = {"X-Api-Key": (folder / "monitor_key").read_text().strip()}
    project, _ = request(url + "/api/v1/project/lookup?" + urlencode({"name": "patchwatch-smoke", "version": "current"}), headers=headers)
    components, _ = request(url + "/api/v1/component/project/" + project["uuid"], headers=headers)
    assert any(c["name"] == "patchwatch-smoke" and c["version"] == "1.2.3" for c in components), components
    assert {t["name"] for t in project["tags"]} >= {"team:smoke"}
    assert stale_projects([project], 48) == []
    print("Smoke passed: real Syft scan, CycloneDX import, tags, component inventory and recent-import monitor")
