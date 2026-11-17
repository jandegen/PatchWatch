#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Configure Dependency-Track through an authenticated port-forward; persist generated keys."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from patchwatch.dtrack.client import DependencyTrack, admin_client
from patchwatch.dtrack.setup import configure
from patchwatch.dtrack.compliance import report


def kubectl(*args, data=None):
    result = subprocess.run(["kubectl", "-n", os.getenv("KUBE_NAMESPACE", "patchwatch"), *args],
                            input=json.dumps(data) if data is not None else None,
                            check=True, text=True, capture_output=True)
    return json.loads(result.stdout) if result.stdout.strip().startswith("{") else None


def main():
    os.umask(0o077)
    namespace = os.getenv("KUBE_NAMESPACE", "patchwatch")
    os.environ.setdefault("OIDC_TEAM_MAPPINGS_FILE", str(Path(__file__).resolve().parent.parent / "deploy/environments/oidc-teams.json"))
    with tempfile.TemporaryDirectory(prefix="patchwatch-configure-") as folder:
        root = Path(folder)
        data = kubectl("get", "secret", "patchwatch-secrets", "-o", "json")["data"]
        for key in ("admin_password", "webhook_token"):
            (root / key).write_bytes(base64.b64decode(data[key]))
        trivy = kubectl("get", "secret", "patchwatch-trivy", "-o", "json")["data"]
        (root / "trivy_token").write_bytes(base64.b64decode(trivy["token"]))
        os.environ["TRIVY_TOKEN_FILE"] = str(root / "trivy_token")
        os.environ["TRIVY_URL"] = "http://patchwatch-trivy:4954"
        existing = kubectl("get", "secret", "patchwatch-provisioning", "--ignore-not-found", "-o", "json")
        if existing:
            for key in ("upload_key", "monitor_key", "ci_upload_key", "versions_key"):
                if key in existing["data"]:  # New server/CI keys are added on upgrade.
                    (root / key).write_bytes(base64.b64decode(existing["data"][key]))
        os.environ["DT_ADMIN_PASSWORD_FILE"] = str(root / "admin_password")
        os.environ["ALLOW_HTTP"] = "true"
        port = int(os.getenv("CONFIGURE_PORT", "18081"))
        base = f"http://127.0.0.1:{port}"
        # A fresh or restarted API pod is not a port-forward target yet; wait for it (v5 needs minutes to start).
        subprocess.run(["kubectl", "-n", namespace, "rollout", "status", "deployment/dtrack-api-server", "--timeout=900s"], check=True)
        forward = subprocess.Popen(["kubectl", "-n", namespace, "port-forward", "service/dtrack-api-server", f"{port}:8080", "--address=127.0.0.1"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if forward.poll() is not None:
                    raise RuntimeError("Port-forward failed")
                try:
                    with urllib.request.urlopen(base + "/api/version", timeout=2): break
                except OSError: time.sleep(1)
            else:
                raise RuntimeError("Port-forward timed out")
            webhook = "http://patchwatch-bridge:8080/webhook/" + (root / "webhook_token").read_text()
            configure(base, root, webhook, os.environ.get("PUBLIC_URL") or sys.exit("PUBLIC_URL is required"), initial_admin=not existing)
            if os.getenv("COMPLIANCE_REPORT"):
                # Use the existing read-only monitor key for the report, even during setup.
                client = DependencyTrack(base, {"X-Api-Key": (root / "monitor_key").read_text().strip()})
                Path(os.environ["COMPLIANCE_REPORT"]).write_text(json.dumps(report(client), indent=2) + "\n")
            # Kubernetes secret values travel via stdin, never command-line arguments or logs.
            for name, values in [("patchwatch-provisioning", {k: (root / k).read_text() for k in ("upload_key", "monitor_key", "ci_upload_key", "versions_key")}),
                                 ("patchwatch-monitor-key", {"api_key": (root / "monitor_key").read_text()}),
                                 ("patchwatch-versions-key", {"api_key": (root / "versions_key").read_text()})]:
                kubectl("apply", "-f", "-", data={"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": namespace}, "stringData": values})
            if not existing:
                # v5 applies extension settings at runtime: start the first OSV mirror right away
                # instead of waiting for the daily schedule.
                admin_client(base, initial_admin=False).mirror("osv")
        finally:
            forward.terminate()
            forward.wait(timeout=10)


if __name__ == "__main__":
    main()
