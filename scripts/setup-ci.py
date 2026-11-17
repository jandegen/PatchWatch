#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-time GitLab configuration using existing glab and kubectl login.

Stores only namespace-scoped credentials in protected production variables.
Never prints credential values. Run after scripts/bootstrap-cluster.sh.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def output(args):
    return subprocess.check_output(args, text=True)


def api(endpoint, payload=None, method=None):
    args = ["glab", "api", endpoint]
    if method:
        args += ["--method", method]
    if payload is None:
        return json.loads(output(args))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as stream:
        json.dump(payload, stream); stream.flush()
        args += ["--input", stream.name, "--header", "Content-Type: application/json"]
        if method is None:
            args += ["--method", "POST"]
        return json.loads(output(args))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="120", help="GitLab numeric project ID")
    parser.add_argument("--namespace", default="patchwatch")
    args = parser.parse_args()
    os.umask(0o077)
    existing = api(f"projects/{args.project}/variables")
    keys = {v["key"] for v in existing if v.get("environment_scope") == "production"}
    def variable(key, value, file=False):
        if key in keys:
            print(f"Preserving existing variable {key}")
            return
        api(f"projects/{args.project}/variables", {"key": key, "value": value,
            "variable_type": "file" if file else "env_var", "protected": True,
            "masked": not file, "raw": True, "environment_scope": "production"})
        print(f"Configured protected variable {key}")
    if "KUBE_CONFIG" not in keys:
        config = json.loads(output(["kubectl", "config", "view", "--raw", "--flatten", "--minify", "-o", "json"]))
        cluster = config["clusters"][0]["cluster"]
        for _ in range(30):
            secret = json.loads(output(["kubectl", "get", "secret", "patchwatch-ci-token", "-n", args.namespace, "-o", "json"]))
            if secret.get("data", {}).get("token"):
                break
            time.sleep(1)
        import base64
        token = base64.b64decode(secret["data"]["token"]).decode()
        kubeconfig = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "cluster", "cluster": cluster}],
                      "users": [{"name": "patchwatch-ci", "user": {"token": token}}],
                      "contexts": [{"name": "patchwatch", "context": {"cluster": "cluster", "user": "patchwatch-ci", "namespace": args.namespace}}],
                      "current-context": "patchwatch"}
        variable("KUBE_CONFIG", json.dumps(kubeconfig), file=True)
    if not {"REGISTRY_PULL_USERNAME", "REGISTRY_PULL_TOKEN"}.issubset(keys):
        if keys.intersection({"REGISTRY_PULL_USERNAME", "REGISTRY_PULL_TOKEN"}):
            raise SystemExit("Only one registry variable exists. Resolve the partial configuration before continuing.")
        deployment = api(f"projects/{args.project}/deploy_tokens", {"name": "patchwatch-kubernetes", "scopes": ["read_registry"]})
        variable("REGISTRY_PULL_USERNAME", deployment["username"])
        variable("REGISTRY_PULL_TOKEN", deployment["token"])
    print("CI configured. Default branch must be protected; main deploys automatically after successful checks.")


if __name__ == "__main__":
    main()
