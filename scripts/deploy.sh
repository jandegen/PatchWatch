#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
: "${KUBE_NAMESPACE:=patchwatch}"
: "${BRIDGE_IMAGE:?Set BRIDGE_IMAGE to an immutable CI image reference}"
: "${PUBLIC_URL:?Set PUBLIC_URL to the public HTTPS address of this installation}"
export KUBE_NAMESPACE BRIDGE_IMAGE PUBLIC_URL
if [[ -n ${KUBE_CONFIG:-} ]]; then
  export KUBECONFIG="$KUBE_CONFIG"
fi
# First-install secrets are generated once. PostgreSQL passwords must never change silently.
if ! kubectl get secret patchwatch-secrets -n "$KUBE_NAMESPACE" >/dev/null 2>&1; then
  secret_dir=$(mktemp -d)
  trap 'rm -rf "$secret_dir"' EXIT
  umask 077
  python3 - "$secret_dir" <<'PY'
from pathlib import Path
import secrets,sys
p=Path(sys.argv[1])
for key in ['postgres_password','webhook_token','admin_password']:
    (p/key).write_text(secrets.token_urlsafe(36))
(p/'routes.json').write_text('[]\n')
PY
  kubectl create secret generic patchwatch-secrets -n "$KUBE_NAMESPACE" \
    --from-file="$secret_dir/postgres_password" --from-file="$secret_dir/webhook_token" --from-file="$secret_dir/admin_password" --from-file="$secret_dir/routes.json"
fi
# Dependency-Track 5 key-encryption key (base64 AES-256): generated once. Losing it makes stored integration
# secrets (Trivy token, feed credentials) unreadable, and a changed key stops the API server from starting.
if ! kubectl get secret patchwatch-dtrack-kek -n "$KUBE_NAMESPACE" >/dev/null 2>&1; then
  python3 - <<'PYCODE' | kubectl create -f -
import base64,json,os,secrets
print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"patchwatch-dtrack-kek","namespace":os.environ["KUBE_NAMESPACE"]},
                  "stringData":{"kek":base64.b64encode(secrets.token_bytes(32)).decode()}}))
PYCODE
fi
# Database credentials in the shape the official chart expects; derived from the single source of truth.
python3 - <<'PYCODE' | kubectl apply -f -
import base64,json,os,subprocess
ns=os.environ["KUBE_NAMESPACE"]
secret=json.loads(subprocess.run(["kubectl","get","secret","patchwatch-secrets","-n",ns,"-o","json"],check=True,capture_output=True,text=True).stdout)
password=base64.b64decode(secret["data"]["postgres_password"]).decode()
print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"patchwatch-dtrack-db","namespace":ns},
                  "stringData":{"username":"dtrack","password":password}}))
PYCODE
# Use a persistent read_registry deploy token: CI_JOB_TOKEN expires when this job ends.
if [[ -n ${REGISTRY_PULL_TOKEN:-} ]]; then
  : "${REGISTRY_PULL_USERNAME:?Required with REGISTRY_PULL_TOKEN}"
  registry_dir=$(mktemp -d)
  trap 'rm -rf "${secret_dir:-}" "$registry_dir"' EXIT
  python3 - "$registry_dir/config.json" <<'PY'
import base64,json,os,sys
from pathlib import Path
os.umask(0o077)
auth=base64.b64encode((os.environ['REGISTRY_PULL_USERNAME']+':'+os.environ['REGISTRY_PULL_TOKEN']).encode()).decode()
Path(sys.argv[1]).write_text(json.dumps({'auths':{os.environ['CI_REGISTRY']:{'auth':auth}}}))
PY
  kubectl create secret generic gitlab-registry -n "$KUBE_NAMESPACE" --type=kubernetes.io/dockerconfigjson \
    --from-file=".dockerconfigjson=$registry_dir/config.json" --dry-run=client -o yaml | kubectl apply -f -
fi
# Independent token, preserved on upgrades and never emitted in logs or arguments.
if ! kubectl get secret patchwatch-trivy -n "$KUBE_NAMESPACE" >/dev/null 2>&1; then
  python3 - <<'PYCODE'
import json,os,secrets,subprocess
payload={"apiVersion":"v1","kind":"Secret","metadata":{"name":"patchwatch-trivy","namespace":os.environ["KUBE_NAMESPACE"]},"stringData":{"token":secrets.token_urlsafe(36)}}
subprocess.run(["kubectl","create","-f","-"], input=json.dumps(payload),text=True,check=True)
PYCODE
fi
helmfile -f helmfile.yaml.gotmpl sync
kubectl rollout status deployment/patchwatch-bridge -n "$KUBE_NAMESPACE" --timeout=120s

python3 scripts/configure-cluster.py

kubectl rollout restart deployment/patchwatch-bridge -n "$KUBE_NAMESPACE"
kubectl rollout status deployment/patchwatch-bridge -n "$KUBE_NAMESPACE" --timeout=120s
