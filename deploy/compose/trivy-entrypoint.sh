#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
TRIVY_TOKEN=$(cat /run/secrets/trivy_token)
if [ -z "$TRIVY_TOKEN" ]; then echo 'Trivy token must not be empty' >&2; exit 1; fi
export TRIVY_TOKEN
exec trivy server --listen 0.0.0.0:4954 --cache-dir /data
