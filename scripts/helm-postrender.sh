#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The official 1.x chart does not expose dnsConfig. Keep it upstream and patch PodSpecs.
set -eu
render_dir=$(mktemp -d)
trap 'rm -rf "$render_dir"' EXIT HUP INT TERM
cat > "$render_dir/resources.yaml"
cat > "$render_dir/kustomization.yaml" <<'YAML'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [resources.yaml]
patches:
  - target:
      kind: (Deployment|StatefulSet)
    patch: |-
      - op: add
        path: /spec/template/spec/dnsConfig
        value:
          options:
            - name: ndots
              value: '1'
YAML
# Preserve the document boundary when Helmfile concatenates release output.
printf '%s\n' '---'
kubectl kustomize "$render_dir"
