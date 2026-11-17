#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run once with cluster-admin context. CI only receives this namespace's credentials.
set -euo pipefail
: "${KUBE_NAMESPACE:=patchwatch}"
kubectl create namespace "$KUBE_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$KUBE_NAMESPACE" apply -f - <<'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: patchwatch-ci
automountServiceAccountToken: false
---
apiVersion: v1
kind: Secret
metadata:
  name: patchwatch-ci-token
  annotations:
    kubernetes.io/service-account.name: patchwatch-ci
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: patchwatch-ci
rules:
  - apiGroups: ['']
    resources: [services, serviceaccounts, secrets, configmaps, persistentvolumeclaims]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: ['']
    resources: [pods, pods/log, events]
    verbs: [get, list, watch]
  - apiGroups: ['']
    resources: [pods/portforward]
    verbs: [create]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, replicasets]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: patchwatch-ci
subjects:
  - kind: ServiceAccount
    name: patchwatch-ci
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: patchwatch-ci
YAML
# Namespace reads are cluster-scoped; the deploy script does not need this permission.
echo 'Namespace and CI RBAC ready. Export its kubeconfig to protected file variable KUBE_CONFIG (docs/installation/index.md).'
