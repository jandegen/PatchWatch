# Installation on Kubernetes

Before the first deployment, adapt the [environment parameters](customization.md). Commands are run in the repository root directory.


The prerequisites are a reachable Kubernetes cluster, `kubectl`, Helm,
Helmfile with the diff plugin, an ingress controller and persistent storage. The
guides use the namespace `patchwatch` and the releases `patchwatch` and
`dtrack`. A DNS address such as `patchwatch.example.org` must point to the ingress.
TLS can be set up through cert-manager and an issuer of your own or through a provided
TLS secret. This project does not install cluster controllers.

Define the StorageClass, ingress class, NetworkPolicy selectors, certificates and URLs per the
[customization overview](customization.md). `ndots:1` reduces unwanted
DNS search domain expansion; with the official chart, the Helm post-renderer
adds this pod setting via `kubectl kustomize`.

## Deployment via GitLab CI

The pipeline tests every merge request and `main`. On `main` it then builds the
bridge image tagged with the full commit SHA and deploys automatically via Helmfile.
A `resource_group` prevents concurrent deployments. Errors in tests or rendering
block build and deployment. Deployment credentials are made available only to the protected
production environment. Fork/MR pipelines do not receive them.

One-time, with an existing cluster admin and `glab` login:

```sh
export GITLAB_PROJECT_ID=1234  # replace with the numeric ID of your own Patchwatch project
export KUBE_NAMESPACE=patchwatch
bash scripts/bootstrap-cluster.sh
python3 scripts/setup-ci.py --project "$GITLAB_PROJECT_ID"
```

`main` must be protected in GitLab. The setup creates the following **protected**
project variables with environment scope `production`:

| Variable | Type | Purpose |
|---|---|---|
| `KUBE_CONFIG` | File | ServiceAccount `patchwatch-ci`, permissions exclusively in the namespace |
| `REGISTRY_PULL_USERNAME` | Masked | Project deploy token user |
| `REGISTRY_PULL_TOKEN` | Masked | Long-lived `read_registry` token for later image pulls |

The runner tags and Docker-in-Docker configuration in `.gitlab-ci.yml` must
match your own runner and registry installation. Replace or remove installation-specific
registry exceptions and private CA mounts beforehand.
The registry, GitLab and certificate chain must be reachable and trusted from the runner, DinD and Kubernetes nodes.
Set your own public HTTPS URL as the CI variable `PUBLIC_URL`; also adapt
`deploy.environment.url` in the pipeline.

CI creates a separate Trivy token in `patchwatch-trivy` and enables the
[native Trivy analyzer](../configuration/trivy.md). The database password, webhook token and admin password are created once in
`patchwatch-secrets`. Existing values are kept on subsequent deployments. The values are not
in Helm values or Git. In addition, the team `ci-upload` is created with its own key `ci_upload_key` (in `patchwatch-provisioning`) for the [GitLab CI template](../usage/ci-integration.md); for this, the pipeline builds a second image `ci` from `Dockerfile.ci`. Afterwards PostgreSQL, the bridge, Dependency-Track,
the frontend, TLS ingress, NetworkPolicies, and backup and monitoring CronJobs are rolled out.
The initial setup runs over a local, authenticated Kubernetes port-forward.
It replaces `admin/admin` and creates upload/read teams, OSV ecosystems, EPSS, the
[security/license rules](../configuration/policies.md) including the license group and separate MR rule copies, and the
webhook rule. The generated API keys are in `patchwatch-provisioning`; the monitor gets
the read key in `patchwatch-monitor-key` (`VIEW_PORTFOLIO` and
`VIEW_POLICY_VIOLATION` and `VIEW_VULNERABILITY`, together with compliance and delta reports). CI does not log any keys.

The team `project-versions` receives `VIEW_PORTFOLIO` and `PORTFOLIO_MANAGEMENT` for the server-side
latest synchronization. The key stays in `patchwatch-provisioning` (`versions_key`) and in the separate
secret `patchwatch-versions-key`. The CronJob `patchwatch-versions` runs every five minutes with the
bridge image; schedule and secret are configurable via `versions.schedule` and `versions.existingSecret`,
and it can be disabled with `versions.enabled: false`. On the first installation the secret is created
after the Helm rollout during the setup. CI upload keys keep their previous permissions.
The synchronization additionally runs on every setup. Rules and provenance information:
[CI integration](../usage/ci-integration.md#3-what-appears-in-patchwatch).

Display the admin password only locally and then store it in the password manager:

```sh
kubectl -n patchwatch get secret patchwatch-secrets -o jsonpath='{.data.admin_password}' | base64 -d
```

The declarative configuration consists of `helmfile.yaml.gotmpl`,
`deploy/environments/infra.yaml`, `deploy/environments/dtrack.yaml` and the own
infra chart. Dependency-Track uses the **official chart 2.9.0 with application 5.2.1**.
In addition to the secrets mentioned above, `deploy.sh` creates `patchwatch-dtrack-kek` once (the
key-encryption key of the v5 secret manager, **to be included in every cluster backup**) and derives
`patchwatch-dtrack-db` (user and password in the chart's format) from `patchwatch-secrets`.
Outbound, the API server reaches only public addresses plus the bridge and Trivy
(`DT_OUTBOUND_ALLOWED_DESTINATIONS` in `deploy/environments/dtrack.yaml`).

## Manual rollout

Without GitLab CI, build a bridge image from the commit to be released and publish it under
an immutable reference in your own registry. The nodes
need read access; with a private registry, create the secret `gitlab-registry` beforehand
or adapt `imagePullSecrets` to your own pull secret configuration.
After the namespace/RBAC bootstrap, run the same deployment path:

```sh
export PUBLIC_URL=https://patchwatch.example.org
export BRIDGE_IMAGE="registry.example.org/platform/patchwatch/bridge:$(git rev-parse HEAD)"
bash scripts/deploy.sh
```

On failure, Helm atomically rolls back the affected release. This is **not** a
rollback of database migrations or configuration changes of the API. Check backup
and restore before upgrades. The two releases are interdependent and can have separate revision states.
CI gets no access to other namespaces. The long-lived CI ServiceAccount token is
deliberately restricted to the namespace; on rotation, replace the secret `patchwatch-ci-token` and `KUBE_CONFIG`.
