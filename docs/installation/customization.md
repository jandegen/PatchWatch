# Adapting to your own environment

The documentation uses `patchwatch.example.org`, `keycloak.example.org`,
`registry.example.org/platform/patchwatch` and the GitLab project path
`platform/patchwatch` as examples. These addresses do not provide available
services or published images. They must be replaced with your own values.
A GitLab instance of your own is only needed for GitLab CI and MR feedback.

The bundled Kubernetes profiles come from a specific installation.
Changing the documentation does not replace their values. Before a first
deployment, check and adapt all of the following places.

## Domains, platform and identities

| Parameter | Where to adapt | Notes |
|---|---|---|
| Installation-specific profiles | Your own private repository with `environments/infra.yaml` and `environments/dtrack.yaml`; `PATCHWATCH_ENV_DIR` points to it | `deploy/environments/` contains only generic reference values. Hostnames, issuer and CA do not belong in this repository. The deploy job clones the repository from `PATCHWATCH_ENV_PROJECT` |
| Public Patchwatch URL | Compose `.env`: `PUBLIC_URL`; Kubernetes `deploy/environments/dtrack.yaml`: `frontend.apiBaseUrl`, `ingress.hostname`, `ingress.tls[].hosts` | Browsers and agents must be able to reach this HTTPS address |
| URL for API setup | Environment variable `PUBLIC_URL` when calling `scripts/deploy.sh` or `scripts/configure-cluster.py`; set it as a CI variable in GitLab | Required, no fallback |
| GitLab environment URL | CI variable `PUBLIC_URL` | Used for `deploy.environment.url` |
| Namespace | `KUBE_NAMESPACE`, `scripts/setup-ci.py --namespace`, GitLab variable of the same name | Default `patchwatch`; bootstrap, Helmfile and setup must use the same namespace |
| Helm release names | `helmfile.yaml.gotmpl` | Keep `patchwatch` and `dtrack`; scripts and internal service names assume these names |
| Ingress controller | `deploy/environments/dtrack.yaml`: `ingress.ingressClassName`, controller-dependent annotations | Install the controller separately; replace annotations when using a different controller |
| StorageClass | `deploy/environments/infra.yaml`: `storageClass`; `deploy/environments/dtrack.yaml`: `fileStorage.local.storageClassName` | Use an available class of your own; check volume sizes and expandability |
| TLS certificates | Ingress TLS secret and, if applicable, the cert-manager annotation | cert-manager is optional if certificates are provided another way |
| ClusterIssuer | Ingress annotation `cert-manager.io/cluster-issuer` | Use the name of your own issuer or remove the annotation with other certificate management |
| OIDC | `DT_OIDC_*` and `OIDC_*` in `deploy/environments/dtrack.yaml`; Keycloak client | Adapt issuer, realm, client ID, web origin and the exact callback URL together |
| Internal CA | `oidcTrust.enabled`, `oidcTrust.caPem`, truststore init and `JAVA_TOOL_OPTIONS` | Use only the public root certificate of your own CA, in your own infra profile (see below) |
| Technical names and team permissions | `deploy/environments/oidc-teams.json` | Groups must exist in Keycloak; configure project access additionally if needed |
| Agent URL | `agent.json`: `url` | Enter your own HTTPS base URL without `/api` |
| Notifications | Secret or `.secrets/routes.json` | Your own team mapping and target URLs per [alerting](../configuration/alerting.md) |

Without Keycloak, remove the `DT_OIDC_*` and `OIDC_*` entries or disable OIDC.
With a publicly trusted IdP, the additional CA init, its
volumes, the truststore entry in `JAVA_TOOL_OPTIONS` and the OIDC CA ConfigMap
are not required. Remove related settings together;
[OIDC and TLS](../configuration/oidc.md#tls-trust) describes the procedure.

The [NetworkPolicies](../../deploy/helm/patchwatch/templates/networkpolicy.yaml)
assume an ingress controller in the namespace `ingress-nginx` for incoming traffic.
With a different controller, adapt its namespace selector and, if necessary,
the target ports. Also check DNS lookup and outgoing destinations.

## GitLab and registry

| Parameter | Where to adapt |
|---|---|
| GitLab login | `glab auth login --hostname gitlab.example.org` before setup scripts; use your own repository as the Git remote |
| Numeric project ID | Always specify `scripts/setup-ci.py --project` and `scripts/setup-mr-feedback.py --project` explicitly; the scripts contain existing local defaults |
| Runner tags | `.gitlab-ci.yml`: align `default.tags` with your available runners |
| Registry connection | `.gitlab-ci.yml`: `.docker-build.services[].command`; remove the installation-specific `--insecure-registry` entry or deliberately replace it with your own registry configuration |
| Registry/GitLab CA | Check the runner CA mounts and DinD start code in `.gitlab-ci.yml` and `ci/install-tools.sh`; with a public PKI, do not assume a private CA mount |
| CI image for included projects | Explicitly set `inputs.image` to your own published image on every include |
| Template source | Set `include.project` to your own project path and pin `ref` to an existing reviewed commit or your own release tag |
| Component feedback | Check `ci/mr-feedback.yml` for project ID and images before enabling your own feedback schedules |

A minimal example for a template consumer:

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
```

`v1` and the image must first have been published in your own project.
The image default stored in the template is not generally usable. For
immutable releases, use a reviewed commit and an image digest.

## Check before a rollout

1. Adapt the chosen configuration files in a checkout of your own; do not write passwords into values or Git.
2. Check DNS, HTTPS, registry access and storage prerequisites independently of the deployment.
3. Set `PUBLIC_URL`, the GitLab project ID and image references explicitly.
4. Lint/render Helm and check the diff; for Compose, run `docker compose config --quiet`.
5. Roll out and initialize per [Installation](index.md), and test an upload and, if applicable, an OIDC login.

A Helmfile of your own can reference its own values files. The shipped
deployment scripts use the root Helmfile; new file names are not read automatically
without adapting it.
