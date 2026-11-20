# Documentation

The guides describe the implemented state of Patchwatch. Examples
with `example.org`, `platform/patchwatch`, `workstation-01` and realm `engineering`
are placeholders. Shell commands are run from the root directory of your own
checkout unless stated otherwise. The release names `patchwatch`
and `dtrack` and the namespace `patchwatch` match the bundled scripts.

## Getting started and installation

| Guide | Goal |
|---|---|
| [Quick start](getting-started.md) | Start locally, sign in and prepare the first upload |
| [Choose a deployment mode](installation/index.md) | Prerequisites and differences between Compose and Kubernetes |
| [Configure your own environment](installation/customization.md) | Adapt domains, registry, GitLab, storage, TLS, namespace and defaults |
| [Docker Compose](installation/compose.md) | Set up the full stack and HTTPS |
| [Kubernetes / GitLab CI](installation/kubernetes.md) | Prepare the cluster, configure the pipeline and roll out |

## Configuration

| Guide | Goal |
|---|---|
| [Keycloak / OIDC](configuration/oidc.md) | Set up the public client, PKCE, groups, team permissions and CA trust |
| [Policies and compliance](configuration/policies.md) | Configure security/license rules and evaluation |
| [Alerting and ticketing](configuration/alerting.md) | Set up delivery targets, filters and retries |
| [Trivy](configuration/trivy.md) | Configure and verify the native analyzer and token |

## Usage

| Guide | Goal |
|---|---|
| [Agent](usage/agent.md) | Linux/macOS, scan roots, extensions and schedules |
| [Inventory and findings](usage/inventory.md) | Device identity, registration, tags and visibility |
| [Services from Compose](usage/services.md) | Understand and configure static service collection |
| [GitLab CI integration](usage/ci-integration.md) | Repository/image SBOMs, versions and gates |
| [GitLab setup script](usage/gitlab-setup-script.md) | Connect a GitLab project interactively with one shell script |
| [BSI check of the CI SBOMs](usage/bsi-sbom.md) | Mandatory metadata, distribution licenses and upload check |
| [Delta reports](usage/delta-reports.md) | Evaluate and send changes against earlier versions |
| [Merge request feedback](usage/mr-feedback.md) | Set up isolated scans and the protected feedback worker |

## Operations and reference

- [Operations](operations/index.md): monitoring, backups, restore, updates and key rotation.
- [Architecture and limits](reference/architecture.md): components, data flow, data scope and detection limits.
- [Licenses and SPDX](reference/licenses.md): project license, declared dependencies and inventory.

## Designs and roadmap

[Designs](design/README.md) cover agent packages and enrollment that are not yet
implemented. They are not installation guides. The
[roadmap](design/roadmap.md) describes further open integrations.

## Changing the documentation

Assign new guides to the matching topic directory and link them here.
Replace concrete operator domains, users, cluster nodes or GitLab project IDs with
neutral examples. Examples must name the variables and
prerequisites they need; deviations between examples and the actual
script defaults belong in the [customization overview](installation/customization.md).
Set links relative to the respective document. When documentation paths change,
also update them in script hints and then renew the SPDX inventory.
