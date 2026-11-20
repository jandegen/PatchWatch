# Installation

| Deployment mode | Suited for | Prerequisites |
|---|---|---|
| [Docker Compose](compose.md) | Local trial or a single server | Docker/Compose, Python for setup, persistent storage; HTTPS for remote agents |
| [Kubernetes with Helmfile](kubernetes.md) | Operation in your own cluster | Kubernetes, Helm/Helmfile, ingress controller, StorageClass and TLS; optionally GitLab CI |

Both variants include PostgreSQL, Dependency-Track, the frontend, the bridge and the
Trivy server. Backups and monitoring must be set up for regular
operation. The Docker Compose variant needs no GitLab instance.
The Kubernetes deploy can be done manually with the same scripts as in CI.

## Order for a new installation

1. Run the [local quick start](../getting-started.md) to get to know the system, or choose the deployment mode directly.
2. Define your [own environment parameters](customization.md) and build/publish the required images.
3. Start and initialize the stack following the Compose or Kubernetes guide.
4. Set up [user access / Keycloak](../configuration/oidc.md), [policies](../configuration/policies.md) and [notification targets](../configuration/alerting.md).
5. Connect [agents](../usage/agent.md) or [CI projects](../usage/ci-integration.md) and verify an import.
6. Test [backups, restore and monitoring](../operations/index.md).

## Existing installations

The bundled versions of Dependency-Track and the Helm chart are fixed in the repository;
they are not a recommendation to switch to a newer version unchecked.
Check backups and upgrade notes before making changes.
