# Quick start

This procedure starts Patchwatch locally with Docker Compose. Prerequisites are
Docker with Compose v2+, Python ≥3.12, about 7 GiB of free memory and
enough storage for the database and vulnerability data. A checkout of the
repository must be available. This local example requires neither Kubernetes
nor GitLab, a domain of your own or Keycloak.

## Start and initialize the stack

In the root directory of the checkout:

```sh
python3 scripts/init-compose.py
docker compose up -d --build --wait --wait-timeout 600
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
```

Open `http://localhost:8080`, user `admin`, password from
`.secrets/admin_password`. The setup replaces the initial default password,
creates technical teams and keys, and configures sources and policies.
The first data synchronization can take longer than starting the containers.
In this example the HTTP port is bound to loopback only.

## Record the first inventory

On a Linux or macOS machine, install Python and Syft and follow the
[agent guide](usage/agent.md). For an agent on a different
machine, first set up [HTTPS](installation/compose.md#https-for-remote-agents);
do not carry local HTTP exceptions over to remote devices.
Alternatively, connect a GitLab repository with the interactive [setup script](usage/gitlab-setup-script.md)
(it needs only `curl` and `jq`), or follow the [GitLab CI integration](usage/ci-integration.md) by hand.
This requires a GitLab project and a published CI image of your own;
the [Compose setup for CI](usage/ci-integration.md#14-ci-with-a-compose-server-without-kubernetes)
describes the procedure without Kubernetes.

## For regular operation

- Configure [alerting targets](configuration/alerting.md); the initial configuration sends no messages.
- Set up [backups and monitoring](operations/index.md) and verify a restore.
- With multiple users, configure [OIDC groups and permissions](configuration/oidc.md).
- For Kubernetes, continue with the [installation guide](installation/kubernetes.md) and the [environment parameters](installation/customization.md).

`docker compose down` stops the services and keeps the volumes. `down -v` removes
the stored data. More topics are in the [documentation overview](README.md).
