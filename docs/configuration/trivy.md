# Native Trivy scans in Dependency-Track

Dependency-Track has a Trivy analyzer. It sends supported components from
imported SBOMs to a separate Trivy server and takes over its findings into the
existing analysis. The Syft agent continues to create the inventory. Trivy installs no
agents and, through this integration, scans neither machine file systems nor running cluster pods.

```
Syft agent → CycloneDX → Dependency-Track → Trivy server + Trivy database
                              ↓
                      Findings / policy / bridge
```

## Kubernetes

The infra chart deploys `patchwatch-trivy` with a persistent 4 GiB cache, one replica,
startup/readiness/liveness probes and without root privileges. The server is reachable exclusively via
a ClusterIP service on port 4954. A NetworkPolicy allows only the
Dependency-Track API pod access. There is no ingress and no Kubernetes API access
for Trivy. Loading/updating the Trivy database requires outbound HTTPS access.

On the first deployment, the existing GitLab pipeline creates a dedicated random token
in `patchwatch-trivy`, key `token`. Updates keep this token. The API configuration sets:

| DTrack setting | Value |
|---|---|
| Enable | true |
| Base URL | `http://patchwatch-trivy:4954` |
| API Token | From Kubernetes secret, stored encrypted in DTrack |
| Ignore Unfixed | false |
| Scan Libraries / OS | true each |

Token authentication protects the Trivy RPC endpoints; `/healthz` stays open for probes.
The internal HTTP stays inside the cluster; the agent upload still uses HTTPS.
New BOMs are analyzed automatically. Existing projects can be analyzed again
in DTrack; the regular periodic vulnerability matching applies as well.
Scan errors and outdated DB downloads must be monitored: with a disturbed analyzer, a missing finding
does not mean that a component is safe.

## Docker Compose

```sh
python3 scripts/init-compose.py
docker compose up -d --build --wait --wait-timeout 900
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
```

The server publishes no host port. The one-off service `trivy-cache-init` only prepares
the write permissions of the dedicated cache volume; it has no network access.
Trivy itself runs as UID/GID 10001 with a read-only root file system.
The database download can take several minutes on first start. The cache is kept across
restarts and is restorable; a backup of its contents is not required.
The token, in contrast, belongs in the existing encrypted secret backup.

With a different Compose secret path, also adapt the `*_FILE` variables for the setup.
Without `TRIVY_URL`, `patchwatch.dtrack.setup` does not change the existing Trivy configuration.
Optionally it supports `TRIVY_IGNORE_UNFIXED=true`; by default, findings without an
available fix are also shown. The one-off setup call must reach DTrack from the machine;
the configured Trivy URL, in contrast, must be reachable **from the DTrack container**.

## End-to-end check

A real test of the DTrack RPC integration is possible with the following script:

```sh
DT_URL=https://patchwatch.example.org \
  DT_ADMIN_PASSWORD_FILE=/secure/path/admin_password \
  python3 scripts/smoke-trivy.py
```

The test uploads only synthetic Maven coordinates for Log4j, waits for
`CVE-2021-44228` with the attribution `TRIVY_ANALYZER` and deletes its own test project again.
No vulnerable software is installed. The test creates regular DTrack findings;
with configured notification targets, these can trigger a test message.
A valid admin API token can alternatively be provided via `DT_ADMIN_API_KEY_FILE`.

## Version, limits and operation

Trivy is pinned to **0.76.2** and the image digest
`sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb`.
No `latest` tags or Trivy GitHub Actions are used. For updates, update the approved
release and image digest together in Helm, Compose and SPDX and test the native
DTrack RPC integration again. The scanner image and the downloaded vulnerability database
have different update cycles.

The analyzer needs usable package coordinates. Without PURL, distribution version or
source package metadata, OS packages in particular can be matched incompletely.
A Syft inventory does not automatically become more complete through the additional analyzer.
DTrack creates the scan requests from its inventory; Trivy-specific properties can
improve OS matching. Do not adopt foreign components or metadata unchecked.

NeuVector integration and automatic runtime service detection remain [open TODOs](../design/roadmap.md).
The separate [Compose collection](../usage/services.md) already reads static service definitions.
For this, no credentials are created and no collectors or response rules are enabled.

References: [Dependency-Track: Vulnerability analyzers](https://dependencytrack.github.io/docs/next/),
[Trivy client/server](https://trivy.dev/docs/latest/references/modes/client-server/),
[Release 0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2).
