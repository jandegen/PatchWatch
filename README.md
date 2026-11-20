# Patchwatch

Patchwatch records the software on developer machines and in GitLab projects as
SBOMs, matches the inventory against vulnerability sources through Dependency-Track, and
reports findings and license violations to the responsible teams.

It supports Linux and macOS, directory and image scans with Syft, and metadata of
selected IDE and browser extensions. The central installation consists of
Dependency-Track, PostgreSQL, the frontend, the bridge and the Trivy server.
Patchwatch detects vulnerabilities; it does not install updates on endpoints.

## Architecture

![Architecture: agents and GitLab CI upload SBOMs to Dependency-Track. Trivy and vulnerability sources provide analysis data; the bridge sends notifications.](docs/assets/architecture.svg)

The agent and CI create the software inventory with Syft. Dependency-Track stores
and analyzes the SBOMs and shows findings in the web interface. The bridge
forwards filtered notifications and retries on delivery failures.
The central stack runs with Docker Compose or on Kubernetes.

## Getting started

1. [Quick start with Docker Compose](docs/getting-started.md) for the first local installation.
2. [Choose an installation](docs/installation/index.md): Compose or Kubernetes with Helmfile.
3. [Set up the agent](docs/usage/agent.md) or [connect GitLab projects](docs/usage/ci-integration.md).
4. Configure [Keycloak login](docs/configuration/oidc.md), [policies](docs/configuration/policies.md)
   and [notifications](docs/configuration/alerting.md).
5. Set up [backups, monitoring and updates](docs/operations/index.md) before regular operation.

The **[documentation overview](docs/README.md)** guides you through all guides,
references and not yet implemented designs. All examples use
neutral domains and project paths; before a deployment, adapt the
[installation parameters](docs/installation/customization.md) to your own environment.
The checked-in Kubernetes profiles are a reference deployment to be adapted.

## Usage

- **Record machines:** configure the agent, store the upload key and enable the regular scan.
- **Check projects:** include the CI template and upload repositories or container images as SBOMs.
- **Handle findings:** assess vulnerabilities and license violations in the web interface; use delta or MR reports where needed.
- **Inform teams:** configure notification targets and filters so that relevant findings arrive as a ticket or chat message.

## Features

- Host inventory with stable device assignment, canonical tags and registration.
- CycloneDX SBOMs from directories, container images and GitLab pipelines.
- Vulnerability analysis with Dependency-Track and its native Trivy integration.
- Security and license rules, compliance reports and optional CI gates.
- Delta reports and findings feedback for merge requests.
- Persistent notifications via webhooks, JIRA, Slack and Teams.
- OIDC login with Keycloak groups and separate task permissions.

The [architecture overview](docs/reference/architecture.md) describes the data scope,
detection limits and privacy. An enrollment service and
agent installation packages (`.deb`, `.pkg`) are built with `packaging/build.py` ([agent](docs/usage/agent.md)); signing and the private runtime are still a [design](docs/design/README.md).

## Development and testing

Python ≥3.12; the application code needs no additional Python runtime packages.
Helm and Helmfile are required for deployment checks.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/spdx.py --check
helm lint deploy/helm/patchwatch
python3 packaging/build.py deb      # agent package into dist/
```

Code structure: `patchwatch/core` (shared), `agent` (host agent, packageable on its own),
`dtrack` (Dependency-Track client and administration), `ci` (GitLab CI jobs) and `bridge`.
`tests/test_boundaries.py` checks the allowed dependencies between the layers;
details in the [architecture overview](docs/reference/architecture.md#code-structure).

After changes to versioned source files, run `python3 scripts/spdx.py`
so that the [SPDX source inventory](docs/reference/licenses.md) stays current.

## License

Patchwatch is licensed under **Apache-2.0**: [LICENSE](LICENSE), [NOTICE](NOTICE).
Declared dependencies and scope of the inventory:
[Licenses and SPDX](docs/reference/licenses.md).
