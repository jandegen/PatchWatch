# Services from Compose files

The agent and the regular [CI template](ci-integration.md) can record **CycloneDX services**
in addition to software packages. These are static statements from Compose files, no proof of
running processes or services actually deployed. NeuVector and a Kubernetes
runtime inventory remain [open TODOs](../design/roadmap.md).

## Configuring collection

For the Linux/macOS agent, `detect_services` is `true` by default. The configured
`roots` are searched; `extension_homes` and image contents are no additional search roots.
Compose detection can be switched off with `detect_services: false`.

In the CI template, the input of the same name controls the search under `scan_paths`. Additional
service names can be specified via `services`:

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      services: 'api worker'
      detect_services: true
```

The template and job image used must already contain these inputs; until the next
release is published, use a matching commit and the corresponding `ci:<commit-sha>` image.
Explicit names consist of letters, digits, `.`, `_`, `-`, start with a letter
or a digit and are at most 64 characters long. For exclusively explicit
names, set `detect_services: false`. They are also taken into account with `mode: parent`.

## Data scope and deduplication

The reader takes over the service name and a literal image reference as `patchwatch:image`; an
existing literal image tag can be taken over as the version. Compose variables are
not resolved. Environment, secrets, volumes, commands, ports and endpoints are not
transferred. Image references can reveal internal registry/repository names.

Identical service names are merged across all search roots and Compose files. With
differing images, the first find wins. In CI, explicit names take precedence over detected
entries; for such names, the automatically detected image metadata statement is therefore dropped.
Services of the same name from different projects can therefore collapse. Services stay
separate from package components and create no invented dependency edges.

## Limits and visibility

- Considered are `compose.yaml`, `compose.yml`, `docker-compose.yaml` and
  `docker-compose.yml`, up to five directory levels below the respective root. At most 200
  automatically detected services, sorted by name, are taken over.
- `.git`, `node_modules`, `vendor`, `venv`, `.venv`, `__pycache__`, `site-packages`, `proc` and
  `sys` are skipped during descent. Unreadable files are omitted.
  Syft `excludes`/CI `exclude` apply only to Syft, not to this separate reader.
- The reader supports service definitions with indentation under a top-level `services:` key,
  not a full YAML/Compose reconciliation. Flow notation, anchors, includes, overrides,
  profiles and variables are not evaluated as by `docker compose config`. No
  Docker/Compose command is executed and no service is started.
- In Dependency-Track, the entries are on the project under **Services**, not under
  **Components**. A service entry does not scan the referenced image; configure `images`
  or an inventory of components of your own for that.
- Services alone do not satisfy the check for a non-empty package inventory. Explicit
  CI collection projects remain exempt from this check. With `mode: parent`, services are in
  the dedicated child project `<project>/services` of the same version; the parent remains a pure
  aggregation container. The parent job updates the service child project even when aggregation is
  already active. The [migration of existing parents](ci-integration.md#multiple-inventories-hierarchy)
  copies and verifies their service inventory before it is removed from the parent.
- The [MR feedback loop](mr-feedback.md), delta reports and compliance gates currently
  do not compare service inventories. Packages and findings still apply to these checks.
