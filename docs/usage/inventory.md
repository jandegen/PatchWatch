# Hostnames, tags and visible findings

## Identity of a machine

A machine appears as a project with its **hostname**, e.g. `workstation-01`, and the
fixed version `current`. The agent detects the hostname automatically. `hostname` in the
configuration is an optional explicit override, e.g. for central preparation.
No `devhost-` prefix and no random UUID is used as the display name any more.

`host_id` is kept as the stable asset ID and is in the tag `asset-id:<id>`. After
registration, uploads address the **project UUID** from `project_uuid`. A name change
or repeated scan therefore creates no second inventory. A new upload creates no
new project version; `current` is marked as the latest version during registration.

The central registration needs administrative credentials; the running agent keeps
only `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`:

```sh
DT_ADMIN_PASSWORD_FILE=/secure/path/admin_password \
  python3 -m patchwatch.dtrack.register --config ~/.config/patchwatch/agent.json
# For a system installation: --config /etc/patchwatch/agent.json, run as the owner of the file.
```

Alternatively, use `DT_ADMIN_API_KEY_FILE`. The credentials are not written into the
agent configuration. The command updates name, tags, active status and
`isLatest` and stores only the project UUID locally. Existing UUIDs, components, findings,
analyses and ticket deduplication are kept. The former project
`devhost-<host_id>` is found and renamed automatically. If the assignment is ambiguous,
an administrator can explicitly determine the target with `--project-uuid <uuid>`.
Name collisions are rejected; projects are not merged automatically.

When the hostname or tags change, run the registration again. This is
deliberately an administrative task: DTrack 4.14 ignores tag changes of an existing
project made by a pure upload key. We therefore do not extend the key stored on the machines
with global write permissions. A deleted registered project must be
reassigned; a UUID upload does not silently create a replacement project.

## Tag convention

Project tags use `key:value`, lowercase, without spaces and commas.
Every key has exactly one value. Duplicate identical tags are removed; contradictory
values or invalid tags are rejected before the scan. Passwords and URLs do not belong in tags.

| Tag | Origin |
|---|---|
| `managed-by:patchwatch` | Marks projects managed by Patchwatch |
| `asset-type:workstation` | Machine software inventory |
| `host:workstation-01` | Hostname |
| `asset-id:<host_id>` | Stable asset identifier |
| `os:linux` / `os:darwin` | Operating system detected by the agent |
| `distro:ubuntu` | Linux distribution from `/etc/os-release`, if available |
| `agent-scope:user` / `agent-scope:system` | Permission scope of the installation |
| `team:platform` | Optional, explicitly configured owner |
| `environment:development` | Optional, explicitly configured environment |
| `asset-group:developer-workstations` | Optional, configured machine group |
| `asset-type:application`, `source:gitlab-ci`, `gitlab-project-id:<id>` | Projects from the [GitLab CI template](ci-integration.md) instead of machines; `team:`/`environment:` there from the template inputs |

A team is **not** guessed from user names or hostnames. The example configuration
therefore contains no fictitious team assignment. Detected tags must not be overwritten by contradictory
configuration values. The former prefixes `agent:` and `host-group:`
are normalized to `agent-scope:` and `asset-group:` when read.

The registered tag set corresponds to the agent configuration plus the detected attributes.
Team/environment tags added centrally must therefore also be in the configuration before
the registration is run again. Changes apply after a successful registration.
Bridge routes can use `team:*`, `environment:*` or `asset-group:*` as filters.
The Patchwatch notification rule processes only projects with `managed-by:patchwatch`.
The monitor identifies machines by `managed-by:patchwatch` together with
`asset-type:workstation`; old `devhost-*` projects continue to be recognized during migrations.
DTrack 4.14 assigns these tags to the **project**, not to every individual package copy.

## Where are components and findings visible?

- **Projects → hostname → Components / Audit:** actual inventory and findings of the machine.
- **Global components:** cross-project search mask. Enter a name such as `stdlib`, `certifi` or `bash`
  and run "Search". An empty search view is not an empty inventory. The registration
  marks `current` as the latest version so that the "latest project versions only" filter applies.
- **Dashboard:** aggregated portfolio metrics. These are calculated separately from project findings
  and can lag behind in time after a large import.

The setup and the registration request a portfolio refresh via the official
API. DTrack updates these metrics regularly every hour. A complete calculation
can take a while for large inventories. In the dashboard, the refresh button can also be used.
The daily monitor compares known project counts and finding counts with the
portfolio counters; after 75 minutes of import/aggregation tolerance, it reports missing counters
as an operational error. Monitoring still needs only `VIEW_PORTFOLIO`.

## What is guaranteed, what is not?

Detected and stored findings are visible on the project and in its audit view.
The Trivy integration was verified end to end with a real finding (`CVE-2021-44228`, `TRIVY_ANALYZER`).
For the developer PC, `CVE-2026-111943` and the certifi
advisory `GHSA-6q48-6c7w-9gw2` were also demonstrated in DTrack.

A **complete detection of every vulnerability** cannot be guaranteed: collection,
PURL/distro metadata, current databases and successful analyzer runs are prerequisites.
A version hit can also already be mitigated by a distribution patch or the trust store
actually used. Such assessments belong traceably in the finding audit;
do not suppress findings wholesale based on an old version string.

The severity limit `HIGH`/`CRITICAL` by default concerns only the **notification bridge**.
`MEDIUM` and `LOW` findings also remain visible in DTrack. A CVE can be tracked via an alias such as
GHSA; consider both identifiers in the audit view. A green upload
timer alone confirms neither error-free analyzers nor a current vulnerability database.


## Services and extensions

IDE/browser extensions appear as package components with technical ID and version;
identical installations are merged within the same ecosystem. The
[agent guide](agent.md#ide-and-browser-extensions) describes the supported products.
Static services from Compose files, in contrast, appear under **Services**. They prove
no running process and replace no image scan; see [service collection](services.md).

## Dependency graph

The agent obtains package dependencies from Syft's CycloneDX output and adapts the references
to the deduplicated components. References stay limited to their scan source;
file components, unknown targets and self-edges are not taken over.
The stable host node connects the roots of the subgraphs detected by the scanner.
Package-to-package edges come exclusively from the scanner. Isolated packages without detected
relationships stay completely in the component table but receive no invented
host dependency. An inventory without any detected relationships can therefore still have an
empty graph. Syft does not determine a complete runtime graph for every ecosystem from a file system.

A direct host edge to each of the more than 11,000 packages was discarded: besides the wrong
statement about direct dependencies, the large project field caused a Java heap overflow in DTrack 4.14
when loading all components. Anchoring detected subgraphs
avoids this multiplication and also keeps separate cycles reachable.

Earlier agent versions discarded `dependencies` during sanitizing. Projects already
imported get the graph only through a renewed upload with the current
agent version. Reload **Project → Dependency Graph** afterwards. For large host inventories,
first examine a single component; thousands of nodes can make the display
confusing. For an empty UI despite a renewed import, check the API output
`GET /api/v1/bom/cyclonedx/project/{uuid}` for actually present `dependsOn` edges;
the number of `dependencies` records alone is not sufficient, since DTrack also exports empty
entries. The compliance report counts anchorings at the host and package dependencies separately.
