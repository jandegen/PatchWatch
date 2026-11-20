# Architecture, data flow and limits

## Objectives

**Problem:** On developer machines, software is installed from many sources: package managers, Homebrew, global npm/pip installs, IDE plugins, container images and manually unpacked binaries. Without an inventory it stays unclear which versions are in use. When a new CVE is published, it cannot be answered who is affected.

**Goals:**

- A current, machine-readable inventory of the software in use per machine (SBOM in CycloneDX format).
- Continuous matching against vulnerability data. New CVEs trigger notifications without a rescan being necessary.
- Automatic notification of the responsible teams, with a JIRA ticket where needed.
- Low operating effort: one central service, one lean agent, exclusively open-source components.
- Privacy-compliant collection that covers only the software inventory (name, version, source, path) and no usage data.

**Non-goals:**

- Monitoring of employees, usage time or behavior.
- Replacement for a full endpoint security or MDM product.
- Automatic patching. The project detects and reports.

## Scope

| Area | Covered by this project |
|---|---|
| OS packages (deb, rpm, apk) | Yes |
| Language ecosystems (npm, PyPI, Go, Maven, Cargo, …) | Yes, as long as readable in the file system |
| Container images | Optional, via Syft at image level |
| Services from Compose files | Static inventory from names and image references; no runtime detection |
| Binaries without a package manager | Partially, depending on Syft detection |
| IDE and browser extensions | Yes, for supported editors and browsers on Linux/macOS; [scope and limits](../usage/agent.md#ide-and-browser-extensions) |
| Runtime behavior, usage statistics | No, deliberately excluded |

## Architecture

```
Dev machine                    Central stack                     Output
┌────────────────┐   SBOM    ┌──────────────────────┐  Webhook  ┌────────────────┐
│ Syft           │  (HTTPS)  │ Dependency-Track     │ ────────► │ JIRA / Slack / │
│ + timer        │ ────────► │ API server + Postgres│           │ Teams          │
│ (CycloneDX)    │           └──────────▲───────────┘           └────────────────┘
└────────────────┘                      │
                                        │ continuous synchronization
                          OSV · GitHub Advisories · NVD · OSS Index
```

**Data flow:**

1. The agent creates an SBOM of the configured sources with Syft and adds installed IDE/browser extensions from local metadata. Duplicate extension entries are merged.
2. The SBOM is transferred to the Dependency-Track API over HTTPS. There is one project per host.
3. Dependency-Track continuously matches the components against the vulnerability sources.
4. New findings and policy violations trigger notifications via webhook.
5. A bridge or a workflow tool turns them into JIRA tickets or chat messages.

## Components

| Component | Role | License |
|---|---|---|
| [Syft](https://github.com/anchore/syft) | SBOM generation on the machine | Apache 2.0 |
| [Dependency-Track](https://dependencytrack.org) | SBOM management, vulnerability matching, policies, notifications | Apache 2.0 |
| PostgreSQL | Database for Dependency-Track | PostgreSQL License |
| Kubernetes, Helm/Helmfile | Operation of the central service | n/a |
| Patchwatch bridge (Python/SQLite) | Persistent delivery to JIRA, Slack and Teams | Apache 2.0 |

**Vulnerability sources:** OSV and GitHub Advisories provide the more precise hits for ecosystem packages (npm, PyPI, Go, Maven). NVD/CPE is used additionally, but produces more false positives and false negatives. For OS packages, distro advisories are authoritative.

## Privacy and co-determination

In Germany, the introduction of technical systems suited to monitoring behavior or performance is subject to co-determination (§ 87 (1) no. 6 BetrVG). Involve the data protection officer and the works council before the rollout.

**Data minimization as a design principle:**

- Collected are package name, version, source, file path and detected license identifiers as well as hostname, asset ID and the
  inventory tags explicitly intended for assignment.
- Not transferred are usage times, start times, duration, file contents, browser history
  or extension permissions. Scanners read local package and extension metadata; absolute
  locations can contain user names. Define scan roots and `extension_homes` accordingly.
- The SBOM is deleted locally after the upload.
- Access to Dependency-Track is role-based; retention periods are documented.

Recommendation: describe the procedure in a works agreement or in the record of processing activities, including purpose, data scope and deletion concept.

## Known limitations

- **Matching quality:** CPE-based matching is imprecise. Ecosystem-native sources are significantly more reliable.
- **Blind spots:** Binaries without a package manager and tools outside the scan roots are detected only partially
  or not at all. Extensions are collected in the supported default paths; Safari,
  other IDEs and deviating profile paths are not covered. A collected extension does not
  yet guarantee CVE matching. Windows is currently not supported.
- **Scan load:** A full scan of `/` can take a long time on large machines.
- **Delay:** Findings appear only once the vulnerability databases have included the CVE and the host has delivered an SBOM once.

## Code structure

The Python package `patchwatch` is organized in layers. Imports point downwards only;
`tests/test_boundaries.py` checks this and ensures that imports inside functions
are resolvable as well.

| Layer | Contents | May import |
|---|---|---|
| `core` | HTTP client with redirect block, tag schema, SBOM reduction and upload, Compose services, SBOM quality | standard library only |
| `agent` | `config` (validated profile), `scanner` (Syft), `extensions` (IDE/browser extensions), `runner` (one run), `profile` (initial profile), `cli` | `core` |
| `dtrack` | `client` (REST client, admin login), `setup` (setup), `policies`, `groups`, `versions`, `scopes`, `register`, `monitor`, `compliance`, `legacy` | `core` |
| `ci` | `pipeline` (CI job), `bsi` (BSI check), `mr` (merge request and branch feedback), `delta` | `core`, `dtrack` |
| `bridge` | Webhook receiver, deduplication and delivery | `core` |

The agent thus forms an independently deliverable unit (`agent` + `core`): the zipapp from
`packaging/build.py` contains only these two packages. Invoke the tools with
`python3 -m patchwatch.<layer>.<module>`, for the agent and CI job `python3 -m patchwatch.agent` and
`python3 -m patchwatch.ci` respectively.
