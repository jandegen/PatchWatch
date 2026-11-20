# Concept: simplified agent distribution

As of: 16 November 2026. Proposal based on the repository. **Partially implemented:** the agent is
separated as a layer of its own (`patchwatch/agent` + `patchwatch/core`, standard library only);
`packaging/build.py` builds a reproducible zipapp, a `.deb` and (on macOS) a `.pkg` from it,
`patchwatch-agent --init-config` creates the profile with a new `host_id`, and the CI job
`agent-packages` publishes the artifacts. The package uses the system Python (≥3.12).
**Still open:** private Python runtime, signing/notarization, package SBOM, diagnostic command,
registration with target device metadata, update/rollback flows and everything on enrollment.

## Recommendation

Deliver the agent as a versioned installation package including the Python runtime and Syft.
A separate device profile contains configuration and credentials and is distributed via
Ansible or MDM. Installation, setup and updates thereby
become repeatable management actions; a Git checkout on endpoints is no longer needed.

First keep the existing direct upload to Dependency-Track and automate
registration from the management machine. Add an enrollment service of its own
only when devices without existing management are to be onboarded or
a reliably enforced permission per device is required.

## Starting point and concrete obstacles

| Today | Effect | Proposed change |
|---|---|---|
| `scripts/install-agent.sh` installs from a local checkout | Sources and build environment have to go onto every machine | Ready-made release packages |
| Python ≥3.12 and Syft must be installed beforehand | Different versions, paths and failure patterns | Tested, bundled runtime and scanner |
| `pip install --no-deps .` builds on site; build dependencies are therefore not excluded | Installation may need additional package index access | Build exclusively in CI |
| URL, scan roots and key are set up separately | Manual steps and configuration deviations | Centrally maintained profiles with device state |
| systemd/launchd files are copied but not enabled | A successful installation does not yet mean a regular scan | A separate setup step verifies and enables |
| `patchwatch.dtrack.register` needs administrative DTrack credentials | Registration remains an additional administrative flow | Central registration workflow |
| No agent release jobs, package storage or regulated updates | Updating and rollback remain manual work | Versioned artifacts and staged rollout |

Basis: [installer](../../scripts/install-agent.sh), [agent guide](../usage/agent.md),
[registration](../usage/inventory.md), [project metadata](../../pyproject.toml) and
[GitLab pipeline](../../.gitlab-ci.yml).

## Target flow for managed machines

1. The management installs an approved package version for operating system and architecture.
2. It takes over an existing `host_id` or creates a new one once. Cloned
   operating system images contain neither device identity nor credentials.
3. It collects hostname, operating system and distribution from the target device. A central
   registration job creates the project or updates it and returns
   `project_uuid`. Administrative credentials stay on the management machine.
4. Ansible/MDM writes profile, project UUID and upload key with restrictive permissions.
5. A new diagnostic command checks configuration, read permissions, scanner, TLS trust,
   API reachability and project assignment. The first full scan confirms the
   BOM import; only then does the rollout report the device as successfully set up.
6. The management enables the daily schedule. On temporary unreachability,
   the device stays recognizable as pending and the setup is repeated.

Targeted operation: one Ansible playbook or one MDM job per device group.
A manual path of package installation and profile import remains available for individual devices.
Secrets are passed neither as command line arguments nor in general download URLs.

Important prerequisite: `inventory_tags()` currently determines OS and distribution on the
executing machine. `patchwatch.dtrack.register` can therefore not yet be used unchanged to
register arbitrary remote devices. Registration must be able to process explicit,
validated target device metadata; the local call stays compatible.

## Packages and release process

| Target | Intended format | Distribution |
|---|---|---|
| Debian/Ubuntu systems with systemd | `.deb` | First versioned download, later an internal APT repository |
| macOS | Signed and notarized `.pkg` | MDM or manual package import |
| RPM-based Linux systems | `.rpm`, if a need is demonstrated | Existing Linux management, later an RPM repository |

Initial scope: Linux x86_64 and macOS arm64. Further architectures are added according to the actual
device inventory. This is a planning assumption, not a fleet analysis documented in the repository.
Windows stays outside this concept, since the agent needs platform-specific adaptations.

The package contains the agent, private Python runtime, Syft, service definitions and license notices.
A directory bundle with a fixed entry point is the preferred target; a single
self-extracting binary is not required for this. Runtime and scanner are started via
absolute paths. The concrete bundling is first verified in a build prototype,
including Linux compatibility limits and macOS signing. It changes the
maintenance responsibility: Python and Syft security updates need new agent packages.

For each release tag `vX.Y.Z`, CI builds the supported packages. Package version and Python project version
must match. The publication comprises checksums, a trustworthily
signed release attestation or signed repository metadata, an SBOM of the
components actually bundled, and build provenance. A checksum next to a download
alone does not replace a trustworthy signature proof.

The existing source SPDX and the container SBOMs do not replace this package SBOM.
In particular, the previous assumption "the agent has no third-party packages of its own" in
`ci/components.yml` and the CI documentation must be adapted to the bundled runtime.
macOS needs suitable build/test runners and signing access; their availability
is to be clarified before implementation. Endpoints need no GitLab build or admin token.

## Configuration, updates and operation

- **Separate software and device state:** program files under `/opt/patchwatch`,
  configuration and keys under `/etc/patchwatch`, state under `/var/lib/patchwatch`.
  The package installer overwrites neither `host_id`, `project_uuid`, profile nor keys.
- **Idempotent setup:** Rolling out again repairs package and service definitions
  but creates no new device. Name and identity conflicts abort with a clear
  error; projects are not merged automatically.
- **Deliberate scan profiles:** For example Linux system and macOS developer device with matching
  roots. Completeness, home access and macOS privacy permissions remain explicitly
  part of the profile; package installation alone grants no additional read permissions.
- **Diagnostics:** New commands for version, configuration check and local status; output
  with agent/Syft version, last scan and last confirmed import, without keys.
  The existing scan entry point is kept.
- **Scheduling:** Keep the Linux random delay; also provide a distributed
  start for macOS. Package installation starts no unscheduled full scan.
- **Updates:** The management distributes concrete versions first to pilot devices and then
  to further groups. Running scans are awaited before the swap; pause the schedule
  temporarily. No parallel write access to installation or device state.
- **Rollback:** The previous version stays available; configuration migrations are versioned and
  backward compatible or reversible with a protected backup. Identity and project UUID
  are kept. A package downgrade alone is not enough with an incompatible migration.
- **Uninstallation:** Stops the schedule and removes software. Device state and credentials
  are deleted only on explicit cleanup; central revocation is part of offboarding.

## Registration and keys: two stages

The detailed design of the second stage is in the [enrollment concept](enrollment.md).

**Stage 1 – use existing management.** A central job registers devices and distributes
their configuration. The agents keep the previous DTrack upload permissions, administrative
permissions stay central. Keys are distributed via the secret management of Ansible/MDM
and rotated independently of the software package. The central job and target device must use the same
persisted `host_id`; repetitions after partial failures must not create duplicates.

This stage simplifies distribution but offers no demonstrated permission boundary
per device: `project_uuid` is a target address, no access protection. The existing upload key
also has `PROJECT_CREATION_UPLOAD`. A shared key does not allow revoking an individual
device. Any separate keys must be checked for their actual DTrack permissions;
a mere split of the keys proves no project isolation.

**Stage 2 – optional enrollment and upload service.** For self-service, each device receives
a short-lived, single-use enrollment token from an authorized management process.
The service binds the registration to a device identifier and an approved profile,
registers the DTrack project centrally and issues a device credential of its own.
Repetitions after a connection abort are idempotent; a new device installation cannot
take over the previous identity merely by claiming a known `host_id`.

For effective isolation, later uploads go through this service. It enforces the assignment
of device credential to project UUID, limits uploads and keeps DTrack keys central.
An enrollment service that merely returns the same shared upload key does not solve the
isolation problem. Operation, availability, revocation, rotation and state database
are additional effort and justify the separate decision for this stage.

## Alternatives considered

| Variant | Benefit | Assessment |
|---|---|---|
| Only extend the existing installer | Quickly fewer manual steps | Interim solution; Python, build and update dependencies remain |
| Wheel with external Python/Syft installation | Small artifacts, simple Python builds | Sensible if the entire fleet already guarantees these prerequisites centrally |
| Native packages with private runtime and Syft | Uniform installation, clear update path | Recommended target; more build and patch responsibility |
| Container as standard agent | Known image distribution path | Not preferred for host inventory because of file system access, user profiles and desktop environments |
| Own updater and enrollment immediately | Independent of Ansible/MDM | Only with demonstrated need; significantly more server and security logic |

## Implementation in verifiable steps

1. **Package prototype:** Confirm device inventory and management path; fix one Linux and one
   macOS test device. Bundle runtime, Syft and service definitions. Demonstrate installation
   on clean systems without preinstalled Python/Syft and without a source checkout.
   Document minimum OS versions. Only then fix the final build technique.
2. **Managed rollout:** Add release jobs, package verification, diagnostics and central registration
   with target device metadata. Deliver an Ansible role and MDM installation recipe.
   Take over existing installations while preserving their identity; explicitly assign existing
   user-level installations before a system migration.
3. **Updates and operational maturity:** Trial pilot group, version overview, rotation, rollback and
   uninstallation. Add package repositories only if they simplify the chosen
   management path. Then decide on stage 2 based on actual need.

Acceptance criteria:

- One management job suffices from installation to the first confirmed BOM import;
  no manual JSON editing on the endpoint.
- After the package is provided, the installation needs no Python package index or
  reload access for Syft; API access is needed only for registration and upload.
- Repeated setup, upgrade and rollback preserve `host_id`, `project_uuid` and findings.
- A network outage creates a traceable pending/failed state;
  repetition creates no second project.
- Keys appear neither in the software package nor in process arguments or logs;
  administrative DTrack credentials exist exclusively in the central management.
- Demonstrated tests cover fresh installation, migration, name collision,
  missing TLS trust, interrupted setup and update during a running scan.
- Target for the pilot: at most five minutes of active administration time per device group,
  excluding package download and scan duration. Before/after values are collected in the pilot.
