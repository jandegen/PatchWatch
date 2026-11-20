# Agent for Linux and macOS

## Installation via package (recommended for managed machines)

The agent can be packaged independently of the rest of the project: `patchwatch/agent` and
`patchwatch/core` need only the Python standard library. `packaging/build.py` reproducibly creates a zipapp
and the installation packages from them; the CI job `agent-packages` stores them as
artifacts in `dist/`.

```sh
python3 packaging/build.py pyz                 # dist/patchwatch-agent.pyz
python3 packaging/build.py deb                 # dist/patchwatch-agent_<version>_all.deb
python3 packaging/build.py deb --syft ./syft   # bundle Syft (architecture-specific)
python3 packaging/build.py pkg                 # macOS: dist/patchwatch-agent-<version>.pkg
sudo apt install ./dist/patchwatch-agent_1.0.10_all.deb
```

The package installs the launcher `patchwatch-agent`, the zipapp under `/usr/lib/patchwatch/`, the
systemd units (on macOS, a launcher in `/usr/local/bin` and the LaunchDaemon) and creates
`/etc/patchwatch/agent.json` with a new `host_id` (`patchwatch-agent --init-config`). An
existing configuration is never overwritten. The schedule is **not** enabled: first enter
`url` and key, run `sudo patchwatch-agent` once, then enable the timer
(see below). The package requires `python3 >= 3.12`; with `--syft`, Syft is included, otherwise it must be
present. A private Python runtime, signing and notarization are not yet part of the
build ([concept](../design/agent-distribution.md)). The `.pkg` is built only on macOS
(`pkgbuild`) and has not yet been tried on a device.

## Installation from the checkout (development, individual machines)

Prerequisites: Python ≥3.12, Syft and network access to the HTTPS API. Reference version
for Syft: **1.57.1**. Obtain and verify the release archive and checksums from the
[official release](https://github.com/anchore/syft/releases/tag/v1.57.1),
or distribute Syft through the existing package management. The installer does not download third-party
installation scripts. Syft must be in the service's PATH; otherwise set an
absolute `syft` path in `agent.json`.

```sh
sudo bash scripts/install-agent.sh
sudoedit /etc/patchwatch/agent.json
# Securely transfer the key from the DTrack team sbom-upload to /etc/patchwatch/api-key:
sudo chmod 600 /etc/patchwatch/api-key
# Optionally register administratively first, see inventory.md.
sudo patchwatch-agent
```

Before the installer, provide a checkout on the target machine and run the commands
from its root directory. In `agent.json`, check at least `url`,
`api_key_file` and the desired `roots`. The bundled URL is a
placeholder (`https://patchwatch.example.org`) and must be replaced; the installer generates `host_id`.

The upload key is created by the central setup with `patchwatch.dtrack.setup`:

| Installation | Source on the server |
|---|---|
| Docker Compose | `.secrets/upload_key` after the [Compose setup](../installation/compose.md) |
| Kubernetes | Secret `patchwatch-provisioning`, field `upload_key` |

Transfer the file securely to the target machine and install it there as
`/etc/patchwatch/api-key` with owner `root` and mode `0600`.
For an agent directly on the Compose server, this works from the checkout with
`sudo install -o root -m 0600 .secrets/upload_key /etc/patchwatch/api-key`.
Distribute only this upload key. The agent receives exclusively `BOM_UPLOAD` and
`PROJECT_CREATION_UPLOAD`, no administrative or portfolio read access.

## Connecting to a Compose server

For remote machines, first set up [Compose with HTTPS](../installation/compose.md#https-for-remote-agents).
`url` is then for example `https://patchwatch.example.org:8443`,
without `/api`. DNS, port forwarding and CA trust must work on every agent machine.
Compose service names such as `apiserver` are resolvable only in the container network.
The agent runs as a host service; Compose does not start it automatically.

A first local scan on the same machine as the Compose stack is also possible without a
system installation. After the quick start and with Syft in the PATH, in the checkout:

```sh
python3 - <<'PY'
import json, os, socket, uuid
from pathlib import Path
os.umask(0o077)
path = Path('.secrets/agent-local.json')
config = json.loads(path.read_text()) if path.exists() else {
    'url': 'http://localhost:8080',
    'allow_http': True,
    'host_id': str(uuid.uuid4()),
    'hostname': socket.gethostname(),
    'agent_scope': 'user',
    'api_key_file': str(Path('.secrets/upload_key').resolve()),
    'roots': [str(Path.cwd())],
    'scan_extensions': False,
    'lock_file': str(Path('.secrets/agent-local.lock').resolve()),
}
path.write_text(json.dumps(config, indent=2) + '\n')
PY
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  python3 -m patchwatch.dtrack.register --config .secrets/agent-local.json
python3 -m patchwatch.agent --config .secrets/agent-local.json
```

With a different `HTTP_PORT`, adapt both local URLs. This example records
only the checkout and deliberately uses HTTP on loopback. For a complete
system inventory, use the system installation and suitable scan roots;
for it, adopt the same `host_id` and, if applicable, `project_uuid` if it is meant to
continue the local test inventory.
`ALLOW_HTTP=true` controls the administrative registration; the agent instead reads
`allow_http` from its JSON file. For HTTPS, remove this field.
Administrator credentials stay with the operator. Remote hosts can be registered with a
copy of their target configuration on the operator's machine; afterwards,
transfer the updated file with `project_uuid` back to the host.

After a successful upload, check the inventory under **Projects → hostname → current → Components**.
The agent waits for the BOM import; findings can arrive later. Only after a successful test run,
activate the timer or LaunchDaemon described below.

The DTrack project is named like the machine (e.g. `workstation-01`), version `current`.
The installer additionally generates a stable `host_id`. After the administrative registration,
uploads go via `project_uuid`; renaming and tag changes therefore need no
new inventory. Registration, tag schema and migration are described in [inventory.md](inventory.md).
The hostname is transferred according to the desired device assignment;
user names are still not used as identity automatically.

Configuration example: [`agent/agent.example.json`](../../agent/agent.example.json).

| Setting | Meaning |
|---|---|
| `url` | HTTPS base URL, without `/api` |
| `allow_http` | Default `false`; set to `true` explicitly only for local HTTP tests |
| `host_id` | Stable asset ID, additionally tagged as `asset-id:*` |
| `hostname` | Optional display name; by default the automatically detected hostname |
| `project_uuid` | Target project after administrative registration, stays the same on renaming |
| `agent_scope` | `user` or `system`, matching the installation |
| `api_key_file` | Key file, mode `0600` or `0400` |
| `roots` | Syft scan directories; default `/usr`, `/opt`; `[]` disables directory scans |
| `scan_extensions` | Collect IDE/browser extensions; default `true`; independent of `roots` |
| `extension_homes` | Optional: absolute user home directories; automatic detection if omitted; `[]` disables collection |
| `images` | Optional Syft image sources, e.g. `registry:registry.example/tool:1.2` |
| `tags` | Additional canonical tags such as `team:platform`; set team only if the assignment is known |
| `excludes` | Additional Syft exclusions relative to the respective scan root |
| `detect_services` | Default `true`: upload services of all Compose files under `roots` (up to depth 5; name and image only) as CycloneDX services |
| `scan_timeout` | Seconds per scan; default 7200 |
| `lock_file` | Prevents concurrent scans of the same host |

A full scan is possible with `roots: ["/"]`. Pseudo file systems, temporary directories,
Docker/containerd storage and macOS `/System`, `/Volumes` are excluded. For other
roots, adapt exclusions relatively. Homebrew on Apple Silicon needs `/opt/homebrew`,
on Intel usually `/usr/local`. For user packages and repositories, explicitly include the
corresponding directories. Limited roots do **not** automatically record all
OS package databases; if needed, include `/var/lib/dpkg`, `/var/lib/rpm`, `/lib/apk` or scan `/`.
With multiple roots, identical components are merged. Syft still receives
one scan call per configured root; avoid overlapping roots so as not to do scan work
multiple times. Extension collection needs no additional Syft calls. The agent extends the
directory default catalogs with `+javascript-package-cataloger` so that global npm installs in particular
are recorded. An empty inventory is rejected as protection against accidental overwriting; set
`allow_empty: true` only for deliberately empty sources. Upload limit: 128 MiB.

## Services from Compose

`detect_services` by default collects static service names and image references from
Compose files under `roots`. Search limits, merging of identical names and differences
from a running service are described in the [service guide](services.md). Syft exclusions
are not applied to this separate reader.

## IDE and browser extensions

By default the agent additionally reads installed extensions in the usual
user directories on Linux and macOS. No further Syft scans are started for this
and no editors, browsers or extensions are executed.

- **VS Code**, Insiders, Code OSS, Cursor and Windsurf, including the respective
  supported `.vscode-server`/`.cursor-server`/`.windsurf-server` directories:
  `extensions/*/package.json`.
- **JetBrains**: plugin descriptors in `META-INF/plugin.xml` and plugin JARs under
  `~/.local/share/JetBrains/*/plugins` or
  `~/Library/Application Support/JetBrains/*/plugins`.
- **Chrome, Chromium, Brave, Edge and Vivaldi**: `manifest.json` in the extension directories
  of all profiles under the usual configuration directories. For Chromium/Chrome, selected
  Snap/Flatpak default paths are also taken into account.
- **Firefox**: unpacked extensions and XPI archives in the profile directories;
  on Linux including the Snap/Flatpak default paths.

When run as root, user homes are determined from the operating system user database;
without root, only the own home is taken into account. An explicit selection is possible:

```json
"scan_extensions": true,
"extension_homes": ["/home/alice", "/home/bob"]
```

On macOS, use `/Users/alice` accordingly. Homes must be readable; macOS privacy permissions
can additionally limit access. Deviating editor/browser profile paths, Safari extensions
and other IDEs are currently not covered. Existing installation files are inventoried,
including disabled extensions and older versions still present; the activation state is
not determined. Faulty or unreadable metadata produces a warning without user paths.

The identity consists of ecosystem, technical extension ID and version. Identical extensions
in multiple user accounts, profiles or editors are transferred once; their locations are
merged. Different versions stay separate. A Syft package entry of the same manifest
or plugin JAR is merged with the extension based on location and version;
contained npm/Java libraries and known dependency relationships are kept.
Dependencies inside extensions are recorded only as far as the Syft scan roots
cover them. The generic PURLs identify extensions unambiguously but guarantee no
CVE matching in Dependency-Track.

Only technical ID, version, ecosystem, location and, if applicable, a short license statement
are read. Descriptions, permissions, browser history, settings and extension code
are not transferred. As with Syft, absolute locations can contain user names.
For pure image scans, set `roots: []` and `scan_extensions: false`.

Manifest formats: [VS Code](https://code.visualstudio.com/api/references/extension-manifest),
[JetBrains](https://plugins.jetbrains.com/docs/intellij/plugin-configuration-file.html),
[Chromium](https://developer.chrome.com/docs/extensions/reference/manifest),
[Firefox](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json).

Component type, package name/group, version, PURL/CPE, package paths as well as detected
license IDs, short license names and SPDX expressions are kept. Full license texts and
licensor metadata are not transferred. Details: [licenses.md](../reference/licenses.md).
File components, descriptions, authors, Syft metadata and contents are removed. PURL/CPE
describe package coordinates and origin for matching. Absolute package paths can contain
personal names in home directories; align scan roots accordingly.
Syft reads local files for detection; the sanitized SBOM does not transfer their contents.
Raw SBOMs are only in the private temporary directory and are removed even on errors.
A power failure/SIGKILL can leave temporary files behind; keep the system's own TMP cleanup active.

The upload uses limited retries for temporary HTTP/network errors, verifies TLS and
waits for the DTrack processing token. This confirms the completed BOM import;
the subsequent vulnerability matching can take longer. Distribute proxy and CA settings
via the Python standard environment (`HTTPS_PROXY`, `SSL_CERT_FILE`). Do not disable TLS verification.

Enable on Linux:

```sh
sudo systemctl enable --now patchwatch-agent.timer
systemctl list-timers patchwatch-agent.timer
journalctl -u patchwatch-agent.service
```

The persistent daily timer starts from 02:00 with up to two hours of random delay.
For the system inventory, the service runs as root, with `nice`, idle I/O and systemd hardening.
The registry login for optional private images must be available to the service account.

Enable on macOS:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/eu.patchwatch.agent.plist
sudo launchctl kickstart system/eu.patchwatch.agent
```

The LaunchDaemon runs on load and daily at 03:00. Set up log rotation for
`/var/log/patchwatch-agent.log` via the existing MDM/newsyslog configuration.
Rollout via Ansible/MDM: install the package, distribute configuration and key with restrictive permissions,
a one-off test run, then enable the schedule. The central deployment does not automatically install
agents on third-party machines.
