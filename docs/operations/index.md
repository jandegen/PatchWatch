# Operations

## Status and monitoring

```sh
kubectl -n patchwatch get pods,pvc,ingress,cronjobs
kubectl -n patchwatch logs deployment/patchwatch-bridge
kubectl -n patchwatch logs deployment/dtrack-api-server
kubectl -n patchwatch create job --from=cronjob/patchwatch-monitor patchwatch-monitor-manual
```

The daily monitor runs at 07:00 UTC and fails if an active host project marked with
`managed-by:patchwatch` and `asset-type:workstation` and version `current` has delivered no SBOM for 48 hours or has never been imported.
Feed CronJob/job failures into your existing Kubernetes monitoring (e.g.
`kube_job_status_failed`); the project installs no second monitoring stack.
The monitor itself needs only `VIEW_PORTFOLIO`. The team `inventory-monitor`, used jointly for monitoring, compliance and
delta reports, additionally has `VIEW_POLICY_VIOLATION` and
`VIEW_VULNERABILITY` (Dependency-Track 5 requires them for the BOM export with vulnerabilities).

Hosts that were never created cannot be detected without a target inventory. For this,
`python -m patchwatch.dtrack.monitor --expected-file expected-hosts.json` supports a list of the expected
**project names**, e.g. `["workstation-01"]`. Mount this file into the
monitor via your own secret/ConfigMap and set `EXPECTED_HOSTS_FILE`. Exit codes: 0 current, 1 stale/missing or inconsistent portfolio counters, 2 API error.
After 75 minutes of aggregation tolerance, empty portfolio counters are detected as an error despite an existing
host inventory. Details: [inventory.md](../usage/inventory.md).

Bridge: `/health` checks SQLite reachability, `/metrics` provides
`patchwatch_deliveries_total`, `patchwatch_deliveries_pending`,
`patchwatch_oldest_pending_seconds`. The endpoint is internal; for debugging use `kubectl port-forward
service/patchwatch-bridge 18082:8080`. Explicitly allow a Prometheus scrape via
NetworkPolicy if needed. Alert on open deliveries older than 15 minutes.
The number of successful deliveries is no proof of a complete host target inventory.

## Backups and restore

Kubernetes creates a verified PostgreSQL custom dump daily at 01:15 UTC on its own
PVC `patchwatch-backup`. Successful dumps are removed after 14 days. A failed
dump is never named as finished; job failures trigger an alert via the existing monitoring.
Before the dump, the job waits for a limited time for TCP reachability so that the brief application of
NetworkPolicies on new pods does not cause immediate failed attempts.
Compose starts backups with the profile `operations`, immediately and then every 24 hours into `./backups`.
Run a single backup manually:

```sh
docker compose --profile operations run --rm --entrypoint /bin/sh backup /scripts/backup.sh
kubectl -n patchwatch create job --from=cronjob/patchwatch-backup patchwatch-backup-manual
```

**A database dump alone is not enough for disaster recovery.** Additionally back up:

- the key-encryption key of Dependency-Track 5 (Compose `.secrets/dt_kek`, Kubernetes secret
  `patchwatch-dtrack-kek`): without it, the credentials stored in the secret manager are unreadable after a restore;
- the Dependency-Track file storage (Compose volume `dtrack` at `/data`, Kubernetes PVC `dtrack-storage`);
- the secrets `patchwatch-secrets`, `patchwatch-provisioning`, `patchwatch-monitor-key`,
  `patchwatch-integrations`, `patchwatch-trivy` and the registry pull credentials, encrypted outside the cluster;
- the bridge SQLite database including a consistent WAL state so that tickets are not created again.

Compose example for a consistent bridge copy and Dependency-Track data:

```sh
mkdir -p backups
docker compose exec -T bridge python -c "import sqlite3; s=sqlite3.connect('/data/bridge.sqlite'); d=sqlite3.connect('/data/bridge-backup.sqlite'); s.backup(d); d.close(); s.close()"
docker compose cp bridge:/data/bridge-backup.sqlite backups/bridge.sqlite
docker compose cp apiserver:/data backups/dtrack-data
```

Afterwards, replicate the backup encrypted to another location. A PVC in the same cluster is
no protection against cluster loss. Set up snapshots or external volume backups suited to the storage system in use
for all three data PVCs. Do not copy the bridge database without a SQLite backup or a complete
snapshot. Never put secret exports into Git or normal job artifacts.

Restore PostgreSQL in Compose (service interruption):

```sh
docker compose stop apiserver frontend gateway gateway-tls
# The dump must be present on the host; terminate all database connections beforehand.
cat backups/dtrack-<timestamp>.dump | docker compose exec -T postgresql sh -c \
  'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; pg_restore -U dtrack -d dtrack --clean --if-exists --exit-on-error'
# Restore the matching /data and secrets with the same encryption key version.
docker compose up -d --wait
```

For Kubernetes, scale the API deployment (`dtrack-api-server`) to 0 before the restore; use a temporary job with the
PostgreSQL image, the same database secret and access to the backup PVC/service.
Verify the restore including `/data` in isolation first, then scale the API back to 1.
No restore script deletes or overwrites a production database automatically.
RPO with a daily dump is at most 24 hours; RTO depends on restore and feed/index rebuild.

## Updates and key rotation

Versions and version lines are defined in Compose, Helm profiles, Dockerfiles, `ci/components.yml`
and the SPDX generator. The bridge Dockerfile follows `python:3.14-alpine3.22` and
updates Alpine packages at build time; other references are pinned more tightly. The declared
SPDX source inventory therefore does not describe the exact packages of each built image; for that, use the
image SBOMs from the [CI integration](../usage/ci-integration.md#6-this-repository-one-inventory-per-component).
Before updates, read release notes and migrations, adapt image/chart versions together,
run tests and a restore rehearsal, regenerate `python3 scripts/spdx.py` and merge changes via
merge request. Dependency-Track 5.x itself is updated with pinned tags; observe the release notes at
[Upgrading running instances](https://dependencytrack.github.io/docs/next/guides/administration/upgrading-instances/).

Upload key: create a new key for the team, distribute it via MDM, verify uploads, revoke the old
key. Update the provisioning secret accordingly. Rotate read keys separately
and restart the bridge/monitor. With existing local/cluster key files, the bootstrap does not create new
keys; replace manually revoked keys there as well.

PostgreSQL password: first change it in a controlled way via `ALTER ROLE`, then update the secret and pods.
A secret update alone does **not** change the password of an initialized database.
Webhook token: update the secret and the notification rule together, restart the bridge.
After a manual change, also update the admin password in `patchwatch-secrets` so that later
CI configuration keeps working. Never replace the encryption key without a DTrack migration procedure.

For GitHub Advisories, the protected CI variable `GITHUB_TOKEN` can be set in the production scope;
`patchwatch.dtrack.setup` enters the token into the Dependency-Track secret manager and enables the source.
The NVD matching needs no API key in v5 (`NVD_API_KEY` no longer applies).
OSV is enabled without credentials for the configured ecosystems. `OSV_ECOSYSTEMS`
can override the list; DTrack stores it semicolon-separated (commas in the
input are normalized). On the initial installation, the setup starts the first OSV synchronization
immediately so that it uses the enabled ecosystems (`POST /api/v2/vuln-data-sources/osv/mirror-runs`). Initial synchronization
and later matching can take a long time. Check in DTrack that the sources ran successfully;
a green pod alone does not prove current CVE data. OSS Index stays disabled without credentials;
optionally set `OSS_INDEX_USERNAME` and `OSS_INDEX_TOKEN`.

## Data scope and deletion

Configure role-based UI access in DTrack separately with the responsible people.
The upload team and monitoring team are technical accounts. They do not replace team/project ACLs
for human users. For confidential team inventories, enable the DTrack ACL mode and project assignments
before the rollout. No usage statistics or automatic patch actions.

Operating proposal: upload daily, warn after 48 hours; decommissioned machines
are deactivated after 30 days following approval and deleted after 90 days. No
unattended deletion job is deliberately active for this. Document the actual retention periods and responsibilities with
data protection/works council before the rollout. Source SBOMs are deleted locally after the run,
DTrack keeps the current project inventory and analysis history. The bridge outbox contains finding
and project names; it is kept for deduplication. A deletion concept must therefore also cover the outbox,
backups and external JIRA/chat data. Deleted dedupe entries can lead to new notifications
on repetition.


## Aborted analysis or deploy runs

The deploy job first rolls out the services and then runs API configuration and the
compliance report. An error in the report can therefore mark the job red although the
rollout was already successful; it is not an automatic rollback of the entire installation.
On `ConnectionResetError` or timeout during the report, first check API pod status, restarts,
logs and memory usage. After the API has recovered, run the deploy job again;
do not treat missing report artifacts as a passed compliance check.

On a Java heap overflow, the DTrack API exits with
`-XX:+ExitOnOutOfMemoryError` so that Kubernetes or Compose restarts it. It must not keep running
with a still-open health endpoint and damaged background tasks.
Take the size of SBOMs and graph roots into account in capacity planning; a
completed upload HTTP request alone does not confirm a successful evaluation.


## Version markers and scan freshness

`patchwatch-versions` corrects the latest marker of the managed CI projects every five minutes.
In Kubernetes, check errors with `kubectl -n patchwatch get jobs` and the logs of the job in question.
In Compose the service runs after `docker compose --profile operations up -d versions`; its logs
show changes or API errors. After key rotation, restart the service. The key
`versions_key` has management permissions and stays on the server, separate from CI upload and monitor.

A manual run with the already set-up key:

```sh
DT_URL=https://patchwatch.example.org DT_API_KEY_FILE=.secrets/versions_key \
  python3 -m patchwatch.dtrack.versions
```

The same run also **migrates** loose MR and branch versions (tags `scan-purpose:mr-feedback` or
`scan-purpose:branch`): it creates the parent project `<project path>` with the same version if it is missing, and
attaches the components beneath it. Only versions whose parent name matches a regular project of the same GitLab
project ID, and only parents with the same scope tags, are touched. The run is idempotent.

Afterwards it enables `AGGREGATE_DIRECT_CHILDREN` for CI, MR and branch parents with child projects,
even if they are already deeper in the tree. For every managed
GitLab project, a navigation project `<project path> @ all versions` is created above them:

```text
group/patchwatch                  all versions (without aggregation)
  group/patchwatch                main        (aggregates services)
    group/patchwatch/bridge       main
  group/patchwatch                mr-19       (aggregates services)
    group/patchwatch/bridge       mr-19
```

The folder has only `patchwatch-role:folder` and the GitLab project ID as tags, no
latest marker and no collection logic. It does not add up different scan states
and is not an inventory or notification target. Existing foreign parent assignments are
kept; name collisions are reported as errors. In the tree view, this allows collapsing the
entire repository. The native metrics calculation runs asynchronously.

If a version parent still contains inventory of its own, DTrack refuses the conversion with HTTP 409.
The regular run then reports the required admin run of `python3 -m patchwatch.dtrack.groups`;
it does not move or delete inventory itself. For the service migration, see
[CI hierarchy](../usage/ci-integration.md#multiple-inventories-hierarchy).

Projects of the old scheme `<project>/mr-feedback/<component>` are deleted once. Without `--apply` they are only
listed; only projects with tag `scan-purpose:mr-feedback` beneath an `mr-feedback` path segment count:

```sh
DT_URL=https://patchwatch.example.org DT_API_KEY_FILE=.secrets/versions_key \
  python3 -m patchwatch.dtrack.legacy            # list
DT_URL=... DT_API_KEY_FILE=... python3 -m patchwatch.dtrack.legacy --apply   # delete
```

Latest denotes the highest active stable release, or else the default branch. A repeated
upload of an older release does not change this selection. **Scan freshness** is read from *Last BOM Import*
of the inventory project; for the aggregating collection project, from its child projects. A latest tick
is no promise of a current scan. Commit and pipeline are linked under *External References*.
For overdue host uploads, the existing monitor remains responsible. Details and migration of
existing CI projects: [CI integration](../usage/ci-integration.md#3-what-appears-in-patchwatch).
