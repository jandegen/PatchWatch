# Delta reports: changes compared to the previous version

The delta report compares a project version with its predecessor and shows what has changed in
**vulnerabilities**, **licenses**, **policy violations** and **components**. Dependency-Track
does not offer this by itself: each version is a project of its own there, and the built-in notifications
report individual events, not a comparison of two versions.

The report is created

- automatically in the job `patchwatch-sbom` of the [CI template](ci-integration.md), right after the upload, or
- by hand or via cron through `python -m patchwatch.ci.delta`.

Output: `patchwatch-delta.md` (readable), `patchwatch-delta.json` (machine-readable), the job log and optionally
webhook (Slack, Mattermost) as well as email.

For reports directly in the merge request, there is the optional [MR feedback loop](mr-feedback.md).
It compares the MR commit with an exact target branch commit via separate SBOM artifacts.

## What is compared

| Area | New | Fixed / dropped | Notes |
|---|---|---|---|
| Vulnerabilities | Identifier + component only in the new version | only in the old version | A vulnerability that survives a component update counts as *unchanged*. Findings with analysis state `not_affected`, `false_positive` or `resolved` do not count. |
| Policy violations | Rule + component only new | only old | Only unsuppressed violations, separated by LICENSE/SECURITY and WARN/FAIL. |
| Licenses | new license IDs in the project, changed license of a component, components without license information | – | A change is a reason for review, not a legal assessment (see [policies](../configuration/policies.md)). |
| Components | added | removed, version change | Components are identified by their package URL without version. |

Excerpt of a report:

```
# PatchWatch delta: team/app v1.4.0
Compared with **v1.3.0**. Components: 212 → 215.

| | New | Fixed / resolved | Unchanged |
| Vulnerabilities | 2 | 5 | 14 |
| Policy violations | 1 | 0 | 3 |
...
## New vulnerabilities
- **CRITICAL** CVE-2026-1234 in pkg:npm/foo
```

## Which version is the predecessor?

1. `PATCHWATCH_DELTA_BASELINE` (input `delta_baseline`), if set.
2. For tags (`v1.4.0`): the next lower release version, sorted **numerically** (`v1.10.0` is above `v1.9.0`).
   A rerun of an old pipeline is therefore never compared with a newer version.
3. For the default branch (`main`): the highest existing release.
4. Versions of MRs (`mr-<IID>`, `base-…`) and feature branches (tags `scan-purpose:…`) are never
   automatic predecessors; only `PATCHWATCH_DELTA_BASELINE` can explicitly choose them. The
   MR report compares with the version of the respective target branch instead.
5. If there is no predecessor (first release), the report says "nothing to compare with yet". Nothing is sent.

The choice of the comparison version is independent of the latest tick: even the release marked as latest
remains a comparison base for the default branch.

The default branch is overwritten on every run. A comparison "main of yesterday against main of today" is
therefore not possible; release tags exist for that.

## Setup in CI

**Prerequisite:** the read key `PATCHWATCH_READ_KEY` (team `inventory-monitor`, see
[CI integration, 1.1](ci-integration.md)). Without it, no delta report runs. The permissions
`VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION` and (since Dependency-Track 5) `VIEW_VULNERABILITY` suffice; the
vulnerabilities come from the BOM export (variant `withVulnerabilities`, which in v5 requires `VIEW_VULNERABILITY`),
not from the findings list.

After including the template, the report is **active by default**. Inputs:

| Input | Default | Meaning |
|---|---|---|
| `delta` | `true` | Create the delta report |
| `delta_baseline` | empty | Fixed comparison version instead of the automatic previous version |
| `delta_notify` | `relevant` | `relevant`: only for new vulnerabilities/violations or license changes; `always`; `never` |

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      delta_notify: always
```

The report is purely informational: if it fails (e.g. missing permissions), the job reports "Delta report skipped",
and the pipeline continues. A gate against *new* findings is deliberately not provided; `fail_on` continues to check the
entire inventory of the version.

### Configuring delivery

Credentials belong as **masked/protected** CI variables at group level, never in the `.gitlab-ci.yml`.

| Variable | Purpose |
|---|---|
| `PATCHWATCH_DELTA_WEBHOOK` | HTTPS URL of a Slack or Mattermost incoming webhook. `{"text": "<Markdown>"}` is sent. HTTP is rejected. |
| `PATCHWATCH_DELTA_SMTP_HOST` | SMTP server; enables email delivery together with `…_MAIL_TO` |
| `PATCHWATCH_DELTA_SMTP_PORT` | Default `587` (STARTTLS); `465` uses implicit TLS. Unencrypted delivery is not provided. |
| `PATCHWATCH_DELTA_SMTP_USER` / `PATCHWATCH_DELTA_SMTP_PASSWORD` | Login, optional. The password also as `…_PASSWORD_FILE` |
| `PATCHWATCH_DELTA_MAIL_FROM` | Sender, default `patchwatch@<smtp-host>` |
| `PATCHWATCH_DELTA_MAIL_TO` | Recipients, separated by comma |

Webhook and email are independent of each other. A failed delivery appears in the log (without URL
and credentials) and does not abort the job. For teams or systems with a different message format, process the
JSON report from the artifact further.

Further variables:

| Variable | Default | Meaning |
|---|---|---|
| `PATCHWATCH_DELTA_WAIT` | `300` | Seconds the job waits for the vulnerability analysis |
| `PATCHWATCH_DELTA_DIR` | Project directory | Target folder of the report files |

Dependency-Track analyzes vulnerabilities **after** the BOM import. The job therefore rereads the new version
every 20 seconds until two readings match or the wait budget
`PATCHWATCH_DELTA_WAIT` is reached. Two identical readings are a stabilized snapshot,
no proof of finished analyzers; even an initially empty result can appear stable.
Without stabilization, the report contains the note "findings may be incomplete". With
`PATCHWATCH_DELTA_WAIT=0`, the waiting is skipped. This waiting phase does not update the policy violations
read earlier by the CI gate (see [CI limits](ci-integration.md#4-limits-and-notes)).

## By hand or via cron

```sh
DT_URL=https://patchwatch.example.org \
DT_API_KEY_FILE=/secure/path/monitor_key \
  python3 -m patchwatch.ci.delta --project team/app --version v1.4.0 --output-dir /tmp/delta
```

| Option | Meaning |
|---|---|
| `--project` | DTrack project name, for monorepos `group/project/component` |
| `--version` | Version to report on |
| `--baseline` | Comparison version; without it, the automatic previous version |
| `--output-dir` | Folder for `patchwatch-delta.md` and `.json` (default `.`) |
| `--wait` | Seconds to wait for the vulnerability analysis (default `0`) |

Delivery and mode are controlled via the same `PATCHWATCH_DELTA_*` variables. Errors return exit code 1.
After installation, the command is also available as `patchwatch-delta`.

Comparison of two arbitrary versions without delivery:

```sh
PATCHWATCH_DELTA_NOTIFY=never python3 -m patchwatch.ci.delta --project team/app --version v1.4.0 --baseline v1.2.0
```

## Limits

- The report shows only what Dependency-Track knows. If a package is missing in the SBOM, it is also missing in the comparison.
  The report is a snapshot at pipeline run time. Vulnerabilities that become known only later for an
  already published version are not reported; the notifications of the
  [bridge](../configuration/alerting.md) exist for that. A new report is created on the next run or via `patchwatch.ci.delta`.
- Suppressed findings are recognizable only via their analysis state (see table above).
- Reports contain component names and vulnerability IDs. Treat them like an internal inventory and send them only to
  trusted channels. The artifacts expire after one week.
- Per section, the Markdown report shows at most 40 lines; the JSON is complete.
