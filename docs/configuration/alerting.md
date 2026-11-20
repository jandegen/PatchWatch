# Alerting and ticketing

Dependency-Track sends `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY` and
`POLICY_VIOLATION` to `http://patchwatch-bridge:8080/webhook/<token>` (Compose: `bridge`).
The initial API setup creates the notification rule with the tag filter `managed-by:patchwatch`.
The high/critical policy is likewise limited to this management tag; further
[security/license rules](policies.md) have their own scopes. The [canonical tag schema](../usage/inventory.md) keeps collection and routing consistent.
In the cluster, the bridge is reachable only from the API pod and has no public ingress.
Dependency-Track 5 restricts outbound connections: the bridge (and Trivy) are therefore explicitly listed in
`DT_OUTBOUND_ALLOWED_DESTINATIONS` (Compose `compose.yaml`, Kubernetes `deploy/environments/dtrack.yaml`).
An additional non-public webhook address must be added there.
The v5 format differs from the v4 format: groups are named `GROUP_NEW_VULNERABILITY` etc. and
`policyViolation.condition` replaces `policyCondition`. The bridge accepts both forms; the
deduplication keys stay the same so that findings already reported are not reported again.
The token is a random URL path component of at least 32 characters; do not log webhook URLs.
Allow external bridge operation exclusively via HTTPS and restricted access.

Targets are deliberately empty at first: real JIRA/chat delivery requires the organization-specific
URLs and credentials. An empty `routes.json` accepts valid webhooks
but creates no delivery. **Configure and test targets before the agent rollout.**

Example `routes.json` (real URLs contain secrets and belong in a secret):

```json
[
  {
    "name": "platform-slack",
    "kind": "slack",
    "url": "https://hooks.slack.com/services/REPLACE",
    "tags": ["team:platform"]
  },
  {
    "name": "platform-jira",
    "kind": "jira",
    "url": "https://jira.example.org",
    "project": "SEC",
    "issue_type": "Task",
    "token_env": "JIRA_TOKEN",
    "tags": ["team:platform"]
  },
  {
    "name": "tools-teams",
    "kind": "teams",
    "url": "https://example.webhook.office.com/REPLACE",
    "projects": ["workstation-01"]
  }
]
```

Every route has a stable, unique `name`. `tags` and `projects` are optional filters:
within one filter a single match suffices; if both are given, both must match.
Without a filter, the target receives all findings. If the default notification contains no tags,
the bridge resolves them via the DTrack API with the separate `VIEW_PORTFOLIO` key.
Kubernetes sets up this access automatically. The assignment thus stays current even after a
team change. Errors while reloading lead to HTTP 503, not to silent discarding.

By default only `HIGH` and `CRITICAL` are forwarded (`MIN_SEVERITY`). Policy violations
often have no vulnerability severity and bypass the severity filter. This also applies to
license and other WARN rules; policy name and state determine the finding, not automatically
high/critical. A fix filter is not implemented:
standard webhooks provide no reliable, uniform fix status. For this optional
extension, the bridge would have to evaluate further ecosystem/repository data.

## Prioritization with CISA KEV and EPSS

The bridge uses two public sources and falls back to plain severity if they fail:

- **CISA KEV** (`KEV_URL`): catalog of known exploited vulnerabilities, loaded daily and stored in the
  SQLite database. On errors, the last state remains valid (new attempt after one hour).
- **FIRST EPSS** (`EPSS_URL`): exploitation probability per CVE, cached per CVE for one day and
  queried only at delivery so that the webhook never waits for it.

`KEV_ENABLED` / `EPSS_ENABLED` (default `true`) switch the sources off; `EPSS_HIGH` (0.5) and
`EPSS_MEDIUM` (0.1) set the thresholds. Helm: `bridge.enrichment.*`, Compose: `ENRICHMENT_ENABLED`,
`KEV_URL`, `EPSS_URL`.

Priority per event: KEV = `kev`; EPSS ≥ 0.5 or `CRITICAL` = `high`; EPSS ≥ 0.1, `HIGH` or policy = `medium`; otherwise `low`.

- KEV hits bypass `MIN_SEVERITY` and are forwarded even for `MEDIUM`/`LOW`.
- Chat messages get `[KEV]` or `(EPSS 87%)`; Jira tickets get the label `kev` as well as due date,
  ransomware note and EPSS in the description.
- The Jira priority is set only if the route contains a `priority_map` (priority names
  differ per instance): `"priority_map": {"kev": "Highest", "high": "High", "medium": "Medium", "low": "Low"}`.
- **Later addition to KEV:** after each KEV update, findings already delivered are checked.
  Affected Jira tickets (searched by label) get priority, label `kev` and a comment
  (the service account needs edit and comment permissions); Slack/Teams get a follow-up message. Once per target.

Network: the bundled NetworkPolicies restrict only ingress, so the bridge may already
reach the internet outbound. If an egress default deny applies in the cluster or at the firewall,
HTTPS (443) to `www.cisa.gov` and `api.first.org` as well as DNS must be allowed, or internal mirrors
must be configured via `kevUrl`/`epssUrl`.

Limits: the `vulnId` is matched; GHSA findings without a CVE ID are recognized neither by KEV nor by EPSS.
High EPSS values alone do not bypass `MIN_SEVERITY` (only KEV does).

## Configuring Kubernetes

Replace only the `routes.json` property in the existing secret; **keep the database and admin password
unchanged**. A local, restrictively stored JSON file can be patched without printing the secret:

```sh
python3 - <<'PY'
import json,subprocess
from pathlib import Path
patch={'stringData': {'routes.json': Path('.secrets/routes.json').read_text()}}
subprocess.run(['kubectl','-n','patchwatch','patch','secret','patchwatch-secrets','--type=merge','--patch-file=/dev/stdin'], input=json.dumps(patch), text=True, check=True)
PY
# Additionally create the JIRA credentials as secret patchwatch-integrations with key JIRA_TOKEN.
kubectl -n patchwatch rollout restart deployment/patchwatch-bridge
```

`token_env` denotes a name in the container environment. The secret `patchwatch-integrations`
is optionally mounted as environment. For a JIRA PAT, the bearer token suffices. For basic auth
(e.g. Jira Cloud), additionally specify `username` with the service account. The account needs
issue search and issue creation in the target project so that finding by label works.
The REST v2 interface with text description is used; check the compatibility of the specific
JIRA server and any required custom fields before production use.

## Configuring Docker Compose

Change `.secrets/routes.json` and restart the bridge. For tag reloading or Jira, use a local,
uncommitted override `compose.integrations.yaml`:

```yaml
services:
  bridge:
    environment:
      DT_URL: http://apiserver:8080
      ALLOW_HTTP: 'true'
      DT_API_KEY_FILE: /run/secrets/monitor_key
      JIRA_TOKEN_FILE: /run/secrets/jira_token
    volumes:
      - ./.secrets/monitor_key:/run/secrets/monitor_key:ro
      - ./.secrets/jira_token:/run/secrets/jira_token:ro
```

The files mounted into the bridge must be readable for UID 10001; the host parent folder
`.secrets` stays `0700`. For example, give the files in question `chmod 444`. Upload keys
for the machines, in contrast, always get `0600`.

```sh
docker compose -f compose.yaml -f compose.integrations.yaml up -d bridge
```

Teams uses Adaptive Cards (the webhook/workflow must support this message format),
Slack the incoming webhook format `text`. Targets can allow HTTP via `allow_http: true` for a
local integration test; real targets should use HTTPS.

## Delivery and deduplication

The webhook responds with 202 only **after** the commit to SQLite. Unknown event groups are
ignored with 202, invalid relevant payloads are rejected with 400 and oversized payloads with 413.
The outbox is kept across restarts and deployments. For each host (project UUID),
package coordinate including version, vulnerability/policy condition ID and route name,
exactly one entry exists. Repeated scans and the two vulnerability event groups create
no new tickets. A new package version deliberately results in a new entry. Aliases between
CVE and GHSA are not yet merged across sources.

Failed targets are retried individually with exponential backoff up to a maximum interval of one hour,
without limit. Other targets that succeeded are not sent to again. For Jira, the
bridge searches for `patchwatch-<finding-hash>` as a label before every creation, in order to also recognize a previously
accepted request after a timeout. Chat webhooks offer no atomic
idempotency; a process abort after acceptance by the target and before the local commit can repeat a
message. Jira search index delays can also cause duplicates.
Exactly-once delivery is not promised.

The bridge runs with exactly one replica and `Recreate`, since SQLite and the delivery logic require a
single worker. Treat renamed routes as new targets; keep observing removed routes with
open deliveries. Metrics on `/metrics` show open deliveries
and the age of the oldest message. Alert on persisting retries. With an empty route list,
no delivery can be expected. A test button in Dependency-Track sends a generic
test notification; a real test finding webhook is needed for a complete end-to-end test.


KEV findings get a fixed internal **24-hour review deadline** from the first observation as
KEV. The deadline is stored per finding in SQLite and does not shift on retries,
restarts or multiple targets. Jira receives a due date; the exact UTC time
is additionally in the text and in chat messages. The CISA remediation deadline remains separate.
The bridge does not record completion of handling; the ticket system manages it and any further
escalations. See [policy management](policies.md).
