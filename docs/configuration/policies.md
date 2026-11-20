# License and security policies

## Active baseline rules

[patchwatch/dtrack/data/default-policies.json](../../patchwatch/dtrack/data/default-policies.json) is the versioned
source of the automatically managed rules. Kubernetes CI/CD and the Compose setup command
apply the same configuration.

| Rule | Trigger | Result | Scope |
|---|---|---|---|
| Patchwatch severity High or Critical | known vulnerability with HIGH or CRITICAL | FAIL | `managed-by:patchwatch` |
| Patchwatch unresolved license review | license is missing or cannot be resolved | WARN | `managed-by:patchwatch` |
| Patchwatch EPSS at least 10 percent | EPSS ≥ 0.1 | WARN | `managed-by:patchwatch` |
| Patchwatch distribution license approval | no license option from the baseline group | WARN | `policy-profile:distribution` |
| Patchwatch blocked xz upstream releases | xz/liblzma upstream 5.6.0 or 5.6.1 according to package coordinates | FAIL | `managed-by:patchwatch` |
| Patchwatch direct dependency major version lag | direct dependency more than one major version behind | WARN | `source:gitlab-ci` |


`WARN` requires a review; it is not a blanket rejection of the software.
In particular, there is no automatically invented GPL/AGPL block for developer machines.
A known SPDX license without a warning is not yet a legal clearance. Obligations such as
attribution, license texts, source code offers and passing on changes need an
assessment of the specific use and distribution.

The security policy now also applies via the management tag. Other projects receive
no Patchwatch rules merely because they are on the same DTrack instance.
Multiple tags of a policy widen the scope: they are alternatives, not an
AND combination. For a profile of your own, e.g., use exclusively `policy-profile:distribution`.
Combining it with `managed-by:patchwatch` would also include all other managed
projects. Maintain tags according to the [inventory guide](../usage/inventory.md) via registration;
the upload key deliberately has no permission to change tags.

## Thresholds, profiles and data coverage

EPSS uses the probability `0.1` (10%), not the percentile and not the number 10.
The native EPSS feed is enabled during setup. Missing EPSS values produce no native
EPSS violation and must not be understood as zero risk. The FIRST query of the
bridge is a separate data path and does not replace the DTrack feed.

The license group `Patchwatch distribution baseline` is fully reconciled from
[default-license-groups.json](../../patchwatch/dtrack/data/default-license-groups.json):
0BSD, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, ISC, MIT, PostgreSQL, Python-2.0 and Zlib.
It is an initial checklist, not a confirmation that license obligations are met. Licenses not
included result in `WARN`, not an automatic claim of a license violation.
Group members of this one managed group are reset on deployment;
groups of your own remain untouched. Other allow lists can be managed in the UI as described below.
A different file path is possible via `PATCHWATCH_LICENSE_GROUPS_FILE`.
All SPDX IDs and external group references are resolved before changes.

CI uploads of Git tags additionally receive `policy-profile:distribution`; default-branch
inventories and host projects do not receive this profile automatically. For already created
release projects, add the tag administratively, since the upload key may not change
existing tags. A new upload alone therefore does not guarantee a subsequent profile assignment.

The version distance rule uses DTrack's `VERSION_DISTANCE` and concerns only detected direct
dependencies. More than **one** major version behind produces `WARN`; minor/patch distances
are ignored. Missing repository metadata, incomparable versions and unknown
dependency graphs can prevent the evaluation. The finding is no EOL proof and
does not automatically take into account the support contract of an older major line.

The initial package block concerns known xz upstream versions 5.6.0/5.6.1 including
simple distribution release suffixes for `deb`, `rpm` and `generic`. Renamed packages,
deviating version schemes and binaries without package identifiers cannot be fully
covered. `+really` rollback versions are not blocked wholesale by the pattern.
The block requires a review/replacement of the package version; it proves no active exploitation.
Source: [Red Hat: xz supply-chain compromise](https://www.redhat.com/en/blog/urgent-security-alert-fedora-40-and-rawhide-users).

## Supplementary operating rules

- **KEV:** on first observation of a finding as known exploited, the bridge sets
  a persistent review deadline of 24 hours. All targets and repetitions use the same
  deadline. On later KEV inclusion, it starts at that observation. Jira receives a `duedate`
  at day level; the description and chat contain the exact UTC time. The CISA deadline
  is kept separately. This is an internal review deadline, not a claimed statutory
  date and no guarantee of completion. Ticket status/confirmation and further escalations
  are to be managed in the responsible ticket system. Without bridge routes, no external
  delivery takes place; old deliveries already completed are not re-sent merely because the
  deadline was introduced.
- **SBOM completeness:** empty inventories already lead to an error in CI; explicit
  collection projects remain exempt. Missing versions or package URLs for software packages
  result in additional `OPERATIONAL / WARN` in the CI/compliance report. This is a supplementary
  check outside the native DTrack policy list. With `--fail-on warn` or CI `fail_on: warn`,
  the gates take these notes into account; empty ordinary inventories in the report are `FAIL`.
- **Freshness:** the existing 48-hour monitoring of host uploads remains active. A
  completely missing host still requires a target inventory (`--expected-file`).

## Changing rules in the repository

1. Change the file `patchwatch/dtrack/data/default-policies.json`. Every rule needs a unique name
   with the prefix `Patchwatch `, `operator` (`ANY`/`ALL`), `violationState` (`INFO`/`WARN`/`FAIL`),
   at least one `scopeTags` entry and at least one condition. Conditions describe the
   undesired state: `ANY` reports when at least one condition is met, `ALL` only when
   all are. An allow list is therefore checked via `IS_NOT`.
2. Validate and test locally:

   ```sh
   python3 -m patchwatch.dtrack.policies --check
   python3 -m unittest discover -s tests -v
   python3 scripts/spdx.py
   python3 scripts/spdx.py --check
   ```

3. Review the change and merge it into `main`. GitLab CI reconciles the rules after the
   Helm deployment. The deploy job provides `ci/compliance-report.json` as an artifact for one
   week. The report is a snapshot of existing imports; CI does not trigger a
   new scan of all machines. Assess the current version after a renewed agent run
   or the next native DTrack evaluation.
4. After rule changes, upload the affected SBOMs again. On this machine:

   ```sh
   systemctl --user start patchwatch-agent.service
   journalctl --user -u patchwatch-agent.service -n 20 --no-pager
   ```

   For a system-wide installation, use `sudo systemctl start patchwatch-agent.service` instead.
   Compare results only after BOM processing and policy evaluation have completed.

The reconciliation takes over the complete definition of exactly the policies named in the file:
conditions, state, operator and tag/project bindings. Additional conditions or
scope changes in the UI are overwritten on the next reconciliation. Other policies are
kept. Removing from the file alone does not delete an existing policy: for final
decommissioning, remove the definition **and** delete the old policy in the UI. When renaming,
likewise: remove the old policy separately. This way, foreign rules and their history are not deleted
without asking.

For Compose, after a rule change reconcile only the regular policies and license groups again:

```sh
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  python3 -m patchwatch.dtrack.policies
```

This command does not update derived `Patchwatch MR …` rules. If the
[MR reports](../usage/mr-feedback.md) are used, also run the complete setup call from the
[deployment guide](../installation/compose.md) again;
Kubernetes does both on the regular deployment.

For a remote system, use its HTTPS URL without `ALLOW_HTTP`. Alternatively, use a
securely stored admin/provisioning key via `DT_ADMIN_API_KEY_FILE`. For a
pure policy reconciliation, `POLICY_MANAGEMENT` and the matching read permissions for reading/resolving the references
are needed; neither the upload key nor the monitor key may write rules.

For a separate configuration set, set `PATCHWATCH_POLICIES_FILE=/path/policies.json`.
In CI, the file must be present in the checkout and the variable set in the deploy job.
It replaces the entire default configuration set. Changes on the executing machine
alone do not change the file used by the GitLab runner.

## Organization-specific license lists

First clarify for which use the list applies: internally used tool, SaaS,
distributed container image or delivered product. Then create a group of your own in **Administration →
License Groups**, e.g. `Company distribution approved`, and assign the
approved SPDX licenses. The built-in copyleft groups are starting points,
not an already decided company policy.

Example of an additional rule with its own name in the `policies` list:

```json
{
  "name": "Patchwatch company distribution license approval",
  "operator": "ANY",
  "violationState": "FAIL",
  "scopeTags": ["policy-profile:distribution"],
  "conditions": [
    {"subject": "LICENSE_GROUP", "operator": "IS_NOT", "value": "Company distribution approved"}
  ]
}
```

`IS_NOT` on an approval group reports components for which no permitted license option
exists. For an explicitly decided prohibition group, use `LICENSE_GROUP IS`
instead. `value` in the JSON is the **group name**, not the installation-dependent UUID.
The group must exist beforehand; missing references abort the reconciliation before
policies are changed. The memberships of additional groups maintained exclusively in the UI are not overwritten by the
reconciliation; the managed baseline group is the exception described above. Document group changes with approval, date and justification in the
change ticket; for further DTrack installations, track them separately.

For a single license, use `subject: LICENSE` and its SPDX ID such as `AGPL-3.0-only`.
The special value `unresolved` stands for missing/unresolvable information. The implementation
resolves IDs and group names to the respective DTrack UUID. SPDX expressions keep their
meaning: `MIT OR GPL-3.0-only` allows a choice; `MIT AND GPL-3.0-only` requires both.
Do not remove an alternative license to make a warning disappear.

## Managing in the UI and handling findings

- **Administration → Policies:** define rule, `ANY`/`ALL`, violation state, conditions and scope.
  Create independently managed UI rules under a name of their own that is not in the
  JSON file. A policy without project/tag assignment is global; explicitly check the
  scope before use.
- **Project → Policy Violations:** filter by LICENSE/SECURITY and WARN/FAIL and open the affected
  component. Verify the license from package/upstream evidence; preferably correct wrong or missing
  metadata at the source and scan again. A manual
  component entry can be replaced on the next SBOM import.
- Document exceptions via the analysis of the specific policy violation: justification,
  responsible person, evidence/ticket, usage context and resubmission. Do not use a suppression
  as a global approval of a license. Schedule expiry/resubmission externally;
  no automatic expiry of exceptions is implemented here.
- **Project → Audit Vulnerabilities:** review security findings separately by affectedness.
  According to DTrack, suppressed vulnerabilities produce no security policy violation.
  A missing hit proves no absence of vulnerabilities; scan roots,
  package coordinates and Trivy/feed availability are part of the assessment.

Use `POLICY_MANAGEMENT` for policies and groups, `VIEW_PORTFOLIO` for inventory readers
and additionally `VIEW_POLICY_VIOLATION` for compliance reports (delta reports also need
`VIEW_VULNERABILITY`). The automatically managed team `inventory-monitor` receives exactly these read permissions. Give write permissions for finding analyses only to responsible teams. Agents
get no admin credentials. The existing webhook rule takes policy violations into account;
external delivery still requires configured bridge routes.

## Report and optional CI gate

With the existing read-only monitor key:

```sh
DT_URL=https://patchwatch.example.org \
DT_API_KEY_FILE=/secure/path/monitor_key \
  python3 -m patchwatch.dtrack.compliance --output compliance-report.json
```

For each active managed project, the report contains license metadata coverage, license conflicts,
graph edges and the number of unsuppressed native policy violations by rule,
category and state, as well as supplementary `qualityViolations` for empty inventories and
missing package versions/URLs. It contains neither complete SBOMs nor installation paths. Still treat it as an
internal inventory. Read errors are reported as errors; missing data
is not interpreted as passed.

By default the report is informational. `--fail-on fail` returns exit code 2 for at least
one native or supplementary FAIL finding; `--fail-on warn` additionally for WARN and
license conflicts as well as SBOM metadata warnings. Both
concern the entire managed inventory, not only newly introduced findings. API/data errors
return exit code 1. Add such a gate to a release process only once the handling of existing findings is
defined. The deployment of the security system itself is not blocked by
existing host findings.

`patchwatch:license-conflict=true` marks contradictory expressions when merging
package copies. DTrack 4.14 has no policy condition for arbitrary component properties;
therefore these cases appear in the separate report and are taken into account with `--fail-on warn`.
The native license policy alone does not guarantee the detection of such conflicts. Even
known but wrong license metadata can remain undetected without a manual review.

Sources: [DTrack Policy Compliance](https://docs.dependencytrack.org/usage/policy-compliance/),
[DTrack License Evaluation](https://docs.dependencytrack.org/analysis-types/license/).
