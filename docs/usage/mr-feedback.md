# Findings report for a merge request

Patchwatch publishes directly in the respective MR what **its merge** would
change: new and fixed/dropped vulnerabilities with CVE, severity and package as well as
added, dropped and changed licenses per package. Unchanged license types are also
assigned to a newly added or removed package. Policy violations are shown in
both directions. A bot updates its existing comment per
MR and component instead of creating another one on every run.

The comparison is **current target branch without MR → target branch with this MR**. For this, the
scanner computes a real three-way merge with `git merge-tree --write-tree` and
scans both trees in the same job. Changes to the target branch that are still missing in the source branch
are thus kept on both sides. Neither an old release version nor
the source branch alone is used as a comparison. GitLab's paid merged-results
pipelines are not required for this; existing merged-results pipelines are also
supported if their synthetic commit contains the current MR source state as parent commit.

## Integration in the same project

Two reusable templates suffice. Pin the includes to a reviewed Patchwatch commit
and the CI image to its build SHA or digest. The image must contain the paired
scan function (artifact format 2), Git >= 2.38 and Syft; the current `Dockerfile.ci`
additionally contains the Docker CLI for optional image builds.

```yaml
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
stages: [test]
include:
  - project: platform/patchwatch
    ref: <reviewed commit>
    file: ci-templates/mr-sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<digest>
      scan_paths: .
  - project: platform/patchwatch
    ref: <the same reviewed commit>
    file: ci-templates/mr-feedback.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<digest>
```

The scanner `patchwatch-mr-sbom` runs only in MR pipelines and needs neither bot nor
dTrack keys. `GIT_DEPTH=0` provides the shared history. It fetches the current
target branch via `origin`, computes the merge and materializes both trees separately,
without changing the checked-out repository. On a merge conflict, an
explicit conflict artifact is created; no supposed change report is published.

The worker `patchwatch-mr-feedback` runs in the **same project**, exclusively on its
protected default branch as a schedule or web pipeline with `PATCHWATCH_MR_FEEDBACK=true`.
It checks out no application code, takes over no inherited build scripts and processes
only the scan artifacts. A separate worker project is optional: for that, set `project_id` to the
target project ID. Without the input (default `0`), `CI_PROJECT_ID` is used.

Exclude normal jobs and includes when `PATCHWATCH_MR_FEEDBACK=true` so that the
feedback schedule triggers no builds or deployments, e.g. as the first job rule:

```yaml
rules:
  - if: '$PATCHWATCH_MR_FEEDBACK == "true"'
    when: never
  # Then the previous rules of this job.
```

Patchwatch's `.gitlab-ci.yml` shows this including conditional includes. With your own
higher-level `workflow:rules`, allow schedule/web pipelines on the default branch.

## Scan inputs

| Input | Meaning |
|---|---|
| `job_name`, `stage`, `image` | Job name, stage and scanner image |
| `scan_paths` | Directories to scan, default `.`; disable with `''` |
| `exclude` | Additional Syft exclusions |
| `dockerfiles` | Space-separated Dockerfile paths; each is built with the repository root as context in both trees |
| `compose_images` | Space-separated selectors such as `compose.yaml:postgresql`; reads the respective image version separately from both trees |
| `images` | Additional fixed registry references, identical on both sides; for changes made by the MR, use `dockerfiles` or `compose_images` instead |

`dockerfiles` needs a Docker daemon in the **scanner job**, e.g. a `docker:dind` service
with matching `DOCKER_HOST`/TLS settings. Dockerfiles are built explicitly; this
can execute their build commands. Never provide protected bot/dTrack keys for this.
The built images are scanned locally as Docker archives, then cleaned up and
not uploaded to the registry. The worker needs no Docker daemon.

Compose selectors support simple `services:` definitions with literal `image:`
references. Image variables and build-only services are not guessed but reported
as errors. Here, image packages are compared, not CycloneDX service inventories.
If a selected service, Dockerfile or scan path disappears on one side, its
inventory may be empty. Two empty inventories are rejected as a faulty scan configuration.
Mutable tags and unpinned build downloads can change between builds; for
reproducible results, pin images and build dependencies.

For monorepos, include the templates with different `job_name` values and point the
worker to the respective producer via `scan_job`. `component` names the
separate dTrack comparison and bot comment. Artifacts of different components never
come into contact with each other.

## Credentials and schedule

Protect the default branch and its CI changes through trusted maintainers. Under
**Settings → CI/CD → Variables → Access protected resources in merge request pipelines**,
disable the option **Allow merge request pipelines to access protected variables and runners**.
This way, even MRs between protected branches receive no protected
keys. `masked` alone does not prevent access.
[GitLab documentation](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/#control-access-to-protected-variables-and-runners)

| Variable | Content |
|---|---|
| `PATCHWATCH_GITLAB_URL` | HTTPS base URL of GitLab |
| `PATCHWATCH_GITLAB_TOKEN` | Project bot with Developer role and `api` scope: read artifacts/pipelines, write MR comments and request a new MR scan when the target branch has changed |
| `PATCHWATCH_URL` | HTTPS base URL of dTrack |
| `PATCHWATCH_UPLOAD_KEY` | `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` |
| `PATCHWATCH_READ_KEY` | `VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION`, `VIEW_VULNERABILITY` |
| `PATCHWATCH_CA_CERT` | Optional: internal CA as PEM or file variable; TLS verification stays active |

Configure keys as **masked/protected**, optionally as file variables with the suffix `_FILE`.
New worker variables can be restricted to the environment `patchwatch-mr-feedback`;
the template uses this environment with `action: access`, without creating a deployment.
Existing protected release keys with scope `*` can continue to be used.
Do not store personal admin tokens in the worker.

With an existing `glab` login and the three dTrack variables set up, the
setup can be automated:

```sh
export GITLAB_PROJECT_ID=1234  # numeric ID of the project with the feedback worker
# Create the bot and protected variables, leave the schedule deactivated before the merge:
python3 scripts/setup-mr-feedback.py --project "$GITLAB_PROJECT_ID" --ca-cert /path/to/ca.pem
# After merging the CI includes into the default branch, activate the schedule:
python3 scripts/setup-mr-feedback.py --project "$GITLAB_PROJECT_ID" --activate
```

The script locks protected resources for MR pipelines, creates a Developer bot restricted to the project
with a lifetime of 90 days and sets the five-minute schedule with
`PATCHWATCH_MR_FEEDBACK=true`. Existing keys are kept; values are not
printed. Renew the token before it expires. Alternatively, set up variables and schedule manually.

Before the first worker run, apply the regular dTrack configuration. It creates separate
`Patchwatch MR …` rule copies for `scan-purpose:mr-feedback`. Team policies of your own and
release distribution rules are not copied automatically.

## Updates and limits

The worker processes open MRs of the same project; fork MRs are skipped. It downloads
`patchwatch-mr.json` via the specific successful job ID and checks source state, pipeline SHA
and current target branch. The artifact contains both SBOMs, target/source SHA and merge tree.
Old one-sided SBOM artifacts are not accepted as a correct comparison.

If the target branch has moved on in the meantime, the worker publishes "Pending" and
requests at most one automatic new MR pipeline per source/target combination. Running
pipelines are awaited. If this scan fails, the scan job can be retried
manually; the worker does not start an endless series of failed pipelines.
Before every comment, it checks source and target state again and discards outdated results.
`resource_group` serializes worker runs per project; operate only one worker configuration per
target project. Also serialize external cron runs.

### dTrack versions

All versions are under the **same project name as the regular inventory**
(`<project path>[/<component>]`); separation is via version and scope tag:

| Version | Content | Tags |
|---|---|---|
| `mr-<IID>` | Merge result of this MR; every run overwrites it | `scan-purpose:mr-feedback`, `gitlab-project-id:<id>` |
| `base-<target branch>` | **Baseline:** paired scan of the target branch at the current target commit (default, `baseline: scan`) | like `mr-<IID>` |
| `<target branch>` (e.g. `main`, `dev`) | Only with `baseline: branch`: the regular branch inventory as baseline, as long as its commit matches the current target commit | as before (CI inventory) |

An MR thus always compares against its own target branch ("into main", "into dev"): `base-main`
or `base-dev` is the target branch without the MR, `mr-<IID>` is the merge result. Both sides
are created in the same scan job with the same inputs, carry the same scope tags and are evaluated by the
same `Patchwatch MR …` policies. As a result, only real changes appear in the report.

For component workers (`component` set), the component versions of a version hang under a
**parent project** `<project path>` with the **same version** (`mr-<IID>`, `base-<target branch>`, branch name).
This way the project tree in dTrack shows all components grouped per branch or MR, as for `main`. dTrack does not create
missing parents itself: the worker creates them from an empty SBOM with the same scope tags. A
parent without these tags (such as a release of the same name) is never touched; the component is then uploaded without
a parent. The aggregation of the children (`AGGREGATE_DIRECT_CHILDREN`) is set by the server-side
run `patchwatch-versions` every five minutes, and also by the setup or `python -m patchwatch.dtrack.groups`
with admin permissions; the upload key may not do that. Above that, a navigation project
`<project path> @ all versions` groups the different versions without aggregation of its own.

`baseline: branch` is intended only for projects whose production policies match the mirrored
MR policies and for which triage (`not_affected`, `false_positive`) plays no role:
the regular inventory is evaluated by the production policies (`Patchwatch …` instead of
`Patchwatch MR …`) and carries manual triage decisions. Both appear in the report as a
change (identical violations count as "new" and "dropped"). The worker recognizes the state of the
branch version by the commit URL that every upload supplies as origin; if it is outdated, missing
or inactive, it uses the paired scan.

The worker never overwrites a version that does not carry its scope tag: a version named
`mr-7` or `base-main`, which comes e.g. from a CI inventory, leads to an error.
The names `mr-<number>` and `base-…` are therefore reserved for branches. Release tags,
latest synchronization, delta baselines and production notifications ignore these versions.

### Feature branches as versions

With `branch_scan_job` (default: empty = off), the worker creates for **every unprotected
non-default branch** a dTrack version with the branch name and the tag
`scan-purpose:branch`. The branch pipeline runs without keys for this with
`ci-templates/branch-sbom.yml` (artifact `patchwatch-branch.json`); upload happens only through
the protected worker, as with MRs. Protected branches continue to upload via the regular
inventory job (`branches` input) and are skipped here. A branch is only uploaded again
if its commit differs from that of the version; names of releases or
other inventories are never overwritten. Prerequisite: the project's `workflow:rules`
allow branch pipelines (push) for these branches.

```yaml
include:
  - project: platform/patchwatch
    ref: <reviewed commit>
    file: ci-templates/branch-sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<digest>
      dockerfiles: Dockerfile            # same inputs as in the MR scan
  - project: platform/patchwatch
    ref: <the same reviewed commit>
    file: ci-templates/mr-feedback.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<digest>
      branch_scan_job: patchwatch-branch-sbom
```

After the import, the analysis states are read repeatedly. Two identical queries are
a stabilized **snapshot**, no proof of finished analyzers. Timeouts
are marked as incomplete and retried; even zero findings are no approval.

The comment is a preview with at most 20 entries per section and limited text lengths.
Directly above it is **"Download the full report (ZIP: Markdown + JSON)"**. The archive
contains the complete comparison including SHAs, merge tree and evaluation time,
without line or text truncation. It is stored as a Markdown upload in the **target project of the MR**,
even if the worker runs in a different project. The link points to exactly this
snapshot and remains after the CI artifacts expire. GitLab project permissions
and its rules for retention of attachments continue to apply. Uploads are not deleted automatically by
Patchwatch. For a pending or failed re-evaluation,
the last report stays linked with an explicit label of the previous evaluation state.
Unchanged finished results create no new archive.

JSON, Markdown and ZIP are additionally available for one week as worker artifacts under
`patchwatch-mr-reports/<MR-IID>/`. The worker creates a GitLab report artifact
`annotations` with direct `external_link` references to the ZIPs, even for reused
results. These links appear on the **worker job page**, not as a security widget
in the MR pipeline. The bot needs no further permissions for this beyond its existing
project token with `api` scope.

### GitLab's MR reports

The scan template uses `artifacts:expose_as` to provide the **raw SBOM data** directly in the
MR interface as an artifact link. These paired inventories contain no
findings evaluation yet. The complete Patchwatch comparison is provided by the ZIP link in the
bot comment.

An arbitrary Markdown/JSON comparison cannot be registered as a freely definable native
MR report widget. GitLab's native widgets for dependency scanning and
license changes require **GitLab Ultimate** and its supported report formats,
matching SBOM metadata and report jobs in the MR/comparison pipeline. An
`annotations` report in a scheduled worker pipeline does not automatically link its findings
with the MR pipeline. The Community Edition cannot display these security/license widgets.
Patchwatch therefore provides direct attachments and job annotations instead of
emitting security findings as unrelated test or code quality results.

References: [Show artifacts in the MR](https://docs.gitlab.com/ci/yaml/#artifactsexpose_as),
[Annotations](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportsannotations),
[Dependency scanning](https://docs.gitlab.com/user/application_security/dependency_scanning/),
[License scanning](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/),
[Markdown uploads](https://docs.gitlab.com/api/project_markdown_uploads/).

Missing/expired artifacts result in "Pending", API/upload/evaluation errors in an
error comment and a failed worker job. Other MRs continue to be processed.
Closed MRs are no longer updated; comments remain as history.
`mr-<IID>`, `base-…` and branch versions are not yet deleted automatically; earlier
versions under `<project path>/mr-feedback` remain in place and can be deleted. Later published
CVEs are evaluated after a renewed scan job; unchanged finished job results are
not constantly re-uploaded.

The SBOMs come from mutable MR pipelines. The report is review feedback, no
attestation against deliberate manipulation of the scan configuration. Package names are shown without
active mentions, HTML or GitLab quick actions.

## Patchwatch itself

`ci/mr-components.yml` scans the bridge and CI image from their respective Dockerfiles as well as
API server, frontend, PostgreSQL, Trivy and gateway via `compose.yaml`. This way,
image versions are actually read from the target or merge tree; the image list of the
source branch is not mistakenly used for both sides. Tests verify that the same
components as in the regular release scans are covered.

`ci/mr-feedback.yml` includes the seven workers for the Patchwatch project.
Before reuse, adapt its project ID and registry references. In protected
feedback pipelines, the CI image belonging to the default branch commit is used. The
MR pipeline builds only the scanner image beforehand; the bridge/CI images to be compared are
then built separately from the two trees. The normal release/deploy flow and
its component schedule stay independent of the feedback schedule.

`ci/branch-components.yml` contains the same scans with identical inputs for feature branches
(`ci-templates/branch-sbom.yml`); `ci/mr-feedback.yml` sets `branch_scan_job` for this. The
`workflow:rules` start a push pipeline for every branch unless it has an open MR: in that case
its MR pipeline suffices, and the branch version stays at the state before the MR, while
`mr-<IID>` is current. The CI image is also built in branch pipelines for this.

References: [Git merge tree](https://git-scm.com/docs/git-merge-tree),
[Syft scan targets](https://oss.anchore.com/docs/guides/sbom/scan-targets/),
[MR pipelines API](https://docs.gitlab.com/api/merge_requests/#create-merge-request-pipeline),
[Artifacts by job ID](https://docs.gitlab.com/api/job_artifacts/#download-a-single-artifact-file-by-job-id),
[MR comments](https://docs.gitlab.com/api/notes/#merge-requests).
