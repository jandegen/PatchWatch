# GitLab CI template: connecting projects to PatchWatch

The template [`ci-templates/sbom.yml`](../../ci-templates/sbom.yml) creates an SBOM (CycloneDX) in the pipeline of a
project and uploads it to Dependency-Track. The project then appears
in PatchWatch next to the developer machines. Severity/license policies, notifications
via the bridge and the dashboards thus apply automatically to these projects as well.

There are two parts: the **one-time setup** (section 1, by the operator of PatchWatch)
and the **integration per project** (section 2, with its own template and image reference).

**Shortcut for GitLab projects:** the interactive script
[`setup-gitlab-project.sh`](gitlab-setup-script.md) from the release does section 2 for you: it checks the
connection, stores the variables, generates the configuration for a single repository or a monorepo and opens a merge
request. It needs only `curl` and `jq`. The sections below explain what it generates.

## 1. One-time setup

### 1.1 Keys

The setup (`patchwatch.dtrack.setup`, in Kubernetes the deploy job on `main`) creates the
DTrack team **`ci-upload`** with `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` and `VIEW_PORTFOLIO`. It has its
own key, separate from the agents, so that both can be rotated and revoked independently.

```sh
# Kubernetes (after the first deployment with this version)
kubectl -n patchwatch get secret patchwatch-provisioning -o jsonpath='{.data.ci_upload_key}' | base64 -d
# Compose
cat .secrets/ci_upload_key
```

For the server-side version synchronization, the team **`project-versions`** is additionally created with
`VIEW_PORTFOLIO` and `PORTFOLIO_MANAGEMENT`. Its `versions_key` stays exclusively on the server;
it is **not** distributed as a GitLab variable. Kubernetes provides it as `patchwatch-versions-key`.
The CronJob `patchwatch-versions` synchronizes the latest marker every five minutes; in addition, the
synchronization runs on every deployment. In Compose, start it after the setup:

```sh
docker compose --profile operations up -d versions
```

Optional and only for evaluation and gate: the existing **read key** (`monitor_key`, permissions
`VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION` and `VIEW_VULNERABILITY`). It sees the **entire** portfolio. Pipelines that
receive it can therefore read all findings. Distribute it only to pipelines that may read the entire portfolio; otherwise
set up project-specific access or omit the key.

### 1.2 GitLab variables at group level

*Group → Settings → CI/CD → Variables.* Set at the top group level, they apply to all
projects below. Projects then need no configuration of their own.

| Variable | Type / flags | Content |
|---|---|---|
| `PATCHWATCH_URL` | Variable | `https://patchwatch.example.org` |
| `PATCHWATCH_UPLOAD_KEY` | Variable, **masked, protected** | Key of the team `ci-upload` |
| `PATCHWATCH_READ_KEY` | Variable, **masked, protected**, optional | `monitor_key`; enables result summary and `fail_on` |
| `PATCHWATCH_CA_CERT` | **File**, optional | Certificate of the internal CA, if the runner does not trust it |

*Protected* is important: the keys are available only in pipelines of protected branches and tags,
not in merge requests from forks or in arbitrary feature branches. The default branch
must therefore be **protected**. Set both properties, **masked** and **protected**, and
neither print the keys nor include them in debug traces. The template does not log them.

For the **upload**, `PATCHWATCH_CA_CERT` replaces Python's trust list. Syft and
image pulls are not affected. HTTP is rejected; only for internal tests, set
`PATCHWATCH_ALLOW_HTTP: 'true'`.

### 1.3 Job image and template version

The job runs in an image with Syft and the PatchWatch module ([`Dockerfile.ci`](../../Dockerfile.ci)).
The pipeline of this repository builds it and puts it into the registry. This pipeline
also contains a Kubernetes deployment and installation-specific runner and
registry settings. For Compose, the image can be built independently of it,
see section 1.4. **Publishing a version via the adapted repository pipeline:**

```sh
git tag v1.1.0 && git tag -f v1
git push origin v1.1.0 && git push -f origin v1
```

Run these steps only on the commit containing the changes to be released. The tag pipeline
publishes `ci:v1.1.0` and the moving `ci:v1`. Projects include `ref: v1`
and thereby receive compatible improvements; an incompatible change becomes `v2`. The tags `v*`
should be configured in GitLab as **protected tags**. Until the first tag pipeline has finished,
the default image `ci:v1` does not exist yet.

The release pipeline also copies the image to GitHub (`ghcr.io/<owner>/<repo>/ci:v1`, see
[Release](../operations/release.md)). If you include the template from there, pass this image as the
`image` input; no registry of your own is needed.

For `branches`, `services` and `detect_services`, both the template and the job image
must support the inputs. Older states of `v1` do not yet contain `services` and `detect_services`;
`branches` is not contained in all older states. For a fork of your own,
release versions together with the image. Also update the Git tag `v1`
on release and wait for the successful image build. For a fixed version, set next to
`ref: v1.1.0` also `image: $CI_REGISTRY/platform/patchwatch/ci:v1.1.0`.

The repository `platform/patchwatch` must be readable for the including projects (visibility
*internal* or permission), and the registry must deliver the image. With a private registry,
the project must be added to the job token allowlist.

### 1.4 CI with a Compose server without Kubernetes

The templates work with both deployment modes. For Compose, first complete the
[Compose setup including HTTPS](../installation/compose.md) fully.
`scripts/setup-ci.py`, `KUBE_CONFIG`, Helm and Kubernetes secrets
are not needed for connecting GitLab projects to this server.
`scripts/setup-ci.py` sets up the Kubernetes deployment pipeline.

**Provide the CI image:** Push a reviewed Patchwatch state including templates
into a GitLab project readable for the consumers. Build and publish the image from exactly this state;
replace the following registry values:

```sh
PATCHWATCH_REF=$(git rev-parse HEAD)
PATCHWATCH_CI_IMAGE="registry.example.org/platform/patchwatch/ci:${PATCHWATCH_REF}"
docker login registry.example.org
docker build --pull -f Dockerfile.ci -t "$PATCHWATCH_CI_IMAGE" .
docker push "$PATCHWATCH_CI_IMAGE"
```

The checkout must match the published commit for the build, without
additional local code changes. The build machine needs Docker and access
to the base image registries as well as write permissions on the target registry. With a
different runner architecture, build the image for that platform.
The Compose image `patchwatch-bridge:local` contains no Syft scanner and does not replace
this CI image. The Compose services themselves need no publication in a registry
for their local build.

**Configure GitLab:** Set the variables from section 1.2. As
`PATCHWATCH_URL`, use for example `https://patchwatch.example.org:8443`,
as `PATCHWATCH_UPLOAD_KEY` the content of `.secrets/ci_upload_key`. The optional
`PATCHWATCH_READ_KEY` comes from `.secrets/monitor_key`. Read and transfer files with keys only
via a secure administrative channel.
With a restricted environment scope, the variables must also apply to the SBOM job without
`environment`, usually scope `*`.

From the **runner job container**, DNS, HTTPS port and certificate chain of the
Compose gateway must be reachable; likewise the GitLab and image registry.
Loopback and internal Compose names (`apiserver`, `gateway`) are no
server addresses for this. With an internal CA, store `PATCHWATCH_CA_CERT` as a file variable.
For the pull of the job image, the registry CA must already be trusted by the runner;
the job variable only takes effect after the image pull.

**Connect a consumer project:** Replace `ref` with the full commit determined above
and the image tag with the same commit. This way no `v1` release
and no Kubernetes deployment pipeline is needed:

```yaml
include:
  - project: platform/patchwatch
    ref: '<full reviewed commit>'
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:<the same commit>
      team: platform
      # Deliberate first stocktaking with still incomplete BSI metadata:
      bsi_mode: report
```

This first example uploads an inventory that does not count as BSI-compliant.
For regular operation, add the [BSI metadata](bsi-sbom.md) and
set `bsi_mode: enforce` (or remove the input for the default `enforce`).
Your own `stages` must contain `test` or select an existing
stage via `inputs.stage`. The default branch must be protected so that the job receives its
protected upload key. For an ordinary repository scan, the runner
needs no Docker daemon; additional image builds need a build configuration
of their own.

**Verify the first import:** Start a pipeline on the protected default branch.
The job `patchwatch-sbom` must report `Upload processed by Dependency-Track`.
Check the artifacts `patchwatch-sbom.json` and `patchwatch-bsi-report.json` and, in
the web interface, open the project under its GitLab path and the default branch version.
The component table must contain the scanned inventory. The import
does not yet confirm the completion of the vulnerability analysis.
After the central setup, start `versions` as in section 1.1 so that the
latest marker is synchronized regularly.

In case of errors, first check:

| Symptom | Check |
|---|---|
| Job image cannot be loaded | Full registry path, published tag, runner CA and job token allowlist |
| Upload key missing | Protected branch/tag, variable type and environment scope |
| Connection or TLS fails | Gateway URL reachable from the job, port, DNS and `PATCHWATCH_CA_CERT` |
| HTTP 401/403 | `ci_upload_key` from the same instance, team permissions and, if applicable, project access |
| BSI check refuses upload | `patchwatch-bsi-report.json` and component-specific metadata |

For optional MR reports, then set up [MR feedback](mr-feedback.md);
the DTrack URL and CA settings there also point to the Compose gateway.

## 2. Integration into a project

The examples use a template fork of your own `platform/patchwatch` and an
image you published yourself. Adapt `project`, `ref` and `inputs.image` before use;
the template default for the image is installation-specific.
See [registry and GitLab parameters](../installation/customization.md#gitlab-and-registry).

Minimal, in the project's `.gitlab-ci.yml`:

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
```

This creates the job `patchwatch-sbom` in the stage `test`. It runs on the **default branch** and on
**tags**, not in merge requests. Missing mandatory BSI information blocks
the upload and the job by default. Before including, [configure the BSI metadata](bsi-sbom.md).

### Configuration (`inputs`)

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      team: platform
      environment: production
```

| Input | Default | Meaning |
|---|---|---|
| `job_name` | `patchwatch-sbom` | Name of the job; needed if the template is included multiple times |
| `stage` | `test` | Stage; for image scans choose a stage **after** the build |
| `image` | set explicitly | Job image of your own with Syft and Patchwatch; e.g. `registry.example.org/platform/patchwatch/ci:v1` |
| `team` | empty | Tag `team:<value>`; controls alert routing. Empty: top GitLab group |
| `environment` | empty | Optional tag `environment:<value>` |
| `scan_paths` | `.` | Directories in the repository, separated by spaces; empty = images only |
| `images` | empty | Image references, separated by spaces |
| `exclude` | empty | Syft exclusion patterns, e.g. `./docs/** ./**/testdata/**` |
| `component` | empty | Name suffix for monorepos. The inventory is then filed under the project `group/project` (see section "Multiple inventories") |
| `mode` | `inventory` | `parent` creates an empty aggregation parent and a separate service child project |
| `services` | empty | Additional service names, separated by spaces, as CycloneDX services |
| `detect_services` | `true` | Enter services from supported Compose files under `scan_paths` as CycloneDX services; name and image only, [search limits](services.md) |
| `branches` | empty | Additional permitted upload branches, separated by spaces, exact names without globs. Version = branch name, not marked as latest. Also adapt `run_if` |
| `run_if` | default branch or tag | GitLab `rules:if` expression for when the job runs; alone it does not unlock further upload branches (use `branches` for that). Only double quotes inside, e.g. `$CI_PIPELINE_SOURCE == "schedule"` |
| `fail_on` | `none` | `none`, `warn` or `fail`; needs `PATCHWATCH_READ_KEY` |
| `delta` | `true` | Delta report against the previous version, see [delta reports](delta-reports.md); needs `PATCHWATCH_READ_KEY` |
| `delta_baseline` | empty | Fixed comparison version; empty = automatically the previous version |
| `delta_notify` | `relevant` | `relevant`, `always` or `never` for webhook/email delivery |
| `allow_failure` | `false` | Continue the pipeline despite a job failure when explicitly set to `true` |
| `bsi_mode` | `enforce` | Missing mandatory BSI information refuses the upload; `report` is only for the migration of incomplete inventories |
| `bsi_metadata` | empty | JSON file with verified component-specific information; [format and examples](bsi-sbom.md) |
| `sbom_creator` | project URL | Email/URL of the SBOM creator |
| `component_creator` | project URL | Email/URL of the creator of the primary component |
| `distribution_license` | empty | Verified SPDX expression of the distribution license of the primary component |

Team and environment values consist of lowercase letters, digits, `.`, `_` and `-`. The team is never guessed from
user names: where the GitLab group does not correspond to the team, set `team`.

### Examples

**Upload an additional branch** (default branch and tags remain permitted):

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      branches: dev
      run_if: '$CI_COMMIT_TAG || ($CI_COMMIT_BRANCH && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) || $CI_COMMIT_BRANCH == "dev"'
```

`branches` is passed to the module as `PATCHWATCH_BRANCHES`. `dev` must also be protected for the protected
keys. The upload creates the version `dev` including `patchwatch-report.json`;
later `dev` uploads do not change the central latest selection (highest stable release,
otherwise default branch; see section 3).
With multiple inventories, set the same `branches` and `run_if` values for parent and components.
A job started on a branch that is not released skips scan and upload with a
`WARNING: PatchWatch CI skipped` message and exit code 0; no report is created.

**Repository and built image** (image scan after the build):

```yaml
stages: [test, build, scan]

include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      stage: scan
      team: platform
      images: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
```

Images of the GitLab registry are read with the job token. For a registry without a valid TLS certificate
or via HTTP, set in the project `variables: {SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY: "true"}` or
`SYFT_REGISTRY_INSECURE_USE_HTTP: "true"`.

**Monorepo with multiple inventories** (one DTrack project each, grouped under the project itself):

```yaml
stages: [test, prepare, scan]

include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      job_name: sbom-parent
      stage: prepare
      mode: parent
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      job_name: sbom-api
      stage: scan
      scan_paths: services/api
      component: api
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      job_name: sbom-web
      stage: scan
      scan_paths: services/web
      component: web
```

See "Multiple inventories" below for the background.

**Gate for releases** (tags block, the default branch only warns):

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      fail_on: fail

patchwatch-sbom:
  rules:
    - if: '$CI_COMMIT_TAG'
      allow_failure: false
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      allow_failure: true
```

**Scheduled** (e.g. for third-party images that change only on version changes):

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      job_name: sbom-postgres
      component: postgres
      scan_paths: ''
      images: postgres:17.7-alpine
      run_if: $CI_PIPELINE_SOURCE == "schedule"
```

You create the schedule under *Build → Pipeline schedules*. A schedule starts the **entire** pipeline
of the project. So that nothing else runs (tests, builds, deploy), the remaining jobs need a rule
`if: '$CI_PIPELINE_SOURCE == "schedule"'` with `when: never`. The
[`.gitlab-ci.yml`](../../.gitlab-ci.yml) of this repository does this via `.not-scheduled`.
Dependency-Track itself detects new CVEs for an unchanged version via its feeds; a schedule more frequent than
weekly therefore makes sense only for entering new versions.

**Different runner** (e.g. tags): jobs from the template can be extended in the project:

```yaml
patchwatch-sbom:
  tags: [k3s, docker]
```

### Multiple inventories (hierarchy)

With `component`, a DTrack project of its own `group/project/<component>` is created per inventory. These hang
as **child projects** under the project `group/project` (in the UI as a tree; the switch *Show flat
project view* shows all flat). For this to work:

- **The collection project must exist beforehand.** Dependency-Track does not create a missing parent
  (`404 The parent component could not be found`). The job with `mode: parent` creates it as an empty SBOM
  and must run in an **earlier stage** than the component jobs. A job of its own is needed because
  parallel jobs would otherwise create the same project simultaneously. If it is missing, the component job states
  exactly that in the error message.
- **The collection project adds up the metrics of its child projects** (findings, policy violations,
  components, "Aggregate direct children"). The upload key cannot set this. The
  setup (every deployment) and the regular run of `patchwatch-versions` take care of it
  for CI, MR and branch parents with child projects, or manually with admin access:
  `DT_URL=https://… DT_ADMIN_PASSWORD_FILE=… python3 -m patchwatch.dtrack.groups`. Until then, the
  collection project shows only the tree but no totals.
- **Existing projects are re-parented:** Dependency-Track evaluates `parentName` only when creating a
  project. Components that already existed before their collection project otherwise remain roots. The same
  admin step therefore attaches projects `group/project/<component>` under `group/project` provided both have
  the same tag `gitlab-project-id` and the same version.
- The collection project has **no components or services of its own**. `mode: parent` creates it once
  with an empty SBOM and marks it with `patchwatch-role:parent`. Existing parents are
  only looked up and not overwritten; aggregation and legacy data are thus kept.
- Detected and explicitly specified services are uploaded separately to `group/project/services` in the same
  version, with the same GitLab project tag and the parent as the parent project.
  The component name `services` is reserved for this. Every parent run updates this inventory,
  even if the parent already aggregates. An empty service inventory removes previously detected services.
  The child project upload receives the commit and pipeline origin. For `--dry-run`, the
  parent SBOM is created and next to it `<output-stem>-services.json` (with a JSON output file).
- For the safe parent lookup, the CI key needs `VIEW_PORTFOLIO`. With older installations,
  first run the setup again; alternatively provide `PATCHWATCH_READ_KEY`.
- Above the version parents, `patchwatch-versions` creates a shared navigation folder
  `<project path> @ all versions`. It does not aggregate; only the individual version parents
  sum their child projects. Projects without `component` remain individual inventory projects
  under this folder. Details in the [operations manual](../operations/index.md#version-markers-and-scan-freshness).

**Migrating existing parents** (for example LinkDash):

1. Pause parent and component uploads for the migration. Create a regular backup beforehand.
2. Run the current setup or start
   `DT_URL=https://… DT_ADMIN_PASSWORD_FILE=… python3 -m patchwatch.dtrack.groups` with admin access.
3. If the switch to `AGGREGATE_DIRECT_CHILDREN` fails with HTTP 409, the admin step exports
   the services and imports them to `<parent>/services` of the same version. Existing, conflict-free
   target inventories are kept. Only after the import has completed and a renewed export has been compared successfully
   are the original services deleted from the parent in a targeted way. Afterwards,
   aggregation is enabled again. Repeated runs use the same child project.
4. Check parent aggregation and the service inventory in the child project, then continue CI.

Package components of its own in the parent, a name collision, deviating metadata of the same service or
failed copy checks abort the setup with project, cause and action hint.
The parent is not replaced by an empty SBOM in this case. On an error during deletion,
the verified copy is already in the child project; after fixing the cause, repeat the same step.
A CI run before the migration reports parent services still present and leaves both inventories unchanged.
Whether services block aggregation for the specific LinkDash project must be confirmed
on the running system; this guide does not replace the diagnosis there.

For service collection, the [separate parser and deduplication limits](services.md) apply.

## 3. What appears in PatchWatch

| Attribute | Value |
|---|---|
| Project name | `group/project` (with `component`: `group/project/<component>`, as a child project of `group/project`) |
| Version | Default branch or additional branch from `branches`: its name. Tag: the unchanged tag name |
| Latest | Highest active stable release; as long as none exists, the default branch. Further branches and MR versions (`mr-<IID>`, see [MR feedback](mr-feedback.md)) do not replace the default branch and never count as a release. Synchronization at the latest on the next successful five-minute run |
| Origin | Exact commit URL with short SHA and branch/tag name as well as pipeline link under *External References* |
| Freshness | *Last BOM Import* shows the last processed upload; latest does not assess scan freshness |
| Tags | `managed-by:patchwatch`, `asset-type:application`, `source:gitlab-ci`, `gitlab-project-id:<id>`, `team:<team>`, optionally `environment:<value>`; for Git tags additionally `policy-profile:distribution` |

The latest selection is numeric (`v1.10.0` before `v1.9.0`), independent of upload order and
scan time. Stable tags consist of numbers, optionally with a leading `v` and dots: `v1`, `1.2`,
`v1.2.3`. Pre-releases (`v2.0.0-rc.1`), build suffixes and free labels are recorded but do not replace
a stable release. For numerically identical alias tags, the longer name wins deterministically,
then the lexically greater name. Inactive versions are not chosen as latest.

The collection project and components of the same GitLab project follow the same highest release version.
If a component lacks this version, it receives no latest tick. If no releases exist yet,
the detected default branch becomes latest. With several contradictory default branches,
no version is guessed. Existing `main`/`master` inventories are recognized even without a new upload;
other default branch names first need an upload with the new origin information.
In projects whose additional branch (e.g. `dev`) was uploaded before this change, its
version still carries the old default branch origin; the next upload corrects it.

The upload itself sends `isLatest=false`; the synchronization also corrects existing projects.
Dependency-Track 4.14 evaluates the upload field `isLatest` only on creation. A newly created or
changing state can therefore appear without a tick until the next successful synchronization.
Host projects stay at `current` and latest; the CI rule concerns only managed GitLab CI projects.

Commit SHA, ref, default branch, pipeline URL and SBOM creation time are additionally in the
CycloneDX SBOM; commit and pipeline in the `patchwatch-report.json`. The origin is updated on every
SBOM import. Collection projects that no longer accept BOMs take over the
origin links of the most recently imported direct child project of the same version during synchronization. Their own
*Last BOM Import* remains unchanged; for scan freshness, look at the child projects.

- **Projects:** in Dependency-Track, filter by tag `asset-type:application`. Machines carry
  `asset-type:workstation`; the monitor for missing uploads considers only machines.
- **Findings and policy violations:** on the project under *Audit Vulnerabilities* and *Policy Violations*.
  The rules with the tag `managed-by:patchwatch` ([policies](../configuration/policies.md)) apply automatically.
- **Alerts:** the bridge routes by `team:*` and `environment:*` ([alerting](../configuration/alerting.md)). New
  findings of a project trigger messages as with machines; check the routes before the broad rollout.
- **Job log and artifact `patchwatch-report.json`:** with `PATCHWATCH_READ_KEY`, findings by severity (from the project metrics, without suppressed findings, possibly not yet current shortly after the analysis),
  policy violations and a link to the project; without a read key, component count and local
  SBOM metadata warnings (`qualityViolations`) as well as commit SHA and pipeline link.

## 4. Limits and notes

- **Declared dependencies are recorded** from lockfiles and manifests (e.g. `package-lock.json`,
  `poetry.lock`, `go.mod`, `pom.xml`, `Cargo.lock`) as well as the packages of scanned images. Without a lockfile,
  versions are missing, and an empty inventory is rejected. A Dockerfile alone is no source; scan the
  image for that. A missing hit proves no absence of vulnerabilities.
- **Tags are set only on creation.** The CI key may upload project inventories and read the portfolio; it does not change project properties. Make changes to
  `team` or `environment` afterwards in Dependency-Track on the project (*Project → Properties*); registration
  via `patchwatch.dtrack.register` is not intended for CI projects.
- **Renaming:** If a GitLab project is renamed or moved, a new DTrack project is created on the next run.
  The old one can be found via the tag `gitlab-project-id:<id>` and archived.
- **Versions grow:** every release tag is a project version of its own. Deactivate or delete old versions
  as needed; there is no automatic cleanup.
- **The gate evaluates the whole project**, not just new findings: unsuppressed native
  policy violations and supplementary `qualityViolations` of the uploaded SBOM. Existing findings
  can therefore block even small changes. Introduce it first with `none`, assess existing findings,
  then enable the desired threshold. The upload waits for the completed
  BOM import, not for all analyzers. The gate evaluation uses the policy snapshot
  read immediately afterwards. The optional delta report waits separately for two identical
  readings; it does not update the gate snapshot read earlier. A passed run
  therefore guarantees no fully completed vulnerability or policy analysis.
- **Merge requests** upload nothing and have no access to the keys. A pre-check before
  the merge is not part of this template. Optionally, the separate
  [MR feedback loop](mr-feedback.md) adds SBOM scans and an updatable bot comment.
- The SBOM contains package names, versions, licenses, detected dependency relationships and
  package paths supplied by Syft. Source code, descriptions and authors are removed;
  workspace/image paths are not removed wholesale. These can contain confidential names.
  Treat inventories and artifacts as internal accordingly.

## 5. Troubleshooting

| Message | Cause |
|---|---|
| `PATCHWATCH_UPLOAD_KEY is not set` | Variable missing, or the branch is not protected |
| `PATCHWATCH_URL is not set` | Group variable missing or does not belong to the project's group |
| `WARNING: PatchWatch CI skipped: Branch …` | Branch is neither the default branch nor released in `branches` / `PATCHWATCH_BRANCHES`. `run_if` only controls the job start; no upload and no report |
| `Upload failed (HTTP 401/403)` | Key wrong, expired, or team without `BOM_UPLOAD`/`PROJECT_CREATION_UPLOAD` |
| `Upload failed: network/TLS error` | Runner cannot reach PatchWatch or does not trust the CA: set `PATCHWATCH_CA_CERT` |
| `Empty inventory rejected` | No lockfiles found; check `scan_paths` or scan an image |
| `Team/environment are not valid tag values` | Group name not usable as a tag: set the input `team` |
| `Parent lookup requires VIEW_PORTFOLIO` | Run the setup again for updated CI permissions or provide `PATCHWATCH_READ_KEY` |
| `Parent still owns services` | Pause CI and run `python3 -m patchwatch.dtrack.groups` with admin access for the migration |
| `fail_on needs PATCHWATCH_READ_KEY` | Gate enabled but no read key available |
| Exit code 2 | Gate triggered: native policy violations or SBOM quality findings above the chosen threshold (`patchwatch-report.json`; native findings additionally under *Policy Violations*) |
| Image pull fails | Job image not readable (registry permission, tag `v1` not built yet) |

Try it locally, without upload and without keys, in the repository directory:

```sh
docker run --rm -v "$PWD:/ws" -e CI_PROJECT_DIR=/ws -e CI_PROJECT_PATH=group/project \
  -e CI_PROJECT_ID=1 -e CI_PROJECT_ROOT_NAMESPACE=group -e CI_DEFAULT_BRANCH=main \
  -e CI_COMMIT_BRANCH=main -e PATCHWATCH_SBOM_OUTPUT=/ws/sbom.json \
  registry.example.org/platform/patchwatch/ci:v1 sh -c 'cd /opt/patchwatch && python -m patchwatch.ci --dry-run'
```

## 6. This repository: one inventory per component

The following table uses `platform/patchwatch` as an example for your own
GitLab project path. The actual inventory names result from `CI_PROJECT_PATH`.

PatchWatch consists of several parts. [`ci/components.yml`](../../ci/components.yml) includes the template
for each individually, so that every part has its own DTrack project and its own, individually
adaptable job (`.gitlab-ci.yml` includes only this file).

| Job | DTrack project | Scanned | Runs |
|---|---|---|---|
| `sbom-parent` | `platform/patchwatch` and `…/services` | empty collection project plus Compose service inventory in the child project | Default branch, stage `prepare` |
| `sbom-bridge` | `platform/patchwatch/bridge` | self-built bridge image | Default branch, after the build |
| `sbom-ci-image` | `platform/patchwatch/ci-image` | self-built job image (contains Syft) | Default branch, after the build |
| `sbom-dtrack-apiserver` | `…/dtrack-apiserver` | `dependencytrack/apiserver` | Schedule or manual |
| `sbom-dtrack-frontend` | `…/dtrack-frontend` | `dependencytrack/frontend` | Schedule or manual |
| `sbom-postgres` | `…/postgres` | `postgres` | Schedule or manual |
| `sbom-trivy` | `…/trivy` | `aquasec/trivy` (by digest) | Schedule or manual |
| `sbom-gateway` | `…/gateway` | `nginxinc/nginx-unprivileged` | Schedule or manual |

- **Hierarchy:** `platform/patchwatch` is the collection project (aggregation of the child projects, see
  "Multiple inventories"); all other projects of the table hang below it.
- **Third-party images** are scanned on a schedule because their version changes only with a commit. This way
  you see in PatchWatch the CVEs of the versions that are actually running. Manually: *Run pipeline* on the
  default branch (source `web`).
- **Maintain versions in only one place:** the image references in `ci/components.yml` must match
  [`compose.yaml`](../../compose.yaml) and the chart tag in `deploy/environments/dtrack.yaml`. The test
  `tests/test_components.py` aborts the pipeline if they diverge. On a version change,
  change all affected references including the Helm profile and SPDX generator;
  the MR scans read the images directly from the respective Compose file.
- **The agent has no project of its own.** It uses only the standard library and has no packages
  from a package manager; a lockfile would be empty. The Python version it runs with is covered via the
  bridge image, Syft via the `ci-image`. A hand-maintained manifest file for these two
  would keep versions twice and was deliberately not created.
- To adapt a single job: define the same job name in `.gitlab-ci.yml`, e.g.
  `sbom-trivy: {allow_failure: false}`. New component: add a block to `ci/components.yml` and add the
  reference to `compose.yaml`.
- The regular SBOM jobs block the deployment by default when mandatory BSI information is missing.
  For a deliberate migration, `bsi_mode: report` is possible; these inventories are not compliant.
  The jobs run with the job image of the same
  commit (`ci:<sha>`); the schedule jobs use `ci:v1` because nothing is built on a schedule.


The additional [MR feedback configuration](mr-feedback.md#patchwatch-itself) scans the same
components in MR pipelines, each for the target branch and its merge result. It creates paired SBOM artifacts; the reports
are published by a protected worker on the default branch of the same project.

## Release profile and SBOM metadata

Git tag uploads receive `policy-profile:distribution` for the native license baseline check.
For already existing projects, an administrator must add the profile tag; the upload key
does not change existing tags. Missing package versions or package URLs appear as
`qualityViolations` (`WARN`) in the report. `fail_on: warn` takes these notes into account,
`fail_on: fail` does not block because of such warnings. Explicit collection projects are exempt from
empty inventories. Rules and limits: [policy guide](../configuration/policies.md).
