# Connecting a GitLab project with the setup script

`setup-gitlab-project.sh` connects an existing GitLab project to PatchWatch in a few minutes. It is an interactive
shell script: each step first says what it is about to do, asks before it writes anything, and the end of the run
lists what you still have to do. It needs no Python, no `glab` and no clone of the project.

What it sets up is the [CI template](ci-integration.md) `ci-templates/sbom.yml`: a job that creates a
CycloneDX SBOM of the repository (and optionally of container images) and uploads it to PatchWatch. The script
does not change the PatchWatch server and never pushes to your default branch: the CI configuration arrives as a
merge request.

## What you need

| Requirement | Details |
|---|---|
| Tools | A POSIX shell, `curl`, `jq`, `tar` and `sha256sum` (or `shasum` on macOS). The script checks them first and, if `jq` is missing, stops with an install hint before doing anything. |
| GitLab | Version 17.0 or newer (the template uses `spec:inputs`) and the **Maintainer** role in the project. |
| GitLab token | A personal access token with the scope `api` (*Preferences → Access tokens*). Short expiry is fine, it is used for this run only. |
| PatchWatch URL | HTTPS address of your PatchWatch server, e.g. `https://patchwatch.example.org`. |
| Upload key | The key of the team `ci-upload`. The operator of PatchWatch has it (`ci_upload_key`, see [section 1.1](ci-integration.md#11-keys)). |
| Job image | Comes with the release: the public image `ghcr.io/<owner>/<repo>/ci:vX.Y.Z`. Your runners must be able to pull it. |

The default branch must be protected, because the upload key is stored as a *protected* variable. If it is not,
the script offers to protect it.

## Quick start

Download the script from the PatchWatch release, check it, read it, then run it. Do not pipe it into a shell:
the script asks questions and needs your keyboard.

```sh
base=https://github.com/<owner>/<repo>/releases/download/vX.Y.Z
curl -fsSLO "$base/setup-gitlab-project.sh"
curl -fsSLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS      # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
less setup-gitlab-project.sh                       # optional, but it is a short read
sh setup-gitlab-project.sh
```

The script asks for everything it does not find in the environment or in options. For secrets, use the
environment so that they never appear on a command line or in your shell history:

```sh
export GITLAB_TOKEN=...             # otherwise the script asks, with hidden input
export PATCHWATCH_UPLOAD_KEY=...    # otherwise the script asks, with hidden input
sh setup-gitlab-project.sh --project group/project --patchwatch-url https://patchwatch.example.org
```

## The eight steps

| # | Step | What happens | Writes? |
|---|---|---|---|
| 1 | Check prerequisites | Looks for the required tools | no |
| 2 | Log in to GitLab | Reads the project, checks the token with `GET /user` | no |
| 3 | Check the project | Checks your role, the GitLab version and the default branch; offers to protect the branch | only the branch protection, after asking |
| 4 | Check the PatchWatch server | Tests the URL and the upload key (and an optional read key) with one read-only request | no |
| 5 | Download the CI templates | Downloads `patchwatch-ci-templates.tar.gz` and `SHA256SUMS` from the release and verifies the checksum | no |
| 6 | Choose what to inventory | Looks at file names in your repository and asks about layout, services, images, stages | no |
| 7 | Store the CI/CD variables | Creates `PATCHWATCH_URL`, `PATCHWATCH_UPLOAD_KEY` and optionally the read key and the CA certificate | after asking |
| 8 | Create the merge request | Commits to a new branch, validates with GitLab's CI lint, opens the merge request | after asking |

Step 6 shows the complete generated configuration and the PatchWatch project names before anything is written.
At the end the script prints three blocks: **What the script did**, **What you need to do now** (merge the request,
wait for the pipeline, check PatchWatch, revoke the token) and **If something goes wrong**.

### What to inventory

The script reads only the **names** of the files in your repository (through the GitLab API) to make suggestions.
It then asks:

- **Layout.** *One inventory* for the whole repository, or *one inventory per component* for a monorepo. For
  components, the script suggests the folders that contain dependency manifests or Dockerfiles; you accept, rename
  or add components. Each component becomes its own PatchWatch project `group/project/<component>`, below a parent
  project `group/project`. The script generates the parent job (`mode: parent`, stage `.pre`) that has to run first,
  see [Multiple inventories](ci-integration.md#multiple-inventories-hierarchy). The component name `services` is
  reserved.
- **Services.** Whether to list the services of Compose files ([details and limits](services.md)), and additional
  service names. In the component layout, services go to the parent job (`group/project/services`).
- **Images.** Container images to scan, if your pipeline pushes them before the scan stage. Choose the stage
  that runs after the build.
- **Team, environment, BSI mode, extra branches, `fail_on`.** All with an explanation and a default. The BSI mode
  starts at `report`; switch to `enforce` once the [BSI metadata](bsi-sbom.md) is complete. `fail_on` is only offered
  when you supplied a read key.
- **Stages.** If your `.gitlab-ci.yml` defines `stages:`, the script reads them and asks which one the inventory
  jobs should use.

## What ends up in your project

| File | Content |
|---|---|
| `.gitlab/patchwatch/sbom.yml` | The template, unchanged, from the release. Do not edit; use `--update`. |
| `.gitlab/patchwatch/patchwatch.yml` | The generated jobs (one `include` per job with its `inputs`) and a machine-readable header with your answers. |
| `.gitlab-ci.yml` | One added line, `- local: .gitlab/patchwatch/patchwatch.yml`, under `include:`. |

The script never rewrites a `.gitlab-ci.yml` that already has an `include:` section. It prints the line for you to
add and lists it under *What you need to do now*. An existing file without `include:` gets an `include:` block
appended; a missing file is created. The merge request is only opened if GitLab's CI lint accepts the result.

The CI/CD variables are created on the project (or on a group with `--group`):

| Variable | Flags | Content |
|---|---|---|
| `PATCHWATCH_URL` | plain | The PatchWatch URL |
| `PATCHWATCH_UPLOAD_KEY` | masked, protected | Upload key |
| `PATCHWATCH_READ_KEY` | masked, protected, optional | Read key (`monitor_key`): result summary, `fail_on`, delta report |
| `PATCHWATCH_CA_CERT` | file, optional | CA certificate for servers with an internal CA (`--ca-cert-file`) |

A variable that already exists with the right settings is kept. Wrong flags are corrected. A variable with a
different value is kept unless you pass `--force`.

## Options

Nearly everything the script asks can be passed as an option, so it also runs without a terminal (`--yes` takes the
default of every question; BSI metadata files and per-component images are only offered interactively). `sh setup-gitlab-project.sh --help` prints the full list.

| Option | Meaning |
|---|---|
| `--gitlab-url`, `--project`, `--group` | Instance, project (path, ID or URL) and an optional group for the variables |
| `--patchwatch-url`, `--ca-cert-file` | PatchWatch server and its CA certificate |
| `--component NAME=PATH` | One inventory per component (repeatable); `--no-components` for a single inventory |
| `--service NAME`, `--no-detect-services` | Additional services; switch off Compose detection |
| `--scan-image REF`, `--image-stage`, `--component-stage` | Images to scan and the stages of the jobs |
| `--team`, `--environment`, `--bsi-mode`, `--branch`, `--fail-on` | Template inputs, see [Configuration](ci-integration.md#configuration-inputs) |
| `--job-image` | CI job image (default: the one named in the release) |
| `--dry-run` | Do everything that only reads, show the plan, write nothing |
| `--yes`, `--force` | Accept defaults; overwrite variables that exist with another value |
| `--update` | Refresh the vendored template, keep your configuration |
| `--reconfigure` | Ask the inventory questions again, with your previous answers as defaults |
| `--branch-name` | Branch for the merge request (default `patchwatch/setup`) |
| `--release-url`, `--templates-archive` | Download location, or a local archive (not checksum-verified) |

Examples:

```sh
# see what would happen, change nothing
sh setup-gitlab-project.sh --dry-run

# monorepo, no questions
sh setup-gitlab-project.sh --yes --project acme/shop --patchwatch-url https://patchwatch.example.org \
  --component api=services/api --component web=web --team platform

# refresh the template after a PatchWatch release
sh setup-gitlab-project.sh --update --project acme/shop --patchwatch-url https://patchwatch.example.org
```

## Safety

- The token is written to a private temporary file (mode `0600`) that `curl` reads with `-K`. It is never on a
  command line, never printed and never sent to anything except your GitLab instance. The upload key is handled
  the same way. Request bodies with secrets are files, not arguments. The temporary directory is removed on exit,
  also after an error or Ctrl+C.
- The templates archive is downloaded without any GitLab credentials and verified against `SHA256SUMS`. A mismatch
  stops the script before anything is written.
- The script refuses `http://` URLs for GitLab and PatchWatch.
- Nothing is committed to your default branch. Abandoning the script at a confirmation leaves the project
  untouched, except for what earlier steps already confirmed (for example the variables from step 7).
- Re-running is safe: it only changes what is missing or wrong, and says so.

## Troubleshooting

| Message or symptom | Cause and remedy |
|---|---|
| `'jq' is missing` | Install `jq` (`apt install jq`, `brew install jq`, `apk add jq`, `winget install jqlang.jq`) and run again. |
| `GitLab rejected the token (HTTP 401)` | Token expired or without the scope `api`. |
| `You need the Maintainer role` | Ask a maintainer to run the script or raise your role. |
| `rejected the upload key (HTTP 401/403)` | Use the `ci_upload_key` (team `ci-upload`), not an agent or read key. |
| `Cannot reach https://...` | URL, network or proxy. For an internal CA pass `--ca-cert-file ca.pem`. |
| `Checksum mismatch` | Damaged or tampered download; nothing was written. Download again. |
| `CI lint reports errors` | Usually a stage that does not exist in your pipeline. The branch is kept for inspection; run again with `--reconfigure` and pick existing stages. |
| Job: upload key or URL not set | The key is protected: the pipeline must run on a protected branch or tag. |
| Job: `404 ... parent not found` | The parent job did not run first (component layout); check that `patchwatch-sbom-parent` exists and is in `.pre`. |
| Runner cannot pull the job image | Make the `ghcr.io` package of the CI image public, or mirror it and pass `--job-image`. |

## Limits

- Only the SBOM job is set up. Merge-request feedback and branch scans (`mr-feedback.yml`, `mr-sbom.yml`,
  `branch-sbom.yml`) need schedules and a read key and are configured as described in [MR feedback](mr-feedback.md).
- The script is tested with dash, busybox ash and bash on Linux. It should work on macOS; on Windows use WSL.
- The component suggestions come from file names only. Review them; the script never reads file contents.
- The release provides the script and the templates only when the project is mirrored to GitHub (see
  [Release](../operations/release.md)). Without that, pass `--release-url` or `--templates-archive`.
