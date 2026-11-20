# Release

A release is created by a tag `vX.Y.Z` (must match `version` in `pyproject.toml` and
`patchwatch/__init__.py`):

```bash
git tag v0.2.0 && git push origin v0.2.0
```

After the tests, the pipeline (`ci/release.yml`) runs:

| Job | Result |
|---|---|
| `verify-release` | Tag and project version match |
| `release-bridge-image` | `bridge:X.Y.Z`, `bridge:X.Y`, `bridge:latest` in the registry (the CI image is built by `build-ci-image`) |
| `release-packages` | `patchwatch-agent.pyz`, `.deb`, `patchwatch-ci-templates.tar.gz`, `SHA256SUMS` in the generic package registry (`packages/generic/patchwatch-agent/X.Y.Z`); with `GITHUB_MIRROR_URL` also `setup-gitlab-project.sh` |
| `release-pkg-macos` | macOS `.pkg`, only with `PATCHWATCH_MACOS_RUNNER=true` and a runner with tag `macos`; unsigned |
| `release-sbom-parent`, `release-sbom-bridge`, `release-sbom-ci-image` | Collection project and version `vX.Y.Z` of the bridge and the CI image in PatchWatch/Dependency-Track (profile `distribution`, delta report against the previous release); `allow_failure`, a dTrack outage does not block the release |
| `sbom-dtrack-*`, `sbom-postgres`, `sbom-trivy`, `sbom-gateway` | Third-party images as version `vX.Y.Z` in dTrack (also run on tags, `allow_failure`) |
| `release-sbom-project` | One CycloneDX 1.6 SBOM for the entire project (repository plus bridge, CI image and all images from `compose.yaml`), artifact `patchwatch-sbom.cdx.json` without expiry |
| `release` | GitLab release with download links, including the SBOM |
| `mirror-github` | Push of the source state and tag to GitHub |
| `release-github-images` | Copies `bridge:X.Y.Z`, `X.Y`, `latest` to `ghcr.io/<owner>/<repo>/bridge` and `ci:vX.Y.Z`, `vX` to `.../ci` with the same digest (each plus a commit tag; only with `GITHUB_GHCR_TOKEN`) |
| `release-github` | GitHub release for the tag with `patchwatch-agent.pyz`, `.deb`, `patchwatch-ci-templates.tar.gz`, `setup-gitlab-project.sh`, `SHA256SUMS` and the SBOM |

## GitHub mirror

The GitLab history is not mirrored. For each release, one commit is created in the GitHub repository from the
tagged state (`git archive`), followed by a tag. Beforehand, the job checks the state against
`MIRROR_FORBIDDEN_PATTERNS` and aborts on a match.

CI/CD variables (Settings → CI/CD → Variables, all protected):

- `GITHUB_MIRROR_URL`: e.g. `https://github.com/<owner>/patchwatch.git` (empty or existing repository)
- `GITHUB_MIRROR_TOKEN`: fine-grained token with `Contents: write` (masked)
- `MIRROR_FORBIDDEN_PATTERNS`: regex with installation-specific terms, e.g. `example\.internal|myuser`

- `GITHUB_GHCR_TOKEN` (optional): classic personal access token with `write:packages` (masked). ghcr.io
  does not accept fine-grained tokens. Without this variable, no images are published.

## Creating tokens on GitHub

`python3 scripts/setup-release-mirror.py` first shows which of the four variables are already set in the GitLab
project and correctly marked as protected (tokens additionally masked). It only asks for and writes what is missing
or wrongly marked; correct variables stay unchanged unless `--force` is given. The tokens are prompted for without
echo (or read from `GITHUB_MIRROR_TOKEN` and `GITHUB_GHCR_TOKEN`) and checked against GitHub before writing: write
access to the repository and the scope `write:packages` respectively (`--skip-check` disables this). An empty input
for the ghcr.io token skips image publishing. `--dry-run` only shows the plan. Create both tokens in GitHub first:

**1. Mirror token (`GITHUB_MIRROR_TOKEN`): fine-grained token**

1. GitHub → profile picture → *Settings* → *Developer settings* → *Personal access tokens* → *Fine-grained tokens* →
   *Generate new token*.
2. *Token name* e.g. `patchwatch-release-mirror`, *Expiration* as needed (at most 1 year), *Resource owner*
   the owner of the repository (for an organization, it must allow tokens).
3. *Repository access* → *Only select repositories* → choose the mirror repository.
4. *Repository permissions* → *Contents*: **Read and write**. *Metadata: Read-only* is set automatically.
   Nothing more is needed; the release and its assets also go through *Contents*.
5. *Generate token* and copy the value (`github_pat_…`) immediately; it is shown only once.

**2. ghcr.io token (`GITHUB_GHCR_TOKEN`): classic token**

Fine-grained tokens do not support GitHub Packages; it must be a *personal access token (classic)*.

1. GitHub → *Settings* → *Developer settings* → *Personal access tokens* → *Tokens (classic)* →
   *Generate new token* → *Generate new token (classic)*.
2. *Note* e.g. `patchwatch-ghcr`, *Expiration* as needed.
3. Tick the scope **`write:packages`** (`read:packages` is set along with it). No further scopes.
4. *Generate token* and copy the value (`ghp_…`) immediately.
5. The token belongs to the user and writes with that user's permissions. For a repository in an organization, the
   token must be authorized for SSO (*Configure SSO* next to the token) and the user must be allowed to create
   packages in the organization. Ideally use a dedicated service account.

If a token expires, the respective job fails: create a new one and run the script again.

## Artifacts and images on GitHub

`release-github` creates the GitHub release for the mirrored tag and uploads agent packages, checksums and the
project SBOM; on a rerun, assets of the same name are replaced. The macOS `.pkg` is unsigned and is not published.

In the SBOM, internal registry names are replaced by the public ghcr.io names, so the references to the bridge and
CI image point to published images. The CI image (`ghcr.io/<owner>/<repo>/ci:vX`) is the job container of the CI
templates; anyone including them passes it as the `image` input. All files (including the contents of `.pyz` and
`.deb`) and the image including its configuration are checked against `MIRROR_FORBIDDEN_PATTERNS` before the upload;
a match aborts the job before anything is published.

`patchwatch-ci-templates.tar.gz` holds the CI templates and the name of the public CI image of this release;
`setup-gitlab-project.sh` is the [setup script](../usage/gitlab-setup-script.md) with this release's download
location filled in (both are covered by `SHA256SUMS` and by the pattern check). The script is only built when
`GITHUB_MIRROR_URL` is set, because it needs a public download location.

The images are copied, not rebuilt: the digest on ghcr.io matches the one in the GitLab registry and in the SBOM.
On the first push the packages are created as private. Once, under *Package settings*, set them to *Public*
(for `bridge` and `ci`) and link them to the repository, otherwise the images cannot be pulled anonymously.

Installation-specific values (hostnames, OIDC issuer, root CA) live in a private repository,
see `PATCHWATCH_ENV_PROJECT` and `PATCHWATCH_ENV_DIR` in the [customization guide](../installation/customization.md).
Configure tags `v*` as protected tags.
