# BSI check of the CI SBOMs

The CI processing checks the machine-verifiable requirements of
[BSI TR-03183-2 v2.1.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=6)
before the upload. The output is CycloneDX 1.6 JSON. This concerns the regular
CI SBOMs as well as the upload of branch/MR SBOMs by the protected worker.
The SPDX source inventory of the repository and the host agent inventory are separate from it.

## Behavior and migration

`bsi_mode: enforce` is the default. Missing mandatory information refuses the upload,
independent of `fail_on` and of the presence of a read key. The regular
SBOM job now has `allow_failure: false`. Existing integrations must add their
missing manufacturer, license and file information; a successful
Syft inventory alone is not sufficient for this. Update the template and CI image together.

Before the upload, the following are created in the project directory:

- `patchwatch-sbom.json`: the SBOM actually intended for upload;
- `patchwatch-bsi-report.json`: rules, components and missing information, even if the
  upload is refused. `checksPassed` refers only to the implemented checks;
  it is no certification or assurance of complete recording of the scope of delivery.

Both files are job artifacts, even for a failed job. `--dry-run`
runs the same checks without upload and without an API key. For an
explicit stocktaking during the migration, `bsi_mode: report`
can be set: BSI field gaps are then logged and the inventory may be
uploaded. It is therefore **not to be classified as BSI-compliant**. Invalid
CycloneDX JSON is not uploaded even in this mode.

`mode: parent` and the associated service project are management objects for
Dependency-Track. Their report marks them as not applicable; their empty
documents are not SBOMs of a delivered item. The component SBOMs must be checked
separately. The DTrack project hierarchy does not replace an external BOM reference.

## Project information

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      stage: scan
      scan_paths: dist
      sbom_creator: security@example.org
      component_creator: https://example.org/product
      distribution_license: Apache-2.0
      bsi_metadata: compliance/sbom-metadata.json
```

The stage `scan` must exist in the including project and come after the build.
`dist` here denotes the actual delivery directory, not the
entire source tree wholesale. Exclusions must not hide delivered components.

| Input | Environment variable | Meaning |
|---|---|---|
| `bsi_mode` | `PATCHWATCH_BSI_MODE` | `enforce` or, explicitly, `report` |
| `bsi_metadata` | `PATCHWATCH_BSI_METADATA` | JSON file relative to `CI_PROJECT_DIR` |
| `sbom_creator` | `PATCHWATCH_SBOM_CREATOR` | Email or HTTP(S) URL of the SBOM creator; without it `CI_PROJECT_URL` |
| `component_creator` | `PATCHWATCH_COMPONENT_CREATOR` | Creator of the primary logical component; without it `CI_PROJECT_URL` |
| `distribution_license` | `PATCHWATCH_DISTRIBUTION_LICENSE` | Verified SPDX expression of the distribution license of the primary component |

The last two statements also apply to the logical scan roots of your own
repository directories. They are **not** transferred to third-party packages or
containers. `supplier` is not interpreted as `manufacturer`. The global
license expression is not used as the distribution license of all dependencies.

## Verified metadata per component

The JSON file optionally contains `root` and `components`. `root` supplements the primary
component. Keys under `components` are exact output `bom-ref`s, purls or
`file:` plus the full Syft file name, for example `file:/app/start.py`.
The full name is in `patchwatch-sbom.json`; the error report additionally
contains names, version and purl. Non-matching selectors are errors so that
outdated statements do not disappear unnoticed.

```json
{
  "components": {
    "pkg:pypi/example@1.2.3": {
      "manufacturer": {"url": ["https://example.org/library"]},
      "licenses": [{"expression": "MIT", "acknowledgement": "concluded"}],
      "externalReferences": [
        {"type": "source-distribution", "url": "https://example.org/library/source/1.2.3"}
      ]
    },
    "file:/app/start.py": {
      "manufacturer": {"url": ["https://example.org/product"]},
      "licenses": [{"expression": "Apache-2.0", "acknowledgement": "concluded"}],
      "artifact": "dist/app/start.py",
      "properties": [
        {"name": "bsi:component:executable", "value": "executable"},
        {"name": "bsi:component:archive", "value": "no archive"},
        {"name": "bsi:component:structured", "value": "unstructured"}
      ],
      "externalReferences": [
        {"type": "distribution", "url": "https://example.org/releases/1.0/app/start.py"}
      ]
    }
  }
}
```

`artifact` is optional. It denotes a real file within the checkout.
The generator computes its SHA-512, sets the actual file name and,
if the version is missing, uses its modification time in RFC 3339. Existing
version identifiers are kept. Paths outside the checkout, including via
symlinks, are rejected. Archive content paths and image paths are never
resolved against files of the runner host.

For directory scans, the generator determines missing file versions automatically
from the local file metadata. For files in images, missing versions
or modification times must be added from the build or image. Existing
SHA-512 file hashes are carried over to explicitly specified distribution references.
The distribution URI must point to the component that is actually deliverable;
the generator does not invent a download address for it.

Physical files need all three classifications. The executable bit
alone is not enough: Python files and shared libraries are also executable in the
sense of the guideline. Whether a binary contains statically linked components or
a decomposable structure must be evident from the build or an analysis.
Logical components do not need these file fields.

A purl selector may supplement general creator/license statements for multiple instances.
Instance-specific changes to name, version, type, hash or `artifact`
need the individual `bom-ref` if ambiguous. The processing no longer merges
instances.

## Licenses and delivery boundary

A scanner license does not automatically become a verified distribution license.
A valid SPDX license or SPDX expression with
`acknowledgement: concluded` is required. Names such as `Custom Licence` and unknown identifiers
are errors. Licenses not covered by SPDX must, after checking the SPDX and
ScanCode lists, be described by a suitable `LicenseRef-...`.

CycloneDX 1.6 allows only one expression in `licenses`. If a verified
distribution expression replaces the original scanner observations, they stay
machine-readable as JSON in `patchwatch:bsi:original-licenses`.
These original statements must also use valid SPDX identifiers/expressions;
if needed, explicitly replace the property with verified original license statements.
This way, original and distribution licenses are not lost on merging.

According to chapter 3.2.4, the first dependency outside the scope of delivery may only be
identified. This must be marked deliberately per component with the property
`{"name":"patchwatch:bsi:scope","value":"identified"}`.
It still needs creator, name, version and existing unambiguous
identifiers. Delivered components must not use this exception.

## Dependencies, versions and limits

Scanner roots, nested components, known empty dependency lists,
files, hashes and component references are kept. References are
rewritten per scan so that identical scanner IDs from different images
do not collide. Containment is a directed relationship per chapter 3.2.7.
Existing `compositions` are kept; otherwise completeness is
explicitly reported as `unknown`. Unknown is not reported as complete.
The scan settings record all files with SHA-512, including files not managed by a package manager; this increases the
scope compared with the earlier inventory.

For navigation, the DTrack version remains a branch/tag/MR slot. The
primary component of the regular SBOM, however, carries commit SHA plus
inventory fingerprint for branches, and the release identifier for tags. Changes to an image
under the same tag therefore change the snapshot version for branch scans.
Branch/MR documents carry the scanned commit or merge tree;
the worker uses the verified commit as the primary version.

**The checks prove no complete recording of the scope of delivery.** The producer
must still ensure that all delivered executables and archives,
statically linked components, interpreters and the first external dependency
are recorded and that the information matches the build. A package scan cannot replace
this substantive check. The JSON schema check runs offline against
bundled official CycloneDX schemas; vulnerability information is processed
separately from the SBOM.

## Branch/MR scans

`mr-sbom.yml` and `branch-sbom.yml` also support `bsi_metadata`,
`sbom_creator`, `component_creator` and `distribution_license`. The metadata file
is read from each tree actually scanned, not from the current
worker checkout. The scan artifacts contain `bsiFindings` for diagnosis.

The protected worker checks the documents again before every upload. Its
`mr-feedback.yml` supports `bsi_mode`, `sbom_creator`, `component_creator` and
`distribution_license` for the primary component it creates. Creators and
distribution licenses of the subcomponents must already be in the scan artifact.
The worker executes no file paths supplied from the artifact. Its SBOMs and
BSI reports are in the directory `patchwatch-mr-reports/` with version-dependent names
and are part of the existing job artifacts.
