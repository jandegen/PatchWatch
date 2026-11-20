# License and SPDX

Own source code and deployment files: **Apache-2.0**, full text in `LICENSE`,
notice in `NOTICE` and `SPDX-License-Identifier` in the code/script files.
The machine-readable project inventory is **`patchwatch.spdx.json` (SPDX 2.3, JSON)**.
It contains the project itself, file list, SHA-1/SHA-256 checksums,
package verification code, license declaration and relationships to the components used.
The SPDX document itself uses the data license `CC0-1.0` prescribed by the SPDX format.
This does not change the project license.

```sh
python3 scripts/spdx.py
python3 scripts/spdx.py --check
```

The generator records versioned and not yet ignored source files. The SPDX document
itself is excluded because of the checksum self-reference. Ignored secrets, virtual
environments and build artifacts are not recorded. CI checks the exact inventory.
Document namespace and package verification code depend reproducibly on the source state;
the creation date is set to the start of the project. Project version: `1.0.10`.

| Third-party component | Declared license |
|---|---|
| Syft | Apache-2.0 |
| Docker CLI | Apache-2.0 |
| Trivy | Apache-2.0 |
| Dependency-Track API / frontend / official Helm chart | Apache-2.0 |
| PostgreSQL | PostgreSQL |
| Python | Python-2.0 |
| nginx-unprivileged container build scripts | Apache-2.0 |

The SPDX packages describe **declared deployment dependencies** whose files are not
presented as analyzed. Container base operating systems and transitive third-party packages
are not fully part of this source inventory. The license of the nginx binary itself
is BSD-2-Clause; it is to be distinguished from the Apache-licensed container build scripts.
For the distribution of container images, additionally create an image SBOM with Syft and
include the license texts of the packages contained. OSV/GitHub/NVD data and optional integrations
have their own data licenses/terms of use. No third-party source code is copied into the repository.


## License inventory of the developer machines

The project SPDX describes Patchwatch itself. The licenses of the installed software
are transferred separately to Dependency-Track with each host SBOM.

The agent takes over SPDX license IDs, short license names and SPDX expressions detected by Syft.
For VS Code extensions, a short license statement from the manifest is additionally taken over,
if present. The other extension readers currently add no license metadata.
`AND`, `OR` and `WITH` are preserved; no legal assessment of its own is
derived from them. License texts, URLs and details of individual licensors are removed.
Package copies detected multiple times remain the same component; missing license information in one
scan root does not overwrite information already present from another root.
Different expressions for the same package coordinates are not combined automatically with
`AND` or `OR`; the first statement is kept and the component gets
`patchwatch:license-conflict=true` for manual review.

Without a detected license, the statement remains unknown. In particular, third-party packages do **not**
automatically receive the Apache-2.0 license of Patchwatch. Detection coverage and correctness depend on
the package metadata and the configured scan roots. A machine-detected license label
is no proof that all license obligations are met.

In DTrack, this information is at **Projects → hostname → Components** in the license column
or in the component detail. The global license view contains the SPDX license catalog and is
no evidence of complete assignment of the host packages.

The automatically managed rules comprise a license policy for missing/unresolvable
information (`WARN`), the high/critical security policy (`FAIL`) and further
[security/license rules](../configuration/policies.md#active-baseline-rules). The release profile uses the
managed license group `Patchwatch distribution baseline`; host projects do not receive this
profile automatically. License conflicts additionally appear in the compliance report. Definition, allow lists,
exceptions and report/gates are described in the [policy guide](../configuration/policies.md).
An organization-specific allow/deny list is added only with explicit specifications.

Reference: [DTrack License Evaluation](https://docs.dependencytrack.org/analysis-types/license/).
