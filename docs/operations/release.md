# Release

Ein Release entsteht durch einen Tag `vX.Y.Z` (muss zu `version` in `pyproject.toml` und
`patchwatch/__init__.py` passen):

```bash
git tag v0.2.0 && git push origin v0.2.0
```

Die Pipeline (`ci/release.yml`) führt nach den Tests aus:

| Job | Ergebnis |
|---|---|
| `verify-release` | Tag und Projektversion stimmen überein |
| `release-bridge-image` | `bridge:X.Y.Z`, `bridge:X.Y`, `bridge:latest` in der Registry (das CI-Image baut `build-ci-image`) |
| `release-packages` | `patchwatch-agent.pyz`, `.deb`, `SHA256SUMS` in der generischen Paketablage (`packages/generic/patchwatch-agent/X.Y.Z`) |
| `release-pkg-macos` | macOS-`.pkg`, nur mit `PATCHWATCH_MACOS_RUNNER=true` und einem Runner mit Tag `macos`; unsigniert |
| `release-sbom-parent`, `release-sbom-bridge`, `release-sbom-ci-image` | Sammelprojekt und Version `vX.Y.Z` der Bridge und des CI-Images in PatchWatch/Dependency-Track (Profil `distribution`, Delta-Bericht zum vorherigen Release); `allow_failure`, ein dTrack-Ausfall blockiert das Release nicht |
| `sbom-dtrack-*`, `sbom-postgres`, `sbom-trivy`, `sbom-gateway` | Drittanbieter-Images als Version `vX.Y.Z` in dTrack (laufen bei Tags ebenfalls, `allow_failure`) |
| `release-sbom-project` | Eine CycloneDX-1.6-SBOM für das gesamte Projekt (Repository plus Bridge, CI-Image und alle Images aus `compose.yaml`), Artefakt `patchwatch-sbom.cdx.json` ohne Ablauf |
| `release` | GitLab-Release mit Download-Links, darunter die SBOM |
| `mirror-github` | Push von Standardbranch und Tag nach GitHub |

## GitHub-Mirror

Die GitLab-Historie wird nicht gespiegelt. Pro Release entsteht ein Commit im GitHub-Repository aus dem
getaggten Stand (`git archive`), danach ein Tag. Vorher prüft der Job den Stand gegen
`MIRROR_FORBIDDEN_PATTERNS` und bricht bei einem Treffer ab.

CI/CD-Variablen (Settings → CI/CD → Variables, alle protected):

- `GITHUB_MIRROR_URL`: z. B. `https://github.com/<owner>/patchwatch.git` (leeres oder bestehendes Repository)
- `GITHUB_MIRROR_TOKEN`: Fine-grained Token mit `Contents: write` (masked)
- `MIRROR_FORBIDDEN_PATTERNS`: Regex mit installationsspezifischen Begriffen, z. B. `example\.internal|meinuser`

Installationsspezifische Werte (Hostnamen, OIDC-Issuer, Root-CA) liegen in einem privaten Repository,
siehe `PATCHWATCH_ENV_PROJECT` und `PATCHWATCH_ENV_DIR` in der [Anpassung](../installation/customization.md).
Tags `v*` als geschützte Tags konfigurieren.
