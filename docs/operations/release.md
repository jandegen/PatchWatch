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
| `mirror-github` | Push des Quellstands und des Tags nach GitHub |
| `release-github-images` | Kopiert mit gleichem Digest `bridge:X.Y.Z`, `X.Y`, `latest` nach `ghcr.io/<owner>/<repo>/bridge` und `ci:vX.Y.Z`, `vX` nach `.../ci` (jeweils plus Commit-Tag; nur mit `GITHUB_GHCR_TOKEN`) |
| `release-github` | GitHub Release zum Tag mit `patchwatch-agent.pyz`, `.deb`, `SHA256SUMS` und der SBOM |

## GitHub-Mirror

Die GitLab-Historie wird nicht gespiegelt. Pro Release entsteht ein Commit im GitHub-Repository aus dem
getaggten Stand (`git archive`), danach ein Tag. Vorher prüft der Job den Stand gegen
`MIRROR_FORBIDDEN_PATTERNS` und bricht bei einem Treffer ab.

CI/CD-Variablen (Settings → CI/CD → Variables, alle protected):

- `GITHUB_MIRROR_URL`: z. B. `https://github.com/<owner>/patchwatch.git` (leeres oder bestehendes Repository)
- `GITHUB_MIRROR_TOKEN`: Fine-grained Token mit `Contents: write` (masked)
- `MIRROR_FORBIDDEN_PATTERNS`: Regex mit installationsspezifischen Begriffen, z. B. `example\.internal|meinuser`

- `GITHUB_GHCR_TOKEN` (optional): klassisches Personal Access Token mit `write:packages` (masked). ghcr.io
  akzeptiert keine Fine-grained Tokens. Ohne diese Variable werden keine Images veröffentlicht.

## Tokens auf GitHub erstellen

`python3 scripts/setup-release-mirror.py` zeigt zuerst, welche der vier Variablen im GitLab-Projekt schon gesetzt
und korrekt als protected (Tokens zusätzlich masked) markiert sind. Gefragt und geschrieben wird nur, was fehlt oder
falsch markiert ist; korrekte Variablen bleiben unverändert, außer mit `--force`. Die Tokens werden verdeckt abgefragt
(oder aus `GITHUB_MIRROR_TOKEN` und `GITHUB_GHCR_TOKEN` gelesen) und vor dem Schreiben gegen GitHub geprüft: Schreibzugriff
auf das Repository beziehungsweise der Scope `write:packages` (`--skip-check` schaltet das ab). Eine leere Eingabe beim
ghcr.io-Token überspringt die Image-Veröffentlichung. `--dry-run` zeigt nur den Plan. Beide Tokens vorher in GitHub
erstellen:

**1. Mirror-Token (`GITHUB_MIRROR_TOKEN`): Fine-grained Token**

1. GitHub → Profilbild → *Settings* → *Developer settings* → *Personal access tokens* → *Fine-grained tokens* →
   *Generate new token*.
2. *Token name* z. B. `patchwatch-release-mirror`, *Expiration* nach Bedarf (maximal 1 Jahr), *Resource owner*
   der Besitzer des Repositorys (bei einer Organisation muss diese Tokens erlauben).
3. *Repository access* → *Only select repositories* → das Mirror-Repository wählen.
4. *Repository permissions* → *Contents*: **Read and write**. *Metadata: Read-only* wird automatisch gesetzt.
   Mehr ist nicht nötig, auch das Release und die Assets laufen über *Contents*.
5. *Generate token* und den Wert (`github_pat_…`) sofort kopieren; er wird nur einmal angezeigt.

**2. ghcr.io-Token (`GITHUB_GHCR_TOKEN`): klassisches Token**

Fine-grained Tokens unterstützen GitHub Packages nicht, es muss ein *Personal access token (classic)* sein.

1. GitHub → *Settings* → *Developer settings* → *Personal access tokens* → *Tokens (classic)* →
   *Generate new token* → *Generate new token (classic)*.
2. *Note* z. B. `patchwatch-ghcr`, *Expiration* nach Bedarf.
3. Scope **`write:packages`** ankreuzen (`read:packages` wird mit gesetzt). Keine weiteren Scopes.
4. *Generate token* und den Wert (`ghp_…`) sofort kopieren.
5. Das Token gehört dem Benutzer und schreibt mit dessen Rechten. Für ein Repository in einer Organisation muss
   das Token für SSO autorisiert sein (*Configure SSO* neben dem Token) und der Benutzer Pakete in der Organisation
   anlegen dürfen. Am besten ein dediziertes Dienstkonto verwenden.

Läuft ein Token ab, schlägt der jeweilige Job fehl: dann ein neues erstellen und das Skript erneut ausführen.

## Artefakte und Images auf GitHub

`release-github` legt das GitHub Release zum gespiegelten Tag an und lädt Agent-Pakete, Prüfsummen und die
Projekt-SBOM hoch; bei einem erneuten Lauf werden gleichnamige Assets ersetzt. Die macOS-`.pkg` ist unsigniert
und wird nicht veröffentlicht.

In der SBOM werden interne Registry-Namen durch die öffentlichen ghcr.io-Namen ersetzt, die Referenzen auf
Bridge- und CI-Image zeigen damit auf veröffentlichte Images. Das CI-Image (`ghcr.io/<owner>/<repo>/ci:vX`) ist
der Job-Container der CI-Vorlagen; wer sie einbindet, übergibt es als `image`-Input. Alle Dateien (auch die Inhalte von `.pyz` und `.deb`) und
das Image samt Konfiguration werden vor dem Upload gegen `MIRROR_FORBIDDEN_PATTERNS` geprüft; ein Treffer
bricht den Job ab, bevor etwas veröffentlicht wird.

Die Images werden kopiert, nicht neu gebaut: Der Digest auf ghcr.io entspricht dem in der GitLab-Registry und in
der SBOM. Beim ersten Push entstehen die Pakete als privat. Einmalig unter *Package settings* auf *Public*
stellen (für `bridge` und `ci`) und mit dem Repository verknüpfen, sonst sind die Images nicht anonym abrufbar.

Installationsspezifische Werte (Hostnamen, OIDC-Issuer, Root-CA) liegen in einem privaten Repository,
siehe `PATCHWATCH_ENV_PROJECT` und `PATCHWATCH_ENV_DIR` in der [Anpassung](../installation/customization.md).
Tags `v*` als geschützte Tags konfigurieren.
