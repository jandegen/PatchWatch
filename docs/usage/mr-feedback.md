# Findings-Bericht für einen Merge Request

Patchwatch veröffentlicht direkt im jeweiligen MR, was sich **durch dessen Merge** ändern
würde: neue und behobene/entfallende Schwachstellen mit CVE, Schweregrad und Paket sowie
hinzukommende, entfallende und geänderte Lizenzen je Paket. Auch unveränderte Lizenztypen
werden einem neu hinzukommenden oder entfernten Paket zugeordnet. Policy-Verstöße werden
in beide Richtungen ausgewiesen. Ein Bot aktualisiert seinen vorhandenen Kommentar je
MR und Komponente, statt bei jedem Lauf einen weiteren anzulegen.

Der Vergleich lautet **aktueller Zielbranch ohne MR → Zielbranch mit diesem MR**. Dafür
berechnet der Scanner mit `git merge-tree --write-tree` einen echten Drei-Wege-Merge und
scannt beide Bäume im selben Job. Änderungen am Zielbranch, die im Quellbranch noch fehlen,
bleiben dadurch auf beiden Seiten erhalten. Es werden weder eine alte Release-Version noch
der Quellbranch allein als Vergleich herangezogen. GitLabs kostenpflichtige Merged-results-
Pipelines sind dafür nicht erforderlich; existierende Merged-results-Pipelines werden ebenfalls
unterstützt, wenn ihr synthetischer Commit den aktuellen MR-Quellstand als Elterncommit enthält.

## Einbindung im selben Projekt

Zwei wiederverwendbare Templates genügen. Die Includes auf einen geprüften Patchwatch-Commit
und das CI-Image auf dessen Build-SHA oder Digest festlegen. Das Image muss die gepaarte
Scan-Funktion enthalten (Artefaktformat 2), Git >= 2.38 und Syft; das aktuelle `Dockerfile.ci`
enthält außerdem Docker CLI für optionale Image-Builds.

```yaml
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
stages: [test]
include:
  - project: platform/patchwatch
    ref: <geprüfter Commit>
    file: ci-templates/mr-sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<Digest>
      scan_paths: .
  - project: platform/patchwatch
    ref: <derselbe geprüfte Commit>
    file: ci-templates/mr-feedback.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<Digest>
```

Der Scanner `patchwatch-mr-sbom` läuft nur in MR-Pipelines und benötigt weder Bot- noch
dTrack-Schlüssel. `GIT_DEPTH=0` stellt die gemeinsame Historie bereit. Er lädt den aktuellen
Zielbranch über `origin`, berechnet den Merge und materialisiert beide Bäume getrennt,
ohne das ausgecheckte Repository zu verändern. Bei einem Merge-Konflikt entsteht ein
explizites Konfliktartefakt; es wird kein vermeintlicher Änderungsbericht veröffentlicht.

Der Worker `patchwatch-mr-feedback` läuft im **selben Projekt**, ausschließlich auf dessen
geschütztem Default-Branch als Schedule- oder Web-Pipeline mit `PATCHWATCH_MR_FEEDBACK=true`.
Er checkt keinen Anwendungscode aus, übernimmt keine geerbten Build-Skripte und verarbeitet
nur die Scan-Artefakte. Ein separates Worker-Projekt ist optional: dafür `project_id` auf die
Zielprojekt-ID setzen. Ohne Input (Standard `0`) wird `CI_PROJECT_ID` verwendet.

Normale Jobs und Includes bei `PATCHWATCH_MR_FEEDBACK=true` ausschließen, damit der
Feedback-Zeitplan keine Builds oder Deployments auslöst, z. B. als erste Job-Regel:

```yaml
rules:
  - if: '$PATCHWATCH_MR_FEEDBACK == "true"'
    when: never
  # Danach die bisherigen Regeln dieses Jobs.
```

Patchwatchs `.gitlab-ci.yml` zeigt dies einschließlich bedingter Includes. Bei eigenen
übergeordneten `workflow:rules` Schedule-/Web-Pipelines auf dem Default-Branch zulassen.

## Scan-Eingaben

| Input | Bedeutung |
|---|---|
| `job_name`, `stage`, `image` | Jobname, Stage und Scanner-Image |
| `scan_paths` | Zu scannende Verzeichnisse, Standard `.`; mit `''` deaktivieren |
| `exclude` | Zusätzliche Syft-Ausschlüsse |
| `dockerfiles` | Leerzeichengetrennte Dockerfile-Pfade; jedes wird mit Repository-Root als Kontext in beiden Bäumen gebaut |
| `compose_images` | Leerzeichengetrennte Selektoren wie `compose.yaml:postgresql`; liest die jeweilige Image-Version getrennt aus beiden Bäumen |
| `images` | Zusätzliche feste Registry-Referenzen, identisch auf beiden Seiten; für Änderungen durch den MR stattdessen `dockerfiles` oder `compose_images` verwenden |

`dockerfiles` benötigt einen Docker-Daemon im **Scanner-Job**, z. B. einen `docker:dind`-Service
mit passenden `DOCKER_HOST`-/TLS-Einstellungen. Es werden explizit Dockerfiles gebaut; das
kann deren Build-Befehle ausführen. Dafür niemals geschützte Bot-/dTrack-Schlüssel bereitstellen.
Die gebauten Images werden lokal als Docker-Archive gescannt, anschließend aufgeräumt und
nicht in die Registry hochgeladen. Der Worker benötigt keinen Docker-Daemon.

Compose-Selektoren unterstützen einfache `services:`-Definitionen mit wörtlichen `image:`-
Referenzen. Image-Variablen und Build-only-Dienste werden nicht geraten, sondern als Fehler
gemeldet. Hier werden Image-Pakete verglichen, keine CycloneDX-Serviceinventare.
Verschwindet ein ausgewählter Dienst, Dockerfile oder Scanpfad auf einer Seite, darf deren
Inventar leer sein. Zwei leere Inventare werden als fehlerhafte Scan-Konfiguration abgelehnt.
Mutable Tags und unfixierte Build-Downloads können sich zwischen Builds ändern; für
reproduzierbare Ergebnisse Images und Build-Abhängigkeiten festlegen.

Für Monorepos die Templates mit unterschiedlichen `job_name`-Werten einbinden und den
Worker über `scan_job` auf den jeweiligen Produzenten verweisen. `component` benennt den
separaten dTrack-Vergleich und Bot-Kommentar. Artefakte verschiedener Komponenten kommen
nicht miteinander in Berührung.

## Zugangsdaten und Zeitplan

Default-Branch und dessen CI-Änderungen durch vertrauenswürdige Maintainer schützen. Unter
**Settings → CI/CD → Variables → Access protected resources in merge request pipelines**
die Option **Allow merge request pipelines to access protected variables and runners**
deaktivieren. Dadurch erhalten auch MRs zwischen geschützten Branches keine geschützten
Schlüssel. `masked` allein verhindert den Zugriff nicht.
[GitLab-Dokumentation](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/#control-access-to-protected-variables-and-runners)

| Variable | Inhalt |
|---|---|
| `PATCHWATCH_GITLAB_URL` | HTTPS-Basis-URL von GitLab |
| `PATCHWATCH_GITLAB_TOKEN` | Projekt-Bot mit Developer-Rolle und `api`-Scope: Artefakte/Pipelines lesen, MR-Kommentare schreiben und bei verändertem Zielbranch einen neuen MR-Scan anfordern |
| `PATCHWATCH_URL` | HTTPS-Basis-URL von dTrack |
| `PATCHWATCH_UPLOAD_KEY` | `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` |
| `PATCHWATCH_READ_KEY` | `VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION`, `VIEW_VULNERABILITY` |
| `PATCHWATCH_CA_CERT` | Optional: interne CA als PEM oder Dateivariable; TLS-Prüfung bleibt aktiv |

Schlüssel **masked/protected** konfigurieren, optional als Dateivariablen mit Suffix `_FILE`.
Neue Worker-Variablen können auf Environment `patchwatch-mr-feedback` begrenzt werden;
das Template nutzt dieses Environment mit `action: access`, ohne ein Deployment anzulegen.
Vorhandene geschützte Release-Schlüssel mit Scope `*` können weiterverwendet werden.
Keine persönlichen Admin-Tokens im Worker hinterlegen.

Mit bestehender `glab`-Anmeldung und den drei eingerichteten dTrack-Variablen kann die
Einrichtung automatisiert werden:

```sh
export GITLAB_PROJECT_ID=1234  # numerische ID des Projekts mit Feedback-Worker
# Bot und geschützte Variablen erstellen, Zeitplan vor dem Merge noch deaktiviert lassen:
python3 scripts/setup-mr-feedback.py --project "$GITLAB_PROJECT_ID" --ca-cert /pfad/zur/ca.pem
# Nach dem Merge der CI-Includes auf den Default-Branch den Zeitplan aktivieren:
python3 scripts/setup-mr-feedback.py --project "$GITLAB_PROJECT_ID" --activate
```

Das Script sperrt geschützte Ressourcen für MR-Pipelines, erstellt einen auf das Projekt
begrenzten Developer-Bot mit 90 Tagen Laufzeit und setzt den Fünf-Minuten-Zeitplan mit
`PATCHWATCH_MR_FEEDBACK=true`. Bestehende Schlüssel bleiben erhalten; Werte werden nicht
ausgegeben. Token vor Ablauf erneuern. Alternativ Variablen und Schedule manuell einrichten.

Vor dem ersten Worker-Lauf die reguläre dTrack-Konfiguration anwenden. Sie legt gesonderte
`Patchwatch MR …`-Regelkopien für `scan-purpose:mr-feedback` an. Eigene Team-Policies und
Release-Distributionsregeln werden nicht automatisch kopiert.

## Aktualisierung und Grenzen

Der Worker verarbeitet offene MRs desselben Projekts; Fork-MRs werden übersprungen. Er lädt
`patchwatch-mr.json` über die konkrete erfolgreiche Job-ID und prüft Quellstand, Pipeline-SHA
und aktuellen Zielbranch. Das Artefakt enthält beide SBOMs, Ziel-/Quell-SHA und Merge-Baum.
Alte einseitige SBOM-Artefakte werden nicht als korrekter Vergleich akzeptiert.

Ist der Zielbranch inzwischen weitergelaufen, veröffentlicht der Worker „Ausstehend“ und
fordert höchstens eine automatische neue MR-Pipeline je Quell-/Ziel-Kombination an. Laufende
Pipelines werden abgewartet. Schlägt dieser Scan fehl, kann der Scan-Job manuell erneut
versucht werden; der Worker startet keine endlose Folge fehlgeschlagener Pipelines.
Vor jedem Kommentar prüft er Quell- und Zielstand erneut und verwirft überholte Ergebnisse.
`resource_group` serialisiert Worker-Läufe je Projekt; nur eine Worker-Konfiguration pro
Zielprojekt betreiben. Externe Cron-Läufe ebenfalls serialisieren.

### dTrack-Versionen

Alle Versionen liegen unter **demselben Projektnamen wie das reguläre Inventar**
(`<Projektpfad>[/<Komponente>]`); die Trennung erfolgt über Version und Scope-Tag:

| Version | Inhalt | Tags |
|---|---|---|
| `mr-<IID>` | Merge-Ergebnis dieses MRs; jeder Lauf überschreibt sie | `scan-purpose:mr-feedback`, `gitlab-project-id:<id>` |
| `base-<Zielbranch>` | **Baseline:** gepaarter Scan des Zielbranches am aktuellen Ziel-Commit (Standard, `baseline: scan`) | wie `mr-<IID>` |
| `<Zielbranch>` (z. B. `main`, `dev`) | Nur mit `baseline: branch`: das reguläre Branch-Inventar als Baseline, solange sein Commit dem aktuellen Ziel-Commit entspricht | wie bisher (CI-Inventar) |

Ein MR vergleicht damit immer gegen seinen eigenen Zielbranch („into main“, „into dev“): `base-main`
bzw. `base-dev` sind der Zielbranch ohne den MR, `mr-<IID>` ist das Merge-Ergebnis. Beide Seiten
entstehen im selben Scan-Job mit denselben Eingaben, tragen dieselben Scope-Tags und werden von
denselben `Patchwatch MR …`-Policies bewertet. Dadurch erscheinen nur echte Änderungen im Bericht.

Bei Komponenten-Workern (`component` gesetzt) hängen die Komponenten-Versionen einer Version unter einem
**Parent-Projekt** `<Projektpfad>` mit **derselben Version** (`mr-<IID>`, `base-<Zielbranch>`, Branch-Name).
So zeigt der Projektbaum in dTrack pro Branch oder MR alle Komponenten gruppiert, wie bei `main`. dTrack legt
fehlende Parents nicht selbst an: der Worker erzeugt sie aus einem leeren SBOM mit denselben Scope-Tags. Ein
Parent ohne diese Tags (etwa ein Release gleichen Namens) wird nie angefasst, die Komponente wird dann ohne
Parent hochgeladen. Die Aggregation der Kinder (`AGGREGATE_DIRECT_CHILDREN`) setzt der serverseitige
Lauf `patchwatch-versions` alle fünf Minuten, außerdem die Einrichtung bzw. `python -m patchwatch.dtrack.groups`
mit Admin-Rechten; der Upload-Key darf das nicht. Darüber gruppiert ein Navigationsprojekt
`<Projektpfad> @ all versions` die verschiedenen Versionen ohne eigene Aggregation.

`baseline: branch` ist nur für Projekte gedacht, deren Produktions-Policies den gespiegelten
MR-Policies entsprechen und deren Triage (`not_affected`, `false_positive`) keine Rolle spielt:
Das reguläre Inventar wird von den Produktions-Policies bewertet (`Patchwatch …` statt
`Patchwatch MR …`) und trägt manuelle Triage-Entscheidungen. Beides erscheint im Bericht als
Änderung (gleiche Verstöße gelten als „neu“ und „entfallen“). Der Worker erkennt den Stand der
Branch-Version an der Commit-URL, die jeder Upload als Herkunft mitgibt; ist sie veraltet, fehlt
oder inaktiv, nutzt er den gepaarten Scan.

Der Worker überschreibt nie eine Version, die nicht sein Scope-Tag trägt: Eine Version namens
`mr-7` oder `base-main`, die z. B. aus einem CI-Inventar stammt, führt zu einem Fehler.
Die Namen `mr-<Zahl>` und `base-…` sind deshalb für Branches reserviert. Release-Tags,
Latest-Abgleich, Delta-Baselines und Produktionsbenachrichtigungen ignorieren diese Versionen.

### Feature-Branches als Versionen

Mit `branch_scan_job` (Standard: leer = aus) erzeugt der Worker für **jeden ungeschützten
Nicht-Default-Branch** eine dTrack-Version mit dem Branch-Namen und dem Tag
`scan-purpose:branch`. Der Branch-Pipeline läuft dafür ohne Schlüssel mit
`ci-templates/branch-sbom.yml` (Artefakt `patchwatch-branch.json`); hochgeladen wird erst durch
den geschützten Worker, wie bei MRs. Geschützte Branches laden weiter über den regulären
Inventar-Job hoch (`branches`-Input) und werden hier übersprungen. Ein Branch wird nur neu
hochgeladen, wenn sein Commit von dem der Version abweicht; Namen von Releases oder
anderen Inventaren werden nie überschrieben. Voraussetzung: Das `workflow:rules` des Projekts
lässt Branch-Pipelines (Push) für diese Branches zu.

```yaml
include:
  - project: platform/patchwatch
    ref: <geprüfter Commit>
    file: ci-templates/branch-sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<Digest>
      dockerfiles: Dockerfile            # dieselben Eingaben wie im MR-Scan
  - project: platform/patchwatch
    ref: <derselbe geprüfte Commit>
    file: ci-templates/mr-feedback.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci@sha256:<Digest>
      branch_scan_job: patchwatch-branch-sbom
```

Nach dem Import werden die Analysestände wiederholt gelesen. Zwei identische Abfragen sind
eine stabilisierte **Momentaufnahme**, kein Nachweis abgeschlossener Analyzer. Timeouts
werden als unvollständig markiert und erneut versucht; auch null Findings sind keine Freigabe.

Der Kommentar ist eine Vorschau mit maximal 20 Einträgen je Abschnitt und begrenzten Textlängen.
Direkt darüber steht **„Vollständigen Bericht herunterladen (ZIP: Markdown + JSON)“**. Das Archiv
enthält den vollständigen Vergleich einschließlich SHAs, Merge-Baum und Auswertungszeitpunkt,
ohne Zeilen- oder Textkürzung. Es wird als Markdown-Upload im **Zielprojekt des MRs** gespeichert,
auch wenn der Worker in einem anderen Projekt läuft. Der Link verweist auf genau diese
Momentaufnahme und bleibt nach Ablauf der CI-Artefakte bestehen. GitLab-Projektberechtigungen
und die dortigen Regeln zur Aufbewahrung von Anhängen gelten weiterhin. Uploads werden durch
Patchwatch nicht automatisch gelöscht. Bei ausstehender oder fehlgeschlagener Neuauswertung
bleibt der letzte Bericht mit ausdrücklicher Kennzeichnung des vorherigen Auswertungsstands
verlinkt. Unveränderte fertige Ergebnisse erzeugen kein neues Archiv.

JSON, Markdown und ZIP liegen zusätzlich eine Woche als Worker-Artefakte unter
`patchwatch-mr-reports/<MR-IID>/`. Der Worker erzeugt ein GitLab-Report-Artefakt
`annotations` mit direkten `external_link`-Verweisen auf die ZIPs, auch bei wiederverwendeten
Ergebnissen. Diese Links erscheinen auf der **Worker-Job-Seite**, nicht als Security-Widget
in der MR-Pipeline. Der Bot benötigt dafür keine weiteren Rechte neben seinem bisherigen
Projekt-Token mit `api`-Scope.

### GitLabs MR-Reports

Das Scan-Template nutzt `artifacts:expose_as`, um die **SBOM-Rohdaten** direkt in der
MR-Oberfläche als Artefakt-Link bereitzustellen. Diese gepaarten Inventare enthalten noch
keine Findings-Auswertung. Den vollständigen Patchwatch-Vergleich liefert der ZIP-Link im
Bot-Kommentar.

Ein beliebiger Markdown-/JSON-Vergleich lässt sich nicht als frei definierbares natives
MR-Report-Widget registrieren. GitLabs native Widgets für Dependency-Scanning und
Lizenzänderungen benötigen **GitLab Ultimate** und dessen unterstützte Report-Formate,
passende SBOM-Metadaten sowie Report-Jobs in der MR-/Vergleichspipeline. Ein
`annotations`-Report in einer geplanten Worker-Pipeline verknüpft deren Findings nicht
automatisch mit der MR-Pipeline. Die Community Edition kann diese Security-/Lizenz-Widgets
nicht anzeigen. Patchwatch liefert deshalb direkte Anhänge und Job-Annotations statt
Security-Findings als fachfremde Test- oder Code-Quality-Ergebnisse auszugeben.

Referenzen: [Artefakte im MR anzeigen](https://docs.gitlab.com/ci/yaml/#artifactsexpose_as),
[Annotations](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportsannotations),
[Dependency Scanning](https://docs.gitlab.com/user/application_security/dependency_scanning/),
[Lizenz-Scanning](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/),
[Markdown-Uploads](https://docs.gitlab.com/api/project_markdown_uploads/).

Fehlende/abgelaufene Artefakte ergeben „Ausstehend“, API-/Upload-/Auswertungsfehler einen
Fehlerkommentar und fehlgeschlagenen Worker-Job. Andere MRs werden weiter verarbeitet.
Geschlossene MRs werden nicht mehr aktualisiert; Kommentare bleiben als Historie bestehen.
`mr-<IID>`-, `base-…`- und Branch-Versionen werden noch nicht automatisch gelöscht; frühere
Versionen unter `<Projektpfad>/mr-feedback` bleiben unverändert stehen und können gelöscht werden. Später veröffentlichte
CVEs werden nach erneutem Scan-Job ausgewertet; unveränderte fertige Job-Ergebnisse werden
nicht ständig neu hochgeladen.

Die SBOMs stammen aus veränderbaren MR-Pipelines. Der Bericht ist Review-Feedback, keine
Attestierung gegen absichtliche Manipulation der Scan-Konfiguration. Paketnamen werden ohne
aktive Erwähnungen, HTML oder GitLab-Quick-Actions dargestellt.

## Patchwatch selbst

`ci/mr-components.yml` scannt Bridge und CI-Image aus ihren jeweiligen Dockerfiles sowie
API-Server, Frontend, PostgreSQL, Trivy und Gateway über `compose.yaml`. Dadurch werden
Image-Versionen tatsächlich aus dem Ziel- bzw. Merge-Baum gelesen; die Image-Liste des
Quellbranchs wird nicht irrtümlich für beide Seiten verwendet. Tests prüfen, dass dieselben
Komponenten wie bei den regulären Release-Scans abgedeckt sind.

`ci/mr-feedback.yml` bindet die sieben Worker für das Patchwatch-Projekt ein.
Vor der Nachnutzung dessen Projekt-ID und Registry-Referenzen anpassen. In geschützten
Feedback-Pipelines wird das zum Default-Branch-Commit gehörende CI-Image verwendet. Die
MR-Pipeline baut nur das Scanner-Image vorab; die zu vergleichenden Bridge-/CI-Images werden
anschließend separat aus den beiden Bäumen gebaut. Der normale Release-/Deploy-Ablauf und
sein Komponenten-Zeitplan bleiben unabhängig vom Feedback-Zeitplan.

`ci/branch-components.yml` enthält dieselben Scans mit identischen Eingaben für Feature-Branches
(`ci-templates/branch-sbom.yml`); `ci/mr-feedback.yml` setzt dafür `branch_scan_job`. Die
`workflow:rules` starten für jeden Branch eine Push-Pipeline, außer er hat einen offenen MR: dann
genügt dessen MR-Pipeline, und die Branch-Version bleibt auf dem Stand vor dem MR, während
`mr-<IID>` aktuell ist. Das CI-Image wird dafür auch in Branch-Pipelines gebaut.

Referenzen: [Git-Merge-Baum](https://git-scm.com/docs/git-merge-tree),
[Syft-Scan-Ziele](https://oss.anchore.com/docs/guides/sbom/scan-targets/),
[MR-Pipelines-API](https://docs.gitlab.com/api/merge_requests/#create-merge-request-pipeline),
[Artefakte per Job-ID](https://docs.gitlab.com/api/job_artifacts/#download-a-single-artifact-file-by-job-id),
[MR-Kommentare](https://docs.gitlab.com/api/notes/#merge-requests).
