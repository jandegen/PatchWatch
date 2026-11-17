# GitLab-CI-Template: Projekte in PatchWatch einbinden

Das Template [`ci-templates/sbom.yml`](../../ci-templates/sbom.yml) erzeugt in der Pipeline eines
Projekts ein SBOM (CycloneDX) und lädt es nach Dependency-Track hoch. Das Projekt erscheint
danach in PatchWatch neben den Entwickler-Rechnern. Severity-/Lizenz-Policies, Benachrichtigungen
über die Bridge und die Dashboards gelten damit automatisch auch für diese Projekte.

Es gibt zwei Teile: die **einmalige Einrichtung** (Abschnitt 1, durch den Betreiber von PatchWatch)
und die **Einbindung pro Projekt** (Abschnitt 2, mit eigener Template- und Image-Referenz).

## 1. Einmalige Einrichtung

### 1.1 Schlüssel

Die Einrichtung (`patchwatch.dtrack.setup`, in Kubernetes der Deploy-Job auf `main`) legt das
DTrack-Team **`ci-upload`** mit `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` und `VIEW_PORTFOLIO` an. Es hat einen
eigenen Schlüssel, getrennt von den Agenten, damit sich beide unabhängig rotieren und sperren lassen.

```sh
# Kubernetes (nach dem ersten Deployment mit dieser Version)
kubectl -n patchwatch get secret patchwatch-provisioning -o jsonpath='{.data.ci_upload_key}' | base64 -d
# Compose
cat .secrets/ci_upload_key
```

Für den serverseitigen Versionsabgleich entsteht zusätzlich das Team **`project-versions`** mit
`VIEW_PORTFOLIO` und `PORTFOLIO_MANAGEMENT`. Sein `versions_key` bleibt ausschließlich auf dem Server;
er wird **nicht** als GitLab-Variable verteilt. Kubernetes stellt ihn als `patchwatch-versions-key` bereit.
Der CronJob `patchwatch-versions` gleicht alle fünf Minuten die Latest-Markierung ab, zusätzlich läuft
der Abgleich bei jedem Deployment. In Compose nach der Einrichtung starten:

```sh
docker compose --profile operations up -d versions
```

Optional und nur für Auswertung und Gate: der bestehende **Lese-Schlüssel** (`monitor_key`, Rechte
`VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION` und `VIEW_VULNERABILITY`). Er sieht das **gesamte** Portfolio. Pipelines, die ihn
erhalten, können also alle Findings lesen. Nur an Pipelines verteilen, die das gesamte Portfolio lesen dürfen; andernfalls
projektbezogenen Zugriff einrichten oder den Schlüssel weglassen.

### 1.2 GitLab-Variablen auf Gruppenebene

*Gruppe → Einstellungen → CI/CD → Variablen.* Auf oberster Gruppenebene gesetzt, gelten sie für alle
Projekte darunter. Projekte brauchen dann keine eigene Konfiguration.

| Variable | Typ / Flags | Inhalt |
|---|---|---|
| `PATCHWATCH_URL` | Variable | `https://patchwatch.example.org` |
| `PATCHWATCH_UPLOAD_KEY` | Variable, **masked, protected** | Schlüssel des Teams `ci-upload` |
| `PATCHWATCH_READ_KEY` | Variable, **masked, protected**, optional | `monitor_key`; aktiviert Ergebnis-Zusammenfassung und `fail_on` |
| `PATCHWATCH_CA_CERT` | **Datei**, optional | Zertifikat der internen CA, falls der Runner ihr nicht vertraut |

*Protected* ist wichtig: Die Schlüssel stehen nur in Pipelines geschützter Branches und Tags zur
Verfügung, nicht in Merge-Requests aus Forks oder in beliebigen Feature-Branches. Der Default-Branch
muss deshalb **geschützt** sein. Beide Eigenschaften, **masked** und **protected**, setzen und
Schlüssel weder ausgeben noch in Debug-Traces übernehmen. Das Template protokolliert sie nicht.

`PATCHWATCH_CA_CERT` ersetzt für den **Upload** die Vertrauensliste von Python. Syft und
Image-Pulls sind nicht betroffen. HTTP wird abgelehnt; nur für interne Tests
`PATCHWATCH_ALLOW_HTTP: 'true'` setzen.

### 1.3 Job-Image und Template-Version

Der Job läuft in einem Image mit Syft und dem PatchWatch-Modul ([`Dockerfile.ci`](../../Dockerfile.ci)).
Die Pipeline dieses Repositorys baut es und legt es in die Registry. Diese Pipeline
enthält außerdem ein Kubernetes-Deployment und installationsspezifische Runner- und
Registry-Einstellungen. Für Compose kann das Image unabhängig davon gebaut werden,
siehe Abschnitt 1.4. **Veröffentlichung einer Version über die angepasste Repository-Pipeline:**

```sh
git tag v1.1.0 && git tag -f v1
git push origin v1.1.0 && git push -f origin v1
```

Diese Schritte erst auf dem Commit mit den freizugebenden Änderungen ausführen. Die Tag-Pipeline
veröffentlicht `ci:v1.1.0` und das bewegliche `ci:v1`. Projekte binden `ref: v1`
ein und erhalten damit kompatible Verbesserungen; ein inkompatibler Wechsel wird `v2`. Die Tags `v*`
sollten in GitLab als **geschützte Tags** konfiguriert sein. Bis die erste Tag-Pipeline fertig ist,
existiert das Standard-Image `ci:v1` noch nicht.

Für `branches`, `services` und `detect_services` müssen sowohl das Template als auch das Job-Image
die Inputs unterstützen. Ältere Stände von `v1` enthalten `services` und `detect_services` noch nicht;
`branches` ist nicht in allen älteren Ständen enthalten. Für einen eigenen Fork
Versionen gemeinsam mit dem Image freigeben. Den Git-Tag `v1` beim Release
ebenfalls aktualisieren und den erfolgreichen Image-Build abwarten. Für eine feste Version neben
`ref: v1.1.0` auch `image: $CI_REGISTRY/platform/patchwatch/ci:v1.1.0` setzen.

Das Repository `platform/patchwatch` muss für die einbindenden Projekte lesbar sein (Sichtbarkeit
*internal* oder Berechtigung), und die Registry muss das Image ausliefern. Bei privater Registry
ist das Projekt in der Job-Token-Zulassungsliste einzutragen.

### 1.4 CI mit einem Compose-Server ohne Kubernetes

Die Templates funktionieren mit beiden Betriebsarten. Für Compose zuerst das
[Compose-Setup einschließlich HTTPS](../installation/compose.md) vollständig
abschließen. `scripts/setup-ci.py`, `KUBE_CONFIG`, Helm und Kubernetes-Secrets
werden für die Anbindung von GitLab-Projekten an diesen Server nicht benötigt.
`scripts/setup-ci.py` richtet die Kubernetes-Deployment-Pipeline ein.

**CI-Image bereitstellen:** Einen geprüften Patchwatch-Stand inklusive Templates
in ein für die Konsumenten lesbares GitLab-Projekt pushen. Aus genau diesem Stand
das Image bauen und veröffentlichen; die folgenden Registry-Werte ersetzen:

```sh
PATCHWATCH_REF=$(git rev-parse HEAD)
PATCHWATCH_CI_IMAGE="registry.example.org/platform/patchwatch/ci:${PATCHWATCH_REF}"
docker login registry.example.org
docker build --pull -f Dockerfile.ci -t "$PATCHWATCH_CI_IMAGE" .
docker push "$PATCHWATCH_CI_IMAGE"
```

Der Checkout muss für den Build dem veröffentlichten Commit entsprechen, ohne
zusätzliche lokale Codeänderungen. Der Build-Rechner benötigt Docker und Zugang
zu den Basisimage-Registries sowie Schreibrechte auf die Zielregistry. Bei einer
anderen Runner-Architektur das Image für diese Plattform bauen.
Das Compose-Image `patchwatch-bridge:local` enthält keinen Syft-Scanner und ersetzt
dieses CI-Image nicht. Die Compose-Dienste selbst benötigen für ihren lokalen Build
keine Veröffentlichung in einer Registry.

**GitLab konfigurieren:** Die Variablen aus Abschnitt 1.2 setzen. Als
`PATCHWATCH_URL` beispielsweise `https://patchwatch.example.org:8443` verwenden,
als `PATCHWATCH_UPLOAD_KEY` den Inhalt von `.secrets/ci_upload_key`. Der optionale
`PATCHWATCH_READ_KEY` stammt aus `.secrets/monitor_key`. Dateien mit Schlüsseln nur
über einen sicheren administrativen Kanal auslesen und übertragen.
Bei beschränktem Environment-Scope müssen die Variablen auch für den SBOM-Job ohne
`environment` gelten, üblicherweise Scope `*`.

Vom **Runner-Job-Container** müssen DNS, HTTPS-Port und Zertifikatskette des
Compose-Gateways erreichbar sein; ebenso die GitLab- und Image-Registry.
Loopback und interne Compose-Namen (`apiserver`, `gateway`) sind dafür keine
Serveradressen. Bei einer internen CA `PATCHWATCH_CA_CERT` als Datei-Variable
hinterlegen. Für den Pull des Job-Images muss die Registry-CA bereits dem Runner
vertraut sein; die Job-Variable greift erst nach dem Image-Pull.

**Konsumentenprojekt anbinden:** `ref` durch den oben ermittelten vollständigen
Commit und den Image-Tag durch denselben Commit ersetzen. So ist kein `v1`-Release
und keine Kubernetes-Deployment-Pipeline nötig:

```yaml
include:
  - project: platform/patchwatch
    ref: '<vollständiger geprüfter Commit>'
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:<derselbe Commit>
      team: platform
      # Bewusste erste Bestandsaufnahme mit noch unvollständigen BSI-Metadaten:
      bsi_mode: report
```

Dieses erste Beispiel lädt ein Inventar hoch, das nicht als BSI-konform gilt.
Für den regulären Betrieb die [BSI-Metadaten](bsi-sbom.md) ergänzen und
`bsi_mode: enforce` setzen (oder den Input für den Standard `enforce` entfernen).
Eigene `stages` müssen `test` enthalten oder über `inputs.stage` eine vorhandene
Stage auswählen. Der Default-Branch muss geschützt sein, damit der Job seinen
geschützten Upload-Key erhält. Für einen gewöhnlichen Repository-Scan benötigt
der Runner keinen Docker-Daemon; zusätzliche Image-Builds benötigen eine eigene
Build-Konfiguration.

**Ersten Import prüfen:** Eine Pipeline auf dem geschützten Default-Branch starten.
Der Job `patchwatch-sbom` muss `Upload processed by Dependency-Track` melden.
Die Artefakte `patchwatch-sbom.json` und `patchwatch-bsi-report.json` prüfen und in
der Weboberfläche das Projekt unter seinem GitLab-Pfad und der Default-Branch-Version
öffnen. Die Komponententabelle muss den gescannten Bestand enthalten. Der Import
bestätigt noch nicht den Abschluss der Schwachstellenanalyse.
Nach der zentralen Einrichtung `versions` wie in Abschnitt 1.1 starten, damit die
Latest-Markierung regelmäßig abgeglichen wird.

Bei Fehlern zuerst prüfen:

| Symptom | Prüfung |
|---|---|
| Job-Image kann nicht geladen werden | Vollständiger Registry-Pfad, veröffentlichter Tag, Runner-CA und Job-Token-Zulassung |
| Upload-Key fehlt | Geschützter Branch/Tag, Variablentyp und Environment-Scope |
| Verbindung oder TLS schlägt fehl | Vom Job erreichbare Gateway-URL, Port, DNS und `PATCHWATCH_CA_CERT` |
| HTTP 401/403 | `ci_upload_key` aus derselben Instanz, Teamrechte und gegebenenfalls Projektzugriff |
| BSI-Prüfung verweigert Upload | `patchwatch-bsi-report.json` und komponentenspezifische Metadaten |

Für optionale MR-Berichte anschließend [MR-Feedback](mr-feedback.md) einrichten;
die dortigen DTrack-URL- und CA-Einstellungen zeigen ebenfalls auf das Compose-Gateway.

## 2. Einbindung in ein Projekt

Die Beispiele verwenden einen eigenen Template-Fork `platform/patchwatch` und ein
selbst veröffentlichtes Image. `project`, `ref` und `inputs.image` vor der Nutzung
anpassen; der Template-Default für das Image ist installationsspezifisch.
Siehe [Registry- und GitLab-Parameter](../installation/customization.md#gitlab-und-registry).

Minimal, in der `.gitlab-ci.yml` des Projekts:

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
```

Das erzeugt den Job `patchwatch-sbom` in der Stage `test`. Er läuft auf dem **Default-Branch** und bei
**Tags**, nicht in Merge-Requests. Fehlende BSI-Pflichtangaben blockieren standardmäßig
den Upload und den Job. Vor der Einbindung die [BSI-Metadaten konfigurieren](bsi-sbom.md).

### Konfiguration (`inputs`)

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

| Input | Standard | Bedeutung |
|---|---|---|
| `job_name` | `patchwatch-sbom` | Name des Jobs; nötig, wenn das Template mehrfach eingebunden wird |
| `stage` | `test` | Stage; für Image-Scans eine Stage **nach** dem Build wählen |
| `image` | explizit setzen | Eigenes Job-Image mit Syft und Patchwatch; z. B. `registry.example.org/platform/patchwatch/ci:v1` |
| `team` | leer | Tag `team:<wert>`; steuert das Alert-Routing. Leer: oberste GitLab-Gruppe |
| `environment` | leer | Optionaler Tag `environment:<wert>` |
| `scan_paths` | `.` | Verzeichnisse im Repository, durch Leerzeichen getrennt; leer = nur Images |
| `images` | leer | Image-Referenzen, durch Leerzeichen getrennt |
| `exclude` | leer | Syft-Ausschlussmuster, z. B. `./docs/** ./**/testdata/**` |
| `component` | leer | Namenszusatz für Monorepos. Das Inventar wird dann unter dem Projekt `gruppe/projekt` einsortiert (siehe Abschnitt „Mehrere Inventare“) |
| `mode` | `inventory` | `parent` legt einen leeren Aggregations-Parent und ein separates Service-Unterprojekt an |
| `services` | leer | Zusätzliche Dienstnamen, durch Leerzeichen getrennt, als CycloneDX-Services |
| `detect_services` | `true` | Dienste aus unterstützten Compose-Dateien unter `scan_paths` als CycloneDX-Services eintragen; nur Name und Image, [Suchgrenzen](services.md) |
| `branches` | leer | Zusätzliche erlaubte Upload-Branches, durch Leerzeichen getrennt, exakte Namen ohne Globs. Version = Branchname, nicht als neueste markiert. Auch `run_if` anpassen |
| `run_if` | Default-Branch oder Tag | GitLab-`rules:if`-Ausdruck, wann der Job läuft; schaltet allein keine weiteren Upload-Branches frei (dafür `branches`). Innen nur doppelte Anführungszeichen, z. B. `$CI_PIPELINE_SOURCE == "schedule"` |
| `fail_on` | `none` | `none`, `warn` oder `fail`; benötigt `PATCHWATCH_READ_KEY` |
| `delta` | `true` | Delta-Bericht gegenüber der Vorversion, siehe [Delta-Berichte](delta-reports.md); benötigt `PATCHWATCH_READ_KEY` |
| `delta_baseline` | leer | Feste Vergleichsversion; leer = automatisch die Vorversion |
| `delta_notify` | `relevant` | `relevant`, `always` oder `never` für Webhook/E-Mail-Versand |
| `allow_failure` | `false` | Pipeline trotz Fehler des Jobs fortsetzen, wenn ausdrücklich auf `true` gesetzt |
| `bsi_mode` | `enforce` | Fehlende BSI-Pflichtangaben verweigern den Upload; `report` ist nur für die Migration unvollständiger Inventare |
| `bsi_metadata` | leer | JSON-Datei mit geprüften komponentenspezifischen Angaben; [Format und Beispiele](bsi-sbom.md) |
| `sbom_creator` | Projekt-URL | E-Mail/URL des SBOM-Erstellers |
| `component_creator` | Projekt-URL | E-Mail/URL des Erstellers der primären Komponente |
| `distribution_license` | leer | Geprüfter SPDX-Ausdruck der Auslieferungslizenz der primären Komponente |

Team- und Umgebungswerte bestehen aus Kleinbuchstaben, Ziffern, `.`, `_` und `-`. Das Team wird nie aus
Benutzernamen geraten: Wo die GitLab-Gruppe nicht dem Team entspricht, `team` setzen.

### Beispiele

**Zusätzlichen Branch hochladen** (Default-Branch und Tags bleiben zugelassen):

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

`branches` wird als `PATCHWATCH_BRANCHES` an das Modul übergeben. `dev` muss für die geschützten
Schlüssel ebenfalls geschützt sein. Der Upload erzeugt die Version `dev` samt `patchwatch-report.json`;
spätere `dev`-Uploads ändern die zentrale Latest-Auswahl nicht (höchstes stabiles Release,
sonst Default-Branch; siehe Abschnitt 3).
Bei mehreren Inventaren dieselben `branches`- und `run_if`-Werte für Parent und Komponenten setzen.
Ein gestarteter Job auf einem nicht freigegebenen Branch überspringt Scan und Upload mit einer
`WARNING: PatchWatch CI skipped`-Meldung und Exit-Code 0; dabei entsteht kein Bericht.

**Repository und gebautes Image** (Image-Scan nach dem Build):

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

Images der GitLab-Registry werden mit dem Job-Token gelesen. Für eine Registry ohne gültiges TLS-Zertifikat
oder per HTTP im Projekt `variables: {SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY: "true"}` bzw.
`SYFT_REGISTRY_INSECURE_USE_HTTP: "true"` setzen.

**Monorepo mit mehreren Inventaren** (je ein DTrack-Projekt, gruppiert unter dem Projekt selbst):

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

Siehe „Mehrere Inventare“ unten für den Hintergrund.

**Gate für Releases** (Tags blockieren, der Default-Branch warnt nur):

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

**Zeitgesteuert** (z. B. für Images von Dritten, die sich nur bei Versionswechseln ändern):

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

Den Zeitplan legst du unter *Build → Pipeline-Zeitpläne* an. Ein Zeitplan startet die **gesamte** Pipeline
des Projekts. Damit dabei nichts anderes läuft (Tests, Builds, Deploy), brauchen die übrigen Jobs eine Regel
`if: '$CI_PIPELINE_SOURCE == "schedule"'` mit `when: never`. Das macht
[`.gitlab-ci.yml`](../../.gitlab-ci.yml) dieses Repositorys über `.not-scheduled` vor.
Neue CVEs zu einer unveränderten Version erkennt Dependency-Track selbst über seine Feeds; ein häufigerer
Zeitplan als wöchentlich ist daher nur für das Eintragen neuer Versionen sinnvoll.

**Anderer Runner** (z. B. Tags): Jobs aus dem Template lassen sich im Projekt ergänzen:

```yaml
patchwatch-sbom:
  tags: [k3s, docker]
```

### Mehrere Inventare (Hierarchie)

Mit `component` entsteht je Inventar ein eigenes DTrack-Projekt `gruppe/projekt/<component>`. Diese hängen
als **Unterprojekte** unter dem Projekt `gruppe/projekt` (in der UI als Baum; der Schalter *Show flat
project view* zeigt alle flach). Damit das funktioniert:

- **Das Sammelprojekt muss vorher existieren.** Dependency-Track legt ein fehlendes Parent nicht an
  (`404 The parent component could not be found`). Der Job mit `mode: parent` erzeugt es als leeres SBOM
  und muss in einer **früheren Stage** laufen als die Komponenten-Jobs. Ein eigener Job ist nötig, weil
  parallele Jobs sonst gleichzeitig dasselbe Projekt anlegen würden. Fehlt er, nennt der Komponenten-Job
  genau das in der Fehlermeldung.
- **Das Sammelprojekt zählt die Kennzahlen seiner Unterprojekte zusammen** (Findings, Policy-Verstöße,
  Komponenten, „Aggregate direct children“). Das kann der Upload-Schlüssel nicht einstellen. Die
  Einrichtung (jedes Deployment) und der regelmäßige Lauf von `patchwatch-versions` erledigen es
  für CI-, MR- und Branch-Parents mit Unterprojekten, oder manuell mit Admin-Zugang:
  `DT_URL=https://… DT_ADMIN_PASSWORD_FILE=… python3 -m patchwatch.dtrack.groups`. Bis dahin zeigt das
  Sammelprojekt nur den Baum, aber keine Summen.
- **Bestehende Projekte werden umgehängt:** Dependency-Track wertet `parentName` nur beim Anlegen eines
  Projekts aus. Komponenten, die schon vor ihrem Sammelprojekt existierten, bleiben sonst Wurzeln. Derselbe
  Admin-Schritt hängt deshalb Projekte `gruppe/projekt/<component>` unter `gruppe/projekt`, sofern beide
  denselben Tag `gitlab-project-id` und dieselbe Version haben.
- Das Sammelprojekt hat **keine eigenen Komponenten oder Services**. `mode: parent` legt es einmalig
  mit einer leeren SBOM an und kennzeichnet es mit `patchwatch-role:parent`. Bestehende Parents werden
  nur nachgeschlagen und nicht überschrieben; dadurch bleiben Aggregation und Altbestände erhalten.
- Erkannte und explizit angegebene Services werden separat nach `gruppe/projekt/services` in derselben
  Version hochgeladen, mit demselben GitLab-Projekt-Tag und dem Parent als übergeordnetem Projekt.
  Der Komponentenname `services` ist dafür reserviert. Jeder Parent-Lauf aktualisiert dieses Inventar,
  auch wenn der Parent bereits aggregiert. Ein leeres Service-Inventar entfernt früher erkannte Dienste.
  Der Unterprojekt-Upload erhält die Commit- und Pipeline-Herkunft. Für `--dry-run` entstehen die
  Parent-SBOM und daneben `<ausgabestamm>-services.json` (bei einer JSON-Ausgabedatei).
- Für den sicheren Parent-Nachschlag braucht der CI-Schlüssel `VIEW_PORTFOLIO`. Bei älteren Installationen
  zuerst die Einrichtung erneut ausführen; alternativ `PATCHWATCH_READ_KEY` bereitstellen.
- Über den Versions-Parents legt `patchwatch-versions` einen gemeinsamen Navigationsordner
  `<Projektpfad> @ all versions` an. Er aggregiert nicht; nur die einzelnen Versions-Parents
  summieren ihre Unterprojekte. Projekte ohne `component` bleiben einzelne Inventarprojekte
  unter diesem Ordner. Details im [Betriebshandbuch](../operations/index.md#versionsmarkierungen-und-scan-aktualität).

**Bestehende Parents migrieren** (beispielsweise LinkDash):

1. Parent- und Komponenten-Uploads für die Migration pausieren. Vorher ein reguläres Backup erstellen.
2. Die aktuelle Einrichtung ausführen oder mit Admin-Zugang
   `DT_URL=https://… DT_ADMIN_PASSWORD_FILE=… python3 -m patchwatch.dtrack.groups` starten.
3. Scheitert die Umstellung auf `AGGREGATE_DIRECT_CHILDREN` mit HTTP 409, exportiert der Admin-Schritt
   die Services und importiert sie nach `<parent>/services` derselben Version. Vorhandene, konfliktfreie
   Zielbestände bleiben erhalten. Erst nach abgeschlossenem Import und erfolgreichem Vergleich eines
   erneuten Exports werden die ursprünglichen Services gezielt aus dem Parent gelöscht. Danach wird
   die Aggregation erneut aktiviert. Wiederholte Läufe verwenden dasselbe Unterprojekt.
4. Parent-Aggregation und Service-Inventar im Unterprojekt prüfen, danach CI fortsetzen.

Eigene Paketkomponenten im Parent, eine Namenskollision, abweichende Metadaten desselben Services oder
fehlgeschlagene Kopierprüfungen brechen die Einrichtung mit Projekt, Ursache und Handlungshinweis ab.
Der Parent wird dabei nicht durch eine leere SBOM ersetzt. Bei einem Fehler während des Löschens
liegt die geprüfte Kopie bereits im Unterprojekt; nach Behebung der Ursache denselben Schritt wiederholen.
Ein CI-Lauf vor der Migration meldet noch vorhandene Parent-Services und lässt beide Inventare unverändert.
Ob Services beim konkreten LinkDash-Projekt die Aggregation blockieren, muss am laufenden System
bestätigt werden; diese Anleitung ersetzt die Diagnose dort nicht.

Für Service-Erfassung gelten die [gesonderten Parser- und Deduplizierungsgrenzen](services.md).

## 3. Was in PatchWatch erscheint

| Merkmal | Wert |
|---|---|
| Projektname | `gruppe/projekt` (bei `component`: `gruppe/projekt/<component>`, als Unterprojekt von `gruppe/projekt`) |
| Version | Default-Branch oder zusätzlicher Branch aus `branches`: dessen Name. Tag: der unveränderte Tag-Name |
| Latest | Höchstes aktives stabiles Release; solange keines existiert, der Default-Branch. Weitere Branches und MR-Versionen (`mr-<IID>`, siehe [MR-Feedback](mr-feedback.md)) ersetzen den Default-Branch nicht und gelten nie als Release. Abgleich spätestens beim nächsten erfolgreichen Fünf-Minuten-Lauf |
| Herkunft | Exakte Commit-URL mit kurzer SHA und Branch-/Tagname sowie Pipeline-Link unter *External References* |
| Aktualität | *Last BOM Import* zeigt den letzten verarbeiteten Upload; Latest bewertet keine Scan-Frische |
| Tags | `managed-by:patchwatch`, `asset-type:application`, `source:gitlab-ci`, `gitlab-project-id:<id>`, `team:<team>`, optional `environment:<wert>`; bei Git-Tags zusätzlich `policy-profile:distribution` |

Die Latest-Auswahl erfolgt numerisch (`v1.10.0` vor `v1.9.0`), unabhängig von Upload-Reihenfolge und
Scanzeitpunkt. Stabile Tags bestehen aus Zahlen, optional mit führendem `v` und Punkten: `v1`, `1.2`,
`v1.2.3`. Vorabversionen (`v2.0.0-rc.1`), Build-Suffixe und freie Labels werden erfasst, ersetzen aber
kein stabiles Release. Bei numerisch gleichen Alias-Tags gewinnt deterministisch der längere Name,
danach der lexikalisch größere Name. Inaktive Versionen werden nicht als Latest gewählt.

Sammelprojekt und Komponenten desselben GitLab-Projekts folgen derselben höchsten Release-Version.
Fehlt einer Komponente diese Version, erhält sie kein Latest-Häkchen. Existieren noch keine Releases,
führt der erkannte Default-Branch zu Latest. Bei mehreren widersprüchlichen Default-Branches
wird keine Version geraten. Bestehende `main`-/`master`-Inventare werden auch ohne neuen Upload erkannt;
andere Default-Branch-Namen brauchen zunächst einen Upload mit den neuen Herkunftsangaben.
In Projekten, deren Zusatzbranch (z. B. `dev`) vor dieser Änderung hochgeladen wurde, trägt dessen
Version noch die alte Default-Branch-Herkunft; der nächste Upload korrigiert sie.

Der Upload selbst sendet `isLatest=false`; der Abgleich korrigiert auch vorhandene Projekte.
Dependency-Track 4.14 wertet das Upload-Feld `isLatest` nur beim Anlegen aus. Ein neu angelegter oder
wechselnder Stand kann deshalb bis zum nächsten erfolgreichen Abgleich ohne Häkchen erscheinen.
Host-Projekte bleiben bei `current` und Latest; die CI-Regel betrifft nur verwaltete GitLab-CI-Projekte.

Commit-SHA, Ref, Default-Branch, Pipeline-URL und SBOM-Erstellungszeitpunkt stehen zusätzlich in der
CycloneDX-SBOM; Commit und Pipeline im `patchwatch-report.json`. Die Herkunft wird bei jedem
SBOM-Import aktualisiert. Sammelprojekte, die keine BOMs mehr annehmen, übernehmen beim Abgleich die
Herkunftslinks des zuletzt importierten direkten Unterprojekts derselben Version. Ihr eigener
*Last BOM Import* bleibt dabei unverändert; für die Scan-Frische die Unterprojekte betrachten.

- **Projekte:** in Dependency-Track nach Tag `asset-type:application` filtern. Rechner tragen
  `asset-type:workstation`; der Monitor für ausbleibende Uploads betrachtet nur Rechner.
- **Findings und Policy-Verstöße:** am Projekt unter *Audit Vulnerabilities* und *Policy Violations*.
  Die Regeln mit dem Tag `managed-by:patchwatch` ([Richtlinien](../configuration/policies.md)) greifen automatisch.
- **Alerts:** die Bridge routet nach `team:*` und `environment:*` ([Alerting](../configuration/alerting.md)). Neue
  Findings eines Projekts lösen wie bei Rechnern Meldungen aus; vor dem breiten Rollout die Routen prüfen.
- **Job-Log und Artefakt `patchwatch-report.json`:** mit `PATCHWATCH_READ_KEY` Findings nach Severity (aus den Projekt-Metriken, ohne unterdrückte Befunde, kurz nach der Analyse eventuell noch nicht aktuell),
  Policy-Verstöße und Link zum Projekt; ohne Lese-Schlüssel Komponentenzahl und lokale
  SBOM-Metadatenwarnungen (`qualityViolations`) sowie Commit-SHA und Pipeline-Link.

## 4. Grenzen und Hinweise

- **Erfasst werden deklarierte Abhängigkeiten** aus Lockfiles und Manifesten (z. B. `package-lock.json`,
  `poetry.lock`, `go.mod`, `pom.xml`, `Cargo.lock`) sowie die Pakete gescannter Images. Ohne Lockfile
  fehlen Versionen, und ein leeres Inventar wird abgelehnt. Eine Dockerfile allein ist keine Quelle; dafür das
  Image scannen. Ein fehlender Treffer beweist keine Abwesenheit von Schwachstellen.
- **Tags werden nur beim Anlegen gesetzt.** Der CI-Schlüssel darf Projektinventare hochladen und das Portfolio lesen; Projekteigenschaften ändert er nicht. Änderungen an
  `team` oder `environment` danach in Dependency-Track am Projekt vornehmen (*Projekt → Eigenschaften*); die
  Registrierung per `patchwatch.dtrack.register` ist für CI-Projekte nicht vorgesehen.
- **Umbenennung:** Wird ein GitLab-Projekt umbenannt oder verschoben, entsteht beim nächsten Lauf ein neues
  DTrack-Projekt. Das alte lässt sich über den Tag `gitlab-project-id:<id>` finden und archivieren.
- **Versionen wachsen:** jeder Release-Tag ist eine eigene Projektversion. Alte Versionen bei Bedarf
  deaktivieren oder löschen; ein automatisches Aufräumen gibt es nicht.
- **Das Gate bewertet das ganze Projekt**, nicht nur neue Findings: nicht unterdrückte native
  Policy-Verstöße und ergänzende `qualityViolations` der hochgeladenen SBOM. Bestehende Befunde
  können deshalb auch kleine Änderungen blockieren. Zuerst mit `none` einführen, bestehende Befunde
  bewerten, dann die gewünschte Schwelle aktivieren. Der Upload wartet auf den abgeschlossenen
  BOM-Import, nicht auf alle Analyzer. Die Gate-Auswertung verwendet die unmittelbar danach
  gelesene Policy-Momentaufnahme. Der optionale Delta-Bericht wartet separat auf zwei gleiche
  Lesungen; er aktualisiert die zuvor gelesene Gate-Momentaufnahme nicht. Ein bestandener Lauf
  garantiert deshalb keine vollständig abgeschlossene Schwachstellen- oder Policy-Analyse.
- **Merge-Requests** laden nichts hoch und haben keinen Zugriff auf die Schlüssel. Eine Vorab-Prüfung vor
  dem Merge ist nicht Teil dieses Templates. Optional ergänzt die separate
  [MR-Feedback-Schleife](mr-feedback.md) SBOM-Scans und einen aktualisierbaren Bot-Kommentar.
- Das SBOM enthält Paketnamen, Versionen, Lizenzen, erkannte Abhängigkeitsbeziehungen und
  von Syft gelieferte Paketpfade. Quelltexte, Beschreibungen und Autoren werden entfernt;
  Workspace-/Image-Pfade werden nicht pauschal entfernt. Diese können vertrauliche Namen
  enthalten. Inventare und Artefakte entsprechend intern behandeln.

## 5. Fehlersuche

| Meldung | Ursache |
|---|---|
| `PATCHWATCH_UPLOAD_KEY is not set` | Variable fehlt, oder der Branch ist nicht geschützt (protected) |
| `PATCHWATCH_URL is not set` | Gruppenvariable fehlt oder gehört nicht zur Gruppe des Projekts |
| `WARNING: PatchWatch CI skipped: Branch …` | Branch weder Default-Branch noch in `branches` / `PATCHWATCH_BRANCHES` freigegeben. `run_if` steuert nur den Jobstart; kein Upload und kein Bericht |
| `Upload failed (HTTP 401/403)` | Schlüssel falsch, abgelaufen oder Team ohne `BOM_UPLOAD`/`PROJECT_CREATION_UPLOAD` |
| `Upload failed: network/TLS error` | Runner erreicht PatchWatch nicht oder vertraut der CA nicht: `PATCHWATCH_CA_CERT` setzen |
| `Empty inventory rejected` | Keine Lockfiles gefunden; `scan_paths` prüfen oder Image scannen |
| `Team/environment are not valid tag values` | Gruppenname nicht als Tag verwendbar: Input `team` setzen |
| `Parent lookup requires VIEW_PORTFOLIO` | Einrichtung für aktualisierte CI-Rechte erneut ausführen oder `PATCHWATCH_READ_KEY` bereitstellen |
| `Parent still owns services` | CI pausieren und `python3 -m patchwatch.dtrack.groups` mit Admin-Zugang für die Migration ausführen |
| `fail_on needs PATCHWATCH_READ_KEY` | Gate aktiviert, aber kein Lese-Schlüssel verfügbar |
| Exit-Code 2 | Gate ausgelöst: native Policy-Verstöße oder SBOM-Qualitätsbefunde über der gewählten Schwelle (`patchwatch-report.json`; native Befunde zusätzlich unter *Policy Violations*) |
| Image-Pull schlägt fehl | Job-Image nicht lesbar (Registry-Berechtigung, Tag `v1` noch nicht gebaut) |

Lokal ausprobieren, ohne Upload und ohne Schlüssel, im Verzeichnis des Repositorys:

```sh
docker run --rm -v "$PWD:/ws" -e CI_PROJECT_DIR=/ws -e CI_PROJECT_PATH=gruppe/projekt \
  -e CI_PROJECT_ID=1 -e CI_PROJECT_ROOT_NAMESPACE=gruppe -e CI_DEFAULT_BRANCH=main \
  -e CI_COMMIT_BRANCH=main -e PATCHWATCH_SBOM_OUTPUT=/ws/sbom.json \
  registry.example.org/platform/patchwatch/ci:v1 sh -c 'cd /opt/patchwatch && python -m patchwatch.ci --dry-run'
```

## 6. Dieses Repository: eine Inventur je Komponente

Die folgende Tabelle verwendet `platform/patchwatch` als Beispiel für den eigenen
GitLab-Projektpfad. Die tatsächlichen Inventarnamen entstehen aus `CI_PROJECT_PATH`.

PatchWatch besteht aus mehreren Teilen. [`ci/components.yml`](../../ci/components.yml) bindet das Template
für jeden einzeln ein, sodass jeder Teil ein eigenes DTrack-Projekt und einen eigenen, einzeln
anpassbaren Job hat (`.gitlab-ci.yml` bindet nur diese Datei ein).

| Job | DTrack-Projekt | Gescannt | Läuft |
|---|---|---|---|
| `sbom-parent` | `platform/patchwatch` und `…/services` | leeres Sammelprojekt plus Compose-Service-Inventar im Unterprojekt | Default-Branch, Stage `prepare` |
| `sbom-bridge` | `platform/patchwatch/bridge` | selbst gebautes Bridge-Image | Default-Branch, nach dem Bauen |
| `sbom-ci-image` | `platform/patchwatch/ci-image` | selbst gebautes Job-Image (enthält Syft) | Default-Branch, nach dem Bauen |
| `sbom-dtrack-apiserver` | `…/dtrack-apiserver` | `dependencytrack/apiserver` | Zeitplan oder manuell |
| `sbom-dtrack-frontend` | `…/dtrack-frontend` | `dependencytrack/frontend` | Zeitplan oder manuell |
| `sbom-postgres` | `…/postgres` | `postgres` | Zeitplan oder manuell |
| `sbom-trivy` | `…/trivy` | `aquasec/trivy` (per Digest) | Zeitplan oder manuell |
| `sbom-gateway` | `…/gateway` | `nginxinc/nginx-unprivileged` | Zeitplan oder manuell |

- **Hierarchie:** `platform/patchwatch` ist das Sammelprojekt (Aggregation der Unterprojekte, siehe
  „Mehrere Inventare“); alle anderen Projekte der Tabelle hängen darunter.
- **Fremde Images** werden zeitgesteuert gescannt, weil sich ihre Version nur mit einem Commit ändert. So
  siehst du in PatchWatch die CVEs der Versionen, die tatsächlich laufen. Manuell: *Pipeline ausführen* im
  Default-Branch (Quelle `web`).
- **Versionen nur an einer Stelle pflegen:** Die Image-Referenzen in `ci/components.yml` müssen zu
  [`compose.yaml`](../../compose.yaml) und dem Chart-Tag in `deploy/environments/dtrack.yaml` passen. Der Test
  `tests/test_components.py` bricht die Pipeline ab, wenn sie auseinanderlaufen. Bei einem Versionswechsel
  alle betroffenen Referenzen einschließlich Helm-Profil und SPDX-Generator ändern;
  die MR-Scans lesen die Images direkt aus der jeweiligen Compose-Datei.
- **Der Agent hat kein eigenes Projekt.** Er nutzt nur die Standardbibliothek und hat keine Pakete
  aus einem Paketmanager, ein Lockfile wäre leer. Die Python-Version, mit der er läuft, ist über das
  Bridge-Image abgedeckt, Syft über das `ci-image`. Eine handgepflegte Manifest-Datei für diese beiden
  würde Versionen doppelt führen und wurde bewusst nicht angelegt.
- Einen einzelnen Job anpassen: in `.gitlab-ci.yml` denselben Jobnamen definieren, z. B.
  `sbom-trivy: {allow_failure: false}`. Neue Komponente: Block in `ci/components.yml` ergänzen und die
  Referenz in `compose.yaml` aufnehmen.
- Die regulären SBOM-Jobs blockieren bei fehlenden BSI-Pflichtangaben standardmäßig das Deployment.
  Für eine bewusste Migration ist `bsi_mode: report` möglich; diese Inventare sind nicht konform.
  Die Jobs laufen mit dem Job-Image desselben
  Commits (`ci:<sha>`); die Zeitplan-Jobs nutzen `ci:v1`, weil bei einem Zeitplan nichts gebaut wird.


Die zusätzliche [MR-Feedback-Konfiguration](mr-feedback.md#patchwatch-selbst) scannt dieselben
Komponenten in MR-Pipelines, jeweils für den Zielbranch und dessen Merge-Ergebnis. Sie erzeugt gepaarte SBOM-Artefakte; die Berichte
veröffentlicht ein geschützter Worker auf dem Default-Branch desselben Projekts.

## Release-Profil und SBOM-Metadaten

Git-Tag-Uploads erhalten `policy-profile:distribution` für die native Lizenz-Baseline-Prüfung.
Bei schon bestehenden Projekten muss ein Administrator das Profil-Tag ergänzen; der Upload-Key
ändert vorhandene Tags nicht. Fehlende Paketversionen oder Paket-URLs erscheinen als
`qualityViolations` (`WARN`) im Bericht. `fail_on: warn` berücksichtigt diese Hinweise,
`fail_on: fail` blockiert wegen solcher Warnungen nicht. Explizite Sammelprojekte sind von
leeren Inventaren ausgenommen. Regeln und Grenzen: [Policy-Anleitung](../configuration/policies.md).
