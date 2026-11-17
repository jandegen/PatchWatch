# Dienste aus Compose-Dateien

Agent und reguläres [CI-Template](ci-integration.md) können neben Softwarepaketen auch
**CycloneDX-Services** erfassen. Das sind statische Angaben aus Compose-Dateien, kein Nachweis
laufender Prozesse oder tatsächlich bereitgestellter Dienste. NeuVector und ein Kubernetes-
Laufzeitinventar bleiben [offene TODOs](../design/roadmap.md).

## Erfassung konfigurieren

Beim Linux-/macOS-Agenten ist `detect_services` standardmäßig `true`. Durchsucht werden die
konfigurierten `roots`; `extension_homes` und Image-Inhalte sind keine zusätzlichen Suchwurzeln.
Mit `detect_services: false` lässt sich die Compose-Erkennung abschalten.

Im CI-Template steuert der gleichnamige Input die Suche unter `scan_paths`. Zusätzliche
Dienstnamen lassen sich über `services` angeben:

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      services: 'api worker'
      detect_services: true
```

Das verwendete Template und Job-Image müssen diese Inputs bereits enthalten; bis zur nächsten
Release-Veröffentlichung einen passenden Commit und das zugehörige `ci:<commit-sha>`-Image
verwenden. Explizite Namen bestehen aus Buchstaben, Ziffern, `.`, `_`, `-`, beginnen mit einem
Buchstaben oder einer Ziffer und sind maximal 64 Zeichen lang. Für ausschließlich explizite
Namen `detect_services: false` setzen. Sie werden auch bei `mode: parent` berücksichtigt.

## Datenumfang und Deduplizierung

Der Leser übernimmt Dienstname und eine literale Image-Referenz als `patchwatch:image`; ein
vorhandener literaler Image-Tag kann als Version übernommen werden. Compose-Variablen werden
nicht aufgelöst. Environment, Secrets, Volumes, Befehle, Ports und Endpunkte werden nicht
übertragen. Image-Referenzen können interne Registry-/Repository-Namen offenlegen.

Gleiche Dienstnamen werden über alle Suchwurzeln und Compose-Dateien zusammengeführt. Bei
abweichenden Images gewinnt der erste Fund. Explizite Namen haben in CI Vorrang vor erkannten
Einträgen; dadurch entfällt für solche Namen die automatisch erkannte Image-Metadatenangabe.
Gleichnamige Dienste verschiedener Projekte können daher zusammenfallen. Services bleiben
getrennt von Paketkomponenten und erzeugen keine erfundenen Abhängigkeitskanten.

## Grenzen und Sichtbarkeit

- Berücksichtigt werden `compose.yaml`, `compose.yml`, `docker-compose.yaml` und
  `docker-compose.yml`, bis fünf Verzeichnisebenen unter der jeweiligen Wurzel. Maximal 200
  automatisch erkannte, nach Namen sortierte Dienste werden übernommen.
- `.git`, `node_modules`, `vendor`, `venv`, `.venv`, `__pycache__`, `site-packages`, `proc` und
  `sys` werden beim Abstieg übersprungen. Nicht lesbare Dateien werden ausgelassen.
  Syft-`excludes`/CI-`exclude` gelten nur für Syft, nicht für diesen separaten Leser.
- Der Leser unterstützt Dienstdefinitionen mit Einrückung unter einem obersten `services:`-Schlüssel,
  keinen vollständigen YAML-/Compose-Abgleich. Flow-Schreibweisen, Anchors, Includes, Overrides,
  Profile und Variablen werden nicht wie durch `docker compose config` ausgewertet. Es wird kein
  Docker-/Compose-Befehl ausgeführt und kein Dienst gestartet.
- In Dependency-Track stehen die Angaben am Projekt unter **Services**, nicht unter
  **Komponenten**. Ein Service-Eintrag scannt das referenzierte Image nicht; dafür `images`
  bzw. ein eigenes Komponenten-Inventar konfigurieren.
- Services allein erfüllen nicht die Prüfung auf ein nicht leeres Paketinventar. Explizite
  CI-Sammelprojekte bleiben von dieser Prüfung ausgenommen. Bei `mode: parent` liegen Services
  im eigenen Unterprojekt `<projekt>/services` derselben Version; der Parent bleibt ein reiner
  Aggregationscontainer. Der Parent-Job aktualisiert das Service-Unterprojekt auch bei bereits
  aktiver Aggregation. Die [Migration bestehender Parents](ci-integration.md#mehrere-inventare-hierarchie)
  kopiert und prüft deren Service-Inventar, bevor es aus dem Parent entfernt wird.
- Die [MR-Feedback-Schleife](mr-feedback.md), Delta-Berichte und Compliance-Gates vergleichen
  derzeit keine Service-Inventare. Für diese Prüfungen gelten weiterhin Pakete und Findings.
