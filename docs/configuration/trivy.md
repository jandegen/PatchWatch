# Native Trivy-Scans in Dependency-Track

Dependency-Track besitzt einen Trivy-Analyzer. Er sendet unterstützte Komponenten aus
importierten SBOMs an einen separaten Trivy-Server und übernimmt dessen Findings in die
bestehende Analyse. Der Syft-Agent erzeugt weiterhin das Inventar. Trivy installiert keine
Agenten und scannt über diese Anbindung weder Rechner-Dateisysteme noch laufende Cluster-Pods.

```
Syft-Agent → CycloneDX → Dependency-Track → Trivy-Server + Trivy-Datenbank
                              ↓
                      Findings / Policy / Bridge
```

## Kubernetes

Das Infra-Chart deployt `patchwatch-trivy` mit persistentem 4-GiB-Cache, einer Replica,
Startup-/Readiness-/Liveness-Probes und ohne Root-Rechte. Der Server ist ausschließlich über
einen ClusterIP-Service auf Port 4954 erreichbar. Eine NetworkPolicy erlaubt nur dem
Dependency-Track-API-Pod den Zugriff. Es gibt keinen Ingress und keinen Kubernetes-API-Zugang
für Trivy. Für das Laden/Aktualisieren der Trivy-Datenbank ist ausgehender HTTPS-Zugriff nötig.

Die bestehende GitLab-Pipeline erzeugt beim ersten Deployment einen eigenen zufälligen Token
in `patchwatch-trivy`, Key `token`. Updates erhalten diesen Token. Die API-Konfiguration setzt:

| DTrack-Einstellung | Wert |
|---|---|
| Enable | true |
| Base URL | `http://patchwatch-trivy:4954` |
| API Token | Aus Kubernetes-Secret, verschlüsselt in DTrack gespeichert |
| Ignore Unfixed | false |
| Scan Libraries / OS | jeweils true |

Die Token-Authentifizierung schützt die Trivy-RPC-Endpunkte; `/healthz` bleibt für Probes offen.
Das interne HTTP bleibt im Cluster; der Agent-Upload verwendet weiterhin HTTPS.
Neue BOMs werden automatisch analysiert. Bestehende Projekte lassen sich in DTrack erneut
analysieren; der reguläre periodische Schwachstellenabgleich greift ebenfalls.
Scanfehler und veraltete DB-Downloads müssen überwacht werden: Ein fehlendes Finding bedeutet
bei einem gestörten Analyzer nicht, dass eine Komponente sicher ist.

## Docker Compose

```sh
python3 scripts/init-compose.py
docker compose up -d --build --wait --wait-timeout 900
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
```

Der Server veröffentlicht keinen Host-Port. Der einmalige Dienst `trivy-cache-init` bereitet
nur die Schreibrechte des dedizierten Cache-Volumes vor; er hat keinen Netzwerkzugang.
Trivy selbst läuft als UID/GID 10001 mit schreibgeschütztem Root-Dateisystem.
Der Datenbankdownload kann beim ersten Start mehrere Minuten dauern. Der Cache bleibt über
Neustarts erhalten und ist wiederherstellbar; ein Backup seiner Inhalte ist nicht erforderlich.
Den Token dagegen in das bestehende verschlüsselte Secret-Backup aufnehmen.

Bei anderem Compose-Secret-Pfad auch die `*_FILE`-Variablen für die Einrichtung anpassen.
Ohne `TRIVY_URL` verändert `patchwatch.dtrack.setup` die bestehende Trivy-Konfiguration nicht.
Optional unterstützt es `TRIVY_IGNORE_UNFIXED=true`; standardmäßig werden auch Findings ohne
verfügbaren Fix angezeigt. Der einmalige Einrichtungsaufruf muss vom Rechner aus DTrack erreichen;
die konfigurierte Trivy-URL muss dagegen **vom DTrack-Container** erreichbar sein.

## Ende-zu-Ende-Prüfung

Ein echter Test der DTrack-RPC-Anbindung ist mit folgendem Skript möglich:

```sh
DT_URL=https://patchwatch.example.org \
  DT_ADMIN_PASSWORD_FILE=/sicherer/pfad/admin_password \
  python3 scripts/smoke-trivy.py
```

Der Test lädt ausschließlich synthetische Maven-Koordinaten für Log4j hoch, wartet auf
`CVE-2021-44228` mit der Zuordnung `TRIVY_ANALYZER` und löscht sein eigenes Testprojekt wieder.
Es wird keine verwundbare Software installiert. Der Test erzeugt reguläre DTrack-Findings;
bei konfigurierten Benachrichtigungszielen können diese eine Testmeldung auslösen.
Ein gültiges Admin-API-Token kann alternativ über `DT_ADMIN_API_KEY_FILE` bereitgestellt werden.

## Version, Grenzen und Betrieb

Trivy ist auf **0.76.2** und den Image-Digest
`sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb` festgelegt.
Es werden keine `latest`-Tags oder Trivy-GitHub-Actions verwendet. Bei Updates den freigegebenen
Release und Image-Digest gemeinsam in Helm, Compose und SPDX aktualisieren und die native
DTrack-RPC-Anbindung erneut testen. Scanner-Image und heruntergeladene Schwachstellendatenbank
haben unterschiedliche Aktualisierungszyklen.

Der Analyzer benötigt verwertbare Paketkoordinaten. Ohne PURL, Distributionsversion oder
Source-Paket-Metadaten können insbesondere OS-Pakete unvollständig zugeordnet werden.
Ein Syft-Inventar wird durch den zusätzlichen Analyzer nicht automatisch vollständiger.
DTrack erzeugt die Scan-Anfragen aus seinem Inventar; Trivy-spezifische Eigenschaften können
das OS-Matching verbessern. Keine fremden Komponenten oder Metadaten ungeprüft übernehmen.

NeuVector-Anbindung und automatische Laufzeit-Service-Erkennung bleiben [offene TODOs](../design/roadmap.md).
Die separate [Compose-Erfassung](../usage/services.md) liest bereits statische Dienstdefinitionen.
Es werden dafür weder Zugangsdaten angelegt noch Collectors oder Response Rules aktiviert.

Referenzen: [Dependency-Track: Vulnerability analyzers](https://dependencytrack.github.io/docs/next/),
[Trivy Client/Server](https://trivy.dev/docs/latest/references/modes/client-server/),
[Release 0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2).
