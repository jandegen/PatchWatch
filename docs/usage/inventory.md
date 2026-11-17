# Hostnamen, Tags und sichtbare Findings

## Identität eines Rechners

Ein Rechner erscheint als Projekt mit seinem **Hostname**, z. B. `workstation-01`, und der
festen Version `current`. Der Agent erkennt den Hostnamen automatisch. `hostname` in der
Konfiguration ist ein optionaler expliziter Override, z. B. für eine zentrale Vorbereitung.
Es wird kein `devhost-`-Präfix und keine zufällige UUID mehr als Anzeigename verwendet.

`host_id` bleibt als stabile Asset-ID erhalten und steht im Tag `asset-id:<id>`. Nach der
Registrierung adressieren Uploads die **Projekt-UUID** aus `project_uuid`. Ein Namenswechsel
oder wiederholter Scan legt dadurch kein zweites Inventar an. Ein neuer Upload erzeugt keine
neue Projektversion; `current` wird bei der Registrierung als neueste Version markiert.

Die zentrale Registrierung benötigt administrative Zugangsdaten, der laufende Agent behält
nur `BOM_UPLOAD` und `PROJECT_CREATION_UPLOAD`:

```sh
DT_ADMIN_PASSWORD_FILE=/sicherer/pfad/admin_password \
  python3 -m patchwatch.dtrack.register --config ~/.config/patchwatch/agent.json
# Bei Systeminstallation: --config /etc/patchwatch/agent.json, als Besitzer der Datei ausführen.
```

Alternativ `DT_ADMIN_API_KEY_FILE` verwenden. Die Zugangsdaten werden nicht in die
Agent-Konfiguration geschrieben. Der Befehl aktualisiert Name, Tags, Aktivstatus und
`isLatest` und speichert nur die Projekt-UUID lokal. Vorhandene UUIDs, Komponenten, Findings,
Analysen und Ticket-Deduplizierung bleiben erhalten. Das frühere Projekt
`devhost-<host_id>` wird automatisch gefunden und umbenannt. Bei nicht eindeutiger Zuordnung
kann ein Administrator mit `--project-uuid <uuid>` ausdrücklich das Ziel bestimmen.
Namenskollisionen werden abgewiesen; Projekte werden nicht automatisch zusammengeführt.

Bei Änderung des Hostnamens oder der Tags die Registrierung erneut ausführen. Das ist
bewusst eine administrative Aufgabe: DTrack 4.14 ignoriert Tag-Änderungen eines bestehenden
Projekts durch einen reinen Upload-Key. Wir erweitern deshalb den auf den Rechnern liegenden
Schlüssel nicht um globale Schreibrechte. Ein gelöschtes registriertes Projekt muss neu
zugeordnet werden; ein UUID-Upload legt nicht stillschweigend ein Ersatzprojekt an.

## Tag-Konvention

Projekt-Tags verwenden `schlüssel:wert`, kleingeschrieben, ohne Leerzeichen und Kommas.
Jeder Schlüssel hat genau einen Wert. Doppelte identische Tags werden entfernt, widersprüchliche
Werte oder ungültige Tags vor dem Scan abgewiesen. Passwörter und URLs gehören nicht in Tags.

| Tag | Herkunft |
|---|---|
| `managed-by:patchwatch` | Kennzeichnet von Patchwatch verwaltete Projekte |
| `asset-type:workstation` | Rechnersoftware-Inventar |
| `host:workstation-01` | Hostname |
| `asset-id:<host_id>` | Stabile Asset-Kennung |
| `os:linux` / `os:darwin` | Betriebssystem erkannt vom Agenten |
| `distro:ubuntu` | Linux-Distribution aus `/etc/os-release`, sofern verfügbar |
| `agent-scope:user` / `agent-scope:system` | Berechtigungsumfang der Installation |
| `team:platform` | Optional, ausdrücklich konfigurierter Eigentümer |
| `environment:development` | Optional, ausdrücklich konfigurierte Umgebung |
| `asset-group:developer-workstations` | Optional, konfigurierte Rechnergruppe |
| `asset-type:application`, `source:gitlab-ci`, `gitlab-project-id:<id>` | Projekte aus dem [GitLab-CI-Template](ci-integration.md) statt Rechnern; `team:`/`environment:` dort aus den Template-Inputs |

Ein Team wird **nicht** aus Benutzernamen oder Hostnamen geraten. Die Beispielkonfiguration
enthält daher keine fiktive Teamzuordnung. Erkannte Tags dürfen nicht durch widersprüchliche
Konfigurationswerte überschrieben werden. Die früheren Präfixe `agent:` und `host-group:`
werden beim Einlesen zu `agent-scope:` bzw. `asset-group:` normalisiert.

Der registrierte Tag-Satz entspricht der Agent-Konfiguration plus den erkannten Merkmalen.
Zentral ergänzte Team-/Umgebungs-Tags müssen deshalb auch in der Konfiguration stehen, bevor
die Registrierung erneut ausgeführt wird. Änderungen gelten nach erfolgreicher Registrierung.
Bridge-Routen können `team:*`, `environment:*` oder `asset-group:*` als Filter verwenden.
Die Patchwatch-Notification-Regel verarbeitet nur Projekte mit `managed-by:patchwatch`.
Der Monitor identifiziert Rechner anhand von `managed-by:patchwatch` zusammen mit
`asset-type:workstation`; alte `devhost-*`-Projekte werden während Migrationen weiter erkannt.
DTrack 4.14 ordnet diese Tags dem **Projekt** zu, nicht jeder einzelnen Paketkopie.

## Wo sind Komponenten und Findings sichtbar?

- **Projekte → Hostname → Komponenten / Audit:** tatsächlicher Bestand und Findings des Rechners.
- **Globale Komponenten:** projektübergreifende Suchmaske. Name wie `stdlib`, `certifi` oder `bash`
  eingeben und „Suchen“ ausführen. Eine leere Suchansicht ist kein leeres Inventar. Die Registrierung
  markiert `current` als neueste Version, damit der Filter „nur neueste Projektversionen“ greift.
- **Dashboard:** aggregierte Portfolio-Metriken. Diese werden separat von Projekt-Findings
  berechnet und können nach einem großen Import zeitlich nachlaufen.

Die Einrichtung und die Registrierung fordern einen Portfolio-Refresh über die offizielle
API an. DTrack aktualisiert diese Metriken regulär jede Stunde. Eine vollständige Berechnung
kann bei großen Inventaren dauern. Im Dashboard kann auch der Aktualisieren-Knopf verwendet
werden. Der tägliche Monitor vergleicht bekannte Projektzahlen und Finding-Zahlen mit den
Portfolio-Zählern; nach 75 Minuten Import-/Aggregations-Toleranz meldet er fehlende Zähler
als Betriebsfehler. Das Monitoring benötigt weiterhin nur `VIEW_PORTFOLIO`.

## Was ist gewährleistet, was nicht?

Erkannte und gespeicherte Findings sind am Projekt und über dessen Audit-Ansicht sichtbar.
Die Trivy-Anbindung wurde mit einem echten Finding (`CVE-2021-44228`, `TRIVY_ANALYZER`)
Ende zu Ende geprüft. Für den Entwickler-PC wurden auch `CVE-2026-111943` und das certifi-
Advisory `GHSA-6q48-6c7w-9gw2` in DTrack nachgewiesen.

Eine **vollständige Erkennung jeder Schwachstelle** lässt sich nicht garantieren: Erfassung,
PURL-/Distro-Metadaten, aktuelle Datenbanken und erfolgreiche Analyzer-Läufe sind Voraussetzungen.
Ein Versionsfund kann außerdem durch einen Distributionspatch oder den tatsächlich verwendeten
Trust Store bereits entschärft sein. Solche Bewertungen gehören nachvollziehbar ins Finding-Audit;
Findings nicht pauschal anhand eines alten Versionsstrings unterdrücken.

Die Severity-Grenze `HIGH`/`CRITICAL` betrifft standardmäßig nur die **Benachrichtigungs-Bridge**.
Auch `MEDIUM`- und `LOW`-Findings bleiben in DTrack sichtbar. Eine CVE kann über einen Alias wie
GHSA geführt werden; in der Audit-Ansicht beide Kennungen berücksichtigen. Ein grüner Upload-
Timer allein bestätigt weder fehlerfreie Analyzer noch eine aktuelle Schwachstellendatenbank.


## Dienste und Erweiterungen

IDE-/Browser-Erweiterungen erscheinen als Paketkomponenten mit technischer ID und Version;
gleiche Installationen werden innerhalb desselben Ökosystems zusammengeführt. Die
[Agent-Anleitung](agent.md#ide--und-browser-erweiterungen) beschreibt die unterstützten Produkte.
Statische Dienste aus Compose-Dateien erscheinen dagegen unter **Services**. Sie belegen
keinen laufenden Prozess und ersetzen keinen Image-Scan; siehe [Service-Erfassung](services.md).

## Dependency Graph

Der Agent erhält Paket-Abhängigkeiten aus Syfts CycloneDX-Ausgabe und passt die Referenzen
an die deduplizierten Komponenten an. Referenzen bleiben auf ihre Scan-Quelle beschränkt;
Dateikomponenten, unbekannte Ziele und Selbstkanten werden nicht übernommen.
Der stabile Host-Knoten verbindet die Wurzeln der vom Scanner erkannten Teilgraphen.
Paket-zu-Paket-Kanten stammen ausschließlich aus dem Scanner. Isolierte Pakete ohne erkannte
Beziehungen bleiben vollständig in der Komponententabelle, erhalten aber keine erfundene
Host-Abhängigkeit. Ein Inventar ganz ohne erkannte Beziehungen kann deshalb weiterhin einen
leeren Graphen haben. Syft ermittelt aus einem Dateisystem nicht für jedes Ökosystem einen
vollständigen Laufzeitgraphen.

Eine direkte Host-Kante zu jedem der über 11.000 Pakete wurde verworfen: Neben der falschen
Aussage über direkte Abhängigkeiten verursachte das große Projektfeld in DTrack 4.14 beim
Laden aller Komponenten einen Java-Heap-Überlauf. Die Verankerung erkannter Teilgraphen
vermeidet diese Vervielfachung und lässt auch getrennte Zyklen erreichbar.

Die früheren Agent-Versionen haben `dependencies` beim Bereinigen verworfen. Bereits
importierte Projekte bekommen den Graphen erst durch einen erneuten Upload mit der aktuellen
Agent-Version. **Projekt → Dependency Graph** danach neu laden. Bei großen Host-Inventaren
zunächst eine einzelne Komponente untersuchen; Tausende Knoten können die Darstellung
unübersichtlich machen. Eine leere UI trotz erneuten Imports über die API-Ausgabe
`GET /api/v1/bom/cyclonedx/project/{uuid}` auf tatsächlich vorhandene `dependsOn`-Kanten prüfen;
die Anzahl der `dependencies`-Datensätze allein reicht nicht, da DTrack auch leere Einträge
exportiert. Der Compliance-Bericht zählt Verankerungen am Host und Paket-Abhängigkeiten getrennt.
