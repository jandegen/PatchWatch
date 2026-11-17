# Architektur, Datenfluss und Grenzen

## Zielsetzung

**Problem:** Auf Entwickler-Rechnern wird Software aus vielen Quellen installiert: Paketmanager, Homebrew, globale npm-/pip-Installs, IDE-Plugins, Container-Images und manuell entpackte Binaries. Ohne Inventar bleibt unklar, welche Versionen im Einsatz sind. Wird eine neue CVE veröffentlicht, lässt sich nicht beantworten, wer betroffen ist.

**Ziele:**

- Ein aktuelles, maschinenlesbares Inventar der eingesetzten Software pro Rechner (SBOM im CycloneDX-Format).
- Kontinuierlicher Abgleich gegen Schwachstellendaten. Neue CVEs lösen Meldungen aus, ohne dass neu gescannt werden muss.
- Automatische Benachrichtigung der zuständigen Teams, bei Bedarf mit JIRA-Ticket.
- Geringer Betriebsaufwand: ein zentraler Dienst, ein schlanker Agent, ausschließlich Open-Source-Komponenten.
- Datenschutzkonforme Erfassung, die nur Software-Inventar (Name, Version, Quelle, Pfad) umfasst und keine Nutzungsdaten.

**Nicht-Ziele:**

- Überwachung von Mitarbeitenden, Nutzungsdauer oder Verhalten.
- Ersatz für ein vollwertiges Endpoint-Security- oder MDM-Produkt.
- Automatisches Patchen. Das Projekt erkennt und meldet.

## Abgrenzung

| Bereich | Von diesem Projekt abgedeckt |
|---|---|
| OS-Pakete (deb, rpm, apk) | Ja |
| Sprach-Ökosysteme (npm, PyPI, Go, Maven, Cargo, …) | Ja, sofern lesbar im Dateisystem |
| Container-Images | Optional, per Syft auf Image-Ebene |
| Dienste aus Compose-Dateien | Statisches Inventar aus Namen und Image-Referenzen; keine Laufzeiterkennung |
| Binaries ohne Paketmanager | Teilweise, abhängig von der Syft-Erkennung |
| IDE- und Browser-Extensions | Ja, für unterstützte Editoren und Browser unter Linux/macOS; [Umfang und Grenzen](../usage/agent.md#ide--und-browser-erweiterungen) |
| Laufzeit-Verhalten, Nutzungsstatistiken | Nein, bewusst ausgeschlossen |

## Architektur

```
Dev-Rechner                    Zentraler Stack                   Ausgang
┌────────────────┐   SBOM    ┌──────────────────────┐  Webhook  ┌────────────────┐
│ Syft           │  (HTTPS)  │ Dependency-Track     │ ────────► │ JIRA / Slack / │
│ + Timer        │ ────────► │ API-Server + Postgres│           │ Teams          │
│ (CycloneDX)    │           └──────────▲───────────┘           └────────────────┘
└────────────────┘                      │
                                        │ laufende Synchronisation
                          OSV · GitHub Advisories · NVD · OSS Index
```

**Datenfluss:**

1. Der Agent erzeugt per Syft ein SBOM der konfigurierten Quellen und ergänzt installierte IDE-/Browser-Erweiterungen aus lokalen Metadaten. Doppelte Erweiterungseinträge werden zusammengeführt.
2. Das SBOM wird per HTTPS an die Dependency-Track-API übertragen. Pro Host existiert ein Projekt.
3. Dependency-Track gleicht die Komponenten laufend mit den Schwachstellenquellen ab.
4. Neue Findings und Policy-Verstöße lösen Notifications per Webhook aus.
5. Eine Bridge oder ein Workflow-Tool erzeugt daraus JIRA-Tickets oder Chat-Nachrichten.

## Komponenten

| Komponente | Rolle | Lizenz |
|---|---|---|
| [Syft](https://github.com/anchore/syft) | SBOM-Erzeugung auf dem Rechner | Apache 2.0 |
| [Dependency-Track](https://dependencytrack.org) | SBOM-Verwaltung, Schwachstellen-Matching, Policies, Notifications | Apache 2.0 |
| PostgreSQL | Datenbank für Dependency-Track | PostgreSQL License |
| Kubernetes, Helm/Helmfile | Betrieb des zentralen Dienstes | n/a |
| Patchwatch-Bridge (Python/SQLite) | Persistente Zustellung an JIRA, Slack und Teams | Apache 2.0 |

**Schwachstellenquellen:** OSV und GitHub Advisories liefern für Ökosystem-Pakete (npm, PyPI, Go, Maven) die präziseren Treffer. NVD/CPE wird ergänzend genutzt, erzeugt aber mehr False Positives und False Negatives. Für OS-Pakete sind Distro-Advisories maßgeblich.

## Datenschutz und Mitbestimmung

In Deutschland unterliegt die Einführung technischer Einrichtungen, die zur Überwachung von Verhalten oder Leistung geeignet sind, der Mitbestimmung (§ 87 Abs. 1 Nr. 6 BetrVG). Vor dem Rollout sind Datenschutzbeauftragte und Betriebsrat einzubinden.

**Datensparsamkeit als Designprinzip:**

- Erfasst werden Paketname, Version, Quelle, Dateipfad und erkannte Lizenzkennungen sowie Hostname, Asset-ID und die
  zur Zuordnung ausdrücklich vorgesehenen Inventar-Tags.
- Nicht übertragen werden Nutzungszeiten, Startzeitpunkte, Dauer, Dateiinhalte, Browser-Historie
  oder Erweiterungsberechtigungen. Scanner lesen lokale Paket- und Erweiterungsmetadaten; absolute
  Fundorte können Benutzernamen enthalten. Scan-Wurzeln und `extension_homes` entsprechend festlegen.
- Das SBOM wird nach dem Upload lokal gelöscht.
- Zugriff auf Dependency-Track erfolgt rollenbasiert, Aufbewahrungsfristen werden dokumentiert.

Empfehlung: Das Verfahren in einer Betriebsvereinbarung bzw. im Verzeichnis der Verarbeitungstätigkeiten beschreiben, inklusive Zweck, Datenumfang und Löschkonzept.

## Bekannte Einschränkungen

- **Matching-Qualität:** CPE-basiertes Matching ist ungenau. Ökosystem-native Quellen sind deutlich zuverlässiger.
- **Blinde Flecken:** Binaries ohne Paketmanager und Tools außerhalb der Scan-Wurzeln werden nur teilweise
  oder gar nicht erkannt. Erweiterungen werden in den unterstützten Standardpfaden erfasst; Safari,
  andere IDEs und abweichende Profilpfade sind nicht abgedeckt. Eine erfasste Erweiterung garantiert
  noch kein CVE-Matching. Windows wird derzeit nicht unterstützt.
- **Scan-Last:** Ein Vollscan von `/` kann auf großen Rechnern lange dauern.
- **Zeitverzug:** Findings erscheinen erst, wenn die Schwachstellendatenbanken die CVE aufgenommen haben und der Host einmal ein SBOM geliefert hat.

## Code-Struktur

Das Python-Paket `patchwatch` ist in Schichten gegliedert. Importe zeigen nur nach unten;
`tests/test_boundaries.py` prüft das und stellt sicher, dass auch Importe innerhalb von Funktionen
auflösbar sind.

| Schicht | Inhalt | Darf importieren |
|---|---|---|
| `core` | HTTP-Client mit Redirect-Sperre, Tag-Schema, SBOM-Reduktion und Upload, Compose-Services, SBOM-Qualität | nur Standardbibliothek |
| `agent` | `config` (validiertes Profil), `scanner` (Syft), `extensions` (IDE-/Browser-Erweiterungen), `runner` (ein Lauf), `profile` (Erstprofil), `cli` | `core` |
| `dtrack` | `client` (REST-Client, Admin-Login), `setup` (Einrichtung), `policies`, `groups`, `versions`, `scopes`, `register`, `monitor`, `compliance`, `legacy` | `core` |
| `ci` | `pipeline` (CI-Job), `bsi` (BSI-Prüfung), `mr` (Merge-Request- und Branch-Feedback), `delta` | `core`, `dtrack` |
| `bridge` | Webhook-Empfänger, Deduplizierung und Zustellung | `core` |

Der Agent bildet damit eine eigenständig auslieferbare Einheit (`agent` + `core`): Das Zipapp aus
`packaging/build.py` enthält ausschließlich diese beiden Pakete. Aufruf der Werkzeuge:
`python3 -m patchwatch.<schicht>.<modul>`, für Agent und CI-Job `python3 -m patchwatch.agent` bzw.
`python3 -m patchwatch.ci`.
