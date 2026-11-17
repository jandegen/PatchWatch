# Dokumentation

Die Anleitungen beschreiben den implementierten Stand von Patchwatch. Beispiele
mit `example.org`, `platform/patchwatch`, `workstation-01` und Realm `engineering`
sind Platzhalter. Shell-Befehle werden aus dem Wurzelverzeichnis des eigenen
Checkouts ausgeführt, sofern nicht anders angegeben. Release-Namen `patchwatch`
und `dtrack` sowie der Namespace `patchwatch` entsprechen den mitgelieferten Skripten.

## Einstieg und Installation

| Anleitung | Ziel |
|---|---|
| [Schnellstart](getting-started.md) | Lokal starten, anmelden und den ersten Upload vorbereiten |
| [Betriebsart wählen](installation/index.md) | Voraussetzungen und Unterschiede zwischen Compose und Kubernetes |
| [Eigene Umgebung konfigurieren](installation/customization.md) | Domains, Registry, GitLab, Storage, TLS, Namespace und Defaults anpassen |
| [Docker Compose](installation/compose.md) | Vollständigen Stack und HTTPS einrichten |
| [Kubernetes / GitLab CI](installation/kubernetes.md) | Cluster vorbereiten, Pipeline konfigurieren und ausrollen |

## Konfiguration

| Anleitung | Ziel |
|---|---|
| [Keycloak / OIDC](configuration/oidc.md) | Öffentlichen Client, PKCE, Gruppen, Teamrechte und CA-Vertrauen einrichten |
| [Richtlinien und Compliance](configuration/policies.md) | Security-/Lizenzregeln und Auswertung konfigurieren |
| [Alerting und Ticketing](configuration/alerting.md) | Zustellziele, Filter und Wiederholungen einrichten |
| [Trivy](configuration/trivy.md) | Nativen Analyzer und Token konfigurieren und prüfen |

## Nutzung

| Anleitung | Ziel |
|---|---|
| [Agent](usage/agent.md) | Linux/macOS, Scan-Wurzeln, Erweiterungen und Zeitpläne |
| [Inventar und Findings](usage/inventory.md) | Geräteidentität, Registrierung, Tags und Sichtbarkeit |
| [Dienste aus Compose](usage/services.md) | Statische Service-Erfassung verstehen und konfigurieren |
| [GitLab-CI-Integration](usage/ci-integration.md) | Repository-/Image-SBOMs, Versionen und Gates |
| [BSI-Prüfung der CI-SBOMs](usage/bsi-sbom.md) | Pflichtmetadaten, Auslieferungslizenzen und Upload-Prüfung |
| [Delta-Berichte](usage/delta-reports.md) | Änderungen gegenüber früheren Versionen auswerten und versenden |
| [Merge-Request-Feedback](usage/mr-feedback.md) | Isolierte Scans und geschützten Feedback-Worker einrichten |

## Betrieb und Referenz

- [Betrieb](operations/index.md): Monitoring, Backups, Wiederherstellung, Updates und Schlüsselrotation.
- [Architektur und Grenzen](reference/architecture.md): Komponenten, Datenfluss, Datenumfang und Erkennungsgrenzen.
- [Lizenzen und SPDX](reference/licenses.md): Projektlizenz, deklarierte Abhängigkeiten und Inventur.

## Entwürfe und Roadmap

[Entwürfe](design/README.md) behandeln Agent-Pakete und Enrollment, die noch nicht
implementiert sind. Sie sind keine Installationsanleitungen. Die
[Roadmap](design/roadmap.md) beschreibt weitere offene Integrationen.

## Änderungen an der Dokumentation

Neue Anleitungen dem passenden Themenverzeichnis zuordnen und hier verlinken.
Konkrete Betreiber-Domains, Benutzer, Cluster-Nodes oder GitLab-Projekt-IDs durch
neutrale Beispiele ersetzen. Beispiele müssen ihre benötigten Variablen und
Voraussetzungen benennen; Abweichungen zwischen Beispielen und tatsächlichen
Skript-Defaults gehören in die [Anpassungsübersicht](installation/customization.md).
Links relativ zum jeweiligen Dokument setzen. Änderungen an Dokumentationspfaden
auch in Skripthinweisen aktualisieren und anschließend die SPDX-Inventur erneuern.
