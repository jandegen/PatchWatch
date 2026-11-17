# Konzept: vereinfachte Agent-Verteilung

Stand: 16. November 2026. Vorschlag auf Basis des Repositorys. **Teilweise umgesetzt:** Der Agent ist
als eigene Schicht (`patchwatch/agent` + `patchwatch/core`, nur Standardbibliothek) abgetrennt;
`packaging/build.py` baut daraus ein reproduzierbares Zipapp, ein `.deb` und (unter macOS) ein `.pkg`,
`patchwatch-agent --init-config` legt das Profil mit neuer `host_id` an, und der CI-Job
`agent-packages` veröffentlicht die Artefakte. Das Paket verwendet das System-Python (≥3.12).
**Noch offen:** private Python-Laufzeit, Signierung/Notarisierung, Paket-SBOM, Diagnosebefehl,
Registrierung mit Zielgeräte-Metadaten, Update-/Rollback-Abläufe und alles zu Enrollment.

## Empfehlung

Den Agenten als versioniertes Installationspaket einschließlich Python-Laufzeit und Syft
ausliefern. Ein separates Geräteprofil enthält Konfiguration und Zugangsdaten und wird
über Ansible beziehungsweise MDM verteilt. Installation, Einrichtung und Updates werden
dadurch wiederholbare Verwaltungsaktionen; ein Git-Checkout auf Endgeräten entfällt.

Zunächst den bestehenden direkten Upload zu Dependency-Track beibehalten und die
Registrierung vom Verwaltungsrechner aus automatisieren. Einen eigenen Enrollment-Dienst
erst ergänzen, wenn Geräte ohne bestehende Verwaltung aufgenommen werden sollen oder
eine zuverlässig durchgesetzte Berechtigung pro Gerät erforderlich ist.

## Ausgangslage und konkrete Hindernisse

| Heute | Auswirkung | Vorgeschlagene Änderung |
|---|---|---|
| `scripts/install-agent.sh` installiert aus einem lokalen Checkout | Quellen und Build-Umgebung müssen auf jeden Rechner | Fertige Release-Pakete |
| Python ≥3.12 und Syft müssen vorher installiert sein | Unterschiedliche Versionen, Pfade und Fehlerbilder | Getestete, mitgelieferte Laufzeit und Scanner |
| `pip install --no-deps .` baut vor Ort; Build-Abhängigkeiten sind damit nicht ausgeschlossen | Installation kann zusätzlichen Paketindex-Zugriff benötigen | Ausschließlich in CI bauen |
| URL, Scan-Wurzeln und Schlüssel werden separat eingerichtet | Manuelle Schritte und Konfigurationsabweichungen | Zentral gepflegte Profile mit Gerätezustand |
| systemd-/launchd-Dateien werden kopiert, aber nicht aktiviert | Erfolgreiche Installation bedeutet noch keinen regelmäßigen Scan | Eigener Einrichtungsschritt prüft und aktiviert |
| `patchwatch.dtrack.register` benötigt administrative DTrack-Zugangsdaten | Registrierung bleibt ein zusätzlicher administrativer Ablauf | Zentraler Registrierungsworkflow |
| Keine Agent-Release-Jobs, Paketablage oder geregelten Updates | Aktualisierung und Rücknahme bleiben Handarbeit | Versionierte Artefakte und gestaffelter Rollout |

Grundlage: [Installer](../../scripts/install-agent.sh), [Agent-Anleitung](../usage/agent.md),
[Registrierung](../usage/inventory.md), [Projektmetadaten](../../pyproject.toml) und
[GitLab-Pipeline](../../.gitlab-ci.yml).

## Zielablauf für verwaltete Rechner

1. Die Verwaltung installiert eine freigegebene Paketversion für Betriebssystem und Architektur.
2. Sie übernimmt eine vorhandene `host_id` oder erzeugt einmalig eine neue. Geklonte
   Betriebssystem-Images enthalten weder Geräteidentität noch Zugangsdaten.
3. Sie erfasst Hostname, Betriebssystem und Distribution vom Zielgerät. Ein zentraler
   Registrierungsjob legt das Projekt an beziehungsweise aktualisiert es und liefert
   `project_uuid` zurück. Administrative Zugangsdaten bleiben auf dem Verwaltungsrechner.
4. Ansible/MDM schreibt Profil, Projekt-UUID und Upload-Schlüssel mit restriktiven Rechten.
5. Ein neuer Diagnosebefehl prüft Konfiguration, Leserechte, Scanner, TLS-Vertrauen,
   API-Erreichbarkeit und Projektzuordnung. Der erste vollständige Scan bestätigt den
   BOM-Import; erst danach meldet der Rollout das Gerät als erfolgreich eingerichtet.
6. Die Verwaltung aktiviert den täglichen Zeitplan. Bei temporärer Nichterreichbarkeit
   bleibt das Gerät als ausstehend erkennbar und die Einrichtung wird wiederholt.

Angestrebte Bedienung: ein Ansible-Playbook beziehungsweise ein MDM-Auftrag pro Gerätegruppe.
Ein manueller Weg aus Paketinstallation und Profilimport bleibt für Einzelgeräte verfügbar.
Geheimnisse werden weder als Kommandozeilenargument noch in allgemeinen Download-URLs übergeben.

Wichtige Voraussetzung: `inventory_tags()` ermittelt OS und Distribution derzeit auf dem
ausführenden Rechner. `patchwatch.dtrack.register` kann daher noch nicht unverändert zur
Registrierung beliebiger entfernter Geräte dienen. Die Registrierung muss explizite,
validierte Zielgeräte-Metadaten verarbeiten können; der lokale Aufruf bleibt kompatibel.

## Pakete und Release-Prozess

| Ziel | Vorgesehenes Format | Verteilung |
|---|---|---|
| Debian-/Ubuntu-Systeme mit systemd | `.deb` | Zunächst versionierter Download, später internes APT-Repository |
| macOS | Signiertes und notarisiertes `.pkg` | MDM oder manueller Paketimport |
| RPM-basierte Linux-Systeme | `.rpm`, bei nachgewiesenem Bedarf | Vorhandene Linux-Verwaltung, später RPM-Repository |

Startumfang: Linux x86_64 und macOS arm64. Weitere Architekturen werden nach tatsächlichem
Gerätebestand ergänzt. Das ist eine Planungsannahme, keine im Repository belegte Flottenanalyse.
Windows bleibt außerhalb dieses Konzepts, da der Agent plattformspezifische Anpassungen benötigt.

Das Paket enthält Agent, private Python-Laufzeit, Syft, Dienstdefinitionen und Lizenzhinweise.
Ein Verzeichnisbundle mit festem Einstiegspunkt ist das bevorzugte Ziel; ein einzelnes
selbstentpackendes Binary ist dafür nicht erforderlich. Laufzeit und Scanner werden über
absolute Pfade gestartet. Die konkrete Bündelung wird zuerst in einem Build-Prototyp geprüft,
einschließlich Linux-Kompatibilitätsgrenzen und macOS-Signierung. Sie verändert die
Wartungsverantwortung: Python- und Syft-Sicherheitsupdates benötigen neue Agent-Pakete.

Pro Release-Tag `vX.Y.Z` baut CI die unterstützten Pakete. Paketversion und Python-Projektversion
müssen übereinstimmen. Die Veröffentlichung umfasst Prüfsummen, einen vertrauenswürdig
signierten Release-Nachweis beziehungsweise signierte Repository-Metadaten, eine SBOM der
tatsächlich gebündelten Komponenten und Build-Herkunft. Eine Prüfsumme neben einem Download
allein ersetzt keinen vertrauenswürdigen Signaturnachweis.

Die vorhandene Quell-SPDX und die Container-SBOMs ersetzen diese Paket-SBOM nicht.
Insbesondere muss die bisherige Annahme „Agent hat keine eigenen Drittanbieterpakete“ in
`ci/components.yml` und der CI-Dokumentation an die gebündelte Laufzeit angepasst werden.
macOS benötigt geeignete Build-/Test-Runner und Signierungszugänge; deren Verfügbarkeit
ist vor der Umsetzung zu klären. Endgeräte benötigen keinen GitLab-Build- oder Admin-Token.

## Konfiguration, Updates und Betrieb

- **Software und Gerätezustand trennen:** Programmdateien unter `/opt/patchwatch`,
  Konfiguration und Schlüssel unter `/etc/patchwatch`, Zustand unter `/var/lib/patchwatch`.
  Der Paketinstaller überschreibt weder `host_id`, `project_uuid`, Profil noch Schlüssel.
- **Idempotente Einrichtung:** Erneutes Ausrollen repariert Paket und Dienstdefinitionen,
  erzeugt aber kein neues Gerät. Namen- und Identitätskonflikte brechen mit einem klaren
  Fehler ab; Projekte werden nicht automatisch zusammengeführt.
- **Bewusste Scanprofile:** Zum Beispiel Linux-System und macOS-Entwicklergerät mit passenden
  Wurzeln. Vollständigkeit, Home-Zugriff und macOS-Datenschutzrechte bleiben ausdrücklich
  Teil des Profils; Paketinstallation allein gewährt keine zusätzlichen Leserechte.
- **Diagnose:** Neue Befehle für Version, Konfigurationsprüfung und lokalen Status; Ausgabe
  mit Agent-/Syft-Version, letztem Scan und letztem bestätigten Import, ohne Schlüssel.
  Der bestehende Scan-Einstiegspunkt bleibt erhalten.
- **Zeitplanung:** Linux-Zufallsverzögerung beibehalten; für macOS ebenfalls einen verteilten
  Start vorsehen. Paketinstallation startet keinen ungeplanten Vollscan.
- **Updates:** Verwaltung verteilt konkrete Versionen zunächst an Pilotgeräte und danach
  an weitere Gruppen. Laufende Scans werden vor dem Austausch abgewartet; Zeitplan vorübergehend
  anhalten. Kein paralleler Schreibzugriff auf Installation oder Gerätezustand.
- **Rollback:** Vorversion bleibt verfügbar; Konfigurationsmigrationen sind versioniert und
  rückwärtskompatibel oder mit geschützter Sicherung rücknehmbar. Identität und Projekt-UUID
  bleiben erhalten. Ein Paket-Downgrade allein genügt bei inkompatibler Migration nicht.
- **Deinstallation:** Stoppt den Zeitplan und entfernt Software. Gerätezustand und Zugangsdaten
  werden nur bei ausdrücklicher Bereinigung gelöscht; zentrale Sperrung gehört zum Offboarding.

## Registrierung und Schlüssel: zwei Ausbaustufen

Der detaillierte Entwurf der zweiten Stufe steht im [Enrollment-Konzept](enrollment.md).

**Stufe 1 – bestehende Verwaltung nutzen.** Ein zentraler Job registriert Geräte und verteilt
ihre Konfiguration. Die Agenten behalten die bisherigen DTrack-Uploadrechte, administrative
Rechte bleiben zentral. Schlüssel werden über die Geheimnisverwaltung von Ansible/MDM
verteilt und unabhängig vom Softwarepaket rotiert. Zentraler Job und Zielgerät müssen dieselbe
persistierte `host_id` verwenden; Wiederholungen nach Teilfehlern dürfen keine Duplikate erzeugen.

Diese Stufe vereinfacht die Verteilung, bietet aber keine nachgewiesene Berechtigungsgrenze
pro Gerät: `project_uuid` ist eine Zieladresse, kein Zugriffsschutz. Der vorhandene Upload-Key
hat außerdem `PROJECT_CREATION_UPLOAD`. Ein gemeinsamer Schlüssel ermöglicht keine einzelne
Gerätesperrung. Etwaige getrennte Schlüssel müssen auf ihre tatsächlichen DTrack-Rechte geprüft
werden; eine reine Aufteilung der Schlüssel beweist keine Projektisolation.

**Stufe 2 – optionaler Enrollment- und Upload-Dienst.** Für Self-Service erhält jedes Gerät
ein kurzlebiges, einmal verwendbares Enrollment-Token aus einem autorisierten Verwaltungsprozess.
Der Dienst bindet die Registrierung an eine Gerätekennung und ein freigegebenes Profil,
registriert zentral das DTrack-Projekt und stellt eine eigene Gerätezugangsberechtigung aus.
Wiederholungen nach Verbindungsabbruch sind idempotent; eine neue Geräteinstallation kann
nicht allein durch Behaupten einer bekannten `host_id` die bisherige Identität übernehmen.

Für wirksame Isolation laufen spätere Uploads über diesen Dienst. Er erzwingt die Zuordnung
von Geräteberechtigung zu Projekt-UUID, begrenzt Uploads und hält DTrack-Schlüssel zentral.
Ein Enrollment-Dienst, der nur denselben gemeinsamen Upload-Key zurückgibt, löst das
Isolationsproblem nicht. Betrieb, Verfügbarkeit, Sperrung, Rotation und Zustandsdatenbank
sind zusätzlicher Aufwand und begründen die getrennte Entscheidung für diese Stufe.

## Abgewogene Alternativen

| Variante | Nutzen | Bewertung |
|---|---|---|
| Nur den bestehenden Installer erweitern | Schnell weniger manuelle Schritte | Übergangslösung; Python-, Build- und Update-Abhängigkeiten bleiben |
| Wheel mit externer Python-/Syft-Installation | Kleine Artefakte, einfache Python-Builds | Sinnvoll, falls die gesamte Flotte diese Voraussetzungen bereits zentral garantiert |
| Native Pakete mit privater Laufzeit und Syft | Einheitliche Installation, klarer Updateweg | Empfohlenes Ziel; mehr Build- und Patchverantwortung |
| Container als Standard-Agent | Bekannter Image-Verteilungsweg | Für Hostinventar wegen Dateisystemzugriff, Benutzerprofilen und Desktop-Umgebungen nicht bevorzugt |
| Eigener Updater und Enrollment sofort | Unabhängig von Ansible/MDM | Erst bei belegtem Bedarf; deutlich mehr Server- und Sicherheitslogik |

## Umsetzung in überprüfbaren Schritten

1. **Paket-Prototyp:** Gerätebestand und Verwaltungsweg bestätigen; ein Linux- und ein
   macOS-Testgerät festlegen. Laufzeit, Syft und Dienstdefinitionen bündeln. Installation
   auf sauberen Systemen ohne vorinstalliertes Python/Syft und ohne Quell-Checkout nachweisen.
   Mindest-OS-Versionen dokumentieren. Erst danach die endgültige Build-Technik festlegen.
2. **Verwalteter Rollout:** Release-Jobs, Paketprüfung, Diagnose und zentrale Registrierung
   mit Zielgeräte-Metadaten ergänzen. Ansible-Rolle und MDM-Installationsrezept liefern.
   Bestehende Installationen unter Erhalt ihrer Identität übernehmen; vorhandene
   benutzerbezogene Installationen vor einer Systemmigration ausdrücklich zuordnen.
3. **Updates und Betriebsreife:** Pilotgruppe, Versionsübersicht, Rotation, Rollback und
   Deinstallation erproben. Paket-Repositories nur ergänzen, wenn sie den gewählten
   Verwaltungsweg vereinfachen. Danach Stufe 2 anhand des tatsächlichen Bedarfs entscheiden.

Abnahmekriterien:

- Ein Verwaltungsauftrag reicht von der Installation bis zum ersten bestätigten BOM-Import;
  keine manuelle JSON-Bearbeitung auf dem Endgerät.
- Nach der Paketbereitstellung benötigt die Installation keinen Python-Paketindex oder
  Nachladezugriff für Syft; API-Zugriff wird erst für Registrierung und Upload benötigt.
- Wiederholte Einrichtung, Upgrade und Rollback erhalten `host_id`, `project_uuid` und Findings.
- Ein Netzwerkausfall erzeugt einen nachvollziehbaren ausstehenden/fehlgeschlagenen Zustand;
  Wiederholung erzeugt kein zweites Projekt.
- Schlüssel erscheinen weder im Softwarepaket noch in Prozessargumenten oder Logs;
  administrative DTrack-Zugänge liegen ausschließlich in der zentralen Verwaltung.
- Nachgewiesene Tests umfassen frische Installation, Migration, Namenskollision,
  fehlendes TLS-Vertrauen, unterbrochene Einrichtung sowie Update bei laufendem Scan.
- Ziel für den Pilot: höchstens fünf Minuten aktive Administrationszeit pro Gerätegruppe,
  ohne Paketdownload und Scandauer. Vorher-/Nachher-Werte werden im Pilot erhoben.
