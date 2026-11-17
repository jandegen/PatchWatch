# Agent für Linux und macOS

## Installation per Paket (empfohlen für verwaltete Rechner)

Der Agent ist unabhängig vom restlichen Projekt paketierbar: `patchwatch/agent` und
`patchwatch/core` benötigen nur die Python-Standardbibliothek. `packaging/build.py` erzeugt daraus
reproduzierbar ein Zipapp und die Installationspakete; die CI-Job `agent-packages` legt sie als
Artefakte in `dist/` ab.

```sh
python3 packaging/build.py pyz                 # dist/patchwatch-agent.pyz
python3 packaging/build.py deb                 # dist/patchwatch-agent_<Version>_all.deb
python3 packaging/build.py deb --syft ./syft   # Syft mitliefern (architekturspezifisch)
python3 packaging/build.py pkg                 # macOS: dist/patchwatch-agent-<Version>.pkg
sudo apt install ./dist/patchwatch-agent_1.0.3_all.deb
```

Das Paket installiert den Starter `patchwatch-agent`, das Zipapp unter `/usr/lib/patchwatch/`, die
systemd-Units (bzw. unter macOS Starter in `/usr/local/bin` und den LaunchDaemon) und legt
`/etc/patchwatch/agent.json` mit einer neuen `host_id` an (`patchwatch-agent --init-config`). Eine
vorhandene Konfiguration wird nie überschrieben. Der Zeitplan wird **nicht** aktiviert: erst
`url` und Schlüssel eintragen, einmal `sudo patchwatch-agent` ausführen, dann den Timer aktivieren
(siehe unten). Das Paket benötigt `python3 >= 3.12`; bei `--syft` ist Syft enthalten, sonst muss es
vorhanden sein. Eine private Python-Laufzeit, Signierung und Notarisierung sind noch nicht Teil des
Builds ([Konzept](../design/agent-distribution.md)). Das `.pkg` wird nur unter macOS gebaut
(`pkgbuild`) und wurde bisher nicht auf einem Gerät erprobt.

## Installation aus dem Checkout (Entwicklung, einzelne Rechner)

Voraussetzungen: Python ≥3.12, Syft und Netzwerkzugriff auf die HTTPS-API. Referenzversion
für Syft: **1.57.1**. Release-Archiv und Checksummen vom
[offiziellen Release](https://github.com/anchore/syft/releases/tag/v1.57.1) beziehen und prüfen,
oder Syft über die vorhandene Paketverwaltung verteilen. Der Installer lädt keine fremden
Installationsskripte nach. Syft muss im PATH des Dienstes sein; sonst in `agent.json` einen
absoluten `syft`-Pfad setzen.

```sh
sudo bash scripts/install-agent.sh
sudoedit /etc/patchwatch/agent.json
# Schlüssel aus DTrack-Team sbom-upload sicher nach /etc/patchwatch/api-key übertragen:
sudo chmod 600 /etc/patchwatch/api-key
# Optional zuerst administrativ registrieren, siehe inventory.md.
sudo patchwatch-agent
```

Vor dem Installer einen Checkout auf dem Zielrechner bereitstellen und die Befehle
aus dessen Wurzelverzeichnis ausführen. In `agent.json` mindestens `url`,
`api_key_file` und die gewünschten `roots` prüfen. Die mitgelieferte URL ist ein
Platzhalter (`https://patchwatch.example.org`) und muss ersetzt werden; `host_id` erzeugt der Installer.

Den Upload-Schlüssel erzeugt die zentrale Einrichtung mit `patchwatch.dtrack.setup`:

| Installation | Quelle auf dem Server |
|---|---|
| Docker Compose | `.secrets/upload_key` nach dem [Compose-Setup](../installation/compose.md) |
| Kubernetes | Secret `patchwatch-provisioning`, Feld `upload_key` |

Die Datei sicher auf den Zielrechner übertragen und dort als
`/etc/patchwatch/api-key` mit Besitzer `root` und Modus `0600` installieren.
Bei einem Agenten direkt auf dem Compose-Server geht das aus dem Checkout mit
`sudo install -o root -m 0600 .secrets/upload_key /etc/patchwatch/api-key`.
Nur diesen Upload-Schlüssel verteilen. Der Agent erhält ausschließlich `BOM_UPLOAD` und
`PROJECT_CREATION_UPLOAD`, keinen administrativen oder Portfolio-Lesezugriff.

## Verbindung zu einem Compose-Server

Für entfernte Rechner zuerst [Compose mit HTTPS](../installation/compose.md#https-für-entfernte-agenten)
einrichten. `url` ist dann beispielsweise `https://patchwatch.example.org:8443`,
ohne `/api`. DNS, Portfreigabe und CA-Vertrauen müssen auf jedem Agent-Rechner
funktionieren. Compose-Dienstnamen wie `apiserver` sind nur im Container-Netz auflösbar.
Der Agent läuft als Host-Dienst; Compose startet ihn nicht automatisch.

Ein erster lokaler Scan auf demselben Rechner wie der Compose-Stack ist auch ohne
Systeminstallation möglich. Nach dem Schnellstart und mit Syft im PATH im Checkout:

```sh
python3 - <<'PY'
import json, os, socket, uuid
from pathlib import Path
os.umask(0o077)
path = Path('.secrets/agent-local.json')
config = json.loads(path.read_text()) if path.exists() else {
    'url': 'http://localhost:8080',
    'allow_http': True,
    'host_id': str(uuid.uuid4()),
    'hostname': socket.gethostname(),
    'agent_scope': 'user',
    'api_key_file': str(Path('.secrets/upload_key').resolve()),
    'roots': [str(Path.cwd())],
    'scan_extensions': False,
    'lock_file': str(Path('.secrets/agent-local.lock').resolve()),
}
path.write_text(json.dumps(config, indent=2) + '\n')
PY
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  python3 -m patchwatch.dtrack.register --config .secrets/agent-local.json
python3 -m patchwatch.agent --config .secrets/agent-local.json
```

Bei abweichendem `HTTP_PORT` beide lokalen URLs anpassen. Dieses Beispiel erfasst
nur den Checkout und verwendet bewusst HTTP auf Loopback. Für ein vollständiges
Systeminventar die Systeminstallation und passende Scan-Wurzeln verwenden;
für sie dieselbe `host_id` und gegebenenfalls `project_uuid` übernehmen, wenn sie
das lokale Testinventar fortführen soll.
`ALLOW_HTTP=true` steuert die administrative Registrierung; der Agent liest
stattdessen `allow_http` aus seiner JSON-Datei. Für HTTPS dieses Feld entfernen.
Administratorzugangsdaten bleiben beim Betreiber. Entfernte Hosts können mit einer
Kopie ihrer Zielkonfiguration auf dem Betreiberrechner registriert werden; danach
die aktualisierte Datei mit `project_uuid` auf den Host zurückübertragen.

Nach erfolgreichem Upload unter **Projekte → Hostname → current → Komponenten**
den Bestand prüfen. Der Agent wartet auf den BOM-Import; Findings können später
eintreffen. Erst nach einem erfolgreichen Testlauf den unten beschriebenen
Timer beziehungsweise LaunchDaemon aktivieren.

Das DTrack-Projekt heißt wie der Rechner (z. B. `workstation-01`), Version `current`.
Der Installer generiert zusätzlich eine stabile `host_id`. Nach der administrativen Registrierung
wird über `project_uuid` hochgeladen; Umbenennung und Tag-Änderungen benötigen deshalb keinen
neuen Bestand. Registrierung, Tag-Schema und Migration sind in [inventory.md](inventory.md)
beschrieben. Der Hostname wird entsprechend der gewünschten Gerätezuordnung übertragen;
Nutzernamen werden weiterhin nicht automatisch als Identität verwendet.

Konfigurationsbeispiel: [`agent/agent.example.json`](../../agent/agent.example.json).

| Einstellung | Bedeutung |
|---|---|
| `url` | HTTPS-Basis-URL, ohne `/api` |
| `allow_http` | Standard `false`; ausschließlich für lokale HTTP-Tests ausdrücklich auf `true` setzen |
| `host_id` | Stabile Asset-ID, wird zusätzlich als `asset-id:*` getaggt |
| `hostname` | Optionaler Anzeigename; standardmäßig automatisch erkannter Hostname |
| `project_uuid` | Zielprojekt nach administrativer Registrierung, bleibt bei Umbenennung gleich |
| `agent_scope` | `user` oder `system`, passend zur Installation |
| `api_key_file` | Schlüsseldatei, Modus `0600` oder `0400` |
| `roots` | Syft-Scan-Verzeichnisse; Standard `/usr`, `/opt`; `[]` deaktiviert Verzeichnis-Scans |
| `scan_extensions` | IDE-/Browser-Erweiterungen erfassen; Standard `true`; unabhängig von `roots` |
| `extension_homes` | Optional: absolute Benutzer-Home-Verzeichnisse; ohne Angabe automatische Ermittlung; `[]` deaktiviert die Erfassung |
| `images` | Optionale Syft-Imagequellen, z. B. `registry:registry.example/tool:1.2` |
| `tags` | Zusätzliche kanonische Tags wie `team:platform`; Team nur bei bekannter Zuordnung setzen |
| `excludes` | Zusätzliche Syft-Ausschlüsse relativ zur jeweiligen Scan-Wurzel |
| `detect_services` | Standard `true`: Services aller Compose-Dateien unter `roots` (bis Tiefe 5; nur Name und Image) als CycloneDX-Services hochladen |
| `scan_timeout` | Sekunden je Scan; Standard 7200 |
| `lock_file` | Verhindert konkurrierende Scans desselben Hosts |

Ein Vollscan ist mit `roots: ["/"]` möglich. Pseudo-Dateisysteme, temporäre Verzeichnisse,
Docker-/containerd-Storage und macOS `/System`, `/Volumes` werden ausgeschlossen. Für andere
Wurzeln Ausschlüsse relativ anpassen. Homebrew auf Apple Silicon benötigt `/opt/homebrew`,
unter Intel üblicherweise `/usr/local`. Für Benutzerpakete und Repositories ausdrücklich
entsprechende Verzeichnisse aufnehmen. Begrenzte Wurzeln erfassen **nicht** automatisch alle
OS-Paketdatenbanken; bei Bedarf `/var/lib/dpkg`, `/var/lib/rpm`, `/lib/apk` einbeziehen oder `/` scannen.
Bei mehreren Wurzeln werden identische Komponenten zusammengeführt. Syft erhält weiterhin
einen Scan-Aufruf je konfigurierter Wurzel; überlappende Wurzeln vermeiden, um Scan-Arbeit
nicht mehrfach auszuführen. Die Erweiterungserfassung benötigt keine zusätzlichen Syft-Aufrufe. Der Agent ergänzt die
Directory-Standardkataloge um `+javascript-package-cataloger`, damit insbesondere globale npm-Installationen erfasst
werden. Eine leere Inventur wird zum Schutz vor versehentlichem Überschreiben abgewiesen; nur für
bewusst leere Quellen `allow_empty: true` setzen. Upload-Grenze: 128 MiB.

## Dienste aus Compose

`detect_services` erfasst standardmäßig statische Dienstnamen und Image-Referenzen aus
Compose-Dateien unter `roots`. Suchgrenzen, Zusammenführung gleicher Namen und Unterschiede
zu einem laufenden Dienst beschreibt die [Service-Anleitung](services.md). Syft-Ausschlüsse
werden auf diesen separaten Leser nicht angewendet.

## IDE- und Browser-Erweiterungen

Der Agent liest standardmäßig zusätzlich installierte Erweiterungen in den üblichen
Benutzerverzeichnissen auf Linux und macOS. Dafür werden keine weiteren Syft-Scans gestartet
und keine Editoren, Browser oder Erweiterungen ausgeführt.

- **VS Code**, Insiders, Code OSS, Cursor und Windsurf, einschließlich der jeweiligen
  unterstützten `.vscode-server`-/`.cursor-server`-/`.windsurf-server`-Verzeichnisse:
  `extensions/*/package.json`.
- **JetBrains**: Plugin-Deskriptoren in `META-INF/plugin.xml` und Plugin-JARs unter
  `~/.local/share/JetBrains/*/plugins` bzw.
  `~/Library/Application Support/JetBrains/*/plugins`.
- **Chrome, Chromium, Brave, Edge und Vivaldi**: `manifest.json` in den Erweiterungsverzeichnissen
  aller Profile unter den üblichen Konfigurationsverzeichnissen. Für Chromium/Chrome werden
  außerdem ausgewählte Snap-/Flatpak-Standardpfade berücksichtigt.
- **Firefox**: entpackte Erweiterungen und XPI-Archive in den Profilverzeichnissen;
  unter Linux einschließlich der Snap-/Flatpak-Standardpfade.

Bei Ausführung als root werden Benutzer-Homes aus der Betriebssystem-Benutzerdatenbank
ermittelt; ohne root wird nur das eigene Home berücksichtigt. Eine explizite Auswahl ist möglich:

```json
"scan_extensions": true,
"extension_homes": ["/home/alice", "/home/bob"]
```

Auf macOS entsprechend `/Users/alice` verwenden. Homes müssen lesbar sein; macOS-Datenschutzrechte
können den Zugriff zusätzlich begrenzen. Abweichende Editor-/Browser-Profilpfade, Safari-Erweiterungen
und andere IDEs sind derzeit nicht abgedeckt. Inventarisiert werden vorhandene Installationsdateien,
auch deaktivierte Erweiterungen und noch vorhandene ältere Versionen; der Aktivierungszustand wird
nicht ermittelt. Fehlerhafte oder nicht lesbare Metadaten erzeugen eine Warnung ohne Benutzerpfade.

Die Identität besteht aus Ökosystem, technischer Erweiterungs-ID und Version. Gleiche Erweiterungen
in mehreren Benutzerkonten, Profilen oder Editoren werden einmal übertragen; ihre Fundorte werden
zusammengeführt. Verschiedene Versionen bleiben getrennt. Ein Syft-Paketeintrag desselben Manifests
bzw. Plugin-JARs wird anhand von Fundort und Version mit der Erweiterung zusammengeführt;
enthaltene npm-/Java-Bibliotheken und bekannte Abhängigkeitsbeziehungen bleiben erhalten.
Abhängigkeiten innerhalb von Erweiterungen werden nur erfasst, soweit die Syft-Scan-Wurzeln sie
abdecken. Die generischen PURLs kennzeichnen Erweiterungen eindeutig, garantieren aber kein
CVE-Matching in Dependency-Track.

Es werden nur technische ID, Version, Ökosystem, Fundort und gegebenenfalls eine kurze Lizenzangabe
ausgelesen. Beschreibungen, Berechtigungen, Browser-Historie, Einstellungen und Erweiterungscode
werden nicht übertragen. Absolute Fundorte können wie bei Syft Benutzernamen enthalten.
Für reine Image-Scans `roots: []` und `scan_extensions: false` setzen.

Manifestformate: [VS Code](https://code.visualstudio.com/api/references/extension-manifest),
[JetBrains](https://plugins.jetbrains.com/docs/intellij/plugin-configuration-file.html),
[Chromium](https://developer.chrome.com/docs/extensions/reference/manifest),
[Firefox](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json).

Es werden Komponenten-Typ, Paketname/-gruppe, Version, PURL/CPE, Paketpfade sowie erkannte
Lizenz-IDs, kurze Lizenznamen und SPDX-Ausdrücke behalten. Vollständige Lizenztexte und
Lizenzgeber-Metadaten werden nicht übertragen. Details: [licenses.md](../reference/licenses.md).
Dateikomponenten, Descriptions, Autoren, Syft-Metadaten und Inhalte werden entfernt. PURL/CPE
beschreiben Paketkoordinaten und Herkunft für das Matching. Absolute Paketpfade können bei
Home-Verzeichnissen personenbezogene Namen enthalten; Scan-Wurzeln entsprechend abstimmen.
Syft liest zur Erkennung lokale Dateien; die bereinigte SBOM überträgt deren Inhalte nicht.
Raw-SBOMs liegen nur im privaten temporären Verzeichnis und werden auch bei Fehlern entfernt.
Ein Stromausfall/SIGKILL kann temporäre Dateien hinterlassen; systemeigene TMP-Bereinigung aktiv halten.

Der Upload nutzt begrenzte Wiederholungen für temporäre HTTP-/Netzwerkfehler, prüft TLS und
wartet auf den DTrack-Verarbeitungstoken. Das bestätigt den abgeschlossenen BOM-Import;
das anschließende Schwachstellen-Matching kann länger dauern. Proxy- und CA-Einstellungen
über die Python-Standardumgebung (`HTTPS_PROXY`, `SSL_CERT_FILE`) verteilen. Keine TLS-Prüfung deaktivieren.

Linux aktivieren:

```sh
sudo systemctl enable --now patchwatch-agent.timer
systemctl list-timers patchwatch-agent.timer
journalctl -u patchwatch-agent.service
```

Der persistente tägliche Timer startet ab 02:00 mit bis zu zwei Stunden Zufallsverzögerung.
Der Dienst läuft für Systeminventar als root, mit `nice`, Idle-I/O und systemd-Härtung.
Die Registry-Anmeldung für optionale private Images muss dem Dienstkonto zur Verfügung stehen.

macOS aktivieren:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/eu.patchwatch.agent.plist
sudo launchctl kickstart system/eu.patchwatch.agent
```

Der LaunchDaemon läuft beim Laden und täglich um 03:00. Logrotation für
`/var/log/patchwatch-agent.log` über die vorhandene MDM-/newsyslog-Konfiguration einrichten.
Rollout per Ansible/MDM: Paket installieren, Konfiguration und Schlüssel mit restriktiven Rechten
verteilen, einmaliger Testlauf, anschließend Zeitplan aktivieren. Keine Agenten auf fremden
Rechnern werden durch das zentrale Deployment automatisch installiert.
