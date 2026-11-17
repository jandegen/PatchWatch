# Installation mit Docker Compose

Alle Befehle im Repository-Wurzelverzeichnis ausführen. Für eine lokale Erprobung siehe [Schnellstart](../getting-started.md).


Voraussetzungen: Docker mit Compose v2+, Python ≥3.12 für Hilfsskripte und etwa 7 GiB freier RAM.

```sh
python3 scripts/init-compose.py   # erzeugt auch .secrets/dt_kek (Key-Encryption-Key von Dependency-Track 5)
docker compose up -d --build --wait --wait-timeout 600
# http://localhost:8080
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
# Tägliche PostgreSQL-Backups zusätzlich starten:
docker compose --profile operations up -d backup
```

Die Datei `.env` wird aus `.env.example` erzeugt. Nur das Gateway bindet standardmäßig einen
Host-Port, und zwar `127.0.0.1:8080`. API, PostgreSQL und Bridge sind ausschließlich im privaten
Compose-Netz erreichbar. Die API-URL im Frontend muss vom **Browser** erreichbar sein.
Die `.env` wird von Compose gelesen, aber nicht automatisch von
`python3 -m patchwatch.dtrack.setup`. Bei einer eigenen öffentlichen URL auch dessen
Parameter `PUBLIC_URL` im Einrichtungsaufruf auf die eigene URL setzen; `DT_URL`
kann für die lokale Einrichtung weiterhin auf Loopback zeigen.

Named Volumes persistieren Datenbank, Dependency-Track-Dateispeicher und Bridge-Outbox.
Der Key-Encryption-Key `.secrets/dt_kek` verschlüsselt die in Dependency-Track gespeicherten Zugangsdaten und
gehört in jede Sicherung; ein anderer Schlüssel verhindert den Start des API-Servers.
`docker compose down` behält Volumes; `down -v` löscht sie unwiederbringlich.

`.secrets` hat Modus `0700`. Die hineingenerierten Server-Secret-Dateien sind innerhalb dieses
Verzeichnisses lesbar, damit verschiedene Container-UIDs sie als Compose-Bind-Mount verwenden
können. Host-Upload-Schlüssel bleiben `0600`. Passwörter niemals aus `.env` ins Repository übernehmen.

## HTTPS für entfernte Agenten

Ein gültiges Zertifikat mit passendem SAN und den privaten Schlüssel als `.secrets/tls.crt` und
`.secrets/tls.key` ablegen. Die Zertifikatskette muss von Agent und Browser vertraut werden.

```dotenv
PUBLIC_URL=https://patchwatch.example.org:8443
HTTPS_BIND_ADDRESS=0.0.0.0
HTTPS_PORT=8443
```

```sh
docker compose --profile tls up -d --build --wait --wait-timeout 600
```

Der zusätzliche TLS-Gateway terminiert HTTPS. Der HTTP-Port bleibt durch den getrennten
Parameter `HTTP_BIND_ADDRESS=127.0.0.1` auf Loopback begrenzt. Alternativ einen vorhandenen
TLS-Reverse-Proxy vor das Loopback-Gateway setzen. Zugang zum Inventar nur über internes
Netz/VPN vorsehen. Agenten lehnen HTTP standardmäßig ab; `ALLOW_HTTP=true` ist für die
internen Setup-/Monitor-Aufrufe.

Wenn HTTPS nach dem lokalen Schnellstart eingerichtet wird, die Einrichtung mit
der neuen öffentlichen URL erneut ausführen. Der Aufruf läuft auf dem Compose-Host;
die internen Integrations-URLs bleiben Compose-Dienstnamen:

```sh
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=https://patchwatch.example.org:8443 \
  python3 -m patchwatch.dtrack.setup
```

Bei abweichendem HTTP-Port `DT_URL` entsprechend ändern. Für die erste Einrichtung
zusätzlich `--initial-admin` verwenden. Bei geändertem `SECRETS_DIR` alle
Secret-Pfade und `--output` anpassen: Das Python-Setup liest die Compose-`.env`
nicht ein. Der TLS-Schlüssel und das Zertifikat müssen für den Benutzer des
TLS-Gateway-Containers lesbar sein; das umgebende Secret-Verzeichnis bleibt `0700`.

## Agenten und GitLab CI anbinden

Die erfolgreiche Einrichtung erzeugt folgende Dateien im Ausgabeordner
(standardmäßig `.secrets`):

| Datei | Verwendung |
|---|---|
| `upload_key` | Host-Agent; sicher auf die Geräte verteilen, dort Modus `0600` |
| `ci_upload_key` | Geschützte, maskierte GitLab-Variable `PATCHWATCH_UPLOAD_KEY` |
| `monitor_key` | Server-Monitor; optional geschützte CI-Lesezugriffe |
| `versions_key` | Ausschließlich serverseitiger Abgleich der Projektversionen |

Agenten und CI-Jobs verwenden die von außen erreichbare HTTPS-Basis-URL aus
`PUBLIC_URL`, ohne `/api`. `localhost` im CI-Job bezeichnet den Job-Container,
nicht den Compose-Server. Nur das Gateway muss für sie erreichbar sein.

1. [Agent einrichten und ersten lokalen oder entfernten Upload prüfen](../usage/agent.md#verbindung-zu-einem-compose-server).
2. Für GitLab [CI-Image ohne Kubernetes veröffentlichen und Runner anbinden](../usage/ci-integration.md#14-ci-mit-einem-compose-server-ohne-kubernetes).
3. Nach erfolgreicher Einrichtung den Versionsabgleich starten:

   ```sh
   docker compose --profile operations up -d versions
   docker compose logs --tail=50 versions
   ```

Das gesamte Profil `operations` erst aktivieren, wenn `versions_key` vorhanden ist.
Backup allein kann wie oben mit explizitem Dienstnamen gestartet werden.

## Integrationen und Monitoring

Ziele in `.secrets/routes.json` konfigurieren, siehe [alerting.md](../configuration/alerting.md). Danach
`docker compose restart bridge`. Für Tag-Auflösung den Leseschlüssel als zusätzliche
Datei in die Bridge mounten; ein Beispiel steht ebenfalls dort.

```sh
docker compose --profile monitoring run --rm monitor
```

Dieser Aufruf prüft das Inventar einmal und liefert Exitcode 1 bei veralteten Hosts und 2 bei
API-/Konfigurationsfehlern. Für regelmäßige Compose-Prüfungen einen Host-Timer/Cronjob verwenden;
fehlgeschlagene Aufrufe in das bestehende Monitoring übernehmen.

Compose-Restore, Secret-Rotation und Monitoring: [operations.md](../operations/index.md).
