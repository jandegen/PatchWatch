# Schnellstart

Dieser Ablauf startet Patchwatch lokal mit Docker Compose. Voraussetzung sind
Docker mit Compose v2+, Python ≥3.12, ungefähr 7 GiB freier Arbeitsspeicher und
ausreichend Speicher für Datenbank und Schwachstellendaten. Ein Checkout des
Repositorys muss vorliegen. Für dieses lokale Beispiel sind weder Kubernetes
noch GitLab, eine eigene Domain oder Keycloak erforderlich.

## Stack starten und initialisieren

Im Wurzelverzeichnis des Checkouts:

```sh
python3 scripts/init-compose.py
docker compose up -d --build --wait --wait-timeout 600
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
```

Öffnen: `http://localhost:8080`, Benutzer `admin`, Passwort aus
`.secrets/admin_password`. Die Einrichtung ersetzt das initiale Standardpasswort,
legt technische Teams und Schlüssel an und konfiguriert Quellen und Richtlinien.
Der erste Datenabgleich kann länger dauern als der Start der Container.
Der HTTP-Port ist für dieses Beispiel nur an Loopback gebunden.

## Erstes Inventar erfassen

Auf einem Linux- oder macOS-Rechner Python und Syft installieren und die
[Agent-Anleitung](usage/agent.md) befolgen. Für einen Agenten auf einem anderen
Rechner zunächst [HTTPS](installation/compose.md#https-für-entfernte-agenten)
einrichten; lokale HTTP-Ausnahmen nicht auf entfernte Geräte übertragen.
Als Alternative ein Repository über die [GitLab-CI-Integration](usage/ci-integration.md)
anbinden. Ein GitLab-Projekt und ein eigenes veröffentlichtes CI-Image sind dafür erforderlich;
die [Compose-Einrichtung für CI](usage/ci-integration.md#14-ci-mit-einem-compose-server-ohne-kubernetes)
beschreibt den Ablauf ohne Kubernetes.

## Für den regulären Betrieb

- [Alerting-Ziele](configuration/alerting.md) konfigurieren; die initiale Konfiguration verschickt keine Meldungen.
- [Backups und Monitoring](operations/index.md) einrichten und einen Restore prüfen.
- Bei mehreren Benutzern [OIDC-Gruppen und Rechte](configuration/oidc.md) konfigurieren.
- Für Kubernetes mit der [Installationsanleitung](installation/kubernetes.md) und den [Umgebungsparametern](installation/customization.md) fortfahren.

`docker compose down` stoppt die Dienste und erhält die Volumes. `down -v` entfernt
die gespeicherten Daten. Weitere Themen stehen in der [Dokumentationsübersicht](README.md).
