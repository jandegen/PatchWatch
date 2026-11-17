# Installation

| Betriebsart | Geeignet für | Voraussetzungen |
|---|---|---|
| [Docker Compose](compose.md) | Lokale Erprobung oder einen einzelnen Server | Docker/Compose, Python für Einrichtung, persistenter Speicher; HTTPS für entfernte Agenten |
| [Kubernetes mit Helmfile](kubernetes.md) | Betrieb in einem eigenen Cluster | Kubernetes, Helm/Helmfile, Ingress-Controller, StorageClass und TLS; optional GitLab CI |

Beide Varianten enthalten PostgreSQL, Dependency-Track, Frontend, Bridge und
Trivy-Server. Backups und Monitoring müssen für den regulären Betrieb eingerichtet
werden. Die Docker-Compose-Variante benötigt keine GitLab-Instanz.
Der Kubernetes-Deploy kann manuell über dieselben Skripte wie in CI erfolgen.

## Reihenfolge für eine neue Installation

1. [Lokalen Schnellstart](../getting-started.md) zum Kennenlernen durchführen oder direkt die Betriebsart wählen.
2. [Eigene Umgebungsparameter](customization.md) festlegen und die benötigten Images bauen/veröffentlichen.
3. Den Stack gemäß Compose- oder Kubernetes-Anleitung starten und initialisieren.
4. [Benutzerzugriff / Keycloak](../configuration/oidc.md), [Richtlinien](../configuration/policies.md) und [Meldeziele](../configuration/alerting.md) einrichten.
5. [Agenten](../usage/agent.md) oder [CI-Projekte](../usage/ci-integration.md) anbinden und einen Import prüfen.
6. [Backups, Restore und Monitoring](../operations/index.md) testen.

## Bestehende Installationen

Die mitgelieferten Versionen von Dependency-Track und Helm-Chart sind im Repository
festgelegt; sie sind keine Empfehlung, ungeprüft auf eine neuere Version zu wechseln.
Vor Änderungen Backups und Upgrade-Hinweise prüfen.
