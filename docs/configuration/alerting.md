# Alerting und Ticketing

Dependency-Track sendet `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY` und
`POLICY_VIOLATION` an `http://patchwatch-bridge:8080/webhook/<token>` (Compose: `bridge`).
Die API-Ersteinrichtung legt die Notification-Regel mit Tag-Filter `managed-by:patchwatch` an.
Die High-/Critical-Policy ist ebenfalls auf dieses Verwaltungs-Tag begrenzt; weitere
[Security-/Lizenzregeln](policies.md) haben eigene Scopes. Das [kanonische Tag-Schema](../usage/inventory.md) hält Erfassung und Routing konsistent.
Die Bridge ist im Cluster nur vom API-Pod erreichbar und hat keinen öffentlichen Ingress.
Dependency-Track 5 beschränkt ausgehende Verbindungen: Bridge (und Trivy) stehen deshalb ausdrücklich in
`DT_OUTBOUND_ALLOWED_DESTINATIONS` (Compose `compose.yaml`, Kubernetes `deploy/environments/dtrack.yaml`).
Eine zusätzliche, nicht-öffentliche Webhook-Adresse muss dort ergänzt werden.
Das v5-Format unterscheidet sich vom v4-Format: Gruppen heißen `GROUP_NEW_VULNERABILITY` usw. und
`policyViolation.condition` ersetzt `policyCondition`. Die Bridge akzeptiert beide Formen; die
Deduplizierungsschlüssel bleiben gleich, sodass bereits gemeldete Findings nicht erneut gemeldet werden.
Das Token ist ein mindestens 32 Zeichen langer zufälliger URL-Pfadbestandteil; Webhook-URLs
nicht protokollieren. Externen Bridge-Betrieb ausschließlich über HTTPS und eingeschränkten Zugriff erlauben.

Ziele sind bewusst zunächst leer: Für echte JIRA-/Chat-Zustellung sind die organisationsspezifischen
URLs und Zugangsdaten erforderlich. Ein leeres `routes.json` nimmt gültige Webhooks an,
legt aber keine Zustellung an. **Vor dem Agenten-Rollout Ziele konfigurieren und testen.**

Beispiel für `routes.json` (echte URLs enthalten Geheimnisse und gehören in ein Secret):

```json
[
  {
    "name": "platform-slack",
    "kind": "slack",
    "url": "https://hooks.slack.com/services/REPLACE",
    "tags": ["team:platform"]
  },
  {
    "name": "platform-jira",
    "kind": "jira",
    "url": "https://jira.example.org",
    "project": "SEC",
    "issue_type": "Task",
    "token_env": "JIRA_TOKEN",
    "tags": ["team:platform"]
  },
  {
    "name": "tools-teams",
    "kind": "teams",
    "url": "https://example.webhook.office.com/REPLACE",
    "projects": ["workstation-01"]
  }
]
```

Jede Route hat einen stabilen eindeutigen `name`. `tags` und `projects` sind optionale Filter:
Innerhalb eines Filters genügt ein Treffer; sind beide angegeben, müssen beide passen.
Ohne Filter erhält das Ziel alle Findings. Wenn die Standard-Notification keine Tags enthält,
löst die Bridge sie über die DTrack-API mit dem separaten `VIEW_PORTFOLIO`-Schlüssel auf.
Kubernetes richtet diesen Zugang automatisch ein. Die Zuordnung bleibt so auch nach einer
Teamänderung aktuell. Fehler beim Nachladen führen zu HTTP 503, nicht zum stillen Verwerfen.

Standardmäßig werden nur `HIGH` und `CRITICAL` weitergegeben (`MIN_SEVERITY`). Policy-Verstöße
haben häufig keine Vulnerability-Severity und umgehen den Severity-Filter. Das gilt auch für
Lizenz- und andere WARN-Regeln; Policy-Name und Zustand bestimmen den Befund, nicht automatisch
High/Critical. Ein Fix-Filter ist nicht implementiert:
Standard-Webhooks liefern keinen verlässlichen, einheitlichen Fix-Status. Für diesen optionalen
Ausbau müsste die Bridge weitere Ökosystem-/Repository-Daten auswerten.

## Priorisierung mit CISA KEV und EPSS

Die Bridge nutzt zwei öffentliche Quellen und fällt bei Ausfall auf die reine Severity zurück:

- **CISA KEV** (`KEV_URL`): Katalog bekannt ausgenutzter Lücken, täglich geladen und in der
  SQLite-Datenbank gespeichert. Bei Fehlern gilt der letzte Stand weiter (neuer Versuch nach einer Stunde).
- **FIRST EPSS** (`EPSS_URL`): Ausnutzungswahrscheinlichkeit je CVE, pro CVE einen Tag gecacht und
  erst bei der Zustellung abgefragt, sodass der Webhook nie darauf wartet.

`KEV_ENABLED` / `EPSS_ENABLED` (Standard `true`) schalten die Quellen ab; `EPSS_HIGH` (0,5) und
`EPSS_MEDIUM` (0,1) setzen die Schwellen. Helm: `bridge.enrichment.*`, Compose: `ENRICHMENT_ENABLED`,
`KEV_URL`, `EPSS_URL`.

Priorität je Event: KEV = `kev`; EPSS ≥ 0,5 oder `CRITICAL` = `high`; EPSS ≥ 0,1, `HIGH` oder Policy = `medium`; sonst `low`.

- KEV-Treffer umgehen `MIN_SEVERITY` und werden auch bei `MEDIUM`/`LOW` weitergegeben.
- Chat-Nachrichten erhalten `[KEV]` bzw. `(EPSS 87%)`; Jira-Tickets das Label `kev` sowie Fälligkeit,
  Ransomware-Hinweis und EPSS in der Beschreibung.
- Die Jira-Priorität wird nur gesetzt, wenn die Route ein `priority_map` enthält (Prioritätsnamen
  sind je Instanz verschieden): `"priority_map": {"kev": "Highest", "high": "High", "medium": "Medium", "low": "Low"}`.
- **Nachträgliche Aufnahme in KEV:** Nach jedem KEV-Update werden bereits zugestellte Findings geprüft.
  Betroffene Jira-Tickets (Suche per Label) erhalten Priorität, Label `kev` und einen Kommentar
  (Service-Konto braucht Bearbeiten- und Kommentarrechte); Slack/Teams bekommen eine Folgenachricht. Je Ziel einmalig.

Netzwerk: Die mitgelieferten NetworkPolicies beschränken nur Ingress, die Bridge darf also
ausgehend bereits ins Internet. Gilt im Cluster oder an der Firewall ein Egress-Default-Deny, müssen
HTTPS (443) zu `www.cisa.gov` und `api.first.org` sowie DNS freigegeben oder interne Spiegel
über `kevUrl`/`epssUrl` hinterlegt werden.

Grenzen: Abgeglichen wird die `vulnId`; GHSA-Findings ohne CVE-ID werden weder bei KEV noch bei EPSS
erkannt. Hohe EPSS-Werte allein umgehen `MIN_SEVERITY` nicht (nur KEV).

## Kubernetes konfigurieren

Nur die `routes.json`-Eigenschaft im vorhandenen Secret ersetzen; **Datenbank- und Admin-Passwort
unverändert erhalten**. Ein lokales, restriktiv gespeichertes JSON kann ohne Secret-Ausgabe gepatcht werden:

```sh
python3 - <<'PY'
import json,subprocess
from pathlib import Path
patch={'stringData': {'routes.json': Path('.secrets/routes.json').read_text()}}
subprocess.run(['kubectl','-n','patchwatch','patch','secret','patchwatch-secrets','--type=merge','--patch-file=/dev/stdin'], input=json.dumps(patch), text=True, check=True)
PY
# JIRA-Zugangsdaten zusätzlich als Secret patchwatch-integrations mit Key JIRA_TOKEN anlegen.
kubectl -n patchwatch rollout restart deployment/patchwatch-bridge
```

`token_env` bezeichnet einen Namen im Container-Environment. Das Secret `patchwatch-integrations`
wird optional als Environment eingebunden. Bei JIRA PAT genügt das Bearer-Token. Für Basic-Auth
(z. B. Jira Cloud) zusätzlich `username` mit dem Servicekonto angeben. Das Konto benötigt
Issue-Suche und Issue-Erstellung im Zielprojekt, damit das Wiederfinden per Label funktioniert.
Es wird die REST-v2-Schnittstelle mit Text-Description verwendet; Kompatibilität des konkreten
JIRA-Servers und benötigte benutzerdefinierte Pflichtfelder vor Produktivbetrieb prüfen.

## Docker Compose konfigurieren

`.secrets/routes.json` ändern und Bridge neu starten. Für Tag-Nachladen oder Jira ein lokales,
nicht eingechecktes Override `compose.integrations.yaml` verwenden:

```yaml
services:
  bridge:
    environment:
      DT_URL: http://apiserver:8080
      ALLOW_HTTP: 'true'
      DT_API_KEY_FILE: /run/secrets/monitor_key
      JIRA_TOKEN_FILE: /run/secrets/jira_token
    volumes:
      - ./.secrets/monitor_key:/run/secrets/monitor_key:ro
      - ./.secrets/jira_token:/run/secrets/jira_token:ro
```

Die in die Bridge eingebundenen Dateien müssen für UID 10001 lesbar sein; der Host-Elternordner
`.secrets` bleibt `0700`. Z. B. die betreffenden Dateien mit `chmod 444` versehen. Upload-Schlüssel
für die Rechner erhalten dagegen stets `0600`.

```sh
docker compose -f compose.yaml -f compose.integrations.yaml up -d bridge
```

Teams nutzt Adaptive Cards (Webhook/Workflow muss dieses Nachrichtenformat unterstützen),
Slack das Incoming-Webhook-Format `text`. Ziele können über `allow_http: true` HTTP für einen
lokalen Integrationstest freigeben; echte Ziele sollen HTTPS nutzen.

## Zustellung und Deduplizierung

Der Webhook antwortet erst **nach** dem Commit in SQLite mit 202. Unbekannte Eventgruppen werden
mit 202 ignoriert, ungültige relevante Payloads mit 400 und zu große Payloads mit 413 abgewiesen.
Die Outbox bleibt über Neustarts und Deployments erhalten. Für jeden Host (Projekt-UUID),
Paketkoordinate einschließlich Version, Vulnerability-/Policy-Condition-ID und Routennamen
existiert genau ein Eintrag. Wiederholte Scans und die beiden Vulnerability-Eventgruppen erzeugen
keine neuen Tickets. Eine neue Paketversion ergibt bewusst einen neuen Eintrag. Aliase zwischen
CVE und GHSA werden noch nicht quellübergreifend zusammengeführt.

Fehlgeschlagene Ziele werden einzeln mit exponentiellem Backoff bis maximal einer Stunde Abstand
unbegrenzt wiederholt. Erfolgreiche andere Ziele werden nicht erneut gesendet. Für Jira sucht die
Bridge vor jeder Erstellung nach `patchwatch-<finding-hash>` als Label, um auch einen zuvor
angenommenen Request nach Timeout zu erkennen. Chat-Webhooks bieten keine atomare
Idempotenz; ein Prozessabbruch nach Annahme beim Ziel und vor dem lokalen Commit kann eine
Nachricht wiederholen. Jira-Suchindexverzögerungen können ebenfalls Duplikate verursachen.
Es wird keine Exactly-once-Zustellung versprochen.

Die Bridge läuft mit genau einer Replica und `Recreate`, da SQLite und die Zustelllogik einen
Worker voraussetzen. Routen beim Umbenennen als neue Ziele behandeln; entfernte Routen mit
noch offenen Zustellungen weiter beobachten. Metriken auf `/metrics` zeigen offene Zustellungen
und Alter der ältesten Meldung. Auf persistierende Retries alarmieren. Bei leerer Route-Liste
kann keine Zustellung erwartet werden. Ein Testbutton in Dependency-Track sendet eine generische
Testnotification; ein echter Test-Finding-Webhook ist für einen vollständigen Ende-zu-Ende-Test nötig.


KEV-Findings erhalten eine feste interne **24-Stunden-Prüffrist** ab erster Beobachtung als
KEV. Die Frist ist pro Finding in SQLite gespeichert und verschiebt sich nicht bei Retries,
Neustarts oder mehreren Zielen. Jira erhält ein Fälligkeitsdatum; der genaue UTC-Zeitpunkt
steht zusätzlich im Text und in Chat-Meldungen. Die CISA-Abhilfefrist bleibt davon getrennt.
Ein Bearbeitungsabschluss wird von der Bridge nicht erfasst; ihn und eventuelle weitere
Eskalationen verwaltet das Ticketsystem. Siehe [Policy-Verwaltung](policies.md).
