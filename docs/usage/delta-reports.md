# Delta-Berichte: Änderungen gegenüber der Vorversion

Der Delta-Bericht vergleicht eine Projektversion mit ihrem Vorgänger und zeigt, was sich an
**Schwachstellen**, **Lizenzen**, **Policy-Verstößen** und **Komponenten** geändert hat. Dependency-Track
bietet das nicht von selbst: Jede Version ist dort ein eigenes Projekt, und die eingebauten Benachrichtigungen
melden einzelne Ereignisse, keinen Vergleich zweier Versionen.

Der Bericht entsteht

- automatisch im Job `patchwatch-sbom` des [CI-Templates](ci-integration.md), direkt nach dem Upload, oder
- von Hand bzw. per Cron über `python -m patchwatch.ci.delta`.

Ausgabe: `patchwatch-delta.md` (lesbar), `patchwatch-delta.json` (maschinenlesbar), das Job-Log und optional
Webhook (Slack, Mattermost) sowie E-Mail.

Für Berichte direkt im Merge Request gibt es die optionale [MR-Feedback-Schleife](mr-feedback.md).
Sie vergleicht den MR-Commit mit einem exakten Zielbranch-Commit über separate SBOM-Artefakte.

## Was verglichen wird

| Bereich | Neu | Behoben / entfallen | Hinweise |
|---|---|---|---|
| Schwachstellen | Kennung + Komponente nur in der neuen Version | nur in der alten Version | Eine Schwachstelle, die ein Komponenten-Update überlebt, gilt als *unverändert*. Befunde mit Analysestatus `not_affected`, `false_positive` oder `resolved` zählen nicht. |
| Policy-Verstöße | Regel + Komponente nur neu | nur alt | Nur nicht unterdrückte Verstöße, getrennt nach LICENSE/SECURITY und WARN/FAIL. |
| Lizenzen | neue Lizenz-IDs im Projekt, geänderte Lizenz einer Komponente, Komponenten ohne Lizenzangabe | – | Eine Änderung ist ein Anlass zur Prüfung, keine rechtliche Bewertung (siehe [Richtlinien](../configuration/policies.md)). |
| Komponenten | hinzugefügt | entfernt, Versionswechsel | Komponenten werden über ihre Paket-URL ohne Version identifiziert. |

Auszug eines Berichts:

```
# PatchWatch delta: team/app v1.4.0
Compared with **v1.3.0**. Components: 212 → 215.

| | New | Fixed / resolved | Unchanged |
| Vulnerabilities | 2 | 5 | 14 |
| Policy violations | 1 | 0 | 3 |
...
## New vulnerabilities
- **CRITICAL** CVE-2026-1234 in pkg:npm/foo
```

## Welche Version ist der Vorgänger?

1. `PATCHWATCH_DELTA_BASELINE` (Input `delta_baseline`), falls gesetzt.
2. Bei Tags (`v1.4.0`): die nächstniedrigere Release-Version, **numerisch** sortiert (`v1.10.0` liegt über `v1.9.0`).
   Ein erneuter Lauf einer alten Pipeline wird deshalb nie mit einer neueren Version verglichen.
3. Beim Default-Branch (`main`): das höchste vorhandene Release.
4. Versionen von MRs (`mr-<IID>`, `base-…`) und Feature-Branches (Tags `scan-purpose:…`) sind nie
   automatische Vorgänger; nur `PATCHWATCH_DELTA_BASELINE` kann sie ausdrücklich wählen. Der
   MR-Bericht vergleicht stattdessen mit der Version des jeweiligen Zielbranches.
5. Gibt es keinen Vorgänger (erstes Release), steht im Bericht „nothing to compare with yet“. Es wird nichts versendet.

Die Auswahl der Vergleichsversion ist unabhängig vom Latest-Häkchen: Auch das als Latest markierte
Release bleibt eine Vergleichsbasis für den Default-Branch.

Der Default-Branch wird bei jedem Lauf überschrieben. Ein Vergleich „main von gestern gegen main von heute“ ist
daher nicht möglich; dafür sind Release-Tags da.

## Einrichtung in der CI

**Voraussetzung:** Der Lese-Schlüssel `PATCHWATCH_READ_KEY` (Team `inventory-monitor`, siehe
[CI-Integration, 1.1](ci-integration.md)). Ohne ihn läuft kein Delta-Bericht. Die Rechte
`VIEW_PORTFOLIO`, `VIEW_POLICY_VIOLATION` und (seit Dependency-Track 5) `VIEW_VULNERABILITY` genügen; die
Schwachstellen kommen aus dem BOM-Export (Variante `withVulnerabilities`, die in v5 `VIEW_VULNERABILITY`
verlangt), nicht aus der Findings-Liste.

Nach dem Einbinden des Templates ist der Bericht **standardmäßig aktiv**. Inputs:

| Input | Standard | Bedeutung |
|---|---|---|
| `delta` | `true` | Delta-Bericht erzeugen |
| `delta_baseline` | leer | Feste Vergleichsversion statt automatischer Vorversion |
| `delta_notify` | `relevant` | `relevant`: nur bei neuen Schwachstellen/Verstößen oder Lizenzänderungen; `always`; `never` |

```yaml
include:
  - project: 'platform/patchwatch'
    ref: v1
    file: 'ci-templates/sbom.yml'
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      delta_notify: always
```

Der Bericht ist rein informativ: Schlägt er fehl (z. B. fehlende Rechte), meldet der Job „Delta report skipped“,
und die Pipeline läuft weiter. Ein Gate gegen *neue* Findings gibt es bewusst nicht; `fail_on` prüft weiter den
gesamten Bestand der Version.

### Versand konfigurieren

Zugangsdaten gehören als **masked/protected** CI-Variablen auf Gruppenebene, nie in die `.gitlab-ci.yml`.

| Variable | Zweck |
|---|---|
| `PATCHWATCH_DELTA_WEBHOOK` | HTTPS-URL eines Slack- oder Mattermost-Incoming-Webhooks. Gesendet wird `{"text": "<Markdown>"}`. HTTP wird abgelehnt. |
| `PATCHWATCH_DELTA_SMTP_HOST` | SMTP-Server; aktiviert den E-Mail-Versand zusammen mit `…_MAIL_TO` |
| `PATCHWATCH_DELTA_SMTP_PORT` | Standard `587` (STARTTLS); `465` verwendet implizites TLS. Unverschlüsselter Versand ist nicht vorgesehen. |
| `PATCHWATCH_DELTA_SMTP_USER` / `PATCHWATCH_DELTA_SMTP_PASSWORD` | Anmeldung, optional. Das Passwort auch als `…_PASSWORD_FILE` |
| `PATCHWATCH_DELTA_MAIL_FROM` | Absender, Standard `patchwatch@<smtp-host>` |
| `PATCHWATCH_DELTA_MAIL_TO` | Empfänger, durch Komma getrennt |

Webhook und E-Mail sind unabhängig voneinander. Ein fehlgeschlagener Versand erscheint im Log (ohne URL
und Zugangsdaten) und bricht den Job nicht ab. Für Teams oder Systeme mit anderem Nachrichtenformat den
JSON-Bericht aus dem Artefakt weiterverarbeiten.

Weitere Variablen:

| Variable | Standard | Bedeutung |
|---|---|---|
| `PATCHWATCH_DELTA_WAIT` | `300` | Sekunden, die der Job auf die Schwachstellenanalyse wartet |
| `PATCHWATCH_DELTA_DIR` | Projektverzeichnis | Zielordner der Berichtsdateien |

Dependency-Track analysiert Schwachstellen **nach** dem BOM-Import. Der Job liest die neue Version deshalb
alle 20 Sekunden erneut, bis zwei Lesungen übereinstimmen oder das Wartebudget
`PATCHWATCH_DELTA_WAIT` erreicht ist. Zwei gleiche Lesungen sind eine stabilisierte Momentaufnahme,
kein Nachweis abgeschlossener Analyzer; auch ein zunächst leeres Ergebnis kann stabil erscheinen.
Ohne Stabilisierung enthält der Bericht den Hinweis „findings may be incomplete“. Mit
`PATCHWATCH_DELTA_WAIT=0` entfällt das Warten. Diese Wartephase aktualisiert nicht die zuvor vom
CI-Gate gelesenen Policy-Verstöße (siehe [CI-Grenzen](ci-integration.md#4-grenzen-und-hinweise)).

## Von Hand oder per Cron

```sh
DT_URL=https://patchwatch.example.org \
DT_API_KEY_FILE=/sicherer/pfad/monitor_key \
  python3 -m patchwatch.ci.delta --project team/app --version v1.4.0 --output-dir /tmp/delta
```

| Option | Bedeutung |
|---|---|
| `--project` | DTrack-Projektname, bei Monorepos `gruppe/projekt/komponente` |
| `--version` | zu berichtende Version |
| `--baseline` | Vergleichsversion; ohne Angabe die automatische Vorversion |
| `--output-dir` | Ordner für `patchwatch-delta.md` und `.json` (Standard `.`) |
| `--wait` | Sekunden Wartezeit auf die Schwachstellenanalyse (Standard `0`) |

Versand und Modus werden über dieselben `PATCHWATCH_DELTA_*`-Variablen gesteuert. Fehler liefern Exit-Code 1.
Das Kommando steht nach der Installation auch als `patchwatch-delta` zur Verfügung.

Vergleich zweier beliebiger Versionen ohne Versand:

```sh
PATCHWATCH_DELTA_NOTIFY=never python3 -m patchwatch.ci.delta --project team/app --version v1.4.0 --baseline v1.2.0
```

## Grenzen

- Der Bericht zeigt nur, was Dependency-Track kennt. Fehlt ein Paket im SBOM, fehlt es auch im Vergleich.
  Der Bericht ist eine Momentaufnahme beim Pipeline-Lauf. Schwachstellen, die erst später zu einer
  bereits veröffentlichten Version bekannt werden, meldet er nicht; dafür sind die Benachrichtigungen der
  [Bridge](../configuration/alerting.md) da. Ein neuer Bericht entsteht beim nächsten Lauf oder per `patchwatch.ci.delta`.
- Unterdrückte Befunde sind nur über ihren Analysestatus erkennbar (siehe Tabelle oben).
- Berichte enthalten Komponentennamen und Schwachstellen-IDs. Wie ein internes Inventar behandeln und nur an
  vertrauenswürdige Kanäle senden. Die Artefakte laufen nach einer Woche ab.
- Pro Abschnitt zeigt der Markdown-Bericht höchstens 40 Zeilen; vollständig ist das JSON.
