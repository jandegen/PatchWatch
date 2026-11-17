# Lizenz- und Security-Richtlinien

## Aktive Grundregeln

[patchwatch/default-policies.json](../../patchwatch/default-policies.json) ist die versionierte
Quelle der automatisch verwalteten Regeln. Kubernetes-CI/CD und der Compose-Setup-Befehl
wenden dieselbe Konfiguration an.

| Regel | Auslöser | Ergebnis | Geltungsbereich |
|---|---|---|---|
| Patchwatch severity High or Critical | bekannte Schwachstelle mit HIGH oder CRITICAL | FAIL | `managed-by:patchwatch` |
| Patchwatch unresolved license review | Lizenz fehlt oder lässt sich nicht auflösen | WARN | `managed-by:patchwatch` |
| Patchwatch EPSS at least 10 percent | EPSS ≥ 0,1 | WARN | `managed-by:patchwatch` |
| Patchwatch distribution license approval | keine Lizenzoption aus der Baseline-Gruppe | WARN | `policy-profile:distribution` |
| Patchwatch blocked xz upstream releases | xz/liblzma-Upstream 5.6.0 oder 5.6.1 gemäß Paketkoordinaten | FAIL | `managed-by:patchwatch` |
| Patchwatch direct dependency major version lag | direkte Abhängigkeit mehr als eine Major-Version zurück | WARN | `source:gitlab-ci` |


`WARN` verlangt eine Prüfung; es ist keine pauschale Ablehnung der Software.
Insbesondere gibt es keine automatisch erfundene GPL-/AGPL-Sperre für Entwickler-Rechner.
Eine bekannte SPDX-Lizenz ohne Warnung ist noch keine rechtliche Freigabe. Pflichten wie
Attribution, Lizenztexte, Quellcodeangebote und Weitergabe von Änderungen benötigen eine
Bewertung des konkreten Einsatzes und der Distribution.

Die Security-Policy gilt jetzt ebenfalls über das Verwaltungs-Tag. Andere Projekte erhalten
keine Patchwatch-Regeln allein dadurch, dass sie auf derselben DTrack-Instanz liegen.
Mehrere Tags einer Policy erweitern den Geltungsbereich: Sie sind Alternativen, keine
UND-Verknüpfung. Für ein eigenes Profil z. B. ausschließlich `policy-profile:distribution`
verwenden. Die Kombination mit `managed-by:patchwatch` würde auch alle anderen verwalteten
Projekte einschließen. Tags gemäß [Inventar-Anleitung](../usage/inventory.md) über die Registrierung
pflegen; der Upload-Schlüssel besitzt absichtlich keine Berechtigung zum Ändern der Tags.

## Schwellen, Profile und Datenabdeckung

EPSS verwendet die Wahrscheinlichkeit `0.1` (10 %), nicht das Perzentil und nicht die Zahl 10.
Der native EPSS-Feed wird beim Setup aktiviert. Fehlende EPSS-Werte erzeugen keine native
EPSS-Verletzung und dürfen nicht als Nullrisiko verstanden werden. Die FIRST-Abfrage der
Bridge ist ein eigener Datenpfad und ersetzt den DTrack-Feed nicht.

Die Lizenzgruppe `Patchwatch distribution baseline` wird aus
[default-license-groups.json](../../patchwatch/default-license-groups.json) vollständig abgeglichen:
0BSD, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, ISC, MIT, PostgreSQL, Python-2.0 und Zlib.
Sie ist eine anfängliche Prüfliste, keine Bestätigung erfüllter Lizenzpflichten. Nicht
enthaltene Lizenzen ergeben `WARN`, keine automatische Behauptung eines Lizenzverstoßes.
Gruppenmitglieder dieser einen verwalteten Gruppe werden beim Deployment zurückgesetzt;
eigene Gruppen bleiben unberührt. Andere Allow-Listen können wie unten beschrieben im UI
verwaltet werden. Ein abweichender Dateipfad ist über `PATCHWATCH_LICENSE_GROUPS_FILE` möglich.
Alle SPDX-IDs und externen Gruppenreferenzen werden vor Änderungen aufgelöst.

CI-Uploads von Git-Tags erhalten zusätzlich `policy-profile:distribution`; Default-Branch-
Inventare und Hostprojekte erhalten dieses Profil nicht automatisch. Bei bereits angelegten
Release-Projekten den Tag administrativ ergänzen, da der Upload-Key bestehende Tags nicht
ändern darf. Ein neuer Upload allein garantiert daher keine nachträgliche Profilzuweisung.

Die Versionsabstandsregel nutzt DTracks `VERSION_DISTANCE` und betrifft nur erkannte direkte
Abhängigkeiten. Mehr als **eine** Major-Version Rückstand erzeugt `WARN`; Minor-/Patch-Abstände
werden ignoriert. Fehlende Repository-Metadaten, nicht vergleichbare Versionen und unbekannte
Abhängigkeitsgraphen können die Auswertung verhindern. Der Befund ist kein EOL-Nachweis und
berücksichtigt nicht automatisch den Supportvertrag einer älteren Major-Linie.

Die initiale Paketsperre betrifft bekannte xz-Upstream-Versionen 5.6.0/5.6.1 einschließlich
einfacher Distributions-Release-Suffixe bei `deb`, `rpm` und `generic`. Umbenannte Pakete,
abweichende Versionsschemata und Binärdateien ohne Paketkennungen können nicht vollständig
abgedeckt werden. `+really`-Rollback-Versionen werden durch das Muster nicht pauschal gesperrt.
Die Sperre verlangt Prüfung/Ersetzung der Paketversion; sie beweist keine aktive Ausnutzung.
Quelle: [Red Hat: xz supply-chain compromise](https://www.redhat.com/en/blog/urgent-security-alert-fedora-40-and-rawhide-users).

## Ergänzende Betriebsregeln

- **KEV:** Die Bridge setzt bei erstmaliger Beobachtung eines Findings als bekannt ausgenutzt
  eine persistente Prüffrist von 24 Stunden. Alle Ziele und Wiederholungen verwenden dieselbe
  Frist. Bei späterer KEV-Aufnahme beginnt sie bei deren Beobachtung. Jira erhält `duedate`
  auf Tagesebene, Beschreibung und Chat enthalten den genauen UTC-Zeitpunkt. Die CISA-Frist
  bleibt separat erhalten. Das ist eine interne Prüffrist, kein behaupteter gesetzlicher
  Termin und keine Garantie der Erledigung. Ticketstatus/Bestätigung und weitere Eskalationen
  sind im zuständigen Ticketsystem zu verwalten. Ohne Bridge-Routen findet keine externe
  Zustellung statt; bereits abgeschlossene alte Zustellungen werden nicht allein wegen
  Einführung der Frist erneut versendet.
- **SBOM-Vollständigkeit:** Leere Inventare führen in CI bereits zum Fehler; explizite
  Sammelprojekte bleiben ausgenommen. Fehlende Versionen oder Paket-URLs bei Softwarepaketen
  ergeben zusätzliche `OPERATIONAL / WARN` im CI-/Compliance-Bericht. Das ist eine ergänzende
  Prüfung außerhalb der nativen DTrack-Policy-Liste. Bei `--fail-on warn` bzw. CI `fail_on: warn`
  berücksichtigen die Gates diese Hinweise; leere gewöhnliche Inventare im Bericht sind `FAIL`.
- **Aktualität:** Die vorhandene 48-Stunden-Überwachung der Host-Uploads bleibt aktiv. Ein
  ganz fehlender Host benötigt weiterhin einen Sollbestand (`--expected-file`).

## Regeln im Repository ändern

1. Datei `patchwatch/default-policies.json` ändern. Jede Regel braucht einen eindeutigen Namen
   mit Präfix `Patchwatch `, `operator` (`ANY`/`ALL`), `violationState` (`INFO`/`WARN`/`FAIL`),
   mindestens ein `scopeTags` und mindestens eine Bedingung. Bedingungen beschreiben den
   unerwünschten Zustand: `ANY` meldet bei mindestens einer erfüllten Bedingung, `ALL` erst
   bei allen. Eine Freigabeliste wird deshalb über `IS_NOT` geprüft.
2. Lokal validieren und testen:

   ```sh
   python3 -m patchwatch.dtrack.policies --check
   python3 -m unittest discover -s tests -v
   python3 scripts/spdx.py
   python3 scripts/spdx.py --check
   ```

3. Änderung reviewen und nach `main` übernehmen. GitLab CI gleicht die Regeln nach dem
   Helm-Deployment ab. Der Deploy-Job stellt `ci/compliance-report.json` als Artefakt für eine
   Woche bereit. Der Bericht ist eine Momentaufnahme bestehender Imports; CI löst keinen
   neuen Scan sämtlicher Rechner aus. Die aktuelle Version ist nach einem erneuten Agent-Lauf
   bzw. der nächsten nativen DTrack-Auswertung zu beurteilen.
4. Nach Regeländerungen die betroffenen SBOMs erneut hochladen. Auf diesem Rechner:

   ```sh
   systemctl --user start patchwatch-agent.service
   journalctl --user -u patchwatch-agent.service -n 20 --no-pager
   ```

   Bei systemweiter Installation stattdessen `sudo systemctl start patchwatch-agent.service`.
   Erst nach abgeschlossener BOM-Verarbeitung und Policy-Auswertung Ergebnisse vergleichen.

Der Abgleich übernimmt die vollständige Definition genau der in der Datei benannten Policies:
Bedingungen, Zustand, Operator und Tag-/Projektbindungen. Zusätzliche Bedingungen oder
Scope-Änderungen im UI werden beim nächsten Abgleich überschrieben. Andere Policies bleiben
erhalten. Entfernen aus der Datei allein löscht keine bestehende Policy: Zur endgültigen
Stilllegung Definition entfernen **und** die alte Policy im UI löschen. Beim Umbenennen gilt
entsprechend: alte Policy separat entfernen. So werden fremde Regeln und deren Historie nicht
ungefragt gelöscht.

Für Compose nach einer Regeländerung nur die regulären Policies und Lizenzgruppen erneut abgleichen:

```sh
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  python3 -m patchwatch.dtrack.policies
```

Dieser Befehl aktualisiert keine abgeleiteten `Patchwatch MR …`-Regeln. Werden die
[MR-Berichte](../usage/mr-feedback.md) verwendet, auch den vollständigen Einrichtungsaufruf aus der
[Deployment-Anleitung](../installation/compose.md) erneut ausführen;
Kubernetes erledigt beides beim regulären Deployment.

Bei einem entfernten System dessen HTTPS-URL ohne `ALLOW_HTTP` verwenden. Alternativ einen
sicher abgelegten Admin-/Provisionierungs-Key über `DT_ADMIN_API_KEY_FILE` verwenden. Für
reinen Policy-Abgleich sind `POLICY_MANAGEMENT` und zum Lesen/Auflösen der Referenzen die
passenden Leserechte nötig; weder Upload-Key noch Monitor-Key dürfen Regeln schreiben.

Für einen separaten Konfigurationssatz `PATCHWATCH_POLICIES_FILE=/pfad/policies.json` setzen.
In CI muss die Datei im Checkout vorhanden und die Variable im Deploy-Job gesetzt sein.
Sie ersetzt den gesamten Standard-Konfigurationssatz. Änderungen auf dem ausführenden Rechner
allein ändern nicht die vom GitLab-Runner verwendete Datei.

## Organisationsspezifische Lizenzlisten

Zuerst klären, für welchen Einsatz die Liste gilt: intern genutztes Werkzeug, SaaS,
weitergegebenes Container-Image oder ausgeliefertes Produkt. Dann in **Administration →
License Groups** eine eigene Gruppe anlegen, z. B. `Company distribution approved`, und die
freigegebenen SPDX-Lizenzen zuordnen. Die eingebauten Copyleft-Gruppen sind Ausgangspunkte,
keine bereits beschlossene Unternehmensrichtlinie.

Beispiel einer zusätzlichen Regel mit eigenem Namen in der `policies`-Liste:

```json
{
  "name": "Patchwatch company distribution license approval",
  "operator": "ANY",
  "violationState": "FAIL",
  "scopeTags": ["policy-profile:distribution"],
  "conditions": [
    {"subject": "LICENSE_GROUP", "operator": "IS_NOT", "value": "Company distribution approved"}
  ]
}
```

`IS_NOT` bei einer Freigabegruppe meldet Komponenten, für die keine erlaubte Lizenzoption
besteht. Für eine ausdrücklich beschlossene Verbotsgruppe stattdessen `LICENSE_GROUP IS`
verwenden. `value` ist im JSON der **Gruppenname**, nicht die installationsabhängige UUID.
Die Gruppe muss vorher vorhanden sein; fehlende Referenzen brechen den Abgleich vor der
Änderung von Policies ab. Die Mitgliedschaften zusätzlicher, ausschließlich im UI gepflegter Gruppen werden vom
Abgleich nicht überschrieben; die verwaltete Baseline-Gruppe ist die oben beschriebene Ausnahme. Gruppenänderungen mit Freigabe, Datum und Begründung im
Änderungsticket dokumentieren; bei weiteren DTrack-Installationen separat nachvollziehen.

Für eine einzelne Lizenz `subject: LICENSE` und deren SPDX-ID wie `AGPL-3.0-only` verwenden.
Der Spezialwert `unresolved` steht für fehlende/nicht auflösbare Angaben. Die Implementierung
löst IDs und Gruppennamen auf die jeweilige DTrack-UUID auf. SPDX-Ausdrücke behalten ihre
Bedeutung: `MIT OR GPL-3.0-only` erlaubt eine Wahl; `MIT AND GPL-3.0-only` verlangt beide.
Keine alternative Lizenz entfernen, um eine Warnung verschwinden zu lassen.

## Im UI verwalten und Befunde bearbeiten

- **Administration → Policies:** Regel, `ANY`/`ALL`, Violation State, Bedingungen und Scope
  festlegen. Unabhängig verwaltete UI-Regeln unter eigenem Namen anlegen, der nicht in der
  JSON-Datei steht. Eine Policy ohne Projekt-/Tag-Zuordnung ist global; vor dem Einsatz den
  Scope ausdrücklich prüfen.
- **Projekt → Policy Violations:** nach LICENSE/SECURITY und WARN/FAIL filtern und betroffene
  Komponente öffnen. Lizenz aus Paket-/Upstream-Nachweisen überprüfen; falsche oder fehlende
  Metadaten vorzugsweise an der Quelle korrigieren und erneut scannen. Ein manueller
  Komponenten-Eintrag kann beim nächsten SBOM-Import ersetzt werden.
- Ausnahmen über die Analyse der konkreten Policy-Verletzung dokumentieren: Begründung,
  verantwortliche Person, Evidenz/Ticket, Einsatzkontext und Wiedervorlage. Eine Suppression
  nicht als globale Freigabe einer Lizenz verwenden. Ablauf-/Wiedervorlage extern terminieren;
  hier wird kein automatischer Ablauf von Ausnahmen implementiert.
- **Projekt → Audit Vulnerabilities:** Security-Befunde getrennt nach Betroffenheit prüfen.
  Unterdrückte Schwachstellen erzeugen laut DTrack keine Security-Policy-Verletzung.
  Ein fehlender Treffer beweist keine Abwesenheit von Schwachstellen; Scan-Wurzeln,
  Paketkoordinaten und Trivy-/Feed-Verfügbarkeit gehören zur Bewertung.

Für Policies und Gruppen `POLICY_MANAGEMENT`, für Inventarleser `VIEW_PORTFOLIO`
und für Compliance-Berichte zusätzlich `VIEW_POLICY_VIOLATION` verwenden (Delta-Berichte brauchen außerdem
`VIEW_VULNERABILITY`). Das automatisch verwaltete Team `inventory-monitor` erhält genau diese Leserechte. Schreibberechtigungen für Befundanalysen nur zuständigen Teams geben. Agenten
bekommen keine Admin-Credentials. Die bestehende Webhook-Regel berücksichtigt Policy-Verstöße;
externe Zustellung erfordert weiterhin konfigurierte Bridge-Routen.

## Bericht und optionales CI-Gate

Mit dem vorhandenen schreibgeschützten Monitor-Schlüssel:

```sh
DT_URL=https://patchwatch.example.org \
DT_API_KEY_FILE=/sicherer/pfad/monitor_key \
  python3 -m patchwatch.dtrack.compliance --output compliance-report.json
```

Der Bericht enthält je aktivem verwalteten Projekt Lizenz-Metadatenabdeckung, Lizenzkonflikte,
Graph-Kanten und die Anzahl nicht unterdrückter nativer Policy-Verletzungen nach Regel,
Kategorie und Zustand sowie ergänzende `qualityViolations` für leere Inventare und
fehlende Paketversionen/-URLs. Er enthält weder komplette SBOMs noch Installationspfade. Trotzdem als
internes Inventar behandeln. Fehler beim Lesen werden als Fehler gemeldet; fehlende Daten
werden nicht als bestanden interpretiert.

Standardmäßig ist der Bericht informativ. `--fail-on fail` liefert Exit-Code 2 für mindestens
einen nativen oder ergänzenden FAIL-Befund; `--fail-on warn` zusätzlich für WARN und
Lizenzkonflikte sowie SBOM-Metadatenwarnungen. Beide
betreffen den gesamten verwalteten Bestand, nicht nur neu eingeführte Befunde. API-/Datenfehler
liefern Exit-Code 1. Ein solches Gate erst mit festgelegtem Umgang mit bestehenden Findings in
einen Release-Prozess aufnehmen. Das Deployment des Sicherheitssystems selbst wird durch
bestehende Host-Findings nicht blockiert.

`patchwatch:license-conflict=true` kennzeichnet widersprüchliche Ausdrücke beim Zusammenführen
von Paketkopien. DTrack 4.14 hat keine Policy-Bedingung für beliebige Komponenten-Properties;
daher stehen diese Fälle im separaten Bericht und sind bei `--fail-on warn` berücksichtigt.
Die native Lizenz-Policy allein garantiert nicht die Erkennung solcher Konflikte. Auch
bekannte, aber falsche Lizenzmetadaten können ohne manuelle Prüfung unerkannt bleiben.

Quellen: [DTrack Policy Compliance](https://docs.dependencytrack.org/usage/policy-compliance/),
[DTrack License Evaluation](https://docs.dependencytrack.org/analysis-types/license/).
