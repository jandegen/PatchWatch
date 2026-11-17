# Betrieb

## Status und Monitoring

```sh
kubectl -n patchwatch get pods,pvc,ingress,cronjobs
kubectl -n patchwatch logs deployment/patchwatch-bridge
kubectl -n patchwatch logs deployment/dtrack-api-server
kubectl -n patchwatch create job --from=cronjob/patchwatch-monitor patchwatch-monitor-manual
```

Der tägliche Monitor läuft um 07:00 UTC und schlägt fehl, wenn ein aktives, über
`managed-by:patchwatch` und `asset-type:workstation` markiertes Hostprojekt mit Version `current` seit 48 Stunden keine SBOM geliefert hat oder noch nie importiert wurde.
CronJob-/Job-Fehler in das vorhandene Kubernetes-Monitoring aufnehmen (z. B.
`kube_job_status_failed`); das Projekt installiert keinen zweiten Monitoring-Stack.
Der Monitor selbst benötigt nur `VIEW_PORTFOLIO`. Das gemeinsam für Monitoring, Compliance- und
Delta-Berichte verwendete Team `inventory-monitor` besitzt zusätzlich `VIEW_POLICY_VIOLATION` und
`VIEW_VULNERABILITY` (Dependency-Track 5 verlangt sie für den BOM-Export mit Schwachstellen).

Noch nie angelegte Hosts können ohne Sollbestand nicht erkannt werden. Dafür unterstützt
`python -m patchwatch.dtrack.monitor --expected-file expected-hosts.json` eine Liste der erwarteten
**Projektnamen**, z. B. `["workstation-01"]`. Diese Datei per eigenem Secret/ConfigMap in den
Monitor mounten und `EXPECTED_HOSTS_FILE` setzen. Exitcodes: 0 aktuell, 1 veraltet/fehlend oder inkonsistente Portfolio-Zähler, 2 API-Fehler.
Nach 75 Minuten Aggregations-Toleranz werden leere Portfolio-Zähler trotz vorhandenem
Hostbestand als Fehler erkannt. Details: [inventory.md](../usage/inventory.md).

Bridge: `/health` prüft die SQLite-Erreichbarkeit, `/metrics` liefert
`patchwatch_deliveries_total`, `patchwatch_deliveries_pending`,
`patchwatch_oldest_pending_seconds`. Der Endpoint ist intern; zum Debuggen `kubectl port-forward
service/patchwatch-bridge 18082:8080` verwenden. Einen Prometheus-Scrape bei Bedarf explizit per
NetworkPolicy erlauben. Auf offene Zustellungen älter als 15 Minuten alarmieren.
Die Zahl erfolgreicher Zustellungen ist kein Beleg für einen vollständigen Host-Sollbestand.

## Backups und Wiederherstellung

Kubernetes erzeugt täglich um 01:15 UTC ein geprüftes PostgreSQL-Custom-Dump auf eigenem
PVC `patchwatch-backup`. Erfolgreiche Dumps werden nach 14 Tagen entfernt. Ein fehlgeschlagener
Dump wird nie als fertig benannt; Job-Fehler lösen über das bestehende Monitoring Alarm aus.
Vor dem Dump wartet der Job begrenzt auf TCP-Erreichbarkeit, damit das kurze Anwenden von
NetworkPolicies bei neuen Pods keine sofortigen Fehlversuche verursacht.
Compose startet Backups mit Profil `operations`, sofort und danach alle 24 Stunden in `./backups`.
Einzelbackup manuell ausführen:

```sh
docker compose --profile operations run --rm --entrypoint /bin/sh backup /scripts/backup.sh
kubectl -n patchwatch create job --from=cronjob/patchwatch-backup patchwatch-backup-manual
```

**Ein Datenbank-Dump allein reicht nicht für Disaster Recovery.** Zusätzlich sichern:

- den Key-Encryption-Key von Dependency-Track 5 (Compose `.secrets/dt_kek`, Kubernetes Secret
  `patchwatch-dtrack-kek`): ohne ihn sind die im Secret-Manager gespeicherten Zugangsdaten nach einem Restore unlesbar;
- Dependency-Track-Dateispeicher (Compose-Volume `dtrack` unter `/data`, Kubernetes PVC `dtrack-storage`);
- Secrets `patchwatch-secrets`, `patchwatch-provisioning`, `patchwatch-monitor-key`,
  `patchwatch-integrations`, `patchwatch-trivy` und den Registry-Pull-Zugang, verschlüsselt außerhalb des Clusters;
- Bridge-SQLite-Datenbank inklusive konsistentem WAL-Zustand, damit Tickets nicht erneut entstehen.

Compose-Beispiel für eine konsistente Bridge-Kopie und Dependency-Track-Daten:

```sh
mkdir -p backups
docker compose exec -T bridge python -c "import sqlite3; s=sqlite3.connect('/data/bridge.sqlite'); d=sqlite3.connect('/data/bridge-backup.sqlite'); s.backup(d); d.close(); s.close()"
docker compose cp bridge:/data/bridge-backup.sqlite backups/bridge.sqlite
docker compose cp apiserver:/data backups/dtrack-data
```

Sicherung danach verschlüsselt an einen anderen Ort replizieren. Ein PVC im selben Cluster ist
kein Schutz vor Clusterverlust. Snapshots bzw. externe Volume-Backups passend zum verwendeten Storage-System
für alle drei Daten-PVCs einrichten. Bridge-Datenbank nicht ohne SQLite-Backup oder vollständigen
Snapshot kopieren. Secret-Exporte niemals in Git oder normale Job-Artefakte legen.

PostgreSQL in Compose wiederherstellen (Dienstunterbrechung):

```sh
docker compose stop apiserver frontend gateway gateway-tls
# Der Dump muss auf dem Host vorhanden sein; alle Datenbankverbindungen vorher beenden.
cat backups/dtrack-<timestamp>.dump | docker compose exec -T postgresql sh -c \
  'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; pg_restore -U dtrack -d dtrack --clean --if-exists --exit-on-error'
# Zugehöriges /data und Secrets mit derselben Verschlüsselungs-Key-Version wiederherstellen.
docker compose up -d --wait
```

Für Kubernetes das API-Deployment (`dtrack-api-server`) vor dem Restore auf 0 skalieren; einen zeitweiligen Job mit
PostgreSQL-Image, demselben Datenbank-Secret und Zugriff auf Backup-PVC/Service verwenden.
Restore einschließlich `/data` zuerst isoliert prüfen, dann API wieder auf 1 skalieren.
Kein Restore-Script löscht oder überschreibt automatisch eine produktive Datenbank.
RPO bei täglichem Dump maximal 24 Stunden; RTO hängt von Restore und Feed-/Indexaufbau ab.

## Updates und Schlüsselrotation

Versionen bzw. Versionslinien sind in Compose, Helm-Profilen, Dockerfiles, `ci/components.yml`
und SPDX-Generator hinterlegt. Das Bridge-Dockerfile folgt `python:3.14-alpine3.22` und
aktualisiert Alpine-Pakete beim Build; andere Referenzen sind enger festgelegt. Die deklarierte
SPDX-Quellinventur beschreibt daher nicht die exakten Pakete jedes gebauten Images; dafür die
Image-SBOMs aus der [CI-Integration](../usage/ci-integration.md#6-dieses-repository-eine-inventur-je-komponente) verwenden.
Vor Updates Release Notes und Migrationen lesen, Image/Chart-Versionen gemeinsam anpassen,
Tests und Restore-Probe ausführen, `python3 scripts/spdx.py` neu erzeugen und Änderungen per
Merge Request einspielen. Dependency-Track 5.x selbst wird mit gepinnten Tags aktualisiert; Release-Hinweise unter
[Upgrading running instances](https://dependencytrack.github.io/docs/next/guides/administration/upgrading-instances/) beachten.

Upload-Key: neuen Schlüssel für das Team erzeugen, per MDM verteilen, Uploads prüfen, alten
Schlüssel widerrufen. Das provisioning-Secret entsprechend aktualisieren. Leseschlüssel getrennt
rotieren und Bridge/Monitor neu starten. Der Bootstrap erzeugt bei vorhandenen lokalen/Cluster-
Schlüsseldateien keine neuen Schlüssel; manuell widerrufene Schlüssel dort ebenfalls ersetzen.

PostgreSQL-Passwort: zuerst kontrolliert per `ALTER ROLE` ändern, dann Secret und Pods aktualisieren.
Nur ein Secret-Update ändert das Passwort einer initialisierten Datenbank **nicht**.
Webhook-Token: Secret und Notification-Regel gemeinsam aktualisieren, Bridge neu starten.
Admin-Passwort nach manueller Änderung auch in `patchwatch-secrets` aktualisieren, damit spätere
CI-Konfiguration weiter funktioniert. Den Verschlüsselungsschlüssel nie ohne DTrack-Migrationsverfahren ersetzen.

Für GitHub Advisories kann die geschützte CI-Variable `GITHUB_TOKEN` im Production-Scope gesetzt werden;
`patchwatch.dtrack.setup` trägt das Token im Secret-Manager von Dependency-Track ein und aktiviert die Quelle.
Der NVD-Abgleich braucht in v5 keinen API-Schlüssel (`NVD_API_KEY` entfällt).
OSV wird ohne Zugangsdaten für die konfigurierten Ökosysteme aktiviert. `OSV_ECOSYSTEMS`
kann die Liste überschreiben; DTrack speichert sie semikolongetrennt (Kommas in der
Eingabe werden normalisiert). Bei der Erstinstallation startet die Einrichtung den ersten OSV-Abgleich
sofort, damit er die aktivierten Ökosysteme nutzt (`POST /api/v2/vuln-data-sources/osv/mirror-runs`). Initiale Synchronisation
und späteres Matching können lange dauern. In DTrack den erfolgreichen Lauf der Quellen prüfen;
ein grüner Pod allein belegt keine aktuellen CVE-Daten. OSS Index bleibt ohne Zugangsdaten deaktiviert;
optional `OSS_INDEX_USERNAME` und `OSS_INDEX_TOKEN` setzen.

## Datenumfang und Löschung

Rollenbasierten UI-Zugriff in DTrack separat mit den zuständigen Personen konfigurieren.
Upload-Team und Monitoring-Team sind technische Konten. Sie ersetzen keine Team-/Projekt-ACLs
für menschliche Benutzer. Bei vertraulichen Team-Inventaren DTrack-ACL-Modus und Projektzuordnungen
vor dem Rollout aktivieren. Keine Nutzungsstatistiken oder automatischen Patchaktionen.

Betriebsvorschlag: Upload täglich, Warnung nach 48 Stunden; außer Betrieb genommene Rechner
nach Freigabe nach 30 Tagen deaktivieren und nach 90 Tagen löschen. Dafür ist bewusst kein
unbeaufsichtigter Löschjob aktiv. Die tatsächlichen Fristen und Zuständigkeiten vor Rollout mit
Datenschutz/Betriebsrat dokumentieren. Quell-SBOMs werden lokal nach dem Lauf gelöscht,
DTrack behält den aktuellen Projektbestand und Analysehistorie. Bridge-Outbox enthält Finding-
und Projektnamen; sie bleibt für Deduplizierung erhalten. Ein Löschkonzept muss daher auch Outbox,
Backups und externe JIRA-/Chat-Daten umfassen. Gelöschte Dedupe-Einträge können bei Wiederholung
zu neuen Meldungen führen.


## Abgebrochene Analyse- oder Deploy-Läufe

Der Deploy-Job rollt zuerst die Dienste aus und führt danach API-Konfiguration und
Compliance-Bericht aus. Ein Fehler beim Bericht kann den Job daher rot markieren, obwohl der
Rollout bereits erfolgreich war; er ist kein automatischer Rollback der gesamten Installation.
Bei `ConnectionResetError` oder Timeout während des Berichts zunächst API-Pod-Status, Neustarts,
Logs und Speicherverbrauch prüfen. Nach Wiederherstellung der API den Deploy-Job erneut
ausführen; fehlende Berichtsartefakte nicht als bestandene Compliance-Prüfung werten.

Bei einem Java-Heap-Überlauf beendet sich die DTrack-API mit
`-XX:+ExitOnOutOfMemoryError`, damit Kubernetes bzw. Compose sie neu startet. Sie soll nicht
mit einem weiterhin offenen Health-Endpunkt und beschädigten Hintergrundaufgaben weiterlaufen.
Die Größe der SBOMs und Graph-Wurzeln bei der Kapazitätsplanung berücksichtigen; ein
abgeschlossener Upload-HTTP-Request allein bestätigt noch keine erfolgreiche Auswertung.


## Versionsmarkierungen und Scan-Aktualität

`patchwatch-versions` korrigiert alle fünf Minuten die Latest-Markierung der verwalteten CI-Projekte.
In Kubernetes Fehler mit `kubectl -n patchwatch get jobs` und den Logs des betreffenden Jobs prüfen.
In Compose läuft der Dienst nach `docker compose --profile operations up -d versions`; dessen Logs
zeigen Änderungen oder API-Fehler. Nach Schlüsselrotation den Dienst neu starten. Der Schlüssel
`versions_key` besitzt Verwaltungsrechte und bleibt auf dem Server, getrennt von CI-Upload und Monitor.

Ein manueller Lauf mit dem bereits eingerichteten Schlüssel:

```sh
DT_URL=https://patchwatch.example.org DT_API_KEY_FILE=.secrets/versions_key \
  python3 -m patchwatch.dtrack.versions
```

Derselbe Lauf **migriert** außerdem lose MR- und Branch-Versionen (Tags `scan-purpose:mr-feedback` oder
`scan-purpose:branch`): Er legt das Parent-Projekt `<Projektpfad>` mit derselben Version an, falls es fehlt, und
hängt die Komponenten darunter. Nur Versionen, deren Elternname zu einem regulären Projekt derselben GitLab-
Projekt-ID passt, und nur Parents mit denselben Scope-Tags werden angefasst. Der Lauf ist idempotent.

Danach aktiviert er für CI-, MR- und Branch-Parents mit Unterprojekten
`AGGREGATE_DIRECT_CHILDREN`, auch wenn sie bereits tiefer im Baum liegen. Für jedes verwaltete
GitLab-Projekt entsteht darüber ein Navigationsprojekt `<Projektpfad> @ all versions`:

```text
group/patchwatch                  all versions (ohne Aggregation)
  group/patchwatch                main        (aggregiert Services)
    group/patchwatch/bridge       main
  group/patchwatch                mr-19       (aggregiert Services)
    group/patchwatch/bridge       mr-19
```

Der Ordner hat nur `patchwatch-role:folder` und die GitLab-Projekt-ID als Tags, keine
Latest-Markierung und keine Collection-Logik. Er addiert keine unterschiedlichen Scan-Stände
und ist kein Inventar- oder Benachrichtigungsziel. Bestehende fremde Parent-Zuordnungen bleiben
erhalten; Namenskollisionen werden als Fehler gemeldet. In der Baumansicht lässt sich damit das
gesamte Repository einklappen. Die native Kennzahlenberechnung erfolgt asynchron.

Enthält ein Versions-Parent noch eigenes Inventar, verweigert DTrack die Umwandlung mit HTTP 409.
Der regelmäßige Lauf meldet dann den nötigen Admin-Lauf von `python3 -m patchwatch.dtrack.groups`;
er selbst verschiebt oder löscht kein Inventar. Für die Service-Migration siehe
[CI-Hierarchie](../usage/ci-integration.md#mehrere-inventare-hierarchie).

Projekte des alten Schemas `<Projekt>/mr-feedback/<Komponente>` löscht man einmalig. Ohne `--apply` werden sie nur
aufgelistet; nur Projekte mit Tag `scan-purpose:mr-feedback` unterhalb eines `mr-feedback`-Pfadsegments zählen:

```sh
DT_URL=https://patchwatch.example.org DT_API_KEY_FILE=.secrets/versions_key \
  python3 -m patchwatch.dtrack.legacy            # auflisten
DT_URL=... DT_API_KEY_FILE=... python3 -m patchwatch.dtrack.legacy --apply   # löschen
```

Latest bezeichnet das höchste aktive stabile Release, ersatzweise den Default-Branch. Ein erneuter
Upload eines älteren Releases ändert diese Auswahl nicht. **Scan-Frische** liest man an *Last BOM Import*
des Inventarprojekts ab; beim aggregierenden Sammelprojekt an dessen Unterprojekten. Ein Latest-Häkchen
ist keine Zusage eines aktuellen Scans. Commit und Pipeline sind unter *External References* verlinkt.
Für rückständige Host-Uploads bleibt der vorhandene Monitor zuständig. Einzelheiten und Migration
bestehender CI-Projekte: [CI-Integration](../usage/ci-integration.md#3-was-in-patchwatch-erscheint).
