# Installation auf Kubernetes

Vor dem ersten Deployment die [Umgebungsparameter](customization.md) anpassen. Die Befehle werden im Repository-Wurzelverzeichnis ausgeführt.


Vorausgesetzt werden ein erreichbarer Kubernetes-Cluster, `kubectl`, Helm,
Helmfile mit Diff-Plugin, ein Ingress-Controller und persistenter Speicher. Die
Anleitungen verwenden Namespace `patchwatch` und die Releases `patchwatch` und
`dtrack`. Eine DNS-Adresse wie `patchwatch.example.org` muss auf den Ingress zeigen.
TLS kann über cert-manager und einen eigenen Issuer oder über ein bereitgestelltes
TLS-Secret eingerichtet werden. Dieses Projekt installiert keine Cluster-Controller.

StorageClass, Ingress-Klasse, NetworkPolicy-Selektoren, Zertifikate und URLs gemäß
[Anpassungsübersicht](customization.md) festlegen. `ndots:1` reduziert unerwünschte
DNS-Suchdomain-Erweiterungen; beim offiziellen Chart ergänzt der Helm-Postrenderer
diese Pod-Einstellung per `kubectl kustomize`.

## Bereitstellung über GitLab CI

Die Pipeline testet jeden Merge Request und `main`. Auf `main` baut sie anschließend das
Bridge-Image mit dem vollständigen Commit-SHA als Tag und deployt automatisch per Helmfile.
Ein `resource_group` verhindert konkurrierende Deployments. Fehler in Tests oder Rendering
blockieren Build und Deployment. Deployment-Zugangsdaten werden nur dem geschützten
Production-Environment zur Verfügung gestellt. Fork-/MR-Pipelines erhalten sie nicht.

Einmalig mit vorhandenem Cluster-Admin- und `glab`-Login:

```sh
export GITLAB_PROJECT_ID=1234  # durch die numerische ID des eigenen Patchwatch-Projekts ersetzen
export KUBE_NAMESPACE=patchwatch
bash scripts/bootstrap-cluster.sh
python3 scripts/setup-ci.py --project "$GITLAB_PROJECT_ID"
```

`main` muss in GitLab geschützt sein. Die Einrichtung legt folgende **geschützte**
Projektvariablen mit Environment-Scope `production` an:

| Variable | Typ | Zweck |
|---|---|---|
| `KUBE_CONFIG` | File | ServiceAccount `patchwatch-ci`, Rechte ausschließlich im Namespace |
| `REGISTRY_PULL_USERNAME` | Masked | Projekt-Deploy-Token-Benutzer |
| `REGISTRY_PULL_TOKEN` | Masked | Dauerhaftes `read_registry`-Token für spätere Image-Pulls |

Die Runner-Tags und Docker-in-Docker-Konfiguration in `.gitlab-ci.yml` müssen
zur eigenen Runner- und Registry-Installation passen. Installationsspezifische
Registry-Ausnahmen und private CA-Mounts vorher ersetzen oder entfernen.
Registry, GitLab und Zertifikatskette müssen aus Runner, DinD und Kubernetes-Nodes
erreichbar bzw. vertrauenswürdig sein. Als CI-Variable `PUBLIC_URL` die eigene
öffentliche HTTPS-URL setzen; auch `deploy.environment.url` in der Pipeline anpassen.

CI erzeugt einen separaten Trivy-Token in `patchwatch-trivy` und aktiviert den
[nativen Trivy-Analyzer](../configuration/trivy.md). Datenbank-Passwort, Webhook-Token und Admin-Passwort entstehen einmalig in
`patchwatch-secrets`. Bestehende Werte bleiben bei Folgedeployments erhalten. Die Werte stehen
nicht in Helm-Values oder Git. Zusätzlich entsteht das Team `ci-upload` mit eigenem Schlüssel `ci_upload_key` (in `patchwatch-provisioning`) für das [GitLab-CI-Template](../usage/ci-integration.md); die Pipeline baut dafür ein zweites Image `ci` aus `Dockerfile.ci`. Anschließend werden PostgreSQL, Bridge, Dependency-Track,
Frontend, TLS-Ingress, NetworkPolicies, Backup- und Monitoring-CronJobs ausgerollt.
Die Ersteinrichtung läuft über einen lokalen, authentifizierten Kubernetes-Port-Forward.
Dabei werden `admin/admin` ersetzt, Upload-/Leseteams, OSV-Ecosystems, EPSS, die
[Security-/Lizenzregeln](../configuration/policies.md) samt Lizenzgruppe und separaten MR-Regelkopien sowie die
Webhook-Regel angelegt. Die generierten API-Schlüssel liegen in `patchwatch-provisioning`; der Monitor bekommt
den Leseschlüssel in `patchwatch-monitor-key` (`VIEW_PORTFOLIO` und
`VIEW_POLICY_VIOLATION` und `VIEW_VULNERABILITY`, gemeinsam mit Compliance- und Delta-Berichten). CI protokolliert keine Schlüssel.

Das Team `project-versions` erhält `VIEW_PORTFOLIO` und `PORTFOLIO_MANAGEMENT` für den serverseitigen
Latest-Abgleich. Der Schlüssel bleibt in `patchwatch-provisioning` (`versions_key`) und im separaten
Secret `patchwatch-versions-key`. Der CronJob `patchwatch-versions` läuft alle fünf Minuten mit dem
Bridge-Image; Zeitplan und Secret sind über `versions.schedule` und `versions.existingSecret` konfigurierbar,
mit `versions.enabled: false` lässt er sich deaktivieren. Bei der ersten Installation entsteht das Secret
nach dem Helm-Rollout während der Einrichtung. CI-Upload-Schlüssel behalten ihre bisherigen Rechte.
Der Abgleich läuft zusätzlich bei jeder Einrichtung. Regeln und Herkunftsinformationen:
[CI-Integration](../usage/ci-integration.md#3-was-in-patchwatch-erscheint).

Admin-Passwort ausschließlich lokal anzeigen und anschließend im Passwortmanager ablegen:

```sh
kubectl -n patchwatch get secret patchwatch-secrets -o jsonpath='{.data.admin_password}' | base64 -d
```

Die deklarative Konfiguration besteht aus `helmfile.yaml.gotmpl`,
`deploy/environments/infra.yaml`, `deploy/environments/dtrack.yaml` und dem eigenen
Infra-Chart. Dependency-Track nutzt das **offizielle Chart 2.9.0 mit Anwendung 5.2.1**.
Zusätzlich zu den oben genannten Secrets legt `deploy.sh` einmalig `patchwatch-dtrack-kek` (der
Key-Encryption-Key des v5-Secret-Managers, **mit in jede Cluster-Sicherung**) an und leitet
`patchwatch-dtrack-db` (Benutzer und Passwort im Format des Charts) aus `patchwatch-secrets` ab.
Der API-Server erreicht ausgehend nur öffentliche Adressen sowie Bridge und Trivy
(`DT_OUTBOUND_ALLOWED_DESTINATIONS` in `deploy/environments/dtrack.yaml`).

## Manuell ausrollen

Ohne GitLab CI ein Bridge-Image aus dem freizugebenden Commit bauen und unter
einer unveränderlichen Referenz in der eigenen Registry veröffentlichen. Die Nodes
benötigen Lesezugriff; bei privater Registry das Secret `gitlab-registry` vorab
anlegen oder `imagePullSecrets` an die eigene Pull-Secret-Konfiguration anpassen.
Nach dem Namespace-/RBAC-Bootstrap denselben Deployment-Pfad ausführen:

```sh
export PUBLIC_URL=https://patchwatch.example.org
export BRIDGE_IMAGE="registry.example.org/platform/patchwatch/bridge:$(git rev-parse HEAD)"
bash scripts/deploy.sh
```

Bei Fehlschlag setzt Helm jeweils das betroffene Release atomar zurück. Das ist **keine**
Rücknahme von Datenbankmigrationen oder Konfigurationsänderungen der API. Vor Upgrades Backup
und Restore prüfen. Die beiden Releases sind abhängig und können getrennte Revisionsstände haben.
CI erhält keinen Zugriff auf andere Namespaces. Der langlebige CI-ServiceAccount-Token ist
bewusst namespacebeschränkt; bei Rotation Secret `patchwatch-ci-token` und `KUBE_CONFIG` ersetzen.
