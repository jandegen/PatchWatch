# Auf die eigene Umgebung anpassen

Die Dokumentation verwendet `patchwatch.example.org`, `keycloak.example.org`,
`registry.example.org/platform/patchwatch` und den GitLab-Projektpfad
`platform/patchwatch` als Beispiele. Diese Adressen stellen keine verfügbaren
Dienste oder veröffentlichten Images bereit. Sie müssen durch eigene Werte ersetzt
werden. Eine eigene GitLab-Instanz ist nur für GitLab CI und MR-Feedback nötig.

Die mitgelieferten Kubernetes-Profile stammen aus einer konkreten Installation.
Eine Änderung der Dokumentation ersetzt deren Werte nicht. Vor einem ersten
Deployment alle folgenden Stellen prüfen und anpassen.

## Domains, Plattform und Identitäten

| Parameter | Wo anpassen? | Hinweise |
|---|---|---|
| Installationsspezifische Profile | Eigenes privates Repository mit `environments/infra.yaml` und `environments/dtrack.yaml`; `PATCHWATCH_ENV_DIR` zeigt darauf | `deploy/environments/` enthält nur generische Referenzwerte. Hostnamen, Issuer und CA gehören nicht in dieses Repository. Der Deploy-Job klont das Repository aus `PATCHWATCH_ENV_PROJECT` |
| Öffentliche Patchwatch-URL | Compose `.env`: `PUBLIC_URL`; Kubernetes `deploy/environments/dtrack.yaml`: `frontend.apiBaseUrl`, `ingress.hostname`, `ingress.tls[].hosts` | Browser und Agenten müssen diese HTTPS-Adresse erreichen |
| URL für API-Einrichtung | Umgebungsvariable `PUBLIC_URL` beim Aufruf von `scripts/deploy.sh` oder `scripts/configure-cluster.py`; in GitLab als CI-Variable setzen | Pflicht, kein Fallback |
| GitLab-Environment-URL | CI-Variable `PUBLIC_URL` | Wird für `deploy.environment.url` verwendet |
| Namespace | `KUBE_NAMESPACE`, `scripts/setup-ci.py --namespace`, GitLab-Variable gleichen Namens | Standard `patchwatch`; Bootstrap, Helmfile und Einrichtung müssen denselben Namespace verwenden |
| Helm-Release-Namen | `helmfile.yaml.gotmpl` | `patchwatch` und `dtrack` beibehalten; Skripte und interne Service-Namen setzen diese Namen voraus |
| Ingress-Controller | `deploy/environments/dtrack.yaml`: `ingress.ingressClassName`, controllerabhängige Annotationen | Controller separat installieren; Annotationen bei einem anderen Controller ersetzen |
| StorageClass | `deploy/environments/infra.yaml`: `storageClass`; `deploy/environments/dtrack.yaml`: `fileStorage.local.storageClassName` | Eigene verfügbare Klasse einsetzen; Volumegrößen und Erweiterbarkeit prüfen |
| TLS-Zertifikate | Ingress-TLS-Secret und gegebenenfalls cert-manager-Annotation | cert-manager ist optional, wenn Zertifikate anderweitig bereitgestellt werden |
| ClusterIssuer | Ingress-Annotation `cert-manager.io/cluster-issuer` | Namen des eigenen Issuers verwenden oder Annotation bei anderer Zertifikatsverwaltung entfernen |
| OIDC | `DT_OIDC_*` und `OIDC_*` in `deploy/environments/dtrack.yaml`; Keycloak-Client | Issuer, Realm, Client-ID, Web-Origin und exakte Callback-URL gemeinsam anpassen |
| Interne CA | `oidcTrust.enabled`, `oidcTrust.caPem`, Truststore-Init und `JAVA_TOOL_OPTIONS` | Nur das öffentliche eigene Root-Zertifikat einsetzen, im eigenen Infra-Profil (siehe unten) |
| Technische Namen und Teamrechte | `deploy/environments/oidc-teams.json` | Gruppen müssen in Keycloak existieren; Projektzugriff gegebenenfalls zusätzlich konfigurieren |
| Agent-URL | `agent.json`: `url` | Eigene HTTPS-Basis-URL ohne `/api` eintragen |
| Benachrichtigungen | Secret bzw. `.secrets/routes.json` | Eigene Teamzuordnung und Ziel-URLs gemäß [Alerting](../configuration/alerting.md) |

Ohne Keycloak die `DT_OIDC_*`- und `OIDC_*`-Einträge entfernen bzw. OIDC deaktivieren.
Bei einem öffentlich vertrauenswürdigen IdP sind zusätzlicher CA-Init, dessen
Volumes, der Truststore-Eintrag in `JAVA_TOOL_OPTIONS` und die OIDC-CA-ConfigMap
nicht erforderlich. Zusammengehörige Einstellungen gemeinsam entfernen;
[OIDC und TLS](../configuration/oidc.md#tls-vertrauen) beschreibt den Ablauf.

Die [NetworkPolicies](../../deploy/helm/patchwatch/templates/networkpolicy.yaml)
setzen für eingehenden Traffic einen Ingress-Controller im Namespace `ingress-nginx`
voraus. Bei anderem Controller dessen Namespace-Selektor und gegebenenfalls
Zielports anpassen. DNS-Suche und ausgehende Ziele ebenfalls prüfen.

## GitLab und Registry

| Parameter | Wo anpassen? |
|---|---|
| GitLab-Anmeldung | `glab auth login --hostname gitlab.example.org` vor Setup-Skripten; eigenes Repository als Git-Remote verwenden |
| Numerische Projekt-ID | `scripts/setup-ci.py --project` und `scripts/setup-mr-feedback.py --project` immer explizit angeben; die Skripte enthalten bestehende lokale Defaults |
| Runner-Tags | `.gitlab-ci.yml`: `default.tags` auf verfügbare eigene Runner abstimmen |
| Registry-Verbindung | `.gitlab-ci.yml`: `.docker-build.services[].command`; installationsspezifischen `--insecure-registry`-Eintrag entfernen oder bewusst durch eigene Registry-Konfiguration ersetzen |
| Registry-/GitLab-CA | Runner-CA-Mounts und DinD-Startcode in `.gitlab-ci.yml` sowie `ci/install-tools.sh` prüfen; bei öffentlicher PKI keinen privaten CA-Mount voraussetzen |
| CI-Image für eingebundene Projekte | Bei jedem Include `inputs.image` explizit auf das eigene veröffentlichte Image setzen |
| Template-Quelle | `include.project` auf den eigenen Projektpfad setzen und `ref` auf einen vorhandenen geprüften Commit oder eigenen Release-Tag pinnen |
| Komponenten-Feedback | `ci/mr-feedback.yml` auf Projekt-ID und Images prüfen, bevor die eigenen Feedback-Zeitpläne aktiviert werden |

Ein minimales Beispiel für einen Template-Konsumenten:

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
```

`v1` und das Image müssen im eigenen Projekt zuerst veröffentlicht worden sein.
Der im Template hinterlegte Image-Default ist nicht allgemein nutzbar. Für
unveränderliche Freigaben einen geprüften Commit und Image-Digest verwenden.

## Vor einem Rollout prüfen

1. Gewählte Konfigurationsdateien in einem eigenen Checkout anpassen; keine Passwörter in Values oder Git schreiben.
2. DNS, HTTPS, Registry-Zugriff und Storage-Voraussetzungen unabhängig vom Deployment prüfen.
3. `PUBLIC_URL`, GitLab-Projekt-ID und Image-Referenzen explizit setzen.
4. Helm linten/rendern und Diff prüfen; für Compose `docker compose config --quiet` ausführen.
5. Gemäß [Installation](index.md) ausrollen, initialisieren und einen Upload sowie gegebenenfalls einen OIDC-Login testen.

Ein eigenes Helmfile kann eigene Values-Dateien referenzieren. Die ausgelieferten
Deployment-Skripte verwenden das Wurzel-Helmfile; neue Dateinamen werden ohne dessen
Anpassung nicht automatisch eingelesen.
