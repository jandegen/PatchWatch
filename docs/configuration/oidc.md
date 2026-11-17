# Keycloak-Anbindung über OIDC

Die Anmeldung nutzt die native OIDC-Unterstützung von Dependency-Track 5.2.1.
Keycloak authentifiziert Benutzer; Dependency-Track weist Berechtigungen über
Teams anhand eines Gruppen-Claims zu. Eine bestimmte Keycloak-Installation oder
ein separates Konfigurationsrepository ist nicht erforderlich.

## Voraussetzungen und Beispielwerte

Benötigt werden ein eigener Keycloak-Realm, administrative Rechte für die
Client-/Gruppenkonfiguration und ein erreichbarer Patchwatch-Server. Die folgenden
Werte sind Beispiele und müssen gemeinsam an die eigene Installation angepasst werden.

| Einstellung | Beispiel / Vorgabe |
|---|---|
| Patchwatch | `https://patchwatch.example.org` |
| Issuer | `https://keycloak.example.org/realms/engineering` |
| Realm | `engineering` |
| Client-ID | `patchwatch` |
| Client-Typ | Öffentlich, ohne Client-Secret |
| Flow | Authorization Code mit verpflichtendem S256-PKCE |
| Redirect-URI | `https://patchwatch.example.org/static/oidc-callback.html` |
| Web-Origin | `https://patchwatch.example.org` |
| Scopes | `openid profile email` |
| Benutzername | Claim `preferred_username` |
| Teamzuordnung | Claim `groups`, flache Gruppennamen ohne übergeordneten Pfad |

Browser und API-Server müssen den Issuer über HTTPS erreichen und seiner
Zertifikatskette vertrauen. Die öffentliche URL muss auch aus dem Cluster bzw.
Compose-Netz auflösbar sein.

## Client in Keycloak einrichten

1. Im eigenen Realm einen OpenID-Connect-Client mit ID `patchwatch` anlegen.
2. Client-Authentifizierung deaktivieren: Der Browser verwendet einen öffentlichen
   Client ohne Client-Secret. Den Standard-Flow aktivieren, Direct Access Grants
   und Implicit Flow deaktivieren. PKCE auf `S256` festlegen.
3. Die exakte Redirect-URI aus der Tabelle und die Web-Origin registrieren.
   Bei einem anderen Host oder Basis-Pfad die tatsächliche Frontend-Callback-URL verwenden.
4. Einen Group-Membership-Protocol-Mapper hinzufügen: Claim-Name `groups`,
   **Full group path** deaktivieren, Ausgabe in ID-Token, Access-Token und Userinfo aktivieren.
   Den Mapper dem Client bzw. einem standardmäßig zugewiesenen Client-Scope zuordnen.
5. Die übergeordnete Gruppe `patchwatch` und die sechs Zugriffsgruppen aus der
   Rollenmatrix erstellen. Gleiche Namen wie in der Mapping-Datei verwenden.

Keycloak darf weiterhin Passwortanmeldung im Browser anbieten. Deaktiviert werden
nur direkte Passwort-Grants für diesen Client. Bestehende lokale Administratoren
und Agent-/CI-API-Schlüssel in Dependency-Track bleiben verwendbar.

## Gruppen und Berechtigungen


Jede der folgenden Zugriffsgruppen enthält die Leserechte `VIEW_PORTFOLIO`,
`VIEW_VULNERABILITY` und `VIEW_POLICY_VIOLATION`. Zusätzliche Rechte sind ausdrücklich
auf die jeweilige Aufgabe begrenzt. Die Gruppen können kombiniert werden;
Dependency-Track vereinigt die Berechtigungen der zugeordneten Teams.

| Keycloak-Gruppe | Dependency-Track-Team | Zusätzliche Rechte / Aufgaben |
|---|---|---|
| `patchwatch-viewers` | Patchwatch Viewers | Nur Lesen von Portfolio, Schwachstellen und Policy-Verstößen |
| `patchwatch-security-analysts` | Patchwatch Security Analysts | `VULNERABILITY_ANALYSIS`: Findings bewerten, kommentieren, als False Positive einstufen und unterdrücken; VEX-Verarbeitung |
| `patchwatch-compliance-reviewers` | Patchwatch Compliance Reviewers | `POLICY_VIOLATION_ANALYSIS`: Policy-Verstöße bewerten, kommentieren und unterdrücken |
| `patchwatch-maintainers` | Patchwatch Maintainers | `PORTFOLIO_MANAGEMENT_UPDATE`, `BOM_UPLOAD`: Projektdaten bearbeiten und SBOMs hochladen |
| `patchwatch-policy-managers` | Patchwatch Policy Managers | `POLICY_MANAGEMENT_CREATE`, `POLICY_MANAGEMENT_READ`, `POLICY_MANAGEMENT_UPDATE`: Regeln erstellen, lesen und ändern |
| `patchwatch-admins` | Patchwatch Administrators | Vollständige in der Mapping-Datei definierte Administration, einschließlich Benutzer-, Secret-, System- und Portfolioverwaltung |

Security Analysts ändern keine eigenen Schwachstellendefinitionen; dafür wäre
`VULNERABILITY_MANAGEMENT` nötig. Compliance Reviewers bearbeiten die Bewertung
von Verstößen, während Policy Managers die zugrunde liegenden Regeln bearbeiten.
Maintainers können keine Projekte erstellen oder löschen. Policy Managers können
keine Regeln löschen. Nur das Administrator-Team erhält den globalen
`PORTFOLIO_ACCESS_CONTROL_BYPASS`; bei aktivierter Projektzugriffskontrolle muss
zusätzlich die Projektfreigabe für die jeweiligen Teams eingerichtet werden.

Die vollständige verbindliche Berechtigungsliste steht in
[`deploy/environments/oidc-teams.json`](../../deploy/environments/oidc-teams.json).
Für reine Browser-Teams erzeugt die Einrichtung keine API-Schlüssel.

## Benutzer zuweisen und Rechte entziehen


1. In Keycloak den Realm `engineering` öffnen und den gewünschten Benutzer auswählen.
2. Unter **Groups** die benötigten Zugriffsgruppen zuweisen. Für die Bearbeitung
   von Security-Findings genügt `patchwatch-security-analysts`; für Policy-Verstöße
   zusätzlich `patchwatch-compliance-reviewers`.
3. Den Benutzer auch direkt der übergeordneten Gruppe `patchwatch` zuweisen.
   Diese Gruppe gewährt selbst keine Berechtigungen und erhält einen Gruppen-Claim,
   wenn später alle Zugriffsgruppen entfernt werden.
4. In Patchwatch neu anmelden. Das OIDC-Konto wird beim ersten Login automatisch
   angelegt; bei jeder erfolgreichen Authentifizierung werden die Teams synchronisiert.

Mitgliedschaften entweder in der Keycloak-Administration oder über die eigene
deklarative Benutzerverwaltung pflegen. Bei operatorverwalteten Benutzern gehören
die Zuweisungen in deren Konfigurationsquelle, damit der Operator manuelle Änderungen
nicht zurücksetzt. Patchwatch weist bestehenden Benutzern keine Gruppen automatisch zu.

Zum Entzug einer Rolle die entsprechende Zugriffsgruppe entfernen. Bei der
nächsten erfolgreichen Anmeldung entfernt die Teamsynchronisation die entsprechende
Teammitgliedschaft. Bereits bestehende Dependency-Track-Sitzungen werden durch
Änderungen in Keycloak nicht unmittelbar widerrufen.

**Sonderfall in Dependency-Track 5.2.1:** Hat ein Benutzer gar keine Realm-Gruppen,
entfällt bei Keycloak der Claim `groups`. Dependency-Track verweigert dann die
Anmeldung, führt aber keine Teamsynchronisation aus; vorherige Teameinträge bleiben
bestehen. Die direkte Mitgliedschaft in `patchwatch` vermeidet diesen Sonderfall.
Für einen sofortigen Entzug bestehende Dependency-Track-Sitzungen beenden oder das
OIDC-Konto in Dependency-Track entfernen.

## API und Frontend konfigurieren

In Kubernetes stehen die Einstellungen in
[`deploy/environments/dtrack.yaml`](../../deploy/environments/dtrack.yaml).
API und Frontend müssen denselben Issuer und dieselbe Client-ID erhalten.
Für die Helm-Values sind diese Ausschnitte entsprechend mit der bestehenden
Konfiguration zusammenzuführen; vorhandene Umgebungsvariablen nicht verwerfen:

```yaml
apiServer:
  web:
    extraEnv:
      - {name: DT_OIDC_ENABLED, value: 'true'}
      - {name: DT_OIDC_ISSUER, value: 'https://keycloak.example.org/realms/engineering'}
      - {name: DT_OIDC_CLIENT_ID, value: patchwatch}
      - {name: DT_OIDC_USERNAME_CLAIM, value: preferred_username}
      - {name: DT_OIDC_USER_PROVISIONING, value: 'true'}
      - {name: DT_OIDC_TEAM_SYNCHRONIZATION, value: 'true'}
      - {name: DT_OIDC_TEAMS_CLAIM, value: groups}
frontend:
  extraEnv:
    - {name: OIDC_ISSUER, value: 'https://keycloak.example.org/realms/engineering'}
    - {name: OIDC_CLIENT_ID, value: patchwatch}
    - {name: OIDC_SCOPE, value: 'openid profile email'}
    - {name: OIDC_FLOW, value: code}
    - {name: OIDC_LOGIN_BUTTON_TEXT, value: 'Mit Keycloak anmelden'}
```

Nach dem [Deployment](../installation/kubernetes.md) gleicht
`scripts/configure-cluster.py` die Gruppen-Mappings und Teamrechte aus
`deploy/environments/oidc-teams.json` ab. Zusätzliche Rechte an diesen verwalteten
Teams werden bei erneutem Abgleich entfernt. Für reine Änderungen an Teamrechten
kann bei laufender Installation gezielt dieser Wrapper aufgerufen werden:

```sh
PUBLIC_URL=https://patchwatch.example.org python3 scripts/configure-cluster.py
```

Dabei werden auch die übrigen verwalteten Einstellungen der Installation abgeglichen.
Ein API-Neustart ist für Teamrechte nicht nötig; Änderungen an Pod-Umgebungsvariablen
werden dagegen mit einem Rollout wirksam.

### Docker Compose

Compose aktiviert OIDC nicht automatisch. Die gleiche Konfiguration kann über
eine eigene Override-Datei, beispielsweise `compose.oidc.yaml`, ergänzt werden:

```yaml
services:
  apiserver:
    environment:
      DT_OIDC_ENABLED: 'true'
      DT_OIDC_ISSUER: https://keycloak.example.org/realms/engineering
      DT_OIDC_CLIENT_ID: patchwatch
      DT_OIDC_USERNAME_CLAIM: preferred_username
      DT_OIDC_USER_PROVISIONING: 'true'
      DT_OIDC_TEAM_SYNCHRONIZATION: 'true'
      DT_OIDC_TEAMS_CLAIM: groups
  frontend:
    environment:
      OIDC_ISSUER: https://keycloak.example.org/realms/engineering
      OIDC_CLIENT_ID: patchwatch
      OIDC_SCOPE: openid profile email
      OIDC_FLOW: code
      OIDC_LOGIN_BUTTON_TEXT: Mit Keycloak anmelden
```

Die eigene HTTPS-URL in `.env` als `PUBLIC_URL` setzen, die Callback-URI in Keycloak
an diese URL anpassen und den bereits eingerichteten TLS-Proxy bzw. das TLS-Profil
beibehalten. Ohne separate TLS-Konfiguration ist dieses Beispiel nicht vollständig.
Die Override-Datei bei allen Compose-Aufrufen ergänzen:

```sh
docker compose -f compose.yaml -f compose.oidc.yaml config --quiet
docker compose -f compose.yaml -f compose.oidc.yaml up -d --wait
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=https://patchwatch.example.org \
  OIDC_TEAM_MAPPINGS_FILE=deploy/environments/oidc-teams.json \
  python3 -m patchwatch.dtrack.setup
```

Die Einrichtung setzt eine initialisierte Installation voraus. Bei einer zusätzlichen
internen CA zuerst den folgenden Vertrauenspfad ergänzen. Ohne
`OIDC_TEAM_MAPPINGS_FILE` verändert der allgemeine Konfigurationsaufruf keine
OIDC-Teamzuordnung; der Kubernetes-Wrapper setzt die Datei standardmäßig.

## TLS-Vertrauen

Bei einem öffentlich vertrauenswürdigen Keycloak-Zertifikat genügt der normale
Java-Truststore. Die zusätzliche CA-Konfiguration des Referenzprofils kann dann
entfallen: CA-Init-Container, dessen Volumes und Mounts sowie den
Truststore-Eintrag in `JAVA_TOOL_OPTIONS` gemeinsam entfernen und
`oidcTrust.enabled: false` im Infra-Profil setzen.

Bei einer privaten PKI ausschließlich das öffentliche eigene Root-Zertifikat
verwenden. Das Chart liest es aus dem Wert `oidcTrust.caPem` (im eigenen, nicht
öffentlichen Infra-Profil, siehe [Anpassung](../installation/customization.md)).
Bei `oidcTrust.enabled: true` veröffentlicht das Chart es als ConfigMap
`patchwatch-oidc-ca`.

Der Init-Container kopiert bei jedem API-Podstart den Standard-Java-Truststore des
API-Images und importiert die zusätzliche Root-CA. Öffentliche CAs bleiben erhalten;
Zertifikats- und Hostnamenprüfung bleiben aktiv. Init-Container und API-Server
müssen dieselbe Image-Version nutzen. Bei CA-Rotation Zertifikat aktualisieren,
Infra-Chart ausrollen und API-Pods neu starten. Browser müssen der CA ebenfalls vertrauen.

Für Compose einen aus dem jeweiligen API-Image abgeleiteten Truststore mit eigener
CA bereitstellen und in den API-Container einhängen oder einen entsprechenden
Init-/Image-Build-Schritt ergänzen. Der Kubernetes-Init wird nicht automatisch auf
Compose übertragen. Kein Client-Secret und kein privater CA-Schlüssel wird benötigt.

## Optional: Verwaltung mit dem EDP-Keycloak-Operator

Bei bereits installiertem EDP-Keycloak-Operator können Client und Gruppen in einem
eigenen Infrastrukturrepository als Custom Resources verwaltet werden. Das Beispiel
setzt einen bestehenden `KeycloakRealm` namens `engineering` im Namespace `keycloak`
voraus; Realm-Referenz und Namespace müssen zur eigenen Operatorinstallation passen.
Es ist kein Manifest für den offiziellen `keycloak.org`-Operator.

```yaml
apiVersion: v1.edp.epam.com/v1
kind: KeycloakClient
metadata:
  name: patchwatch
  namespace: keycloak
spec:
  realmRef:
    name: engineering
    kind: KeycloakRealm
  clientId: patchwatch
  public: true
  directAccess: false
  standardFlowEnabled: true
  redirectUris:
    - https://patchwatch.example.org/static/oidc-callback.html
  webOrigins:
    - https://patchwatch.example.org
  webUrl: https://patchwatch.example.org
  attributes:
    pkce.code.challenge.method: S256
  protocolMappers:
    - name: groups
      protocol: openid-connect
      protocolMapper: oidc-group-membership-mapper
      config:
        full.path: 'false'
        id.token.claim: 'true'
        access.token.claim: 'true'
        userinfo.token.claim: 'true'
        claim.name: groups
---
apiVersion: v1.edp.epam.com/v1
kind: KeycloakRealmGroup
metadata:
  name: patchwatch
  namespace: keycloak
spec:
  realmRef:
    name: engineering
    kind: KeycloakRealm
  name: patchwatch
---
apiVersion: v1.edp.epam.com/v1
kind: KeycloakRealmGroup
metadata:
  name: patchwatch-security-analysts
  namespace: keycloak
spec:
  realmRef:
    name: engineering
    kind: KeycloakRealm
  name: patchwatch-security-analysts
  parentGroup:
    name: patchwatch
```

Die übrigen Zugriffsgruppen nach derselben Struktur mit ihren Namen aus der
Rollenmatrix anlegen. Mit den zur installierten Operatorversion passenden CRDs
rendern bzw. validieren, Diff prüfen und über den eigenen Deployment-Prozess ausrollen.
Anschließend die Dependency-Track-Teamzuordnung abgleichen. Der Operator braucht
keinen Zugriff auf das Patchwatch-Deployment.

## Prüfung und Fehlerdiagnose

```sh
export PATCHWATCH_URL=https://patchwatch.example.org
curl --fail "$PATCHWATCH_URL/api/v1/oidc/available"
curl --fail "$PATCHWATCH_URL/static/config.json"
```

`/api/v1/oidc/available` muss `true` zurückgeben; die Frontend-Konfiguration muss
denselben Issuer und dieselbe Client-ID wie die API sowie `OIDC_FLOW: code`
enthalten. Zusätzlich vollständige Anmeldung, Lese-/Schreibrechte und einen
Gruppenentzug mit neuem Login prüfen. Bei Operatorbetrieb müssen Client und Gruppen
`status.status: OK` melden.

| Symptom | Prüfung |
|---|---|
| Kein Keycloak-Login verfügbar | API-OIDC-Konfiguration, Discovery-Erreichbarkeit, DNS und CA-Trust prüfen |
| `Invalid redirect_uri` | Exakte Callback-URL inklusive `/static/oidc-callback.html` prüfen |
| Login funktioniert, Rechte fehlen | `groups`-Claim, flache Namen, Team-Mapping und gegebenenfalls Projektfreigaben prüfen; erneut anmelden |
| Login scheitert nach Gruppenentzug | Prüfen, ob noch eine Realm-Gruppe wie `patchwatch` vorhanden ist |
| `PKIX path building failed` | Eigenes Root-Zertifikat und erfolgreichen Truststore-Init prüfen |
