# Keycloak integration via OIDC

Login uses the native OIDC support of Dependency-Track 5.2.1.
Keycloak authenticates users; Dependency-Track assigns permissions via
teams based on a groups claim. A specific Keycloak installation or
a separate configuration repository is not required.

## Prerequisites and example values

You need a Keycloak realm of your own, administrative permissions for the
client/group configuration and a reachable Patchwatch server. The following
values are examples and must be adapted together to your own installation.

| Setting | Example / default |
|---|---|
| Patchwatch | `https://patchwatch.example.org` |
| Issuer | `https://keycloak.example.org/realms/engineering` |
| Realm | `engineering` |
| Client ID | `patchwatch` |
| Client type | Public, without client secret |
| Flow | Authorization code with mandatory S256 PKCE |
| Redirect URI | `https://patchwatch.example.org/static/oidc-callback.html` |
| Web origin | `https://patchwatch.example.org` |
| Scopes | `openid profile email` |
| Username | Claim `preferred_username` |
| Team mapping | Claim `groups`, flat group names without parent path |

The browser and API server must reach the issuer over HTTPS and trust its
certificate chain. The public URL must also be resolvable from the cluster or
Compose network.

## Setting up the client in Keycloak

1. Create an OpenID Connect client with ID `patchwatch` in your own realm.
2. Disable client authentication: the browser uses a public
   client without client secret. Enable the standard flow, disable direct access grants
   and implicit flow. Set PKCE to `S256`.
3. Register the exact redirect URI from the table and the web origin.
   With a different host or base path, use the actual frontend callback URL.
4. Add a group membership protocol mapper: claim name `groups`,
   disable **Full group path**, enable output in ID token, access token and userinfo.
   Assign the mapper to the client or to a default-assigned client scope.
5. Create the parent group `patchwatch` and the six access groups from the
   role matrix. Use the same names as in the mapping file.

Keycloak may continue to offer password login in the browser. Only direct password
grants are disabled for this client. Existing local administrators
and agent/CI API keys in Dependency-Track remain usable.

## Groups and permissions


Each of the following access groups includes the read permissions `VIEW_PORTFOLIO`,
`VIEW_VULNERABILITY` and `VIEW_POLICY_VIOLATION`. Additional permissions are explicitly
limited to the respective task. The groups can be combined;
Dependency-Track merges the permissions of the assigned teams.

| Keycloak group | Dependency-Track team | Additional permissions / tasks |
|---|---|---|
| `patchwatch-viewers` | Patchwatch Viewers | Read-only access to portfolio, vulnerabilities and policy violations |
| `patchwatch-security-analysts` | Patchwatch Security Analysts | `VULNERABILITY_ANALYSIS`: assess, comment on, classify as false positive and suppress findings; VEX processing |
| `patchwatch-compliance-reviewers` | Patchwatch Compliance Reviewers | `POLICY_VIOLATION_ANALYSIS`: assess, comment on and suppress policy violations |
| `patchwatch-maintainers` | Patchwatch Maintainers | `PORTFOLIO_MANAGEMENT_UPDATE`, `BOM_UPLOAD`: edit project data and upload SBOMs |
| `patchwatch-policy-managers` | Patchwatch Policy Managers | `POLICY_MANAGEMENT_CREATE`, `POLICY_MANAGEMENT_READ`, `POLICY_MANAGEMENT_UPDATE`: create, read and change rules |
| `patchwatch-admins` | Patchwatch Administrators | Full administration as defined in the mapping file, including user, secret, system and portfolio management |

Security analysts do not change their own vulnerability definitions; that would need
`VULNERABILITY_MANAGEMENT`. Compliance reviewers edit the assessment
of violations, while policy managers edit the underlying rules.
Maintainers cannot create or delete projects. Policy managers cannot
delete rules. Only the administrator team receives the global
`PORTFOLIO_ACCESS_CONTROL_BYPASS`; with project access control enabled, the project
assignment for the respective teams must additionally be set up.

The complete authoritative permission list is in
[`deploy/environments/oidc-teams.json`](../../deploy/environments/oidc-teams.json).
For browser-only teams, the setup creates no API keys.

## Assigning users and revoking permissions


1. In Keycloak, open the realm `engineering` and select the desired user.
2. Under **Groups**, assign the required access groups. For handling
   security findings, `patchwatch-security-analysts` suffices; for policy violations,
   additionally `patchwatch-compliance-reviewers`.
3. Also assign the user directly to the parent group `patchwatch`.
   This group grants no permissions itself and ensures a groups claim
   if all access groups are removed later.
4. Sign in to Patchwatch again. The OIDC account is created automatically
   on first login; on every successful authentication, the teams are synchronized.

Maintain memberships either in the Keycloak administration or through your own
declarative user management. For operator-managed users, the assignments belong
in their configuration source so that the operator does not reset manual changes.
Patchwatch does not assign groups to existing users automatically.

To revoke a role, remove the corresponding access group. On the
next successful login, the team synchronization removes the corresponding
team membership. Existing Dependency-Track sessions are not revoked immediately by
changes in Keycloak.

**Special case in Dependency-Track 5.2.1:** If a user has no realm groups at all,
Keycloak omits the claim `groups`. Dependency-Track then refuses
login but performs no team synchronization; previous team entries remain
in place. Direct membership in `patchwatch` avoids this special case.
For an immediate revocation, end existing Dependency-Track sessions or remove the
OIDC account in Dependency-Track.

## Configuring the API and frontend

In Kubernetes, the settings are in
[`deploy/environments/dtrack.yaml`](../../deploy/environments/dtrack.yaml).
The API and frontend must receive the same issuer and the same client ID.
For the Helm values, merge these excerpts with the existing
configuration accordingly; do not discard existing environment variables:

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
    - {name: OIDC_LOGIN_BUTTON_TEXT, value: 'Sign in with Keycloak'}
```

After the [deployment](../installation/kubernetes.md),
`scripts/configure-cluster.py` reconciles the group mappings and team permissions from
`deploy/environments/oidc-teams.json`. Additional permissions on these managed
teams are removed on renewed reconciliation. For pure changes to team permissions,
this wrapper can be invoked specifically on a running installation:

```sh
PUBLIC_URL=https://patchwatch.example.org python3 scripts/configure-cluster.py
```

This also reconciles the remaining managed settings of the installation.
An API restart is not needed for team permissions; changes to pod environment variables,
in contrast, take effect with a rollout.

### Docker Compose

Compose does not enable OIDC automatically. The same configuration can be added through
an override file of your own, for example `compose.oidc.yaml`:

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
      OIDC_LOGIN_BUTTON_TEXT: Sign in with Keycloak
```

Set your own HTTPS URL in `.env` as `PUBLIC_URL`, adapt the callback URI in Keycloak
to this URL and keep the TLS proxy or TLS profile already set up.
Without a separate TLS configuration, this example is not complete.
Add the override file to all Compose calls:

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

The setup requires an initialized installation. With an additional
internal CA, first add the following trust path. Without
`OIDC_TEAM_MAPPINGS_FILE`, the general configuration call changes no
OIDC team assignment; the Kubernetes wrapper sets the file by default.

## TLS trust

With a publicly trusted Keycloak certificate, the normal
Java truststore suffices. The additional CA configuration of the reference profile can then
be dropped: remove the CA init container, its volumes and mounts, and the
truststore entry in `JAVA_TOOL_OPTIONS` together, and
set `oidcTrust.enabled: false` in the infra profile.

With a private PKI, use only the public root certificate of your own CA.
The chart reads it from the value `oidcTrust.caPem` (in your own, non-public
infra profile, see [customization](../installation/customization.md)).
With `oidcTrust.enabled: true`, the chart publishes it as ConfigMap
`patchwatch-oidc-ca`.

On every API pod start, the init container copies the default Java truststore of the
API image and imports the additional root CA. Public CAs are kept;
certificate and hostname verification stay active. The init container and API server
must use the same image version. On CA rotation, update the certificate,
roll out the infra chart and restart the API pods. Browsers must trust the CA as well.

For Compose, provide a truststore derived from the respective API image with your own
CA and mount it into the API container, or add a corresponding
init/image build step. The Kubernetes init is not transferred automatically to
Compose. No client secret and no private CA key is needed.

## Optional: management with the EDP Keycloak operator

With the EDP Keycloak operator already installed, the client and groups can be managed as custom resources
in an infrastructure repository of your own. The example
assumes an existing `KeycloakRealm` named `engineering` in the namespace `keycloak`;
the realm reference and namespace must match your own operator installation.
It is not a manifest for the official `keycloak.org` operator.

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

Create the remaining access groups with the same structure and their names from the
role matrix. Render or validate with the CRDs matching the installed operator version,
check the diff and roll out through your own deployment process.
Then reconcile the Dependency-Track team assignment. The operator needs
no access to the Patchwatch deployment.

## Verification and troubleshooting

```sh
export PATCHWATCH_URL=https://patchwatch.example.org
curl --fail "$PATCHWATCH_URL/api/v1/oidc/available"
curl --fail "$PATCHWATCH_URL/static/config.json"
```

`/api/v1/oidc/available` must return `true`; the frontend configuration must contain
the same issuer and the same client ID as the API as well as `OIDC_FLOW: code`.
Additionally verify a complete login, read/write permissions and a
group revocation with a new login. With operator operation, the client and groups must report
`status.status: OK`.

| Symptom | Check |
|---|---|
| No Keycloak login available | Check API OIDC configuration, discovery reachability, DNS and CA trust |
| `Invalid redirect_uri` | Check the exact callback URL including `/static/oidc-callback.html` |
| Login works, permissions missing | Check `groups` claim, flat names, team mapping and, if applicable, project assignments; sign in again |
| Login fails after group revocation | Check whether a realm group such as `patchwatch` is still present |
| `PKIX path building failed` | Check your own root certificate and a successful truststore init |
