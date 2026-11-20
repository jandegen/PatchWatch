# Installation with Docker Compose

Run all commands in the repository root directory. For a local trial, see the [quick start](../getting-started.md).


Prerequisites: Docker with Compose v2+, Python ≥3.12 for helper scripts and about 7 GiB of free RAM.

```sh
python3 scripts/init-compose.py   # also creates .secrets/dt_kek (Dependency-Track 5 key-encryption key)
docker compose up -d --build --wait --wait-timeout 600
# http://localhost:8080
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=http://localhost:8080 \
  python3 -m patchwatch.dtrack.setup --initial-admin
# Additionally start the daily PostgreSQL backups:
docker compose --profile operations up -d backup
```

The `.env` file is created from `.env.example`. By default only the gateway binds a
host port, namely `127.0.0.1:8080`. The API, PostgreSQL and the bridge are reachable only in the private
Compose network. The API URL in the frontend must be reachable from the **browser**.
Compose reads `.env`, but `python3 -m patchwatch.dtrack.setup` does not read it
automatically. With a public URL of your own, also set its
parameter `PUBLIC_URL` in the setup call to your own URL; `DT_URL`
can keep pointing to loopback for the local setup.

Named volumes persist the database, the Dependency-Track file storage and the bridge outbox.
The key-encryption key `.secrets/dt_kek` encrypts the credentials stored in Dependency-Track and
belongs in every backup; a different key prevents the API server from starting.
`docker compose down` keeps volumes; `down -v` deletes them irrecoverably.

`.secrets` has mode `0700`. The server secret files generated into it are readable inside this
directory so that different container UIDs can use them as a Compose bind mount.
Host upload keys stay `0600`. Never copy passwords from `.env` into the repository.

## HTTPS for remote agents

Place a valid certificate with a matching SAN and the private key as `.secrets/tls.crt` and
`.secrets/tls.key`. The certificate chain must be trusted by the agent and the browser.

```dotenv
PUBLIC_URL=https://patchwatch.example.org:8443
HTTPS_BIND_ADDRESS=0.0.0.0
HTTPS_PORT=8443
```

```sh
docker compose --profile tls up -d --build --wait --wait-timeout 600
```

The additional TLS gateway terminates HTTPS. The HTTP port stays restricted to loopback by the separate
parameter `HTTP_BIND_ADDRESS=127.0.0.1`. Alternatively, put an existing
TLS reverse proxy in front of the loopback gateway. Provide access to the inventory only via the internal
network/VPN. Agents reject HTTP by default; `ALLOW_HTTP=true` is meant for the
internal setup/monitor calls.

If HTTPS is set up after the local quick start, run the setup again with
the new public URL. The call runs on the Compose host;
the internal integration URLs remain Compose service names:

```sh
DT_URL=http://localhost:8080 ALLOW_HTTP=true \
  DT_ADMIN_PASSWORD_FILE=.secrets/admin_password \
  WEBHOOK_TOKEN_FILE=.secrets/webhook_token \
  TRIVY_URL=http://trivy:4954 TRIVY_TOKEN_FILE=.secrets/trivy_token \
  BRIDGE_URL=http://bridge:8080 PUBLIC_URL=https://patchwatch.example.org:8443 \
  python3 -m patchwatch.dtrack.setup
```

With a different HTTP port, change `DT_URL` accordingly. For the first setup,
additionally use `--initial-admin`. If `SECRETS_DIR` is changed, adjust all
secret paths and `--output`: the Python setup does not read the Compose `.env`.
The TLS key and certificate must be readable by the user of the
TLS gateway container; the surrounding secrets directory stays `0700`.

## Connecting agents and GitLab CI

A successful setup creates the following files in the output folder
(`.secrets` by default):

| File | Use |
|---|---|
| `upload_key` | Host agent; distribute securely to the devices, mode `0600` there |
| `ci_upload_key` | Protected, masked GitLab variable `PATCHWATCH_UPLOAD_KEY` |
| `monitor_key` | Server monitor; optionally protected CI read access |
| `versions_key` | Exclusively for the server-side project version synchronization |

Agents and CI jobs use the externally reachable HTTPS base URL from
`PUBLIC_URL`, without `/api`. `localhost` in the CI job refers to the job container,
not to the Compose server. Only the gateway has to be reachable for them.

1. [Set up the agent and verify the first local or remote upload](../usage/agent.md#connecting-to-a-compose-server).
2. For GitLab, [publish the CI image without Kubernetes and connect the runner](../usage/ci-integration.md#14-ci-with-a-compose-server-without-kubernetes).
3. After a successful setup, start the version synchronization:

   ```sh
   docker compose --profile operations up -d versions
   docker compose logs --tail=50 versions
   ```

Enable the entire `operations` profile only once `versions_key` exists.
Backup alone can be started with an explicit service name as above.

## Integrations and monitoring

Configure targets in `.secrets/routes.json`, see [alerting.md](../configuration/alerting.md). Then run
`docker compose restart bridge`. For tag resolution, mount the read key as an additional
file into the bridge; an example is also given there.

```sh
docker compose --profile monitoring run --rm monitor
```

This call checks the inventory once and returns exit code 1 for stale hosts and 2 for
API/configuration errors. For regular Compose checks, use a host timer/cron job;
feed failed calls into your existing monitoring.

Compose restore, secret rotation and monitoring: [operations.md](../operations/index.md).
