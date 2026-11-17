#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
mkdir -p /backups
stamp=$(date -u +%Y%m%dT%H%M%SZ)
target="/backups/dtrack-$stamp.dump"
trap 'rm -f "$target.partial"' EXIT HUP INT TERM
export PGPASSWORD="$(cat /run/secrets/postgres_password)"
# Newly created pods may start before network policy rules have propagated.
# Wait for TCP readiness rather than burning all Job retries on that short race.
attempt=0
until pg_isready -q -h "${PGHOST:-postgresql}" -U dtrack -d dtrack -t 3; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 20 ]; then
    echo 'PostgreSQL did not become reachable within the readiness budget' >&2
    exit 1
  fi
  sleep 3
done
pg_dump -h "${PGHOST:-postgresql}" -U dtrack -d dtrack -Fc -f "$target.partial"
pg_restore --list "$target.partial" >/dev/null
mv "$target.partial" "$target"
find /backups -name 'dtrack-*.dump' -mtime +"${BACKUP_RETENTION_DAYS:-14}" -delete
echo "PostgreSQL backup completed: $stamp"
