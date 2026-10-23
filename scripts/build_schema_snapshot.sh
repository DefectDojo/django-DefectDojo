#!/usr/bin/env bash
# Build a release's schema snapshot and prove it, for the fresh-install fast path in
# dojo/management/commands/schema_snapshot.py.
#
#   scripts/build_schema_snapshot.sh --image <django image> --out <dir> [--gate-versions "16 17 18"]
#
# 1. Migrates an empty PostgreSQL 16 database from zero with the image (16 is the oldest version
#    the snapshot supports, and a plain dump loads only into the same or a newer version). Only
#    `migrate`, never the full initializer, so no user or fixture data is created.
# 2. `manage.py schema_snapshot --write-manifest` describes it, and fails if the database holds a
#    user or an API token: the snapshot is published in the release image.
# 3. Dumps it with pg_dump 16 as plain SQL (--no-owner --no-privileges --inserts), so it loads over
#    the application's own connection on any server from 16 up, managed databases included.
# 4. Gate: for every version in --gate-versions, runs the image's real initializer against an empty
#    database with the snapshot mounted, as a non-superuser that owns the database (like a managed
#    database's user). It requires that the initializer loaded the snapshot and applied nothing, and
#    that the migration rows and the schema match the source (scripts/schema_snapshot_normalize.py).
#    Any failure fails the script, and the release with it.
#
# Writes <dir>/migrated.sql and <dir>/manifest.json, and logs under <dir>/logs. Needs docker and
# python3.
set -euo pipefail

usage() { sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

IMAGE=""
OUT=""
GATE_VERSIONS="16 17 18"
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --gate-versions) GATE_VERSIONS="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done
[ -n "$IMAGE" ] && [ -n "$OUT" ] || usage

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LOGS="$OUT/logs"
mkdir -p "$LOGS"
PG_REPO="${SCHEMA_SNAPSHOT_PG_REPO:-postgres}"
VALKEY_IMAGE="${SCHEMA_SNAPSHOT_VALKEY_IMAGE:-valkey/valkey:9-alpine}"
PREFIX="schemasnapshot-$$"
NET="$PREFIX-net"

cleanup() {
    for id in $(docker ps -aq --filter "name=^${PREFIX}-"); do docker rm -f "$id" >/dev/null 2>&1 || true; done
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log() { printf '[schema-snapshot] %s\n' "$*"; }
die() { printf '[schema-snapshot] ERROR: %s\n' "$*" >&2; exit 1; }

docker network create "$NET" >/dev/null
docker run -d --name "$PREFIX-valkey" --network "$NET" --network-alias valkey "$VALKEY_IMAGE" >/dev/null

start_postgres() {  # <name> <version>: an empty database dojodb, as $PREFIX-<name>
    docker run -d --name "$PREFIX-$1" --network "$NET" \
        -e POSTGRES_USER=dbusr -e POSTGRES_PASSWORD=password -e POSTGRES_DB=dojodb \
        "$PG_REPO:$2" >/dev/null
    # Over TCP: on first boot the image runs its init scripts on a socket-only server and restarts.
    for _ in $(seq 1 60); do
        docker exec "$PREFIX-$1" pg_isready -q -U dbusr -h 127.0.0.1 && return 0
        sleep 1
    done
    die "postgres $2 did not become ready"
}

# The application's database user on a managed database: not a superuser, owner of its database
# (on PostgreSQL 15 and later that also makes it the owner of the public schema).
add_app_owner() {  # <name>
    docker exec "$PREFIX-$1" psql -q -U dbusr -d postgres \
        -c "CREATE ROLE dojoapp LOGIN PASSWORD 'password' NOSUPERUSER NOCREATEROLE" \
        -c "ALTER DATABASE dojodb OWNER TO dojoapp"
}

psql_value() {  # <name> <sql>
    docker exec "$PREFIX-$1" psql -U dbusr -d dojodb -Atc "$2"
}

run_dojo() {  # <database name> <database user> <docker run args...>: the image against that database
    local db="$1" user="$2"; shift 2
    docker run --rm --name "$PREFIX-run-$db" --network "$NET" --user root \
        -e "DD_DATABASE_URL=postgresql://$user:password@$PREFIX-$db:5432/dojodb" \
        -e "DD_DATABASE_HOST=$PREFIX-$db" -e DD_DATABASE_PORT=5432 \
        -e DD_SECRET_KEY=schema-snapshot-only -e DD_CREDENTIAL_AES_256_KEY=schema-snapshot-only-0123456789 \
        -e DD_CELERY_BROKER_URL=redis://valkey:6379/0 -e DD_CACHE_URL=redis://valkey:6379/1 \
        -e DD_ADMIN_USER=admin -e DD_ADMIN_MAIL=admin@example.com -e DD_ADMIN_PASSWORD=schema-snapshot-only \
        -e DD_ADMIN_FIRST_NAME=Admin -e DD_ADMIN_LAST_NAME=User \
        "$@"
}

# The newest version in the gate: pg_dump refuses a server newer than itself, so every schema is
# dumped with this one client, which also keeps its formatting identical across them.
# shellcheck disable=SC2086  # one version per word
NEWEST="$(printf '%s\n' $GATE_VERSIONS 16 | sort -n | tail -1)"

schema_of() {  # <name> <file>: that database's schema
    docker run --rm --network "$NET" -e PGPASSWORD=password "$PG_REPO:$NEWEST" \
        pg_dump -h "$PREFIX-$1" -U dbusr -d dojodb --schema-only --no-owner --no-privileges > "$2"
}

# --- 1. Migrate from zero on PostgreSQL 16 -------------------------------------------------------
log "Migrating an empty PostgreSQL 16 database from zero with $IMAGE"
start_postgres source 16
started=$(date +%s)
run_dojo source dbusr -v "$OUT:/out" --entrypoint bash "$IMAGE" -c \
    'python3 manage.py migrate --no-input && python3 manage.py schema_snapshot --write-manifest /out/manifest.json' \
    > "$LOGS/migrate.log" 2>&1 || { tail -50 "$LOGS/migrate.log"; die "migrating from zero or writing the manifest failed (log: $LOGS/migrate.log)"; }
log "Migrated in $(( $(date +%s) - started ))s: $(psql_value source 'select count(*) from django_migrations') migrations applied"

# --- 2. Dump ------------------------------------------------------------------------------------
log "Dumping with $(docker exec "$PREFIX-source" pg_dump --version)"
docker exec "$PREFIX-source" pg_dump -U dbusr -d dojodb \
    --format=plain --no-owner --no-privileges --inserts --rows-per-insert=1000 > "$OUT/migrated.sql"
schema_of source "$LOGS/schema-source.sql"
log "Wrote $OUT/migrated.sql ($(wc -c < "$OUT/migrated.sql" | tr -d ' ') bytes) and $OUT/manifest.json"

# --- 3. Gate: the real initializer takes the fast path on every version ---------------------------
expected_rows="$(psql_value source "select string_agg(app || '.' || name, ',' order by app, name) from django_migrations")"
for version in $GATE_VERSIONS; do
    db="gate$version"
    log "Gate on PostgreSQL $version: initializer against an empty database with the snapshot"
    start_postgres "$db" "$version"
    add_app_owner "$db"
    started=$(date +%s)
    run_dojo "$db" dojoapp -v "$OUT:/schema-snapshot:ro" \
        --entrypoint /entrypoint-initializer.sh "$IMAGE" true \
        > "$LOGS/init-pg$version.log" 2>&1 || { tail -50 "$LOGS/init-pg$version.log"; die "initializer failed on PostgreSQL $version"; }
    grep -q "Loaded the schema snapshot" "$LOGS/init-pg$version.log" \
        || { grep -i "schema snapshot" "$LOGS/init-pg$version.log" || true; die "initializer on PostgreSQL $version did not load the snapshot"; }
    if grep -q "  Applying " "$LOGS/init-pg$version.log"; then
        grep "  Applying " "$LOGS/init-pg$version.log" >&2
        die "initializer on PostgreSQL $version applied migrations after loading the snapshot"
    fi
    actual_rows="$(psql_value "$db" "select string_agg(app || '.' || name, ',' order by app, name) from django_migrations")"
    [ "$actual_rows" = "$expected_rows" ] || die "PostgreSQL $version records different migrations than the source"
    [ "$(psql_value "$db" "select count(*) from auth_user")" = 1 ] \
        || die "PostgreSQL $version: first boot did not create exactly the admin user"
    schema_of "$db" "$LOGS/schema-pg$version.sql"
    # The source's schema plus what first boot changes is not what a gate compares, so compare the
    # schema only: first boot adds rows, never tables.
    python3 "$ROOT/scripts/schema_snapshot_normalize.py" "$LOGS/schema-source.sql" "$LOGS/schema-pg$version.sql" \
        || die "the schema restored on PostgreSQL $version differs from the migrated source"
    log "PostgreSQL $version: fast path in $(( $(date +%s) - started ))s as a non-superuser; schema and migration rows match"
done

log "Schema snapshot ready in $OUT"
