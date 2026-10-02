#!/bin/bash
# Capture diagnostics when the unit-test container stops making progress.
#
# The Locations-on rest framework job intermittently goes silent near the end
# of the parallel phase and sits there until the step timeout kills it. When a
# --parallel worker never returns its subsuite, the main process blocks in
# multiprocessing's pool iterator forever and prints nothing, so the log alone
# cannot say whether a test was stuck (and on what) or a worker died.
#
# This runs on the runner, next to `docker compose up`, and never touches the
# test container except to read from it. It dumps once the uwsgi container has
# written no log output for STALL_SECONDS, and again at DEADLINE_SECONDS after
# start whatever the output looks like, so the evidence exists before the step
# timeout (25 minutes) kills everything. Each dump has:
#   - the container's processes and memory
#   - a py-spy stack dump of every python process, taken from the host by host
#     PID, which needs no ptrace capability inside the container
#   - pg_stat_activity (with the pids each backend is blocked by) and pg_locks
#
# Output goes to the file given as $1 so a later `if: always()` step can print
# it even when this step is killed by its timeout.

set -u

OUT="${1:?usage: $0 <output-file>}"
STALL_SECONDS="${STALL_SECONDS:-300}"
DEADLINE_SECONDS="${DEADLINE_SECONDS:-1200}"
POLL_SECONDS="${POLL_SECONDS:-30}"
MAX_DUMPS="${MAX_DUMPS:-3}"
PY_SPY_VERSION="${PY_SPY_VERSION:-0.4.2}"
DB_USER="${DB_USER:-defectdojo}"
DB_NAME="${DB_NAME:-test_defectdojo}"

log() {
    echo "[hang-watchdog $(date -u +%H:%M:%S)] $*" | tee -a "$OUT"
}

section() {
    printf '\n===== %s =====\n' "$*" >> "$OUT"
}

py_spy() {
    if [ -z "${PY_SPY:-}" ]; then
        # Installed only when a dump is actually needed, so a healthy run pays nothing.
        pipx install --quiet "py-spy==${PY_SPY_VERSION}" >> "$OUT" 2>&1 \
            || python3 -m pip install --quiet --user --break-system-packages "py-spy==${PY_SPY_VERSION}" >> "$OUT" 2>&1 \
            || true
        PY_SPY="$(command -v py-spy || echo "${HOME}/.local/bin/py-spy")"
    fi
    sudo "$PY_SPY" "$@"
}

dump() {
    local reason="$1" cid="$2"
    log "dumping diagnostics (${reason})"

    section "docker top uwsgi"
    docker top "$cid" -eo pid,ppid,stat,etime,rss,args >> "$OUT" 2>&1

    section "docker stats"
    docker stats --no-stream >> "$OUT" 2>&1

    section "py-spy dump of every python process (host pids)"
    local pid
    for pid in $(docker top "$cid" -eo pid,args | awk 'NR > 1 && /python/ {print $1}'); do
        printf '\n--- pid %s ---\n' "$pid" >> "$OUT"
        py_spy dump --pid "$pid" >> "$OUT" 2>&1 || echo "py-spy failed for pid ${pid}" >> "$OUT"
    done

    section "pg_stat_activity"
    docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -X -c \
        "select pid, datname, state, pg_blocking_pids(pid) as blocked_by, wait_event_type, wait_event,
                now() - xact_start as xact_age, now() - query_start as query_age, left(query, 300) as query
           from pg_stat_activity
          where backend_type = 'client backend'
          order by xact_start nulls last" >> "$OUT" 2>&1

    section "pg_locks not granted, and what holds them"
    docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -X -c \
        "select l.pid, l.locktype, l.mode, l.granted, l.relation::regclass as relation, l.transactionid,
                a.datname, a.state, left(a.query, 200) as query
           from pg_locks l join pg_stat_activity a using (pid)
          where not l.granted
             or l.pid in (select unnest(pg_blocking_pids(pid)) from pg_stat_activity)
          order by l.granted, l.pid" >> "$OUT" 2>&1

    section "last 40 lines of uwsgi output"
    docker logs --tail 40 "$cid" >> "$OUT" 2>&1
}

: > "$OUT"
start=$(date +%s)

cid=""
while [ -z "$cid" ]; do
    cid="$(docker compose ps -q uwsgi 2>/dev/null)"
    [ -n "$cid" ] || sleep 5
done
log "watching container ${cid} (stall ${STALL_SECONDS}s, deadline ${DEADLINE_SECONDS}s)"

last_output=$(date +%s)
last_dump=0
dumps=0
deadline_done=0

while [ "$dumps" -lt "$MAX_DUMPS" ]; do
    sleep "$POLL_SECONDS"
    now=$(date +%s)
    [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" = "true" ] || { log "container stopped"; exit 0; }

    if [ -n "$(docker logs --since "${POLL_SECONDS}s" "$cid" 2>&1 | head -c 1)" ]; then
        last_output=$now
    fi

    if [ "$deadline_done" -eq 0 ] && [ $((now - start)) -ge "$DEADLINE_SECONDS" ]; then
        deadline_done=1
        dump "running for $((now - start))s" "$cid"
        dumps=$((dumps + 1))
        last_dump=$now
    elif [ $((now - last_output)) -ge "$STALL_SECONDS" ] && [ $((now - last_dump)) -ge "$STALL_SECONDS" ]; then
        dump "no output for $((now - last_output))s" "$cid"
        dumps=$((dumps + 1))
        last_dump=$now
    fi
done
log "reached ${MAX_DUMPS} dumps, stopping"
