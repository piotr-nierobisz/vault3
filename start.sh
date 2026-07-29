#!/usr/bin/env bash
#
# start.sh : spin up local dev in Docker containers.
#
#   1. vault3-db        : Postgres (detached, data persisted in a named volume)
#   2. vault3-scheduler : background job scheduler (detached)
#   3. vault3-web       : the BunGo dev server, run in the foreground so you
#                         see the usual `bungo dev` console live.
#
# The Go source is bind-mounted into the web container, so editing files on
# the host triggers bungo's watcher to rebuild and reload (Go/React/
# templates/CSS).
#
# Ports and credentials are read from .env (PORT_INT, POSTGRES_DSN_STRING) so
# this stays in lockstep with the rest of the app. The web container talks to
# the db container over a private Docker network, so its POSTGRES_DSN_STRING
# is rewritten to point at the db container (localhost:778 from .env only
# works from the host); every other value comes straight from .env, which the
# app loads itself and which real env vars (the DSN override here) take
# precedence over.
#
# Stop everything with Ctrl-C.
#
set -euo pipefail

# ── Resolve paths ────────────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$PROJECT_DIR/.env"

# ── Names / images (override via env if you like) ────────────────────────────
NET="${VAULT3_NET:-vault3-net}"
DB_CONTAINER="${VAULT3_DB_CONTAINER:-vault3-db}"
WEB_CONTAINER="${VAULT3_WEB_CONTAINER:-vault3-web}"
SCHED_CONTAINER="${VAULT3_SCHED_CONTAINER:-vault3-scheduler}"
RUN_SCHEDULER="${VAULT3_RUN_SCHEDULER:-1}"            # background job scheduler (set 0 to skip)
PG_VOLUME="${VAULT3_PG_VOLUME:-vault3-pgdata}"        # postgres data (persists)
GO_VOLUME="${VAULT3_GO_VOLUME:-vault3-gocache}"       # GOPATH: modules + bungo
BUILD_VOLUME="${VAULT3_BUILD_VOLUME:-vault3-gobuild}" # go build cache
PG_IMAGE="${VAULT3_PG_IMAGE:-postgres:16-alpine}"
GO_IMAGE="${VAULT3_GO_IMAGE:-golang:1.25}"
BUNGO_VERSION="${VAULT3_BUNGO_VERSION:-v0.4.0}"       # matches go.mod
DEV_WS_PORT=35730                                     # bungo live-reload socket

# ── Preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "✖ docker CLI not found on PATH"; exit 1; }
docker info >/dev/null 2>&1 || { echo "✖ docker daemon is not running"; exit 1; }
[ -f "$ENV_FILE" ] || { echo "✖ .env not found at $ENV_FILE"; exit 1; }

# read_env KEY : echo the value of KEY from .env, with surrounding quotes stripped
read_env() {
  local v
  v="$(grep -E "^[[:space:]]*$1=" "$ENV_FILE" | tail -n1 || true)"
  v="${v#*=}"
  v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
  printf '%s' "$v"
}

# ── Required secrets ─────────────────────────────────────────────────────────
# The app aborts at startup on any missing REQUIRED_ENV_VARS entry. We enforce
# the same contract before spinning up containers so a half-filled .env fails
# fast with a clear list instead of a buried crash loop. The var list is
# parsed straight from the Go source, so it can never drift from what the app
# requires; a value counts as present if it is set in .env or exported in the
# environment. (The Mailgun keys are deliberately optional — see
# internal/config/constants.go.)
REQUIRED_VARS="$(awk '/var REQUIRED_ENV_VARS = \[\]string\{/{f=1; next} f && /^}/{f=0} f' \
  "$PROJECT_DIR/internal/config/constants.go" | grep -oE '"[A-Z0-9_]+"' | tr -d '"')"
MISSING=()
for v in $REQUIRED_VARS; do
  val="$(read_env "$v")"; [ -n "$val" ] || val="${!v:-}"
  [ -n "$val" ] || MISSING+=("$v")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
  echo "✖ refusing to start: missing required secrets (set them in .env or the environment):"
  for v in "${MISSING[@]}"; do echo "    - $v"; done
  exit 1
fi

PORT="$(read_env PORT_INT)"; PORT="${PORT:-3403}"
DSN="$(read_env POSTGRES_DSN_STRING)"
[ -n "$DSN" ] || { echo "✖ POSTGRES_DSN_STRING is missing/empty in .env"; exit 1; }

# Parse postgres://user:pass@host:port/dbname?query from the .env DSN.
DSN_RE='^postgres(ql)?://([^:]+):([^@]+)@([^:/]+):([0-9]+)/([^?]+)(\?.*)?$'
[[ "$DSN" =~ $DSN_RE ]] || { echo "✖ could not parse POSTGRES_DSN_STRING: $DSN"; exit 1; }
DB_USER="${BASH_REMATCH[2]}"
DB_PASS="${BASH_REMATCH[3]}"
DB_HOST_PORT="${BASH_REMATCH[5]}"   # host-published port (kept inline with .env)
DB_NAME="${BASH_REMATCH[6]}"
DB_QUERY="${BASH_REMATCH[7]:-}"     # e.g. ?sslmode=disable (preserved)

# DSN the containers use to reach the db container across the Docker network
# (container hostname + Postgres' real internal port 5432).
CONTAINER_DSN="postgres://${DB_USER}:${DB_PASS}@${DB_CONTAINER}:5432/${DB_NAME}${DB_QUERY}"

echo "┌─ vault3 dev (docker) ───────────────────────────────"
echo "│ app      : http://localhost:${PORT}"
echo "│ db       : localhost:${DB_HOST_PORT}  →  ${DB_CONTAINER}:5432  (${DB_NAME}/${DB_USER})"
echo "│ reload   : ws://localhost:${DEV_WS_PORT}/__bungo"
if [ "$RUN_SCHEDULER" = 1 ]; then
  echo "│ jobs     : ${SCHED_CONTAINER} (detached)  →  docker logs -f ${SCHED_CONTAINER}"
fi
echo "└─────────────────────────────────────────────────────"

# ── Network ──────────────────────────────────────────────────────────────────
docker network inspect "$NET" >/dev/null 2>&1 || { echo "▸ creating network ${NET}"; docker network create "$NET" >/dev/null; }

# ── Database (detached, reuse if already up) ─────────────────────────────────
STARTED_DB=0
if docker ps --format '{{.Names}}' | grep -qx "$DB_CONTAINER"; then
  echo "▸ database already running — reusing ${DB_CONTAINER}"
else
  docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
  echo "▸ starting database (${PG_IMAGE})"
  docker run -d \
    --name "$DB_CONTAINER" \
    --network "$NET" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASS" \
    -e POSTGRES_DB="$DB_NAME" \
    -p "${DB_HOST_PORT}:5432" \
    -v "$PG_VOLUME":/var/lib/postgresql/data \
    "$PG_IMAGE" >/dev/null
  STARTED_DB=1
fi

# Stop the db on exit only if this run started it; data stays in the volume.
CLEANED=0
cleanup() {
  [ "$CLEANED" = 1 ] && return; CLEANED=1
  # The scheduler is tied to this dev session; always tear it down on exit.
  docker rm -f "$SCHED_CONTAINER" >/dev/null 2>&1 || true
  if [ "$STARTED_DB" = 1 ]; then
    echo
    echo "▸ stopping ${DB_CONTAINER} (data kept in volume ${PG_VOLUME})"
    docker stop "$DB_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# ── Wait for Postgres to accept connections ──────────────────────────────────
printf "▸ waiting for postgres"
for i in $(seq 1 60); do
  if docker exec "$DB_CONTAINER" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    echo " — ready"; break
  fi
  printf "."
  sleep 1
  if [ "$i" = 60 ]; then
    echo " — timed out"; docker logs --tail 40 "$DB_CONTAINER" || true; exit 1
  fi
done

# ── Scheduler (detached; background jobs run in their own container) ──────────
# The scheduler shares the source bind-mount and Go caches with the web
# container but runs the plain cmd/scheduler binary. It builds then `exec`s
# the binary so it is PID 1 and receives Docker's SIGTERM directly (graceful
# shutdown); the shared build cache makes the rebuild fast. It does not apply
# the schema (the web container owns that), so on a brand-new database it may
# boot before the schema exists; `--restart on-failure` lets it retry until
# the web container has synced. There is no hot reload — re-run start.sh (or
# restart the container) to pick up scheduler code changes.
if [ "$RUN_SCHEDULER" = 1 ]; then
  docker rm -f "$SCHED_CONTAINER" >/dev/null 2>&1 || true
  echo "▸ starting scheduler (${GO_IMAGE}) — logs: docker logs -f ${SCHED_CONTAINER}"
  docker run -d \
    --name "$SCHED_CONTAINER" \
    --network "$NET" \
    --restart on-failure:20 \
    -e POSTGRES_DSN_STRING="$CONTAINER_DSN" \
    -w /app \
    -v "$PROJECT_DIR":/app \
    -v "$GO_VOLUME":/go \
    -v "$BUILD_VOLUME":/root/.cache/go-build \
    "$GO_IMAGE" \
    sh -c "go build -o /tmp/vault3-scheduler ./cmd/scheduler && exec /tmp/vault3-scheduler" >/dev/null
fi

# ── Web / dev server (foreground; you watch the bungo console here) ───────────
docker rm -f "$WEB_CONTAINER" >/dev/null 2>&1 || true

# Interactive TTY when we have one (so the console renders); plain stdin otherwise.
TTY_FLAGS="-i"; [ -t 1 ] && TTY_FLAGS="-it"

echo "▸ starting bungo dev (${GO_IMAGE}) — first run pulls images & installs bungo; Ctrl-C to stop"
echo

# Note: file-change hot reload relies on inotify events crossing the bind
# mount. Docker Desktop's default VirtioFS forwards them; if reloads don't
# fire, ensure VirtioFS (not the legacy gRPC FUSE / osxfs) is selected in
# Docker settings.
docker run --rm $TTY_FLAGS \
  --name "$WEB_CONTAINER" \
  --network "$NET" \
  -p "${PORT}:${PORT}" \
  -p "${DEV_WS_PORT}:${DEV_WS_PORT}" \
  -e POSTGRES_DSN_STRING="$CONTAINER_DSN" \
  -w /app \
  -v "$PROJECT_DIR":/app \
  -v "$GO_VOLUME":/go \
  -v "$BUILD_VOLUME":/root/.cache/go-build \
  "$GO_IMAGE" \
  sh -c "command -v bungo >/dev/null 2>&1 || go install github.com/piotr-nierobisz/BunGo/cmd/bungo@${BUNGO_VERSION}; exec bungo dev --entry cmd/vault3/main.go"
