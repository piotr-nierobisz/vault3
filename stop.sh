#!/usr/bin/env bash
#
# stop.sh : tear down the local dev containers started by start.sh.
#
# Stops and removes the web, scheduler and database containers. Data is kept
# in the named Postgres volume by default, so the next start.sh reuses it;
# pass --wipe to also delete the volume and start clean next time.
#
# Container/volume/network names mirror start.sh and can be overridden with
# the same VAULT3_* env vars.
#
set -euo pipefail

# ── Names (override via env, matching start.sh) ──────────────────────────────
NET="${VAULT3_NET:-vault3-net}"
DB_CONTAINER="${VAULT3_DB_CONTAINER:-vault3-db}"
WEB_CONTAINER="${VAULT3_WEB_CONTAINER:-vault3-web}"
SCHED_CONTAINER="${VAULT3_SCHED_CONTAINER:-vault3-scheduler}"
PG_VOLUME="${VAULT3_PG_VOLUME:-vault3-pgdata}"

WIPE=0
for arg in "$@"; do
  case "$arg" in
    --wipe) WIPE=1 ;;
    -h|--help)
      echo "Usage: ./stop.sh [--wipe]"
      echo "  --wipe   also delete the Postgres data volume (${PG_VOLUME})"
      exit 0
      ;;
    *) echo "✖ unknown argument: $arg (try --help)"; exit 1 ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "✖ docker CLI not found on PATH"; exit 1; }
docker info >/dev/null 2>&1 || { echo "✖ docker daemon is not running"; exit 1; }

echo "┌─ vault3 dev teardown ───────────────────────────────"

# ── Containers (force-remove; ignore if already gone) ────────────────────────
for c in "$WEB_CONTAINER" "$SCHED_CONTAINER" "$DB_CONTAINER"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
    echo "▸ removing ${c}"
    docker rm -f "$c" >/dev/null 2>&1 || true
  fi
done

# ── Network (remove only if no containers still attached) ────────────────────
if docker network inspect "$NET" >/dev/null 2>&1; then
  echo "▸ removing network ${NET}"
  docker network rm "$NET" >/dev/null 2>&1 || true
fi

# ── Data volume ──────────────────────────────────────────────────────────────
if [ "$WIPE" = 1 ]; then
  echo "▸ deleting data volume ${PG_VOLUME}"
  docker volume rm "$PG_VOLUME" >/dev/null 2>&1 || true
else
  echo "▸ keeping data volume ${PG_VOLUME} (pass --wipe to delete)"
fi

echo "└─ done ──────────────────────────────────────────────"
