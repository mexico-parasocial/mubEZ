#!/bin/sh
# Starts the broker, with the bucket as the source of truth when one is set.
#
# With LITESTREAM_BUCKET unset (local dev, the repo's docker-compose.yml) this
# just runs the command: the SQLite file on disk is the database.
#
# With LITESTREAM_BUCKET set, the disk is only a cache:
#   1. If the database file does not exist yet, restore it from the bucket
#      (a new host, a lost volume, a moved container).
#   2. Run the broker under `litestream replicate`, which streams every WAL
#      change to the bucket within ~1 s and stops the broker if replication
#      cannot continue, so the supervisor restarts it.
#
# Never run two brokers against the same bucket path: both would write the
# same replica and corrupt it. The broker is a single instance by design.

set -eu

db="${DATABASE_PATH:-/app/data/mubez.db}"

if [ -z "${LITESTREAM_BUCKET:-}" ]; then
  exec "$@"
fi

if [ -z "${LITESTREAM_ACCESS_KEY_ID:-}" ] || [ -z "${LITESTREAM_SECRET_ACCESS_KEY:-}" ]; then
  echo "mubez-entrypoint: LITESTREAM_BUCKET is set but the bucket credentials are not" >&2
  echo "  (LITESTREAM_ACCESS_KEY_ID[_FILE], LITESTREAM_SECRET_ACCESS_KEY[_FILE])" >&2
  exit 64
fi

export DATABASE_PATH="$db"
export LITESTREAM_PATH="${LITESTREAM_PATH:-mubez}"
export LITESTREAM_ENDPOINT="${LITESTREAM_ENDPOINT:-}"
# us-east-1 is accepted by S3, R2 and MinIO alike.
export LITESTREAM_REGION="${LITESTREAM_REGION:-us-east-1}"
export LITESTREAM_FORCE_PATH_STYLE="${LITESTREAM_FORCE_PATH_STYLE:-false}"
export LITESTREAM_SYNC_INTERVAL="${LITESTREAM_SYNC_INTERVAL:-1s}"
mkdir -p "$(dirname "$db")"

if [ ! -f "$db" ]; then
  echo "mubez-entrypoint: no local database; restoring from s3://$LITESTREAM_BUCKET/$LITESTREAM_PATH if it exists"
  litestream restore -config /etc/litestream.yml -if-replica-exists "$db"
fi

exec litestream replicate -config /etc/litestream.yml -exec "$*"
