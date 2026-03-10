#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_STATE_DIR="${ROOT_DIR}/.nwa-service"

DB_DSN="${NWA_DB:-${1:-${DEFAULT_STATE_DIR}/platform.sqlite}}"
DATA_DIR="${NWA_DATA_DIR:-${2:-${DEFAULT_STATE_DIR}/data}}"
PORT="${PORT:-${NWA_PORT:-8110}}"

mkdir -p "${DATA_DIR}"
case "${DB_DSN}" in
  postgres://*|postgresql://*)
    ;;
  *)
    mkdir -p "$(dirname "${DB_DSN}")"
    ;;
esac

if [[ -z "${NWA_ADMIN_PASSWORD:-}" ]]; then
  echo "NWA_ADMIN_PASSWORD is not set. A bootstrap admin password will be generated and logged on first startup." >&2
fi

echo "Starting N.W.A. platform service"
echo "DB: ${DB_DSN}"
echo "Data dir: ${DATA_DIR}"
echo "Port: ${PORT}"

cd "${ROOT_DIR}"
exec go run . -db "${DB_DSN}" -data-dir "${DATA_DIR}" -p "${PORT}"
