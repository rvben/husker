#!/usr/bin/env bash
set -euo pipefail

PORT="${HUSKER_DRILL_PORT:-17877}"
BASE_URL="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
LOG_FILE="$(mktemp)"
PID=""

cleanup() {
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  rm -rf "${DATA_DIR}"
  rm -f "${LOG_FILE}"
}
trap cleanup EXIT

echo "[graceful-shutdown] building daemon"
cargo build --quiet --package husker --no-default-features

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="${TARGET_DIR}/debug/husker"
if [[ ! -x "${BIN}" ]]; then
  echo "[graceful-shutdown] expected ${BIN} to exist after build" >&2
  exit 1
fi

echo "[graceful-shutdown] starting daemon on ${BASE_URL}"
HUSKER_DATA_DIR="${DATA_DIR}" \
  RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
  "${BIN}" daemon --listen "127.0.0.1:${PORT}" \
  >"${LOG_FILE}" 2>&1 &
PID=$!

for _ in {1..50}; do
  if curl -fsS "${BASE_URL}/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

curl -fsS "${BASE_URL}/v1/health" >/dev/null
echo "[graceful-shutdown] daemon healthy, sending SIGTERM"
kill -TERM "${PID}"
wait "${PID}"
PID=""

grep -q "shutdown signal received" "${LOG_FILE}"
grep -q "shutting down, draining VMs" "${LOG_FILE}"
echo "[graceful-shutdown] drill completed"
