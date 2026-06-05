#!/usr/bin/env bash
set -euo pipefail

PORT="${HUSKER_CHAOS_PORT:-17878}"
BASE_URL="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
LOG1="$(mktemp)"
LOG2="$(mktemp)"
PID1=""
PID2=""
LAST_PID=""

cleanup() {
  if [[ -n "${PID1}" ]] && kill -0 "${PID1}" 2>/dev/null; then
    kill "${PID1}" 2>/dev/null || true
    wait "${PID1}" 2>/dev/null || true
  fi
  if [[ -n "${PID2}" ]] && kill -0 "${PID2}" 2>/dev/null; then
    kill "${PID2}" 2>/dev/null || true
    wait "${PID2}" 2>/dev/null || true
  fi
  rm -rf "${DATA_DIR}"
  rm -f "${LOG1}" "${LOG2}"
}
trap cleanup EXIT

start_daemon() {
  local log_file="$1"
  HUSKER_DATA_DIR="${DATA_DIR}" \
    cargo run --quiet --package husker --no-default-features -- daemon --listen "127.0.0.1:${PORT}" \
    >"${log_file}" 2>&1 &
  LAST_PID="$!"
}

wait_for_health() {
  for _ in {1..50}; do
    if curl -fsS "${BASE_URL}/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

echo "[chaos-restart] starting daemon #1"
start_daemon "${LOG1}"
PID1="${LAST_PID}"
wait_for_health

echo "[chaos-restart] load probe while daemon #1 is running"
for _ in {1..25}; do
  curl -fsS "${BASE_URL}/v1/health" >/dev/null || true
done

echo "[chaos-restart] force killing daemon #1"
kill -KILL "${PID1}" || true
wait "${PID1}" || true
PID1=""

echo "[chaos-restart] starting daemon #2 after crash"
start_daemon "${LOG2}"
PID2="${LAST_PID}"
wait_for_health
curl -fsS "${BASE_URL}/v1/health" >/dev/null

echo "[chaos-restart] graceful shutdown daemon #2"
kill -TERM "${PID2}"
wait "${PID2}" || true
PID2=""

grep -q "shutdown signal received" "${LOG2}"
echo "[chaos-restart] drill completed"
