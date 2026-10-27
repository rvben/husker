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

fail() {
  echo "[chaos-restart] ERROR: $*" >&2
  for log_file in "${LOG1}" "${LOG2}"; do
    if [[ -s "${log_file}" ]]; then
      echo "[chaos-restart] daemon log ${log_file}:" >&2
      sed -n '1,240p' "${log_file}" >&2
    fi
  done
  exit 1
}

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

# Build before starting anything, so the health wait below measures the
# daemon's startup and never a compile.
echo "[chaos-restart] building daemon"
cargo build --quiet --package husker --no-default-features

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="${TARGET_DIR}/debug/husker"
[[ -x "${BIN}" ]] || fail "expected ${BIN} to exist after build"

# A health answer proves a daemon is up only if nothing else could have given
# it, so every start first requires that nothing answers on the port.
start_daemon() {
  local log_file="$1"
  if curl -fsS "${BASE_URL}/v1/health" >/dev/null 2>&1; then
    fail "something already answers on ${BASE_URL} before the daemon starts"
  fi
  HUSKER_DATA_DIR="${DATA_DIR}" \
    RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
    "${BIN}" daemon --listen "127.0.0.1:${PORT}" \
    >"${log_file}" 2>&1 &
  LAST_PID="$!"
}

# Waits until the daemon with the given pid answers, failing early if that
# process exits (a port it could not bind, a startup error).
wait_for_health() {
  local pid="$1"
  for _ in {1..50}; do
    kill -0 "${pid}" 2>/dev/null || fail "daemon ${pid} exited before becoming healthy"
    if curl -fsS "${BASE_URL}/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  fail "daemon ${pid} did not become healthy within 10 seconds"
}

echo "[chaos-restart] starting daemon #1"
start_daemon "${LOG1}"
PID1="${LAST_PID}"
wait_for_health "${PID1}"

echo "[chaos-restart] load probe while daemon #1 is running"
for _ in {1..25}; do
  curl -fsS "${BASE_URL}/v1/health" >/dev/null || true
done

echo "[chaos-restart] force killing daemon #1"
kill -KILL "${PID1}" || fail "daemon #1 exited before it could be killed"
wait "${PID1}" || true
PID1=""

echo "[chaos-restart] starting daemon #2 after crash"
start_daemon "${LOG2}"
PID2="${LAST_PID}"
wait_for_health "${PID2}"

echo "[chaos-restart] graceful shutdown daemon #2"
kill -TERM "${PID2}"
wait "${PID2}" || fail "daemon #2 did not exit cleanly on SIGTERM"
PID2=""

grep -q "shutdown signal received" "${LOG2}" \
  || fail "daemon #2 did not log the shutdown signal"
echo "[chaos-restart] drill completed"
