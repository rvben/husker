#!/usr/bin/env bash
set -euo pipefail

# Privileged Linux validation of the daemon runtime's two externally observable
# shutdown paths:
#
# 1. An API bind failure after bridge/NAT setup still stops workers, drains, and
#    removes both the nftables table and bridge.
# 2. SIGTERM stops workers before drain, then removes NAT and the bridge.
# 3. When KVM assets are supplied, SIGTERM drains a live Firecracker VM,
#    releases its TAP, persists `stopped`, and does not resurrect it on restart.
#
# The drill owns one exact bridge/table, isolated ports, and a temporary data
# directory. The first two scenarios do not require KVM. Set both
# HUSKER_LINUX_SHUTDOWN_KERNEL and HUSKER_LINUX_SHUTDOWN_ROOTFS to enable the
# live-VM scenario; CI also sets HUSKER_LINUX_SHUTDOWN_REQUIRE_VM=1 so missing
# KVM/assets cannot silently turn the release gate green.

PREFIX="[linux-shutdown]"
PORT="${HUSKER_LINUX_SHUTDOWN_PORT:-17879}"
FAIL_PORT="${HUSKER_LINUX_SHUTDOWN_FAIL_PORT:-17880}"
METRICS_PORT="${HUSKER_LINUX_SHUTDOWN_METRICS_PORT:-17881}"
BRIDGE="${HUSKER_LINUX_SHUTDOWN_BRIDGE:-huskershut}"
SUBNET="${HUSKER_LINUX_SHUTDOWN_SUBNET:-198.19.253.0/30}"
CID_BASE="${HUSKER_LINUX_SHUTDOWN_CID_BASE:-900}"
NFT_TABLE="husker_${BRIDGE}"
WORK_DIR="$(mktemp -d)"
DATA_DIR="${WORK_DIR}/data"
SUCCESS_LOG="${WORK_DIR}/sigterm.log"
FAILURE_LOG="${WORK_DIR}/bind-failure.log"
LIVE_LOG="${WORK_DIR}/live-vm.log"
RESTART_LOG="${WORK_DIR}/restart.log"
DAEMON_PID=""
OCCUPIER_PID=""
VM_ID=""
VM_PID=""
VM_TAP="husker${CID_BASE}"
VM_NAME="shutdown-live-vm"

log() { echo "${PREFIX} $*"; }
fail() {
  echo "${PREFIX} ERROR: $*" >&2
  local file
  for file in "${FAILURE_LOG}" "${SUCCESS_LOG}" "${LIVE_LOG}" "${RESTART_LOG}"; do
    if [[ -s "${file}" ]]; then
      echo "${PREFIX} diagnostic log: ${file}" >&2
      sed -n '1,240p' "${file}" >&2
    fi
  done
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "requires Linux"
fi
if [[ "$(id -u)" != "0" ]]; then
  fail "requires root (bridge and nftables administration)"
fi
for command in curl ip nft pgrep python3; do
  command -v "${command}" >/dev/null || fail "missing required command: ${command}"
done
for value in "${PORT}" "${FAIL_PORT}" "${METRICS_PORT}" "${CID_BASE}"; do
  [[ "${value}" =~ ^[0-9]+$ ]] || fail "ports and CID base must be decimal integers"
done
[[ "${BRIDGE}" =~ ^husker[[:alnum:]]{1,9}$ ]] \
  || fail "bridge must match husker[[:alnum:]]{1,9} and fit Linux's 15-byte limit"

if [[ -n "${HUSKER_LINUX_DRILL_BIN:-}" ]]; then
  BIN="${HUSKER_LINUX_DRILL_BIN}"
else
  command -v cargo >/dev/null || fail "set HUSKER_LINUX_DRILL_BIN or install cargo"
  log "building Linux daemon"
  cargo build --quiet --package husker
  TARGET_DIR="${CARGO_TARGET_DIR:-target}"
  BIN="${TARGET_DIR}/debug/husker"
fi
[[ -x "${BIN}" ]] || fail "daemon binary is not executable: ${BIN}"

reset_owned_network() {
  nft delete table ip "${NFT_TABLE}" 2>/dev/null || true
  ip link delete "${VM_TAP}" 2>/dev/null || true
  ip link delete "${BRIDGE}" 2>/dev/null || true
}

cleanup() {
  if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill -TERM "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  if [[ -n "${OCCUPIER_PID}" ]] && kill -0 "${OCCUPIER_PID}" 2>/dev/null; then
    kill "${OCCUPIER_PID}" 2>/dev/null || true
    wait "${OCCUPIER_PID}" 2>/dev/null || true
  fi
  # A daemon crash could orphan its Firecracker child. Kill only the exact PID
  # whose command line still names this drill's captured VM UUID; never sweep
  # unrelated VMMs on a shared host.
  if [[ -n "${VM_PID}" && -n "${VM_ID}" && -r "/proc/${VM_PID}/cmdline" ]] \
    && tr '\0' ' ' <"/proc/${VM_PID}/cmdline" | grep -Fq "${VM_ID}"; then
    kill -KILL "${VM_PID}" 2>/dev/null || true
  fi
  reset_owned_network
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

assert_network_present() {
  ip link show "${BRIDGE}" >/dev/null 2>&1 \
    || fail "expected bridge ${BRIDGE} while daemon was running"
  nft list table ip "${NFT_TABLE}" >/dev/null 2>&1 \
    || fail "expected nftables table ${NFT_TABLE} while daemon was running"
}

assert_network_absent() {
  ! ip link show "${BRIDGE}" >/dev/null 2>&1 \
    || fail "bridge ${BRIDGE} leaked after daemon exit"
  ! nft list table ip "${NFT_TABLE}" >/dev/null 2>&1 \
    || fail "nftables table ${NFT_TABLE} leaked after daemon exit"
}

assert_vmm_absent() {
  if [[ -n "${VM_PID}" && -r "/proc/${VM_PID}/cmdline" ]] \
    && tr '\0' ' ' <"/proc/${VM_PID}/cmdline" | grep -Fq "${VM_ID}"; then
    fail "Firecracker process ${VM_PID} for ${VM_ID} survived daemon shutdown"
  fi
  if [[ -n "${VM_ID}" ]] \
    && pgrep -af '[f]irecracker' | grep -Fq "${VM_ID}"; then
    fail "a Firecracker process for ${VM_ID} survived daemon shutdown"
  fi
}

wait_for_health() {
  local port="$1"
  for _ in {1..100}; do
    curl -fsS "http://127.0.0.1:${port}/v1/health" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

json_field() {
  local field="$1"
  python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "${field}"
}

assert_log_order() {
  local file="$1"
  shift
  local previous=0
  local marker line
  for marker in "$@"; do
    line="$(awk -v marker="${marker}" -v previous="${previous}" \
      'NR > previous && index($0, marker) { print NR; exit }' "${file}")"
    [[ -n "${line}" ]] || fail "missing log marker '${marker}' in ${file}"
    (( line > previous )) \
      || fail "log marker '${marker}' was out of order in ${file}"
    previous="${line}"
  done
}

daemon_env=(
  "HUSKER_DATA_DIR=${DATA_DIR}"
  "HUSKER_RESOURCE_LIMITS=0"
  "HUSKER_SERVICE_RECONCILE_ENABLED=1"
  "HUSKER_SERVICE_RECONCILE_INTERVAL=1"
  "HUSKER_RECLAIM_GRACE_SECS=1"
  "HUSKER_BRIDGE_NAME=${BRIDGE}"
  "HUSKER_BRIDGE_SUBNET=${SUBNET}"
  "HUSKER_CID_BASE=${CID_BASE}"
  "HUSKER_METRICS_LISTEN=127.0.0.1:${METRICS_PORT}"
  "RUST_LOG=husker=info,husker_api=info,husker_net=info"
)

mkdir -p "${DATA_DIR}"
reset_owned_network
assert_network_absent

log "validating cleanup after an API bind failure"
python3 -m http.server "${FAIL_PORT}" --bind 127.0.0.1 \
  >"${WORK_DIR}/occupier.log" 2>&1 &
OCCUPIER_PID=$!
for _ in {1..50}; do
  curl -fsS "http://127.0.0.1:${FAIL_PORT}/" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${FAIL_PORT}/" >/dev/null \
  || fail "failed to occupy bind-failure port ${FAIL_PORT}"

set +e
env "${daemon_env[@]}" "${BIN}" --output text daemon --listen "127.0.0.1:${FAIL_PORT}" \
  >"${FAILURE_LOG}" 2>&1
failure_status=$?
set -e
kill "${OCCUPIER_PID}" 2>/dev/null || true
wait "${OCCUPIER_PID}" 2>/dev/null || true
OCCUPIER_PID=""

(( failure_status != 0 )) || fail "bind-failure daemon unexpectedly succeeded"
assert_network_absent
assert_log_order "${FAILURE_LOG}" \
  "stopping daemon background workers" \
  "daemon background workers stopped" \
  "shutting down, draining VMs" \
  "removing nftables table" \
  "deleting bridge"
grep -Fq "serving daemon API" "${FAILURE_LOG}" \
  || fail "bind failure did not retain daemon API context"
log "bind-failure cleanup passed"

log "validating SIGTERM ordering and cleanup"
rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"
env "${daemon_env[@]}" "${BIN}" --output text daemon --listen "127.0.0.1:${PORT}" \
  >"${SUCCESS_LOG}" 2>&1 &
DAEMON_PID=$!
wait_for_health "${PORT}" \
  || fail "daemon did not become healthy"
curl -fsS "http://127.0.0.1:${METRICS_PORT}/v1/metrics" >/dev/null \
  || fail "metrics endpoint did not become healthy"
assert_network_present

kill -TERM "${DAEMON_PID}"
wait "${DAEMON_PID}" || fail "daemon returned failure after SIGTERM"
DAEMON_PID=""

assert_network_absent
assert_log_order "${SUCCESS_LOG}" \
  "shutdown signal received" \
  "stopping daemon background workers" \
  "daemon background workers stopped" \
  "shutting down, draining VMs" \
  "removing nftables table" \
  "deleting bridge"
! curl -fsS "http://127.0.0.1:${METRICS_PORT}/v1/metrics" >/dev/null 2>&1 \
  || fail "metrics endpoint remained reachable after shutdown"

log "PASS: bind failure and SIGTERM both stopped workers, drained, and removed ${NFT_TABLE}/${BRIDGE}"

KERNEL="${HUSKER_LINUX_SHUTDOWN_KERNEL:-}"
ROOTFS="${HUSKER_LINUX_SHUTDOWN_ROOTFS:-}"
INITRD="${HUSKER_LINUX_SHUTDOWN_INITRD:-}"
REQUIRE_VM="${HUSKER_LINUX_SHUTDOWN_REQUIRE_VM:-0}"
if [[ -z "${KERNEL}" || -z "${ROOTFS}" ]]; then
  [[ "${REQUIRE_VM}" != "1" ]] \
    || fail "live-VM drill required but kernel/rootfs paths were not both supplied"
  log "SKIP: live-VM drain (set HUSKER_LINUX_SHUTDOWN_KERNEL and HUSKER_LINUX_SHUTDOWN_ROOTFS)"
  exit 0
fi
[[ -r /dev/kvm ]] || fail "live-VM drill requires readable /dev/kvm"
command -v firecracker >/dev/null || fail "live-VM drill requires firecracker on PATH"
[[ -f "${KERNEL}" ]] || fail "kernel not found: ${KERNEL}"
[[ -f "${ROOTFS}" ]] || fail "rootfs not found: ${ROOTFS}"
[[ -z "${INITRD}" || -f "${INITRD}" ]] || fail "initrd not found: ${INITRD}"

log "validating SIGTERM drain of a live Firecracker VM"
rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"
env "${daemon_env[@]}" "${BIN}" --output text daemon --listen "127.0.0.1:${PORT}" \
  >"${LIVE_LOG}" 2>&1 &
DAEMON_PID=$!
wait_for_health "${PORT}" || fail "live-VM daemon did not become healthy"

create_body="$({
  python3 -c 'import json, sys
body = {
    "name": sys.argv[1], "kernel_path": sys.argv[2], "rootfs_path": sys.argv[3],
    "vcpu_count": 1, "mem_size_mib": 256,
}
if sys.argv[4]:
    body["initrd_path"] = sys.argv[4]
print(json.dumps(body))' "${VM_NAME}" "${KERNEL}" "${ROOTFS}" "${INITRD}"
})"
vm_json="$(curl -fsS -H 'Content-Type: application/json' -d "${create_body}" \
  "http://127.0.0.1:${PORT}/v1/vms")" \
  || fail "failed to create live VM"
VM_ID="$(json_field id <<<"${vm_json}")"
VM_PID="$(json_field pid <<<"${vm_json}")"
vm_cid="$(json_field vsock_cid <<<"${vm_json}")"
VM_TAP="husker${vm_cid}"
[[ "$(json_field state <<<"${vm_json}")" == "running" ]] \
  || fail "created VM was not running"
[[ "${VM_PID}" =~ ^[0-9]+$ && -r "/proc/${VM_PID}/cmdline" ]] \
  || fail "created VM did not expose a live VMM pid"
tr '\0' ' ' <"/proc/${VM_PID}/cmdline" | grep -Fq "${VM_ID}" \
  || fail "recorded VMM pid did not belong to ${VM_ID}"
ip link show "${VM_TAP}" >/dev/null 2>&1 \
  || fail "expected live VM TAP ${VM_TAP}"

kill -TERM "${DAEMON_PID}"
wait "${DAEMON_PID}" || fail "live-VM daemon returned failure after SIGTERM"
DAEMON_PID=""
assert_vmm_absent
! ip link show "${VM_TAP}" >/dev/null 2>&1 \
  || fail "VM TAP ${VM_TAP} leaked after daemon shutdown"
assert_network_absent
assert_log_order "${LIVE_LOG}" \
  "shutdown signal received" \
  "stopping daemon background workers" \
  "daemon background workers stopped" \
  "shutting down, draining VMs" \
  "draining VM" \
  "drained VMs on shutdown" \
  "released VM host resources during shutdown" \
  "removing nftables table" \
  "deleting bridge"

log "validating persisted stopped state after daemon restart"
env "${daemon_env[@]}" "${BIN}" --output text daemon --listen "127.0.0.1:${PORT}" \
  >"${RESTART_LOG}" 2>&1 &
DAEMON_PID=$!
wait_for_health "${PORT}" || fail "restart daemon did not become healthy"
restarted_vm="$(curl -fsS "http://127.0.0.1:${PORT}/v1/vms/${VM_NAME}")" \
  || fail "drained VM record was missing after restart"
[[ "$(json_field state <<<"${restarted_vm}")" == "stopped" ]] \
  || fail "drained VM did not remain stopped after restart"
assert_vmm_absent
! ip link show "${VM_TAP}" >/dev/null 2>&1 \
  || fail "drained VM TAP ${VM_TAP} was recreated on restart"

kill -TERM "${DAEMON_PID}"
wait "${DAEMON_PID}" || fail "restart daemon returned failure after SIGTERM"
DAEMON_PID=""
assert_network_absent
log "PASS: live VM drained, VMM/TAP removed, stopped state survived restart"
