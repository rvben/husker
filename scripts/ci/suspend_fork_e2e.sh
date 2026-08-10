#!/usr/bin/env bash
set -euo pipefail

# The daemon shells out to `nft`, `ip`, and `firecracker`; ensure the standard
# admin dirs are on PATH even when invoked with a minimal/sudo-stripped PATH.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:${PATH:-/usr/bin:/bin}"

# End-to-end gate for suspend + fork on a real Firecracker VM:
#   * create a VM from the default images and wait for its agent
#   * suspend it (full-state snapshot, memory freed)
#   * fork the suspended VM -> a new RUNNING VM with a FRESH network identity
#     (distinct guest IP and vsock CID), its agent reachable on the re-homed NIC
#   * the source stays suspended (source and fork coexist)
#
# Exercises FC snapshot -> CoW reflink clone -> `/snapshot/load` with
# `network_overrides` -> live netlink reconfigure, which mock-based unit tests
# cannot reach. Requires Linux with KVM, Firecracker >= 1.12.0, and TAP
# privileges (run as root). Kernel/rootfs/initramfs are fetched from the latest
# images-* release unless HUSKER_E2E_KERNEL/ROOTFS/INITRD point at local files.
#
# Runs on its own bridge/subnet/CID range and a temp data dir + port, so it is
# safe to run alongside a production daemon on the same host.
#
# Run via: HUSKER_RUN_SUSPEND_FORK_E2E=1 make test-suspend-fork-e2e-gated

PORT="${HUSKER_SUSPEND_FORK_E2E_PORT:-17801}"
BASE="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
LOG="$(mktemp)"
PID=""
BRIDGE="huskersfe2e"
CID_BASE=200
SRC="sfe2e-src-$$"
CHILD="sfe2e-child-$$"

log() { echo "[suspend-fork-e2e] $*"; }

# Remove this run's isolated bridge and any TAP devices in its own CID range.
# Idempotent and scoped to this e2e's range (CID_BASE..CID_BASE+9) - it never
# touches husker0 or the production runner TAPs. A bridge delete does NOT cascade
# to its TAPs, and a SIGKILL (e.g. the host running out of disk) skips the EXIT
# trap, so a stranded TAP from a prior run would fail this run's `ip tuntap add`
# with "Device or resource busy". Run defensively at startup and again on exit.
reset_net() {
  ip link delete "${BRIDGE}" 2>/dev/null || true
  local cid
  for cid in $(seq "${CID_BASE}" "$((CID_BASE + 9))"); do
    ip link delete "husker${cid}" 2>/dev/null || true
  done
}

cleanup() {
  if [[ -n "${PID}" ]]; then
    # SIGTERM -> the daemon drains VMs and tears down its own bridge + NAT.
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  reset_net
  rm -rf "${DATA_DIR}" "${WORK}"
  rm -f "${LOG}"
}
trap cleanup EXIT

# Minimal JSON field readers (no jq dependency on the runner).
json_str() { grep -oE "\"$1\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }
json_num() { grep -oE "\"$1\":[0-9]+" | head -1 | grep -oE '[0-9]+'; }

# 1. Resolve kernel + rootfs + initramfs (latest images-* release unless overridden).
KERNEL="${HUSKER_E2E_KERNEL:-}"
ROOTFS="${HUSKER_E2E_ROOTFS:-}"
INITRD="${HUSKER_E2E_INITRD:-}"
if [[ -z "${KERNEL}" || -z "${ROOTFS}" || -z "${INITRD}" ]]; then
  log "resolving the latest images-* release"
  url="$(bash "$(dirname "${BASH_SOURCE[0]}")/resolve-images-tag.sh" --url)"
  log "using images from ${url##*/}"
  [[ -n "${KERNEL}" ]] || { KERNEL="${WORK}/kernel"; curl -fsSL "${url}/kernel-x86_64" -o "${KERNEL}"; }
  [[ -n "${ROOTFS}" ]] || { ROOTFS="${WORK}/rootfs.ext4"; curl -fsSL "${url}/rootfs-x86_64.ext4" -o "${ROOTFS}"; }
  [[ -n "${INITRD}" ]] || { INITRD="${WORK}/initramfs.gz"; curl -fsSL "${url}/initramfs-x86_64.gz" -o "${INITRD}"; }
fi

# 2. Build the daemon.
log "building daemon"
cargo build --quiet --package husker
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
H="${TARGET_DIR}/debug/husker"
[[ -x "${H}" ]] || { echo "expected ${H} after build" >&2; exit 1; }

# 3. Start an isolated daemon (own bridge/subnet/CID range, temp data dir + port),
#    so it never collides with any production daemon on this host.
# Defensively clear anything a prior aborted run left behind so reruns start clean.
reset_net
log "starting isolated daemon on ${BASE} (bridge ${BRIDGE})"
# The isolated e2e daemon does no resource enforcement; disable it so it does not
# fail cgroup setup inside the CI runner's service scope (which has no io
# controller delegated: "cgroup.subtree_control: Device or resource busy").
HUSKER_RESOURCE_LIMITS=0 \
HUSKER_DATA_DIR="${DATA_DIR}" \
  HUSKER_DEFAULT_KERNEL="${KERNEL}" \
  HUSKER_BRIDGE_NAME="${BRIDGE}" \
  HUSKER_BRIDGE_SUBNET="172.31.0.0/24" \
  HUSKER_CID_BASE="${CID_BASE}" \
  RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
  "${H}" daemon --listen "127.0.0.1:${PORT}" >"${LOG}" 2>&1 &
PID=$!
for _ in {1..50}; do curl -fsS "${BASE}/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "${BASE}/v1/health" >/dev/null || { echo "daemon did not become healthy" >&2; cat "${LOG}" >&2; exit 1; }

C() { "${H}" --api-url "${BASE}" "$@"; }
api() { curl -fsS "${BASE}$1" "${@:2}"; }

# 4. Create the source VM and wait for the agent.
log "creating source VM ${SRC}"
init_arg=(); [[ -n "${INITRD}" ]] && init_arg=(--initrd "${INITRD}")
C run --name "${SRC}" "${ROOTFS}" --kernel "${KERNEL}" "${init_arg[@]}" --cpus 1 --memory 512 >/dev/null
ready=0
for _ in {1..60}; do C exec "${SRC}" -- true >/dev/null 2>&1 && { ready=1; break; }; sleep 0.5; done
[[ "${ready}" == 1 ]] || { echo "source agent not reachable" >&2; C logs "${SRC}" --source serial -n 100 >&2 || true; exit 1; }

src_json="$(api "/v1/vms/${SRC}")"
SRC_IP="$(printf '%s' "${src_json}" | json_str guest_ip)"
SRC_CID="$(printf '%s' "${src_json}" | json_num vsock_cid)"
log "source up: ip=${SRC_IP} cid=${SRC_CID}"

# 5. Suspend the source.
log "suspending ${SRC}"
api "/v1/vms/${SRC}/suspend" -X POST >/dev/null
state="$(api "/v1/vms/${SRC}" | json_str state)"
[[ "${state}" == suspended ]] || { echo "source not suspended (got ${state})" >&2; exit 1; }

# 6. Fork the suspended source.
log "forking ${SRC} -> ${CHILD}"
fork_json="$(api "/v1/vms/${SRC}/fork" -X POST -H 'content-type: application/json' \
            -d "{\"fork_name\":\"${CHILD}\"}")"
fork_state="$(printf '%s' "${fork_json}" | json_str state)"
FORK_IP="$(printf '%s' "${fork_json}" | json_str guest_ip)"
FORK_CID="$(printf '%s' "${fork_json}" | json_num vsock_cid)"
[[ "${fork_state}" == running ]] || { echo "fork not running: ${fork_json}" >&2; exit 1; }
[[ -n "${FORK_IP}" && "${FORK_IP}" != "${SRC_IP}" ]] || { echo "fork must get a fresh IP (src=${SRC_IP} fork=${FORK_IP})" >&2; exit 1; }
[[ -n "${FORK_CID}" && "${FORK_CID}" != "${SRC_CID}" ]] || { echo "fork must get a fresh CID (src=${SRC_CID} fork=${FORK_CID})" >&2; exit 1; }
log "fork up with fresh identity: ip=${FORK_IP} cid=${FORK_CID}"

# 7. The fork is a live, reachable guest whose eth0 carries its fresh IP.
fready=0
for _ in {1..60}; do C exec "${CHILD}" -- true >/dev/null 2>&1 && { fready=1; break; }; sleep 0.5; done
[[ "${fready}" == 1 ]] || { echo "fork agent not reachable" >&2; C logs "${CHILD}" --source serial -n 100 >&2 || true; exit 1; }
C exec "${CHILD}" -- sh -c "ip -4 addr show eth0 | grep -qw ${FORK_IP}" >/dev/null \
  || { echo "fork eth0 does not carry its fresh IP ${FORK_IP}" >&2; exit 1; }

# 8. Source and fork coexist: the source stays suspended.
state="$(api "/v1/vms/${SRC}" | json_str state)"
[[ "${state}" == suspended ]] || { echo "source must stay suspended after fork (got ${state})" >&2; exit 1; }

# 9. Cleanup.
C destroy "${CHILD}" --yes >/dev/null 2>&1 || true
C destroy "${SRC}" --yes >/dev/null 2>&1 || true
log "PASS: suspend + fork with a fresh network identity verified on real Firecracker"
