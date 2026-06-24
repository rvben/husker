#!/usr/bin/env bash
set -euo pipefail

# The daemon shells out to `nft`, `ip`, and `firecracker`; ensure the standard
# admin dirs are on PATH even when invoked with a minimal/sudo-stripped PATH.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:${PATH:-/usr/bin:/bin}"

# End-to-end gate for hot pools on a real Firecracker VM:
#   * create a pool (boot a template from the default images, warm it to
#     agent-ready, suspend it to disk)
#   * check out TWO members CONCURRENTLY: each a fresh RUNNING VM with a distinct
#     network identity (guest IP + vsock CID), both reachable at the same time
#
# This is the 1:N path the single-fork suspend-fork gate cannot reach: it
# exercises FC `vsock_override` so concurrent forks of one snapshot do not
# collide on the host vsock socket. Requires Linux + KVM + Firecracker >= 1.16.0
# + TAP privileges (run as root). Kernel/rootfs/initramfs come from the latest
# images-* release unless HUSKER_E2E_KERNEL/ROOTFS/INITRD point at local files.
#
# Runs on its own bridge/subnet/CID range and a temp data dir + port, so it is
# safe to run alongside a production daemon on the same host.
#
# Run via: HUSKER_RUN_POOL_E2E=1 make test-pool-e2e-gated

PORT="${HUSKER_POOL_E2E_PORT:-17802}"
BASE="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
LOG="$(mktemp)"
PID=""
BRIDGE="huskerpe2e"
POOL="pe2e-$$"
A="pe2e-a-$$"
B="pe2e-b-$$"

log() { echo "[pool-e2e] $*"; }

cleanup() {
  if [[ -n "${PID}" ]]; then
    # SIGTERM -> the daemon drains VMs and tears down its own bridge + NAT.
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  # Best-effort: only ever touch THIS run's isolated bridge, never husker0.
  ip link delete "${BRIDGE}" 2>/dev/null || true
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
  # Authenticate the GitHub API call when a token is present (CI sets GITHUB_TOKEN)
  # to dodge the 60/hr unauthenticated rate limit.
  gh_auth=()
  [[ -n "${GITHUB_TOKEN:-}" ]] && gh_auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  TAG="$(curl -fsSL "${gh_auth[@]}" 'https://api.github.com/repos/rvben/husker/releases?per_page=100' \
         | grep -oE 'images-[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u | tail -1)"
  [[ -n "${TAG}" ]] || { echo "could not find an images-* release" >&2; exit 1; }
  log "using images from ${TAG}"
  url="https://github.com/rvben/husker/releases/download/${TAG}"
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

# 3. Start an isolated daemon (own bridge/subnet/CID range, temp data dir + port).
log "starting isolated daemon on ${BASE} (bridge ${BRIDGE})"
HUSKER_DATA_DIR="${DATA_DIR}" \
  HUSKER_DEFAULT_KERNEL="${KERNEL}" \
  HUSKER_BRIDGE_NAME="${BRIDGE}" \
  HUSKER_BRIDGE_SUBNET="172.26.0.0/24" \
  HUSKER_CID_BASE="260" \
  RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
  "${H}" daemon --listen "127.0.0.1:${PORT}" >"${LOG}" 2>&1 &
PID=$!
for _ in {1..50}; do curl -fsS "${BASE}/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "${BASE}/v1/health" >/dev/null || { echo "daemon did not become healthy" >&2; cat "${LOG}" >&2; exit 1; }

C() { "${H}" --api-url "${BASE}" "$@"; }
api() { curl -fsS "${BASE}$1" "${@:2}"; }
checkout() {
  api "/v1/pools/${POOL}/checkout" -X POST -H 'content-type: application/json' -d "{\"vm_name\":\"$1\"}"
}

# 4. Create the pool: boot a template, warm it to agent-ready, suspend it.
log "creating pool ${POOL}"
init_arg=(); [[ -n "${INITRD}" ]] && init_arg=(--initrd "${INITRD}")
C pool create "${POOL}" "${ROOTFS}" --kernel "${KERNEL}" "${init_arg[@]}" --memory 512 >/dev/null
[[ "$(api "/v1/pools/${POOL}" | json_str name)" == "${POOL}" ]] || { echo "pool not created" >&2; exit 1; }

# 5. Check out member A.
log "checkout ${A}"
a_json="$(checkout "${A}")"
A_IP="$(printf '%s' "${a_json}" | json_str guest_ip)"
A_CID="$(printf '%s' "${a_json}" | json_num vsock_cid)"
[[ "$(printf '%s' "${a_json}" | json_str state)" == running ]] || { echo "A not running: ${a_json}" >&2; exit 1; }

# 6. Check out member B WHILE A is still running (the 1:N concurrency the
#    single-fork path could not do without colliding on the vsock socket).
log "checkout ${B} (concurrent with ${A})"
b_json="$(checkout "${B}")"
B_IP="$(printf '%s' "${b_json}" | json_str guest_ip)"
B_CID="$(printf '%s' "${b_json}" | json_num vsock_cid)"
[[ "$(printf '%s' "${b_json}" | json_str state)" == running ]] \
  || { echo "B not running (concurrent checkout failed): ${b_json}" >&2; exit 1; }

# 7. The two members have distinct identities and coexist.
[[ -n "${A_IP}" && -n "${B_IP}" && "${A_IP}" != "${B_IP}" ]] \
  || { echo "members must get distinct IPs (a=${A_IP} b=${B_IP})" >&2; exit 1; }
[[ -n "${A_CID}" && -n "${B_CID}" && "${A_CID}" != "${B_CID}" ]] \
  || { echo "members must get distinct CIDs (a=${A_CID} b=${B_CID})" >&2; exit 1; }
log "two members coexist: A=${A_IP}/cid${A_CID}  B=${B_IP}/cid${B_CID}"

# 8. Both are reachable at the same time, each carrying its own IP on eth0.
for entry in "${A}:${A_IP}" "${B}:${B_IP}"; do
  vm="${entry%%:*}"; ip="${entry##*:}"
  rdy=0
  for _ in {1..60}; do C exec "${vm}" -- true >/dev/null 2>&1 && { rdy=1; break; }; sleep 0.5; done
  [[ "${rdy}" == 1 ]] || { echo "${vm} agent not reachable" >&2; C logs "${vm}" --source serial -n 100 >&2 || true; exit 1; }
  C exec "${vm}" -- sh -c "ip -4 addr show eth0 | grep -qw ${ip}" >/dev/null \
    || { echo "${vm} eth0 does not carry its IP ${ip}" >&2; exit 1; }
done

# 9. The pool is listed; cleanup.
api "/v1/pools" | grep -q "\"${POOL}\"" || { echo "pool missing from list" >&2; exit 1; }
C destroy "${A}" --yes >/dev/null 2>&1 || true
C destroy "${B}" --yes >/dev/null 2>&1 || true
C pool delete "${POOL}" >/dev/null 2>&1 || true
log "PASS: pool with concurrent 1:N checkout (distinct identities, both reachable) verified on real Firecracker"
