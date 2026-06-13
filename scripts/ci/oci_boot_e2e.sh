#!/usr/bin/env bash
set -euo pipefail

# End-to-end gate for the OCI-native sandbox keystone: import a Docker/OCI image
# and boot it as an agent-supervised husker microVM, then assert the full guest
# contract. Validates, on a real Firecracker VM:
#   * import-oci produces a bootable rootfs (agent injected, boot_init set)
#   * the kernel boots the agent as PID 1 (init=/usr/local/bin/husker-agent)
#   * the supervisor mounts /proc, configures networking, and spawns the agent
#     as a restartable child
#   * the agent is reachable over vsock (exec works)
#   * an agent-child crash is recovered (the VM survives)
#
# Requires Linux with KVM + Firecracker, the x86_64-musl target + musl-gcc, and
# sufficient privileges for TAP/Firecracker (run as root or with KVM/TAP perms).
# A built-in-driver kernel (vsock/virtio =y) is fetched from the latest images
# release unless HUSKER_E2E_KERNEL points at one.
#
# Run via: HUSKER_RUN_OCI_BOOT_E2E=1 make test-oci-boot-e2e-gated

PORT="${HUSKER_OCI_E2E_PORT:-17799}"
BASE="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
LOG="$(mktemp)"
PID=""
VM="ocie2e-$$"
IMG="ocie2e-alpine-$$"

log() { echo "[oci-boot-e2e] $*"; }

cleanup() {
  if [[ -n "${PID}" ]]; then
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  # Remove any test TAP devices left behind (keep the husker0 bridge).
  for t in $(ip -br link show 2>/dev/null | grep -oE '^husker[0-9]+' | grep -v '^husker0$'); do
    ip link delete "${t}" 2>/dev/null || true
  done
  rm -rf "${DATA_DIR}" "${WORK}"
  rm -f "${LOG}"
}
trap cleanup EXIT

# 1. Resolve a built-in-driver kernel.
KERNEL="${HUSKER_E2E_KERNEL:-}"
if [[ -z "${KERNEL}" ]]; then
  log "resolving the latest images-* release kernel"
  TAG="$(curl -fsSL 'https://api.github.com/repos/rvben/husker/releases?per_page=100' \
         | grep -oE 'images-[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u | tail -1)"
  [[ -n "${TAG}" ]] || { echo "could not find an images-* release" >&2; exit 1; }
  KERNEL="${WORK}/kernel"
  curl -fsSL "https://github.com/rvben/husker/releases/download/${TAG}/kernel-x86_64" -o "${KERNEL}"
  log "using kernel from ${TAG}"
fi

# 2. Build the x86_64-musl agent and the daemon embedding it.
log "building x86_64-musl guest agent"
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${X86_64_MUSL_LINKER:-musl-gcc}" \
  cargo build --quiet --package husker-agent --profile agent --target x86_64-unknown-linux-musl
log "building daemon (re-embeds the agent)"
cargo build --quiet --package husker
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
H="${TARGET_DIR}/debug/husker"
[[ -x "${H}" ]] || { echo "expected ${H} after build" >&2; exit 1; }

# 3. Start the daemon.
log "starting daemon on ${BASE}"
HUSKER_DATA_DIR="${DATA_DIR}" HUSKER_DEFAULT_KERNEL="${KERNEL}" \
  RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
  "${H}" daemon --listen "127.0.0.1:${PORT}" >"${LOG}" 2>&1 &
PID=$!
for _ in {1..50}; do curl -fsS "${BASE}/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "${BASE}/v1/health" >/dev/null || { echo "daemon did not become healthy" >&2; cat "${LOG}" >&2; exit 1; }

C() { "${H}" --api-url "${BASE}" "$@"; }

# 4. Import alpine as an OCI image (this sets boot_init=agent).
log "importing OCI image: alpine"
C image import-oci alpine --name "${IMG}" >/dev/null
ROOTFS="${DATA_DIR}/images/catalog/${IMG}.ext4"
[[ -f "${ROOTFS}" ]] || { echo "import did not produce ${ROOTFS}" >&2; exit 1; }

# 5. Boot it and wait for the agent (the supervisor's child) to be reachable.
log "booting ${VM} from the imported image"
C run --name "${VM}" "${ROOTFS}" --cpus 1 --memory 256 >/dev/null
ready=0
for _ in {1..60}; do
  if C exec "${VM}" -- true >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
if [[ "${ready}" != 1 ]]; then
  echo "agent did not become reachable; serial log:" >&2
  C logs "${VM}" --source serial -n 200 >&2 || true
  exit 1
fi

# 6. Assert supervisor mode + the guest contract. The supervisor-mode proof is
#    the guest contract itself: the kernel does not mount /proc, so /proc being
#    mounted means the agent ran as the init supervisor (not plain agent mode).
log "asserting supervisor mode and guest contract"
OUT="$(C exec "${VM}" -- sh -c 'test -r /proc/cmdline && echo PROC_OK; ip -4 route 2>/dev/null | grep -q "^default" && echo ROUTE_OK; echo "ALPINE $(cat /etc/alpine-release 2>/dev/null)"')"
echo "${OUT}" | grep -q PROC_OK  || { echo "/proc not mounted: agent did not run as the init supervisor" >&2; C logs "${VM}" --source serial -n 200 >&2 || true; exit 1; }
echo "${OUT}" | grep -q ROUTE_OK || { echo "no default route in the guest" >&2; exit 1; }
log "guest: ${OUT//$'\n'/ }"

# 7. Agent-child crash recovery: kill the agent child (the exec shell's parent),
#    then confirm the supervisor restarted it so the VM is still usable.
log "asserting agent-child crash recovery"
C exec "${VM}" -- sh -c 'kill -9 $PPID' >/dev/null 2>&1 || true
recovered=0
for _ in {1..30}; do
  if C exec "${VM}" -- echo ok >/dev/null 2>&1; then recovered=1; break; fi
  sleep 0.5
done
[[ "${recovered}" == 1 ]] || { echo "supervisor did not restart the agent child" >&2; exit 1; }

C destroy "${VM}" --yes >/dev/null 2>&1 || true
log "PASS: OCI image imported, booted agent-as-PID-1 supervisor, contract + child recovery OK"
