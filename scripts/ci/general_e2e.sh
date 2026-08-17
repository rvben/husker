#!/usr/bin/env bash
set -euo pipefail

# End-to-end gate for the general husker daemon contract: boot real Firecracker
# VMs through the REST API and exercise the full guest lifecycle - create/list/
# get/destroy, exec (env + exit codes), file transfer, interactive shell, serial
# logs, and suspend/resume/fork (crates/husker/tests/e2e.rs, the #[ignore]d
# linux e2e suite).
#
# These tests drive an already-running daemon over HTTP. Historically they
# assumed one on 127.0.0.1:7777, which collides with a production daemon on the
# same host; the suite now honours HUSKER_E2E_API_URL, so this script stands up
# an ISOLATED daemon (own bridge/subnet/CID range, temp data dir, high port) and
# points the tests at it. Safe to run alongside a production daemon.
#
# Requires Linux with KVM + Firecracker, the x86_64-musl target + musl-gcc for
# the embedded agent, and privileges for TAP/Firecracker (run as root).
#
# Run via: HUSKER_RUN_IGNORED_E2E=1 bash scripts/ci/general_e2e.sh

PORT="${HUSKER_GENERAL_E2E_PORT:-17801}"
BASE="http://127.0.0.1:${PORT}"
DATA_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
LOG="$(mktemp)"
PID=""
BRIDGE="huskergene2e"
CID_BASE=220
ROOTFS_COPY="${WORK}/rootfs.ext4"

log() { echo "[general-e2e] $*"; }

# Remove this run's isolated bridge and any TAP devices in its own CID range.
# Scoped to CID_BASE..CID_BASE+15 so it only touches names this run owns - never
# husker0 or a live production TAP. A bridge delete does not cascade to its TAPs,
# and a SIGKILL skips the EXIT trap, so a stranded TAP would fail the next run's
# `ip tuntap add`. Run defensively at startup and again on exit; idempotent.
reset_net() {
  ip link delete "${BRIDGE}" 2>/dev/null || true
  local cid
  for cid in $(seq "${CID_BASE}" "$((CID_BASE + 15))"); do
    ip link delete "husker${cid}" 2>/dev/null || true
  done
}

cleanup() {
  if [[ -n "${PID}" ]]; then
    # SIGTERM -> the daemon drains VMs and tears down its own bridge + TAPs + NAT.
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true
  fi
  reset_net
  rm -rf "${DATA_DIR}" "${WORK}"
  rm -f "${LOG}"
}
trap cleanup EXIT

# 1. Resolve kernel/rootfs/initrd. Prefer explicit HUSKER_E2E_* overrides (the CI
#    workflow sets them from the images release); otherwise fall back to the
#    daemon's default image locations on the host.
KERNEL="${HUSKER_E2E_KERNEL:-/var/lib/husker/kernels/vmlinux}"
ROOTFS_SRC="${HUSKER_E2E_ROOTFS:-/var/lib/husker/images/alpine-x86_64.ext4}"
INITRD="${HUSKER_E2E_INITRD:-/var/lib/husker/kernels/initramfs-x86_64-virt.gz}"
[[ -f "${KERNEL}" ]]     || { echo "kernel not found: ${KERNEL}" >&2; exit 1; }
[[ -f "${ROOTFS_SRC}" ]] || { echo "rootfs not found: ${ROOTFS_SRC}" >&2; exit 1; }

# The daemon clones the rootfs copy-on-write per VM and never mutates the source,
# but some suite tests write into their clone; use a disposable copy regardless.
cp "${ROOTFS_SRC}" "${ROOTFS_COPY}"

# 2. Build the x86_64-musl agent and the daemon embedding it.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${PWD}/${TARGET_DIR}"
fi
AGENT="${TARGET_DIR}/x86_64-unknown-linux-musl/agent/husker-agent"
log "building x86_64-musl guest agent"
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${X86_64_MUSL_LINKER:-musl-gcc}" \
  cargo build --quiet --package husker-agent --profile agent --target x86_64-unknown-linux-musl
log "building daemon (re-embeds the agent)"
HUSKER_EMBED_AGENT_BIN="${AGENT}" cargo build --quiet --package husker
H="${TARGET_DIR}/debug/husker"
[[ -x "${H}" ]] || { echo "expected ${H} after build" >&2; exit 1; }
"${H}" --output json capabilities | grep -Eq '"embedded_agent"[[:space:]]*:[[:space:]]*true' || {
  echo "${H} does not report an embedded guest agent" >&2
  exit 1
}

# 3. Start an isolated daemon (own bridge/subnet/CID range, temp data dir + port).
# Defensively clear anything a prior aborted run left behind so reruns start clean.
reset_net
log "starting isolated daemon on ${BASE} (bridge ${BRIDGE})"
# The isolated e2e daemon does no resource enforcement; disable it so it does not
# fail cgroup setup inside the CI runner's service scope (which has no io
# controller delegated: "cgroup.subtree_control: Device or resource busy").
HUSKER_RESOURCE_LIMITS=0 \
HUSKER_DATA_DIR="${DATA_DIR}" HUSKER_DEFAULT_KERNEL="${KERNEL}" \
  HUSKER_BRIDGE_NAME="${BRIDGE}" \
  HUSKER_BRIDGE_SUBNET="172.31.0.0/24" \
  HUSKER_CID_BASE="${CID_BASE}" \
  RUST_LOG="${RUST_LOG:-husker=info,husker_api=info}" \
  "${H}" daemon --listen "127.0.0.1:${PORT}" >"${LOG}" 2>&1 &
PID=$!
for _ in {1..50}; do curl -fsS "${BASE}/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "${BASE}/v1/health" >/dev/null || { echo "daemon did not become healthy" >&2; cat "${LOG}" >&2; exit 1; }

# 4. Run the general e2e suite against the isolated daemon. Keep the embedded
# agent input identical to the daemon build above: crates/husker/build.rs tracks
# this variable, so dropping it here would invalidate and rebuild the workspace
# immediately before the tests despite using the same source and target dir.
log "running the general husker e2e suite against ${BASE}"
HUSKER_RUN_IGNORED_E2E=1 \
HUSKER_E2E_API_URL="${BASE}" \
HUSKER_E2E_KERNEL="${KERNEL}" \
HUSKER_E2E_ROOTFS="${ROOTFS_COPY}" \
HUSKER_E2E_INITRD="${INITRD}" \
HUSKER_EMBED_AGENT_BIN="${AGENT}" \
  cargo test --package husker --test e2e -- --ignored --test-threads=1

log "PASS: general husker e2e suite green against the isolated daemon"
