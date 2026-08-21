#!/usr/bin/env bash
# Resolve every published kernel configuration without compiling the kernel.
# This catches renamed symbols and unmet Kconfig dependencies on pull requests;
# the image workflow still performs the complete architecture-specific builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$(mktemp -d /tmp/husker-kernel-config-test.XXXXXX)"
OUT_DIR="$(mktemp -d /tmp/husker-kernel-config-out.XXXXXX)"
cleanup() { rm -rf "$WORK_DIR" "$OUT_DIR"; }
trap cleanup EXIT

resolve() {
    local arch="$1" extra_fragment="${2:-}"
    local label="$arch"
    local fragment_env=()
    if [[ -n "$extra_fragment" ]]; then
        label="$arch + ${extra_fragment##*/}"
        fragment_env=(HUSKER_KERNEL_CONFIG_FRAGMENT="$extra_fragment")
    fi

    echo "==> Resolving $label"
    env "${fragment_env[@]}" \
        ARCH="$arch" \
        WORK_DIR="$WORK_DIR" \
        HUSKER_KERNEL_OUT="$OUT_DIR" \
        HUSKER_KERNEL_CONFIG_ONLY=1 \
        bash "$SCRIPT_DIR/build-microvm-kernel.sh"
}

resolve x86_64
resolve aarch64
resolve x86_64 "$SCRIPT_DIR/k3s-kernel.config"

echo "PASS: x86_64, aarch64, and k3s kernel configurations resolved"
