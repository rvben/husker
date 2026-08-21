#!/usr/bin/env bash
# Build a Firecracker-compatible kernel with k3s (Kubernetes) support.
#
# Layers Kubernetes networking features over the same modules-free kernel and
# container-runtime configuration shipped as Husker's default. Keeping one
# builder prevents the Docker and k3s kernels from drifting apart.
#
# Requires: build-essential, flex, bison, libelf-dev, bc, libssl-dev, curl, xz
# Usage:  sudo ./guest/build-k3s-kernel.sh [output_vmlinux] [kernel_version]

set -euo pipefail

OUTPUT="${1:-/mnt/husker/vmlinux-k3s}"
KERNEL_VERSION="${2:-${KERNEL_VERSION:-6.12.93}}"
ARCH="${ARCH:-x86_64}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$(mktemp -d /tmp/husker-k3s-kernel.XXXXXX)"
cleanup() { rm -rf "$OUT_DIR"; }
trap cleanup EXIT

echo "==> Building Firecracker kernel ${KERNEL_VERSION} with k3s support"
echo "    Output: $OUTPUT"

# Install build dependencies
echo "==> Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential flex bison libelf-dev bc libssl-dev curl xz-utils 2>&1 | tail -3

kernel_sha=()
if [ "$KERNEL_VERSION" != 6.12.93 ]; then
    # The shared builder pins the release kernel checksum. Custom versions are
    # an explicit operator choice and cannot use that checksum.
    kernel_sha=(KERNEL_SHA256=skip)
fi

env "${kernel_sha[@]}" \
    ARCH="$ARCH" \
    KERNEL_VERSION="$KERNEL_VERSION" \
    HUSKER_KERNEL_OUT="$OUT_DIR" \
    HUSKER_KERNEL_CONFIG_FRAGMENT="$SCRIPT_DIR/k3s-kernel.config" \
    bash "$SCRIPT_DIR/build-microvm-kernel.sh"

case "$ARCH" in
    x86_64) built="$OUT_DIR/vmlinux" ;;
    aarch64) built="$OUT_DIR/Image-virt" ;;
    *) echo "ERROR: unsupported arch $ARCH" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$OUTPUT")"
cp "$built" "$OUTPUT"

echo "==> Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo "To use this kernel:"
echo "  husker run --kernel $OUTPUT --name myvm rootfs.ext4"
