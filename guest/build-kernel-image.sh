#!/bin/bash
# Build an uncompressed kernel image suitable for Apple VZ (aarch64) or
# Firecracker (x86_64) by extracting it from the Alpine linux-virt apk.
#
# Usage:
#   ./guest/build-kernel-image.sh [ARCH] [ALPINE_VERSION]
#
# Defaults: ARCH=aarch64  ALPINE_VERSION=3.21
#
# Output (aarch64):  ~/.local/share/husker/kernels/Image-virt
# Output (x86_64):   ~/.local/share/husker/kernels/vmlinux

set -euo pipefail

ARCH="${1:-aarch64}"
ALPINE_VERSION="${2:-3.21}"
OUTPUT_DIR="${HUSKER_KERNEL_OUT:-${HOME}/.local/share/husker/kernels}"
WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required (install via 'brew install python' on macOS or 'apt-get install python3' on Linux)" >&2
    exit 1
}

case "$ARCH" in
    aarch64) OUT_NAME="Image-virt" ;;
    x86_64)  OUT_NAME="vmlinux" ;;
    *) echo "ERROR: unsupported arch $ARCH (expected aarch64 or x86_64)" >&2; exit 1 ;;
esac

APK_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main/${ARCH}/"
APK_NAME=$(curl -sL "$APK_URL" | grep -o "linux-virt-[0-9][^\"]*\.apk" | head -1)
[ -z "$APK_NAME" ] && { echo "ERROR: linux-virt apk not found for $ARCH $ALPINE_VERSION" >&2; exit 1; }

echo "Downloading $APK_NAME"
curl -sL "${APK_URL}${APK_NAME}" -o "$WORK_DIR/linux-virt.apk"

mkdir -p "$WORK_DIR/apk"
tar xzf "$WORK_DIR/linux-virt.apk" -C "$WORK_DIR/apk"

VMLINUZ="$WORK_DIR/apk/boot/vmlinuz-virt"
[ -f "$VMLINUZ" ] || { echo "ERROR: vmlinuz-virt not in apk" >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"
OUT_PATH="$OUTPUT_DIR/$OUT_NAME"

# Scan for the gzip magic header (1f 8b 08) inside vmlinuz and decompress
# everything from that offset forward. This is the extract-vmlinux trick.
# python3 is used for portability (macOS od lacks GNU -w1; perl is not always present).
OFFSET=$(python3 - "$VMLINUZ" <<'PYEOF'
import sys
data = open(sys.argv[1], 'rb').read()
idx = data.find(b'\x1f\x8b\x08')
print(idx if idx >= 0 else '')
PYEOF
)

if [ -z "$OFFSET" ]; then
    echo "No gzip magic found — assuming already-uncompressed Image"
    cp "$VMLINUZ" "$OUT_PATH"
else
    echo "Decompressing gzip stream at offset $OFFSET"
    # gunzip exits 2 with a "trailing garbage ignored" message when the
    # compressed stream is followed by PE/EFI trailer bytes (normal for Alpine's
    # vmlinuz-virt). Filter just that message; let any other stderr through.
    set +e
    dd if="$VMLINUZ" bs=1 skip="$OFFSET" status=none \
        | gunzip 2>"$WORK_DIR/gunzip.err" > "$OUT_PATH"
    GUNZIP_RC=${PIPESTATUS[1]}
    set -e
    grep -v "trailing garbage ignored" "$WORK_DIR/gunzip.err" >&2 || true
    if [ "$GUNZIP_RC" -ne 0 ] && [ "$GUNZIP_RC" -ne 2 ]; then
        echo "ERROR: gunzip failed with exit code $GUNZIP_RC" >&2
        exit 1
    fi
fi

# Sanity check: aarch64 Image starts with ARM64 magic 'ARM\x64' at offset 56,
# x86_64 vmlinux is ELF.
if [ "$ARCH" = "aarch64" ]; then
    MAGIC=$(dd if="$OUT_PATH" bs=1 skip=56 count=4 status=none)
    [ "$MAGIC" = "ARM"$'\x64' ] || echo "WARNING: ARM64 magic not found at offset 56 (got: $(printf %q "$MAGIC"))"
else
    file "$OUT_PATH" | grep -q ELF || echo "WARNING: $OUT_NAME is not ELF"
fi

echo "Built: $OUT_PATH ($(du -h "$OUT_PATH" | cut -f1))"
