#!/bin/bash
# Validate that the guest initramfs and inittab are consistent.
#
# Checks:
#   1. Every module referenced by insmod in the inittab exists in the
#      build-initramfs.sh MODULES array.
#   2. Module load order in inittab respects known dependencies.
#   3. af_packet.ko is loaded before udhcpc (DHCP needs PF_PACKET).
#   4. udhcpc invocation does not reference a non-existent script path
#      or use shell backgrounding (&) alongside -b.
#
# Usage:
#   ./guest/test-initramfs.sh           # validate scripts only
#   ./guest/test-initramfs.sh --built   # also validate built initramfs artifact

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INITTAB="$SCRIPT_DIR/inittab"
BUILD_SCRIPT="$SCRIPT_DIR/build-initramfs.sh"
INITRAMFS_PATH="${HOME}/.local/share/husker/kernels/initramfs-virt.gz"

ERRORS=0
TESTS=0

pass() { TESTS=$((TESTS + 1)); echo "  PASS: $1"; }
fail() { TESTS=$((TESTS + 1)); ERRORS=$((ERRORS + 1)); echo "  FAIL: $1"; }

echo "=== Validating guest initramfs configuration ==="
echo ""

# ── 1. Every insmod target in inittab has a matching module in build script ──

echo "--- Module presence ---"

# Extract module basenames from inittab insmod lines
INITTAB_MODULES=$(grep '/sbin/insmod /lib/modules/' "$INITTAB" | sed 's|.*/lib/modules/||' | tr -d '\r')

# Extract module basenames from build script MODULES array
BUILD_MODULES=$(grep -E '^\s+"kernel/' "$BUILD_SCRIPT" | sed 's|.*/||; s|".*||' | tr -d '\r')

for mod in $INITTAB_MODULES; do
    if echo "$BUILD_MODULES" | grep -qF "$mod"; then
        pass "$mod listed in build script"
    else
        fail "$mod referenced in inittab but missing from build-initramfs.sh MODULES array"
    fi
done

# ── 2. Module dependency ordering in inittab ──

echo ""
echo "--- Module load order ---"

# Get line numbers for ordering checks
line_of() {
    grep -n "/sbin/insmod /lib/modules/$1" "$INITTAB" | head -1 | cut -d: -f1
}

# virtio_net depends on failover and net_failover
check_order() {
    local dep="$1" mod="$2" reason="$3"
    local dep_line mod_line
    dep_line=$(line_of "$dep")
    mod_line=$(line_of "$mod")
    if [ -z "$dep_line" ]; then
        fail "$dep not found in inittab (required before $mod)"
        return
    fi
    if [ -z "$mod_line" ]; then
        fail "$mod not found in inittab"
        return
    fi
    if [ "$dep_line" -lt "$mod_line" ]; then
        pass "$dep (line $dep_line) loaded before $mod (line $mod_line): $reason"
    else
        fail "$dep (line $dep_line) must load before $mod (line $mod_line): $reason"
    fi
}

check_order "failover.ko" "net_failover.ko" "net_failover depends on failover"
check_order "net_failover.ko" "virtio_net.ko" "virtio_net depends on net_failover"
check_order "vsock.ko" "vmw_vsock_virtio_transport_common.ko" "transport_common depends on vsock"
check_order "vmw_vsock_virtio_transport_common.ko" "vmw_vsock_virtio_transport.ko" "transport depends on transport_common"

# ── 3. af_packet loaded before DHCP ──

echo ""
echo "--- DHCP prerequisites ---"

AF_PACKET_LINE=$(grep -n "af_packet.ko" "$INITTAB" | head -1 | cut -d: -f1)
UDHCPC_LINE=$(grep -n "udhcpc" "$INITTAB" | head -1 | cut -d: -f1)

if [ -z "$AF_PACKET_LINE" ]; then
    fail "af_packet.ko not loaded in inittab (required for DHCP raw sockets)"
elif [ -z "$UDHCPC_LINE" ]; then
    fail "udhcpc not found in inittab"
elif [ "$AF_PACKET_LINE" -lt "$UDHCPC_LINE" ]; then
    pass "af_packet.ko (line $AF_PACKET_LINE) loaded before udhcpc (line $UDHCPC_LINE)"
else
    fail "af_packet.ko (line $AF_PACKET_LINE) must load before udhcpc (line $UDHCPC_LINE)"
fi

# ── 4. udhcpc invocation correctness ──

echo ""
echo "--- DHCP invocation ---"

UDHCPC_CMD=$(grep "udhcpc" "$INITTAB" | head -1)

# Must not reference /etc/udhcpc/default.script (doesn't exist in Alpine)
if echo "$UDHCPC_CMD" | grep -q '/etc/udhcpc/'; then
    fail "udhcpc references /etc/udhcpc/default.script which does not exist in Alpine"
else
    pass "udhcpc does not reference non-existent /etc/udhcpc/ script"
fi

# Must not use & with -b (double backgrounding)
if echo "$UDHCPC_CMD" | grep -q '&'; then
    if echo "$UDHCPC_CMD" | grep -q '\-b'; then
        fail "udhcpc uses both -b and & (double backgrounding loses foreground DHCP attempt)"
    fi
else
    pass "udhcpc does not use shell backgrounding (&)"
fi

# Must use -b for background retry
if echo "$UDHCPC_CMD" | grep -q '\-b'; then
    pass "udhcpc uses -b for background retry on lease failure"
else
    fail "udhcpc should use -b flag for background retry"
fi

# ── 5. Validate built initramfs artifact (optional) ──

if [ "${1:-}" = "--built" ]; then
    echo ""
    echo "--- Built initramfs validation ---"

    if [ ! -f "$INITRAMFS_PATH" ]; then
        fail "initramfs not found at $INITRAMFS_PATH (run guest/build-initramfs.sh first)"
    else
        WORK_DIR=$(mktemp -d)
        trap "rm -rf $WORK_DIR" EXIT

        (cd "$WORK_DIR" && gzip -dc "$INITRAMFS_PATH" | cpio -i --quiet 2>/dev/null)

        # Find the kernel version directory
        KVER=$(ls "$WORK_DIR/lib/modules/" 2>/dev/null | head -1)
        if [ -z "$KVER" ]; then
            fail "no kernel version directory in initramfs"
        else
            for mod in $INITTAB_MODULES; do
                if [ -f "$WORK_DIR/lib/modules/$KVER/$mod" ]; then
                    pass "$mod present in built initramfs"
                else
                    fail "$mod missing from built initramfs at lib/modules/$KVER/"
                fi
            done
        fi
    fi
fi

# ── Summary ──

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "=== All $TESTS checks passed ==="
    exit 0
else
    echo "=== $ERRORS of $TESTS checks FAILED ==="
    exit 1
fi
