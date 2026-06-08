#!/bin/bash
# Validate that the guest initramfs and inittab are consistent.
#
# Checks:
#   1. Every module referenced by insmod in the inittab exists in the
#      build-initramfs.sh MODULES array.
#   2. Module load order in inittab respects known dependencies.
#   3. af_packet.ko is loaded before husker-net.sh (PF_PACKET needed for
#      udhcpc, which husker-net.sh may invoke as a fallback).
#   4. husker-net.sh wiring: inittab invokes /usr/local/sbin/husker-net.sh,
#      build-rootfs.sh installs it, and the script contains ip= parsing and
#      a udhcpc fallback.
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

# ── 3. af_packet loaded before husker-net.sh ──

echo ""
echo "--- Network prerequisites ---"

AF_PACKET_LINE=$(grep -n "af_packet.ko" "$INITTAB" | head -1 | cut -d: -f1)
HUSKER_NET_LINE=$(grep -n "husker-net.sh" "$INITTAB" | head -1 | cut -d: -f1)

if [ -z "$AF_PACKET_LINE" ]; then
    fail "af_packet.ko not loaded in inittab (required for PF_PACKET / udhcpc fallback)"
elif [ -z "$HUSKER_NET_LINE" ]; then
    fail "husker-net.sh not found in inittab"
elif [ "$AF_PACKET_LINE" -lt "$HUSKER_NET_LINE" ]; then
    pass "af_packet.ko (line $AF_PACKET_LINE) loaded before husker-net.sh (line $HUSKER_NET_LINE)"
else
    fail "af_packet.ko (line $AF_PACKET_LINE) must load before husker-net.sh (line $HUSKER_NET_LINE)"
fi

# ── 4. husker-net.sh wiring ──

echo ""
echo "--- husker-net.sh wiring ---"

HUSKER_NET_SCRIPT="$SCRIPT_DIR/husker-net.sh"

# inittab must invoke husker-net.sh via its installed path
if grep -q '/usr/local/sbin/husker-net.sh' "$INITTAB"; then
    pass "inittab invokes /usr/local/sbin/husker-net.sh"
else
    fail "inittab does not invoke /usr/local/sbin/husker-net.sh"
fi

# inittab must NOT invoke udhcpc directly (it is now delegated to husker-net.sh).
# Only check non-comment lines to avoid false positives from descriptive comments.
if grep -v '^\s*#' "$INITTAB" | grep -q 'udhcpc'; then
    fail "inittab still invokes udhcpc directly (should be delegated to husker-net.sh)"
else
    pass "inittab does not invoke udhcpc directly"
fi

# husker-net.sh must exist
if [ -f "$HUSKER_NET_SCRIPT" ]; then
    pass "husker-net.sh exists at $HUSKER_NET_SCRIPT"
else
    fail "husker-net.sh not found at $HUSKER_NET_SCRIPT"
fi

# husker-net.sh must parse the ip= token
if grep -q 'ip=' "$HUSKER_NET_SCRIPT" 2>/dev/null; then
    pass "husker-net.sh contains ip= parsing logic"
else
    fail "husker-net.sh does not contain ip= parsing logic"
fi

# husker-net.sh must have a udhcpc fallback
if grep -q 'udhcpc' "$HUSKER_NET_SCRIPT" 2>/dev/null; then
    pass "husker-net.sh contains udhcpc fallback"
else
    fail "husker-net.sh does not contain udhcpc fallback"
fi

# husker-net.sh must use busybox-compatible ip addr add / ip route add
if grep -q 'ip addr add' "$HUSKER_NET_SCRIPT" 2>/dev/null; then
    pass "husker-net.sh uses 'ip addr add' (busybox ip compatible)"
else
    fail "husker-net.sh does not use 'ip addr add'"
fi

if grep -q 'ip route add' "$HUSKER_NET_SCRIPT" 2>/dev/null; then
    pass "husker-net.sh uses 'ip route add' (busybox ip compatible)"
else
    fail "husker-net.sh does not use 'ip route add'"
fi

# build-rootfs.sh must install husker-net.sh
BUILD_ROOTFS="$SCRIPT_DIR/build-rootfs.sh"
if [ -f "$BUILD_ROOTFS" ]; then
    if grep -q 'husker-net.sh' "$BUILD_ROOTFS"; then
        pass "build-rootfs.sh installs husker-net.sh"
    else
        fail "build-rootfs.sh does not install husker-net.sh"
    fi
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
