#!/bin/bash
# Build the initramfs for Alpine-based husker VMs.
#
# Downloads the Alpine linux-virt kernel package, extracts the required
# modules, bundles them with a BusyBox-based init, and produces a gzip
# compressed cpio archive.
#
# Usage:
#   ./guest/build-initramfs.sh [ALPINE_VERSION] [ARCH]
#
# Defaults: ALPINE_VERSION=3.21  ARCH=aarch64
#
# Output:
#   ARCH=aarch64 → ~/.local/share/husker/kernels/initramfs-virt.gz
#   ARCH=x86_64  → ~/.local/share/husker/kernels/initramfs-x86_64-virt.gz

set -euo pipefail

ALPINE_VERSION="${1:-3.21}"
ARCH="${2:-aarch64}"
OUTPUT_DIR="${HOME}/.local/share/husker/kernels"
WORK_DIR="$(mktemp -d)"

case "$ARCH" in
    aarch64) OUT_NAME="initramfs-virt.gz" ;;
    x86_64)  OUT_NAME="initramfs-x86_64-virt.gz" ;;
    *) echo "ERROR: unsupported arch $ARCH (expected aarch64 or x86_64)" >&2; exit 1 ;;
esac

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "Building initramfs for Alpine $ALPINE_VERSION ($ARCH)"

# ── Download Alpine kernel package ──────────────────────────────────

APK_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main/${ARCH}/"
echo "Fetching package index from $APK_URL"

APK_NAME=$(curl -sL "$APK_URL" | grep -o "linux-virt-[0-9][^\"]*\.apk" | head -1)
if [ -z "$APK_NAME" ]; then
    echo "ERROR: could not find linux-virt package for Alpine $ALPINE_VERSION $ARCH" >&2
    exit 1
fi

echo "Downloading $APK_NAME"
curl -sL "${APK_URL}${APK_NAME}" -o "$WORK_DIR/linux-virt.apk"

# ── Extract kernel modules ──────────────────────────────────────────

echo "Extracting kernel modules"
mkdir -p "$WORK_DIR/apk"
tar xzf "$WORK_DIR/linux-virt.apk" -C "$WORK_DIR/apk"

KVER=$(ls "$WORK_DIR/apk/lib/modules/" | head -1)
if [ -z "$KVER" ]; then
    echo "ERROR: no kernel version directory found in package" >&2
    exit 1
fi
echo "Kernel version: $KVER"

APK_MDIR="$WORK_DIR/apk/lib/modules/$KVER"

# ── Download BusyBox static binary ──────────────────────────────────

BUSYBOX_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main/${ARCH}/"
BB_NAME=$(curl -sL "$BUSYBOX_URL" | grep -o "busybox-static-[0-9][^\"]*\.apk" | head -1)
echo "Downloading BusyBox ($BB_NAME)"
curl -sL "${BUSYBOX_URL}${BB_NAME}" -o "$WORK_DIR/busybox.apk"

mkdir -p "$WORK_DIR/bb"
tar xzf "$WORK_DIR/busybox.apk" -C "$WORK_DIR/bb"

# ── Build initramfs tree ────────────────────────────────────────────

INITRAMFS="$WORK_DIR/initramfs"
mkdir -p "$INITRAMFS"/{bin,dev,lib/modules/"$KVER",mnt/root,proc,sys}

# BusyBox
cp "$WORK_DIR/bb/bin/busybox.static" "$INITRAMFS/bin/busybox"
chmod 755 "$INITRAMFS/bin/busybox"

# Create symlinks for commands used by init
for cmd in mount umount mkdir insmod sh switch_root; do
    ln -s busybox "$INITRAMFS/bin/$cmd"
done
# insmod is also expected at /sbin/insmod by some paths
mkdir -p "$INITRAMFS/sbin"
ln -s ../bin/busybox "$INITRAMFS/sbin/insmod"

# Modules needed for boot:
#   Block:      virtio_blk
#   Balloon:    virtio_balloon
#   Filesystem: crc16, crc32_generic, crc32c_generic, mbcache, jbd2, ext4
#   Network:    af_packet (for DHCP), failover, net_failover, virtio_net
#   Vsock:      vsock, vmw_vsock_virtio_transport_common, vmw_vsock_virtio_transport
MODULES=(
    # Block
    "kernel/drivers/block/virtio_blk.ko"
    # Memory balloon (husker run --balloon; harmless if unused)
    "kernel/drivers/virtio/virtio_balloon.ko"
    # Filesystem
    "kernel/lib/crc16.ko"
    "kernel/crypto/crc32_generic.ko"
    "kernel/crypto/crc32c_generic.ko"
    "kernel/fs/mbcache.ko"
    "kernel/fs/jbd2/jbd2.ko"
    "kernel/fs/ext4/ext4.ko"
    # Network (af_packet required for DHCP raw sockets)
    "kernel/net/packet/af_packet.ko"
    # Network (dependency order: failover → net_failover → virtio_net)
    "kernel/net/core/failover.ko"
    "kernel/drivers/net/net_failover.ko"
    "kernel/drivers/net/virtio_net.ko"
    # Vsock
    "kernel/net/vmw_vsock/vsock.ko"
    "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko"
    "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko"
)

for mod in "${MODULES[@]}"; do
    src="$APK_MDIR/$mod"
    # Alpine packages .ko.gz, decompress to .ko
    if [ -f "${src}.gz" ]; then
        base=$(basename "$mod")
        gzip -dc "${src}.gz" > "$INITRAMFS/lib/modules/$KVER/$base"
    elif [ -f "$src" ]; then
        cp "$src" "$INITRAMFS/lib/modules/$KVER/"
    else
        echo "WARNING: module $mod not found, skipping" >&2
    fi
done

# ── Init script ─────────────────────────────────────────────────────

cat > "$INITRAMFS/init" << 'INIT_EOF'
#!/bin/sh
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sys /sys
/bin/mount -t devtmpfs devtmpfs /dev

# Honor an explicit init= from the kernel cmdline (husker boots imported OCI
# images via init=/usr/local/bin/husker-agent so the agent supervisor becomes
# PID 1); default to /sbin/init for everything else.
INIT=/sbin/init
for tok in $(cat /proc/cmdline); do
    case "$tok" in
    init=*) INIT="${tok#init=}" ;;
    esac
done

MDIR=/lib/modules/KVER_PLACEHOLDER

# Load block device modules
if [ -f $MDIR/virtio_blk.ko ]; then
    /bin/insmod $MDIR/virtio_blk.ko 2>/dev/null || echo "husker-init: WARNING virtio_blk present but failed to load (kernel/module mismatch?)"
else
    echo "husker-init: skipped virtio_blk (built-in)"
fi

# Memory balloon (optional device; only active when the VM enables it)
/bin/insmod $MDIR/virtio_balloon.ko 2>/dev/null || echo "husker-init: skipped virtio_balloon (built-in or absent)"

# Load filesystem dependency modules
/bin/insmod $MDIR/crc16.ko 2>/dev/null || echo "husker-init: skipped crc16 (built-in or absent)"
/bin/insmod $MDIR/crc32_generic.ko 2>/dev/null || echo "husker-init: skipped crc32_generic (built-in or absent)"
/bin/insmod $MDIR/crc32c_generic.ko 2>/dev/null || echo "husker-init: skipped crc32c_generic (built-in or absent)"
/bin/insmod $MDIR/mbcache.ko 2>/dev/null || echo "husker-init: skipped mbcache (built-in or absent)"
if [ -f $MDIR/jbd2.ko ]; then
    /bin/insmod $MDIR/jbd2.ko 2>/dev/null || echo "husker-init: WARNING jbd2 present but failed to load (kernel/module mismatch?)"
else
    echo "husker-init: skipped jbd2 (built-in)"
fi
if [ -f $MDIR/ext4.ko ]; then
    /bin/insmod $MDIR/ext4.ko 2>/dev/null || echo "husker-init: WARNING ext4 present but failed to load (kernel/module mismatch?)"
else
    echo "husker-init: skipped ext4 (built-in)"
fi

# Wait for /dev/vda to appear (up to 5s: 50 x 100ms)
i=0
while [ ! -b /dev/vda ] && [ $i -lt 50 ]; do
    /bin/busybox usleep 100000
    i=$((i + 1))
done

if [ ! -b /dev/vda ]; then
    echo "FATAL: /dev/vda not found (virtio_blk missing? check earlier husker-init messages)"
    exec /bin/sh
fi

# Mount rootfs
/bin/mount -t ext4 /dev/vda /mnt/root

if [ ! -d /mnt/root/sbin ]; then
    echo "FATAL: rootfs mount failed"
    exec /bin/sh
fi

# Copy modules to rootfs for use after switch_root
/bin/mkdir -p /mnt/root/lib/modules
for m in $MDIR/*.ko; do
    /bin/busybox cp "$m" /mnt/root/lib/modules/ 2>/dev/null || true
done

# Mount virtiofs shares declared in the kernel cmdline.
# Format: husker.share=<tag>=<guest_path>[:ro]
# The mounts target /mnt/root<path> so they survive switch_root.
for tok in $(cat /proc/cmdline); do
    case "$tok" in
    husker.share=*)
        spec="${tok#husker.share=}"
        tag="${spec%%=*}"
        rest="${spec#*=}"
        case "$rest" in
        *:ro)
            gpath="${rest%:ro}"
            /bin/mkdir -p /mnt/root$gpath
            /bin/mount -t virtiofs -o ro "$tag" /mnt/root$gpath 2>/dev/null || \
                echo "husker-init: WARNING could not mount virtiofs $tag on $gpath (ro)"
            ;;
        *)
            gpath="$rest"
            /bin/mkdir -p /mnt/root$gpath
            /bin/mount -t virtiofs "$tag" /mnt/root$gpath 2>/dev/null || \
                echo "husker-init: WARNING could not mount virtiofs $tag on $gpath"
            ;;
        esac
        ;;
    esac
done

# Clean up
/bin/umount /proc
/bin/umount /sys
/bin/umount /dev

exec /bin/switch_root /mnt/root "$INIT"
INIT_EOF

# Substitute kernel version into init script
sed -i.bak "s/KVER_PLACEHOLDER/$KVER/" "$INITRAMFS/init"
rm -f "$INITRAMFS/init.bak"
chmod 755 "$INITRAMFS/init"

# ── Pack initramfs ──────────────────────────────────────────────────

echo "Packing initramfs"
mkdir -p "$OUTPUT_DIR"
(cd "$INITRAMFS" && find . | cpio -o -H newc --quiet | gzip -9) > "$OUTPUT_DIR/$OUT_NAME"

echo "Built: $OUTPUT_DIR/$OUT_NAME ($(du -h "$OUTPUT_DIR/$OUT_NAME" | cut -f1))"

# Also copy the uncompressed kernel Image if present in the APK
KERNEL_IMAGE="$WORK_DIR/apk/boot/vmlinuz-virt"
if [ -f "$KERNEL_IMAGE" ]; then
    # Alpine packages the compressed vmlinuz; the uncompressed Image
    # must be extracted from it for Apple Virtualization.framework.
    echo "Note: vmlinuz-virt is in the package but VZ needs the uncompressed Image."
    echo "      Download it separately or extract from the kernel build."
fi
