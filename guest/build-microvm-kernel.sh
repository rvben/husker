#!/usr/bin/env bash
# Build a modules-free microVM kernel: CONFIG_MODULES=n, every required
# driver compiled in. No loadable modules means kernel/initramfs version
# pairing cannot break, and guests need no insmod step at boot.
#
# Build deps (Debian/Ubuntu): build-essential bc bison flex libelf-dev libssl-dev
# Cross-compiling aarch64 on x86_64: export CROSS_COMPILE=aarch64-linux-gnu-
set -euo pipefail

KERNEL_VERSION="${KERNEL_VERSION:-6.12.93}"
# SHA256 for linux-6.12.93.tar.xz. Override with KERNEL_SHA256 when changing
# KERNEL_VERSION, or set to "skip" to bypass verification.
KERNEL_SHA256_DEFAULT="492648a87c0b69c5ac7f43be64792b9000e3439550d4e82e4a14710c49094fa3"
KERNEL_SHA256="${KERNEL_SHA256:-$KERNEL_SHA256_DEFAULT}"
ARCH="${ARCH:-$(uname -m)}"
JOBS="${JOBS:-$(nproc)}"
OUT_DIR="${HUSKER_KERNEL_OUT:-$HOME/.local/share/husker/kernels}"

_OWN_WORK_DIR=0
if [ -z "${WORK_DIR:-}" ]; then
  WORK_DIR="$(mktemp -d /tmp/husker-kernel-build.XXXXXX)"
  _OWN_WORK_DIR=1
fi
cleanup() { [ "$_OWN_WORK_DIR" = 1 ] && rm -rf "$WORK_DIR"; }
trap cleanup EXIT

case "$ARCH" in
  x86_64)  KARCH=x86_64; KTARGET=vmlinux; OUT_NAME=vmlinux ;;
  aarch64) KARCH=arm64;  KTARGET=Image;   OUT_NAME=Image-virt ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

cd "$WORK_DIR"
MAJOR="${KERNEL_VERSION%%.*}"
echo "==> Fetching linux-${KERNEL_VERSION} (${KARCH})"
[ -f "linux-${KERNEL_VERSION}.tar.xz" ] || \
  curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"

if [ "$KERNEL_SHA256" != "skip" ]; then
  echo "$KERNEL_SHA256  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c
fi

[ -d "linux-${KERNEL_VERSION}" ] || tar xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} defconfig

cfg() { scripts/config "$@"; }

# Everything below is built in: no loadable modules, ever.
cfg --disable MODULES

# virtio core + both transports (Firecracker: MMIO; QEMU and Apple VZ: PCI)
cfg --enable VIRTIO
cfg --enable VIRTIO_PCI
cfg --enable VIRTIO_MMIO
cfg --enable VIRTIO_MMIO_CMDLINE_DEVICES

# virtio devices
cfg --enable VIRTIO_BLK
cfg --enable VIRTIO_NET
cfg --enable VIRTIO_BALLOON
cfg --enable VIRTIO_CONSOLE

# vsock: the guest agent transport
# VIRTIO_VSOCKETS depends on VSOCKETS
cfg --enable VSOCKETS
cfg --enable VIRTIO_VSOCKETS

# filesystems: ext4 rootfs, overlayfs + virtiofs for future work
# VIRTIO_FS depends on FUSE_FS
cfg --enable EXT4_FS
cfg --enable OVERLAY_FS
cfg --enable FUSE_FS
cfg --enable VIRTIO_FS

# AF_PACKET: BusyBox udhcpc needs raw sockets
cfg --enable PACKET

# cgroup v2 memory controller: husker-agent self-limit
cfg --enable CGROUPS
cfg --enable MEMCG

# pseudo filesystems the init path expects
cfg --enable TMPFS
cfg --enable DEVTMPFS
cfg --enable DEVTMPFS_MOUNT

if [ "$KARCH" = "x86_64" ]; then
  cfg --enable KVM_GUEST
  cfg --enable SERIAL_8250
  cfg --enable SERIAL_8250_CONSOLE
else
  # QEMU aarch64 console (ttyAMA0); Apple VZ uses hvc0 via VIRTIO_CONSOLE
  cfg --enable SERIAL_AMBA_PL011
  cfg --enable SERIAL_AMBA_PL011_CONSOLE
fi

make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} olddefconfig

# olddefconfig silently drops options with unmet dependencies; fail loudly.
for opt in VIRTIO VIRTIO_PCI VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES \
           VIRTIO_BLK VIRTIO_NET VIRTIO_BALLOON VIRTIO_CONSOLE \
           VSOCKETS VIRTIO_VSOCKETS EXT4_FS OVERLAY_FS FUSE_FS VIRTIO_FS \
           PACKET CGROUPS MEMCG TMPFS DEVTMPFS DEVTMPFS_MOUNT; do
  grep -q "^CONFIG_${opt}=y" .config || { echo "FATAL: CONFIG_${opt} is not =y" >&2; exit 1; }
done
grep -q "^# CONFIG_MODULES is not set" .config \
  || { echo "FATAL: CONFIG_MODULES is still enabled" >&2; exit 1; }

if [ "$KARCH" = "x86_64" ]; then
  for opt in KVM_GUEST SERIAL_8250 SERIAL_8250_CONSOLE; do
    grep -q "^CONFIG_${opt}=y" .config || { echo "FATAL: CONFIG_${opt} is not =y" >&2; exit 1; }
  done
else
  for opt in SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE; do
    grep -q "^CONFIG_${opt}=y" .config || { echo "FATAL: CONFIG_${opt} is not =y" >&2; exit 1; }
  done
fi

echo "==> Building (this takes a while)"
make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} -j"$JOBS" "$KTARGET"

mkdir -p "$OUT_DIR"
if [ "$KARCH" = "x86_64" ]; then
  cp vmlinux "$OUT_DIR/$OUT_NAME"
else
  cp arch/arm64/boot/Image "$OUT_DIR/$OUT_NAME"
fi
echo "==> Wrote $OUT_DIR/$OUT_NAME"
