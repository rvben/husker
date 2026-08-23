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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_CONFIG="${HUSKER_CONTAINER_KERNEL_CONFIG:-$SCRIPT_DIR/container-kernel.config}"

_OWN_WORK_DIR=0
if [ -z "${WORK_DIR:-}" ]; then
  WORK_DIR="$(mktemp -d /tmp/husker-kernel-build.XXXXXX)"
  _OWN_WORK_DIR=1
fi
# Use an `if`, not `[ ... ] && ...`: as the EXIT trap's last command a `&&` whose
# test is false returns 1, which would make the script exit 1 on SUCCESS whenever
# WORK_DIR was provided externally (e.g. to keep the tree for a second `make`).
cleanup() { if [ "$_OWN_WORK_DIR" = 1 ]; then rm -rf "$WORK_DIR"; fi; }
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
  curl --fail --silent --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
    --output "linux-${KERNEL_VERSION}.tar.xz" \
    "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"

if [ "$KERNEL_SHA256" != "skip" ]; then
  echo "$KERNEL_SHA256  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c
fi

[ -d "linux-${KERNEL_VERSION}" ] || tar xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} defconfig

# Two sources of bloat removed here: defconfig enables large subsystems
# (USB, sound, DRM, wireless, media...) as =y directly, and CONFIG_MODULES=n
# causes olddefconfig to clamp every remaining =m driver to =y as well. The
# sed pass neutralises the =m entries before olddefconfig runs; the explicit
# cfg --disable calls below remove the directly-=y subsystems. Together they
# cut kernel size roughly in half and allow boot inside a 128 MiB guest.
sed -i 's/^\(CONFIG_.*\)=m$/# \1 is not set/' .config

cfg() { scripts/config "$@"; }

apply_config_fragment() {
  local fragment="$1" line symbol
  [ -f "$fragment" ] || { echo "FATAL: kernel config fragment not found: $fragment" >&2; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
      CONFIG_*=y)
        symbol="${line%%=*}"
        cfg --enable "${symbol#CONFIG_}"
        ;;
      *)
        echo "FATAL: unsupported line in $fragment: $line" >&2
        echo "       fragments may contain comments, blank lines, and CONFIG_NAME=y" >&2
        exit 1
        ;;
    esac
  done < "$fragment"
}

assert_config_fragment() {
  local fragment="$1" line symbol
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      CONFIG_*=y)
        symbol="${line%%=*}"
        grep -q "^${symbol}=y$" .config || {
          echo "FATAL: ${symbol} requested by $fragment is not =y after olddefconfig" >&2
          exit 1
        }
        ;;
    esac
  done < "$fragment"
}

# Everything below is built in: no loadable modules, ever.
cfg --disable MODULES

# Disable large subsystems that defconfig enables but microVMs do not need.
# These consume significant kernel memory at boot inside a 128 MiB guest.
cfg --disable USB_SUPPORT
cfg --disable SOUND
cfg --disable DRM
cfg --disable MEDIA_SUPPORT
cfg --disable INPUT
cfg --disable HID
cfg --disable HID_SUPPORT
cfg --disable WIRELESS
cfg --disable WLAN
cfg --disable BLUETOOTH
cfg --disable RFKILL
cfg --disable NFC
cfg --disable I2C
cfg --disable SPI
cfg --disable HWMON
cfg --disable REGULATOR
cfg --disable IOMMU_SUPPORT
cfg --disable VFIO
cfg --disable MTD

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

# Nested Docker/containerd/runc support. Keep this in a declarative fragment so
# the default and k3s kernels cannot drift apart again.
apply_config_fragment "$CONTAINER_CONFIG"
if [ -n "${HUSKER_KERNEL_CONFIG_FRAGMENT:-}" ]; then
  apply_config_fragment "$HUSKER_KERNEL_CONFIG_FRAGMENT"
fi

# pseudo filesystems the init path expects
cfg --enable TMPFS
cfg --enable DEVTMPFS
cfg --enable DEVTMPFS_MOUNT

if [ "$KARCH" = "x86_64" ]; then
  cfg --enable KVM_GUEST
  cfg --enable SERIAL_8250
  cfg --enable SERIAL_8250_CONSOLE
  # PVH boot entry: emits the XEN_ELFNOTE_PHYS32_ENTRY note so QEMU can
  # direct-boot this uncompressed vmlinux (`-kernel vmlinux`). Without it QEMU
  # rejects the flat ELF ("loading uncompressed kernel without PVH ELF Note").
  # Firecracker ignores the extra note and boots the same image, so one kernel
  # serves both backends. aarch64 has no PVH; QEMU boots its `Image` directly.
  cfg --enable PVH
else
  # QEMU aarch64 console (ttyAMA0); Apple VZ uses hvc0 via VIRTIO_CONSOLE
  cfg --enable SERIAL_AMBA_PL011
  cfg --enable SERIAL_AMBA_PL011_CONSOLE
fi

make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} olddefconfig

assert_config_fragment "$CONTAINER_CONFIG"
if [ -n "${HUSKER_KERNEL_CONFIG_FRAGMENT:-}" ]; then
  assert_config_fragment "$HUSKER_KERNEL_CONFIG_FRAGMENT"
fi

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
  for opt in KVM_GUEST SERIAL_8250 SERIAL_8250_CONSOLE PVH; do
    grep -q "^CONFIG_${opt}=y" .config || { echo "FATAL: CONFIG_${opt} is not =y" >&2; exit 1; }
  done
else
  for opt in SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE; do
    grep -q "^CONFIG_${opt}=y" .config || { echo "FATAL: CONFIG_${opt} is not =y" >&2; exit 1; }
  done
fi

mkdir -p "$OUT_DIR"
cp .config "$OUT_DIR/config-${ARCH}"
if [ "${HUSKER_KERNEL_CONFIG_ONLY:-0}" = 1 ]; then
  echo "==> Wrote $OUT_DIR/config-${ARCH} (configuration-only run)"
  exit 0
fi

echo "==> Building (this takes a while)"
make ARCH="$KARCH" ${CROSS_COMPILE:+CROSS_COMPILE="$CROSS_COMPILE"} -j"$JOBS" "$KTARGET"

if [ "$KARCH" = "x86_64" ]; then
  cp vmlinux "$OUT_DIR/$OUT_NAME"
else
  cp arch/arm64/boot/Image "$OUT_DIR/$OUT_NAME"
fi
echo "==> Wrote $OUT_DIR/$OUT_NAME"
