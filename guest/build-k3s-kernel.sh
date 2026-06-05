#!/usr/bin/env bash
# Build a Firecracker-compatible kernel with k3s (Kubernetes) support.
#
# Uses upstream `make defconfig` as base, then enables Firecracker virtio
# drivers and the netfilter/BPF/cgroup options required by k3s, kube-proxy,
# flannel, and containerd.
#
# Requires: build-essential, flex, bison, libelf-dev, bc, libssl-dev
# Usage:  sudo ./guest/build-k3s-kernel.sh [output_vmlinux] [kernel_version]
#
# Default kernel version: 6.1.102 (LTS, matches Firecracker CI kernel series).

set -euo pipefail

OUTPUT="${1:-/mnt/husker/vmlinux-k3s}"
KERNEL_VERSION="${2:-6.1.102}"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
BUILD_DIR="/tmp/kernel-build"

echo "==> Building Firecracker kernel ${KERNEL_VERSION} with k3s support"
echo "    Output: $OUTPUT"

# Install build dependencies
echo "==> Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential flex bison libelf-dev bc libssl-dev wget 2>&1 | tail -3

# Download kernel source
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

TARBALL="linux-${KERNEL_VERSION}.tar.xz"
if [ ! -f "$TARBALL" ]; then
    echo "==> Downloading kernel ${KERNEL_VERSION}..."
    wget -q "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/${TARBALL}"
fi

if [ ! -d "linux-${KERNEL_VERSION}" ]; then
    echo "==> Extracting kernel source..."
    tar xf "$TARBALL"
fi
cd "linux-${KERNEL_VERSION}"

# Start with upstream defconfig (sane defaults for x86_64)
echo "==> Generating base config from defconfig..."
make defconfig

# ── Firecracker essentials ──────────────────────────────────────────
echo "==> Enabling Firecracker virtio drivers..."
scripts/config --enable CONFIG_VIRTIO_BLK
scripts/config --enable CONFIG_VIRTIO_NET
scripts/config --enable CONFIG_VIRTIO_MMIO
scripts/config --enable CONFIG_VIRTIO_VSOCK
scripts/config --enable CONFIG_VHOST_VSOCK
scripts/config --enable CONFIG_VSOCKETS
scripts/config --enable CONFIG_SERIAL_8250
scripts/config --enable CONFIG_SERIAL_8250_CONSOLE
scripts/config --enable CONFIG_EXT4_FS
scripts/config --enable CONFIG_EXT4_FS_POSIX_ACL
scripts/config --enable CONFIG_TMPFS
scripts/config --enable CONFIG_DEVTMPFS
scripts/config --enable CONFIG_DEVTMPFS_MOUNT

# Disable modules (Firecracker uses built-in only)
scripts/config --disable CONFIG_MODULES

# ── Container runtime requirements ──────────────────────────────────
echo "==> Enabling container runtime options (BPF, cgroups)..."
scripts/config --enable CONFIG_BPF_SYSCALL
scripts/config --enable CONFIG_CGROUP_BPF
scripts/config --enable CONFIG_BPF_JIT
scripts/config --enable CONFIG_CFS_BANDWIDTH

# cgroups v2
scripts/config --enable CONFIG_CGROUP_SCHED
scripts/config --enable CONFIG_FAIR_GROUP_SCHED
scripts/config --enable CONFIG_MEMCG
scripts/config --enable CONFIG_CGROUP_PIDS
scripts/config --enable CONFIG_CGROUP_FREEZER
scripts/config --enable CONFIG_CGROUP_DEVICE
scripts/config --enable CONFIG_CGROUP_CPUACCT
scripts/config --enable CONFIG_CPUSETS
scripts/config --enable CONFIG_CGROUP_HUGETLB
scripts/config --enable CONFIG_CGROUP_PERF
scripts/config --enable CONFIG_CGROUP_NET_PRIO
scripts/config --enable CONFIG_CGROUP_NET_CLASSID
scripts/config --enable CONFIG_BLK_CGROUP

# Namespaces and security
scripts/config --enable CONFIG_USER_NS
scripts/config --enable CONFIG_PID_NS
scripts/config --enable CONFIG_NET_NS
scripts/config --enable CONFIG_SECCOMP
scripts/config --enable CONFIG_SECCOMP_FILTER

# Overlay filesystem (container image layers)
scripts/config --enable CONFIG_OVERLAY_FS

# /proc/config.gz for runtime kernel config inspection
scripts/config --enable CONFIG_IKCONFIG
scripts/config --enable CONFIG_IKCONFIG_PROC

# ── k3s / kube-proxy netfilter ──────────────────────────────────────
echo "==> Enabling k3s netfilter options..."
# NETFILTER_ADVANCED is required for xt_comment and other match modules
scripts/config --enable CONFIG_NETFILTER_ADVANCED

# iptables match modules used by kube-proxy
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_COMMENT
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_MULTIPORT
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_MARK
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_STATISTIC
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_RECENT
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_STATE
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_LIMIT
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_CONNMARK
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_IPRANGE
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_LENGTH
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_STRING
scripts/config --enable CONFIG_NETFILTER_XT_MATCH_TCPMSS

# iptables target modules
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_MARK
scripts/config --enable CONFIG_NETFILTER_XT_MARK
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_CONNMARK
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_LOG
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_NFLOG
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_TCPMSS
scripts/config --enable CONFIG_NETFILTER_XT_TARGET_CHECKSUM

# ip6tables (k3s needs dual-stack support)
scripts/config --enable CONFIG_IP6_NF_IPTABLES
scripts/config --enable CONFIG_IP6_NF_FILTER
scripts/config --enable CONFIG_IP6_NF_MANGLE
scripts/config --enable CONFIG_IP6_NF_NAT
scripts/config --enable CONFIG_NF_LOG_SYSLOG

# ── IPVS (kube-proxy IPVS mode) ────────────────────────────────────
echo "==> Enabling IPVS options..."
scripts/config --enable CONFIG_IP_VS
scripts/config --enable CONFIG_IP_VS_PROTO_TCP
scripts/config --enable CONFIG_IP_VS_PROTO_UDP
scripts/config --enable CONFIG_IP_VS_RR
scripts/config --enable CONFIG_IP_VS_WRR
scripts/config --enable CONFIG_IP_VS_SH
scripts/config --enable CONFIG_IP_VS_NFCT
scripts/config --enable CONFIG_IP_VS_LEASTCONN

# ── Networking (flannel, VXLAN) ─────────────────────────────────────
echo "==> Enabling network options..."
scripts/config --enable CONFIG_VXLAN
scripts/config --enable CONFIG_UDP_TUNNEL
scripts/config --enable CONFIG_BRIDGE
scripts/config --enable CONFIG_VETH

# Resolve any dependency conflicts
echo "==> Resolving config dependencies..."
make olddefconfig

echo "==> Building kernel (this may take a while on slower machines)..."
make -j"$(nproc)" vmlinux

echo "==> Installing kernel..."
cp vmlinux "$OUTPUT"

echo "==> Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo ""
echo "Kernel config highlights:"
grep -c '=y' .config | xargs -I{} echo "  Built-in options: {}"
echo ""
echo "To use this kernel:"
echo "  husker run --kernel $OUTPUT --name myvm rootfs.ext4"
