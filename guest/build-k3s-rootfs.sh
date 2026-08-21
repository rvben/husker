#!/usr/bin/env bash
# Build a k3s-ready ext4 rootfs for Firecracker microVMs.
#
# Creates an Ubuntu 22.04 (Jammy) rootfs with k3s, systemd, and the husker
# guest agent pre-installed. The image boots via systemd, starts the agent
# on vsock, and has all k3s dependencies (iptables, conntrack, etc.).
#
# Requires: debootstrap, e2fsprogs, curl (run as root)
# Usage:  sudo ./guest/build-k3s-rootfs.sh [output.ext4] [size_mb]
#
# The script auto-detects architecture for the k3s binary download.

set -euo pipefail

OUTPUT="${1:-k3s-rootfs.ext4}"
SIZE_MB="${2:-2048}"
ARCH="$(uname -m)"

# Map architecture to k3s download suffix
case "$ARCH" in
    x86_64)  K3S_SUFFIX="" ;;
    aarch64) K3S_SUFFIX="-arm64" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Locate the husker-agent binary
AGENT_BIN=""
for candidate in \
    "target/x86_64-unknown-linux-musl/agent/husker-agent" \
    "target/aarch64-unknown-linux-musl/agent/husker-agent" \
    "target/release/husker-agent" \
    "target/debug/husker-agent"; do
    if [[ -f "$candidate" ]]; then
        AGENT_BIN="$candidate"
        break
    fi
done
if [[ -z "$AGENT_BIN" ]]; then
    echo "Error: husker-agent binary not found. Run 'make build-agent' first."
    exit 1
fi

MOUNT_DIR="$(mktemp -d)"
cleanup() {
    echo "Cleaning up..."
    umount "$MOUNT_DIR" 2>/dev/null || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Creating ${SIZE_MB}MB ext4 image: $OUTPUT"
dd if=/dev/zero of="$OUTPUT" bs=1M count="$SIZE_MB" status=progress
mkfs.ext4 -F -L rootfs "$OUTPUT"

echo "==> Mounting image"
mount -o loop "$OUTPUT" "$MOUNT_DIR"

echo "==> Running debootstrap (Ubuntu 22.04 Jammy)"
debootstrap --arch=amd64 jammy "$MOUNT_DIR" http://archive.ubuntu.com/ubuntu

echo "==> Installing packages via chroot"
chroot "$MOUNT_DIR" /bin/bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        systemd systemd-sysv \
        iptables conntrack ethtool socat \
        curl ca-certificates \
        openssh-server \
        iproute2 procps kmod \
        2>&1 | tail -5
    apt-get clean
    rm -rf /var/lib/apt/lists/*

'

echo "==> Downloading k3s binary"
K3S_TAG="$(curl -sfL https://api.github.com/repos/k3s-io/k3s/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)"
if [[ -z "$K3S_TAG" ]]; then
    echo "Error: failed to determine latest k3s version"; exit 1
fi
K3S_URL="https://github.com/k3s-io/k3s/releases/download/${K3S_TAG}/k3s${K3S_SUFFIX}"
echo "    Version: ${K3S_TAG}"
curl -sfL "$K3S_URL" -o "$MOUNT_DIR/usr/local/bin/k3s"
chmod 755 "$MOUNT_DIR/usr/local/bin/k3s"

echo "==> Creating k3s symlinks"
for cmd in kubectl crictl ctr; do
    ln -sf k3s "$MOUNT_DIR/usr/local/bin/$cmd"
done

echo "==> Installing husker-agent"
cp "$AGENT_BIN" "$MOUNT_DIR/usr/local/bin/husker-agent"
chmod 755 "$MOUNT_DIR/usr/local/bin/husker-agent"

echo "==> Creating husker-agent systemd service"
cat > "$MOUNT_DIR/etc/systemd/system/husker-agent.service" << 'EOF'
[Unit]
Description=Husker Guest Agent
After=network.target
ConditionVirtualization=vm

[Service]
Type=simple
ExecStart=/usr/local/bin/husker-agent
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

chroot "$MOUNT_DIR" systemctl enable husker-agent.service

echo "==> Configuring serial console (ttyS0)"
chroot "$MOUNT_DIR" systemctl enable serial-getty@ttyS0.service

echo "==> Configuring cgroups v2"
mkdir -p "$MOUNT_DIR/etc/default"
# Ensure cgroup v2 is mounted (systemd does this by default on Jammy)
cat >> "$MOUNT_DIR/etc/default/grub" 2>/dev/null << 'EOF' || true
GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"
EOF

echo "==> Setting empty root password"
chroot "$MOUNT_DIR" passwd -d root

echo "==> Disabling systemd-resolved (husker injects /etc/resolv.conf directly)"
chroot "$MOUNT_DIR" systemctl disable systemd-resolved.service 2>/dev/null || true
chroot "$MOUNT_DIR" systemctl mask systemd-resolved.service
rm -f "$MOUNT_DIR/etc/resolv.conf"
cat > "$MOUNT_DIR/etc/resolv.conf" << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

echo "==> Configuring hostname"
echo "husker-k3s" > "$MOUNT_DIR/etc/hostname"

echo "==> Cleaning up image"
rm -rf "$MOUNT_DIR/tmp/"* "$MOUNT_DIR/var/tmp/"*

echo "==> Unmounting"
umount "$MOUNT_DIR"

echo "==> Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
