#!/bin/sh
# Userdata script for a k3s server (control plane) node.
#
# Installs k3s as a systemd service so it persists after userdata completes.
# Uses host-gw flannel backend (no VXLAN kernel support needed).
#
# Usage:
#   husker run --name k3s-server --cpus 2 --memory 2048 \
#       --userdata guest/k3s-server.sh k3s-rootfs.ext4
#
# After boot, retrieve the join token:
#   husker exec k3s-server -- cat /var/lib/rancher/k3s/server/node-token

set -e

echo "[husker] Installing k3s server systemd service..."

cat > /etc/systemd/system/k3s-server.service << 'EOF'
[Unit]
Description=k3s server (control plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/k3s server --write-kubeconfig-mode=644 --flannel-backend=host-gw
Restart=always
RestartSec=5
KillMode=process
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now k3s-server.service

echo "[husker] Waiting for node to become Ready..."
timeout 180 sh -c '
    until k3s kubectl get node 2>/dev/null | grep -q " Ready"; do
        sleep 3
    done
'

echo "[husker] k3s server is ready."
k3s kubectl get node
