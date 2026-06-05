#!/bin/sh
# Userdata script for a k3s agent (worker) node.
#
# Installs k3s agent as a systemd service so it persists after userdata completes.
# Sets the hostname to the VM name for unique node identity in the cluster.
#
# Requires K3S_URL and K3S_TOKEN environment variables, passed via:
#   husker run --name k3s-agent-1 --cpus 2 --memory 2048 \
#       --userdata guest/k3s-agent.sh \
#       -e "K3S_URL=https://172.20.0.2:6443" \
#       -e "K3S_TOKEN=$(husker exec k3s-server -- cat /var/lib/rancher/k3s/server/node-token)" \
#       k3s-rootfs.ext4

set -e

if [ -z "$K3S_URL" ] || [ -z "$K3S_TOKEN" ]; then
    echo "[husker] Error: K3S_URL and K3S_TOKEN must be set"
    echo "  Pass via: husker run -e K3S_URL=... -e K3S_TOKEN=..."
    exit 1
fi

echo "[husker] Installing k3s agent systemd service..."
echo "[husker] Joining cluster at $K3S_URL"

cat > /etc/systemd/system/k3s-agent.service << EOF
[Unit]
Description=k3s agent (worker)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/k3s agent --server=${K3S_URL} --token=${K3S_TOKEN} --with-node-id
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
systemctl enable --now k3s-agent.service

echo "[husker] k3s agent started (joining cluster via systemd)."
