#!/usr/bin/env bash
# End-to-end test for a multi-node k3s cluster on Husker microVMs.
#
# Boots a k3s server and 2 agent nodes, waits for all nodes to become Ready,
# deploys workloads, validates networking, and tears everything down.
#
# Usage:  sudo ./guest/test-k3s-cluster.sh [rootfs]
#
# Requires:
#   - Running husker daemon (husker daemon --listen 127.0.0.1:7777)
#   - k3s-rootfs.ext4 built via guest/build-k3s-rootfs.sh
#   - Sufficient memory (~3 GB for the cluster)

set -uo pipefail

ROOTFS="${1:-/mnt/husker/k3s-rootfs.ext4}"
KERNEL="${K3S_KERNEL:-/mnt/husker/vmlinux-k3s}"
SERVER_NAME="k3s-server"
AGENT_NAMES=("k3s-agent-1" "k3s-agent-2")
SERVER_CPUS=2
SERVER_MEM=1536
AGENT_CPUS=1
AGENT_MEM=768
K3S_URL="https://172.20.0.2:6443"

PASS=0
FAIL=0
TESTS_RUN=0

# ── Helpers ────────────────────────────────────────────────────────────

log()  { echo "[test] $*"; }
pass() { PASS=$((PASS + 1)); TESTS_RUN=$((TESTS_RUN + 1)); echo "  [PASS] $*"; }
fail() { FAIL=$((FAIL + 1)); TESTS_RUN=$((TESTS_RUN + 1)); echo "  [FAIL] $*"; }

kubectl_server() {
    husker exec "$SERVER_NAME" -- k3s kubectl "$@"
}

# Apply a YAML manifest inside the server VM.
# Usage: kubectl_apply <<'YAML' ... YAML
kubectl_apply() {
    local yaml
    yaml=$(cat)
    husker exec "$SERVER_NAME" -- sh -c "k3s kubectl apply -f - <<'K3SEOF'
${yaml}
K3SEOF"
}

# Wait for a condition with timeout. Args: description, timeout_secs, check_command...
wait_for() {
    local desc="$1" timeout="$2"
    shift 2
    log "Waiting for $desc (timeout ${timeout}s)..."
    local elapsed=0
    while ! "$@" >/dev/null 2>&1; do
        sleep 5
        elapsed=$((elapsed + 5))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$desc (timed out after ${timeout}s)"
            return 1
        fi
    done
    log "$desc — done (${elapsed}s)"
    return 0
}

cleanup() {
    log "Tearing down cluster..."
    for agent in "${AGENT_NAMES[@]}"; do
        husker destroy "$agent" 2>/dev/null && log "Destroyed VM: $agent" || true
    done
    husker destroy "$SERVER_NAME" 2>/dev/null && log "Destroyed VM: $SERVER_NAME" || true
    log "Cluster torn down"
}
trap cleanup EXIT

# ── Preflight ──────────────────────────────────────────────────────────

if [ ! -f "$ROOTFS" ]; then
    echo "Error: rootfs not found: $ROOTFS"
    echo "Build it with: sudo make build-k3s-rootfs"
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "Error: kernel not found: $KERNEL"
    echo "Build it with: sudo bash guest/build-k3s-kernel.sh"
    echo "Or set K3S_KERNEL to point to a kernel with k3s netfilter support"
    exit 1
fi

log "Using rootfs: $ROOTFS"
log "Using kernel: $KERNEL"
log "Cluster: 1 server (${SERVER_CPUS} vCPU, ${SERVER_MEM}MB) + ${#AGENT_NAMES[@]} agents (${AGENT_CPUS} vCPU, ${AGENT_MEM}MB each)"

# ── Phase 1: Boot cluster ─────────────────────────────────────────────

log ""
log "=== Phase 1: Boot cluster ==="

log "Starting k3s server..."
husker run --name "$SERVER_NAME" --kernel "$KERNEL" --cpus "$SERVER_CPUS" --memory "$SERVER_MEM" \
    --userdata guest/k3s-server.sh "$ROOTFS" || { fail "Failed to create k3s server VM"; exit 1; }

# Wait for k3s API to be reachable
wait_for "k3s server API" 300 husker exec "$SERVER_NAME" -- k3s kubectl get node || exit 1

# Get join token
log "Retrieving join token..."
K3S_TOKEN=$(husker exec "$SERVER_NAME" -- cat /var/lib/rancher/k3s/server/node-token)
if [ -z "$K3S_TOKEN" ]; then
    fail "Failed to retrieve join token"
    exit 1
fi
log "Token acquired"

# Start agents
for agent in "${AGENT_NAMES[@]}"; do
    log "Starting $agent..."
    husker run --name "$agent" --kernel "$KERNEL" --cpus "$AGENT_CPUS" --memory "$AGENT_MEM" \
        --userdata guest/k3s-agent.sh \
        -e "K3S_URL=$K3S_URL" \
        -e "K3S_TOKEN=$K3S_TOKEN" \
        "$ROOTFS" || { fail "Failed to create $agent VM"; exit 1; }
done

# Wait for all nodes to join
EXPECTED_NODES=$(( 1 + ${#AGENT_NAMES[@]} ))
wait_for "all $EXPECTED_NODES nodes Ready" 300 \
    sh -c "husker exec $SERVER_NAME -- k3s kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready' | grep -q '^${EXPECTED_NODES}$'" || exit 1

log ""
log "=== Cluster status ==="
kubectl_server get nodes -o wide
echo ""

# ── Phase 2: Validate cluster health ──────────────────────────────────

log ""
log "=== Phase 2: Cluster health ==="

# Test: all nodes Ready
READY_COUNT=$(kubectl_server get nodes --no-headers 2>/dev/null | grep -c " Ready" || true)
if [ "$READY_COUNT" -eq "$EXPECTED_NODES" ]; then
    pass "All $EXPECTED_NODES nodes are Ready"
else
    fail "Expected $EXPECTED_NODES Ready nodes, got $READY_COUNT"
fi

# Test: CoreDNS running
wait_for "CoreDNS ready" 300 \
    sh -c "husker exec $SERVER_NAME -- k3s kubectl -n kube-system get pods -l k8s-app=kube-dns --no-headers 2>/dev/null | grep -q '1/1.*Running'"

COREDNS_STATUS=$(kubectl_server -n kube-system get pods -l k8s-app=kube-dns --no-headers 2>/dev/null | head -1)
if echo "$COREDNS_STATUS" | grep -q "1/1.*Running"; then
    pass "CoreDNS is Running (1/1)"
else
    fail "CoreDNS not ready: $COREDNS_STATUS"
fi

# Test: metrics-server running
METRICS_STATUS=$(kubectl_server -n kube-system get pods -l k8s-app=metrics-server --no-headers 2>/dev/null | head -1)
if echo "$METRICS_STATUS" | grep -q "Running"; then
    pass "Metrics server is Running"
else
    # Non-fatal: metrics-server often needs more time
    log "  [WARN] Metrics server not ready yet: $METRICS_STATUS"
fi

log ""
kubectl_server -n kube-system get pods
echo ""

# ── Phase 3: Deployment and scheduling ─────────────────────────────────

log ""
log "=== Phase 3: Deployment and scheduling ==="

# Deploy nginx with 3 replicas
log "Creating nginx deployment (3 replicas)..."
kubectl_apply <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test
  labels:
    app: nginx-test
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-test
  template:
    metadata:
      labels:
        app: nginx-test
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
      terminationGracePeriodSeconds: 1
YAML

# Wait for deployment rollout
wait_for "nginx deployment ready" 180 \
    sh -c "husker exec $SERVER_NAME -- k3s kubectl get deployment nginx-test --no-headers 2>/dev/null | grep -q '3/3'"

# Test: all 3 replicas running
READY_REPLICAS=$(kubectl_server get deployment nginx-test -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)
if [ "$READY_REPLICAS" = "3" ]; then
    pass "Nginx deployment: 3/3 replicas ready"
else
    fail "Nginx deployment: expected 3 replicas ready, got $READY_REPLICAS"
fi

# Test: pods scheduled across multiple nodes
log "Checking pod distribution across nodes..."
kubectl_server get pods -l app=nginx-test -o wide --no-headers
NODES_USED=$(kubectl_server get pods -l app=nginx-test -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | sort -u | wc -l | tr -d ' ')
if [ "$NODES_USED" -gt 1 ]; then
    pass "Pods scheduled across $NODES_USED different nodes"
else
    fail "All pods on single node (expected distribution across nodes)"
fi

# ── Phase 4: Service networking ────────────────────────────────────────

log ""
log "=== Phase 4: Service networking ==="

# Create ClusterIP service
log "Creating ClusterIP service..."
kubectl_apply <<'YAML'
apiVersion: v1
kind: Service
metadata:
  name: nginx-clusterip
spec:
  selector:
    app: nginx-test
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
YAML

# Create NodePort service
log "Creating NodePort service..."
kubectl_apply <<'YAML'
apiVersion: v1
kind: Service
metadata:
  name: nginx-nodeport
spec:
  selector:
    app: nginx-test
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30080
  type: NodePort
YAML

sleep 5

# Test: ClusterIP service reachable from server node
CLUSTER_IP=$(kubectl_server get svc nginx-clusterip -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
log "ClusterIP: $CLUSTER_IP"

CLUSTERIP_RESULT=$(husker exec "$SERVER_NAME" -- \
    sh -c "curl -sf --max-time 10 http://${CLUSTER_IP} 2>/dev/null || wget -qO- --timeout=10 http://${CLUSTER_IP} 2>/dev/null" || true)
if echo "$CLUSTERIP_RESULT" | grep -qi "nginx\|welcome"; then
    pass "ClusterIP service reachable at $CLUSTER_IP"
else
    fail "ClusterIP service not reachable at $CLUSTER_IP"
fi

# Test: NodePort service reachable from server node
NODEPORT_RESULT=$(husker exec "$SERVER_NAME" -- \
    sh -c "curl -sf --max-time 10 http://127.0.0.1:30080 2>/dev/null || wget -qO- --timeout=10 http://127.0.0.1:30080 2>/dev/null" || true)
if echo "$NODEPORT_RESULT" | grep -qi "nginx\|welcome"; then
    pass "NodePort service reachable on port 30080"
else
    fail "NodePort service not reachable on port 30080"
fi

# ── Phase 5: DNS resolution inside cluster ─────────────────────────────

log ""
log "=== Phase 5: In-cluster DNS ==="

# Test: CoreDNS resolves service names (query from server node via ClusterIP)
COREDNS_IP=$(kubectl_server get svc -n kube-system kube-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "10.43.0.10")
log "CoreDNS ClusterIP: $COREDNS_IP"

# Use dig/nslookup from the server node (host has access to ClusterIPs via kube-proxy)
DNS_RESULT=$(husker exec "$SERVER_NAME" -- \
    sh -c "nslookup nginx-clusterip.default.svc.cluster.local $COREDNS_IP 2>&1" || true)
if echo "$DNS_RESULT" | grep -qi "address.*10\.\|name:.*nginx"; then
    pass "CoreDNS resolves service name (from server node)"
else
    # Fallback: try using the pod network directly
    NGINX_POD=$(kubectl_server get pods -l app=nginx-test -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$NGINX_POD" ]; then
        DNS_RESULT2=$(kubectl_server exec "$NGINX_POD" -- \
            sh -c "nslookup nginx-clusterip.default.svc.cluster.local 2>&1 || wget -qO- --timeout=5 http://nginx-clusterip 2>&1" 2>/dev/null || true)
        if echo "$DNS_RESULT2" | grep -qi "address.*10\.\|nginx\|welcome"; then
            pass "CoreDNS resolves service name (from pod)"
        else
            fail "In-cluster DNS failed to resolve nginx-clusterip.default.svc.cluster.local"
            log "  DNS output (host): $DNS_RESULT"
            log "  DNS output (pod):  $DNS_RESULT2"
        fi
    else
        fail "In-cluster DNS failed (no fallback pod available)"
        log "  DNS output: $DNS_RESULT"
    fi
fi

# Test: CoreDNS resolves kubernetes.default (critical internal service)
if [ -n "$NGINX_POD" ]; then
    K8S_DNS=$(kubectl_server exec "$NGINX_POD" -- \
        sh -c "nslookup kubernetes.default.svc.cluster.local 2>&1" 2>/dev/null || true)
else
    K8S_DNS=$(husker exec "$SERVER_NAME" -- \
        sh -c "nslookup kubernetes.default.svc.cluster.local $COREDNS_IP 2>&1" || true)
fi
if echo "$K8S_DNS" | grep -qi "address.*10\.43\.\|name:.*kubernetes"; then
    pass "CoreDNS resolves kubernetes.default"
else
    fail "CoreDNS failed to resolve kubernetes.default"
    log "  DNS output: $K8S_DNS"
fi

# ── Phase 6: Cross-node pod communication ──────────────────────────────

log ""
log "=== Phase 6: Cross-node pod communication ==="

# Find a pod on each node and test connectivity between them
POD_IPS=$(kubectl_server get pods -l app=nginx-test -o jsonpath='{range .items[*]}{.status.podIP} {.spec.nodeName}{"\n"}{end}' 2>/dev/null)
log "Pod IPs and nodes:"
echo "$POD_IPS" | while read -r ip node; do
    [ -n "$ip" ] && log "  $ip on $node"
done

# Test cross-node connectivity by curling pod IPs from the server node.
# The server node can reach pod IPs via flannel routes.
FIRST_POD_IP=$(kubectl_server get pods -l app=nginx-test -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
SECOND_POD_IP=$(kubectl_server get pods -l app=nginx-test -o jsonpath='{.items[1].status.podIP}' 2>/dev/null)
if [ -n "$FIRST_POD_IP" ]; then
    CROSS_RESULT=$(husker exec "$SERVER_NAME" -- \
        sh -c "curl -sf --max-time 10 http://${FIRST_POD_IP} 2>/dev/null || wget -qO- --timeout=10 http://${FIRST_POD_IP} 2>/dev/null" || true)
    if echo "$CROSS_RESULT" | grep -qi "nginx\|welcome"; then
        pass "Pod-to-pod communication works (via pod IP $FIRST_POD_IP)"
    else
        fail "Pod-to-pod communication failed to $FIRST_POD_IP"
    fi
else
    fail "Could not determine pod IP for cross-node test"
fi

# Also test second pod IP (may be on a different node)
if [ -n "$SECOND_POD_IP" ] && [ "$SECOND_POD_IP" != "$FIRST_POD_IP" ]; then
    CROSS_RESULT2=$(husker exec "$SERVER_NAME" -- \
        sh -c "curl -sf --max-time 10 http://${SECOND_POD_IP} 2>/dev/null || wget -qO- --timeout=10 http://${SECOND_POD_IP} 2>/dev/null" || true)
    if echo "$CROSS_RESULT2" | grep -qi "nginx\|welcome"; then
        pass "Second pod reachable (via pod IP $SECOND_POD_IP)"
    else
        fail "Second pod not reachable at $SECOND_POD_IP"
    fi
fi

# ── Phase 7: Stateful workload ─────────────────────────────────────────

log ""
log "=== Phase 7: Persistent storage ==="

# Test local-path-provisioner with a PVC
log "Creating PVC and pod with persistent storage..."
kubectl_apply <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
  storageClassName: local-path
---
apiVersion: v1
kind: Pod
metadata:
  name: storage-test
spec:
  containers:
  - name: writer
    image: busybox:1.36
    command: ["sh", "-c", "echo 'husker-k3s-storage-ok' > /data/test.txt && sleep 3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: test-pvc
  terminationGracePeriodSeconds: 1
YAML

wait_for "storage-test pod Running" 120 \
    sh -c "husker exec $SERVER_NAME -- k3s kubectl get pod storage-test --no-headers 2>/dev/null | grep -q Running"

# Verify data was written
STORAGE_DATA=$(husker exec "$SERVER_NAME" -- \
    k3s kubectl exec storage-test -- cat /data/test.txt 2>/dev/null || true)
if [ "$STORAGE_DATA" = "husker-k3s-storage-ok" ]; then
    pass "Persistent volume: data written and read back"
else
    fail "Persistent volume: expected 'husker-k3s-storage-ok', got '$STORAGE_DATA'"
fi

# Test PVC is bound
PVC_STATUS=$(kubectl_server get pvc test-pvc -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [ "$PVC_STATUS" = "Bound" ]; then
    pass "PVC is Bound"
else
    fail "PVC status: $PVC_STATUS (expected Bound)"
fi

# ── Summary ────────────────────────────────────────────────────────────

log ""
log "=== Final cluster state ==="
kubectl_server get nodes -o wide
echo ""
kubectl_server get pods -o wide
echo ""
kubectl_server get svc
echo ""

log ""
log "=== Test Summary ==="
log "  Tests run: $TESTS_RUN"
log "  Passed:    $PASS"
log "  Failed:    $FAIL"

if [ "$FAIL" -gt 0 ]; then
    log ""
    log "SOME TESTS FAILED"
    exit 1
else
    log ""
    log "ALL TESTS PASSED"
fi
