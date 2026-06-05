#!/bin/sh
# Check if the running kernel has the features required by k3s.
#
# Run inside a Husker VM:
#   husker exec <vm> -- sh /path/to/check-k3s-kernel.sh
#
# Checks /proc/config.gz (if available) or /boot/config-$(uname -r).

set -eu

PASS=0
FAIL=0

check() {
    local option="$1"
    local desc="$2"
    if echo "$CONFIG" | grep -q "^${option}=[ym]"; then
        printf "  [OK]   %-30s %s\n" "$option" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  [FAIL] %-30s %s\n" "$option" "$desc"
        FAIL=$((FAIL + 1))
    fi
}

# Load kernel config
CONFIG=""
if [ -f /proc/config.gz ]; then
    CONFIG="$(zcat /proc/config.gz)"
elif [ -f "/boot/config-$(uname -r)" ]; then
    CONFIG="$(cat "/boot/config-$(uname -r)")"
else
    echo "Error: cannot find kernel config (/proc/config.gz or /boot/config-$(uname -r))"
    echo "Try: modprobe configs"
    exit 1
fi

echo "Kernel: $(uname -r)"
echo ""
echo "=== Filesystem ==="
check CONFIG_OVERLAY_FS "OverlayFS (container layers)"

echo ""
echo "=== Networking ==="
check CONFIG_BRIDGE "Bridge networking"
check CONFIG_VETH "Virtual Ethernet pairs"
check CONFIG_NETFILTER "Netfilter framework"
check CONFIG_NF_CONNTRACK "Connection tracking"
check CONFIG_NF_NAT "NAT support"
check CONFIG_IP_NF_IPTABLES "iptables"
check CONFIG_IP_NF_FILTER "iptables filter table"
check CONFIG_IP_NF_NAT "iptables NAT table"
check CONFIG_IP_NF_MANGLE "iptables mangle table"
check CONFIG_IP_VS "IPVS (kube-proxy)"
check CONFIG_IP_VS_RR "IPVS round-robin"
check CONFIG_IP_VS_WRR "IPVS weighted round-robin"
check CONFIG_IP_VS_SH "IPVS source hashing"
check CONFIG_IP_VS_NFCT "IPVS conntrack"
check CONFIG_NETFILTER_XT_MATCH_COMMENT "iptables comment match"
check CONFIG_VXLAN "VXLAN (flannel default backend)"

echo ""
echo "=== Cgroups ==="
check CONFIG_CGROUPS "Control groups"
check CONFIG_CGROUP_CPUACCT "CPU accounting"
check CONFIG_CGROUP_DEVICE "Device whitelist"
check CONFIG_CGROUP_FREEZER "Freezer"
check CONFIG_CGROUP_SCHED "Scheduler"
check CONFIG_CPUSETS "CPU sets"
check CONFIG_MEMCG "Memory controller"
check CONFIG_CGROUP_PIDS "PID controller"
check CONFIG_CGROUP_NET_PRIO "Network priority"

echo ""
echo "=== Namespaces ==="
check CONFIG_NAMESPACES "Namespaces support"
check CONFIG_UTS_NS "UTS namespace"
check CONFIG_IPC_NS "IPC namespace"
check CONFIG_PID_NS "PID namespace"
check CONFIG_NET_NS "Network namespace"
check CONFIG_USER_NS "User namespace"

echo ""
echo "=== Other ==="
check CONFIG_POSIX_MQUEUE "POSIX message queues"
check CONFIG_KEYS "Access key retention"
check CONFIG_SECCOMP "Seccomp"
check CONFIG_SECCOMP_FILTER "Seccomp BPF"

echo ""
echo "=== Summary ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Some required kernel features are missing."
    echo "You may need to build a custom kernel with these options enabled."
    exit 1
else
    echo ""
    echo "All required kernel features are present."
fi
