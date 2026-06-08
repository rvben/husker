#!/bin/sh
# Configure the guest network interface at boot.
#
# Husker passes a static IP assignment on the kernel cmdline in the form:
#
#   ip=<client>::<gateway>:<netmask>::<iface>:off
#   e.g. ip=172.20.0.2::172.20.0.1:255.255.255.0::eth0:off
#
# Fields (1-indexed, colon-separated):
#   1  client  - guest IP address
#   2  server  - (empty; unused)
#   3  gateway - default route
#   4  netmask - dotted-decimal, e.g. 255.255.255.0
#   5  host    - (empty; unused)
#   6  iface   - interface name, e.g. eth0
#   7  autoconf - (off; unused)
#
# When an ip= token is found the interface is configured statically.
# When no ip= token is present the script falls back to udhcpc, which
# preserves compatibility with environments that supply a DHCP server.
#
# Must be POSIX sh / busybox ash compatible: no arrays, no [[ ]], no
# bashisms. Uses only: read, case, while, cut, printf, ip, udhcpc.

# Convert a dotted-decimal netmask (e.g. 255.255.255.0) to a prefix length.
# Works by counting the set bits in each octet using arithmetic only.
netmask_to_prefix() {
    local mask="$1"
    local prefix=0
    local octet rest

    rest="$mask"
    while [ -n "$rest" ]; do
        octet="${rest%%.*}"
        case "${rest}" in
            *.*)  rest="${rest#*.}" ;;
            *)    rest="" ;;
        esac

        # Count set bits in this octet via repeated bit-test.
        local n="$octet"
        local bits=0
        local i=7
        while [ "$i" -ge 0 ]; do
            local bit
            bit=$(( (n >> i) & 1 ))
            if [ "$bit" -eq 1 ]; then
                bits=$(( bits + 1 ))
            fi
            i=$(( i - 1 ))
        done
        prefix=$(( prefix + bits ))
    done

    echo "$prefix"
}

# Read /proc/cmdline and look for an ip= token.
CMDLINE=$(cat /proc/cmdline)
IP_TOKEN=""

for token in $CMDLINE; do
    case "$token" in
        ip=*) IP_TOKEN="${token#ip=}" ;;
    esac
done

if [ -n "$IP_TOKEN" ]; then
    # Parse colon-separated fields: client:server:gateway:netmask:host:iface:autoconf
    CLIENT=$(  echo "$IP_TOKEN" | cut -d: -f1)
    GATEWAY=$( echo "$IP_TOKEN" | cut -d: -f3)
    NETMASK=$( echo "$IP_TOKEN" | cut -d: -f4)
    IFACE=$(   echo "$IP_TOKEN" | cut -d: -f6)

    if [ -z "$CLIENT" ] || [ -z "$GATEWAY" ] || [ -z "$NETMASK" ] || [ -z "$IFACE" ]; then
        echo "husker-net: malformed ip= token '$IP_TOKEN', falling back to udhcpc" >&2
        exec udhcpc -b -i eth0
    fi

    PREFIX=$(netmask_to_prefix "$NETMASK")

    echo "husker-net: configuring $IFACE with $CLIENT/$PREFIX gw $GATEWAY"
    ip link set "$IFACE" up
    ip addr add "$CLIENT/$PREFIX" dev "$IFACE"
    # busybox ip supports 'add' but may not support 'replace'; ignore
    # RTNETLINK answers: File exists if a default route already exists.
    ip route add default via "$GATEWAY" 2>/dev/null || true
else
    echo "husker-net: no ip= on cmdline, starting udhcpc on eth0"
    exec udhcpc -b -i eth0
fi
