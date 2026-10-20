#!/usr/bin/env bash
# Create the netns/veth testbed used by benchmarks and tests.
set -euo pipefail

NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_SRC=${VETH_SRC:-veth_src}
VETH_DST=${VETH_DST:-veth_dst}
SRC_IP=${SRC_IP:-10.10.0.1}
SRC_IP2=${SRC_IP2:-10.10.0.3}
DST_IP=${DST_IP:-10.10.0.2}
PREFIX=${PREFIX:-24}
SRC_MAC=${SRC_MAC:-02:00:00:00:00:01}
DST_MAC=${DST_MAC:-02:00:00:00:00:02}

cleanup() {
    trap - ERR
    ip netns del "$NS_SRC" 2>/dev/null || true
    ip netns del "$NS_DST" 2>/dev/null || true
    ip link del "$VETH_SRC" 2>/dev/null || true
    ip link del "$VETH_DST" 2>/dev/null || true
}
trap 'cleanup; exit 1' ERR

# die() must clean up explicitly: an explicit exit does not trigger ERR.
die() {
    echo "error: $*" >&2
    cleanup
    exit 1
}

# Fixed names are shared by the test scripts; setup is destructive by design.
cleanup

ip netns add "$NS_SRC"
ip netns add "$NS_DST"

ip link add "$VETH_SRC" type veth peer name "$VETH_DST"
ip link set "$VETH_SRC" netns "$NS_SRC"
ip link set "$VETH_DST" netns "$NS_DST"

# Deterministic L2 and no IPv6 noise.
ip netns exec "$NS_SRC" ip link set lo up
ip netns exec "$NS_DST" ip link set lo up
ip netns exec "$NS_SRC" ip link set "$VETH_SRC" address "$SRC_MAC"
ip netns exec "$NS_DST" ip link set "$VETH_DST" address "$DST_MAC"
ip netns exec "$NS_SRC" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 \
    net.ipv6.conf.default.disable_ipv6=1
ip netns exec "$NS_DST" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 \
    net.ipv6.conf.default.disable_ipv6=1

ip netns exec "$NS_SRC" ip addr add "$SRC_IP/$PREFIX" dev "$VETH_SRC"
ip netns exec "$NS_SRC" ip addr add "$SRC_IP2/$PREFIX" dev "$VETH_SRC"
ip netns exec "$NS_DST" ip addr add "$DST_IP/$PREFIX" dev "$VETH_DST"

ip netns exec "$NS_SRC" ip link set "$VETH_SRC" up
ip netns exec "$NS_DST" ip link set "$VETH_DST" up

# Static neighbor entry: keep ARP out of the measured packet stream.
ip netns exec "$NS_SRC" ip neigh replace "$DST_IP" lladdr "$DST_MAC" \
    nud permanent dev "$VETH_SRC"

# Normalize offloads so one packet at the sender is one frame at the hook.
# (GRO is off on veth by default and UDP does not use GSO here, but this keeps
# future TCP/large-payload runs from being merged differently per hook.)
if command -v ethtool >/dev/null; then
    ip netns exec "$NS_SRC" ethtool -K "$VETH_SRC" gro off gso off tso off \
        >/dev/null 2>&1 || true
    ip netns exec "$NS_DST" ethtool -K "$VETH_DST" gro off gso off tso off \
        >/dev/null 2>&1 || true
fi

ip netns exec "$NS_SRC" sysctl -q -w net.ipv4.conf.all.rp_filter=0 \
    net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf."$VETH_SRC".rp_filter=0
ip netns exec "$NS_DST" sysctl -q -w net.ipv4.conf.all.rp_filter=0 \
    net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf."$VETH_DST".rp_filter=0

[ "$SRC_IP" != "$DST_IP" ] || die "SRC_IP and DST_IP must differ"
[ "$SRC_IP2" != "$DST_IP" ] || die "SRC_IP2 and DST_IP must differ"
ip netns exec "$NS_SRC" ip route get "$DST_IP" >/dev/null 2>&1 ||
    die "no route from $SRC_IP to $DST_IP (check PREFIX and addresses)"

echo "testbed ready:"
echo "  $NS_SRC: $VETH_SRC $SRC_IP,$SRC_IP2 -> $DST_IP ($NS_DST:$VETH_DST)"
