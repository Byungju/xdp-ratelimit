#!/usr/bin/env bash
# Read-only testbed inspection. Does not create, attach, or delete anything.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_SRC=${VETH_SRC:-veth_src}
VETH_DST=${VETH_DST:-veth_dst}

hr() {
    printf '\n=== %s ===\n' "$*"
}

src() { ip netns exec "$NS_SRC" "$@"; }
dst() { ip netns exec "$NS_DST" "$@"; }

if ! ip netns list | grep -Fqw -- "$NS_DST"; then
    echo "testbed not found (missing netns $NS_DST); run scripts/setup_testbed.sh" >&2
    exit 1
fi

hr "HOST"
ip netns list
echo "-- testbed links in host (should be absent) --"
ip -br link | grep -E "^($VETH_SRC|$VETH_DST)" || echo "absent"
printf 'netns ids: host=%s src=%s dst=%s\n' \
    "$(readlink /proc/self/ns/net)" \
    "$(src readlink /proc/self/ns/net)" \
    "$(dst readlink /proc/self/ns/net)"

hr "SRC: $NS_SRC/$VETH_SRC"
src ip -d link show "$VETH_SRC"
echo "-- addr --"
src ip addr show dev "$VETH_SRC"
echo "-- route --"
src ip route show table all
echo "-- neigh --"
src ip -s neigh show
echo "-- sysctl --"
src sysctl net.ipv6.conf.all.disable_ipv6 \
    net.ipv4.conf.all.rp_filter net.ipv4.conf."$VETH_SRC".rp_filter
echo "-- link stats --"
src ip -s link show "$VETH_SRC"

hr "DST: $NS_DST/$VETH_DST"
dst ip -d link show "$VETH_DST"
echo "-- addr --"
dst ip addr show dev "$VETH_DST"
echo "-- route --"
dst ip route show table all
echo "-- sysctl --"
dst sysctl net.ipv6.conf.all.disable_ipv6 \
    net.ipv4.conf.all.rp_filter net.ipv4.conf."$VETH_DST".rp_filter
echo "-- link stats --"
dst ip -s link show "$VETH_DST"

hr "PEER MAPPING"
printf 'src own=%s peer(iflink)=%s\n' \
    "$(src cat /sys/class/net/"$VETH_SRC"/ifindex)" \
    "$(src cat /sys/class/net/"$VETH_SRC"/iflink)"
printf 'dst own=%s peer(iflink)=%s\n' \
    "$(dst cat /sys/class/net/"$VETH_DST"/ifindex)" \
    "$(dst cat /sys/class/net/"$VETH_DST"/iflink)"

hr "QUEUES / OFFLOADS"
if command -v ethtool >/dev/null; then
    src ethtool -l "$VETH_SRC" 2>/dev/null || true
    echo "-- queue dirs --"
    src sh -c "ls -d /sys/class/net/$VETH_SRC/queues/* 2>/dev/null | sed 's#.*/##'"
    echo "-- gro/gso/tso --"
    dst ethtool -k "$VETH_DST" 2>/dev/null |
        grep -E '^(generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload):' ||
        true
fi
echo "-- qdisc --"
dst tc qdisc show dev "$VETH_DST" 2>/dev/null || true

hr "XDP STATE"
if dst ip link show "$VETH_DST" | grep -q 'prog/xdp'; then
    dst ip link show "$VETH_DST" | grep -E 'xdp|prog/'
else
    echo "no XDP program attached"
fi
if [ -e "/sys/fs/bpf/xdp-ratelimit/$VETH_DST/stats" ] &&
    [ -x "$ROOT/build/xdp-ratelimit" ]; then
    "$ROOT/build/xdp-ratelimit" stats --iface "$VETH_DST"
else
    echo "no pinned XDP stats"
fi
if command -v ethtool >/dev/null; then
    echo "-- veth driver XDP counters (cumulative) --"
    dst ethtool -S "$VETH_DST" 2>/dev/null |
        grep -E 'peer_ifindex|rx_queue_0_xdp_packets|rx_queue_0_xdp_drops' ||
        true
fi

hr "STACK COUNTERS (cumulative)"
dst nstat -az 2>/dev/null |
    grep -E 'IpInReceives|IpInDelivers|UdpInDatagrams|UdpNoPorts|UdpRcvbufErrors' ||
    true
