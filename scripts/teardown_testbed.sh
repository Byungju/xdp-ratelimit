#!/usr/bin/env bash
# Remove only the testbed resources for this interface pair.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_SRC=${VETH_SRC:-veth_src}
VETH_DST=${VETH_DST:-veth_dst}

# Prefer the loader: it detaches XDP and removes only this interface's pins.
# It also works when the netns is already gone (map cleanup only).
if [ -x "$ROOT/build/xdp-ratelimit" ]; then
    "$ROOT/build/xdp-ratelimit" detach --netns "$NS_DST" \
        --iface "$VETH_DST" >/dev/null 2>&1 || true
else
    if ip netns list | grep -Fqw -- "$NS_DST"; then
        ip netns exec "$NS_DST" ip link set "$VETH_DST" xdp off \
            >/dev/null 2>&1 || true
    fi
fi

ip netns del "$NS_SRC" 2>/dev/null || true
ip netns del "$NS_DST" 2>/dev/null || true
ip link del "$VETH_SRC" 2>/dev/null || true
ip link del "$VETH_DST" 2>/dev/null || true

# Scoped pin cleanup (do not touch other interfaces sharing the bpffs root).
pin_dir="/sys/fs/bpf/xdp-ratelimit/$VETH_DST"
rm -f "$pin_dir/buckets" "$pin_dir/stats"
rmdir "$pin_dir" 2>/dev/null || true
rmdir /sys/fs/bpf/xdp-ratelimit 2>/dev/null || true
rm -f "/run/xdp-ratelimit/$VETH_DST.conf"
rmdir /run/xdp-ratelimit 2>/dev/null || true
