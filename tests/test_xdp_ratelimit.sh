#!/usr/bin/env bash
# Smoke test: verify token bucket semantics on a veth pair.
#
# Full command flow with default values (variables expanded):
#
#   scripts/setup_testbed.sh
#   build/xdp-ratelimit load --netns xdp_dst --iface veth_dst \
#       --rate 1000 --burst 2000 --mode auto
#   ip netns exec xdp_dst ip link show veth_dst           # expect prog/xdp
#   build/xdp-ratelimit stats --iface veth_dst           # expect 0/0
#
#   ip netns exec xdp_dst python3 tests/udp_sink.py --port 9999 --timeout 1 &
#   ip netns exec xdp_dst ss -lun                        # wait for :9999
#   ip netns exec xdp_src python3 tests/send_udp.py \
#       --src 10.10.0.1 --dst 10.10.0.2 --count 3000
#   build/xdp-ratelimit stats --iface veth_dst           # ~2000 pass / ~1000 drop
#
#   sleep 2.5
#   ip netns exec xdp_src python3 tests/send_udp.py \
#       --src 10.10.0.1 --dst 10.10.0.2 --count 1500     # all pass (refill)
#   ip netns exec xdp_src python3 tests/send_udp.py \
#       --src 10.10.0.3 --dst 10.10.0.2 --count 3000     # independent bucket
#   ip netns exec xdp_src python3 tests/send_variants.py \
#       --iface veth_src --kind badihl --count 3000 \
#       --src-ip 10.10.0.1 --dst-ip 10.10.0.2           # ignored (IHL=4)
#
#   build/xdp-ratelimit detach --netns xdp_dst --iface veth_dst
#   scripts/teardown_testbed.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/build/xdp-ratelimit"
NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_SRC=${VETH_SRC:-veth_src}
VETH_DST=${VETH_DST:-veth_dst}
SRC_IP=${SRC_IP:-10.10.0.1}
SRC_IP2=${SRC_IP2:-10.10.0.3}
DST_IP=${DST_IP:-10.10.0.2}
RATE=${RATE:-1000}
BURST=${BURST:-2000}

# The test scripts share fixed netns/iface/pin names; serialize them.
if command -v flock >/dev/null; then
    exec 9>/run/xdp-ratelimit-testbed.lock
    flock 9
fi

SINK_PID=""
SINK_OUT=$(mktemp)

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

stats_field() {
    "$BIN" stats --iface "$VETH_DST" |
        awk -v key="$1" '$1 == key ":" {print $2}'
}

cleanup() {
    if [ -n "$SINK_PID" ]; then
        kill "$SINK_PID" 2>/dev/null || true
    fi
    rm -f "$SINK_OUT"
    "$ROOT/scripts/teardown_testbed.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$ROOT/scripts/setup_testbed.sh"

"$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
    --rate "$RATE" --burst "$BURST" --mode auto

# prog/xdp is present for both native ("xdp") and generic ("xdpgeneric").
# Do not grep for "xdp": the link-netns field contains e.g. "xdp_src".
ip netns exec "$NS_DST" ip link show "$VETH_DST" | grep -q 'prog/xdp' ||
    fail "XDP is not attached"

pass=$(stats_field pass_packets)
drop=$(stats_field drop_packets)
if [ "$pass" != "0" ] || [ "$drop" != "0" ]; then
    fail "initial stats not zero: $pass/$drop"
fi

echo "[0] duplicate load is rejected and keeps pins"
if "$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
    --rate "$RATE" --burst "$BURST" --mode auto >/dev/null 2>&1; then
    fail "duplicate load unexpectedly succeeded"
fi
[ -e "/sys/fs/bpf/xdp-ratelimit/$VETH_DST/stats" ] ||
    fail "duplicate load removed the stats pin"
[ "$(stats_field pass_packets)" = "0" ] ||
    fail "duplicate load changed stats"

echo "[1] burst of 3000 from $SRC_IP (expect ~2000 pass / ~1000 drop)"
ip netns exec "$NS_DST" python3 "$ROOT/tests/udp_sink.py" \
    --port 9999 --timeout 1 >"$SINK_OUT" &
SINK_PID=$!
for _ in $(seq 1 50); do
    ip netns exec "$NS_DST" ss -lun 2>/dev/null | grep -q ':9999 ' && break
    sleep 0.05
done
ip netns exec "$NS_SRC" python3 "$ROOT/tests/send_udp.py" \
    --src "$SRC_IP" --dst "$DST_IP" --count 3000
wait "$SINK_PID" || fail "udp sink failed"
SINK_PID=""
pass=$(stats_field pass_packets)
drop=$(stats_field drop_packets)
total=$((pass + drop))
received=$(awk '/^received_packets:/ {print $2}' "$SINK_OUT")
echo "    pass=$pass drop=$drop total=$total received=$received"
[ "$total" -eq 3000 ] || fail "expected 3000 packets, got $total"
[ "$received" -eq "$pass" ] ||
    fail "delivered ($received) != passed ($pass)"
if [ "$pass" -lt 2000 ] || [ "$pass" -gt 2100 ]; then
    fail "pass out of range: $pass"
fi
if [ "$drop" -lt 900 ] || [ "$drop" -gt 1000 ]; then
    fail "drop out of range: $drop"
fi

echo "[2] idle 2.5s, then burst of 1500 (bucket refills, expect all pass)"
sleep 2.5
ip netns exec "$NS_SRC" python3 "$ROOT/tests/send_udp.py" \
    --src "$SRC_IP" --dst "$DST_IP" --count 1500
new_pass=$(stats_field pass_packets)
new_drop=$(stats_field drop_packets)
echo "    pass=$new_pass drop=$new_drop"
[ $((new_pass - pass)) -eq 1500 ] || fail "idle refill did not pass 1500"
[ "$new_drop" -eq "$drop" ] || fail "unexpected drops after refill"

echo "[3] burst of 3000 from second source $SRC_IP2 (independent bucket)"
ip netns exec "$NS_SRC" python3 "$ROOT/tests/send_udp.py" \
    --src "$SRC_IP2" --dst "$DST_IP" --count 3000
final_pass=$(stats_field pass_packets)
final_drop=$(stats_field drop_packets)
delta_pass=$((final_pass - new_pass))
delta_drop=$((final_drop - new_drop))
echo "    delta_pass=$delta_pass delta_drop=$delta_drop"
[ $((delta_pass + delta_drop)) -eq 3000 ] || fail "second source total mismatch"
if [ "$delta_pass" -lt 2000 ] || [ "$delta_pass" -gt 2100 ]; then
    fail "second source pass out of range: $delta_pass"
fi

echo "[4] malformed IHL=4 is ignored (no token/stat consumption)"
before_pass=$(stats_field pass_packets)
before_drop=$(stats_field drop_packets)
ip netns exec "$NS_SRC" python3 "$ROOT/tests/send_variants.py" \
    --iface "$VETH_SRC" --kind badihl --count 3000 \
    --src-ip "$SRC_IP" --dst-ip "$DST_IP"
sleep 0.2
after_pass=$(stats_field pass_packets)
after_drop=$(stats_field drop_packets)
echo "    delta_pass=$((after_pass - before_pass)) delta_drop=$((after_drop - before_drop))"
[ $((after_pass - before_pass)) -eq 0 ] || fail "badihl consumed pass tokens"
[ $((after_drop - before_drop)) -eq 0 ] || fail "badihl consumed drop tokens"

"$BIN" detach --netns "$NS_DST" --iface "$VETH_DST"
[ ! -e "/sys/fs/bpf/xdp-ratelimit/$VETH_DST" ] ||
    fail "pins were not cleaned up"

echo "PASS: xdp ratelimit smoke test"
