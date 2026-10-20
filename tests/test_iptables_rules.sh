#!/usr/bin/env bash
# Regression test for scripts/iptables_rules.sh.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RULES="$ROOT/scripts/iptables_rules.sh"
NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_DST=${VETH_DST:-veth_dst}
SRC_IP=${SRC_IP:-10.10.0.1}
DST_IP=${DST_IP:-10.10.0.2}
NAME=${NAME:-ratelimit}

# The test scripts share fixed netns/iface names; serialize them.
if command -v flock >/dev/null; then
    exec 9>/run/xdp-ratelimit-testbed.lock
    flock 9
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

count_rules() {
    ip netns exec "$NS_DST" iptables -t raw -S PREROUTING |
        grep -F -c -- "--hashlimit-name $NAME" || true
}

metric() {
    "$RULES" metrics | awk -v key="$1" '$1 == key ":" {print $2}'
}

trap '"$ROOT/scripts/teardown_testbed.sh" >/dev/null 2>&1 || true' EXIT
"$ROOT/scripts/setup_testbed.sh"

echo "[1] on is idempotent"
"$RULES" on >/dev/null
"$RULES" on >/dev/null
[ "$(count_rules)" -eq 1 ] || fail "expected 1 rule, got $(count_rules)"

echo "[2] counters start at zero"
"$RULES" reset >/dev/null
[ "$(metric pass_packets)" -eq 0 ] || fail "pass counter not zero"
[ "$(metric drop_packets)" -eq 0 ] || fail "drop counter not zero"

echo "[3] 3000 burst: ~2000 pass / ~1000 drop"
ip netns exec "$NS_SRC" python3 "$ROOT/tests/send_udp.py" \
    --src "$SRC_IP" --dst "$DST_IP" --count 3000 2>/dev/null
pass=$(metric pass_packets)
drop=$(metric drop_packets)
total=$(metric total_packets)
echo "    pass=$pass drop=$drop total=$total"
[ "$total" -eq 3000 ] || fail "expected total 3000, got $total"
if [ "$pass" -lt 2000 ] || [ "$pass" -gt 2100 ]; then
    fail "pass out of range: $pass"
fi
if [ "$drop" -lt 900 ] || [ "$drop" -gt 1000 ]; then
    fail "drop out of range: $drop"
fi

echo "[4] off removes only our rule"
ip netns exec "$NS_DST" iptables -t raw -A PREROUTING \
    -d 10.99.0.0/16 -j ACCEPT
"$RULES" off >/dev/null
[ "$(count_rules)" -eq 0 ] || fail "hashlimit rule still present"
ip netns exec "$NS_DST" iptables -t raw -S PREROUTING |
    grep -q -- '-d 10.99.0.0/16 -j ACCEPT' ||
    fail "unrelated rule was removed"

echo "[5] metrics fails without the rule"
if "$RULES" metrics >/dev/null 2>&1; then
    fail "metrics should fail when the rule is absent"
fi

echo "PASS: iptables_rules.sh test"
