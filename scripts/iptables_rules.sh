#!/usr/bin/env bash
# Install/remove the iptables hashlimit baseline rule.
#
#   average 1000 pkt/s per source IP, burst 2000, drop above the limit
#
# Commands:
#   on       install (idempotent: replaces rules with the same --hashlimit-name)
#   off      remove all rules with the same --hashlimit-name
#   reset    zero chain/rule counters
#   stats    human readable table
#   metrics  machine readable counters (same keys as the XDP loader)
#   flush    flush the whole chain (dedicated testbed only)
set -euo pipefail

NS_DST=${NS_DST:-xdp_dst}
TABLE=raw
CHAIN=PREROUTING
NAME=${NAME:-ratelimit}
RATE=${RATE:-1000/sec}
BURST=${BURST:-2000}

die() {
    echo "error: $*" >&2
    exit 1
}

validate() {
    [[ $EUID -eq 0 ]] || die "must run as root"
    command -v ip >/dev/null || die "ip (iproute2) not found"
    command -v iptables >/dev/null || die "iptables not found"
    ip netns exec "$NS_DST" true 2>/dev/null ||
        die "netns '$NS_DST' not found (run scripts/setup_testbed.sh)"
    # 15 chars keeps the rule portable to the legacy xt_hashlimit backend.
    [[ $NAME =~ ^[A-Za-z0-9_.-]{1,15}$ ]] ||
        die "NAME must be 1..15 chars of [A-Za-z0-9_.-]"
    [[ $RATE =~ ^[1-9][0-9]*/(sec|second|s|min|minute|m|hour|day)$ ]] ||
        die "RATE must be a positive N/sec|second|s|min|minute|m|hour|day"
    [[ $BURST =~ ^[1-9][0-9]*$ ]] ||
        die "BURST must be a positive integer"
}

run() {
    ip netns exec "$NS_DST" iptables -w 5 -t "$TABLE" "$@"
}

RULE=(-m hashlimit --hashlimit-name "$NAME" --hashlimit-mode srcip
      --hashlimit-above "$RATE" --hashlimit-burst "$BURST" -j DROP)

# Delete every rule that carries our hashlimit name. Matching by name (not by
# the full spec) also removes leftovers installed with different rate/burst.
delete_named_rules() {
    local -a specs spec
    local line removed=0 specs_raw

    specs_raw=$(run -S "$CHAIN") || die "failed to list $TABLE/$CHAIN rules"
    mapfile -t specs <<<"$specs_raw"
    for line in "${specs[@]}"; do
        case "$line" in
        "-A $CHAIN "*) ;;
        *) continue ;;
        esac
        if [[ " $line " != *" --hashlimit-name $NAME "* ]]; then
            continue
        fi
        read -r -a spec <<<"${line#-A "$CHAIN" }"
        run -D "$CHAIN" "${spec[@]}"
        removed=$((removed + 1))
    done
    printf '%s\n' "$removed"
}

# Extract the packet counter (the first value after -c) from an iptables -S -v
# line. Prints nothing when the counter is absent.
packet_counter() {
    local -a tokens
    local i

    read -r -a tokens <<<"$1"
    for ((i = 0; i < ${#tokens[@]}; i++)); do
        if [[ ${tokens[i]} == "-c" && $((i + 1)) -lt ${#tokens[@]} ]]; then
            printf '%s\n' "${tokens[i + 1]}"
            return 0
        fi
    done
    return 1
}

cmd_on() {
    local removed
    removed=$(delete_named_rules)
    run -A "$CHAIN" "${RULE[@]}"
    echo "installed in $NS_DST ($TABLE/$CHAIN, removed $removed existing)"
    run -L "$CHAIN" -n -v -x --line-numbers
}

cmd_off() {
    local removed
    removed=$(delete_named_rules)
    echo "removed $removed rule(s) from $NS_DST ($TABLE/$CHAIN)"
}

cmd_reset() {
    run -Z "$CHAIN"
    echo "zeroed counters in $NS_DST ($TABLE/$CHAIN)"
}

cmd_stats() {
    run -L "$CHAIN" -n -v -x --line-numbers
}

cmd_metrics() {
    local -a specs
    local line counter pass=0 drop=0 found=0 policy="" specs_raw
    local version backend

    specs_raw=$(run -S "$CHAIN" -v) ||
        die "failed to list $TABLE/$CHAIN rules"
    mapfile -t specs <<<"$specs_raw"
    for line in "${specs[@]}"; do
        case "$line" in
        "-P $CHAIN "*)
            policy=$line
            ;;
        "-A $CHAIN "*)
            if [[ " $line " == *" --hashlimit-name $NAME "* ]]; then
                counter=$(packet_counter "$line") ||
                    die "cannot parse counter: $line"
                drop=$((drop + counter))
                found=$((found + 1))
            fi
            ;;
        esac
    done

    [[ -n $policy ]] || die "cannot read chain policy counter"
    [[ $found -gt 0 ]] || die "no $NAME hashlimit rule in $NS_DST ($TABLE/$CHAIN)"

    pass=$(packet_counter "$policy") ||
        die "cannot parse policy counter: $policy"
    # The dedicated testbed chain has no other rules; packets that reach the
    # policy are the accepted (passed) ones.
    version=$(ip netns exec "$NS_DST" iptables --version 2>/dev/null || true)
    backend=$(sed -n 's/.*(\(.*\)).*/\1/p' <<<"$version")
    echo "iptables_version: $version"
    echo "iptables_backend: ${backend:-unknown}"
    echo "netns: $NS_DST"
    echo "table: $TABLE"
    echo "chain: $CHAIN"
    echo "hashlimit_name: $NAME"
    echo "hashlimit_rate: $RATE"
    echo "hashlimit_burst: $BURST"
    echo "pass_packets: $pass"
    echo "drop_packets: $drop"
    echo "total_packets: $((pass + drop))"
}

cmd_flush() {
    echo "warning: flushing the entire $TABLE/$CHAIN chain in $NS_DST" >&2
    run -F "$CHAIN"
    echo "flushed $TABLE/$CHAIN in $NS_DST"
}

case "${1:-}" in
on | off | reset | stats | metrics | flush) ;;
*)
    echo "usage: $0 on|off|reset|stats|metrics|flush" >&2
    exit 1
    ;;
esac

validate

case "$1" in
on) cmd_on ;;
off) cmd_off ;;
reset) cmd_reset ;;
stats) cmd_stats ;;
metrics) cmd_metrics ;;
flush) cmd_flush ;;
esac
