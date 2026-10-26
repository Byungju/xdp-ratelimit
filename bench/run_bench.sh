#!/usr/bin/env bash
# Compare XDP and iptables on the same veth/netns testbed.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/build/xdp-ratelimit"
PKTGEN="$ROOT/build/pktgen"
SINK="$ROOT/build/udp_sink"
RULES="$ROOT/scripts/iptables_rules.sh"
NS_SRC=${NS_SRC:-xdp_src}
NS_DST=${NS_DST:-xdp_dst}
VETH_SRC=${VETH_SRC:-veth_src}
VETH_DST=${VETH_DST:-veth_dst}
SRC_IP=${SRC_IP:-10.10.0.1}
DST_IP=${DST_IP:-10.10.0.2}
BENCH_PORT=9999
SINK_OUT=""
SINK_PID=""
CURRENT_LOG=""

SENDERS=${SENDERS:-2}
SINK_CPU=${SINK_CPU:-2}
RATE_PPS=${RATE_PPS:-5000}
RATE_SEC=${RATE_SEC:-3}
LOAD_PPS=${LOAD_PPS:-200000}
LOAD_SEC=${LOAD_SEC:-3}
MAX_SEC=${MAX_SEC:-3}
BURST_COUNT=${BURST_COUNT:-30000}
MULTI_SRC=${MULTI_SRC:-1000}
MULTI_IP=${MULTI_IP:-10.20.0.1}
REPS=${REPS:-3}
QUICK=0
MODES="none xdp xdp-generic iptables xdp-drop xdp-drop-generic iptables-drop"
PROFILES="burst rate load max multi"
OUTDIR="$ROOT/bench/results"

usage() {
    cat <<EOF
usage: $0 [--quick] [--reps N] [--modes "m1 m2 ..."] [--profiles "p1 p2 ..."]
          [--senders N] [--out DIR]
modes: none xdp xdp-generic iptables xdp-drop xdp-drop-generic iptables-drop
profiles: burst rate load max multi
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
    --quick) QUICK=1; shift ;;
    --reps) REPS=$2; shift 2 ;;
    --modes) MODES=$2; shift 2 ;;
    --profiles) PROFILES=$2; shift 2 ;;
    --senders) SENDERS=$2; shift 2 ;;
    --out) OUTDIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
    esac
done

if [ "$QUICK" = 1 ]; then
    REPS=1
    RATE_SEC=1
    LOAD_SEC=1
    LOAD_PPS=100000
    MAX_SEC=1
    BURST_COUNT=5000
fi

if [ "$EUID" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi
for cmd in ip iptables taskset ss flock python3; do
    command -v "$cmd" >/dev/null || {
        echo "missing command: $cmd" >&2
        exit 1
    }
done
for tool in "$BIN" "$PKTGEN" "$SINK"; do
    [ -x "$tool" ] || {
        echo "missing tool: $tool (run make bench)" >&2
        exit 1
    }
done

NCPU=$(nproc)
if [ "$SENDERS" -gt "$NCPU" ]; then
    SENDERS=$NCPU
fi
if [ "$SINK_CPU" -ge "$NCPU" ]; then
    SINK_CPU=$((NCPU - 1))
fi

exec 9>/run/xdp-ratelimit-testbed.lock
flock 9

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
CSV="$OUTDIR/raw-$STAMP.csv"
SUMMARY="$OUTDIR/summary-$STAMP.md"
ENVFILE="$OUTDIR/env-$STAMP.txt"
TMP=$(mktemp -d /tmp/xdp-bench.XXXXXX)

cleanup() {
    if [ -n "$SINK_PID" ]; then
        kill "$SINK_PID" 2>/dev/null || true
    fi
    "$ROOT/scripts/teardown_testbed.sh" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

src() { ip netns exec "$NS_SRC" "$@"; }
dst() { ip netns exec "$NS_DST" "$@"; }

cpu_busy_jiffies() {
    awk '/^cpu / {print $2+$3+$4+$7+$8+$9}' /proc/stat
}

hook_stats() { # mode -> pass drop total
    case "$1" in
    xdp | xdp-generic | xdp-drop | xdp-drop-generic)
        "$BIN" stats --iface "$VETH_DST" | awk '
            $1=="pass_packets:" {p=$2}
            $1=="drop_packets:" {d=$2}
            $1=="total_packets:" {t=$2}
            END {print p+0, d+0, t+0}'
        ;;
    iptables)
        "$RULES" metrics | awk '
            $1=="pass_packets:" {p=$2}
            $1=="drop_packets:" {d=$2}
            $1=="total_packets:" {t=$2}
            END {print p+0, d+0, t+0}'
        ;;
    iptables-drop)
        dst iptables -t raw -S PREROUTING -v | awk '
            /^-P / {for (i=1;i<=NF;i++) if ($i=="-c") p=$(i+1)}
            /^-A / && /-j DROP/ {for (i=1;i<=NF;i++) if ($i=="-c") d+=$(i+1)}
            END {print p+0, d+0, p+d}'
        ;;
    none)
        echo "0 0 0"
        ;;
    esac
}

xdp_mode() {
    if [ -r /run/xdp-ratelimit/"$VETH_DST".conf ]; then
        awk -F= '/^mode=/{print $2}' /run/xdp-ratelimit/"$VETH_DST".conf
    fi
}

iptables_backend() {
    iptables --version 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p'
}

apply_mode() { # mode
    case "$1" in
    none) ;;
    xdp)
        "$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
            --rate 1000 --burst 2000 --mode auto >/dev/null
        ;;
    xdp-generic)
        "$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
            --rate 1000 --burst 2000 --mode generic >/dev/null
        ;;
    xdp-drop)
        "$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
            --rate 1000 --burst 2000 --mode auto --drop-all >/dev/null
        ;;
    xdp-drop-generic)
        "$BIN" load --netns "$NS_DST" --iface "$VETH_DST" \
            --rate 1000 --burst 2000 --mode generic --drop-all >/dev/null
        ;;
    iptables)
        "$RULES" on >/dev/null
        "$RULES" reset >/dev/null
        ;;
    iptables-drop)
        dst iptables -t raw -A PREROUTING -j DROP
        dst iptables -t raw -Z PREROUTING
        ;;
    *)
        echo "unknown mode: $1" >&2
        exit 1
        ;;
    esac
}

reapply_mode() { # mode, after warmup
    case "$1" in
    none) ;;
    xdp | xdp-generic | xdp-drop | xdp-drop-generic)
        "$BIN" detach --netns "$NS_DST" --iface "$VETH_DST" >/dev/null 2>&1 || true
        apply_mode "$1"
        ;;
    iptables)
        "$RULES" off >/dev/null 2>&1 || true
        apply_mode "$1"
        ;;
    iptables-drop)
        dst iptables -t raw -F PREROUTING
        apply_mode "$1"
        ;;
    esac
}

senders_for() { # profile
    case "$1" in
    burst | rate | load) echo 1 ;;
    *) echo "$SENDERS" ;;
    esac
}

start_sink() { # profile
    case "$1" in
    burst | rate | load) ;;
    *) return 0 ;;
    esac
    SINK_OUT="$TMP/sink-$CURRENT_LOG"
    dst taskset -c "$SINK_CPU" "$SINK" --port "$BENCH_PORT" --timeout 1 \
        >"$SINK_OUT" 2>&1 &
    SINK_PID=$!
    for _ in $(seq 1 100); do
        dst ss -lun 2>/dev/null | grep -q ":$BENCH_PORT " && return 0
        sleep 0.02
    done
    echo "sink did not become ready" >&2
    exit 1
}

stop_sink() {
    if [ -n "$SINK_PID" ]; then
        wait "$SINK_PID" || true
        SINK_PID=""
    fi
}

pktgen_args() { # profile, sender index
    local profile=$1
    local idx=$2
    local common="--iface $VETH_SRC --dst-ip $DST_IP --payload 64"

    case "$profile" in
    burst) echo "$common --count $BURST_COUNT" ;;
    rate) echo "$common --pps $RATE_PPS --duration $RATE_SEC" ;;
    load) echo "$common --pps $LOAD_PPS --duration $LOAD_SEC" ;;
    max) echo "$common --duration $MAX_SEC" ;;
    multi)
        local ip
        ip=$(python3 - "$MULTI_IP" "$idx" <<'PY'
import ipaddress, sys
base = int(ipaddress.IPv4Address(sys.argv[1]))
off = int(sys.argv[2]) * 100000
print(ipaddress.IPv4Address(base + off))
PY
)
        echo "$common --duration $MAX_SEC --src-ip $ip --src-ip-count $MULTI_SRC"
        ;;
    esac
}

run_senders() { # profile, log-prefix
    local profile=$1
    local prefix=$2
    local n
    local -a pids=()
    local -a files=()
    local c

    n=$(senders_for "$profile")
    for ((c = 0; c < n; c++)); do
        local args
        # shellcheck disable=SC2207
        args=($(pktgen_args "$profile" "$c"))
        files+=("$TMP/${prefix}-$c.out")
        src taskset -c "$c" "$PKTGEN" "${args[@]}" >"${files[$c]}" 2>&1 &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    cat "${files[@]}" >"$TMP/${prefix}.all"
}

parse_senders() { # prefix -> sent elapsed cpu_ms errors
    awk -F'[= ]' '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "sent") sent += $(i+1)
                else if ($i == "elapsed_s" && $(i+1) > elapsed) elapsed = $(i+1)
                else if ($i == "cpu_user_ms") cpu += $(i+1)
                else if ($i == "cpu_sys_ms") cpu += $(i+1)
                else if ($i == "errors") err += $(i+1)
            }
        }
        END {printf "%d %.6f %.3f %d\n", sent, elapsed, cpu, err}
    ' "$TMP/$1.all"
}

trial() { # profile mode rep
    local profile=$1 mode=$2 rep=$3
    local pass drop total sent elapsed cpu_ms err received=0
    local xmode="" backend="" extra=""
    local busy0 busy1 busy_ms processed pass_pps drop_pct per_mpps
    local sink_received=""

    CURRENT_LOG="$profile-$mode-$rep"
    echo "[$profile/$mode/$rep] setup + warmup" >&2

    "$ROOT/scripts/teardown_testbed.sh" >/dev/null 2>&1 || true
    "$ROOT/scripts/setup_testbed.sh" >/dev/null
    apply_mode "$mode"

    # Warm caches/JIT, then reset the limiter state/counters.
    run_senders burst "warm-$CURRENT_LOG" >/dev/null
    sleep 0.1
    reapply_mode "$mode"

    start_sink "$profile"

    busy0=$(cpu_busy_jiffies)
    run_senders "$profile" "$CURRENT_LOG"
    sleep 0.3
    busy1=$(cpu_busy_jiffies)
    stop_sink

    read -r sent elapsed cpu_ms err < <(parse_senders "$CURRENT_LOG")
    read -r pass drop total < <(hook_stats "$mode")
    if [ "$mode" = none ]; then
        pass=$sent
        drop=0
        total=$sent
    fi
    if [ "$profile" = burst ] || [ "$profile" = rate ] || [ "$profile" = load ]; then
        sink_received=$(awk -F= '/^received_packets=/{print $2}' "$SINK_OUT")
        received=${sink_received:-0}
    fi

    xmode=$(xdp_mode)
    backend=$(iptables_backend)
    if [ "$pass" -gt 0 ] && [ -n "$sink_received" ]; then
        if [ "$received" -ne "$pass" ]; then
            extra="$extra;sink_mismatch:$received!=$pass"
        fi
    fi
    if [ "$mode" != none ] && [ "$total" -ne "$sent" ]; then
        extra="$extra;hook_mismatch:$total!=$sent"
    fi
    if [ "$err" -ne 0 ]; then
        extra="$extra;tx_errors:$err"
    fi
    extra="${extra#;}"

    busy_ms=$(( (busy1 - busy0) * 1000 / $(getconf CLK_TCK) ))
    elapsed=${elapsed:-0.000001}
    processed=$(awk -v t="$total" -v e="$elapsed" 'BEGIN{printf "%.1f", t/e}')
    pass_pps=$(awk -v p="$pass" -v e="$elapsed" 'BEGIN{printf "%.1f", p/e}')
    drop_pct=$(awk -v d="$drop" -v t="$total" 'BEGIN{if (t > 0) printf "%.2f", 100*d/t; else print "0.00"}')
    per_mpps=$(awk -v b="$busy_ms" -v t="$total" 'BEGIN{if (t > 0) printf "%.2f", b/(t/1000000); else print "0.00"}')

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$profile" "$mode" "$rep" "$(senders_for "$profile")" \
        "$(awk -v s="$sent" -v e="$elapsed" 'BEGIN{printf "%.1f", s/e}')" \
        "$sent" "$elapsed" "$pass" "$drop" "$total" "$processed" \
        "$pass_pps" "$drop_pct" "$busy_ms" "$per_mpps" "$cpu_ms" \
        "$received" "${xmode:--}" "${backend:--}" "$extra" >>"$CSV"

    echo "  sent=$sent pass=$pass drop=$drop processed=$processed pps " \
         "busy=${busy_ms}ms recv=$received $extra" >&2
    "$ROOT/scripts/teardown_testbed.sh" >/dev/null 2>&1 || true
}

{
    echo "mode kernel=$(uname -r) nproc=$NCPU senders=$SENDERS sink_cpu=$SINK_CPU"
    echo "iptables=$(iptables --version 2>/dev/null)"
    echo "cpu=$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)"
    echo "rate_pps=$RATE_PPS rate_sec=$RATE_SEC load_pps=$LOAD_PPS load_sec=$LOAD_SEC max_sec=$MAX_SEC burst=$BURST_COUNT"
    echo "multi_src=$MULTI_SRC modes=$MODES profiles=$PROFILES reps=$REPS"
} | tee "$ENVFILE" >&2

echo "profile,mode,rep,senders,offered_pps,sent,elapsed_s,hook_pass,hook_drop,hook_total,processed_pps,pass_pps,drop_pct,host_busy_ms,busy_ms_per_mpps,pktgen_cpu_ms,received,xdp_mode,iptables_backend,extra" >"$CSV"

read -r -a MODE_ARR <<<"$MODES"
read -r -a PROFILE_ARR <<<"$PROFILES"

for profile in "${PROFILE_ARR[@]}"; do
    for ((rep = 1; rep <= REPS; rep++)); do
        offset=$(( (rep - 1) % ${#MODE_ARR[@]} ))
        for ((i = 0; i < ${#MODE_ARR[@]}; i++)); do
            mode=${MODE_ARR[$(((i + offset) % ${#MODE_ARR[@]}))]}
            case "$mode" in
            *drop*)
                case "$profile" in
                max | load) ;;
                *) continue ;;
                esac
                ;;
            esac
            trial "$profile" "$mode" "$rep"
        done
    done
done

python3 "$ROOT/bench/summarize.py" "$CSV" --out "$SUMMARY" >/dev/null
echo "raw:     $CSV"
echo "summary: $SUMMARY"
echo "env:     $ENVFILE"
