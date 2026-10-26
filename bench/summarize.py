#!/usr/bin/env python3
"""Summarize bench/run_bench.sh CSV output into a Markdown report."""
import argparse
import csv
import statistics
from collections import defaultdict


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def fmt(value, digits=1):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    rows = []
    with open(args.csv_path, newline="") as fp:
        for row in csv.DictReader(fp):
            for key in ("offered_pps", "processed_pps", "pass_pps", "drop_pct",
                        "busy_ms_per_mpps", "pktgen_cpu_ms", "host_busy_ms",
                        "received", "sent", "hook_pass", "hook_drop",
                        "hook_total"):
                try:
                    row[key] = float(row[key])
                except (KeyError, ValueError):
                    row[key] = None
            rows.append(row)

    groups = defaultdict(list)
    for row in rows:
        groups[(row["profile"], row["mode"])].append(row)

    lines = [
        "# XDP vs iptables benchmark summary",
        "",
        "host ms/Mpps is host-wide /proc/stat busy time and is noisy on a shared",
        "host; use processed pps and sender ms/Mpps as primary signals.",
        "",
    ]
    profiles = sorted({r["profile"] for r in rows})
    for profile in profiles:
        lines.append(f"## profile: {profile}")
        lines.append("")
        lines.append("| mode | reps | offered pps | processed pps | pass count | pass pps | drop % | "
                     "host ms/Mpps | sender ms/Mpps | received | xdp mode |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        for mode in sorted({m for (p, m) in groups if p == profile}):
            rs = groups[(profile, mode)]
            xdp_mode = next((r.get("xdp_mode", "") for r in rs
                             if r.get("xdp_mode")), "")
            lines.append(
                f"| {mode} | {len(rs)} | "
                f"{fmt(median([r['offered_pps'] for r in rs]))} | "
                f"{fmt(median([r['processed_pps'] for r in rs]))} | "
                f"{fmt(median([r['hook_pass'] for r in rs]))} | "
                f"{fmt(median([r['pass_pps'] for r in rs]))} | "
                f"{fmt(median([r['drop_pct'] for r in rs]), 2)} | "
                f"{fmt(median([r['busy_ms_per_mpps'] for r in rs]), 2) if profile != 'burst' else '-'} | "
                f"{fmt(median([r['pktgen_cpu_ms'] / (r['processed_pps'] / 1e6) for r in rs if r['processed_pps']]), 2)} | "
                f"{fmt(median([r['received'] for r in rs])) if profile in ('burst','rate','load') else '-'} | "
                f"{xdp_mode} |")
        lines.append("")

    report = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w") as fp:
            fp.write(report)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
