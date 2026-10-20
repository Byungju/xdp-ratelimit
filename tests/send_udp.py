#!/usr/bin/env python3
"""Small UDP sender used by smoke tests.

For high-rate benchmarking use the AF_PACKET based pktgen (next stage).
"""
import argparse
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--payload", type=int, default=64,
                        help="UDP payload bytes")
    parser.add_argument("--pps", type=float, default=0,
                        help="0 = send as fast as possible")
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be > 0")

    payload = b"x" * max(1, args.payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.src, 0))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    except OSError:
        pass

    start = time.monotonic()
    if args.pps > 0:
        interval = 1.0 / args.pps
        next_send = start
        for _ in range(args.count):
            sock.sendto(payload, (args.dst, args.port))
            next_send += interval
            remaining = next_send - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
    else:
        for _ in range(args.count):
            sock.sendto(payload, (args.dst, args.port))
    elapsed = time.monotonic() - start

    print(f"sent={args.count} elapsed_s={elapsed:.6f} "
          f"pps={args.count / elapsed:.1f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
