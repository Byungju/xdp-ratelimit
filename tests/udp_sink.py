#!/usr/bin/env python3
"""UDP sink for delivery verification.

Drains the socket until it has been idle for --timeout seconds, then prints
the number of packets and bytes received. Keeping a receiver bound avoids the
ICMP port-unreachable generation that an idle closed port would cause.
"""
import argparse
import socket


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--rcvbuf", type=int, default=16 << 20)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SO_RCVBUFFORCE bypasses net.core.rmem_max (needs CAP_NET_ADMIN).
        sock.setsockopt(socket.SOL_SOCKET,
                        getattr(socket, "SO_RCVBUFFORCE", 33), args.rcvbuf)
    except OSError:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                            args.rcvbuf)
        except OSError:
            pass
    sock.bind((args.bind, args.port))
    sock.settimeout(args.timeout)

    packets = 0
    nbytes = 0
    try:
        while True:
            data, _ = sock.recvfrom(65535)
            packets += 1
            nbytes += len(data)
    except socket.timeout:
        pass

    print(f"received_packets: {packets}")
    print(f"received_bytes: {nbytes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
