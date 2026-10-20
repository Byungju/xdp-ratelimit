#!/usr/bin/env python3
"""Craft non-standard frames for XDP parser tests.

Kinds:
  badihl  IPv4 with IHL=4 (invalid header length)
  vlan    IPv4 inside a single 802.1Q tag
  ipv6    minimal IPv6 + UDP (not handled by the IPv4-only program)
"""
import argparse
import socket
import struct


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build(kind: str, src_ip: str, dst_ip: str,
          src_mac: bytes, dst_mac: bytes) -> bytes:
    payload = b"X" * 64
    udp = struct.pack("!HHHH", 12345, 9999, 8 + len(payload), 0) + payload

    if kind == "badihl":
        ip = struct.pack("!BBHHHBBH4s4s", 0x44, 0, 92, 1, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        return dst_mac + src_mac + b"\x08\x00" + ip + udp

    if kind == "vlan":
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 92, 1, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        return (dst_mac + src_mac + b"\x81\x00" + b"\x00\x01" +
                b"\x08\x00" + ip + udp)

    if kind == "ipv6":
        src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, 8 + len(payload),
                          17, 64, src, dst)
        return dst_mac + src_mac + b"\x86\xdd" + ip6 + udp

    raise ValueError(f"unknown kind: {kind}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--kind", required=True,
                        choices=["badihl", "vlan", "ipv6"])
    parser.add_argument("--count", type=int, default=3000)
    parser.add_argument("--src-ip", default="10.10.0.1")
    parser.add_argument("--dst-ip", default="10.10.0.2")
    parser.add_argument("--src-mac", default="02:00:00:00:00:01")
    parser.add_argument("--dst-mac", default="02:00:00:00:00:02")
    args = parser.parse_args()

    frame = build(args.kind, args.src_ip, args.dst_ip,
                  bytes.fromhex(args.src_mac.replace(":", "")),
                  bytes.fromhex(args.dst_mac.replace(":", "")))

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for _ in range(args.count):
        sock.send(frame)

    print(f"kind={args.kind} sent={args.count} frame_len={len(frame)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
