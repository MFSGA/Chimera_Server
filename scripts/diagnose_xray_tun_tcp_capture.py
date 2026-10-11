#!/usr/bin/env python3
"""Bounded, non-mutating IPv6/TCP wire probe for the disposable Xray TUN namespace.

Run only *inside* scripts/test_xray_tun_routes_netns.sh's isolated root
network namespace. The sockets are read-only AF_PACKET taps. The capture
records per-interface TCP SEQ/ACK, advertised window, payload length and
checksum; it does not require tcpdump, tshark or packet installation.
"""
import ipaddress
import select
import socket
import struct
import sys
import time


def checksum_valid(ip, tcp):
    pseudo = ip[8:24] + ip[24:40] + struct.pack("!I3xB", len(tcp), 6)
    data = pseudo + tcp
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total == 0xffff


def decode(frame):
    # AF_PACKET SOCK_RAW on veth starts with Ethernet; TUN may present
    # either a pseudo Ethernet header or the IPv6 packet directly.
    for offset in (14, 0, 16, 4):
        if len(frame) < offset + 60 or frame[offset] >> 4 != 6:
            continue
        ip = frame[offset:]
        if ip[6] != 6:  # direct IPv6/TCP, no extension headers in probe
            continue
        payload_len = struct.unpack_from("!H", ip, 4)[0]
        segment = ip[40:40 + payload_len]
        if len(segment) < 20 or len(segment) != payload_len:
            continue
        sport, dport, seq, ack = struct.unpack_from("!HHII", segment, 0)
        if 39643 not in (sport, dport):
            continue
        data_offset = (segment[12] >> 4) * 4
        if not 20 <= data_offset <= len(segment):
            continue
        flags = segment[13]
        window = struct.unpack_from("!H", segment, 14)[0]
        source = str(ipaddress.IPv6Address(ip[8:24]))
        destination = str(ipaddress.IPv6Address(ip[24:40]))
        summary = (
            f"{source}:{sport}>{destination}:{dport} "
            f"seq={seq} ack={ack} flags=0x{flags:02x} "
            f"win={window} data={len(segment) - data_offset} "
            f"len={len(frame)} csum={'OK' if checksum_valid(ip, segment) else 'BAD_OR_OFFLOAD'}"
        )
        return summary
    return None


def main():
    wanted = ("office-gw", "cxray-tun", "echo-gw")
    sockets = {}
    for iface in wanted:
        try:
            fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(0x86dd))
            fd.bind((iface, 0))
            fd.setblocking(False)
        except OSError as exc:
            print(f"CAPTURE interface={iface} unavailable={exc}", flush=True)
            continue
        sockets[fd] = iface
    if not sockets:
        sys.exit("CAPTURE no interfaces attached")
    print(f"CAPTURE ready={','.join(sockets.values())}", flush=True)
    started = time.monotonic()
    count = 0
    while time.monotonic() - started < 40 and count < 600:
        ready, _, _ = select.select(list(sockets), [], [], 0.3)
        for fd in ready:
            try:
                frame, address = fd.recvfrom(65535)
            except BlockingIOError:
                continue
            decoded = decode(frame)
            if decoded:
                count += 1
                print(f"CAPTURE +{time.monotonic()-started:.3f}s "
                      f"iface={sockets[fd]} pkttype={address[2]} {decoded}",
                      flush=True)
    print(f"CAPTURE finished events={count}", flush=True)


if __name__ == "__main__":
    main()
