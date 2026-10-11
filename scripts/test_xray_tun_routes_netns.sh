#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
host_uid=$(id -u)
for command_name in cargo unshare nsenter ip nft sysctl python3 grep seq sleep readlink; do
    command -v "$command_name" >/dev/null
done
if [[ ${XRAY_TUN_SEEDED_NETEM:-0} == 1 || ${XRAY_TUN_BULK_ECHO:-0} == 1 ]]; then
    command -v tc >/dev/null || {
        printf 'Seeded Linux packet-loss probe requires tc (iproute2).\n' >&2
        exit 2
    }
fi
xray_bin=${XRAY_BIN:-}
if [[ -n "$xray_bin" ]]; then
    if [[ "$xray_bin" != /* ]]; then
        xray_bin="$repo_root/$xray_bin"
    fi
    if [[ ! -x "$xray_bin" ]]; then
        printf 'XRAY_BIN must name an executable Xray binary.\n' >&2
        exit 2
    fi
    xray_bin=$(readlink -f -- "$xray_bin")
    read -r xray_version < <("$xray_bin" version)
    if [[ "$xray_version" != *"Xray 26.9.9"* ]]; then
        printf 'Xray TUN client probe requires Xray 26.9.9; found: %s\n' \
            "$xray_version" >&2
        exit 2
    fi
fi

cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features xray-tun --locked

unshare --user --map-users="0:${host_uid}:1" --net bash -s -- \
    "$repo_root" "$xray_bin" <<'NAMESPACE_SCRIPT'
set -euo pipefail
repo_root=$1
xray_bin=$2
cd "$repo_root"
ip link set lo up
config_file=$(mktemp --suffix=.yaml)
failure_config_file=$(mktemp --suffix=.yaml)
server_log_file=$(mktemp)
failure_log_file=$(mktemp)
echo_log_file=$(mktemp)
echo_ready_file=$(mktemp)
stalled_tcp_release_file=$(mktemp)
rm -f "$stalled_tcp_release_file"
xray_client_config_file=
xray_client_log_file=
xray_reference_server_config_file=
xray_reference_server_log_file=
xray_reference_server_pid=
xray_reference_tun_config_file=
xray_reference_tun_log_file=
xray_reference_tun_pid=
office_client_ns_pid=
echo_server_ns_pid=
echo_server_pid=
ptb_capture_pid=
ptb_capture_log_file=
server_pid=
xray_client_pid=
trap 'exit_status=$?; printf "%s\n" "Xray TUN route namespace test failed ($exit_status): $BASH_COMMAND" >&2; ip -4 route show table main >&2 || true; ip -6 route show table main >&2 || true; ip -o addr show >&2 || true; ip -s link show dev cxray-tun >&2 || true; nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route show >&2 || true; nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route show >&2 || true; cat "$server_log_file" "$failure_log_file" "$echo_log_file" "$xray_client_log_file" "$xray_reference_server_log_file" "$xray_reference_tun_log_file" >&2 2>/dev/null || true' ERR
cleanup() {
    if [[ -n "$ptb_capture_pid" ]] && kill -0 "$ptb_capture_pid" 2>/dev/null; then
        kill -TERM "$ptb_capture_pid" 2>/dev/null || true
        wait "$ptb_capture_pid" 2>/dev/null || true
    fi
    if [[ -n "$xray_client_pid" ]] && kill -0 "$xray_client_pid" 2>/dev/null; then
        kill -TERM "$xray_client_pid" 2>/dev/null || true
        wait "$xray_client_pid" 2>/dev/null || true
    fi
    if [[ -n "$xray_reference_server_pid" ]] \
        && kill -0 "$xray_reference_server_pid" 2>/dev/null; then
        kill -TERM "$xray_reference_server_pid" 2>/dev/null || true
        wait "$xray_reference_server_pid" 2>/dev/null || true
    fi
    if [[ -n "$xray_reference_tun_pid" ]] \
        && kill -0 "$xray_reference_tun_pid" 2>/dev/null; then
        kill -TERM "$xray_reference_tun_pid" 2>/dev/null || true
        wait "$xray_reference_tun_pid" 2>/dev/null || true
    fi
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ -n "$echo_server_pid" ]] && kill -0 "$echo_server_pid" 2>/dev/null; then
        kill -TERM "$echo_server_pid" 2>/dev/null || true
        wait "$echo_server_pid" 2>/dev/null || true
    fi
    for namespace_pid in "$office_client_ns_pid" "$echo_server_ns_pid"; do
        if [[ -n "$namespace_pid" ]] && kill -0 "$namespace_pid" 2>/dev/null; then
            kill -TERM "$namespace_pid" 2>/dev/null || true
            wait "$namespace_pid" 2>/dev/null || true
        fi
    done
    rm -f "$config_file" "$failure_config_file" "$server_log_file" \
        "$failure_log_file" "$echo_log_file" "$echo_ready_file" \
        "$stalled_tcp_release_file" "$ptb_capture_log_file"
    if [[ -n "$xray_client_config_file" ]]; then
        rm -f "$xray_client_config_file" "$xray_client_log_file"
    fi
    if [[ -n "$xray_reference_server_config_file" ]]; then
        rm -f "$xray_reference_server_config_file" "$xray_reference_server_log_file"
    fi
    if [[ -n "$xray_reference_tun_config_file" ]]; then
        rm -f "$xray_reference_tun_config_file" "$xray_reference_tun_log_file"
    fi
}
trap cleanup EXIT

cat >"$config_file" <<'YAML'
log:
  loglevel: warning
inbounds:
  - tag: xray-tun-route-smoke
    protocol: tun
    sniffing:
      enabled: true
      destOverride: [quic]
      routeOnly: true
    settings:
      name: cxray-tun
      mtu: 1400
      gateway: [10.44.0.1/24, fd18:44::1/64]
      autoSystemRoutingTable: [198.18.44.0/24, fd18:198:44::/64]
outbounds:
  - tag: direct
    protocol: freedom
  - tag: quic-sni-block
    protocol: blackhole
  - tag: immediate-blackhole
    protocol: blackhole
routing:
  rules:
    - type: field
      network: [tcp]
      port: "39647"
      outboundTag: immediate-blackhole
    - type: field
      domain: [full:www.google.com]
      network: [udp]
      outboundTag: quic-sni-block
YAML

cat >"$failure_config_file" <<'YAML'
log:
  loglevel: warning
inbounds:
  - tag: xray-tun-route-rollback
    protocol: tun
    settings:
      name: cxray-fail
      mtu: 1400
      gateway: [10.45.0.1/24, fd18:45::1/64]
      autoSystemRoutingTable: [198.18.45.0/24, 198.18.46.0/24, fd18:198:45::/64]
outbounds:
  - tag: direct
    protocol: freedom
YAML

ip -4 route add 198.18.46.0/24 dev lo metric 1
failure_status=0
target/debug/chimera_server_app --config "$failure_config_file" \
    >"$failure_log_file" 2>&1 || failure_status=$?
if (( failure_status == 0 )); then
    printf 'Xray TUN unexpectedly started despite a conflicting main-table route.\n' >&2
    exit 1
fi
grep -Fq 'server startup failed; startup resources rolled back' "$failure_log_file"
if ip link show dev cxray-fail >/dev/null 2>&1; then
    printf 'Xray TUN device remained after route-install rollback.\n' >&2
    exit 1
fi
if ip -4 route show table main exact 198.18.45.0/24 | grep -Fq 'cxray-fail'; then
    printf 'Partially installed Xray TUN route remained after route-install rollback.\n' >&2
    exit 1
fi
ip -4 route show table main exact 198.18.46.0/24 | grep -F 'dev lo' >/dev/null
if ip -4 route show table main exact 10.45.0.0/24 | grep -Fq 'cxray-fail'; then
    printf 'Xray TUN gateway address route remained after route-install rollback.\n' >&2
    exit 1
fi

wait_for_network_namespace() {
    local namespace_pid=$1
    local parent_namespace
    parent_namespace=$(readlink /proc/self/ns/net)
    for attempt in $(seq 1 50); do
        if [[ -r "/proc/$namespace_pid/ns/net" ]] \
            && [[ "$(readlink "/proc/$namespace_pid/ns/net")" != "$parent_namespace" ]]; then
            return 0
        fi
        sleep 0.02
    done
    printf 'Network namespace process %s did not enter its namespace.\n' "$namespace_pid" >&2
    return 1
}

ip link add office-gw type veth peer name office-client
ip addr add 10.251.0.1/24 dev office-gw
ip -6 addr add fd18:251::1/64 nodad dev office-gw
ip link set office-gw up
unshare --net sleep infinity >/dev/null 2>&1 &
office_client_ns_pid=$!
wait_for_network_namespace "$office_client_ns_pid"
ip link set office-client netns "$office_client_ns_pid"
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip addr add 10.251.0.2/24 dev office-client
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 addr add fd18:251::2/64 nodad dev office-client
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip link set office-client up
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route add 198.18.44.0/24 via 10.251.0.1
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route add fd18:198:44::/64 via fd18:251::1

ip link add echo-gw type veth peer name echo-ns
ip addr add 10.250.0.1/24 dev echo-gw
ip -6 addr add fd18:250::1/64 nodad dev echo-gw
ip link set echo-gw up
unshare --net sleep infinity >/dev/null 2>&1 &
echo_server_ns_pid=$!
wait_for_network_namespace "$echo_server_ns_pid"
ip link set echo-ns netns "$echo_server_ns_pid"
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip addr add 10.250.0.2/24 dev echo-ns
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip -6 addr add fd18:250::2/64 nodad dev echo-ns
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip addr add 198.18.44.20/32 dev lo
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip -6 addr add fd18:198:44::20/128 nodad dev lo
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip addr add 198.18.45.20/32 dev lo
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip -6 addr add fd18:198:45::20/128 nodad dev lo
nsenter --net="/proc/$echo_server_ns_pid/ns/net" ip link set echo-ns up

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.office-gw.rp_filter=0
# The test-only UID rule routes the server's Freedom sockets around the TUN to
# the echo namespace. Keep Office ingress on main so client packets still hit TUN.
ip rule add pref 50 from 10.251.0.0/24 iif office-gw lookup main
ip -6 rule add pref 50 from fd18:251::/64 iif office-gw lookup main
ip rule add pref 100 uidrange 0-0 lookup 10001
ip -6 rule add pref 100 uidrange 0-0 lookup 10001
ip route add table 10001 198.18.44.20/32 via 10.250.0.2 dev echo-gw
ip -6 route add table 10001 fd18:198:44::20/128 via fd18:250::2 dev echo-gw
ip route add table 10001 198.18.45.20/32 via 10.250.0.2 dev echo-gw
ip -6 route add table 10001 fd18:198:45::20/128 via fd18:250::2 dev echo-gw

nsenter --net="/proc/$echo_server_ns_pid/ns/net" python3 -u - \
    "$echo_ready_file" "$stalled_tcp_release_file" <<'PY' >"$echo_log_file" 2>&1 &
import socket
import sys
import threading
import struct
import os
from pathlib import Path

ready_file = Path(sys.argv[1])
stalled_release_file = Path(sys.argv[2])
listeners = []
for family, address in (
    (socket.AF_INET, "198.18.44.20"),
    (socket.AF_INET6, "fd18:198:44::20"),
    (socket.AF_INET, "198.18.45.20"),
    (socket.AF_INET6, "fd18:198:45::20"),
):
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    tcp.bind((address, 39643))
    tcp.listen()
    # Dedicated no-read target for true *server receive-window* pressure.
    # Its receive loop is gated by a shared file so the raw client can
    # establish that the TUN advertised a zero window before releasing it.
    stalled_tcp = socket.socket(family, socket.SOCK_STREAM)
    stalled_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        stalled_tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    stalled_tcp.bind((address, 39648))
    stalled_tcp.listen()
    udp = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    udp.bind((address, 39644))
    ptb_udp = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        ptb_udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ptb_udp.bind((address, 39646))
    listeners.extend((tcp, stalled_tcp, udp, ptb_udp))

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def send_pmtu_error(listener, payload, peer):
    family = listener.family
    local = listener.getsockname()[0]
    if family == socket.AF_INET:
        source = socket.inet_aton(peer[0])
        target = socket.inet_aton(local)
        udp_length = len(payload) + 8
        udp = struct.pack("!HHHH", peer[1], 39646, udp_length, 0)
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + udp_length, 0x6241, 0,
            64, socket.IPPROTO_UDP, 0, source, target,
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        quoted = ip + udp
        message = struct.pack("!BBHHH", 3, 4, 0, 0, 1280) + quoted
        message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw.bind((local, 0))
        raw.sendto(message, (peer[0], 0))
        raw.close()
        return "IPv4 Fragmentation Needed"

    source = socket.inet_pton(socket.AF_INET6, peer[0])
    target = socket.inet_pton(socket.AF_INET6, local)
    udp_length = len(payload) + 8
    udp = struct.pack("!HHHH", peer[1], 39646, udp_length, 0)
    ip = struct.pack("!IHBB16s16s", 6 << 28, udp_length, socket.IPPROTO_UDP, 64, source, target)
    quoted = ip + udp
    message = struct.pack("!BBHI", 2, 0, 0, 1280) + quoted
    pseudo = source + target + struct.pack("!I3xB", len(message), socket.IPPROTO_ICMPV6)
    message = message[:2] + struct.pack("!H", checksum(pseudo + message)) + message[4:]
    raw = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    raw.bind((local, 0, 0, 0))
    raw.sendto(message, (peer[0], 0, 0, 0))
    raw.close()
    return "IPv6 Packet Too Big"

def echo_tcp_connection(connection):
    with connection:
        if connection.getsockname()[1] == 39648:
            import time
            print(f"RX PRESSURE TARGET accepted {connection.getpeername()} on {connection.getsockname()}", flush=True)
            deadline = time.monotonic() + 65
            while not stalled_release_file.exists() and time.monotonic() < deadline:
                time.sleep(.025)
            print(f"RX PRESSURE TARGET released {connection.getpeername()}", flush=True)
            # Keep the target connection open after it drains backlog;
            # Xray's window-update/retransmit scheduling can be slower
            # than Chimera's, so do not close after only two idle seconds.
            connection.settimeout(65)
            received_count = 0
            next_report = 256 * 1024
            try:
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    received_count += len(chunk)
                    if received_count >= next_report:
                        print(f"RX PRESSURE TARGET read {received_count} bytes", flush=True)
                        next_report += 256 * 1024
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass
            print(f"RX PRESSURE TARGET drained {received_count} bytes", flush=True)
            return
        while data := connection.recv(65536):
            if os.environ.get('XRAY_TUN_SEEDED_NETEM') == '1' and len(data) >= 4096:
                print(f"SEEDED TARGET received peer={connection.getpeername()} "
                      f"bytes={len(data)}", flush=True)
            connection.sendall(data)
            if os.environ.get('XRAY_TUN_SEEDED_NETEM') == '1' and len(data) >= 4096:
                print(f"SEEDED TARGET echoed peer={connection.getpeername()} "
                      f"bytes={len(data)}", flush=True)
            # Dedicated TIME_WAIT probe: close the target side first,
            # producing an outbound FIN on the TUN TCP stream rather than
            # relying on a client-initiated close (LAST_ACK on server).
            if data.startswith(b"chimera-timewait-active-close"):
                return
            if data.startswith(b"chimera-timewait-shutdown-write"):
                # Send downstream EOF without closing the downstream
                # read direction. This distinguishes a true TCP write
                # half-close from a full target socket close.
                connection.shutdown(socket.SHUT_WR)
                connection.settimeout(4)
                try:
                    connection.recv(1)
                except socket.timeout:
                    pass
                return
            if data.startswith(b"chimera-timewait-hold-open"):
                # Negative control for the short-idle-policy oracle: do
                # not close or half-close the target socket at all during
                # the bounded server-FIRST-FIN window. A server FIN
                # here can only be due to the Xray session/control path.
                connection.settimeout(8)
                try:
                    connection.recv(1)
                except socket.timeout:
                    pass
                return

def serve_tcp(listener):
    while True:
        connection, _ = listener.accept()
        print(f"TCP accepted {connection.getpeername()} on {listener.getsockname()}", flush=True)
        # Raw TCP RST compatibility probes deliberately hold older
        # connections open; do not let one block the next accept/echo.
        threading.Thread(
            target=echo_tcp_connection, args=(connection,), daemon=True
        ).start()

def serve_udp(listener):
    while True:
        data, peer = listener.recvfrom(65536)
        if listener.getsockname()[1] == 39646:
            kind = send_pmtu_error(listener, data, peer)
            print(f"{kind} sent for {peer} -> {listener.getsockname()}", flush=True)
            continue
        print(f"UDP received {peer} on {listener.getsockname()}: {len(data)} bytes", flush=True)
        listener.sendto(data, peer)

for listener in listeners:
    target = serve_tcp if listener.type == socket.SOCK_STREAM else serve_udp
    threading.Thread(target=target, args=(listener,), daemon=True).start()
ready_file.write_text("ready")
threading.Event().wait()
PY
echo_server_pid=$!
for attempt in $(seq 1 100); do
    if [[ -s "$echo_ready_file" ]]; then
        break
    fi
    if ! kill -0 "$echo_server_pid" 2>/dev/null; then
        printf 'Dual-stack echo server exited before becoming ready.\n' >&2
        cat "$echo_log_file" >&2
        exit 1
    fi
    sleep 0.05
done
if [[ ! -s "$echo_ready_file" ]]; then
    printf 'Dual-stack echo server did not become ready.\n' >&2
    cat "$echo_log_file" >&2
    exit 1
fi

run_unknown_protocol_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" <<'PY'
import socket
import struct
import sys

target_v4, target_v6, label = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
rx4.bind((source_v4, 0))
rx4.settimeout(3)
raw4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
source_bytes = socket.inet_aton(source_v4)
target_bytes = socket.inet_aton(target_v4)
header = struct.pack(
    "!BBHHHBBH4s4s", 0x45, 0, 28, 0x4411, 0, 64, 252, 0,
    source_bytes, target_bytes,
)
header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
raw4.sendto(header + b"unknown4", (target_v4, 0))
while True:
    reply4, _ = rx4.recvfrom(4096)
    ihl = (reply4[0] & 0x0f) * 4
    if reply4[9] != socket.IPPROTO_ICMP or reply4[ihl:ihl + 2] != b"\x03\x02":
        continue
    quoted4 = reply4[ihl + 8:]
    if quoted4[9] == 252 and quoted4[12:16] == source_bytes \
            and quoted4[16:20] == target_bytes:
        break
print(f"{label}: IPv4 protocol-unreachable response passed.", flush=True)
rx4.close()
raw4.close()

rx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx6.bind((source_v6, 0, 0, 0))
rx6.settimeout(3)
sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sniffer.bind(("office-client", 0))
sniffer.setblocking(False)
raw6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 252)
raw6.bind((source_v6, 0, 0, 0))
raw6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 64)
raw6.sendto(b"unknown6", (target_v6, 0, 0, 0))
source_v6_bytes = socket.inet_pton(socket.AF_INET6, source_v6)
target_v6_bytes = socket.inet_pton(socket.AF_INET6, target_v6)
while True:
    try:
        reply6, _ = rx6.recvfrom(4096)
    except TimeoutError:
        captured = []
        while True:
            try:
                frame = sniffer.recv(4096)
            except BlockingIOError:
                break
            if len(frame) >= 54 and frame[12:14] == b"\x86\xdd":
                packet = frame[14:]
                if packet[6] == socket.IPPROTO_ICMPV6:
                    captured.append(packet[40:48].hex())
        print(f"{label}: captured IPv6 ICMP frames at client: {captured!r}", flush=True)
        raise
    icmp6 = reply6[40:] if reply6 and reply6[0] >> 4 == 6 else reply6
    if icmp6[:2] != b"\x04\x01":
        continue
    quoted6 = icmp6[8:]
    if quoted6[6] == 252 and quoted6[8:24] == source_v6_bytes \
            and quoted6[24:40] == target_v6_bytes:
        break
print(f"{label}: IPv6 parameter-problem response passed.", flush=True)
rx6.close()
raw6.close()
sniffer.close()
PY
}

run_non_echo_icmp_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" <<'PY'
import socket
import struct
import sys

target_v4, target_v6, label = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
rx4.bind((source_v4, 0))
rx4.settimeout(0.4)
tx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def ipv4_error_packet(icmp_type, code, details, identification):
    source4 = socket.inet_aton(source_v4)
    target4 = socket.inet_aton(target_v4)
    quoted = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 28, 0x6631, 0, 64, socket.IPPROTO_UDP,
        0, target4, source4,
    )
    quoted = quoted[:10] + struct.pack("!H", checksum(quoted)) + quoted[12:]
    quoted += struct.pack("!HHHH", 443, 45240, 8, 0)
    message = struct.pack("!BBH", icmp_type, code, 0) + details + quoted
    message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
    outer = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(message), identification, 0, 64,
        socket.IPPROTO_ICMP, 0, source4, target4,
    )
    outer = outer[:10] + struct.pack("!H", checksum(outer)) + outer[12:]
    return outer + message

for icmp_type, code, details, identification, name in (
    (3, 3, b"\x00\x00\x00\x00", 0x6632, "Destination Unreachable"),
    (11, 0, b"\x00\x00\x00\x00", 0x6633, "Time Exceeded"),
    (12, 0, b"\x14\x00\x00\x00", 0x6634, "Parameter Problem"),
):
    tx4.sendto(
        ipv4_error_packet(icmp_type, code, details, identification),
        (target_v4, 0),
    )
    try:
        while True:
            response, _ = rx4.recvfrom(4096)
            if response[16:20] == socket.inet_aton(source_v4) \
                    and response[9] == socket.IPPROTO_ICMP:
                raise RuntimeError(
                    f"{label}: unexpected IPv4 response to {name}"
                )
    except TimeoutError:
        pass
    print(f"{label}: IPv4 {name} was consumed without a TUN reply.", flush=True)
rx4.close()
tx4.close()

quoted6_source = socket.inet_pton(socket.AF_INET6, target_v6)
quoted6_destination = socket.inet_pton(socket.AF_INET6, source_v6)
quoted6 = struct.pack(
    "!IHBB16s16s", 6 << 28, 8, socket.IPPROTO_UDP, 64,
    quoted6_source, quoted6_destination,
) + struct.pack("!HHHH", 443, 45241, 8, 0)
rx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx6.bind((source_v6, 0, 0, 0))
rx6.settimeout(0.4)
tx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
tx6.bind((source_v6, 0, 0, 0))

for icmp_type, code, details, name in (
    (1, 4, b"\x00\x00\x00\x00", "Destination Unreachable"),
    (3, 0, b"\x00\x00\x00\x00", "Time Exceeded"),
    (4, 0, b"\x00\x00\x00\x28", "Parameter Problem"),
):
    message = struct.pack("!BBH", icmp_type, code, 0) + details + quoted6
    tx6.sendto(message, (target_v6, 0, 0, 0))
    try:
        while True:
            response, address = rx6.recvfrom(4096)
            payload = response[40:] if response and response[0] >> 4 == 6 else response
            # Ignore unrelated IPv6 neighbor-discovery traffic (e.g.
            # Neighbor Solicitation, type 135) seen on this raw socket.
            # Only an error from the probed TUN endpoint is a failure.
            if address[0] != target_v6 or not payload or payload[0] >= 128:
                continue
            raise RuntimeError(
                f"{label}: unexpected IPv6 response to {name}: {payload[:2]!r}"
            )
    except TimeoutError:
        pass
    print(f"{label}: IPv6 {name} was consumed without a TUN reply.", flush=True)
rx6.close()
tx6.close()
PY
}

run_truncated_icmp_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" <<'PY'
import socket
import struct
import sys

target_v4, target_v6, label = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
rx4.bind((source_v4, 0))
rx4.settimeout(0.4)
tx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
source4 = socket.inet_aton(source_v4)
target4 = socket.inet_aton(target_v4)
icmp4 = b"\x08\x00\x00\x00"
icmp4 = icmp4[:2] + struct.pack("!H", checksum(icmp4))
outer4 = struct.pack(
    "!BBHHHBBH4s4s", 0x45, 0, 24, 0x6635, 0, 64,
    socket.IPPROTO_ICMP, 0, source4, target4,
)
outer4 = outer4[:10] + struct.pack("!H", checksum(outer4)) + outer4[12:]
tx4.sendto(outer4 + icmp4, (target_v4, 0))
try:
    while True:
        response, _ = rx4.recvfrom(4096)
        if response[16:20] == source4 and response[9] == socket.IPPROTO_ICMP:
            raise RuntimeError(f"{label}: unexpected response to truncated IPv4 ICMP")
except TimeoutError:
    pass
print(f"{label}: truncated IPv4 Echo Request produced no TUN reply.", flush=True)
rx4.close()
tx4.close()

rx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx6.bind((source_v6, 0, 0, 0))
rx6.settimeout(0.4)
tx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
tx6.bind((source_v6, 0, 0, 0))
tx6.sendto(b"\x80\x00\x00\x00", (target_v6, 0, 0, 0))
try:
    while True:
        response, address = rx6.recvfrom(4096)
        if address[0] == target_v6:
            payload = response[40:] if response and response[0] >> 4 == 6 else response
            raise RuntimeError(
                f"{label}: unexpected response to truncated IPv6 ICMP: {payload[:8]!r}"
            )
except TimeoutError:
    pass
print(f"{label}: truncated IPv6 Echo Request produced no TUN reply.", flush=True)
rx6.close()
tx6.close()
PY
}

run_bad_icmp_checksum_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    local expected_ipv4=$4
    local expected_ipv6=$5
    local expected_fragmented_ipv4=${6:-$expected_ipv4}
    local expected_fragmented_ipv6=${7:-$expected_ipv6}
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" "$expected_ipv4" "$expected_ipv6" \
        "$expected_fragmented_ipv4" "$expected_fragmented_ipv6" <<'PY'
import socket
import struct
import sys

(
    target_v4, target_v6, label, expected_ipv4, expected_ipv6,
    expected_fragmented_ipv4, expected_fragmented_ipv6,
) = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
rx4.bind((source_v4, 0))
rx4.settimeout(0.4)
tx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
source4 = socket.inet_aton(source_v4)
target4 = socket.inet_aton(target_v4)
icmp4 = bytearray(struct.pack("!BBHHH", 8, 0, 0, 7, 10) + b"bad-v4-checksum!")
icmp4[2:4] = struct.pack("!H", checksum(icmp4) ^ 0x0001)
outer4 = struct.pack(
    "!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp4), 0x6636, 0, 64,
    socket.IPPROTO_ICMP, 0, source4, target4,
)
outer4 = outer4[:10] + struct.pack("!H", checksum(outer4)) + outer4[12:]
tx4.sendto(outer4 + icmp4, (target_v4, 0))
reply4 = None
try:
    while True:
        response, _ = rx4.recvfrom(4096)
        if response[12:16] == target4 and response[16:20] == source4:
            reply4 = response
            break
except TimeoutError:
    pass
if expected_ipv4 == "reply":
    if reply4 is None:
        raise RuntimeError(f"{label}: expected an IPv4 Echo Reply for the invalid checksum")
    header_length = (reply4[0] & 0x0f) * 4
    total_length = struct.unpack("!H", reply4[2:4])[0]
    message4 = reply4[header_length:total_length]
    if len(message4) < 8 or message4[:2] != b"\x00\x00" \
            or message4[4:6] != struct.pack("!H", 7) \
            or message4[6:8] != struct.pack("!H", 10) \
            or message4[8:] != b"bad-v4-checksum!" or checksum(message4) != 0:
        raise RuntimeError(f"{label}: invalid IPv4 Echo Reply: {message4!r}")
    print(f"{label}: invalid IPv4 ICMP checksum received a valid Echo Reply.", flush=True)
elif expected_ipv4 == "drop":
    if reply4 is not None:
        raise RuntimeError(f"{label}: unexpected IPv4 Echo Reply for invalid checksum")
    print(f"{label}: invalid IPv4 ICMP checksum was dropped.", flush=True)
else:
    raise RuntimeError(f"unknown IPv4 checksum behavior expectation: {expected_ipv4}")

fragmented4 = bytearray(
    struct.pack("!BBHHH", 8, 0, 0, 7, 11) + b"fragmented-bad-v4"
)
fragmented4[2:4] = struct.pack("!H", checksum(fragmented4) ^ 0x0001)

def send_ipv4_fragment(part, offset, more):
    flags_offset = (0x2000 if more else 0) | (offset // 8)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(part), 0x6637,
        flags_offset, 64, socket.IPPROTO_ICMP, 0, source4, target4,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + part

split4 = 16
tx4.sendto(send_ipv4_fragment(fragmented4[split4:], split4, False), (target_v4, 0))
tx4.sendto(send_ipv4_fragment(fragmented4[:split4], 0, True), (target_v4, 0))
fragment_reply4 = None
rx4.settimeout(0.4)
try:
    while True:
        response, _ = rx4.recvfrom(4096)
        if response[12:16] != target4 or response[16:20] != source4:
            continue
        header_length = (response[0] & 0x0f) * 4
        total_length = struct.unpack("!H", response[2:4])[0]
        message = response[header_length:total_length]
        if len(message) >= 8 and message[:2] == b"\x00\x00" \
                and message[4:8] == struct.pack("!HH", 7, 11):
            fragment_reply4 = message
            break
except TimeoutError:
    pass
if expected_fragmented_ipv4 == "reply":
    if fragment_reply4 is None or fragment_reply4[8:] != b"fragmented-bad-v4\x00" \
            or checksum(fragment_reply4) != 0:
        raise RuntimeError(
            f"{label}: fragmented invalid IPv4 checksum did not receive a valid Echo Reply: {fragment_reply4!r}"
        )
    print(
        f"{label}: fragmented invalid IPv4 ICMP checksum received a valid Echo Reply with payload {fragment_reply4[8:]!r}.",
        flush=True,
    )
elif expected_fragmented_ipv4 == "drop":
    if fragment_reply4 is not None:
        raise RuntimeError(f"{label}: unexpected Echo Reply for fragmented invalid IPv4 checksum")
    print(f"{label}: fragmented invalid IPv4 ICMP checksum was dropped.", flush=True)
else:
    raise RuntimeError(
        f"unknown fragmented IPv4 checksum behavior expectation: {expected_fragmented_ipv4}"
    )
rx4.close()
tx4.close()

source6 = socket.inet_pton(socket.AF_INET6, source_v6)
target6 = socket.inet_pton(socket.AF_INET6, target_v6)
icmp6 = bytearray(struct.pack("!BBHHH", 128, 0, 0, 7, 10) + b"bad-v6-checksum")
pseudo6 = source6 + target6 + struct.pack(
    "!I3xB", len(icmp6), socket.IPPROTO_ICMPV6
)
icmp6[2:4] = struct.pack("!H", checksum(pseudo6 + icmp6) ^ 0x0001)
ipv6 = struct.pack(
    "!IHBB16s16s", 6 << 28, len(icmp6), socket.IPPROTO_ICMPV6, 64,
    source6, target6,
)
tx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx6.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
rx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx6.bind((source_v6, 0, 0, 0))
rx6.settimeout(0.4)
tx6.sendto(ipv6 + icmp6, (target_v6, 0, 0, 0))
reply6 = None
try:
    while True:
        response, address = rx6.recvfrom(4096)
        if address[0] == target_v6:
            reply6 = response
            break
except TimeoutError:
    pass
if expected_ipv6 == "reply":
    if reply6 is None:
        raise RuntimeError(f"{label}: expected an IPv6 Echo Reply for the invalid checksum")
    message6 = reply6[40:] if reply6 and reply6[0] >> 4 == 6 else reply6
    pseudo6_reply = target6 + source6 + struct.pack(
        "!I3xB", len(message6), socket.IPPROTO_ICMPV6
    )
    if len(message6) < 8 or message6[:2] != b"\x81\x00" \
            or message6[4:6] != struct.pack("!H", 7) \
            or message6[6:8] != struct.pack("!H", 10) \
            or message6[8:] != b"bad-v6-checksum" \
            or checksum(pseudo6_reply + message6) != 0:
        raise RuntimeError(f"{label}: invalid IPv6 Echo Reply: {message6!r}")
    print(f"{label}: invalid IPv6 ICMP checksum received a valid Echo Reply.", flush=True)
elif expected_ipv6 == "drop":
    if reply6 is not None:
        message6 = reply6[40:] if reply6 and reply6[0] >> 4 == 6 else reply6
        raise RuntimeError(f"{label}: unexpected IPv6 reply for invalid checksum: {message6!r}")
    print(f"{label}: invalid IPv6 ICMP checksum was dropped.", flush=True)
else:
    raise RuntimeError(f"unknown IPv6 checksum behavior expectation: {expected_ipv6}")

fragmented6 = bytearray(
    struct.pack("!BBHHH", 128, 0, 0, 7, 11) + b"fragmented-bad-v6"
)
pseudo6_fragmented = source6 + target6 + struct.pack(
    "!I3xB", len(fragmented6), socket.IPPROTO_ICMPV6
)
fragmented6[2:4] = struct.pack(
    "!H", checksum(pseudo6_fragmented + fragmented6) ^ 0x0001
)

def send_ipv6_fragment(part, offset, more):
    offset_flags = ((offset // 8) << 3) | (1 if more else 0)
    fragment_header = struct.pack(
        "!BBHI", socket.IPPROTO_ICMPV6, 0, offset_flags, 0x6677889A
    )
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, len(fragment_header) + len(part),
        44, 64, source6, target6,
    )
    return header + fragment_header + part

split6 = 16
tx6.sendto(send_ipv6_fragment(fragmented6[split6:], split6, False), (target_v6, 0, 0, 0))
tx6.sendto(send_ipv6_fragment(fragmented6[:split6], 0, True), (target_v6, 0, 0, 0))
fragment_reply6 = None
rx6.settimeout(0.4)
try:
    while True:
        response, address = rx6.recvfrom(4096)
        if address[0] != target_v6:
            continue
        message = response[40:] if response and response[0] >> 4 == 6 else response
        if len(message) >= 8 and message[:2] == b"\x81\x00" \
                and message[4:8] == struct.pack("!HH", 7, 11):
            fragment_reply6 = message
            break
except TimeoutError:
    pass
if expected_fragmented_ipv6 == "reply":
    if fragment_reply6 is None or fragment_reply6[8:] != b"fragmented-bad-v6\x00":
        raise RuntimeError(f"{label}: fragmented invalid IPv6 checksum did not receive an Echo Reply")
    pseudo6_reply = target6 + source6 + struct.pack(
        "!I3xB", len(fragment_reply6), socket.IPPROTO_ICMPV6
    )
    if checksum(pseudo6_reply + fragment_reply6) != 0:
        raise RuntimeError(f"{label}: fragmented invalid IPv6 Echo Reply checksum is invalid")
    print(
        f"{label}: fragmented invalid IPv6 ICMP checksum received a valid Echo Reply with payload {fragment_reply6[8:]!r}.",
        flush=True,
    )
elif expected_fragmented_ipv6 == "drop":
    if fragment_reply6 is not None:
        raise RuntimeError(f"{label}: unexpected Echo Reply for fragmented invalid IPv6 checksum")
    print(f"{label}: fragmented invalid IPv6 ICMP checksum was dropped.", flush=True)
else:
    raise RuntimeError(
        f"unknown fragmented IPv6 checksum behavior expectation: {expected_fragmented_ipv6}"
    )
tx6.close()
rx6.close()
PY
}

run_fragmented_ipv6_echo_padding_options_probe() {
    local target_v6=$1
    local label=$2
    local options_position=$3
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" "$options_position" <<'PY'
import socket
import struct
import sys

target_v6, label, options_position = sys.argv[1:]
source_v6 = "fd18:251::2"
source6 = socket.inet_pton(socket.AF_INET6, source_v6)
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

if options_position == "hop-before-fragment":
    payload = b"fragmented-hbh-echo!"
    sequence = 0x5678
elif options_position == "destination-after-fragment":
    payload = b"fragmented-dst-echo!"
    sequence = 0x5679
else:
    raise RuntimeError(f"unknown IPv6 option position: {options_position}")
icmp = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x1234, sequence) + payload)
pseudo = source6 + target6 + struct.pack(
    "!I3xB", len(icmp), socket.IPPROTO_ICMPV6
)
icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
padding_options = bytes((socket.IPPROTO_ICMPV6, 0, 1, 4, 0, 0, 0, 0))
if options_position == "hop-before-fragment":
    before_fragment = bytes((socket.IPPROTO_FRAGMENT, 0, 1, 4, 0, 0, 0, 0))
    fragmentable = bytes(icmp)
    ipv6_next_header = socket.IPPROTO_HOPOPTS
    fragment_next_header = socket.IPPROTO_ICMPV6
else:
    before_fragment = b""
    fragmentable = padding_options + icmp
    ipv6_next_header = socket.IPPROTO_FRAGMENT
    fragment_next_header = socket.IPPROTO_DSTOPTS
identification = 0x6677889B if options_position == "hop-before-fragment" else 0x6677889C

def ipv6_fragment(part, offset, more):
    offset_flags = ((offset // 8) << 3) | (1 if more else 0)
    fragment = struct.pack(
        "!BBHI", fragment_next_header, 0, offset_flags, identification
    )
    header = struct.pack(
        "!IHBB16s16s", 6 << 28,
        len(before_fragment) + len(fragment) + len(part),
        ipv6_next_header, 64, source6, target6,
    )
    return header + before_fragment + fragment + part

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx.bind((source_v6, 0, 0, 0))
rx.settimeout(2)
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
split = 16
tx.sendto(ipv6_fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
tx.sendto(ipv6_fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
while True:
    response, address = rx.recvfrom(4096)
    if address[0] != target_v6:
        continue
    message = response[40:] if response and response[0] >> 4 == 6 else response
    if len(message) < 8 or message[:2] != b"\x81\x00":
        continue
    if message[4:8] != struct.pack("!HH", 0x1234, sequence):
        continue
    if message[8:] != payload:
        raise RuntimeError(f"{label}: Echo Reply changed payload: {message[8:]!r}")
    reply_pseudo = target6 + source6 + struct.pack(
        "!I3xB", len(message), socket.IPPROTO_ICMPV6
    )
    if checksum(reply_pseudo + message) != 0:
        raise RuntimeError(f"{label}: fragmented Echo Reply checksum is invalid")
    print(
        f"{label}: fragmented IPv6 Echo with padding-only {options_position} replied with the original payload.",
        flush=True,
    )
    break
rx.close()
tx.close()
PY
}

run_fragmented_ipv6_echo_semantic_destination_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# The two high bits specify: skip, discard, discard+ICMP (unicast),
# and discard+ICMP (unless multicast). 0x1e is deliberately unknown.
for index, option_type in enumerate((0x1e, 0x5e, 0x9e, 0xde)):
    sequence = 0x5700 + index
    marker = bytes((option_type, 2, 0x4a, 0x62))
    payload = b"semantic-dst-" + bytes((option_type,))
    icmp = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x1234, sequence) + payload)
    pseudo = source6 + target6 + struct.pack("!I3xB", len(icmp), socket.IPPROTO_ICMPV6)
    icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
    destination_options = bytes((socket.IPPROTO_ICMPV6, 0)) + marker + bytes((0, 0))
    fragmentable = destination_options + icmp

    def build_fragment(part, offset, more):
        fragment = struct.pack(
            "!BBHI", socket.IPPROTO_DSTOPTS, 0,
            ((offset // 8) << 3) | int(more), 0x66778900 + index
        )
        header = struct.pack(
            "!IHBB16s16s", 6 << 28, len(fragment) + len(part),
            socket.IPPROTO_FRAGMENT, 64, source6, target6
        )
        return header + fragment + part

    split = 16
    tx.sendto(build_fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(build_fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
    outcome = "drop"
    deadline = time.monotonic() + 0.75
    while time.monotonic() < deadline:
        rx.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            response, address = rx.recvfrom(4096)
        except TimeoutError:
            break
        if address[0] != target_v6:
            continue
        message = response[40:] if response[0] >> 4 == 6 else response
        if len(message) < 8:
            continue
        if message[0] == 129 and message[1] == 0:
            if message[4:8] != struct.pack("!HH", 0x1234, sequence):
                continue
            reply_pseudo = target6 + source6 + struct.pack("!I3xB", len(message), socket.IPPROTO_ICMPV6)
            if message[8:] != payload or checksum(reply_pseudo + message) != 0:
                raise RuntimeError(f"{label}: malformed Echo Reply for option {option_type:#04x}")
            outcome = "echo"
            break
        if message[0] == 4 and marker in message[8:]:
            reply_pseudo = target6 + source6 + struct.pack("!I3xB", len(message), socket.IPPROTO_ICMPV6)
            if checksum(reply_pseudo + message) != 0:
                raise RuntimeError(f"{label}: invalid Parameter Problem checksum for {option_type:#04x}")
            pointer = struct.unpack("!I", message[4:8])[0]
            outcome = f"parameter-problem/{message[1]}/pointer-{pointer}"
            break
    expected = {
        0x1e: "echo",
        0x5e: "drop",
        0x9e: "parameter-problem/2/pointer-42",
        0xde: "parameter-problem/2/pointer-42",
    }[option_type]
    if outcome != expected:
        raise RuntimeError(
            f"{label}: unknown Destination Option {option_type:#04x} -> "
            f"{outcome}; expected {expected}"
        )
    print(f"{label}: unknown Destination Option {option_type:#04x} -> {outcome}", flush=True)

# Pin the observed Xray 26.9.9 malformed-option length boundaries.
# Both overrun shapes are silently dropped; a legal zero-length option skips.
malformed_cases = (
    ("unknown-length-overrun", 0x1e, 5, bytes((0x4a, 0x62, 0, 0))),
    ("padn-length-overrun", 1, 5, bytes(4)),
    ("unknown-zero-length", 0x1e, 0, bytes(4)),
)
for index, (case_name, option_type, length, data) in enumerate(malformed_cases):
    sequence = 0x5800 + index
    echo_data = f"malformed-dst-{index}".encode()
    icmp = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x1234, sequence) + echo_data)
    pseudo = source6 + target6 + struct.pack("!I3xB", len(icmp), socket.IPPROTO_ICMPV6)
    icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
    # A complete eight-byte Destination Options header with an option that
    # exceeds its six-byte option field, or an unknown zero-length option.
    options = bytes((socket.IPPROTO_ICMPV6, 0, option_type, length)) + data
    fragmentable = options + icmp
    split = 16
    def fragment_packet(part, offset, more):
        frag_header = struct.pack(
            "!BBHI", socket.IPPROTO_DSTOPTS, 0,
            ((offset // 8) << 3) | int(more), 0x66778A00 + index
        )
        header = struct.pack(
            "!IHBB16s16s", 6 << 28, len(frag_header) + len(part),
            socket.IPPROTO_FRAGMENT, 64, source6, target6,
        )
        return header + frag_header + part
    tx.sendto(fragment_packet(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment_packet(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
    outcome = "drop"
    deadline = time.monotonic() + 0.75
    while time.monotonic() < deadline:
        rx.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            response, address = rx.recvfrom(4096)
        except TimeoutError:
            break
        if address[0] != target_v6:
            continue
        message = response[40:] if response[0] >> 4 == 6 else response
        if len(message) < 8:
            continue
        if message[0] == 129 and message[1] == 0:
            if message[4:8] != struct.pack("!HH", 0x1234, sequence):
                continue
            reply_pseudo = target6 + source6 + struct.pack("!I3xB", len(message), socket.IPPROTO_ICMPV6)
            if checksum(reply_pseudo + message) != 0 or message[8:] != echo_data:
                raise RuntimeError(f"{label}: invalid Echo Reply for {case_name}")
            outcome = "echo"
            break
        if message[0] == 4 and bytes((option_type, length)) in message[8:]:
            reply_pseudo = target6 + source6 + struct.pack("!I3xB", len(message), socket.IPPROTO_ICMPV6)
            if checksum(reply_pseudo + message) != 0:
                raise RuntimeError(f"{label}: bad Parameter Problem checksum for {case_name}")
            pointer = struct.unpack("!I", message[4:8])[0]
            outcome = f"parameter-problem/{message[1]}/pointer-{pointer}"
            break
    expected = "echo" if case_name == "unknown-zero-length" else "drop"
    if outcome != expected:
        raise RuntimeError(
            f"{label}: malformed Destination Option {case_name} -> "
            f"{outcome}; expected {expected}"
        )
    print(f"{label}: malformed Destination Option {case_name} -> {outcome}", flush=True)

rx.close()
tx.close()
PY
}

run_fragmented_ipv6_destination_hdr_ext_len_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# All inputs use out-of-order fragments. The valid 16-byte header controls
# for first-fragment completeness; the malformed cases respectively claim
# too many header bytes, consume ICMP bytes, or underdeclare extra padding.
for index, (name, hdr_ext_len, extra_pad, short_echo) in enumerate((
    ("valid-16-action-10", 1, bytes((0x9e, 2, 0x4a, 0x62, 0, 0, 0, 0)), False),
    ("declared-32-actual-17", 3, b"", True),
    ("declared-16-actual-8", 1, b"", False),
    ("declared-8-actual-16", 0, bytes(8), False),
)):
    sequence = 0x5900 + index
    payload = b"x" if short_echo else b"hdr-ext-len-check"
    icmp = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x1357, sequence) + payload)
    pseudo = source6 + target6 + struct.pack("!I3xB", len(icmp), socket.IPPROTO_ICMPV6)
    icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
    options = bytes((socket.IPPROTO_ICMPV6, hdr_ext_len, 1, 4, 0, 0, 0, 0))
    fragmentable = options + extra_pad + icmp
    # RFC 7112: a legal 16-byte options header needs the following ICMPv6
    # header in fragment zero. The deliberately malformed cases use 16.
    split = 24 if name == "valid-16-action-10" else 16
    def fragment(part, offset, more):
        fragment_header = struct.pack(
            "!BBHI", socket.IPPROTO_DSTOPTS, 0,
            ((offset // 8) << 3) | int(more), 0x66778B00 + index
        )
        ipv6_header = struct.pack(
            "!IHBB16s16s", 6 << 28, len(fragment_header) + len(part),
            socket.IPPROTO_FRAGMENT, 64, source6, target6
        )
        return ipv6_header + fragment_header + part

    tx.sendto(fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
    outcome = "drop"
    deadline = time.monotonic() + 0.8
    while time.monotonic() < deadline:
        rx.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            response, address = rx.recvfrom(4096)
        except TimeoutError:
            break
        if address[0] != target_v6:
            continue
        message = response[40:] if response[0] >> 4 == 6 else response
        if len(message) < 8:
            continue
        reply_pseudo = target6 + source6 + struct.pack(
            "!I3xB", len(message), socket.IPPROTO_ICMPV6
        )
        if message[0] == 129 and message[1] == 0:
            if message[4:8] != struct.pack("!HH", 0x1357, sequence):
                continue
            if checksum(reply_pseudo + message) != 0 or message[8:] != payload:
                raise RuntimeError(f"{label}: invalid Echo Reply for {name}")
            outcome = "echo"
            break
        if message[0] == 4 and struct.pack("!HH", 0x1357, sequence) in message[8:]:
            if checksum(reply_pseudo + message) != 0:
                raise RuntimeError(f"{label}: invalid Parameter Problem checksum for {name}")
            pointer = struct.unpack("!I", message[4:8])[0]
            outcome = f"parameter-problem/{message[1]}/pointer-{pointer}"
            break
    expected = (
        "parameter-problem/2/pointer-48"
        if name == "valid-16-action-10" else "drop"
    )
    if outcome != expected:
        raise RuntimeError(
            f"{label}: Destination Options Hdr Ext Len {name} -> {outcome}; "
            f"expected {expected}"
        )
    print(f"{label}: Destination Options Hdr Ext Len {name} -> {outcome}", flush=True)

rx.close()
tx.close()
PY
}

run_fragmented_ipv6_chained_destination_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
for index, (name, split, second_option) in enumerate((
    ("two-padding-complete", 24, bytes((1, 4, 0, 0, 0, 0))),
    ("two-padding-incomplete", 16, bytes((1, 4, 0, 0, 0, 0))),
    ("second-action10-complete", 24, bytes((0x9e, 2, 0x4a, 0x62, 0, 0))),
)):
    sequence = 0x5a00 + index
    payload = b"chained-dst-" + bytes((index,))
    icmp = bytearray(struct.pack("!BBHHH", 128, 0, 0, 0x1357, sequence) + payload)
    pseudo = source6 + target6 + struct.pack("!I3xB", len(icmp), socket.IPPROTO_ICMPV6)
    icmp[2:4] = struct.pack("!H", checksum(pseudo + icmp))
    options = bytes((socket.IPPROTO_DSTOPTS, 0, 1, 4, 0, 0, 0, 0))
    options += bytes((socket.IPPROTO_ICMPV6, 0)) + second_option
    fragmentable = options + icmp
    def packet(part, offset, more):
        fragment = struct.pack(
            "!BBHI", socket.IPPROTO_DSTOPTS, 0,
            ((offset // 8) << 3) | int(more), 0x66778c00 + index
        )
        ipv6 = struct.pack(
            "!IHBB16s16s", 6 << 28, len(fragment) + len(part),
            socket.IPPROTO_FRAGMENT, 64, source6, target6
        )
        return ipv6 + fragment + part
    tx.sendto(packet(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(packet(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
    outcome = "drop"
    deadline = time.monotonic() + 0.8
    while time.monotonic() < deadline:
        rx.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            response, address = rx.recvfrom(4096)
        except TimeoutError:
            break
        if address[0] != target_v6:
            continue
        message = response[40:] if response[0] >> 4 == 6 else response
        if len(message) < 8:
            continue
        reply_pseudo = target6 + source6 + struct.pack(
            "!I3xB", len(message), socket.IPPROTO_ICMPV6
        )
        if message[0] == 129 and message[1] == 0:
            if message[4:8] != struct.pack("!HH", 0x1357, sequence):
                continue
            if checksum(reply_pseudo + message) != 0 or message[8:] != payload:
                raise RuntimeError(f"{label}: invalid chained Echo Reply {name}")
            outcome = "echo"
            break
        if message[0] == 4 and struct.pack("!HH", 0x1357, sequence) in message[8:]:
            if checksum(reply_pseudo + message) != 0:
                raise RuntimeError(f"{label}: invalid chained Parameter Problem {name}")
            pointer = struct.unpack("!I", message[4:8])[0]
            outcome = f"parameter-problem/{message[1]}/pointer-{pointer}"
            break
    expected = {
        "two-padding-complete": "echo",
        "two-padding-incomplete": "drop",
        "second-action10-complete": "parameter-problem/2/pointer-50",
    }[name]
    if outcome != expected:
        raise RuntimeError(
            f"{label}: chained Destination Options {name} -> {outcome}; "
            f"expected {expected}"
        )
    print(f"{label}: chained Destination Options {name} -> {outcome}", flush=True)
rx.close()
tx.close()
PY
}

run_fragmented_ipv6_udp_destination_first_header_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += bytes(1)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx_udp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
rx_udp.bind(("fd18:251::2", 0, 0, 0))
rx_icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx_icmp.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# First fragment contains one or two complete Destination Options headers
# with and without the complete UDP header; all fragmented tails come first.
for index, (name, chained, split) in enumerate((
    ("one-options-no-udp-header", False, 8),
    ("one-options-complete-udp-header", False, 16),
    ("two-options-no-udp-header", True, 16),
    ("two-options-complete-udp-header", True, 24),
)):
    src_port = 45350 + index
    marker = f"udp-fragment-options-{index}".encode()
    udp_length = len(marker) + 8
    udp = bytearray(struct.pack("!HHHH", src_port, 39644, udp_length, 0) + marker)
    pseudo = source6 + target6 + struct.pack("!I3xB", len(udp), socket.IPPROTO_UDP)
    udp[6:8] = struct.pack("!H", checksum(pseudo + udp))
    opts = bytes((socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_UDP,
                   0, 1, 4, 0, 0, 0, 0))
    if chained:
        opts += bytes((socket.IPPROTO_UDP, 0, 1, 4, 0, 0, 0, 0))
    fragmentable = opts + udp

    def fragment(part, offset, more):
        fh = struct.pack("!BBHI", socket.IPPROTO_DSTOPTS, 0,
                         ((offset // 8) << 3) | int(more), 0x66778D00 + index)
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(fh) + len(part),
                         socket.IPPROTO_FRAGMENT, 64, source6, target6)
        return ip + fh + part

    tx.sendto(fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))

    outcome = "drop"
    deadline = time.monotonic() + 0.9
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            (rx_udp, rx_icmp), (), (), max(0.01, deadline - time.monotonic())
        )
        if not ready:
            break
        for sock in ready:
            response, peer = sock.recvfrom(4096)
            if peer[0] != target_v6:
                continue
            message = response[40:] if response and response[0] >> 4 == 6 else response
            if sock is rx_udp:
                if len(message) < 8:
                    continue
                src, dst, length, udp_checksum = struct.unpack("!HHHH", message[:8])
                if src != 39644 or dst != src_port:
                    continue
                reply_pseudo = target6 + source6 + struct.pack(
                    "!I3xB", len(message), socket.IPPROTO_UDP
                )
                if length != len(message) or message[8:] != marker or checksum(reply_pseudo + message):
                    raise RuntimeError(f"{label}: malformed UDP Echo for {name}")
                outcome = "udp-echo"
                break
            if len(message) < 8 or message[0] not in (1, 2, 3, 4):
                continue
            # Correlate the embedded UDP ports rather than incidental ICMP errors.
            if struct.pack("!HH", src_port, 39644) not in message[8:]:
                continue
            reply_pseudo = target6 + source6 + struct.pack(
                "!I3xB", len(message), socket.IPPROTO_ICMPV6
            )
            if checksum(reply_pseudo + message):
                raise RuntimeError(f"{label}: invalid ICMPv6 checksum for {name}")
            outcome = f"icmp/{message[0]}/{message[1]}/pointer-{struct.unpack('!I', message[4:8])[0]}"
            break
        if outcome != "drop":
            break
    expected = "drop" if name.endswith("no-udp-header") else "udp-echo"
    if outcome != expected:
        raise RuntimeError(
            f"{label}: fragmented IPv6 UDP Destination Options {name} -> "
            f"{outcome}; expected {expected}"
        )
    print(f"{label}: fragmented IPv6 UDP Destination Options {name} -> {outcome}", flush=True)

rx_udp.close()
rx_icmp.close()
tx.close()
PY
}

run_fragmented_ipv6_tcp_destination_first_header_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += bytes(1)
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx_tcp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx_tcp.bind(("fd18:251::2", 0, 0, 0))
rx_icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx_icmp.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# One/two padding-only Destination Options headers. Compare an ordinary
# 24-byte SYN/MSS TCP header with zero-option 20-byte and maximum-option
# 40-byte TCP headers. For the latter, the first fragment can end inside
# the TCP options as well as before or after the complete TCP header.
cases = (
    ("one-options-no-tcp", False, 8, 4),
    ("one-options-eight-tcp", False, 16, 4),
    ("one-options-sixteen-tcp", False, 24, 4),
    ("one-options-complete-tcp", False, 32, 4),
    ("two-options-no-tcp", True, 16, 4),
    ("two-options-eight-tcp", True, 24, 4),
    ("two-options-sixteen-tcp", True, 32, 4),
    ("two-options-complete-tcp", True, 40, 4),
)
for chained, options_len in ((False, 0), (True, 0), (False, 20), (True, 20)):
    option_prefix = "two" if chained else "one"
    header_options = "none" if options_len == 0 else "max"
    base = 16 if chained else 8
    for first_tcp_bytes in ((0, 8, 16, 24) if options_len == 0
                            else (0, 8, 16, 24, 32, 40)):
        cases += ((
            f"{option_prefix}-options-{header_options}-tcp-{first_tcp_bytes}",
            chained,
            base + first_tcp_bytes,
            options_len,
        ),)

for index, (name, chained, split, options_len) in enumerate(cases):
    src_port = 45450 + index
    seq = 0x529a0000 + index
    payload = b"tcp-probe"
    tcp_options = (bytes() if options_len == 0 else
                   bytes((2, 4, 5, 180)) + bytes((1,)) * (options_len - 4))
    tcp = bytearray(
        struct.pack("!HHIIHHHH", src_port, 39643, seq, 0,
                    ((5 + options_len // 4) << 12) | 2, 65535, 0, 0)
        + tcp_options + payload
    )
    pseudo = source6 + target6 + struct.pack("!I3xB", len(tcp), socket.IPPROTO_TCP)
    tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
    options = bytes((socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_TCP,
                     0, 1, 4, 0, 0, 0, 0))
    if chained:
        options += bytes((socket.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0))
    fragmentable = options + tcp
    def fragment(part, offset, more):
        fh = struct.pack("!BBHI", socket.IPPROTO_DSTOPTS, 0,
                         ((offset // 8) << 3) | int(more), 0x66778E00 + index)
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(fh) + len(part),
                         socket.IPPROTO_FRAGMENT, 64, source6, target6)
        return ip + fh + part

    tx.sendto(fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))

    outcome = "drop"
    deadline = time.monotonic() + 0.85
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            (rx_tcp, rx_icmp), (), (), max(0.01, deadline - time.monotonic())
        )
        if not ready:
            break
        for sock in ready:
            response, peer = sock.recvfrom(4096)
            if peer[0] != target_v6:
                continue
            message = response[40:] if response and response[0] >> 4 == 6 else response
            if sock is rx_tcp:
                if len(message) < 20:
                    continue
                sport, dport, response_seq, ack, flags, _, _, _ = struct.unpack(
                    "!HHIIHHHH", message[:20]
                )
                if sport != 39643 or dport != src_port:
                    continue
                reply_pseudo = target6 + source6 + struct.pack(
                    "!I3xB", len(message), socket.IPPROTO_TCP
                )
                if checksum(reply_pseudo + message) != 0:
                    raise RuntimeError(f"{label}: invalid TCP checksum for {name}")
                outcome = "syn-ack" if (flags & 0x12) == 0x12 and ack == seq + 1 else f"tcp-flags-{flags & 0x3f:x}"
                break
            if len(message) < 8 or message[0] not in (1, 2, 3, 4):
                continue
            if struct.pack("!HH", src_port, 39643) not in message[8:]:
                continue
            reply_pseudo = target6 + source6 + struct.pack(
                "!I3xB", len(message), socket.IPPROTO_ICMPV6
            )
            if checksum(reply_pseudo + message):
                raise RuntimeError(f"{label}: invalid ICMPv6 checksum for {name}")
            outcome = f"icmp/{message[0]}/{message[1]}/pointer-{struct.unpack('!I', message[4:8])[0]}"
            break
        if outcome != "drop":
            break
    expected = ("drop" if name.endswith("no-tcp")
                or name.endswith("-tcp-0") else "syn-ack")
    if outcome != expected:
        raise RuntimeError(
            f"{label}: fragmented IPv6 TCP Destination Options {name} -> "
            f"{outcome}; expected {expected}"
        )
    print(f"{label}: fragmented IPv6 TCP Destination Options {name} -> {outcome}", flush=True)

rx_tcp.close()
rx_icmp.close()
tx.close()
PY
}

run_fragmented_ipv6_tcp_malformed_options_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# Deliberately malformed TCP options, not malformed IPv6 extensions or TCP
# header data offset. RFC-valid MSS and EOL controls delimit the behavior.
options_cases = (
    ("valid-mss", bytes((2, 4, 5, 180))),
    ("mss-zero-length", bytes((2, 0, 5, 180))),
    ("mss-too-short", bytes((2, 3, 5, 180))),
    ("mss-too-long", bytes((2, 5, 5, 180))),
    ("window-scale-too-short", bytes((3, 2, 7, 1))),
    ("timestamp-too-short", bytes((8, 2, 1, 1))),
    ("unknown-zero-length", bytes((30, 0, 1, 1))),
    ("eol-ignores-trailer", bytes((0, 2, 0, 0))),
)
for chained in (False, True):
    for first_tcp_bytes in (8, 24):
        for case_index, (name, tcp_options) in enumerate(options_cases):
            index = (int(chained) * 2 + int(first_tcp_bytes == 24)) * len(options_cases) + case_index
            src_port = 45550 + index
            seq = 0x529b0000 + index
            tcp = bytearray(
                struct.pack("!HHIIHHHH", src_port, 39643, seq, 0,
                            (6 << 12) | 2, 65535, 0, 0) + tcp_options
                + b"malformed-tcp-options"
            )
            pseudo = source6 + target6 + struct.pack(
                "!I3xB", len(tcp), socket.IPPROTO_TCP
            )
            tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
            options = bytes((socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_TCP,
                             0, 1, 4, 0, 0, 0, 0))
            if chained:
                options += bytes((socket.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0))
            fragmentable = options + tcp
            split = len(options) + first_tcp_bytes
            def fragment(part, offset, more):
                fh = struct.pack(
                    "!BBHI", socket.IPPROTO_DSTOPTS, 0,
                    ((offset // 8) << 3) | int(more), 0x66778f00 + index
                )
                ip = struct.pack(
                    "!IHBB16s16s", 6 << 28, len(fh) + len(part),
                    socket.IPPROTO_FRAGMENT, 64, source6, target6
                )
                return ip + fh + part

            tx.sendto(fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
            tx.sendto(fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
            outcome = "drop"
            deadline = time.monotonic() + 0.35
            while time.monotonic() < deadline:
                ready, _, _ = select.select(
                    (rx,), (), (), max(0.01, deadline - time.monotonic())
                )
                if not ready:
                    break
                response, peer = rx.recvfrom(4096)
                if peer[0] != target_v6:
                    continue
                message = response[40:] if response and response[0] >> 4 == 6 else response
                if len(message) < 20:
                    continue
                sport, dport, rseq, ack, flags, _, _, _ = struct.unpack(
                    "!HHIIHHHH", message[:20]
                )
                if sport != 39643 or dport != src_port:
                    continue
                reply_pseudo = target6 + source6 + struct.pack(
                    "!I3xB", len(message), socket.IPPROTO_TCP
                )
                if checksum(reply_pseudo + message):
                    raise RuntimeError(f"{label}: invalid TCP reply checksum for {name}")
                outcome = ("syn-ack" if flags & 0x12 == 0x12 and ack == seq + 1
                           else f"tcp-flags-{flags & 0x3f:x}")
                break
            if outcome != "syn-ack":
                raise RuntimeError(
                    f"{label}: malformed TCP option {name} chained={chained} "
                    f"tcp-first={first_tcp_bytes} -> {outcome}; expected syn-ack"
                )
            print(
                f"{label}: malformed TCP option {name} chained={chained} "
                f"tcp-first={first_tcp_bytes} -> {outcome}", flush=True
            )
rx.close()
tx.close()
PY
}

run_fragmented_ipv6_tcp_data_offset_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# Data Offset measured in four-byte words. All SYNs have valid IPv6 and TCP
# checksums. The 6-word control supplies four valid NOP option bytes; the
# 15-word case declares 60 bytes despite the shorter TCP segment.
for chained in (False, True):
    for first_tcp_bytes in (8, 24):
        for offset_words in (0, 4, 5, 6, 15):
            index = 10 * int(chained) + 5 * int(first_tcp_bytes == 24) + (0, 4, 5, 6, 15).index(offset_words)
            src_port = 45620 + index
            seq = 0x529c0000 + index
            tcp = bytearray(
                struct.pack("!HHIIHHHH", src_port, 39643, seq, 0,
                            (offset_words << 12) | 2, 65535, 0, 0)
                + bytes((1, 1, 1, 1)) + b"data-offset-syn"
            )
            pseudo = source6 + target6 + struct.pack("!I3xB", len(tcp), socket.IPPROTO_TCP)
            tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
            options = bytes((socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_TCP,
                             0, 1, 4, 0, 0, 0, 0))
            if chained:
                options += bytes((socket.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0))
            fragmentable = options + tcp
            split = len(options) + first_tcp_bytes

            def fragment(part, offset, more):
                fh = struct.pack("!BBHI", socket.IPPROTO_DSTOPTS, 0,
                                 ((offset // 8) << 3) | int(more), 0x66779000 + index)
                ip = struct.pack("!IHBB16s16s", 6 << 28, len(fh) + len(part),
                                 socket.IPPROTO_FRAGMENT, 64, source6, target6)
                return ip + fh + part

            tx.sendto(fragment(fragmentable[split:], split, False), (target_v6, 0, 0, 0))
            tx.sendto(fragment(fragmentable[:split], 0, True), (target_v6, 0, 0, 0))
            outcome = "drop"
            deadline = time.monotonic() + 0.45
            while time.monotonic() < deadline:
                ready, _, _ = select.select((rx,), (), (), max(0.01, deadline - time.monotonic()))
                if not ready:
                    break
                response, peer = rx.recvfrom(4096)
                if peer[0] != target_v6:
                    continue
                message = response[40:] if response and response[0] >> 4 == 6 else response
                if len(message) < 20:
                    continue
                sport, dport, rseq, ack, flags, _, _, _ = struct.unpack("!HHIIHHHH", message[:20])
                if sport != 39643 or dport != src_port:
                    continue
                reply_pseudo = target6 + source6 + struct.pack("!I3xB", len(message), socket.IPPROTO_TCP)
                if checksum(reply_pseudo + message):
                    raise RuntimeError(f"{label}: invalid TCP checksum for data offset={offset_words}")
                outcome = ("syn-ack" if flags & 0x12 == 0x12 and ack == seq + 1
                           else f"tcp-flags-{flags & 0x3f:x}")
                break
            expected = "syn-ack" if offset_words in (5, 6) else "drop"
            if outcome != expected:
                raise RuntimeError(
                    f"{label}: TCP Data Offset {offset_words} chained={chained} "
                    f"tcp-first={first_tcp_bytes} -> {outcome}; expected {expected}"
                )
            print(
                f"{label}: TCP Data Offset {offset_words} chained={chained} "
                f"tcp-first={first_tcp_bytes} -> {outcome}", flush=True
            )
rx.close()
tx.close()
PY
}

run_fragmented_ipv6_tcp_non_syn_option_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
cases = (
    ("ack", 0x10),
    ("fin-ack", 0x11),
    ("rst", 0x04),
)
options_cases = (
    ("nop", bytes((1, 1, 1, 1))),
    ("invalid-mss", bytes((2, 0, 5, 180))),
    ("invalid-unknown", bytes((30, 0, 1, 1))),
)
for chained in (False, True):
    for first_tcp_bytes in (8, 24):
        for kind_name, flags in cases:
            for option_name, tcp_options in options_cases:
                index = (
                    ((int(chained) * 2 + int(first_tcp_bytes == 24)) * 3
                      + cases.index((kind_name, flags))) * len(options_cases)
                    + options_cases.index((option_name, tcp_options))
                )
                src_port = 45720 + index
                seq = 0x529d0000 + index
                ack = 0x529e0000 + index
                tcp = bytearray(
                    struct.pack("!HHIIHHHH", src_port, 39643, seq, ack,
                                (6 << 12) | flags, 65535, 0, 0)
                    + tcp_options + b"non-syn-options"
                )
                pseudo = source6 + target6 + struct.pack(
                    "!I3xB", len(tcp), socket.IPPROTO_TCP
                )
                tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
                options = bytes((socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_TCP,
                                 0, 1, 4, 0, 0, 0, 0))
                if chained:
                    options += bytes((socket.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0))
                fragmentable = options + tcp
                split = len(options) + first_tcp_bytes
                def fragment(part, offset, more):
                    fh = struct.pack(
                        "!BBHI", socket.IPPROTO_DSTOPTS, 0,
                        ((offset // 8) << 3) | int(more), 0x66779100 + index
                    )
                    ip = struct.pack(
                        "!IHBB16s16s", 6 << 28, len(fh) + len(part),
                        socket.IPPROTO_FRAGMENT, 64, source6, target6
                    )
                    return ip + fh + part

                tx.sendto(fragment(fragmentable[split:], split, False),
                          (target_v6, 0, 0, 0))
                tx.sendto(fragment(fragmentable[:split], 0, True),
                          (target_v6, 0, 0, 0))
                outcome = "drop"
                deadline = time.monotonic() + 0.4
                while time.monotonic() < deadline:
                    ready, _, _ = select.select(
                        (rx,), (), (), max(0.01, deadline - time.monotonic())
                    )
                    if not ready:
                        break
                    response, peer = rx.recvfrom(4096)
                    if peer[0] != target_v6:
                        continue
                    message = (response[40:] if response and response[0] >> 4 == 6
                               else response)
                    if len(message) < 20:
                        continue
                    sport, dport, rseq, rack, rflags, _, _, _ = struct.unpack(
                        "!HHIIHHHH", message[:20]
                    )
                    if sport != 39643 or dport != src_port:
                        continue
                    reply_pseudo = target6 + source6 + struct.pack(
                        "!I3xB", len(message), socket.IPPROTO_TCP
                    )
                    if checksum(reply_pseudo + message):
                        raise RuntimeError(
                            f"{label}: invalid TCP checksum for {kind_name}/{option_name}"
                        )
                    outcome = (f"rst/seq-{rseq == ack}"
                               if (rflags & 0x3f) == 0x04
                               else f"tcp-flags-{rflags & 0x3f:x}")
                    break
                expected = "drop" if kind_name == "rst" else "rst/seq-True"
                if outcome != expected:
                    raise RuntimeError(
                        f"{label}: non-SYN TCP {kind_name}/{option_name} "
                        f"chained={chained} tcp-first={first_tcp_bytes} -> "
                        f"{outcome}; expected {expected}"
                    )
                print(
                    f"{label}: non-SYN TCP {kind_name}/{option_name} "
                    f"chained={chained} tcp-first={first_tcp_bytes} -> {outcome}",
                    flush=True
                )
rx.close()
tx.close()
PY
}

run_fragmented_ipv6_tcp_active_options_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source6 = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target6 = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def tcp_segment(src_port, seq, ack, flags, options=b"", payload=b""):
    tcp = bytearray(
        struct.pack("!HHIIHHHH", src_port, 39643, seq, ack,
                    ((5 + len(options) // 4) << 12) | flags, 65535, 0, 0)
        + options + payload
    )
    pseudo = source6 + target6 + struct.pack("!I3xB", len(tcp), socket.IPPROTO_TCP)
    tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
    return bytes(tcp)

def ipv6_packet(next_header, body):
    return struct.pack(
        "!IHBB16s16s", 6 << 28, len(body), next_header, 64, source6, target6
    ) + body

def send_ipv6(body, next_header=socket.IPPROTO_TCP):
    tx.sendto(ipv6_packet(next_header, body), (target_v6, 0, 0, 0))

def send_fragments(index, chained, first_tcp_bytes, tcp):
    options = bytes((
        socket.IPPROTO_DSTOPTS if chained else socket.IPPROTO_TCP,
        0, 1, 4, 0, 0, 0, 0
    ))
    if chained:
        options += bytes((socket.IPPROTO_TCP, 0, 1, 4, 0, 0, 0, 0))
    data = options + tcp
    split = len(options) + first_tcp_bytes
    if split >= len(data):
        raise RuntimeError("fragment split must leave a nonempty second fragment")
    def fragment(part, offset, more):
        header = struct.pack(
            "!BBHI", socket.IPPROTO_DSTOPTS, 0,
            ((offset // 8) << 3) | int(more), 0x66779200 + index
        )
        return ipv6_packet(socket.IPPROTO_FRAGMENT, header + part)
    tx.sendto(fragment(data[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(data[:split], 0, True), (target_v6, 0, 0, 0))

def recv_response(src_port, deadline_seconds):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            (rx,), (), (), max(0.01, deadline - time.monotonic())
        )
        if not ready:
            return None
        packet, peer = rx.recvfrom(4096)
        if peer[0] != target_v6:
            continue
        segment = packet[40:] if packet and packet[0] >> 4 == 6 else packet
        if len(segment) < 20:
            continue
        sport, dport, seq, ack, offset_flags, _, _, _ = struct.unpack(
            "!HHIIHHHH", segment[:20]
        )
        if sport != 39643 or dport != src_port:
            continue
        pseudo = target6 + source6 + struct.pack(
            "!I3xB", len(segment), socket.IPPROTO_TCP
        )
        if checksum(pseudo + segment):
            raise RuntimeError(f"{label}: invalid TCP response checksum")
        header_len = (offset_flags >> 12) * 4
        if header_len < 20 or header_len > len(segment):
            raise RuntimeError(f"{label}: invalid TCP response data offset")
        return seq, ack, offset_flags & 0x3f, segment[header_len:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)

# Without a kernel TCP socket for the raw SYN, Linux otherwise sends an
# automatic RST in response to SYN-ACK. This temporary rule is isolated
# inside the ephemeral Office namespace and is always removed.
subprocess.run(["nft", "add", "table", "inet", "chimera_active_tcp"], check=True)
try:
    subprocess.run([
        "nft", "add", "chain", "inet", "chimera_active_tcp", "output",
        "{ type filter hook output priority 0; policy accept; }"
    ], check=True)
    subprocess.run([
        "nft", "add", "rule", "inet", "chimera_active_tcp", "output",
        "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
        "tcp", "flags", "rst", "drop"
    ], check=True)

    for chained in (False, True):
        for first_tcp_bytes in (8, 24):
            for option_index, (name, tcp_options) in enumerate((
                ("nop", bytes((1, 1, 1, 1))),
                ("bad-mss", bytes((2, 0, 5, 180))),
                ("bad-unknown", bytes((30, 0, 1, 1))),
            )):
                case = (2 * int(chained) + int(first_tcp_bytes == 24)) * 3 + option_index
                src_port = 45830 + case
                init_seq = 0x52800000 + 100 * case
                send_ipv6(tcp_segment(src_port, init_seq, 0, 0x02))
                response = recv_response(src_port, 2)
                if response is None or response[2] & 0x12 != 0x12 or response[1] != init_seq + 1:
                    raise RuntimeError(
                        f"{label}: active TCP {name} chained={chained} "
                        f"tcp-first={first_tcp_bytes} SYN handshake failed: {response}"
                    )
                server_seq = response[0] + 1
                client_seq = init_seq + 1
                send_ipv6(tcp_segment(src_port, client_seq, server_seq, 0x10))
                payload = f"active-{case:02d}".encode()
                send_fragments(case * 2, chained, first_tcp_bytes, tcp_segment(
                    src_port, client_seq, server_seq, 0x10, tcp_options, payload
                ))
                received = b""
                deadline = time.monotonic() + 2
                while payload not in received and time.monotonic() < deadline:
                    reply = recv_response(src_port, max(0.01, deadline - time.monotonic()))
                    if reply is None:
                        break
                    rseq, rack, rflags, data = reply
                    if rflags & 4:
                        raise RuntimeError(f"{label}: active TCP {name} unexpectedly reset")
                    if data and rseq == server_seq + len(received):
                        received += data
                data_outcome = "echo" if payload in received else "no-echo"
                if data_outcome == "echo":
                    server_seq += len(received)
                    client_seq += len(payload)
                    send_ipv6(tcp_segment(src_port, client_seq, server_seq, 0x10))
                    fin_payload = f"fin-{case:02d}".encode()
                    send_fragments(case * 2 + 1, chained, first_tcp_bytes, tcp_segment(
                        src_port, client_seq, server_seq, 0x11, tcp_options, fin_payload
                    ))
                    fin_received = b""
                    saw_fin = False
                    fin_was_acked = False
                    fin_started = time.monotonic()
                    # The pinned Xray 26.9.9 dispatcher may delay the
                    # outbound peer FIN by about two seconds even after it
                    # acknowledges the inbound FIN. A four-second window
                    # avoids mistaking that boundary for a missing FIN.
                    fin_watch_seconds = 4
                    deadline = fin_started + fin_watch_seconds
                    fin_delay_ms = None
                    while time.monotonic() < deadline:
                        reply = recv_response(src_port, max(0.01, deadline - time.monotonic()))
                        if reply is None:
                            break
                        rseq, rack, rflags, data = reply
                        if rflags & 4:
                            break
                        if rflags & 0x10 and rack == client_seq + len(fin_payload) + 1:
                            fin_was_acked = True
                        if data and rseq == server_seq + len(fin_received):
                            fin_received += data
                            # ACK the echoed tail immediately: gVisor may
                            # hold its FIN until outstanding data is ACKed.
                            send_ipv6(tcp_segment(
                                src_port, client_seq + len(fin_payload) + 1,
                                server_seq + len(fin_received), 0x10
                            ))
                        if rflags & 1:
                            saw_fin = True
                            fin_delay_ms = int((time.monotonic() - fin_started) * 1000)
                            break
                    fin_outcome = ("fin-echo" if fin_payload in fin_received
                                   else "fin-no-echo")
                    if saw_fin:
                        fin_outcome += f"+peer-fin-{fin_delay_ms}ms"
                    else:
                        fin_outcome += f"+no-peer-fin-in-{fin_watch_seconds}s"
                    fin_outcome += "+fin-ack" if fin_was_acked else "+no-fin-ack"
                    send_ipv6(tcp_segment(
                        src_port, client_seq + len(fin_payload) + 1,
                        server_seq + len(fin_received) + int(saw_fin), 0x10
                    ))
                else:
                    fin_outcome = "not-attempted"
                if (data_outcome != "echo" or not fin_outcome.startswith("fin-echo")
                        or not saw_fin or not fin_was_acked):
                    raise RuntimeError(
                        f"{label}: active TCP {name} chained={chained} "
                        f"tcp-first={first_tcp_bytes} -> {data_outcome}/{fin_outcome}; "
                        "expected data echo, inbound FIN ACK and peer FIN"
                    )
                print(
                    f"{label}: active TCP {name} chained={chained} "
                    f"tcp-first={first_tcp_bytes} -> {data_outcome}/{fin_outcome}",
                    flush=True
                )
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_active_tcp"], check=True)
    rx.close()
    tx.close()
PY
}

run_fragmented_ipv6_tcp_active_rst_reuse_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def segment(port, seq, ack, flags, opts=b"", payload=b""):
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        ((5 + len(opts) // 4) << 12) | flags, 65535, 0, 0
    ) + opts + payload)
    pseudo = source + target + struct.pack("!I3xB", len(tcp), 6)
    tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
    return bytes(tcp)

def packet(next_header, data):
    return struct.pack("!IHBB16s16s", 6 << 28, len(data),
                       next_header, 64, source, target) + data

def send(tcp):
    tx.sendto(packet(6, tcp), (target_v6, 0, 0, 0))

def fragmented(tcp, identifier, chained, tcp_first):
    opts = bytes((socket.IPPROTO_DSTOPTS if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        opts += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    data = opts + tcp
    split = len(opts) + tcp_first
    def fragment(body, offset, more):
        frag = struct.pack("!BBHI", socket.IPPROTO_DSTOPTS, 0,
                           ((offset // 8) << 3) | int(more), identifier)
        return packet(socket.IPPROTO_FRAGMENT, frag + body)
    if split >= len(data):
        raise RuntimeError("empty second fragment")
    tx.sendto(fragment(data[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(data[:split], 0, True), (target_v6, 0, 0, 0))

def reply(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select((rx,), (), (), max(0.001, deadline - time.monotonic()))
        if not ready:
            return None
        message, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = message[40:] if message[0] >> 4 == 6 else message
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, fields, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if sport != 39643 or dport != port:
            continue
        pseudo = target + source + struct.pack("!I3xB", len(tcp), 6)
        if checksum(pseudo + tcp):
            raise RuntimeError(f"{label}: invalid response TCP checksum")
        offset = (fields >> 12) * 4
        return seq, ack, fields & 63, tcp[offset:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_rst_reuse"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_rst_reuse", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_rst_reuse",
                    "output", "ip6", "saddr", "fd18:251::2", "ip6", "daddr",
                    target_v6, "ip6", "nexthdr", "tcp",
                    "tcp", "flags", "rst", "drop"], check=True)
    for chained in (False, True):
        for tcp_first in (8, 24):
            for opt_index, (name, opts) in enumerate((
                ("nop", bytes((1, 1, 1, 1))),
                ("invalid-mss", bytes((2, 0, 5, 180))),
                ("invalid-unknown", bytes((30, 0, 1, 1))),
            )):
                case = (2 * int(chained) + int(tcp_first == 24)) * 3 + opt_index
                port = 45920 + case
                initial_seq = 0x52a00000 + 100 * case
                send(segment(port, initial_seq, 0, 0x02))
                r = reply(port, 1.5)
                if r is None or r[2] & 0x12 != 0x12 or r[1] != initial_seq + 1:
                    raise RuntimeError(f"{label}: RST probe handshake failed: {r}")
                srv_ack = r[0] + 1
                cli_seq = initial_seq + 1
                send(segment(port, cli_seq, srv_ack, 0x10))
                data = b"before-rst"
                fragmented(segment(port, cli_seq, srv_ack, 0x10, b"\x01"*4, data),
                           0x66779300 + case * 3, chained, tcp_first)
                echoed = b""
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and data not in echoed:
                    response = reply(port, max(0.001, deadline - time.monotonic()))
                    if response is None:
                        break
                    seq, ack, flags, body = response
                    if body and seq == srv_ack + len(echoed):
                        echoed += body
                if data not in echoed:
                    raise RuntimeError(f"{label}: RST probe initial data not echoed")
                cli_seq += len(data)
                srv_ack += len(data)
                send(segment(port, cli_seq, srv_ack, 0x10))
                # Duplicate/retransmitted segment at the old sequence must
                # not produce a second payload or advance the send window.
                fragmented(segment(port, cli_seq - len(data), srv_ack, 0x10,
                                   b"\x01"*4, data),
                           0x66779301 + case * 3, chained, tcp_first)
                duplicate = False
                until = time.monotonic() + 0.12
                while time.monotonic() < until:
                    response = reply(port, max(0.001, until - time.monotonic()))
                    if response is None:
                        break
                    if response[3]:
                        duplicate = True
                # Send a syntactically valid but far-out-of-window RST+ACK.
                # It must not destroy a live connection. Observe any challenge
                # ACK separately from a subsequent payload-continuity check.
                fragmented(segment(port, cli_seq + (1 << 20), srv_ack, 0x14,
                                   opts, b"rst-test"),
                           0x66779400 + case * 8, chained, tcp_first)
                out_rst_ack = False
                until = time.monotonic() + 0.12
                while time.monotonic() < until:
                    response = reply(port, max(0.001, until - time.monotonic()))
                    if response is None:
                        break
                    if response[2] == 0x10 and response[1] == cli_seq:
                        out_rst_ack = True
                alive_payload = b"after-far-rst"
                fragmented(segment(port, cli_seq, srv_ack, 0x10, b"\x01"*4,
                                   alive_payload),
                           0x66779401 + case * 8, chained, tcp_first)
                alive = b""
                deadline = time.monotonic() + 1.5
                while time.monotonic() < deadline and alive_payload not in alive:
                    response = reply(port, max(0.001, deadline - time.monotonic()))
                    if response is None:
                        break
                    if response[3] and response[0] == srv_ack + len(alive):
                        alive += response[3]
                connection_survived = alive_payload in alive
                if connection_survived:
                    cli_seq += len(alive_payload)
                    srv_ack += len(alive_payload)
                    send(segment(port, cli_seq, srv_ack, 0x10))
                # The exact-window RST+ACK from 13.98 is the recovery control.
                fragmented(segment(port, cli_seq, srv_ack, 0x14, opts, b"rst-test"),
                           0x66779402 + case * 8, chained, tcp_first)
                # This is observation-only until the pinned reference contract
                # is determined; a fresh SYN on the same tuple checks reuse.
                time.sleep(0.10)
                send(segment(port, cli_seq + 1000, 0, 0x02))
                reopened = False
                deadline = time.monotonic() + 1.2
                while time.monotonic() < deadline:
                    response = reply(port, max(0.001, deadline - time.monotonic()))
                    if response is None:
                        break
                    if response[2] & 0x12 == 0x12 and response[1] == cli_seq + 1001:
                        reopened = True
                        break
                # Reopened tuple: a bare RST may parse differently from
                # RST+ACK, particularly with a malformed TCP option length.
                bare_reopened = False
                final_server_seq = None
                if reopened:
                    new_cli_seq = cli_seq + 1001
                    new_server_seq = response[0] + 1
                    send(segment(port, new_cli_seq, new_server_seq, 0x10))
                    fragmented(segment(port, new_cli_seq, new_server_seq, 0x04,
                                       opts, b"rst-test"),
                               0x66779403 + case * 8, chained, tcp_first)
                    time.sleep(0.10)
                    send(segment(port, new_cli_seq + 1000, 0, 0x02))
                    deadline = time.monotonic() + 1.2
                    while time.monotonic() < deadline:
                        check = reply(port, max(0.001, deadline - time.monotonic()))
                        if check is None:
                            break
                        if (check[2] & 0x12 == 0x12
                                and check[1] == new_cli_seq + 1001):
                            bare_reopened = True
                            final_server_seq = check[0] + 1
                            break
                # Near-window probes use the newly reopened, established
                # tuple. Offset -1 is below RCV.NXT; offset +1 is strictly
                # inside the advertised receive window but not the exact
                # next expected sequence. Keep RST TCP data nonempty so that
                # the IPv6 packet genuinely has two fragments.
                behind_ack = False
                behind_survived = False
                ahead_ack = False
                ahead_reopened = False
                if bare_reopened:
                    final_client_seq = new_cli_seq + 1001
                    send(segment(port, final_client_seq, final_server_seq, 0x10))
                    fragmented(segment(
                        port, final_client_seq - 1, final_server_seq,
                        0x14, opts, b"rst-test"
                    ), 0x66779404 + case * 8, chained, tcp_first)
                    until = time.monotonic() + 0.12
                    while time.monotonic() < until:
                        packet_reply = reply(port, max(0.001, until - time.monotonic()))
                        if packet_reply is None:
                            break
                        if packet_reply[2] == 0x10 and packet_reply[1] == final_client_seq:
                            behind_ack = True
                    # Probe the ACK rate limiter without changing any TCP
                    # sequence number or consuming application data. Only
                    # two control flows (one/two Destination Options) take
                    # the longer timing path. The late repetition deliberately
                    # has no RST payload: the 24-byte TCP header still spans
                    # two nonempty fragments when tcp_first == 8.
                    repeat_early_ack = None
                    repeat_late_ack = None
                    if name == "nop" and tcp_first == 8:
                        fragmented(segment(
                            port, final_client_seq - 1, final_server_seq,
                            0x14, opts, b"rst-test"
                        ), 0x66779500 + case * 3, chained, tcp_first)
                        repeat_early_ack = False
                        until = time.monotonic() + 0.12
                        while time.monotonic() < until:
                            repeated = reply(port, max(0.001, until - time.monotonic()))
                            if repeated is None:
                                break
                            if (repeated[2] == 0x10
                                    and repeated[1] == final_client_seq):
                                repeat_early_ack = True
                        time.sleep(1.12)
                        fragmented(segment(
                            port, final_client_seq - 1, final_server_seq,
                            0x14, opts  # header-only RST, no TCP data
                        ), 0x66779501 + case * 3, chained, tcp_first)
                        repeat_late_ack = False
                        until = time.monotonic() + 0.15
                        while time.monotonic() < until:
                            repeated = reply(port, max(0.001, until - time.monotonic()))
                            if repeated is None:
                                break
                            if (repeated[2] == 0x10
                                    and repeated[1] == final_client_seq):
                                repeat_late_ack = True
                    marker = b"alive-after-behind-rst"
                    fragmented(segment(
                        port, final_client_seq, final_server_seq, 0x10,
                        b"\x01" * 4, marker
                    ), 0x66779405 + case * 8, chained, tcp_first)
                    echoed_again = b""
                    deadline = time.monotonic() + 1.2
                    while time.monotonic() < deadline and marker not in echoed_again:
                        packet_reply = reply(port, max(0.001, deadline - time.monotonic()))
                        if packet_reply is None:
                            break
                        if (packet_reply[3]
                                and packet_reply[0] == final_server_seq + len(echoed_again)):
                            echoed_again += packet_reply[3]
                    behind_survived = marker in echoed_again
                    if behind_survived:
                        final_client_seq += len(marker)
                        final_server_seq += len(marker)
                        send(segment(port, final_client_seq, final_server_seq, 0x10))
                        fragmented(segment(
                            port, final_client_seq + 1, final_server_seq,
                            0x14, opts, b"rst-test"
                        ), 0x66779406 + case * 8, chained, tcp_first)
                        until = time.monotonic() + 0.12
                        while time.monotonic() < until:
                            packet_reply = reply(
                                port, max(0.001, until - time.monotonic())
                            )
                            if packet_reply is None:
                                break
                            if packet_reply[2] == 0x10 and packet_reply[1] == final_client_seq:
                                ahead_ack = True
                        time.sleep(0.10)
                        send(segment(port, final_client_seq + 2000, 0, 0x02))
                        deadline = time.monotonic() + 1.2
                        while time.monotonic() < deadline:
                            packet_reply = reply(
                                port, max(0.001, deadline - time.monotonic())
                            )
                            if packet_reply is None:
                                break
                            if (packet_reply[2] & 0x12 == 0x12
                                    and packet_reply[1] == final_client_seq + 2001):
                                ahead_reopened = True
                                break
                if (duplicate or out_rst_ack or not connection_survived
                        or not reopened or not bare_reopened
                        or not behind_survived or not ahead_reopened):
                    raise RuntimeError(
                        f"{label}: RST sequence/window mismatch for {name}, "
                        f"chained={chained}, tcp-first={tcp_first}: "
                        f"duplicate={duplicate} far-rst-ack={out_rst_ack} "
                        f"survived={connection_survived} rst-ack={reopened} "
                        f"bare-rst={bare_reopened} behind-ack={behind_ack} "
                        f"behind-survived={behind_survived} ahead-ack={ahead_ack} "
                        f"ahead-reopened={ahead_reopened}"
                    )
                print(
                    f"{label}: active TCP RST {name} chained={chained} "
                    f"tcp-first={tcp_first} -> duplicate-data={duplicate} "
                    f"far-rst-ack={out_rst_ack} survived={connection_survived} "
                    f"rst-ack-reopened={reopened} bare-rst-reopened={bare_reopened} "
                    f"behind-ack={behind_ack} behind-survived={behind_survived} "
                    f"ahead-ack={ahead_ack} ahead-reopened={ahead_reopened} "
                    f"repeat-early-ack={repeat_early_ack} "
                    f"repeat-late-ack={repeat_late_ack}",
                    flush=True
                )
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_rst_reuse"], check=True)
    rx.close()
    tx.close()
PY
}

run_fragmented_ipv6_tcp_active_ack_window_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def segment(port, seq, ack, flags, payload=b""):
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        (6 << 12) | flags, 65535, 0, 0
    ) + b"\x01" * 4 + payload)
    pseudo = source + target + struct.pack("!I3xB", len(tcp), 6)
    tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
    return bytes(tcp)

def ipv6(nh, body):
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), nh, 64, source, target) + body

def send(tcp):
    tx.sendto(ipv6(6, tcp), (target_v6, 0, 0, 0))

def fragmented(tcp, frag_id, chained):
    extension = bytes((60 if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        extension += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    data = extension + tcp
    split = len(extension) + 8
    def frag(part, at, more):
        header = struct.pack("!BBHI", 60, 0, ((at // 8) << 3) | int(more), frag_id)
        return ipv6(44, header + part)
    assert len(data) > split
    tx.sendto(frag(data[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(frag(data[:split], 0, True), (target_v6, 0, 0, 0))

def response(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select((rx,), (), (), max(0.001, deadline - time.monotonic()))
        if not ready:
            return None
        message, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = message[40:] if message[0] >> 4 == 6 else message
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, field, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if sport != 39643 or dport != port:
            continue
        pseudo = target + source + struct.pack("!I3xB", len(tcp), 6)
        if checksum(pseudo + tcp):
            raise RuntimeError(f"{label}: invalid TCP reply checksum")
        header_len = (field >> 12) * 4
        if not 20 <= header_len <= len(tcp):
            raise RuntimeError(f"{label}: invalid TCP reply header length")
        return seq, ack, field & 63, tcp[header_len:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_ack_window"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_ack_window", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_ack_window", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    probes = (
        ("seq-behind", -1, 0),
        ("seq-ahead", 1, 0),
        ("seq-far", 1 << 20, 0),
        ("ack-future", 0, 64),
    )
    for chained in (False, True):
        for index, (name, sequence_delta, acknowledgment_delta) in enumerate(probes):
            case = 4 * int(chained) + index
            port = 45970 + case
            client_start = 0x52b00000 + 100 * case
            send(segment(port, client_start, 0, 0x02))
            syn_ack = response(port, 1.5)
            if (syn_ack is None or syn_ack[2] & 0x12 != 0x12
                    or syn_ack[1] != client_start + 1):
                raise RuntimeError(f"{label}: active ACK {name} handshake failed: {syn_ack}")
            client_seq = client_start + 1
            server_seq = syn_ack[0] + 1
            send(segment(port, client_seq, server_seq, 0x10))
            initial = f"pre-ack-{case}".encode()
            fragmented(segment(port, client_seq, server_seq, 0x10, initial),
                       0x66779600 + case * 4, chained)
            deadline = time.monotonic() + 2
            echoed = b""
            while time.monotonic() < deadline and initial not in echoed:
                reply = response(port, max(0.001, deadline - time.monotonic()))
                if reply is None:
                    break
                if reply[2] & 4:
                    raise RuntimeError(f"{label}: active ACK {name} unexpected RST")
                if reply[3] and reply[0] == server_seq + len(echoed):
                    echoed += reply[3]
            if echoed != initial:
                raise RuntimeError(f"{label}: active ACK {name} pre-echo failed {echoed!r}")
            client_seq += len(initial)
            server_seq += len(initial)
            send(segment(port, client_seq, server_seq, 0x10))
            # Drain delayed ACKs to avoid attributing one to this bad ACK.
            until = time.monotonic() + 0.09
            while time.monotonic() < until:
                if response(port, max(0.001, until - time.monotonic())) is None:
                    break
            fragmented(segment(
                port, (client_seq + sequence_delta) & 0xffffffff,
                (server_seq + acknowledgment_delta) & 0xffffffff, 0x10
            ), 0x66779601 + case * 4, chained)
            candidate_ack = False
            until = time.monotonic() + 0.20
            while time.monotonic() < until:
                reply = response(port, max(0.001, until - time.monotonic()))
                if reply is None:
                    break
                if reply[2] == 0x10 and reply[1] == client_seq and not reply[3]:
                    candidate_ack = True
            after = f"post-ack-{case}".encode()
            fragmented(segment(port, client_seq, server_seq, 0x10, after),
                       0x66779602 + case * 4, chained)
            received = b""
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and after not in received:
                reply = response(port, max(0.001, deadline - time.monotonic()))
                if reply is None:
                    break
                if reply[2] & 4:
                    raise RuntimeError(f"{label}: active ACK {name} reset active flow")
                if reply[3] and reply[0] == server_seq + len(received):
                    received += reply[3]
            if received != after:
                raise RuntimeError(f"{label}: active ACK {name} post-echo failed: {received!r}")
            # Pinned gVisor ACKs out-of-window *sequence* probes but does
            # not challenge an impossible ACK number. smoltcp does reply
            # to that impossible ACK number. The data path must survive
            # in either case; keep the distinct reply contract explicit.
            expected_ack = (name in ("seq-behind", "seq-far")
                            or (name == "ack-future"
                                and label == "Chimera Xray TUN"))
            if candidate_ack != expected_ack:
                raise RuntimeError(
                    f"{label}: active ACK {name} chained={chained}: "
                    f"candidate-ack={candidate_ack}, expected {expected_ack}"
                )
            client_seq += len(after)
            server_seq += len(after)
            send(segment(port, client_seq, server_seq, 0x10))
            fragmented(segment(port, client_seq, server_seq, 0x14),
                       0x66779603 + case * 4, chained)
            print(f"{label}: active TCP ACK {name} chained={chained} "
                  f"-> candidate-ack={candidate_ack} echo-before-after=True", flush=True)
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_ack_window"], check=True)
    rx.close()
    tx.close()
PY
}

run_fragmented_ipv6_tcp_zero_window_recovery_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff

# A compound SYN negotiates Timestamp as well as Window Scale. Subsequent
# packets must retain a valid TS option (PAWS must not reject the test itself).
compound_ts = None
peer_ts = None
def segment(port, seq, ack, flags, window, payload=b"", options=None):
    if options is None:
        options = (b"\x01\x01\x08\x0a" + struct.pack("!II", compound_ts, peer_ts)
                   if compound_ts is not None and not flags & 0x02 else b"\x01"*4)
    assert len(options) % 4 == 0 and len(options) <= 40
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        ((5 + len(options)//4) << 12) | flags, window, 0, 0
    ) + options + payload)
    pseudo = source + target + struct.pack("!I3xB", len(tcp), 6)
    tcp[16:18] = struct.pack("!H", checksum(pseudo + tcp))
    return bytes(tcp)

def ipv6(nh, payload):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, 64, source, target) + payload

def send(tcp):
    tx.sendto(ipv6(6, tcp), (target_v6, 0, 0, 0))

def fragmented(tcp, ident, chained, drop_tail=False):
    opts = bytes((60 if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        opts += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    body = opts + tcp
    split = len(opts) + 8
    assert split < len(body)
    def fragment(part, offset, more):
        fh = struct.pack("!BBHI", 60, 0, (offset // 8 << 3) | int(more), ident)
        return ipv6(44, fh + part)
    if not drop_tail:
        tx.sendto(fragment(body[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(body[:split], 0, True), (target_v6, 0, 0, 0))

def reply(port, seconds, with_options=False):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select((rx,), (), (), max(0.001, deadline - time.monotonic()))
        if not ready:
            return None
        message, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = message[40:] if message[0] >> 4 == 6 else message
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, bits, window, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if sport != 39643 or dport != port:
            continue
        pseudo = target + source + struct.pack("!I3xB", len(tcp), 6)
        if checksum(pseudo + tcp):
            raise RuntimeError(f"{label}: zero-window reply checksum invalid")
        size = (bits >> 12) * 4
        if not 20 <= size <= len(tcp):
            raise RuntimeError(f"{label}: zero-window reply header length invalid")
        result = (seq, ack, bits & 63, window, tcp[size:])
        return result + (tcp[20:size],) if with_options else result
    return None

def parse_syn_options(options):
    result = {"ws": None, "mss": None, "sack": False, "ts": None}
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            break
        option_len = options[index + 1]
        if option_len < 2 or index + option_len > len(options):
            break
        if kind == 3 and option_len == 3:
            result["ws"] = options[index + 2]
        if kind == 2 and option_len == 4:
            result["mss"] = struct.unpack("!H", options[index+2:index+4])[0]
        if kind == 4 and option_len == 2:
            result["sack"] = True
        if kind == 8 and option_len == 10:
            result["ts"] = struct.unpack("!II", options[index+2:index+10])
        index += option_len
    return result

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_zero_window"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_zero_window", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_zero_window", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    # The previous three flows remain fixed baselines. New WS=0 and a
    # fragmented compound-SYN WS=1 case check narrow windows of 1/2 bytes.
    for case, chained, ws_shift, compound in (
        (0, False, None, False), (1, True, None, False),
        (2, False, 3, False), (3, False, 0, False),
        (4, True, 1, True),
    ):
        scaled = ws_shift is not None
        compound_ts = 0x10203040 if compound else None
        peer_ts = None
        port = 45990 + case
        start_seq = 0x52c00000 + 1000 * case
        syn_options = (bytes((2, 4, 5, 0, 4, 2, 3, 3, 1, 1, 8, 10))
                       + struct.pack("!II", compound_ts, 0)) if compound else (
                           bytes((3, 3, ws_shift, 1)) if scaled else b"\x01"*4
                       )
        syn_packet = segment(port, start_seq, 0, 0x02, 4096, options=syn_options)
        if compound:
            fragmented(syn_packet, 0x66779780 + case, chained)
        else:
            send(syn_packet)
        syn_ack = reply(port, 1.5, with_options=True)
        if syn_ack is None or syn_ack[2] & 0x12 != 0x12 or syn_ack[1] != start_seq + 1:
            raise RuntimeError(f"{label}: zero-window handshake failed: {syn_ack}")
        negotiated = parse_syn_options(syn_ack[5])
        server_scale = negotiated["ws"]
        if scaled and server_scale is None:
            raise RuntimeError(f"{label}: SYN with WS={ws_shift} not negotiated: {syn_ack}")
        if compound:
            if not negotiated["sack"] or negotiated["mss"] is None:
                raise RuntimeError(f"{label}: compound SYN lost MSS/SACK negotiation: {negotiated}")
            if negotiated["ts"] is not None:
                if negotiated["ts"][1] != compound_ts:
                    raise RuntimeError(f"{label}: SYN-ACK echoed wrong TSecr: {negotiated}")
                peer_ts = negotiated["ts"][0]
            else:
                # The server may decline Timestamp negotiation. An RFC
                # compliant client MUST NOT send TS in later segments
                # unless both SYN and SYN-ACK included the option.
                compound_ts = None
        client_seq = start_seq + 1
        server_seq = syn_ack[0] + 1
        # Advertise a zero receive window before the server has emitted data.
        # Measure persist-probe intervals against the same monotonic origin.
        zero_window_started = time.monotonic()
        send(segment(port, client_seq, server_seq, 0x10, 0))
        data = f"zero-window-echo-{case}".encode()
        fragmented(segment(port, client_seq, server_seq, 0x10, 0, data),
                   0x66779700 + 10 * case, chained)
        client_seq += len(data)
        observed_data_ack = False
        zero_probes = []
        probe_times = []
        premature_data = False
        deadline = time.monotonic() + 1.7
        while time.monotonic() < deadline:
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, window, body = r
            if flags & 0x04:
                raise RuntimeError(f"{label}: zero-window unexpected TCP RST")
            if ack == client_seq:
                observed_data_ack = True
            if body:
                zero_probes.append((seq, body))
                probe_times.append(time.monotonic() - zero_window_started)
                if seq == server_seq and body == data:
                    premature_data = True
                # Do not acknowledge a byte while receive window remains zero.
                send(segment(port, client_seq, server_seq, 0x10, 0))
        # Simulate a lost IPv6 fragment of the first nonzero-window update.
        # Only fragment zero reaches the TUN; the other fragment is never
        # transmitted. An incomplete reassembly MUST NOT reopen the window.
        probes_before_loss = len(zero_probes)
        fragmented(segment(port, client_seq, server_seq, 0x10, 4096),
                   0x66779701 + 10 * case, chained, drop_tail=True)
        premature_after_loss = False
        # Only the original unscaled/two-option baseline uses a long
        # persist interval; the new compound-SYN case stays bounded.
        blocked_after_loss = 12.0 if case == 1 else 3.2
        deadline = time.monotonic() + blocked_after_loss
        while time.monotonic() < deadline:
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, window, body = r
            if flags & 0x04:
                raise RuntimeError(f"{label}: partial window update caused reset")
            if body:
                zero_probes.append((seq, body))
                probe_times.append(time.monotonic() - zero_window_started)
                if len(body) > 1:
                    premature_after_loss = True
                send(segment(port, client_seq, server_seq, 0x10, 0))
        probe_retransmitted = len(zero_probes) > probes_before_loss
        probe_gaps = [round(b - a, 2) for a, b in zip(probe_times, probe_times[1:])]
        # The long-stall control records actual inter-probe intervals;
        # do not require two different TCP stacks to use the same timers.
        long_stall_probes = (
            len(probe_times) >= 3
            and probe_times[2] - probe_times[1] > 1.25 * (probe_times[1] - probe_times[0])
        ) if case == 1 else True
        # A raw receive window field of one permits only 2**WS bytes.
        # WS=0, WS=1 and WS=3 must release 1, 2 and 8 bytes respectively.
        small_window_bytes = b""
        small_window_ok = True
        if scaled:
            fragmented(segment(port, client_seq, server_seq, 0x10, 1),
                       0x66779705 + 10 * case, chained)
            deadline = time.monotonic() + 0.55
            while time.monotonic() < deadline:
                r = reply(port, max(0.001, deadline - time.monotonic()))
                if r is None:
                    break
                seq, ack, flags, window, body = r
                if flags & 0x04:
                    raise RuntimeError(f"{label}: WS=3 narrow window reset")
                if body:
                    if seq == server_seq + len(small_window_bytes):
                        small_window_bytes += body
                    elif not (seq == server_seq and body == small_window_bytes):
                        raise RuntimeError(f"{label}: WS=3 unexpected offset {seq-server_seq}")
                    if len(small_window_bytes) > (1 << ws_shift) or not data.startswith(small_window_bytes):
                        small_window_ok = False
            if len(small_window_bytes) != (1 << ws_shift):
                raise RuntimeError(
                    f"{label}: WS={ws_shift} expected {1<<ws_shift} bytes, "
                    f"received {small_window_bytes!r}"
                )
            # Acknowledge the prefix while closing the receive window again:
            # cumulative ACKs during the narrow-window check would slide it.
            send(segment(port, client_seq, server_seq + len(small_window_bytes),
                         0x10, 0))
        # A fresh fragment ID carries the *full* retransmitted update.
        fragmented(segment(port, client_seq, server_seq + len(small_window_bytes),
                           0x10, 4096),
                   0x66779704 + 10 * case, chained)
        chunks = {}
        echoed = small_window_bytes
        echo_retransmitted = False
        retransmit_after = None
        window_reopened_at = time.monotonic()
        # Deliberately lose the ACK for the first complete server response.
        # Wait for a TCP retransmission with the *same* sequence and bytes,
        # then acknowledge it. This must never duplicate application data.
        # A long persist state may carry a larger retransmission timeout
        # into the first post-window data. Observe that case separately.
        # Timestamp-negotiated gVisor can retain a longer RTO after the
        # previous persist probes; separately observe, do not call a
        # short bounded lack of duplicate a failed Echo.
        retransmit_horizon = 18.0 if case in (1, 4) else 4.5
        deadline = time.monotonic() + retransmit_horizon
        while time.monotonic() < deadline and (len(echoed) < len(data) or not echo_retransmitted):
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, window, body = r
            if flags & 0x04:
                raise RuntimeError(f"{label}: zero-window recovery reset")
            if body:
                if seq < server_seq:
                    continue  # a duplicate probe of an old sequence
                offset = seq - server_seq
                if (offset < len(echoed)
                        and offset + len(body) <= len(echoed)):
                    if data[offset:offset + len(body)] != body:
                        raise RuntimeError(f"{label}: corrupt retransmission {body!r}")
                    echo_retransmitted = True
                    retransmit_after = round(time.monotonic() - window_reopened_at, 2)
                    send(segment(port, client_seq, server_seq + len(echoed), 0x10, 4096))
                    continue
                if offset <= len(data):
                    chunks[offset] = body
                next_offset = len(echoed)
                while next_offset in chunks:
                    piece = chunks.pop(next_offset)
                    echoed += piece
                    next_offset = len(echoed)
                if len(echoed) > len(data) or not data.startswith(echoed):
                    raise RuntimeError(f"{label}: zero-window duplicate/corrupt echo {echoed!r}")
                # Withhold the cumulative ACK on first delivery.
        after = f"after-recovery-{case}".encode()
        fragmented(segment(port, client_seq, server_seq + len(echoed),
                           0x10, 4096, after),
                   0x66779702 + 10 * case, chained)
        client_seq += len(after)
        continued = b""
        deadline = time.monotonic() + 2
        expected_seq = server_seq + len(data)
        while time.monotonic() < deadline and len(continued) < len(after):
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, window, body = r
            if body and seq == expected_seq + len(continued):
                continued += body
                send(segment(port, client_seq, expected_seq + len(continued),
                             0x10, 4096))
        probe_offset = -1 if label == "Xray 26.9.9 TUN" else 0
        probe_shape_ok = (bool(zero_probes) and all(
            seq == server_seq + probe_offset and len(body) == 1
            for seq, body in zero_probes
        ))
        print(
            f"{label}: active TCP zero-window chained={chained} scaled={scaled} "
            f"ws-shift={ws_shift} compound={compound} synack-ws={server_scale} "
            f"synack-sack={negotiated['sack']} synack-ts={negotiated['ts'] is not None} "
            f"narrow-bytes={len(small_window_bytes)} "
            f"narrow-ok={small_window_ok} input-ack={observed_data_ack} probes={[(s-server_seq, len(d)) for s,d in zero_probes]} "
            f"premature-full-data={premature_data} "
            f"lost-update-no-data={not premature_after_loss} "
            f"probe-retry={probe_retransmitted} echo-retry={echo_retransmitted} "
            f"probe-at={[round(t, 2) for t in probe_times]} "
            f"probe-gaps={probe_gaps} long-stall-probes={long_stall_probes} "
            f"echo-retry-after={retransmit_after} "
            f"recovered={echoed == data} continued={continued == after}",
            flush=True,
        )
        if (not observed_data_ack or not probe_shape_ok or premature_data
                or premature_after_loss or not probe_retransmitted
                or not echo_retransmitted or not long_stall_probes
                or (scaled and (not small_window_bytes or not small_window_ok))
                or echoed != data or continued != after):
            raise RuntimeError(
                f"{label}: zero-window recovery mismatch chained={chained}: "
                f"input-ack={observed_data_ack} probe-shape={probe_shape_ok} "
                f"premature-full-data={premature_data} "
                f"partial-update-data={premature_after_loss} "
                f"probe-retry={probe_retransmitted} echo-retry={echo_retransmitted} "
                f"probe-at={probe_times!r} long-stall={long_stall_probes} "
                f"echo={echoed!r} continued={continued!r}"
            )
        fragmented(segment(port, client_seq, expected_seq + len(continued),
                           0x14, 4096),
                   0x66779703 + 10 * case, chained)
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_zero_window"], check=True)
    rx.close()
    tx.close()
PY
}

run_fragmented_ipv6_tcp_sack_gap_recovery_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while words >> 16:
        words = (words & 0xffff) + (words >> 16)
    return (~words) & 0xffff

def tcp_segment(port, seq, ack, flags, payload=b"", options=b"\x01"*4):
    assert len(options) % 4 == 0
    segment = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        ((5 + len(options) // 4) << 12) | flags, 4096, 0, 0,
    ) + options + payload)
    pseudo = source + target + struct.pack("!I3xB", len(segment), 6)
    segment[16:18] = struct.pack("!H", checksum(pseudo + segment))
    return bytes(segment)

def ipv6(nh, body):
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), nh, 64, source, target) + body

def send(segment):
    tx.sendto(ipv6(6, segment), (target_v6, 0, 0, 0))

def fragmented(tcp, ident, chained):
    options = bytes((60 if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        options += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    packet = options + tcp
    split = len(options) + 8
    def part(data, offset, more):
        frag = struct.pack("!BBHI", 60, 0, (offset // 8 << 3) | int(more), ident)
        return ipv6(44, frag + data)
    assert split < len(packet)
    tx.sendto(part(packet[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(part(packet[:split], 0, True), (target_v6, 0, 0, 0))

def sack_ranges(options):
    result = []
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            raise RuntimeError(f"{label}: truncated TCP SACK option")
        size = options[index + 1]
        if size < 2 or index + size > len(options):
            raise RuntimeError(f"{label}: malformed reply option size")
        if kind == 5:
            if size < 10 or (size - 2) % 8:
                raise RuntimeError(f"{label}: invalid SACK block length {size}")
            result.extend(struct.unpack("!II", options[at:at+8])
                          for at in range(index + 2, index + size, 8))
        index += size
    return result

def reply(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select((rx,), (), (), max(0.001, deadline - time.monotonic()))
        if not ready:
            return None
        message, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = message[40:] if message[0] >> 4 == 6 else message
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, bits, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if sport != 39643 or dport != port:
            continue
        pseudo = target + source + struct.pack("!I3xB", len(tcp), 6)
        if checksum(pseudo + tcp):
            raise RuntimeError(f"{label}: invalid TCP SACK reply checksum")
        header_len = (bits >> 12) * 4
        if not 20 <= header_len <= len(tcp):
            raise RuntimeError(f"{label}: invalid reply data offset")
        return seq, ack, bits & 0x3f, sack_ranges(tcp[20:header_len]), tcp[header_len:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_sack_gap"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_sack_gap", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_sack_gap", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    for case, (chained, allow_sack) in enumerate(
            ((False, True), (True, True), (False, False), (True, False))):
        port = 46020 + case
        client_isn = 0x52d00000 + case * 1000
        syn_options = (b"\x02\x04\x04\xb0\x04\x02\x01\x01"
                       if allow_sack else b"\x02\x04\x04\xb0")
        send(tcp_segment(port, client_isn, 0, 0x02, options=syn_options))
        syn_ack = reply(port, 1.5)
        if syn_ack is None or syn_ack[2] & 0x12 != 0x12 or syn_ack[1] != client_isn + 1:
            raise RuntimeError(f"{label}: SACK SYN-ACK missing case={case}: {syn_ack}")
        server_seq = syn_ack[0] + 1
        client_seq = client_isn + 1
        send(tcp_segment(port, client_seq, server_seq, 0x10))
        gap = b"lost-"
        tail = f"out-of-order-sack-{case}".encode()
        sack_bounds = (client_seq + len(gap), client_seq + len(gap) + len(tail))
        # The first client TCP data segment is lost in transit; the later
        # segment arrives before it, out of order. Check the receiver's
        # SACK response before retransmitting the missing first segment.
        fragmented(tcp_segment(port, sack_bounds[0], server_seq, 0x18, tail),
                   0x66779800 + case * 10, chained)
        observed_sack = False
        unnegotiated_sack = False
        premature_echo = False
        observed_dup_ack = False
        deadline = time.monotonic() + 0.65
        while time.monotonic() < deadline:
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, blocks, body = r
            if flags & 4:
                raise RuntimeError(f"{label}: SACK gap caused TCP reset")
            observed_dup_ack |= ack == client_seq and bool(flags & 0x10)
            observed_sack |= sack_bounds in blocks
            unnegotiated_sack |= bool(blocks) and not allow_sack
            premature_echo |= bool(body)
        # The exact missing bytes now arrive as their own fragmented
        # retransmission, completing the original TCP byte sequence.
        fragmented(tcp_segment(port, client_seq, server_seq, 0x18, gap),
                   0x66779801 + case * 10, chained)
        expected = gap + tail
        assembled = b""
        final_ack = False
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline and (len(assembled) < len(expected) or not final_ack):
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, blocks, body = r
            if flags & 4:
                raise RuntimeError(f"{label}: SACK gap recovery TCP reset")
            final_ack |= ack == client_seq + len(expected)
            if body:
                if seq == server_seq + len(assembled):
                    assembled += body
                elif seq < server_seq + len(assembled):
                    # A retransmission of already delivered bytes is not
                    # another application read.
                    offset = seq - server_seq
                    if offset < 0 or assembled[offset:offset+len(body)] != body:
                        raise RuntimeError(f"{label}: corrupt duplicate Echo")
                else:
                    raise RuntimeError(f"{label}: reordered Echo after TCP reassembly")
            if len(assembled) > len(expected) or not expected.startswith(assembled):
                raise RuntimeError(f"{label}: duplicate/corrupt Echo {assembled!r}")
        client_seq += len(expected)
        server_seq += len(expected)
        send(tcp_segment(port, client_seq, server_seq, 0x10))
        after = f"after-sack-{case}".encode()
        fragmented(tcp_segment(port, client_seq, server_seq, 0x18, after),
                   0x66779802 + case * 10, chained)
        following = b""
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and len(following) < len(after):
            r = reply(port, max(0.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, blocks, body = r
            if body and seq == server_seq + len(following):
                following += body
        print(
            f"{label}: TCP SACK gap chained={chained} enabled={allow_sack} "
            f"dupack={observed_dup_ack} sack-block={observed_sack} "
            f"unsolicited-sack={unnegotiated_sack} premature-echo={premature_echo} "
            f"full-ack={final_ack} recovered={assembled == expected} "
            f"continued={following == after}", flush=True
        )
        if (not observed_dup_ack or observed_sack != allow_sack
                or unnegotiated_sack or premature_echo
                or not final_ack or assembled != expected or following != after):
            raise RuntimeError(
                f"{label}: SACK gap failure chained={chained} enabled={allow_sack} "
                f"observed-sack={observed_sack} unexpected-sack={unnegotiated_sack}"
            )
        # Closing our synthetic flow must not contaminate the next case.
        client_seq += len(after)
        server_seq += len(after)
        fragmented(tcp_segment(port, client_seq, server_seq, 0x14),
                   0x66779803 + case * 10, chained)
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_sack_gap"], check=True)
    rx.close()
    tx.close()
PY
}

run_ipv6_tcp_sender_sack_retransmit_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
target = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = sum(struct.unpack(f"!{len(data)//2}H", data))
    while words >> 16:
        words = (words & 65535) + (words >> 16)
    return (~words) & 65535

def segment(port, seq, ack, flags, payload=b"", options=b"\x01"*4):
    assert len(options) % 4 == 0
    part = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        ((5 + len(options)//4) << 12) | flags, 8192, 0, 0,
    ) + options + payload)
    part[16:18] = struct.pack(
        "!H", checksum(source + target + struct.pack("!I3xB", len(part), 6) + part),
    )
    return bytes(part)

def send(port, seq, ack, flags, payload=b"", options=b"\x01"*4):
    tcp = segment(port, seq, ack, flags, payload, options)
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64, source, target)
    tx.sendto(ipv6 + tcp, (target_v6, 0, 0, 0))

def receive(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        readable, _, _ = select.select((rx,), (), (), max(0.001, deadline-time.monotonic()))
        if not readable:
            return None
        wire, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = wire[40:] if wire[0] >> 4 == 6 else wire
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, bits, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if sport != 39643 or dport != port:
            continue
        if checksum(target + source + struct.pack("!I3xB", len(tcp), 6) + tcp):
            raise RuntimeError(f"{label}: invalid outbound SACK TCP checksum")
        header_len = (bits >> 12) * 4
        if header_len < 20 or header_len > len(tcp):
            raise RuntimeError(f"{label}: invalid outbound SACK header")
        return seq, ack, bits & 0x3f, tcp[header_len:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_sender_sack"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_sender_sack", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_sender_sack", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    for case, (sack_enabled, multi_hole, scenario) in enumerate((
            (True, False, "baseline"), (False, False, "baseline"),
            (True, True, "baseline"), (False, True, "baseline"),
            (True, False, "reneging"), (True, False, "dsack"),
    )):
        port = 46110 + case
        client_isn = 0x52e00000 + case * 10000
        syn_opts = (b"\x02\x04\x02\x18\x04\x02\x01\x01"
                    if sack_enabled else b"\x02\x04\x02\x18")
        send(port, client_isn, 0, 0x02, options=syn_opts)
        synack = receive(port, 1.5)
        if synack is None or synack[2] & 0x12 != 0x12 or synack[1] != client_isn + 1:
            raise RuntimeError(f"{label}: sender SACK handshake failed: {synack}")
        client_seq = client_isn + 1
        base = synack[0] + 1
        send(port, client_seq, base, 0x10)
        if scenario == "dsack":
            # A genuine DSACK is sent *after observing two copies* of
            # exactly the same server data. Hold the first cumulative ACK
            # until the server retransmits; the first SACK block then lies
            # below the new cumulative ACK (RFC 2883).
            data = b"delayed-ack-dsack-" + bytes((case,))
            send(port, client_seq, base, 0x18, data)
            client_seq += len(data)
            seen_once = False
            seen_duplicate = False
            duplicate_at = None
            started = time.monotonic()
            deadline = started + 12.0
            while time.monotonic() < deadline and not seen_duplicate:
                r = receive(port, max(.001, deadline - time.monotonic()))
                if r is None:
                    break
                seq, ack, flags, body = r
                if flags & 4:
                    raise RuntimeError(f"{label}: DSACK flow reset")
                if body and seq == base and body == data:
                    if seen_once:
                        seen_duplicate = True
                        duplicate_at = round(time.monotonic() - started, 2)
                    seen_once = True
                elif body and base <= seq < base + len(data):
                    raise RuntimeError(f"{label}: DSACK unexpected split/bytes {seq-base} {body!r}")
            # Kind=5, length=10. Block [base,base+len(data)) falls
            # strictly below cumulative ACK and reports a real duplicate.
            dsack_opts = (b"\x01\x01\x05\x0a"
                          + struct.pack("!II", base, base + len(data)))
            if seen_duplicate:
                send(port, client_seq, base + len(data), 0x10, options=dsack_opts)
            after = b"after-genuine-dsack"
            send(port, client_seq, base + len(data), 0x18, after)
            client_seq += len(after)
            continued = b""
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and len(continued) < len(after):
                r = receive(port, max(.001, deadline - time.monotonic()))
                if r is None:
                    break
                seq, ack, flags, body = r
                if flags & 4:
                    raise RuntimeError(f"{label}: post-DSACK reset")
                if body and seq == base + len(data) + len(continued):
                    continued += body
                    send(port, client_seq, base + len(data) + len(continued), 0x10)
            print(
                f"{label}: TCP sender DSACK negotiated={sack_enabled} "
                f"seen-original={seen_once} genuine-duplicate={seen_duplicate} "
                f"duplicate-at={duplicate_at} post-dsack={continued == after}",
                flush=True,
            )
            if not seen_duplicate or continued != after:
                raise RuntimeError(f"{label}: TCP sender DSACK failed")
            continue
        # Use at least five actual outgoing segments in the double-hole
        # case: [ACKed, lost #1, SACKed #1, lost #2, SACKed #2].
        # Segment lengths differ between gVisor and smoltcp.
        data = bytes((i * 37 + 11) % 256
                     for i in range(3500 if multi_hole else 2100))
        for start in range(0, len(data), 1000):
            payload = data[start:start + 1000]
            send(port, client_seq + start, base, 0x18, payload)
        client_seq += len(data)

        packets = {}
        first_ack = None
        deadline = time.monotonic() + 2.3
        while time.monotonic() < deadline:
            result = receive(port, max(.001, deadline - time.monotonic()))
            if result is None:
                break
            seq, ack, flags, body = result
            if flags & 4:
                raise RuntimeError(f"{label}: sender SACK flow reset")
            if not body or seq < base or seq >= base + len(data):
                continue
            offset = seq - base
            if data[offset:offset+len(body)] != body:
                raise RuntimeError(f"{label}: sender produced corrupt Echo")
            packets[offset] = body
            if offset == 0 and first_ack is None:
                first_ack = len(body)
                send(port, client_seq, base + first_ack, 0x10)
            if first_ack is not None and len(packets) >= (5 if multi_hole else 3):
                break
        ordered = sorted(packets)
        if first_ack is None or len(ordered) < (5 if multi_hole else 3):
            raise RuntimeError(f"{label}: not enough outgoing TCP segments for SACK test: {ordered}")
        # Simulate a receiver that loses the segment immediately after its
        # first cumulatively ACKed piece, but gets a later segment in full.
        gap = first_ack
        if gap not in packets:
            raise RuntimeError(f"{label}: no missing segment at {gap}: {ordered}")
        later = next(((offset, body) for offset, body in sorted(packets.items())
                     if offset > gap), None)
        if later is None:
            raise RuntimeError(f"{label}: no packet beyond gap: {ordered}")
        sack_start, sack_payload = later
        sack_end = sack_start + len(sack_payload)
        gap2 = None
        second_sack = None
        if multi_hole:
            gap2 = ordered[3]
            later2 = ordered[4]
            second_sack = (later2, later2 + len(packets[later2]))
            if gap2 < sack_end or later2 <= gap2:
                raise RuntimeError(f"{label}: double SACK holes not disjoint: {ordered}")
            # We *saw* these packets on the raw socket, but model them
            # as lost by removing them from the synthetic receiver buffer.
            packets.pop(gap)
            packets.pop(gap2)
        # Option kind=5: two disjoint blocks require length 18,
        # plus two NOP bytes to align the TCP options header.
        if sack_enabled and multi_hole:
            opts = (b"\x01\x01\x05\x12"
                    + struct.pack("!IIII", base + sack_start, base + sack_end,
                                  base + second_sack[0], base + second_sack[1]))
        elif sack_enabled:
            opts = (b"\x01\x01\x05\x0a"
                    + struct.pack("!II", base + sack_start, base + sack_end))
        else:
            opts = b"\x01" * 4
        # Repeated *same* cumulative ACKs emulate feedback from receiving
        # several out-of-order packets, while only the observed later bytes
        # are reported SACKed. Never invent a SACK block for unseen data.
        for _ in range(4):
            send(port, client_seq, base + gap, 0x10, options=opts)
            time.sleep(.02)
        if scenario == "reneging":
            # The receiver is allowed to discard already SACKed bytes
            # under memory pressure. Drop this range from its synthetic
            # receive buffer *after actually reporting that SACK*, then
            # cease reporting it on later cumulative ACKs.
            packets.pop(sack_start)
        lost_retrans = False
        second_retrans = False
        retrans_order = []
        partial_ack_sent = False
        sacked_retrans = 0
        other_retrans = 0
        first_retx_at = None
        started = time.monotonic()
        deadline = started + 6.5
        while time.monotonic() < deadline and not lost_retrans:
            result = receive(port, max(.001, deadline - time.monotonic()))
            if result is None:
                break
            seq, ack, flags, body = result
            if flags & 4:
                raise RuntimeError(f"{label}: sender SACK retransmission reset")
            if not body or seq < base or seq >= base + len(data):
                continue
            offset = seq - base
            if data[offset:offset+len(body)] != body:
                raise RuntimeError(f"{label}: sender SACK retransmission changed bytes")
            if multi_hole and offset == gap2:
                second_retrans = True
                retrans_order.append(2)
                packets[gap2] = body
                continue
            if offset == gap:
                lost_retrans = True
                retrans_order.append(1)
                packets[gap] = body
                first_retx_at = round(time.monotonic() - started, 2)
                break
            if offset == sack_start:
                sacked_retrans += 1
                if scenario == "reneging":
                    packets[offset] = body
            else:
                other_retrans += 1
        # A partial cumulative ACK moves across lost #1 and the first
        # SACKed segment but stops at missing #2. The second SACK block
        # now reports only the later bytes beyond missing #2.
        if multi_hole and lost_retrans:
            prefix = 0
            while prefix in packets:
                prefix += len(packets[prefix])
            if prefix < gap2:
                raise RuntimeError(f"{label}: cannot partially ACK past gap #1: {prefix}, {gap2}")
            post_gap_opts = (
                b"\x01\x01\x05\x0a"
                + struct.pack("!II", base + second_sack[0], base + second_sack[1])
                if sack_enabled else b"\x01" * 4
            )
            for _ in range(4):
                send(port, client_seq, base + gap2, 0x10, options=post_gap_opts)
                time.sleep(.02)
            partial_ack_sent = True
            if not second_retrans:
                deadline2 = time.monotonic() + 7.0
                while time.monotonic() < deadline2:
                    result = receive(port, max(.001, deadline2 - time.monotonic()))
                    if result is None:
                        break
                    seq, ack, flags, body = result
                    if flags & 4:
                        raise RuntimeError(f"{label}: double-SACK partial ACK reset")
                    if not body or seq < base or seq >= base + len(data):
                        continue
                    offset = seq - base
                    if data[offset:offset + len(body)] != body:
                        raise RuntimeError(f"{label}: second hole corrupt retransmission")
                    if offset == gap2:
                        packets[offset] = body
                        retrans_order.append(2)
                        second_retrans = True
                        break
                    # Do not turn ordinary repeated segments into new data.
                    packets.setdefault(offset, body)
        # Only ACK actually observed contiguous bytes, never the two lost
        # originals merely because their original packets were sniffed.
        recovered = 0
        previous_ack = gap2 if multi_hole and partial_ack_sent else gap
        deadline = time.monotonic() + (16.0 if scenario == "reneging" else 4.0)
        while time.monotonic() < deadline:
            while recovered in packets:
                recovered += len(packets[recovered])
            if recovered != previous_ack:
                send(port, client_seq, base + recovered, 0x10)
                previous_ack = recovered
            if recovered == len(data):
                break
            result = receive(port, max(.001, deadline - time.monotonic()))
            if result is None:
                break
            seq, ack, flags, body = result
            if flags & 4:
                raise RuntimeError(f"{label}: sender SACK recovery reset")
            if body and base <= seq < base + len(data):
                offset = seq - base
                if data[offset:offset+len(body)] != body:
                    raise RuntimeError(f"{label}: sender SACK recovery corrupt Echo")
                packets[offset] = body
        full_ack = base + len(data)
        if recovered != len(data):
            raise RuntimeError(
                f"{label}: sender did not deliver all original bytes "
                f"recovered={recovered} expected={len(data)} packets={sorted(packets)}"
            )
        after = f"post-outbound-sack-{case}".encode()
        send(port, client_seq, full_ack, 0x18, after)
        client_seq += len(after)
        continued = b""
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and len(continued) < len(after):
            result = receive(port, max(.001, deadline - time.monotonic()))
            if result is None:
                break
            seq, ack, flags, body = result
            if flags & 4:
                raise RuntimeError(f"{label}: sender SACK continuation reset")
            if body and seq == full_ack + len(continued):
                continued += body
                send(port, client_seq, full_ack + len(continued), 0x10)
        print(
            f"{label}: TCP sender SACK enabled={sack_enabled} multi={multi_hole} "
            f"scenario={scenario} segments={ordered} hole={gap} hole2={gap2} "
            f"sacked=({sack_start},{sack_end}) sacked2={second_sack} "
            f"hole-retrans={lost_retrans} hole2-retrans={second_retrans} "
            f"partial-ack={partial_ack_sent} retx-order={retrans_order} "
            f"after={first_retx_at} "
            f"sacked-retrans-before-hole={sacked_retrans} other-before-hole={other_retrans} "
            f"reneged-range-recovered={sack_start in packets if scenario == 'reneging' else None} "
            f"all-bytes={recovered == len(data)} continued={continued == after}", flush=True,
        )
        if (not lost_retrans or continued != after
                or (multi_hole and (not second_retrans or not partial_ack_sent))):
            raise RuntimeError(
                f"{label}: SACK sender failed retransmission/continuation "
                f"multi={multi_hole} holes={(lost_retrans, second_retrans)} "
                f"partial-ack={partial_ack_sent}"
            )
        # Do not emit unfragmented local RST: the nft RST suppression
        # rule intentionally rejects it at OUTPUT (EPERM for raw send).
        # Every case has a distinct source port and is torn down with
        # its isolated network namespace.
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_sender_sack"], check=True)
    rx.close()
    tx.close()
PY
}

run_ipv6_tcp_timestamp_replay_probe() {
    local target_v6=$1
    local label=$2
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label = sys.argv[1:]
src = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
dst = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data)//2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def ts_option(tsval, tsecr):
    return b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr)

def packet(port, seq, ack, flags, payload=b"", options=b"\x01"*4,
           window=4096):
    assert len(options) % 4 == 0
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq, ack,
        ((5 + len(options)//4) << 12) | flags, window, 0, 0
    ) + options + payload)
    tcp[16:18] = struct.pack(
        "!H", checksum(src + dst + struct.pack("!I3xB", len(tcp), 6) + tcp)
    )
    return bytes(tcp)

def ipv6(next_header, body):
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), next_header, 64, src, dst) + body

def send(tcp, ident=None, chained=False):
    if ident is None:
        tx.sendto(ipv6(6, tcp), (target_v6, 0, 0, 0))
        return
    # Valid padding Destination Options after Fragment, with TCP header
    # bytes 0-7 alone in fragment zero. The rest, including Timestamp,
    # is delivered by the trailing fragment first.
    options = bytes((60 if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        options += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    body = options + tcp
    split = len(options) + 8
    def fragment(chunk, offset, more):
        frag = struct.pack("!BBHI", 60, 0, ((offset // 8) << 3) | int(more), ident)
        return ipv6(44, frag + chunk)
    tx.sendto(fragment(body[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(fragment(body[:split], 0, True), (target_v6, 0, 0, 0))

def parse_ts(options):
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            break
        size = options[index+1]
        if size < 2 or index + size > len(options):
            raise RuntimeError(f"{label}: invalid reply TCP Timestamp option")
        if kind == 8 and size == 10:
            return struct.unpack("!II", options[index+2:index+10])
        index += size
    return None

def receive(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        readable, _, _ = select.select((rx,), (), (), max(.001, deadline-time.monotonic()))
        if not readable:
            return None
        wire, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = wire[40:] if wire[0] >> 4 == 6 else wire
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, bits, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if (sport, dport) != (39643, port):
            continue
        if checksum(dst + src + struct.pack("!I3xB", len(tcp), 6) + tcp):
            raise RuntimeError(f"{label}: invalid Timestamp reply checksum")
        length = (bits >> 12) * 4
        if not 20 <= length <= len(tcp):
            raise RuntimeError(f"{label}: invalid Timestamp reply header")
        return seq, ack, bits & 0x3f, parse_ts(tcp[20:length]), tcp[length:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_timestamp"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_timestamp", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_timestamp", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    # Preserve the prior ordinary-TS controls and add two flows where
    # client TSval crosses the 32-bit wrap boundary on an established TCP
    # session. SYN-ACK Timestamp negotiation remains independently checked.
    for case, chained, wrapped in (
        (0, False, False), (1, True, False),
        (2, False, True), (3, True, True),
    ):
        port = 46130 + case
        isn = 0x52f00000 + case * 1000
        syn_ts = 0xfffffff0 if wrapped else 40000
        send(packet(port, isn, 0, 0x02, options=ts_option(syn_ts, 0)))
        synack = receive(port, 1.5)
        if synack is None or synack[2] & 0x12 != 0x12 or synack[1] != isn + 1:
            raise RuntimeError(f"{label}: Timestamp handshake failed {synack}")
        negotiated = synack[3] is not None
        # These two labels identify the exact pinned oracle and the
        # current Chimera/smoltcp baseline, not arbitrary TCP servers.
        oracle = label.startswith("Xray 26.9.9")
        if not negotiated:
            raise RuntimeError(
                f"{label}: Timestamp-capable Xray TUN did not negotiate SYN-ACK Timestamp"
            )
        if negotiated and synack[3][1] != syn_ts:
            raise RuntimeError(f"{label}: Timestamp SYN-ACK TSecr mismatch")
        peer_ts = synack[3][0] if negotiated else 0
        client_seq = isn + 1
        server_seq = synack[0] + 1
        def send_data(payload, tsval, ident=None):
            options = ts_option(tsval, peer_ts) if negotiated else b"\x01"*4
            send(packet(port, client_seq, server_seq, 0x18, payload, options),
                 ident=ident, chained=chained)
        def observe_echo(expected, seconds, allow_duplicate=False, expected_tsecr=None):
            deadline = time.monotonic() + seconds
            echo = b""
            duplicate = False
            while time.monotonic() < deadline:
                result = receive(port, max(.001, deadline-time.monotonic()))
                if result is None:
                    break
                seq, ack, flags, ts, body = result
                if flags & 0x04:
                    raise RuntimeError(f"{label}: Timestamp replay reset flow")
                if negotiated and ts is not None:
                    nonlocal_ts[0] = ts[0]
                if body:
                    if negotiated:
                        observed_tsecr.append(ts[1] if ts is not None else None)
                    if expected_tsecr is not None and (
                            ts is None or ts[1] != expected_tsecr):
                        raise RuntimeError(
                            f"{label}: wrong Timestamp Echo TSecr: "
                            f"wanted={expected_tsecr}, received={ts}"
                        )
                    if seq == server_seq + len(echo):
                        echo += body
                    elif seq < server_seq and allow_duplicate:
                        duplicate = True
                    else:
                        raise RuntimeError(f"{label}: unexpected Timestamp Echo seq={seq-server_seq}")
                    if not expected.startswith(echo):
                        raise RuntimeError(f"{label}: corrupted Timestamp Echo bytes")
                    if len(echo) == len(expected):
                        break
            return echo, duplicate
        # Keep actual current server TSval for TSecr; non-TS netstack
        # correctly declines Timestamp and receives plain TCP packets.
        nonlocal_ts = [peer_ts]
        observed_tsecr = []
        client_seq, server_seq = isn + 1, server_seq
        first = b"timestamp-baseline-"
        initial_data_ts = 0xfffffff8 if wrapped else 41000
        send_data(first, initial_data_ts)
        echo, _ = observe_echo(
            first, 1.5,
            expected_tsecr=initial_data_ts if negotiated else None,
        )
        if echo != first:
            raise RuntimeError(f"{label}: Timestamp baseline data failed")
        client_seq += len(first)
        server_seq += len(first)
        peer_ts = nonlocal_ts[0]
        send(packet(port, client_seq, server_seq, 0x10,
                    options=ts_option(initial_data_ts, peer_ts) if negotiated else b"\x01"*4))
        # Fresh TCP sequence, *older TSval than the established packet*.
        # This directly distinguishes stale Timestamp acceptance from PAWS
        # rejection (as opposed to an old-sequence duplicate).
        second = b"timestamp-wrapped-data-" if wrapped else b"timestamp-older-replay-"
        second_ts = 0x00000008 if wrapped else 40001
        send_data(second, second_ts, ident=0x6677a100 + case)
        old_echo, _ = observe_echo(
            second, .7,
            expected_tsecr=(second_ts if wrapped else initial_data_ts)
                           if negotiated else None,
        )
        old_ts_accepted = old_echo == second
        if oracle and not old_ts_accepted and not wrapped:
            raise RuntimeError(
                f"{label}: pinned Xray's observed established stale-TS "
                f"acceptance changed: {old_echo!r}"
            )
        if old_echo and not old_ts_accepted:
            raise RuntimeError(f"{label}: partial stale Timestamp Echo")
        if not old_ts_accepted:
            # Valid newer TSval, same *previously unacknowledged* sequence.
            send_data(second, 0x00000018 if wrapped else 42000,
                      ident=0x6677a110 + case)
            recovered, _ = observe_echo(second, 1.5)
            if recovered != second:
                raise RuntimeError(f"{label}: fresh Timestamp did not recover flow")
        client_seq += len(second)
        server_seq += len(second)
        peer_ts = nonlocal_ts[0]
        acknowledged_ts = (0x00000018 if wrapped and not old_ts_accepted else
                           second_ts if wrapped else 42000)
        send(packet(port, client_seq, server_seq, 0x10,
                    options=ts_option(acknowledged_ts, peer_ts) if negotiated else b"\x01"*4))
        # After the 32-bit wrap, test a previously TS-negotiated Xray
        # flow when a client packet unexpectedly omits TS entirely.
        # The peer may drop it or accept it; in either case a valid
        # subsequent TS-bearing retransmission must restore the stream.
        missing_ts_accepted = None
        if wrapped:
            missing = b"timestamp-missing-option-"
            send(packet(port, client_seq, server_seq, 0x18, missing),
                 ident=0x6677a140 + case, chained=chained)
            missing_echo, _ = observe_echo(
                missing, 0.7, expected_tsecr=second_ts if negotiated else None,
            )
            missing_ts_accepted = missing_echo == missing
            if oracle and not missing_ts_accepted:
                raise RuntimeError(
                    f"{label}: pinned Xray no-Timestamp data acceptance changed"
                )
            if missing_echo and not missing_ts_accepted:
                raise RuntimeError(f"{label}: partial missing-Timestamp Echo")
            if not missing_ts_accepted:
                send_data(missing, 0x00000028, ident=0x6677a150 + case)
                resumed, _ = observe_echo(missing, 1.5)
                if resumed != missing:
                    raise RuntimeError(f"{label}: Timestamp resumed stream stuck")
            client_seq += len(missing)
            server_seq += len(missing)
            peer_ts = nonlocal_ts[0]
            send(packet(port, client_seq, server_seq, 0x10,
                        options=ts_option(0x00000028, peer_ts) if negotiated else b"\x01"*4))
        # Replaying *old TCP sequence* must not duplicate application data,
        # regardless of Timestamp negotiation or the PAWS result above.
        replay_opts = ts_option(0x00000030 if wrapped else 43000, peer_ts) if negotiated else b"\x01"*4
        replay_seq = (client_seq - len(missing)) if wrapped else (client_seq - len(second))
        replay_payload = missing if wrapped else second
        replay = packet(port, replay_seq, server_seq, 0x18, replay_payload, replay_opts)
        send(replay, ident=0x6677a120 + case, chained=chained)
        replay_duplicate = False
        deadline = time.monotonic() + .35
        while time.monotonic() < deadline:
            result = receive(port, max(.001, deadline-time.monotonic()))
            if result is None:
                break
            seq, ack, flags, ts, body = result
            if flags & 0x04:
                raise RuntimeError(f"{label}: timestamp duplicate replay reset")
            if body:
                replay_duplicate = True
        final = b"timestamp-fresh-after-replay"
        send_data(final, 0x00000038 if wrapped else 44000, ident=0x6677a130 + case)
        continued, _ = observe_echo(
            final, 1.5,
            expected_tsecr=(0x38 if wrapped else 44000) if negotiated else None,
        )
        gap_recovery = None
        if case == 0 and continued == final:
            # An out-of-order segment may be buffered before its missing
            # prefix. The next contiguous data must use the cumulative ACK
            # *after* both segments, not the end of the prefix alone.
            client_seq += len(final)
            server_seq += len(final)
            peer_ts = nonlocal_ts[0]
            send(packet(port, client_seq, server_seq, 0x10,
                        options=ts_option(44000, peer_ts)))
            gap_head = b"ts-gap-head-"
            gap_tail = b"ts-gap-tail-"
            send(packet(port, client_seq + len(gap_head), server_seq,
                        0x18, gap_tail, ts_option(50000, peer_ts)),
                 ident=0x6677a200 + case, chained=chained)
            # Drain a possible duplicate ACK/SACK for the missing prefix.
            deadline = time.monotonic() + .08
            while time.monotonic() < deadline:
                r = receive(port, max(.001, deadline-time.monotonic()))
                if r is None:
                    break
                if r[4]:
                    raise RuntimeError(f"{label}: out-of-order tail delivered before gap")
            send(packet(port, client_seq, server_seq, 0x18,
                        gap_head, ts_option(45000, peer_ts)),
                 ident=0x6677a210 + case, chained=chained)
            recovered, _ = observe_echo(gap_head + gap_tail, 1.5,
                                         expected_tsecr=45000)
            if recovered != gap_head + gap_tail:
                raise RuntimeError(f"{label}: timestamp gap reassembly failed")
            client_seq += len(recovered)
            server_seq += len(recovered)
            peer_ts = nonlocal_ts[0]
            send(packet(port, client_seq, server_seq, 0x10,
                        options=ts_option(45000, peer_ts)))
            post_gap = b"ts-gap-after-"
            send(packet(port, client_seq, server_seq, 0x18,
                        post_gap, ts_option(46000, peer_ts)),
                 ident=0x6677a220 + case, chained=chained)
            gap_echo, _ = observe_echo(post_gap, 1.5, expected_tsecr=46000)
            gap_recovery = gap_echo == post_gap
            if not gap_recovery:
                raise RuntimeError(f"{label}: post-gap TSecr/echo failed")
            client_seq += len(post_gap)
            server_seq += len(post_gap)
            peer_ts = nonlocal_ts[0]
            abnormal_ts = []
            # Compare actual receiver/ACK-window behavior, separately from
            # the metadata helper. Non-acceptable sequence and impossible
            # ACK must not corrupt application data; the TSecr result is
            # diagnostic until the reference and local values are known.
            for name, seq_delta, ack_delta, bad_ts in (
                ("far-seq", 0x200000, 0, 61000),
                ("future-ack", 0, 0x200000, 62000),
            ):
                send(packet(port, (client_seq + seq_delta) & 0xffffffff,
                            (server_seq + ack_delta) & 0xffffffff, 0x10,
                            options=ts_option(bad_ts, peer_ts)))
                # Consume challenge/duplicate ACKs before the fresh data.
                deadline = time.monotonic() + .08
                while time.monotonic() < deadline:
                    r = receive(port, max(.001, deadline - time.monotonic()))
                    if r is None:
                        break
                    if r[2] & 4 or r[4]:
                        raise RuntimeError(f"{label}: abnormal {name} reset/delivered data")
                payload = ("ts-" + name + "-").encode()
                good_ts = 46010 if name == "far-seq" else 46020
                send(packet(port, client_seq, server_seq, 0x18,
                            payload, ts_option(good_ts, peer_ts)))
                echoed, _ = observe_echo(payload, 1.5)
                if echoed != payload:
                    raise RuntimeError(f"{label}: post-{name} fresh data failed")
                abnormal_ts.append((name, observed_tsecr[-1]))
                client_seq += len(payload)
                server_seq += len(payload)
                peer_ts = nonlocal_ts[0]
                send(packet(port, client_seq, server_seq, 0x10,
                            options=ts_option(good_ts, peer_ts)))
            # This is the peer-advertised receive window (for outbound
            # Echo), not proof of smoltcp's inbound receive window at 0.
            send(packet(port, client_seq, server_seq, 0x10,
                        options=ts_option(46030, peer_ts), window=0))
            time.sleep(.03)
            send(packet(port, client_seq, server_seq, 0x10,
                        options=ts_option(46031, peer_ts), window=4096))
            after_window = b"ts-after-window-"
            send(packet(port, client_seq, server_seq, 0x18,
                        after_window, ts_option(46040, peer_ts)))
            window_echo, _ = observe_echo(after_window, 1.5)
            if window_echo != after_window:
                raise RuntimeError(f"{label}: post-window fresh data failed")
            abnormal_ts.append(("zero-window-advertisement", observed_tsecr[-1]))
            expected_abnormal = [
                ("far-seq", 46010),
                ("future-ack", 62000),
                ("zero-window-advertisement", 62000),
            ]
            if abnormal_ts != expected_abnormal:
                raise RuntimeError(
                    f"{label}: TCP Timestamp abnormal-ACK TSecr drift: "
                    f"got={abnormal_ts}, pinned-xray={expected_abnormal}"
                )
        else:
            abnormal_ts = None
        print(
            f"{label}: TCP Timestamp PAWS chained={chained} wrapped={wrapped} "
            f"negotiated={negotiated} missing-ts-accepted={missing_ts_accepted} "
            f"older-ts-accepted={old_ts_accepted if negotiated else None} "
            f"plain-fallback-accepted={old_ts_accepted if not negotiated else None} "
            f"echo-tsecr={observed_tsecr} "
            f"old-seq-replay-echo={replay_duplicate} "
            f"fresh-after-replay={continued == final} "
            f"out-of-order-ack-frontier={gap_recovery} "
            f"abnormal-ack-tsecr={abnormal_ts}", flush=True
        )
        if replay_duplicate or continued != final:
            raise RuntimeError(f"{label}: Timestamp stale/replay data integrity failed")
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_timestamp"], check=True)
    rx.close()
    tx.close()
PY
}

run_ipv6_tcp_bulk_downlink_probe() {
    local target_v6=$1
    local label=$2
    # Regress the previous single-send 8 KiB server-to-client sequence hole
    # on actual Linux TCP, with no qdisc loss or modified default smoke.
    XRAY_TUN_SEEDED_NETEM_LOSS_PCT=0 \
    XRAY_TUN_SEEDED_FLOW_COUNT=1 \
    XRAY_TUN_SEEDED_PAYLOAD_BYTES=8192 \
    XRAY_TUN_SEEDED_CHUNK_BYTES=8192 \
        run_ipv6_tcp_seeded_netem_probe "$target_v6" "$label"
    printf '%s: TCP bulk-downlink 8192-byte single-send no-loss passed\n' "$label"
}

run_ipv6_tcp_seeded_netem_probe() {
    local target_v6=$1
    local label=$2
    # Apply qdisc in the disposable office client namespace only. No
    # host/default namespace routes or qdiscs are modified. Each reference
    # implementation gets a fresh qdisc with exactly the same RNG seed.
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" <<'PY'
import concurrent.futures
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys

target_v6, label = sys.argv[1:]
device = "office-client"
seed = 31991
loss_pct = int(os.environ.get('XRAY_TUN_SEEDED_NETEM_LOSS_PCT', '3'))
if loss_pct not in (0, 1, 3):
    raise RuntimeError('Diagnostic netem loss percent must be 0, 1 or 3')
flow_count = int(os.environ.get('XRAY_TUN_SEEDED_FLOW_COUNT', '4'))
payload_size = int(os.environ.get('XRAY_TUN_SEEDED_PAYLOAD_BYTES', str(128 * 1024)))
chunk_size = int(os.environ.get('XRAY_TUN_SEEDED_CHUNK_BYTES', '1024'))
if flow_count not in (1, 4) or payload_size not in (128, 8192, 128 * 1024) \
        or chunk_size not in (128, 1024, 8192) or payload_size % 32:
    raise RuntimeError('Invalid bounded seeded TCP diagnostic dimensions')

def tc(*args):
    return subprocess.run(["tc", *args], check=True,
                          text=True, capture_output=True).stdout

def qdisc():
    return json.loads(tc("-s", "-j", "qdisc", "show", "dev", device))

def echo_worker(index):
    # Fixed contents per flow; TCP handles retransmission for *actual*
    # kernel-qdisc packet loss, unlike the raw withheld-input probes.
    pattern = hashlib.sha256(f"seeded-netem-{index}".encode()).digest()
    payload = pattern * (payload_size // len(pattern))
    expected_digest = hashlib.sha256(payload).digest()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
        client.settimeout(8 if loss_pct == 0 else 45)
        client.connect((target_v6, 39643, 0, 0))
        hasher = hashlib.sha256()
        received = 0
        # Request/echo in bounded chunks, preventing a full duplex send
        # buffer from filling while this client has not yet read echo
        # bytes. This measures real kernel retransmission, not an
        # application-side sendall/receive deadlock.
        for offset in range(0, len(payload), chunk_size):
            block = payload[offset:offset + chunk_size]
            client.sendall(block)
            block_left = len(block)
            while block_left:
                try:
                    chunk = client.recv(min(8192, block_left))
                except TimeoutError:
                    info = client.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                    unacked = struct.unpack_from('=I', info, 24)[0]
                    rto_usec = struct.unpack_from('=I', info, 8)[0]
                    retr = struct.unpack_from('=I', info, 100)[0]
                    print(f"{label}: seeded-netem recv TIMEOUT flow={index} "
                          f"offset={offset} received={received} missing={block_left} "
                          f"tcp-unacked={unacked} tcp-rto-usec={rto_usec} "
                          f"tcp-total-retrans={retr}", flush=True)
                    raise
                if not chunk:
                    raise RuntimeError(f"{label}: seeded netem early EOF "
                                       f"flow={index} recv={received}")
                block_left -= len(chunk)
                received += len(chunk)
                hasher.update(chunk)
        tcp_info = client.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        if len(tcp_info) < 104:
            raise RuntimeError(f"{label}: TCP_INFO truncated")
        # Linux include/uapi/linux/tcp.h: tcpi_total_retrans at offset 100.
        retransmissions = struct.unpack_from("=I", tcp_info, 100)[0]
    print(f"{label}: seeded-netem completed flow={index} "
          f"bytes={received} tcp-total-retrans={retransmissions}", flush=True)
    if received != payload_size or hasher.digest() != expected_digest:
        raise RuntimeError(f"{label}: seeded netem data mismatch flow={index}")
    return retransmissions

before = qdisc()
if any(entry.get("kind") == "netem" for entry in before):
    raise RuntimeError(f"{label}: unexpected pre-existing netem on {device}")
installed = False
try:
    if loss_pct:
        tc("qdisc", "add", "dev", device, "root", "netem",
           "loss", "random", f"{loss_pct}%", "seed", str(seed))
        installed = True
        actual = qdisc()
        rule = next((entry for entry in actual if entry.get("kind") == "netem"), None)
        if rule is None or rule.get("options", {}).get("seed") != seed:
            raise RuntimeError(f"{label}: seeded netem qdisc was not installed: {actual}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=flow_count) as pool:
        retrans = list(pool.map(echo_worker, range(flow_count)))
    during = qdisc()
    drops = sum(int(entry.get("drops", 0)) for entry in during
                if entry.get("kind") == "netem")
    if loss_pct > 0 and (drops < 1 or sum(retrans) < 1):
        raise RuntimeError(f"{label}: loss was not exercised by kernel TCP: "
                           f"qdisc-drops={drops}, tcp-info-total-retrans={retrans}")
    print(f"{label}: seeded-netem loss={loss_pct}% seed={seed} "
          f"flows={flow_count} bytes-per-flow={payload_size} "
          f"qdisc-drops={drops} tcp-retrans={retrans} "
          f"sha256-integrity=True", flush=True)
finally:
    if installed:
        last = qdisc()
        print(f"{label}: seeded-netem qdisc-before-delete="
              f"{[(v.get('packets'), v.get('drops')) for v in last if v.get('kind') == 'netem']}",
              flush=True)
        tc("qdisc", "del", "dev", device, "root")
    if any(entry.get("kind") == "netem" for entry in qdisc()):
        raise RuntimeError(f"{label}: netem qdisc leaked after test")

# A post-loss transfer proves that the link was restored before other
# TCP/Timestamp, UDP, QUIC and teardown cases run.
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect((target_v6, 39643, 0, 0))
    client.sendall(b"seeded-netem-restored")
    data = b""
    while len(data) < len(b"seeded-netem-restored"):
        piece = client.recv(64)
        if not piece:
            break
        data += piece
    if data != b"seeded-netem-restored":
        raise RuntimeError(f"{label}: post-netem link recovery failed")
print(f"{label}: seeded-netem qdisc-removed=True post-loss-echo=True", flush=True)
PY
}

run_ipv6_tcp_multi_server_receive_window_probe() {
    local target_v6=$1
    local label=$2
    local barrier_dir
    barrier_dir=$(mktemp -d)
    rm -f "$stalled_tcp_release_file"
    local first_pid second_pid result=0
    run_ipv6_tcp_true_server_receive_window_probe "$target_v6" "$label slot=0" \
        0 2 "$barrier_dir" >"$barrier_dir/slot-0.log" 2>&1 &
    first_pid=$!
    run_ipv6_tcp_true_server_receive_window_probe "$target_v6" "$label slot=1" \
        1 2 "$barrier_dir" >"$barrier_dir/slot-1.log" 2>&1 &
    second_pid=$!
    if ! wait "$first_pid"; then
        result=1
    fi
    if ! wait "$second_pid"; then
        result=1
    fi
    cat "$barrier_dir/slot-0.log" "$barrier_dir/slot-1.log"
    if [[ "$result" == 0 ]]; then
        for slot in 0 1; do
            if ! grep -Fq 'server RX-window multistall barrier=2 simultaneous-zero=True' \
                "$barrier_dir/slot-$slot.log" \
                || ! grep -Fq 'loss-burst=4 concurrent-echo=4+4 post-gap-tsecr=50010 post-gap-fresh-tsecr=50020' \
                "$barrier_dir/slot-$slot.log"; then
                result=1
            fi
        done
    fi
    rm -rf -- "$barrier_dir"
    if [[ "$result" != 0 ]]; then
        printf '%s multi-stalled TCP receive-window oracle failed.\n' "$label" >&2
        return 1
    fi
    printf '%s: server RX-window multistall cohort=2 both-recovered=True\n' "$label"
}

run_ipv6_tcp_true_server_receive_window_probe() {
    local target_v6=$1
    local label=$2
    local slot=${3:-0}
    local participants=${4:-1}
    local barrier_dir=${5:-unused}
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" "$stalled_tcp_release_file" "$echo_log_file" \
        "$slot" "$participants" "$barrier_dir" <<'PY'
import pathlib
import select
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

target_v6, label, release_path, echo_log_path, slot_arg, count_arg, barrier_arg = sys.argv[1:]
slot, participants = int(slot_arg), int(count_arg)
if not (0 <= slot < participants <= 2):
    raise RuntimeError(f"{label}: invalid receive-pressure cohort {slot}/{participants}")
release = pathlib.Path(release_path)
barrier = pathlib.Path(barrier_arg)
if participants == 1:
    release.unlink(missing_ok=True)
src = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
dst = socket.inet_pton(socket.AF_INET6, target_v6)
client_port = 46230 + slot
target_port = 39648
initial_seq = 0x52700000 + slot * 0x100000
nft_table = f"chimera_rxpressure_{client_port}"

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = sum(struct.unpack(f"!{len(data)//2}H", data))
    while words >> 16:
        words = (words & 65535) + (words >> 16)
    return (~words) & 65535

def tsopt(tsval, tsecr=0):
    return b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr)

def packet(seq, ack, flags, payload=b"", options=b"\x01"*4):
    header = bytearray(struct.pack("!HHIIHHHH", client_port, target_port,
        seq, ack, ((5 + len(options)//4) << 12) | flags, 4096, 0, 0)
        + options + payload)
    header[16:18] = struct.pack("!H", checksum(src + dst +
        struct.pack("!I3xB", len(header), 6) + header))
    return struct.pack("!IHBB16s16s", 6 << 28, len(header), 6, 64, src, dst) + header

def verify_unrelated_echoes(phase):
    # A blocked TCP/39648 receive stream must not prevent new,
    # independent TCP/39643 streams from completing normal forwarding.
    # Each worker uses the kernel TCP stack and a distinct ephemeral tuple;
    # the raw pressure connection continues to own TCP/46230 separately.
    def echo_worker(index):
        payload = (f"parallel-rx-{phase}-{index}-".encode() * 8)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect((target_v6, 39643, 0, 0))
            connection.sendall(payload)
            echo = bytearray()
            while len(echo) < len(payload):
                chunk = connection.recv(len(payload) - len(echo))
                if not chunk:
                    raise RuntimeError(f"{label}: independent echo EOF at {phase}/{index}")
                echo.extend(chunk)
        if echo != payload:
            raise RuntimeError(f"{label}: independent echo mismatch at {phase}/{index}")
        return index

    with ThreadPoolExecutor(max_workers=4) as pool:
        completed = sorted(pool.map(echo_worker, range(4)))
    if completed != [0, 1, 2, 3]:
        raise RuntimeError(f"{label}: independent echo completion mismatch {completed}")
    print(f"{label}: server RX-window concurrent-echo phase={phase} "
          f"flows={len(completed)} integrity=True", flush=True)

def options_fields(options):
    scale = None
    ts = None
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 2 > len(options):
            break
        n = options[i+1]
        if n < 2 or i + n > len(options):
            break
        if kind == 3 and n == 3:
            scale = options[i+2]
        if kind == 8 and n == 10:
            ts = struct.unpack("!II", options[i+2:i+10])
        i += n
    return scale, ts

def receive(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        r, _, _ = select.select([rx], [], [], max(.001, deadline-time.monotonic()))
        if not r:
            return None
        raw, addr = rx.recvfrom(8192)
        if addr[0] != target_v6:
            continue
        tcp = raw[40:] if raw[0] >> 4 == 6 else raw
        if len(tcp) < 20:
            continue
        sp, dp, seq, ack, control, window, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if (sp, dp) != (target_port, client_port):
            continue
        if checksum(dst + src + struct.pack("!I3xB", len(tcp), 6) + tcp):
            raise RuntimeError(f"{label}: server-window reply checksum invalid")
        hdrlen = (control >> 12) * 4
        if not 20 <= hdrlen <= len(tcp):
            raise RuntimeError(f"{label}: invalid TCP reply options size")
        scale, ts = options_fields(tcp[20:hdrlen])
        return seq, ack, control & 0x3f, window, scale, ts, tcp[hdrlen:]
    return None

tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
subprocess.run(["nft", "add", "table", "inet", nft_table], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", nft_table, "output",
        "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", nft_table, "output",
        "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
        "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    # WS=3 on the client enables Xray/gVisor's (larger) advertised
    # server window scale. The SYN's own window field is not scaled.
    synopts = b"\x03\x03\x03\x01" + tsopt(40000)
    tx.sendto(packet(initial_seq, 0, 0x02, options=synopts), (target_v6, 0, 0, 0))
    synack = receive(2)
    if synack is None or synack[2] & 0x12 != 0x12 or synack[1] != initial_seq + 1:
        raise RuntimeError(f"{label}: server RX-window SYN-ACK missing: {synack}")
    if synack[5] is None or synack[5][1] != 40000:
        raise RuntimeError(f"{label}: server RX-window Timestamp not negotiated")
    shift = synack[4] or 0
    server_seq = synack[0] + 1
    peer_ts = synack[5][0]
    client_seq = initial_seq + 1
    tx.sendto(packet(client_seq, server_seq, 0x10,
        options=tsopt(40000, peer_ts)), (target_v6, 0, 0, 0))
    advertised = synack[3]
    total = 0
    segment_num = 0
    zero = False
    limit = 20 * 1024 * 1024
    start = time.monotonic()
    while total < limit and time.monotonic() - start < 100:
        available = min(advertised, limit - total, 16 * 1024)
        if available == 0:
            zero = True
            break
        sent = 0
        while sent < available:
            n = min(1024, available - sent)
            ts = 41000 + (segment_num // 128)
            tx.sendto(packet(client_seq, server_seq, 0x18,
                b"A" * n, tsopt(ts, peer_ts)), (target_v6, 0, 0, 0))
            client_seq += n
            sent += n
            segment_num += 1
        deadline = time.monotonic() + 3
        last_ack = None
        while time.monotonic() < deadline:
            reply = receive(max(.001, deadline - time.monotonic()))
            if reply is None:
                break
            if reply[2] & 0x04:
                raise RuntimeError(f"{label}: server RX-window connection RST")
            last_ack = reply
            if reply[1] == client_seq:
                if reply[5] is not None:
                    peer_ts = reply[5][0]
                advertised = reply[3] << shift
                break
        if last_ack is None or last_ack[1] != client_seq:
            raise RuntimeError(f"{label}: RX-pressure ACK stalled at {total} bytes; "
                f"wanted SEQ={client_seq}, last={last_ack}")
        total += sent
        if advertised == 0:
            # The proxy may still be delivering previously buffered data
            # into the target kernel send buffer *before* it fills. Do not
            # mistake a transient zero window during dial/write ramp-up
            # for a persistently stalled receiver. Give asynchronous
            # window updates a short chance to surface; continue filling
            # if the peer has actually reopened its advertised window.
            tx.sendto(packet(client_seq, server_seq, 0x10,
                options=tsopt(40000, peer_ts)), (target_v6, 0, 0, 0))
            quiet_deadline = time.monotonic() + .25
            while time.monotonic() < quiet_deadline:
                reply = receive(max(.001, quiet_deadline-time.monotonic()))
                if reply is None:
                    break
                if reply[1] == client_seq and reply[3] > 0:
                    advertised = reply[3] << shift
                    if reply[5] is not None:
                        peer_ts = reply[5][0]
            if advertised == 0:
                zero = True
                break
            print(f"{label}: server RX-window reopened during pressure "
                  f"accepted={total} window={advertised}; refilling", flush=True)
            continue
        if segment_num % 1024 < 16:
            print(f"{label}: server RX-window progress={total} "
                  f"advertised={advertised} shift={shift}", flush=True)
    if not zero:
        raise RuntimeError(f"{label}: bounded stalled-target pressure did NOT "
            f"observe zero server receive window, accepted={total}, "
            f"last-window={advertised}, segments={segment_num}")
    print(f"{label}: server RX-window CLOSED accepted={total} shift={shift}", flush=True)
    # These are data-bearing *unacceptable* segments at a stable server
    # zero window, not client-advertised zero-window controls. The duplicate
    # probe, future out-of-order byte and overlap of the previously ACKed
    # byte must not move the cumulative ACK or poison recent Timestamp.
    rejected_probes = (
        ("initial", client_seq, b"X", 75000),
        ("duplicate", client_seq, b"X", 76000),
        ("future", client_seq + 8, b"Q", 77000),
        ("overlap", client_seq - 1, b"R", 78000),
    )
    for name, seq, payload, tsval in rejected_probes:
        tx.sendto(packet(seq, server_seq, 0x18, payload,
            tsopt(tsval, peer_ts)), (target_v6, 0, 0, 0))
        deadline = time.monotonic() + .1
        while time.monotonic() < deadline:
            reply = receive(max(.001, deadline-time.monotonic()))
            if reply is None:
                break
            if reply[2] & 0x04:
                raise RuntimeError(f"{label}: {name} zero-window probe reset flow")
            if reply[1] != client_seq:
                raise RuntimeError(f"{label}: {name} zero-window probe "
                    f"changed cumulative ACK to {reply[1]} from {client_seq}")
    print(f"{label}: server RX-window rejected-zero-segments="
          f"{','.join(name for name, _, _, _ in rejected_probes)}", flush=True)
    # Keep the pressured stream stalled while testing that other,
    # independent destination flows can complete without data corruption.
    verify_unrelated_echoes("stalled")
    if participants == 1:
        release.touch()
    else:
        # All participants must *independently* reach a stable real zero
        # window before either stalled downstream TCP reader is released.
        # File creation is atomic enough here: only existence is checked.
        (barrier / f"zero-{slot}").touch()
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if all((barrier / f"zero-{i}").exists() for i in range(participants)):
                break
            time.sleep(.025)
        else:
            raise RuntimeError(f"{label}: simultaneous zero-window barrier "
                f"timed out, reached={list(barrier.glob('zero-*'))}")
        if slot == 0:
            release.touch()
        deadline = time.monotonic() + 5
        while not release.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        if not release.exists():
            raise RuntimeError(f"{label}: shared downstream release was not observed")
        print(f"{label}: server RX-window multistall barrier="
              f"{participants} simultaneous-zero=True", flush=True)
    reopened = None
    after_release_replies = []
    deadline = time.monotonic() + 25
    next_window_probe = time.monotonic() + 2
    while time.monotonic() < deadline:
        if time.monotonic() >= next_window_probe:
            # A stale-TS pure ACK is a legal zero-length keepalive/window
            # diagnostic, unlike sending new data before the window reopens.
            tx.sendto(packet(client_seq, server_seq, 0x10,
                options=tsopt(40000, peer_ts)), (target_v6, 0, 0, 0))
            next_window_probe = time.monotonic() + 2
        reply = receive(min(.3, max(.001, deadline-time.monotonic())))
        if reply is None:
            continue
        after_release_replies.append((reply[1], reply[2], reply[3], reply[5]))
        if reply[2] & 0x04:
            raise RuntimeError(f"{label}: server RX-window reopened with RST: "
                f"{after_release_replies[-8:]}")
        if reply[1] == client_seq and reply[3] > 0:
            reopened = reply[3] << shift
            if reply[5] is not None:
                peer_ts = reply[5][0]
            break
    if reopened is None:
        target_log = pathlib.Path(echo_log_path).read_text(errors="replace")
        diagnostic = [line for line in target_log.splitlines()
                      if 'RX PRESSURE TARGET' in line]
        raise RuntimeError(f"{label}: no server zero-window reopen ACK; "
            f"replies={after_release_replies[-12:]} target={diagnostic[-8:]}")
    tx.sendto(packet(client_seq, server_seq, 0x18,
        b"Y", tsopt(50000, peer_ts)), (target_v6, 0, 0, 0))
    final = None
    recent_replies = []
    deadline = time.monotonic() + 10
    next_retransmit = time.monotonic() + 2
    while time.monotonic() < deadline:
        if time.monotonic() >= next_retransmit:
            tx.sendto(packet(client_seq, server_seq, 0x18,
                b"Y", tsopt(50000, peer_ts)), (target_v6, 0, 0, 0))
            next_retransmit = time.monotonic() + 2
        reply = receive(min(.3, max(.001, deadline-time.monotonic())))
        if reply is None:
            continue
        recent_replies.append((reply[1], reply[2], reply[3], reply[5]))
        if reply[1] == client_seq + 1:
            final = reply
            break
        if reply[2] & 0x04:
            raise RuntimeError(f"{label}: server RX-window RST while recovering: "
                f"{recent_replies[-6:]}")
    if final is None:
        raise RuntimeError(f"{label}: resumed receive-window did not ACK retransmit; "
            f"reopen={reopened} replies={recent_replies[-12:]}")
    echo = final[5][1] if final[5] is not None else None
    if echo != 50000:
        raise RuntimeError(f"{label}: zero-window rejected TS=75000..78000 "
            f"poisoned recovered TSecr={echo}")
    verify_unrelated_echoes("reopened")
    # Simulate a short burst of four lost TCP segments by delivering
    # their later retransmissions in reverse order. The final missing
    # 4-byte prefix is sent last: no previous suffix may advance the
    # cumulative ACK or poison the Timestamp echoed after repair.
    post_seq = client_seq + 1
    chunks = (b"gap0", b"gap1", b"gap2", b"gap3", b"tail")
    for index in (4, 2, 3, 1):
        tx.sendto(packet(post_seq + 4 * index, server_seq, 0x18,
            chunks[index], tsopt(85000 + index, peer_ts)),
            (target_v6, 0, 0, 0))
        gap_deadline = time.monotonic() + .06
        while time.monotonic() < gap_deadline:
            reply = receive(max(.001, gap_deadline-time.monotonic()))
            if reply is None:
                break
            if reply[2] & 0x04:
                raise RuntimeError(f"{label}: loss-burst suffix reset TCP")
            if reply[1] > post_seq:
                raise RuntimeError(f"{label}: loss-burst suffix was ACKed "
                    f"without prefix: {reply[1]} > {post_seq}")
    tx.sendto(packet(post_seq, server_seq, 0x18,
        chunks[0], tsopt(50010, peer_ts)), (target_v6, 0, 0, 0))
    merged_ack = post_seq + sum(map(len, chunks))
    merged = None
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        reply = receive(min(.3, max(.001, deadline-time.monotonic())))
        if reply is None:
            continue
        if reply[2] & 0x04:
            raise RuntimeError(f"{label}: gap repair reset TCP")
        if reply[1] == merged_ack:
            merged = reply
            break
    if merged is None:
        raise RuntimeError(f"{label}: post-window cumulative gap ACK "
            f"did not reach {merged_ack}")
    merged_tsecr = merged[5][1] if merged[5] is not None else None
    if merged_tsecr != 50010:
        raise RuntimeError(f"{label}: out-of-order TS=85000 "
            f"poisoned gap-repair TSecr={merged_tsecr}")
    if merged[5] is not None:
        peer_ts = merged[5][0]
    tx.sendto(packet(merged_ack, server_seq, 0x18,
        b"Z", tsopt(50020, peer_ts)), (target_v6, 0, 0, 0))
    continued = None
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        reply = receive(min(.3, max(.001, deadline-time.monotonic())))
        if reply is None:
            continue
        if reply[2] & 0x04:
            raise RuntimeError(f"{label}: post-gap new data reset TCP")
        if reply[1] == merged_ack + 1:
            continued = reply
            break
    if continued is None:
        raise RuntimeError(f"{label}: post-gap in-order data not ACKed")
    fresh_tsecr = continued[5][1] if continued[5] is not None else None
    if fresh_tsecr != 50020:
        raise RuntimeError(f"{label}: post-gap in-order TSecr drift {fresh_tsecr}")
    print(f"{label}: server RX-window oracle zero=True accepted={total} "
          f"server-ws={shift} reopen={reopened} "
          f"rejected-byte=True recovered-tsecr={echo} "
          f"zero-duplicates=4 loss-burst=4 concurrent-echo=4+4 "
          f"post-gap-tsecr={merged_tsecr} "
          f"post-gap-fresh-tsecr={fresh_tsecr}", flush=True)
finally:
    release.touch()
    subprocess.run(["nft", "delete", "table", "inet", nft_table], check=True)
    rx.close()
    tx.close()
PY
}

run_ipv6_tcp_timewait_reuse_probe() {
    local target_v6=$1
    local label=$2
    local mode=${3:-default}
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" "$mode" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label, mode = sys.argv[1:]
if mode not in ("default", "idle-policy"):
    raise ValueError(f"unexpected TIME_WAIT probe mode {mode}")
src = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
dst = socket.inet_pton(socket.AF_INET6, target_v6)

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = sum(struct.unpack(f"!{len(data)//2}H", data))
    while words >> 16:
        words = (words & 0xffff) + (words >> 16)
    return (~words) & 0xffff

def stamp(tsval, tsecr):
    return b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr)

def packet(port, seq, ack, flags, payload=b"", options=b"\x01"*4):
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, 39643, seq & 0xffffffff, ack & 0xffffffff,
        ((5 + len(options)//4) << 12) | flags, 4096, 0, 0
    ) + options + payload)
    tcp[16:18] = struct.pack(
        "!H", checksum(src + dst + struct.pack("!I3xB", len(tcp), 6) + tcp)
    )
    return bytes(tcp)

def send(segment, ident=None, chained=False):
    def ipv6(nh, payload):
        return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, 64, src, dst) + payload
    if ident is None:
        tx.sendto(ipv6(6, segment), (target_v6, 0, 0, 0))
        return
    # IPv6 Fragment -> one/two padding Destination Options -> TCP,
    # with just TCP header octets 0..7 in the first fragment.
    extra = bytes((60 if chained else 6, 0, 1, 4, 0, 0, 0, 0))
    if chained:
        extra += bytes((6, 0, 1, 4, 0, 0, 0, 0))
    body = extra + segment
    split = len(extra) + 8
    def frag(chunk, offset, more):
        return ipv6(44, struct.pack(
            "!BBHI", 60, 0, (offset // 8 << 3) | int(more), ident
        ) + chunk)
    tx.sendto(frag(body[split:], split, False), (target_v6, 0, 0, 0))
    tx.sendto(frag(body[:split], 0, True), (target_v6, 0, 0, 0))

def timestamp(options):
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            break
        size = options[index + 1]
        if size < 2 or index + size > len(options):
            raise RuntimeError(f"{label}: malformed TIME_WAIT reply option")
        if kind == 8 and size == 10:
            return struct.unpack("!II", options[index+2:index+10])
        index += size
    return None

def recv(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        readable, _, _ = select.select((rx,), (), (), max(.001, deadline-time.monotonic()))
        if not readable:
            return None
        wire, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        tcp = wire[40:] if wire[0] >> 4 == 6 else wire
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack, bits, _, _, _ = struct.unpack("!HHIIHHHH", tcp[:20])
        if (sport, dport) != (39643, port):
            continue
        if checksum(dst + src + struct.pack("!I3xB", len(tcp), 6) + tcp):
            raise RuntimeError(f"{label}: TIME_WAIT reply checksum invalid")
        length = (bits >> 12) * 4
        if not 20 <= length <= len(tcp):
            raise RuntimeError(f"{label}: TIME_WAIT reply TCP data offset invalid")
        return seq, ack, bits & 0x3f, timestamp(tcp[20:length]), tcp[length:]
    return None

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_timewait"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_timewait", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_timewait", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    cases = (
        ((False, "close"), (True, "close"),
         (False, "shutdown-write"), (True, "shutdown-write"))
        if mode == "default"
        else
        ((False, "close"), (True, "close"),
         (False, "shutdown-write"), (True, "shutdown-write"),
         (False, "hold-open"), (True, "hold-open"))
    )
    for case, (chained, close_style) in enumerate(cases):
        port = 46150 + case + (20 if mode == "idle-policy" else 0)
        cisn = 0x53100000 + 100000 * case
        initial_ts = 52000 + case * 100
        send(packet(port, cisn, 0, 0x02, options=stamp(initial_ts, 0)))
        synack = recv(port, 1.5)
        if synack is None or synack[2] & 0x12 != 0x12 or synack[1] != cisn + 1:
            raise RuntimeError(f"{label}: TIME_WAIT SYN/SYN-ACK failed {synack}")
        negotiated = synack[3] is not None
        if not negotiated:
            raise RuntimeError(f"{label}: TIME_WAIT Timestamp negotiation missing")
        peer_ts = synack[3][0] if negotiated else 0
        cseq = cisn + 1
        sseq = synack[0] + 1
        def opts(ts):
            return stamp(ts, peer_ts) if negotiated else b"\x01"*4
        send(packet(port, cseq, sseq, 0x10, options=opts(initial_ts+1)))
        marker_prefix = {
            "close": b"chimera-timewait-active-close-",
            "shutdown-write": b"chimera-timewait-shutdown-write-",
            "hold-open": b"chimera-timewait-hold-open-",
        }[close_style]
        marker = marker_prefix + bytes((case,))
        send(packet(port, cseq, sseq, 0x18, marker, opts(initial_ts+2)),
             ident=0x6677b000 + case * 10, chained=chained)
        cseq += len(marker)
        body = b""
        server_fin = False
        phase_start = time.monotonic()
        deadline = phase_start + (5.5 if mode == "idle-policy" else 3.2)
        fin_after = None
        while time.monotonic() < deadline and (len(body) < len(marker) or not server_fin):
            r = recv(port, max(.001, deadline-time.monotonic()))
            if r is None:
                break
            seq, ack, flags, ts, data = r
            if flags & 4:
                raise RuntimeError(f"{label}: active FIN fixture reset")
            if ts is not None:
                peer_ts = ts[0]
            if data and seq == sseq + len(body):
                body += data
            if flags & 1:
                if seq + len(data) != sseq + len(marker):
                    raise RuntimeError(f"{label}: FIN arrived before Echo completed")
                server_fin = True
                fin_after = round(time.monotonic() - phase_start, 3)
            if len(body) > len(marker) or not marker.startswith(body):
                raise RuntimeError(f"{label}: corrupted active-close Echo")
        if body != marker:
            raise RuntimeError(
                f"{label}: active-close Echo data missing: {body!r}"
            )
        # Real Xray 26.9.9 forwarded the exact Echo but did not emit a
        # server-first FIN during the initial bounded window, unlike
        # Chimera. If it still has no FIN, close the *client side* and
        # record the LAST_ACK/CLOSED path; do not falsely call it server
        # TIME_WAIT. Only the server-first path can reach server TW.
        active_fin = server_fin
        server_closed_seq = sseq + len(marker) + int(server_fin)
        if server_fin:
            send(packet(port, cseq, server_closed_seq, 0x10,
                        options=opts(initial_ts+3)))
        send(packet(port, cseq, server_closed_seq, 0x11,
                    options=opts(initial_ts+4)),
             ident=0x6677b001 + case * 10, chained=chained)
        next_client_seq = cseq + 1
        final_fin_ack = False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and (not final_fin_ack or not server_fin):
            r = recv(port, max(.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, ts, data = r
            if flags & 4:
                raise RuntimeError(f"{label}: FIN exchange reset")
            if ack == next_client_seq and flags & 0x10:
                final_fin_ack = True
            if flags & 1 and not server_fin:
                server_closed_seq = seq + len(data) + 1
                server_fin = True
                send(packet(port, next_client_seq, server_closed_seq, 0x10,
                            options=opts(initial_ts+6)))
        if not final_fin_ack or not server_fin:
            raise RuntimeError(
                f"{label}: FIN exchange incomplete final-ack={final_fin_ack} "
                f"server-fin={server_fin} active-first={active_fin}"
            )
        # A retransmitted FIN must not create a second application event
        # or yield a new SYN-ACK. TIME_WAIT ACK timing is stack-specific.
        send(packet(port, cseq, server_closed_seq, 0x11, options=opts(initial_ts+5)),
             ident=0x6677b002 + case * 10, chained=chained)
        # Replay old *application bytes* using their original sequence,
        # under a fresh IPv6 Fragment ID after closure. A valid new SYN
        # must not inherit them from the previous TCP incarnation.
        send(packet(port, cseq-len(marker), server_closed_seq, 0x18,
                    marker, opts(initial_ts+7)),
             ident=0x6677b003 + case * 10, chained=chained)
        dup_fin_ack = False
        stale_data_reply = False
        deadline = time.monotonic() + .35
        while time.monotonic() < deadline:
            r = recv(port, max(.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, ts, data = r
            if flags & 4:
                continue
            if ack == next_client_seq and flags & 0x10:
                dup_fin_ack = True
            stale_data_reply |= bool(data)
        # A *higher* ISN is used to request a new incarnation on
        # precisely the same four-tuple; do not infer success merely
        # from a received ACK/RST.
        newer_isn = next_client_seq + 100000
        send(packet(port, newer_isn, 0, 0x02, options=stamp(initial_ts+500, 0)))
        reuse_response = "none"
        resynack = None
        deadline = time.monotonic() + .8
        while time.monotonic() < deadline:
            r = recv(port, max(.001, deadline - time.monotonic()))
            if r is None:
                break
            seq, ack, flags, ts, data = r
            if flags & 0x12 == 0x12 and ack == newer_isn + 1:
                reuse_response = "synack"
                resynack = r
                break
            if flags & 4:
                reuse_response = "rst"
                break
            if flags & 0x10:
                reuse_response = "ack"
        reopened = False
        if resynack is not None:
            nseq = resynack[0] + 1
            new_ts = initial_ts + 501
            new_tsecr = resynack[3][0] if resynack[3] is not None else 0
            send(packet(port, newer_isn+1, nseq, 0x10,
                        options=stamp(new_ts, new_tsecr) if resynack[3] else b"\x01"*4))
            fresh = b"timewait-new-incarnation-" + bytes((case,))
            send(packet(port, newer_isn+1, nseq, 0x18, fresh,
                        stamp(new_ts+1, new_tsecr) if resynack[3] else b"\x01"*4))
            reply = b""
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline and len(reply) < len(fresh):
                r = recv(port, max(.001, deadline-time.monotonic()))
                if r is None:
                    break
                seq, ack, flags, ts, data = r
                if flags & 4:
                    break
                if data and seq == nseq + len(reply):
                    reply += data
            reopened = reply == fresh
            if reply and not reopened:
                raise RuntimeError(f"{label}: reused 4-tuple delivered corrupt Echo")
        print(
            f"{label}: TCP TIME_WAIT mode={mode} chained={chained} "
            f"close-style={close_style} fin-after={fin_after} "
            f"ts-negotiated={negotiated} "
            f"active-fin={active_fin} server-timewait-direction={active_fin} "
            f"server-fin={server_fin} final-ack={final_fin_ack} "
            f"duplicate-fin-ack={dup_fin_ack} stale-data={stale_data_reply} "
            f"same-tuple-syn={reuse_response} new-flow-echo={reopened}",
            flush=True,
        )
        # Pinned Xray Freedom closes client-first and can reopen the tuple.
        # Chimera's server-first FIN now enters an Xray-opt-in TIME-WAIT
        # state and must ACK duplicates without premature tuple reuse.
        oracle = label.startswith("Xray 26.9.9")
        if mode == "default" and active_fin == oracle:
            raise RuntimeError(
                f"{label}: pinned FIN ordering changed "
                f"trigger={close_style} active-fin={active_fin}"
            )
        if stale_data_reply:
            raise RuntimeError(f"{label}: old TCP connection unexpectedly emitted data")
        if not oracle and active_fin:
            if not dup_fin_ack or resynack is not None:
                raise RuntimeError(
                    f"{label}: server-first TIME_WAIT mismatch: "
                    f"duplicate-fin-ack={dup_fin_ack} SYN={reuse_response}"
                )
        elif reuse_response != "synack" or not reopened:
            raise RuntimeError(
                f"{label}: same-four-tuple reuse failed: "
                f"SYN={reuse_response} Echo={reopened}"
            )
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_timewait"], check=True)
    rx.close()
    tx.close()
PY
}

run_ipv6_tcp_blackhole_terminal_probe() {
    local target_v6=$1
    local label=$2
    local expectation=${3:-reference}
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v6" "$label" "$expectation" <<'PY'
import select
import socket
import struct
import subprocess
import sys
import time

target_v6, label, expectation = sys.argv[1:]
if expectation not in ("reference", "chimera"):
    raise ValueError(f"unknown blackhole probe expectation: {expectation}")
source = socket.inet_pton(socket.AF_INET6, "fd18:251::2")
dest = socket.inet_pton(socket.AF_INET6, target_v6)
target_port = 39647

def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    words = sum(struct.unpack(f"!{len(data)//2}H", data))
    while words >> 16:
        words = (words & 0xffff) + (words >> 16)
    return (~words) & 0xffff

def options(ts, tsecr):
    return b"\x01\x01\x08\x0a" + struct.pack("!II", ts, tsecr)

def transmit(port, seq, ack, flags, ts, tsecr, fragment_rst=False):
    tcp = bytearray(struct.pack(
        "!HHIIHHHH", port, target_port, seq & 0xffffffff,
        ack & 0xffffffff, (8 << 12) | flags, 4096, 0, 0
    ) + options(ts, tsecr))
    tcp[16:18] = struct.pack(
        "!H", checksum(source + dest + struct.pack("!I3xB", len(tcp), 6) + tcp)
    )
    if fragment_rst:
        # nftables shields raw fixtures from host-generated RST packets
        # (ip6 nexthdr tcp). Carry an explicit checksum-valid RST+ACK
        # through two IPv6 fragments, as other fixture TCP RST cases do.
        # This preserves the host RST shield for subsequent SYN probes.
        for offset, part, more in ((8, tcp[8:], False), (0, tcp[:8], True)):
            fragment = struct.pack(
                "!BBHI", 6, 0, ((offset // 8) << 3) | int(more),
                0x74700000 + port
            ) + part
            ip = struct.pack(
                "!IHBB16s16s", 6 << 28, len(fragment), 44, 64, source, dest
            )
            tx.sendto(ip + fragment, (target_v6, 0, 0, 0))
        return
    ip = struct.pack(
        "!IHBB16s16s", 6 << 28, len(tcp), 6, 64, source, dest
    )
    tx.sendto(ip + tcp, (target_v6, 0, 0, 0))

def receive(port, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        available, _, _ = select.select([rx], [], [], max(.001, deadline - time.monotonic()))
        if not available:
            return None
        wire, peer = rx.recvfrom(8192)
        if peer[0] != target_v6:
            continue
        segment = wire[40:] if wire[0] >> 4 == 6 else wire
        if len(segment) < 20:
            continue
        sport, dport, seq, ack, bits, _, _, _ = struct.unpack(
            "!HHIIHHHH", segment[:20]
        )
        if (sport, dport) != (target_port, port):
            continue
        if checksum(dest + source + struct.pack("!I3xB", len(segment), 6) + segment):
            raise RuntimeError(f"{label}: blackhole TCP checksum invalid")
        offset = 4 * (bits >> 12)
        if offset < 20 or offset > len(segment):
            raise RuntimeError(f"{label}: blackhole TCP data-offset invalid")
        if segment[offset:]:
            raise RuntimeError(f"{label}: no-response blackhole unexpectedly sent payload")
        opts = segment[20:offset]
        timestamp = None
        p = 0
        while p < len(opts):
            typ = opts[p]
            if typ == 0:
                break
            if typ == 1:
                p += 1
                continue
            if p + 2 > len(opts) or opts[p+1] < 2 or p + opts[p+1] > len(opts):
                raise RuntimeError(f"{label}: invalid blackhole TCP option")
            if typ == 8 and opts[p+1] == 10:
                timestamp = struct.unpack("!II", opts[p+2:p+10])
            p += opts[p+1]
        return seq, ack, bits & 0x3f, timestamp

rx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
rx.bind(("fd18:251::2", 0, 0, 0))
tx = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
tx.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_HDRINCL", 36), 1)
subprocess.run(["nft", "add", "table", "inet", "chimera_bh_fin"], check=True)
try:
    subprocess.run(["nft", "add", "chain", "inet", "chimera_bh_fin", "output",
                    "{ type filter hook output priority 0; policy accept; }"], check=True)
    subprocess.run(["nft", "add", "rule", "inet", "chimera_bh_fin", "output",
                    "ip6", "saddr", "fd18:251::2", "ip6", "daddr", target_v6,
                    "ip6", "nexthdr", "tcp", "tcp", "flags", "rst", "drop"], check=True)
    # Cases 0/1 remain the strict compatibility oracle; cases 2/3
    # additionally characterize an old Timestamp and an in-window RST
    # after entering TIME_WAIT without inferring unsupported PAWS parity.
    for case in range(4):
        port = 46220 + case
        isn = 0x64300000 + 1000 * case
        ts = 60000 + case * 100
        transmit(port, isn, 0, 0x02, ts, 0)
        synack = receive(port, 1.5)
        if synack is None or synack[2] & 0x12 != 0x12 or synack[1] != isn+1:
            raise RuntimeError(f"{label}: blackhole TCP handshake missing {synack}")
        peer_ts = synack[3][0] if synack[3] is not None else 0
        server_seq = synack[0]+1
        client_seq = isn+1
        transmit(port, client_seq, server_seq, 0x10, ts+1, peer_ts)
        first_fin = False
        first_rst = False
        fin_after = None
        started = time.monotonic()
        deadline = started + 4
        while time.monotonic() < deadline:
            r = receive(port, max(.001, deadline-time.monotonic()))
            if r is None:
                break
            seq, ack, flags, ts_reply = r
            if flags & 4:
                first_rst = True
                break
            if flags & 1:
                if seq != server_seq:
                    raise RuntimeError(f"{label}: blackhole sent unexpected FIN sequence")
                first_fin = True
                fin_after = round(time.monotonic() - started, 3)
                if ts_reply is not None:
                    peer_ts = ts_reply[0]
                break
        final_ack = False
        duplicate_fin_ack = False
        reopened_synack = False
        reopen_response = "none"
        if first_fin:
            closed_seq = server_seq+1
            transmit(port, client_seq, closed_seq, 0x10, ts+2, peer_ts)
            transmit(port, client_seq, closed_seq, 0x11, ts+3, peer_ts)
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                r = receive(port, max(.001, deadline-time.monotonic()))
                if r is None:
                    break
                if r[2] & 0x10 and r[1] == client_seq+1 and not r[2] & 4:
                    final_ack = True
                    break
            if not final_ack:
                raise RuntimeError(f"{label}: blackhole server-first FIN did not ACK client FIN")
            transmit(port, client_seq, closed_seq, 0x11, ts+4, peer_ts)
            deadline = time.monotonic() + .8
            while time.monotonic() < deadline:
                r = receive(port, max(.001, deadline-time.monotonic()))
                if r is None:
                    break
                if r[2] & 0x10 and r[1] == client_seq+1 and not r[2] & 4:
                    duplicate_fin_ack = True
                    break
            stale_ts_fin_ack = None
            if case == 2:
                # Retransmit the identical FIN with a stale TSval. Only
                # the reference currently negotiates TCP Timestamps.
                transmit(port, client_seq, closed_seq, 0x11, ts-100, peer_ts)
                stale_ts_fin_ack = False
                deadline = time.monotonic() + .5
                while time.monotonic() < deadline:
                    r = receive(port, max(.001, deadline-time.monotonic()))
                    if r is None:
                        break
                    if r[2] & 0x10 and r[1] == client_seq+1 and not r[2] & 4:
                        stale_ts_fin_ack = True
                        break
            if case == 3:
                # A checksum-valid, in-window RST after FIN completion
                # tests TIME_WAIT assassination separately from duplicate FIN.
                transmit(port, client_seq+1, closed_seq, 0x14, ts+5, peer_ts,
                         fragment_rst=True)
                time.sleep(.05)
            # The pinned gVisor TIME_WAIT handler only redirects a SYN
            # whose ISN advances beyond the old RCV.NXT. A real SYN-ACK
            # acknowledging that newer ISN proves fresh incarnation,
            # rather than mistaking a stray TIME_WAIT ACK for success.
            new_isn = client_seq + 100000
            transmit(port, new_isn, 0, 0x02, ts+500, 0)
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                r = receive(port, max(.001, deadline-time.monotonic()))
                if r is None:
                    break
                if r[2] & 0x12 == 0x12 and r[1] == new_isn+1:
                    reopened_synack = True
                    reopen_response = "synack"
                    break
                if r[2] & 4:
                    reopen_response = "rst"
                    break
                if r[2] & 0x10:
                    reopen_response = "ack"
        print(
            f"{label}: blackhole termination case={case} "
            f"server-first-fin={first_fin} rst={first_rst} "
            f"fin-after={fin_after} final-fin-ack={final_ack} "
            f"duplicate-fin-ack={duplicate_fin_ack} "
            f"same-tuple-new-synack={reopened_synack} "
            f"same-tuple-response={reopen_response} "
            f"stale-ts-fin-ack={stale_ts_fin_ack} "
            f"postclose-rst={case == 3} "
            f"synack-ts-negotiated={synack[3] is not None}", flush=True,
        )
        # Require evidence of the pinned gVisor server-FIRST-FIN
        # and TIME_WAIT-style duplicate-FIN ACK. A newer-ISN SYN may
        # be accepted or refused in this special no-response outbound
        # path, and is measured separately from the established FIN
        # lifecycle. Do not incorrectly conflate these two properties.
        if not (first_fin and not first_rst and final_ack and duplicate_fin_ack):
            raise RuntimeError(
                f"{label}: pinned blackhole FIN/TIME_WAIT behavior changed: "
                f"fin={first_fin} rst={first_rst} ack={final_ack} "
                f"duplicate-ack={duplicate_fin_ack}"
            )
        # The pinned reference rejects immediate tuple reuse even after
        # the case-3 checksum-valid RST. Require the same protection from
        # Chimera rather than treating RST assassination as diagnostic only.
        if reopened_synack:
            raise RuntimeError(
                f"{label}: TIME-WAIT accepted premature same-tuple SYN "
                f"after-rst={case == 3}"
            )
finally:
    subprocess.run(["nft", "delete", "table", "inet", "chimera_bh_fin"], check=True)
    rx.close()
    tx.close()
PY
}

run_pmtu_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" <<'PY'
import socket
import struct
import sys

target_v4, target_v6, label = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"
server_udp_port = 39644
expected_mtu = 1400

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

rx4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
rx4.bind((source_v4, 0))
rx4.settimeout(3)
raw4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
source_bytes = socket.inet_aton(source_v4)
target_bytes = socket.inet_aton(target_v4)
client_udp_port = 45200
identification = 0x5523
udp_length = 1480
udp = struct.pack("!HHHH", client_udp_port, server_udp_port, udp_length, 0)
udp += b"v" * (udp_length - len(udp))
header = struct.pack(
    "!BBHHHBBH4s4s", 0x45, 0, 1500, identification, 0x4000, 64, 17, 0,
    source_bytes, target_bytes,
)
header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
raw4.sendto(header + udp, (target_v4, 0))
while True:
    reply4, _ = rx4.recvfrom(4096)
    ihl = (reply4[0] & 0x0f) * 4
    icmp4 = reply4[ihl:]
    if reply4[9] != socket.IPPROTO_ICMP or icmp4[:2] != b"\x03\x04":
        continue
    quoted4 = icmp4[8:]
    quoted_ihl = (quoted4[0] & 0x0f) * 4
    if quoted4[9] != socket.IPPROTO_UDP \
            or quoted4[4:6] != struct.pack("!H", identification) \
            or quoted4[12:16] != source_bytes \
            or quoted4[16:20] != target_bytes \
            or quoted4[quoted_ihl:quoted_ihl + 2] != struct.pack("!H", client_udp_port):
        continue
    advertised_mtu = struct.unpack("!H", icmp4[6:8])[0]
    if advertised_mtu != expected_mtu:
        raise RuntimeError(
            f"{label}: IPv4 Fragmentation Needed advertised MTU "
            f"{advertised_mtu}, expected {expected_mtu}"
        )
    break
print(f"{label}: IPv4 Fragmentation Needed advertises MTU {expected_mtu}.", flush=True)
rx4.close()
raw4.close()

rx6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
rx6.bind((source_v6, 0, 0, 0))
rx6.settimeout(3)
udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp6.bind((source_v6, 0, 0, 0))
udp6.sendto(b"v" * (1500 - 40 - 8), (target_v6, server_udp_port, 0, 0))
source_v6_bytes = socket.inet_pton(socket.AF_INET6, source_v6)
target_v6_bytes = socket.inet_pton(socket.AF_INET6, target_v6)
client_udp_port = udp6.getsockname()[1]
while True:
    reply6, _ = rx6.recvfrom(4096)
    icmp6 = reply6[40:] if reply6 and reply6[0] >> 4 == 6 else reply6
    if icmp6[:2] != b"\x02\x00":
        continue
    quoted6 = icmp6[8:]
    if len(quoted6) < 48 or quoted6[6] != socket.IPPROTO_UDP \
            or quoted6[8:24] != source_v6_bytes \
            or quoted6[24:40] != target_v6_bytes \
            or quoted6[40:42] != struct.pack("!H", client_udp_port):
        continue
    advertised_mtu = struct.unpack("!I", icmp6[4:8])[0]
    if advertised_mtu != expected_mtu:
        raise RuntimeError(
            f"{label}: IPv6 Packet Too Big advertised MTU "
            f"{advertised_mtu}, expected {expected_mtu}"
        )
    break
print(f"{label}: IPv6 Packet Too Big advertises MTU {expected_mtu}.", flush=True)
rx6.close()
udp6.close()
PY
}

run_downstream_pmtu_error_probe() {
    local target_v4=$1
    local target_v6=$2
    local label=$3
    local v4_before
    local v6_before
    v4_before=$(grep -Fc 'IPv4 Fragmentation Needed sent' "$echo_log_file" || true)
    v6_before=$(grep -Fc 'IPv6 Packet Too Big sent' "$echo_log_file" || true)
    ptb_capture_log_file=$(mktemp)
    python3 -u - "$target_v4" "$target_v6" <<'PY' >"$ptb_capture_log_file" 2>&1 &
import socket
import struct
import sys
import time

target_v4, target_v6 = sys.argv[1:]
target4 = socket.inet_aton(target_v4)
target6 = socket.inet_pton(socket.AF_INET6, target_v6)
source4 = socket.inet_aton("10.250.0.1")
source6 = socket.inet_pton(socket.AF_INET6, "fd18:250::1")
capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
capture.bind(("echo-gw", 0))
capture.settimeout(0.05)
deadline = time.monotonic() + 4
seen = set()
while time.monotonic() < deadline and seen != {"IPv4", "IPv6"}:
    try:
        frame, _ = capture.recvfrom(4096)
    except TimeoutError:
        continue
    if len(frame) < 14:
        continue
    if frame[12:14] == b"\x08\x00" and len(frame) >= 14 + 20:
        packet = frame[14:]
        header_len = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_ICMP:
            continue
        message = packet[header_len:]
        if message[:2] != b"\x03\x04":
            continue
        if struct.unpack("!H", message[6:8])[0] != 1280:
            continue
        quoted = message[8:]
        if len(quoted) < 28:
            continue
        quoted_header_len = (quoted[0] & 0x0f) * 4
        if quoted[9] == socket.IPPROTO_UDP and quoted[12:16] == source4 \
                and quoted[16:20] == target4 \
                and struct.unpack("!H", quoted[quoted_header_len + 2:quoted_header_len + 4])[0] == 39646:
            seen.add("IPv4")
            print(f"IPv4 PTB reached server egress interface for {target_v4}", flush=True)
    elif frame[12:14] == b"\x86\xdd" and len(frame) >= 14 + 40:
        packet = frame[14:]
        if packet[6] != socket.IPPROTO_ICMPV6:
            continue
        message = packet[40:]
        if message[:2] != b"\x02\x00":
            continue
        if struct.unpack("!I", message[4:8])[0] != 1280:
            continue
        quoted = message[8:]
        if len(quoted) < 48:
            continue
        if quoted[6] == socket.IPPROTO_UDP and quoted[8:24] == source6 \
                and quoted[24:40] == target6 \
                and struct.unpack("!H", quoted[42:44])[0] == 39646:
            seen.add("IPv6")
            print(f"IPv6 PTB reached server egress interface for {target_v6}", flush=True)
capture.close()
if seen != {"IPv4", "IPv6"}:
    print(f"missing PTB families at server egress interface: {sorted(seen)!r}", flush=True)
    raise SystemExit(1)
PY
    ptb_capture_pid=$!
    sleep 0.05
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - \
        "$target_v4" "$target_v6" "$label" <<'PY'
import socket
import struct
import sys
import time

target_v4, target_v6, label = sys.argv[1:]
source_v4 = "10.251.0.2"
source_v6 = "fd18:251::2"
target_port = 39646

def contains_matching_ptb(raw, family, source, target, source_port):
    deadline = time.monotonic() + 0.8
    source_bytes = socket.inet_pton(family, source)
    target_bytes = socket.inet_pton(family, target)
    while time.monotonic() < deadline:
        raw.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            packet, _ = raw.recvfrom(4096)
        except TimeoutError:
            return False
        if family == socket.AF_INET:
            if packet and packet[0] >> 4 == 4:
                header_len = (packet[0] & 0x0f) * 4
                message = packet[header_len:]
            else:
                message = packet
            if message[:2] != b"\x03\x04":
                continue
            quoted = message[8:]
            if len(quoted) < 28:
                continue
            quoted_header_len = (quoted[0] & 0x0f) * 4
            if quoted[9] == socket.IPPROTO_UDP \
                    and quoted[12:16] == source_bytes \
                    and quoted[16:20] == target_bytes \
                    and quoted[quoted_header_len:quoted_header_len + 4] == struct.pack("!HH", source_port, target_port):
                return True
        else:
            if packet and packet[0] >> 4 == 6:
                message = packet[40:]
            else:
                message = packet
            if message[:2] != b"\x02\x00":
                continue
            quoted = message[8:]
            if len(quoted) >= 48 and quoted[6] == socket.IPPROTO_UDP \
                    and quoted[8:24] == source_bytes \
                    and quoted[24:40] == target_bytes \
                    and quoted[40:44] == struct.pack("!HH", source_port, target_port):
                return True
    return False

def probe(family, source, target, source_port):
    udp = socket.socket(family, socket.SOCK_DGRAM)
    raw_protocol = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    raw = socket.socket(family, socket.SOCK_RAW, raw_protocol)
    if family == socket.AF_INET:
        udp.bind((source, source_port))
        raw.bind((source, 0))
        destination = (target, target_port)
    else:
        udp.bind((source, source_port, 0, 0))
        raw.bind((source, 0, 0, 0))
        destination = (target, target_port, 0, 0)
    udp.settimeout(0.1)
    for _ in range(2):
        udp.sendto(b"p" * (1372 if family == socket.AF_INET else 1352), destination)
        try:
            udp.recvfrom(4096)
        except TimeoutError:
            pass
        else:
            raise RuntimeError(f"{label}: unexpected UDP response from downstream PTB fixture")
        time.sleep(0.15)
    if contains_matching_ptb(raw, family, source, target, source_port):
        raise RuntimeError(f"{label}: downstream PTB was translated into client-facing ICMP")
    udp.close()
    raw.close()

probe(socket.AF_INET, source_v4, target_v4, 45220)
probe(socket.AF_INET6, source_v6, target_v6, 45221)
print(f"{label}: TUN UDP reached the downstream fixture; no matching TUN-side PTB returned.", flush=True)
PY
    if ! wait "$ptb_capture_pid"; then
        ptb_capture_pid=
        cat "$ptb_capture_log_file" >&2
        return 1
    fi
    ptb_capture_pid=
    cat "$ptb_capture_log_file"
    rm -f "$ptb_capture_log_file"
    ptb_capture_log_file=
    local socket_errors
    socket_errors=$(grep -E 'dokodemo-door udp (send|recv from).*failed:' "$server_log_file" \
        | grep -F -e "$target_v4" -e "$target_v6" || true)
    if [[ -n "$socket_errors" ]]; then
        printf '%s: outbound socket error surfaced to the session handler:\n%s\n' \
            "$label" "$socket_errors"
    else
        printf '%s: no outbound UDP socket error surfaced to the session handler.\n' "$label"
    fi
    for attempt in $(seq 1 50); do
        local v4_after
        local v6_after
        v4_after=$(grep -Fc 'IPv4 Fragmentation Needed sent' "$echo_log_file" || true)
        v6_after=$(grep -Fc 'IPv6 Packet Too Big sent' "$echo_log_file" || true)
        if (( v4_after > v4_before && v6_after > v6_before )); then
            return 0
        fi
        sleep 0.02
    done
    printf '%s: downstream PTB fixture did not emit both ICMP families.\n' "$label" >&2
    cat "$echo_log_file" >&2
    return 1
}

run_host_udp_error_queue_probe() {
    local target_v4=$1
    local target_v6=$2
    python3 - "$target_v4" "$target_v6" <<'PY'
import errno
import select
import socket
import struct
import time
import sys

target_v4, target_v6 = sys.argv[1:]

def wait_error(sock, label):
    poller = select.poll()
    poller.register(sock.fileno(), select.POLLERR)
    if not poller.poll(1200):
        raise RuntimeError(f"{label}: no pending socket error after downstream PTB")

def probe_default(family, local, target, local_port, payload):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET:
        sock.bind((local, local_port))
        destination = (target, 39646)
    else:
        sock.bind((local, local_port, 0, 0))
        destination = (target, 39646, 0, 0)
    sock.sendto(payload, destination)
    poller = select.poll()
    poller.register(sock.fileno(), select.POLLERR)
    if poller.poll(300):
        error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        print(f"Default UDP socket observed asynchronous errno {error_number} for {target}.", flush=True)
    else:
        try:
            sock.sendto(payload, destination)
        except OSError as error:
            print(f"Default UDP socket surfaced errno {error.errno} on later send to {target}.", flush=True)
        else:
            print(f"Default UDP socket reported no asynchronous error for {target}.", flush=True)
    sock.close()

def probe(family, local, target, local_port, err_option, expected_origin, expected_type, expected_code):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET:
        sock.bind((local, local_port))
        destination = (target, 39646)
        sock.setsockopt(socket.IPPROTO_IP, err_option, 1)
        payload = b"q" * 1372
        error_level = socket.IPPROTO_IP
    else:
        sock.bind((local, local_port, 0, 0))
        destination = (target, 39646, 0, 0)
        sock.setsockopt(socket.IPPROTO_IPV6, err_option, 1)
        payload = b"q" * 1352
        error_level = socket.IPPROTO_IPV6
    sock.sendto(payload, destination)
    wait_error(sock, f"{target}: error queue")
    data, ancillary, flags, peer = sock.recvmsg(
        2048, 512, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
    )
    for level, kind, control in ancillary:
        if level != error_level or kind != err_option or len(control) < 16:
            continue
        error_number, origin, error_type, error_code, _pad, mtu, _data = struct.unpack(
            "=IBBBBII", control[:16]
        )
        if (error_number, origin, error_type, error_code, mtu) != (
            errno.EMSGSIZE, expected_origin, expected_type, expected_code, 1280
        ):
            raise RuntimeError(
                f"{target}: unexpected error queue record: "
                f"errno={error_number} origin={origin} type={error_type} "
                f"code={error_code} mtu={mtu}"
            )
        if peer[0] != target or flags & socket.MSG_CTRUNC:
            raise RuntimeError(
                f"{target}: incomplete error queue metadata: peer={peer!r}, "
                f"payload_len={len(data)}, flags={flags}"
            )
        print(f"Linux error queue received {target} PTB with MTU {mtu}.", flush=True)
        sock.close()
        return
    raise RuntimeError(f"{target}: expected IP_RECVERR/IPV6_RECVERR control message")

# Linux UAPI option numbers: IP_RECVERR=11, IPV6_RECVERR=25.
probe_default(socket.AF_INET, "10.250.0.1", target_v4, 45228, b"d" * 1372)
probe_default(socket.AF_INET6, "fd18:250::1", target_v6, 45229, b"d" * 1352)
probe(socket.AF_INET, "10.250.0.1", target_v4, 45230, 11, 2, 3, 4)
probe(socket.AF_INET6, "fd18:250::1", target_v6, 45231, 25, 3, 2, 0)
PY
}

if [[ -n "$xray_bin" ]]; then
    xray_reference_server_config_file=$(mktemp --suffix=.json)
    xray_reference_server_log_file=$(mktemp)
    cat >"$xray_reference_server_config_file" <<JSON
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "198.18.44.20",
    "port": 39645,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "d342d11e-d424-4583-b36e-524ab1f0afa4"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h3"],
        "certificates": [{
          "certificateFile": "$repo_root/scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "$repo_root/scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/xray-tun-e2e", "mode": "packet-up"}
    }
  }],
  "outbounds": [{
    "tag": "direct",
    "protocol": "freedom",
    "settings": {
      "finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["198.18.44.20/32"]}]
    }
  }]
}
JSON
    nsenter --net="/proc/$echo_server_ns_pid/ns/net" \
        "$xray_bin" run -c "$xray_reference_server_config_file" \
        >"$xray_reference_server_log_file" 2>&1 &
    xray_reference_server_pid=$!
fi

RUST_LOG=warn,chimera_server_lib::tun_gateway=debug,chimera_server_lib::session::udp::dokodemo=debug,chimera_server_lib::outbound=debug target/debug/chimera_server_app --config "$config_file" \
    >"$server_log_file" 2>&1 &
server_pid=$!
ready=false
for attempt in $(seq 1 100); do
    ipv4_route=$(ip -4 route show table main exact 198.18.44.0/24 2>/dev/null || true)
    ipv6_route=$(ip -6 route show table main exact fd18:198:44::/64 2>/dev/null || true)
    if [[ "$ipv4_route" == *'dev cxray-tun'* && "$ipv4_route" == *'metric 1'* ]] \
        && [[ "$ipv6_route" == *'dev cxray-tun'* && "$ipv6_route" == *'metric 1'* ]]; then
        ready=true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        printf 'Xray TUN server exited before installing its system routes.\n' >&2
        cat "$server_log_file" >&2
        exit 1
    fi
    sleep 0.05
done
if [[ "$ready" != true ]]; then
    printf 'Xray TUN main-table routes did not appear with metric 1.\n' >&2
    cat "$server_log_file" >&2
    exit 1
fi
sysctl -q -w net.ipv4.conf.cxray-tun.rp_filter=0
ip -o link show dev cxray-tun | grep -F 'mtu 1400' >/dev/null
ip -o -4 addr show dev cxray-tun | grep -F '10.44.0.1/24' >/dev/null
ip -o -6 addr show dev cxray-tun | grep -F 'fd18:44::1/64' >/dev/null
ip route get 198.18.44.20 from 10.251.0.2 iif office-gw | grep -F 'dev cxray-tun' >/dev/null
ip -6 route get fd18:198:44::20 from fd18:251::2 iif office-gw | grep -F 'dev cxray-tun' >/dev/null
ip route get 198.18.44.20 uid 0 | grep -F 'via 10.250.0.2 dev echo-gw table 10001' >/dev/null
ip -6 route get fd18:198:44::20 uid 0 | grep -F 'via fd18:250::2 dev echo-gw table 10001' >/dev/null
# The Xray-only TIME-WAIT path must match the pinned Blackhole FIN
# and duplicate-FIN behavior without allowing immediate tuple reuse.
run_ipv6_tcp_blackhole_terminal_probe fd18:198:44::20 \
    'Chimera Xray TUN blackhole' chimera
run_ipv6_tcp_timewait_reuse_probe fd18:198:44::20 'Chimera Xray TUN'
run_ipv6_tcp_timestamp_replay_probe fd18:198:44::20 'Chimera Xray TUN'
server_rx_pressure_failures=0
seeded_netem_failures=0
bulk_echo_failures=0
# Actual Linux qdisc packet loss is opt-in and scoped only to the disposable
# office-client veth. Neither the normal smoke nor raw Timestamp tests run
# while netem is attached.
if [[ ${XRAY_TUN_SEEDED_NETEM:-0} == 1 ]]; then
    seeded_capture_pid=
    seeded_capture_file=
    if [[ ${XRAY_TUN_BULK_CAPTURE:-0} == 1 ]]; then
        seeded_capture_file=$(mktemp)
        python3 -u "$repo_root/scripts/diagnose_xray_tun_tcp_capture.py" \
            >"$seeded_capture_file" 2>&1 &
        seeded_capture_pid=$!
        sleep 0.1
    fi
    if ! run_ipv6_tcp_seeded_netem_probe fd18:198:44::20 'Chimera Xray TUN'; then
        printf 'Chimera seeded netem kernel-TCP retransmission probe failed.\n' >&2
        seeded_netem_failures=$((seeded_netem_failures + 1))
    fi
    if [[ -n "$seeded_capture_pid" ]]; then
        kill -TERM "$seeded_capture_pid" 2>/dev/null || true
        wait "$seeded_capture_pid" 2>/dev/null || true
        cat "$seeded_capture_file"
        rm -f "$seeded_capture_file"
    fi
fi
if [[ ${XRAY_TUN_BULK_ECHO:-0} == 1 ]]; then
    if ! run_ipv6_tcp_bulk_downlink_probe fd18:198:44::20 'Chimera Xray TUN'; then
        printf 'Chimera full-MSS bulk downlink oracle failed.\n' >&2
        bulk_echo_failures=$((bulk_echo_failures + 1))
    fi
fi
# Diagnostic-only fast pass for iterating on the Linux qdisc fixture.
# It exercises Chimera, invokes the namespace cleanup trap, and exits
# without running the paired oracle or claiming the full suite passed.
if [[ ${XRAY_TUN_SEEDED_NETEM_CHIMERA_ONLY:-0} == 1 ]]; then
    if [[ ${XRAY_TUN_SEEDED_NETEM:-0} != 1 ]]; then
        printf 'Fast netem probe requires XRAY_TUN_SEEDED_NETEM=1.\n' >&2
        exit 2
    fi
    if (( seeded_netem_failures > 0 )); then
        printf 'Chimera quick loss diagnostic echo-target accept entries:\n' >&2
        grep -E 'TCP accepted|SEEDED TARGET' "$echo_log_file" | tail -22 >&2 || true
        exit 1
    fi
    printf 'Chimera seeded netem diagnostic only passed (not paired/full suite).\n'
    exit 0
fi
# Heavy real receive-backpressure oracle is separate from normal smoke.
# Enable explicitly: XRAY_TUN_SERVER_RX_PRESSURE=1 XRAY_BIN=./xray bash ...
if [[ ${XRAY_TUN_SERVER_RX_MULTISTALL:-0} == 1 ]]; then
    if ! run_ipv6_tcp_multi_server_receive_window_probe fd18:198:44::20 'Chimera Xray TUN'; then
        printf 'Chimera simultaneous server receive-window pressure failed.\n' >&2
        server_rx_pressure_failures=$((server_rx_pressure_failures + 1))
    fi
elif [[ ${XRAY_TUN_SERVER_RX_PRESSURE:-0} == 1 ]]; then
    if ! run_ipv6_tcp_true_server_receive_window_probe fd18:198:44::20 'Chimera Xray TUN'; then
        printf 'Chimera true server receive-window probe failed; still checking the pinned Xray oracle.\n' >&2
        server_rx_pressure_failures=$((server_rx_pressure_failures + 1))
    fi
fi
run_ipv6_tcp_sender_sack_retransmit_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_sack_gap_recovery_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_zero_window_recovery_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_active_ack_window_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_active_rst_reuse_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_active_options_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_non_syn_option_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_data_offset_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_malformed_options_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_tcp_destination_first_header_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_udp_destination_first_header_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_chained_destination_probe fd18:198:44::20 'Chimera Xray TUN'
run_fragmented_ipv6_destination_hdr_ext_len_probe fd18:198:44::20 'Chimera Xray TUN'
run_unknown_protocol_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN'
run_non_echo_icmp_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN'
run_truncated_icmp_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN'
run_bad_icmp_checksum_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN' reply drop reply drop
run_fragmented_ipv6_echo_padding_options_probe fd18:198:44::20 'Chimera Xray TUN' hop-before-fragment
run_fragmented_ipv6_echo_padding_options_probe fd18:198:44::20 'Chimera Xray TUN' destination-after-fragment
run_fragmented_ipv6_echo_semantic_destination_probe fd18:198:44::20 'Chimera Xray TUN'
run_pmtu_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN'
run_downstream_pmtu_error_probe 198.18.44.20 fd18:198:44::20 'Chimera Xray TUN'
if [[ -n "$xray_bin" ]]; then
    xray_reference_tun_config_file=$(mktemp --suffix=.json)
    xray_reference_tun_log_file=$(mktemp)
    cat >"$xray_reference_tun_config_file" <<'JSON'
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "xray-tun-reference",
    "protocol": "tun",
    "settings": {
      "name": "xray-ref-tun",
      "mtu": 1400,
      "gateway": ["10.45.0.1/24", "fd18:45::1/64"],
      "autoSystemRoutingTable": ["198.18.45.0/24", "fd18:198:45::/64"]
    }
  }],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}
JSON
    "$xray_bin" run -c "$xray_reference_tun_config_file" \
        >"$xray_reference_tun_log_file" 2>&1 &
    xray_reference_tun_pid=$!
    reference_tun_ready=false
    for attempt in $(seq 1 100); do
        ipv4_route=$(ip -4 route show table main exact 198.18.45.0/24 2>/dev/null || true)
        ipv6_route=$(ip -6 route show table main exact fd18:198:45::/64 2>/dev/null || true)
        if [[ "$ipv4_route" == *'dev xray-ref-tun'* ]] \
            && [[ "$ipv6_route" == *'dev xray-ref-tun'* ]]; then
            reference_tun_ready=true
            break
        fi
        if ! kill -0 "$xray_reference_tun_pid" 2>/dev/null; then
            printf 'Pinned Xray TUN reference exited before installing routes.\n' >&2
            cat "$xray_reference_tun_log_file" >&2
            exit 1
        fi
        sleep 0.05
    done
    if [[ "$reference_tun_ready" != true ]]; then
        printf 'Pinned Xray TUN reference routes did not appear.\n' >&2
        cat "$xray_reference_tun_log_file" >&2
        exit 1
    fi
    ip -o link show dev xray-ref-tun | grep -F 'mtu 1400' >/dev/null
    nsenter --net="/proc/$office_client_ns_pid/ns/net" \
        ip route add 198.18.45.0/24 via 10.251.0.1
    nsenter --net="/proc/$office_client_ns_pid/ns/net" \
        ip -6 route add fd18:198:45::/64 via fd18:251::1
    ip route get 198.18.45.20 from 10.251.0.2 iif office-gw \
        | grep -F 'dev xray-ref-tun' >/dev/null
    ip -6 route get fd18:198:45::20 from fd18:251::2 iif office-gw \
        | grep -F 'dev xray-ref-tun' >/dev/null
    ip -4 route get 198.18.45.20 uid 0 \
        | grep -F 'via 10.250.0.2 dev echo-gw table 10001' >/dev/null
    ip -6 route get fd18:198:45::20 uid 0 \
        | grep -F 'via fd18:250::2 dev echo-gw table 10001' >/dev/null
    if [[ ${XRAY_TUN_SEEDED_NETEM:-0} == 1 ]]; then
        if ! run_ipv6_tcp_seeded_netem_probe fd18:198:45::20 'Xray 26.9.9 TUN'; then
            printf 'Pinned Xray seeded netem kernel-TCP retransmission probe failed.\n' >&2
            seeded_netem_failures=$((seeded_netem_failures + 1))
        fi
    fi
    if [[ ${XRAY_TUN_BULK_ECHO:-0} == 1 ]]; then
        if ! run_ipv6_tcp_bulk_downlink_probe fd18:198:45::20 'Xray 26.9.9 TUN'; then
            printf 'Pinned Xray full-MSS bulk downlink oracle failed.\n' >&2
            bulk_echo_failures=$((bulk_echo_failures + 1))
        fi
    fi
    run_ipv6_tcp_timewait_reuse_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_ipv6_tcp_timestamp_replay_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    if [[ ${XRAY_TUN_SERVER_RX_MULTISTALL:-0} == 1 ]]; then
        if ! run_ipv6_tcp_multi_server_receive_window_probe fd18:198:45::20 'Xray 26.9.9 TUN'; then
            printf 'Pinned Xray simultaneous server receive-window pressure failed.\n' >&2
            server_rx_pressure_failures=$((server_rx_pressure_failures + 1))
        fi
    elif [[ ${XRAY_TUN_SERVER_RX_PRESSURE:-0} == 1 ]]; then
        if ! run_ipv6_tcp_true_server_receive_window_probe fd18:198:45::20 'Xray 26.9.9 TUN'; then
            printf 'Pinned Xray true server receive-window probe failed; keeping strict final result.\n' >&2
            server_rx_pressure_failures=$((server_rx_pressure_failures + 1))
        fi
    fi
    run_ipv6_tcp_sender_sack_retransmit_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_sack_gap_recovery_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_zero_window_recovery_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_active_ack_window_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_active_rst_reuse_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_active_options_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_non_syn_option_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_data_offset_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_malformed_options_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_tcp_destination_first_header_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_udp_destination_first_header_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_chained_destination_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_fragmented_ipv6_destination_hdr_ext_len_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    if ! run_unknown_protocol_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN'; then
        ip -s link show dev xray-ref-tun >&2 || true
        cat "$xray_reference_tun_log_file" >&2 || true
        exit 1
    fi
    run_non_echo_icmp_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN'
    run_truncated_icmp_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN'
    run_bad_icmp_checksum_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN' reply drop reply drop
    run_fragmented_ipv6_echo_padding_options_probe fd18:198:45::20 'Xray 26.9.9 TUN' hop-before-fragment
    run_fragmented_ipv6_echo_padding_options_probe fd18:198:45::20 'Xray 26.9.9 TUN' destination-after-fragment
    run_fragmented_ipv6_echo_semantic_destination_probe fd18:198:45::20 'Xray 26.9.9 TUN'
    run_pmtu_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN'
    run_downstream_pmtu_error_probe 198.18.45.20 fd18:198:45::20 'Xray 26.9.9 TUN'
    xray_client_config_file=$(mktemp --suffix=.json)
    xray_client_log_file=$(mktemp)
    cat >"$xray_client_config_file" <<'JSON'
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 1080,
    "protocol": "socks",
    "settings": {"udp": false}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "198.18.44.20",
        "port": 39644,
        "users": [{"id": "d342d11e-d424-4583-b36e-524ab1f0afa4", "encryption": "none"}]
      }]
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {"serverName": "www.google.com", "alpn": ["h3"]},
      "xhttpSettings": {"host": "www.google.com", "path": "/", "mode": "packet-up"}
    }
  }]
}
JSON
    nsenter --net="/proc/$office_client_ns_pid/ns/net" \
        "$xray_bin" run -c "$xray_client_config_file" \
        >"$xray_client_log_file" 2>&1 &
    xray_client_pid=$!
    before_udp_count=$(grep -c '^UDP received ' "$echo_log_file" || true)
    before_route_count=$(grep -c \
        'www.google.com:39644 dropped by blackhole outbound quic-sni-block' \
        "$server_log_file" || true)
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import socket
import struct
import time

def receive_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("Xray SOCKS client closed during negotiation")
        result.extend(chunk)
    return bytes(result)

deadline = time.monotonic() + 5
while True:
    try:
        connection = socket.create_connection(("127.0.0.1", 1080), timeout=0.2)
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise RuntimeError("Xray SOCKS inbound did not become ready")
        time.sleep(0.05)

with connection:
    connection.settimeout(2)
    connection.sendall(b"\x05\x01\x00")
    if receive_exact(connection, 2) != b"\x05\x00":
        raise RuntimeError("Xray SOCKS inbound rejected no-auth negotiation")
    connection.sendall(b"\x05\x01\x00\x01\xcb\x00\x71\x01" + struct.pack("!H", 80))
    time.sleep(1)
print("Xray 26.9.9 XHTTP/H3 client emitted a live QUIC Initial through the TUN.")
PY
    sleep 0.5
    after_udp_count=$(grep -c '^UDP received ' "$echo_log_file" || true)
    after_route_count=$(grep -c \
        'www.google.com:39644 dropped by blackhole outbound quic-sni-block' \
        "$server_log_file" || true)
    if (( after_route_count <= before_route_count )); then
        printf 'Xray client did not produce a QUIC SNI route-only decision (route count %s -> %s).\n' \
            "$before_route_count" "$after_route_count" >&2
        cat "$xray_client_log_file" "$server_log_file" "$echo_log_file" >&2
        exit 1
    fi
    if [[ "$after_udp_count" != "$before_udp_count" ]]; then
        printf 'Xray-generated QUIC with www.google.com SNI escaped the route-only block.\n' >&2
        exit 1
    fi
    kill -TERM "$xray_client_pid"
    wait "$xray_client_pid" 2>/dev/null || true
    xray_client_pid=
    printf 'Pinned Xray 26.9.9 client QUIC route-only probe passed.\n'

run_xray_h3_interop() {
    cat >"$xray_client_config_file" <<JSON
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 1081,
    "protocol": "socks",
    "settings": {"udp": true}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "198.18.44.20",
        "port": 39645,
        "users": [{"id": "d342d11e-d424-4583-b36e-524ab1f0afa4", "encryption": "none"}]
      }]
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "site-tls.test",
        "alpn": ["h3"],
        "disableSystemRoot": true,
        "certificates": [{
          "certificateFile": "$repo_root/scripts/fixtures/reverse-site-tls-cert.pem",
          "usage": "verify"
        }]
      },
      "xhttpSettings": {
        "host": "site-tls.test",
        "path": "/xray-tun-e2e",
        "mode": "packet-up"
      }
    }
  }]
}
JSON
    : >"$xray_client_log_file"
    nsenter --net="/proc/$office_client_ns_pid/ns/net" \
        "$xray_bin" run -c "$xray_client_config_file" \
        >"$xray_client_log_file" 2>&1 &
    xray_client_pid=$!
    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import socket
import struct
import time

def receive_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("Xray SOCKS client closed during negotiation")
        result.extend(chunk)
    return bytes(result)

def receive_socks_address(connection, atyp):
    if atyp == 1:
        return receive_exact(connection, 4)
    if atyp == 3:
        length = receive_exact(connection, 1)[0]
        return receive_exact(connection, length)
    if atyp == 4:
        return receive_exact(connection, 16)
    raise RuntimeError(f"unexpected SOCKS address type {atyp}")

deadline = time.monotonic() + 5
while True:
    try:
        control = socket.create_connection(("127.0.0.1", 1081), timeout=0.2)
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise RuntimeError("Xray SOCKS inbound did not become ready")
        time.sleep(0.05)

with control:
    control.settimeout(8)
    control.sendall(b"\x05\x01\x00")
    if receive_exact(control, 2) != b"\x05\x00":
        raise RuntimeError("Xray SOCKS inbound rejected no-auth negotiation")
    control.sendall(b"\x05\x01\x00\x01\xc6\x12\x2c\x14" + struct.pack("!H", 39643))
    response = receive_exact(control, 4)
    if response[1] != 0:
        raise RuntimeError(f"Xray VLESS/XHTTP H3 TCP connect failed: {response!r}")
    receive_socks_address(control, response[3])
    receive_exact(control, 2)
    print("Xray SOCKS TCP connect completed; sending echo payload.", flush=True)
    payload = b"xray-tun-vless-xhttp-h3-tcp"
    control.sendall(payload)
    print("TCP echo payload sent; waiting for reply.", flush=True)
    if receive_exact(control, len(payload)) != payload:
        raise RuntimeError("Xray VLESS/XHTTP H3 TCP echo payload mismatch")

print("Xray VLESS/XHTTP H3 TCP session completed through the live Chimera TUN.")

deadline = time.monotonic() + 5
while True:
    try:
        control = socket.create_connection(("127.0.0.1", 1081), timeout=0.2)
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise RuntimeError("Xray SOCKS inbound stopped before UDP association")
        time.sleep(0.05)

with control:
    control.settimeout(8)
    control.sendall(b"\x05\x01\x00")
    if receive_exact(control, 2) != b"\x05\x00":
        raise RuntimeError("Xray SOCKS inbound rejected UDP no-auth negotiation")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    response = receive_exact(control, 4)
    if response[1] != 0:
        raise RuntimeError(f"Xray SOCKS UDP association failed: {response!r}")
    bound_address = receive_socks_address(control, response[3])
    bound_port = struct.unpack("!H", receive_exact(control, 2))[0]
    if response[3] == 1 and bound_address == b"\x00\x00\x00\x00":
        bound_address = b"\x7f\x00\x00\x01"
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(8)
    target = b"\xc6\x12\x2c\x14" + struct.pack("!H", 39644)
    payload = b"xray-tun-vless-xhttp-h3-udp"
    udp.sendto(b"\x00\x00\x00\x01" + target + payload,
               (socket.inet_ntoa(bound_address), bound_port))
    response, _ = udp.recvfrom(4096)
    if len(response) < 10 or response[:4] != b"\x00\x00\x00\x01":
        raise RuntimeError(f"unexpected SOCKS UDP response header: {response!r}")
    if response[10:] != payload:
        raise RuntimeError(f"Xray VLESS/XHTTP H3 UDP echo payload mismatch: {response!r}")
    udp.close()

print("Xray VLESS/XHTTP H3 UDP session completed through the live Chimera TUN.")
PY
    kill -TERM "$xray_client_pid"
    wait "$xray_client_pid" 2>/dev/null || true
    xray_client_pid=
    printf 'Pinned Xray 26.9.9 VLESS/XHTTP H3 TCP/UDP interoperability probe passed.\n'
}
fi

nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - "$repo_root" <<'PY'
from pathlib import Path
import socket
import sys

repo_root = Path(sys.argv[1])
target = ("198.18.44.20", 39644)
initial = bytes.fromhex(
    (repo_root / "chimera_server_lib/src/session/testdata/quic_v1_google.hex")
    .read_text(encoding="ascii")
)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
    connection.settimeout(0.35)
    connection.sendto(initial, target)
    try:
        connection.recvfrom(2048)
    except TimeoutError:
        pass
    else:
        raise RuntimeError("QUIC Initial SNI www.google.com was not route-only blocked")

    # The flow's route-only SNI decision must stay pinned for later datagrams.
    connection.sendto(b"subsequent-quic-datagram", target)
    try:
        connection.recvfrom(2048)
    except TimeoutError:
        pass
    else:
        raise RuntimeError("subsequent QUIC-flow datagram escaped the SNI route")
print("live TUN QUIC SNI route-only selection and flow pinning passed.")
PY

nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import socket

for family, target in (
    (socket.AF_INET, "198.18.44.20"),
    (socket.AF_INET6, "fd18:198:44::20"),
):
    print(f"testing TCP {target}", flush=True)
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect((target, 39643))
        payload = f"{family}-xray-tun-tcp".encode()
        connection.sendall(payload)
        received = b""
        while len(received) < len(payload):
            chunk = connection.recv(4096)
            if not chunk:
                raise RuntimeError(f"TCP echo closed early for {target}")
            received += chunk
        if received != payload:
            raise RuntimeError(f"TCP echo mismatch for {target}: {received!r}")

    print(f"testing UDP {target}", flush=True)
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        payload = f"{family}-xray-tun-udp".encode()
        connection.sendto(payload, (target, 39644))
        received, peer = connection.recvfrom(4096)
        if received != payload:
            raise RuntimeError(f"UDP echo mismatch for {target}: {received!r}")
        if peer[0] != target:
            raise RuntimeError(f"UDP reply source mismatch for {target}: {peer!r}")
print("Xray TUN live IPv4/IPv6 TCP and UDP echo passed.")
PY

if [[ -n "$xray_bin" ]]; then
    run_xray_h3_interop
    if ! grep -Fq '<- site-tls.test:39645 via direct forwarded' "$server_log_file"; then
        printf 'Full Xray H3 session did not use the route-only SNI in the TUN UDP path.\n' >&2
        cat "$xray_client_log_file" "$xray_reference_server_log_file" "$server_log_file" >&2
        exit 1
    fi
    kill -TERM "$xray_reference_tun_pid"
    wait "$xray_reference_tun_pid" 2>/dev/null || true
    xray_reference_tun_pid=
    if ip link show dev xray-ref-tun >/dev/null 2>&1; then
        printf 'Pinned Xray TUN reference device remained after shutdown.\n' >&2
        exit 1
    fi
    if ip -4 route show table main exact 198.18.45.0/24 | grep -Fq 'xray-ref-tun'; then
        printf 'Pinned Xray TUN IPv4 route remained after shutdown.\n' >&2
        exit 1
    fi
    if ip -6 route show table main exact fd18:198:45::/64 | grep -Fq 'xray-ref-tun'; then
        printf 'Pinned Xray TUN IPv6 route remained after shutdown.\n' >&2
        exit 1
    fi

    # Dedicated second pinned-oracle process, after the complete normal
    # Xray interoperability suite has finished and its interface/routes
    # were verified removed. A 2s level-0 idle deadline isolates the
    # Xray policy/dispatcher cancellation path from the default long-lived
    # zero-window and retransmission controls; no production config
    # or default-oracle expectation is changed.
    cat >"$xray_reference_tun_config_file" <<'JSON'
{
  "log": {"loglevel": "debug"},
  "policy": {"levels": {"0": {"connIdle": 2, "uplinkOnly": 1, "downlinkOnly": 1}}},
  "routing": {"rules": [{
    "type": "field", "network": "tcp", "port": "39647",
    "outboundTag": "immediate-blackhole"
  }]},
  "inbounds": [{
    "tag": "xray-tun-reference",
    "protocol": "tun",
    "settings": {
      "name": "xray-ref-tun",
      "mtu": 1400,
      "gateway": ["10.45.0.1/24", "fd18:45::1/64"],
      "autoSystemRoutingTable": ["198.18.45.0/24", "fd18:198:45::/64"]
    }
  }],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "immediate-blackhole", "protocol": "blackhole"}
  ]
}
JSON
    "$xray_bin" run -c "$xray_reference_tun_config_file" \
        >"$xray_reference_tun_log_file" 2>&1 &
    xray_reference_tun_pid=$!
    idle_reference_ready=false
    for attempt in $(seq 1 100); do
        ipv4_route=$(ip -4 route show table main exact 198.18.45.0/24 2>/dev/null || true)
        ipv6_route=$(ip -6 route show table main exact fd18:198:45::/64 2>/dev/null || true)
        if [[ "$ipv4_route" == *'dev xray-ref-tun'* ]] \
            && [[ "$ipv6_route" == *'dev xray-ref-tun'* ]]; then
            idle_reference_ready=true
            break
        fi
        if ! kill -0 "$xray_reference_tun_pid" 2>/dev/null; then
            printf 'Pinned Xray TUN idle-policy oracle exited before installing routes.\n' >&2
            cat "$xray_reference_tun_log_file" >&2
            exit 1
        fi
        sleep 0.05
    done
    if [[ "$idle_reference_ready" != true ]]; then
        printf 'Pinned Xray TUN idle-policy oracle did not install routes.\n' >&2
        cat "$xray_reference_tun_log_file" >&2
        exit 1
    fi
    run_ipv6_tcp_timewait_reuse_probe fd18:198:45::20 \
        'Xray 26.9.9 TUN idle-policy' idle-policy
    run_ipv6_tcp_blackhole_terminal_probe fd18:198:45::20 \
        'Xray 26.9.9 TUN blackhole'
    kill -TERM "$xray_reference_tun_pid"
    wait "$xray_reference_tun_pid" 2>/dev/null || true
    xray_reference_tun_pid=
    if ip link show dev xray-ref-tun >/dev/null 2>&1; then
        printf 'Pinned Xray idle-policy TUN device remained after shutdown.\n' >&2
        exit 1
    fi
    if ip -4 route show table main exact 198.18.45.0/24 | grep -Fq 'xray-ref-tun'; then
        printf 'Pinned Xray idle-policy IPv4 route remained.\n' >&2
        exit 1
    fi
    if ip -6 route show table main exact fd18:198:45::/64 | grep -Fq 'xray-ref-tun'; then
        printf 'Pinned Xray idle-policy IPv6 route remained.\n' >&2
        exit 1
    fi
fi

run_host_udp_error_queue_probe 198.18.44.20 fd18:198:44::20

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
# The process has exited, but IPv6 route/device netlink teardown may be
# observed a little later in a busy namespace. Wait for *all* owned
# resources to disappear, then keep the same strict leak assertions.
# A genuine persistent route or device still fails after this short bound.
xray_tun_cleanup_complete() {
    ! ip link show dev cxray-tun >/dev/null 2>&1 \
        && ! ip -4 route show table main exact 198.18.44.0/24 | grep -Fq 'cxray-tun' \
        && ! ip -6 route show table main exact fd18:198:44::/64 | grep -Fq 'cxray-tun' \
        && ! ip -4 route show table main exact 10.44.0.0/24 | grep -Fq 'cxray-tun'
}
for attempt in $(seq 1 40); do
    if xray_tun_cleanup_complete; then
        break
    fi
    sleep 0.05
done
if ip link show dev cxray-tun >/dev/null 2>&1; then
    printf 'Xray TUN device remained after graceful shutdown.\n' >&2
    exit 1
fi
if ip -4 route show table main exact 198.18.44.0/24 | grep -Fq 'cxray-tun'; then
    printf 'Xray TUN IPv4 system route remained after graceful shutdown.\n' >&2
    exit 1
fi
if ip -6 route show table main exact fd18:198:44::/64 | grep -Fq 'cxray-tun'; then
    printf 'Xray TUN IPv6 system route remained after graceful shutdown.\n' >&2
    ip -6 route show table main exact fd18:198:44::/64 >&2 || true
    ip -d link show dev cxray-tun >&2 || true
    exit 1
fi
if ip -4 route show table main exact 10.44.0.0/24 | grep -Fq 'cxray-tun'; then
    printf 'Xray TUN IPv4 gateway route remained after graceful shutdown.\n' >&2
    exit 1
fi
if (( bulk_echo_failures > 0 )); then
    printf 'Full-MSS bulk downlink probe failed for %d implementation(s).\n' "$bulk_echo_failures" >&2
    exit 1
fi
if (( seeded_netem_failures > 0 )); then
    printf 'Seeded netem retransmission probe failed for %d implementation(s).\n' "$seeded_netem_failures" >&2
    exit 1
fi
if (( server_rx_pressure_failures > 0 )); then
    printf 'True server receive-window parity probe failed in %d implementation(s); the independent dual-stack/cleanup checks above still ran.\n' "$server_rx_pressure_failures" >&2
    exit 1
fi
printf 'Xray TUN live IPv4/IPv6 TCP/UDP forwarding, route conflict rollback, and shutdown cleanup passed in an isolated network namespace.\n'
NAMESPACE_SCRIPT
