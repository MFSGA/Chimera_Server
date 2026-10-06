#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_mode=${1:-full}
if (( $# > 1 )) || [[ "$test_mode" != full && "$test_mode" != --xray-bridge-offline-only ]]; then
    printf 'Usage: XRAY_BIN=<fixed-xray-26.9.9> %s [--xray-bridge-offline-only]\n' "$0" >&2
    exit 2
fi
test_host_uid=$(id -u)
test_user_name=$(id -un)
test_subuid_record=$(awk -F: -v name="$test_user_name" '$1 == name { print $2 ":" $3; exit }' /etc/subuid)
if [[ -z "$test_subuid_record" ]]; then
    printf 'A subordinate UID range for %s in /etc/subuid is required.\n' "$test_user_name" >&2
    exit 1
fi
test_subuid_start=${test_subuid_record%%:*}
test_subuid_count=${test_subuid_record#*:}
if (( test_subuid_count < 1 )); then
    printf 'The subordinate UID range for %s is empty.\n' "$test_user_name" >&2
    exit 1
fi
for command_name in cargo unshare nsenter ip sysctl python3; do
    command -v "$command_name" >/dev/null
done

xray_bin=${XRAY_BIN:-"$repo_root/xray"}
if [[ "$xray_bin" != /* ]]; then
    xray_bin="$repo_root/$xray_bin"
fi
if [[ ! -x "$xray_bin" ]]; then
    printf 'Xray executable not found at %s; set XRAY_BIN to the fixed Xray 26.9.9 binary.\n' "$xray_bin" >&2
    exit 1
fi
printf 'Using %s\n' "$("$xray_bin" version | head -n 1)"
cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features tun-gateway,vless-reverse-tls --locked
export XRAY_BIN="$xray_bin"

unshare \
    --user \
    --map-users="0:${test_host_uid}:1" \
    --map-users="1:${test_subuid_start}:${test_subuid_count}" \
    --net \
bash -s -- "$test_mode" <<'NAMESPACE_SCRIPT'
set -euo pipefail
test_mode=$1
trap 'exit_status=$?; printf "Xray Edge TUN smoke failed with status %s at line %s: %s\\n" "$exit_status" "$LINENO" "$BASH_COMMAND" >&2' ERR

edge_ns_pid=
lan_ns_pid=
office_ns_pid=
hub_pid=
xray_pid=
server_pid=
tcp_echo_pid=
udp_echo_pid=
tcp_echo_v6_pid=
udp_echo_v6_pid=
policy_probe_pid=
offline_udp_client_pid=
smoke_dir=$(mktemp -d)
server_log_file=$smoke_dir/server.log
hub_log_file=$smoke_dir/hub.log
xray_log_file=$smoke_dir/xray.log
tcp_echo_log_file=$smoke_dir/tcp-echo.log
udp_echo_log_file=$smoke_dir/udp-echo.log
tcp_echo_v6_log_file=$smoke_dir/tcp-v6-echo.log
udp_echo_v6_log_file=$smoke_dir/udp-v6-echo.log
policy_probe_log_file=$smoke_dir/policy-probes.log
server_config_file=$smoke_dir/server.yaml
wrong_server_config_file=$smoke_dir/server-wrong-sni.yaml
hub_config_file=$smoke_dir/hub.yaml
xray_config_file=$smoke_dir/xray.json

cleanup() {
    exit_status=$?
    trap - EXIT
    for process_pid in "$server_pid" "$xray_pid" "$hub_pid" "$tcp_echo_pid" "$udp_echo_pid" "$tcp_echo_v6_pid" "$udp_echo_v6_pid" "$policy_probe_pid" "$offline_udp_client_pid"; do
        if [[ -n "$process_pid" ]] && kill -0 "$process_pid" 2>/dev/null; then
            kill -TERM "$process_pid" 2>/dev/null || true
            wait "$process_pid" 2>/dev/null || true
        fi
    done
    for namespace_pid in "$edge_ns_pid" "$lan_ns_pid" "$office_ns_pid"; do
        if [[ -n "$namespace_pid" ]] && kill -0 "$namespace_pid" 2>/dev/null; then
            kill -TERM "$namespace_pid" 2>/dev/null || true
            wait "$namespace_pid" 2>/dev/null || true
        fi
    done
    if (( exit_status != 0 )); then
        for diagnostic_file in "$server_log_file" "$hub_log_file" "$xray_log_file" "$tcp_echo_log_file" "$udp_echo_log_file" "$tcp_echo_v6_log_file" "$udp_echo_v6_log_file" "$policy_probe_log_file"; do
            printf '\n--- %s ---\n' "$diagnostic_file" >&2
            cat "$diagnostic_file" >&2 2>/dev/null || true
        done
    fi
    rm -rf "$smoke_dir"
    exit "$exit_status"
}
trap cleanup EXIT

ip link set lo up
unshare --net sleep infinity >/dev/null 2>&1 &
edge_ns_pid=$!
unshare --net sleep infinity >/dev/null 2>&1 &
lan_ns_pid=$!
unshare --net sleep infinity >/dev/null 2>&1 &
office_ns_pid=$!

# Isolate the Xray Edge, remote LAN endpoint and Office host from the Gateway.
ip link add gateway-edge type veth peer name xray-edge
ip addr add 10.252.0.1/30 dev gateway-edge
ip link set gateway-edge up
ip link set xray-edge netns "$edge_ns_pid"
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$edge_ns_pid/ns/net" ip addr add 10.252.0.2/30 dev xray-edge
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set xray-edge up
ip link add xray-lan type veth peer name lan-xray
ip link set xray-lan netns "$edge_ns_pid"
ip link set lan-xray netns "$lan_ns_pid"
nsenter --net="/proc/$edge_ns_pid/ns/net" ip addr add 10.253.0.1/30 dev xray-lan
nsenter --net="/proc/$edge_ns_pid/ns/net" ip -6 addr add fd18:253::1/64 nodad dev xray-lan
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set xray-lan up
nsenter --net="/proc/$edge_ns_pid/ns/net" ip route add 198.18.0.20/32 via 10.253.0.2 dev xray-lan
nsenter --net="/proc/$edge_ns_pid/ns/net" ip -6 route add fd18:198:18::/64 via fd18:253::2 dev xray-lan
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.2/30 dev lan-xray
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:253::2/64 nodad dev lan-xray
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 198.18.0.20/32 dev lan-xray
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:198:18::20/128 nodad dev lan-xray
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set lan-xray up

ip link add office-gw type veth peer name office-client
ip addr add 10.251.0.1/24 dev office-gw
ip link set office-gw up
ip link set office-client netns "$office_ns_pid"
nsenter --net="/proc/$office_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$office_ns_pid/ns/net" ip addr add 10.251.0.2/24 dev office-client
ip -6 addr add fd18:251::1/64 nodad dev office-gw
nsenter --net="/proc/$office_ns_pid/ns/net" ip -6 addr add fd18:251::2/64 nodad dev office-client
nsenter --net="/proc/$office_ns_pid/ns/net" ip link set office-client up
nsenter --net="/proc/$office_ns_pid/ns/net" ip route add 198.18.0.0/24 via 10.251.0.1
nsenter --net="/proc/$office_ns_pid/ns/net" ip -6 route add fd18:198:18::/64 via fd18:251::1

# This self-signed SAN certificate is a test fixture. Both clients explicitly
# trust it; it is not suitable for a deployed Hub.
cat >"$hub_config_file" <<'YAML'
log:
  loglevel: debug
shutdown:
  gracePeriodSeconds: 1
inbounds:
  - listen: 0.0.0.0
    port: 39643
    protocol: vless
    tag: hub-vless-in
    settings:
      clients:
        - id: 3ac9b383-75a1-431c-8184-106c80eb2274
          email: office-gateway@example.test
        - id: 3ac9b383-75a1-431c-8184-106c80eb2275
          email: xray-edge@example.test
          reverse:
            tag: xray-site
      decryption: none
    streamSettings:
      network: tcp
      security: tls
      tlsSettings:
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            keyFile: scripts/fixtures/reverse-site-tls-key.pem
outbounds:
  - tag: direct
    protocol: freedom
routing:
  rules:
    - type: field
      ip: [198.18.0.0/24, fd18:198:18::/64]
      outboundTag: xray-site
YAML

cat >"$server_config_file" <<'YAML'
log:
  loglevel: warning
inbounds: []
outbounds:
  - tag: direct
    protocol: freedom
  - tag: to-hub
    protocol: vless
    settings:
      vnext:
        - address: 127.0.0.1
          port: 39643
          users:
            - id: 3ac9b383-75a1-431c-8184-106c80eb2274
              encryption: none
    streamSettings:
      network: tcp
      security: tls
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
routing:
  rules:
    - type: field
      inboundTag: [xray-tun]
      network: [tcp, udp]
      ip: [198.18.0.0/24, fd18:198:18::/64]
      outboundTag: to-hub
shutdown:
  gracePeriodSeconds: 1
tunGateway:
  name: chimera-xray
  address: 10.254.0.1/24
  ipv6Address: fd00:254::1/64
  inboundTag: xray-tun
YAML

cat >"$xray_config_file" <<'JSON'
{
  "log": {"loglevel": "debug"},
  "outbounds": [
    {
      "tag": "site-xray-bridge",
      "protocol": "vless",
      "settings": {
        "address": "10.252.0.1",
        "port": 39643,
        "id": "3ac9b383-75a1-431c-8184-106c80eb2275",
        "encryption": "none",
        "reverse": {"tag": "xray-edge-in"}
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "site-tls.test",
          "disableSystemRoot": true,
          "certificates": [{
            "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
            "usage": "verify"
          }]
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "finalRules": [
          {"action": "allow", "network": "tcp", "ip": ["198.18.0.0/24"], "port": "39641"},
          {"action": "allow", "network": "udp", "ip": ["198.18.0.0/24"], "port": "39642"},
          {"action": "allow", "network": "tcp", "ip": ["fd18:198:18::/64"], "port": "39641"},
          {"action": "allow", "network": "udp", "ip": ["fd18:198:18::/64"], "port": "39642"}
        ]
      }
    }
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["xray-edge-in"], "network": "tcp", "outboundTag": "direct"},
      {"type": "field", "inboundTag": ["xray-edge-in"], "network": "udp", "outboundTag": "direct"}
    ]
  }
}
JSON

"$XRAY_BIN" run -test -c "$xray_config_file"

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$tcp_echo_log_file" 2>&1 &
import socket
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("198.18.0.20", 39641))
listener.listen(8)
print("tcp-ready", flush=True)
while True:
    connection, _ = listener.accept()
    with connection:
        while payload := connection.recv(4096):
            print(f"tcp-received {payload!r}", flush=True)
            connection.sendall(payload)
PY
tcp_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$udp_echo_log_file" 2>&1 &
import socket
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("198.18.0.20", 39642))
print("udp-ready", flush=True)
while True:
    payload, peer = listener.recvfrom(8192)
    if payload.startswith(b"xray-bridge-offline-"):
        print(f"udp-marker-received {payload!r} from {peer}", flush=True)
    else:
        print(f"udp-received {len(payload)} bytes from {peer}", flush=True)
    listener.sendto(payload, peer)
PY
udp_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$tcp_echo_v6_log_file" 2>&1 &
import socket
listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("fd18:198:18::20", 39641))
listener.listen(8)
print("tcp-v6-ready", flush=True)
while True:
    connection, _ = listener.accept()
    with connection:
        while payload := connection.recv(4096):
            print(f"tcp-v6-received {payload!r}", flush=True)
            connection.sendall(payload)
PY
tcp_echo_v6_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$udp_echo_v6_log_file" 2>&1 &
import socket
listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
listener.bind(("fd18:198:18::20", 39642))
print("udp-v6-ready", flush=True)
while True:
    payload, peer = listener.recvfrom(8192)
    print(f"udp-v6-received {len(payload)} bytes from {peer}", flush=True)
    listener.sendto(payload, peer)
PY
udp_echo_v6_pid=$!

# Keep disallowed targets open in the remote LAN so the test distinguishes an
# Edge-side policy denial from an absent service or an unreachable route.
nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$policy_probe_log_file" 2>&1 &
import socket
import threading

listeners = []
for family, address in (
    (socket.AF_INET, "198.18.0.20"),
    (socket.AF_INET6, "fd18:198:18::20"),
):
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    tcp.bind((address, 39643))
    tcp.listen(8)
    listeners.append(("tcp", family, tcp))

    udp = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    udp.bind((address, 39644))
    listeners.append(("udp", family, udp))

def tcp_loop(family, listener):
    label = "v4" if family == socket.AF_INET else "v6"
    while True:
        connection, _ = listener.accept()
        with connection:
            payload = connection.recv(4096)
            print(f"denied-tcp-{label} {payload!r}", flush=True)
            if payload:
                connection.sendall(payload)

def udp_loop(family, listener):
    label = "v4" if family == socket.AF_INET else "v6"
    while True:
        payload, peer = listener.recvfrom(4096)
        print(f"denied-udp-{label} {payload!r}", flush=True)
        listener.sendto(payload, peer)

for kind, family, listener in listeners:
    target = tcp_loop if kind == "tcp" else udp_loop
    threading.Thread(target=target, args=(family, listener), daemon=True).start()
print("policy-probes-ready", flush=True)
PY
policy_probe_pid=$!

for _ in $(seq 1 100); do
    if grep -q '^tcp-ready$' "$tcp_echo_log_file" \
        && grep -q '^udp-ready$' "$udp_echo_log_file" \
        && grep -q '^tcp-v6-ready$' "$tcp_echo_v6_log_file" \
        && grep -q '^udp-v6-ready$' "$udp_echo_v6_log_file" \
        && grep -q '^policy-probes-ready$' "$policy_probe_log_file"; then break; fi
    sleep 0.05
done
grep -q '^tcp-ready$' "$tcp_echo_log_file"
grep -q '^udp-ready$' "$udp_echo_log_file"
grep -q '^tcp-v6-ready$' "$tcp_echo_v6_log_file"
grep -q '^udp-v6-ready$' "$udp_echo_v6_log_file"
grep -q '^policy-probes-ready$' "$policy_probe_log_file"

RUST_LOG=chimera_server_lib::handler::vless_reverse=info \
target/debug/chimera_server_app --config "$hub_config_file" >"$hub_log_file" 2>&1 &
hub_pid=$!
sleep 0.2
if ! kill -0 "$hub_pid" 2>/dev/null; then
    printf 'Hub Chimera exited before opening its VLESS listener.\n' >&2
    exit 1
fi
nsenter --net="/proc/$edge_ns_pid/ns/net" "$XRAY_BIN" run -c "$xray_config_file" >"$xray_log_file" 2>&1 &
xray_pid=$!
xray_worker_ready=false
for _ in $(seq 1 120); do
    if grep -q 'vless_reverse_portal_worker_attached' "$hub_log_file"; then
        xray_worker_ready=true
        break
    fi
    if ! kill -0 "$xray_pid" 2>/dev/null; then
        printf 'Xray Edge exited while connecting to the Hub Reverse portal.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$xray_worker_ready" != true ]]; then
    printf 'Xray Edge did not attach a Reverse worker to the Hub within 12 seconds.\n' >&2
    exit 1
fi

start_tun_gateway() {
    local config_file=$1
    RUST_LOG=chimera_server_lib::tun_gateway=warn target/debug/chimera_server_app \
        --config "$config_file" >>"$server_log_file" 2>&1 &
    server_pid=$!
    local tun_ready=false
    for _ in $(seq 1 100); do
        if ip link show dev chimera-xray >/dev/null 2>&1; then
            tun_ready=true
            break
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then
            printf 'TUN Gateway Chimera exited before creating its TUN device.\n' >&2
            return 1
        fi
        sleep 0.05
    done
    if [[ "$tun_ready" != true ]]; then
        printf 'TUN Gateway Chimera did not create its TUN device within 5 seconds.\n' >&2
        return 1
    fi
    ip -o -6 addr show dev chimera-xray | grep -F 'fd00:254::1/64' >/dev/null
    ip route replace 198.18.0.0/24 dev chimera-xray
    ip -6 route replace fd18:198:18::/64 dev chimera-xray
    sysctl -q -w net.ipv4.conf.chimera-xray.rp_filter=0
}

stop_tun_gateway() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid"
        wait "$server_pid"
    fi
    server_pid=
    for _ in $(seq 1 100); do
        if ! ip link show dev chimera-xray >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
    done
    printf 'TUN device remained after Gateway shutdown.\n' >&2
    return 1
}

: >"$server_log_file"
start_tun_gateway "$server_config_file"
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.office-gw.rp_filter=0

if [[ "$test_mode" == --xray-bridge-offline-only ]]; then
    offline_udp_client_program=$(cat <<'PY'
import socket
import sys

target = ("198.18.0.20", 39642)
baseline = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
baseline.settimeout(5)
baseline_marker = b"xray-bridge-offline-baseline"
baseline.sendto(baseline_marker, target)
reply, source = baseline.recvfrom(128)
if reply != baseline_marker or source != target:
    raise SystemExit(f"unexpected baseline UDP echo: {reply!r} from {source!r}")
print("baseline-ready", flush=True)

if sys.stdin.readline().strip() != "probe-offline":
    raise SystemExit("missing offline UDP probe trigger")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
sock.sendto(b"xray-bridge-offline-no-worker", target)
source_port = sock.getsockname()[1]
try:
    reply, source = sock.recvfrom(128)
except TimeoutError:
    print("udp-dropped-no-worker", flush=True)
else:
    raise SystemExit(f"UDP unexpectedly replied while Xray Bridge was offline: {reply!r} from {source!r}")

if sys.stdin.readline().strip() != "probe-recovered":
    raise SystemExit("missing recovered UDP probe trigger")

sent_payloads = set()
for attempt in range(1, 13):
    payload = f"xray-bridge-offline-recovered-{attempt}".encode()
    sent_payloads.add(payload)
    sock.sendto(payload, target)
    sock.settimeout(0.5)
    try:
        reply, source = sock.recvfrom(128)
    except TimeoutError:
        continue
    if reply not in sent_payloads or source != target:
        raise SystemExit(f"unexpected recovered UDP echo: {reply!r} from {source!r}")
    if sock.getsockname()[1] != source_port:
        raise SystemExit("UDP source port changed across Bridge outage recovery")
    print(f"udp-recovered-same-tuple-{attempt}", flush=True)
    break
else:
    raise SystemExit("same-tuple UDP did not recover after Xray Bridge reattachment")

baseline.close()
sock.close()
PY
)
    coproc XRAY_OFFLINE_UDP_CLIENT {
        nsenter --net="/proc/$office_ns_pid/ns/net" python3 -u -c "$offline_udp_client_program"
    }
    offline_udp_client_pid=$XRAY_OFFLINE_UDP_CLIENT_PID
    offline_udp_read_fd=${XRAY_OFFLINE_UDP_CLIENT[0]}
    offline_udp_write_fd=${XRAY_OFFLINE_UDP_CLIENT[1]}
    if ! IFS= read -r -t 8 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != baseline-ready ]]; then
        printf 'Xray Edge baseline UDP path did not become ready.\n' >&2
        exit 1
    fi

    portal_attach_count_before_outage=$(grep -c 'vless_reverse_portal_worker_attached' "$hub_log_file" || true)
    if (( portal_attach_count_before_outage != 1 )); then
        printf 'Expected one Xray Bridge worker before outage, observed %s.\n' "$portal_attach_count_before_outage" >&2
        exit 1
    fi
    kill -TERM "$xray_pid"
    wait "$xray_pid" || true
    xray_pid=
    sleep 0.25
    if ! kill -0 "$hub_pid" 2>/dev/null || ! kill -0 "$server_pid" 2>/dev/null; then
        printf 'Hub or TUN Gateway exited while stopping the Xray Bridge.\n' >&2
        exit 1
    fi
    printf 'probe-offline\n' >&"$offline_udp_write_fd"
    if ! IFS= read -r -t 5 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != udp-dropped-no-worker ]]; then
        printf 'Live TUN UDP did not fail closed while the only Xray Bridge was offline.\n' >&2
        exit 1
    fi
    if grep -Fq "udp-marker-received b'xray-bridge-offline-no-worker'" "$udp_echo_log_file"; then
        printf 'The Edge LAN received the offline-only UDP marker.\n' >&2
        exit 1
    fi

    nsenter --net="/proc/$edge_ns_pid/ns/net" "$XRAY_BIN" run -c "$xray_config_file" >>"$xray_log_file" 2>&1 &
    xray_pid=$!
    xray_worker_ready=false
    for _ in $(seq 1 300); do
        portal_attach_count=$(grep -c 'vless_reverse_portal_worker_attached' "$hub_log_file" || true)
        if (( portal_attach_count > portal_attach_count_before_outage )); then
            xray_worker_ready=true
            break
        fi
        if ! kill -0 "$xray_pid" 2>/dev/null; then
            printf 'Xray Edge exited before reattaching to the live TLS Hub.\n' >&2
            exit 1
        fi
        sleep 0.1
    done
    if [[ "$xray_worker_ready" != true ]]; then
        printf 'Xray TLS Reverse Bridge did not reattach after outage within 30 seconds.\n' >&2
        exit 1
    fi
    printf 'probe-recovered\n' >&"$offline_udp_write_fd"
    if ! IFS= read -r -t 8 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != udp-recovered-same-tuple-* ]]; then
        printf 'Live TUN UDP tuple did not recover after Xray Bridge reattachment.\n' >&2
        exit 1
    fi
    if ! wait "$offline_udp_client_pid"; then
        printf 'Xray Bridge outage UDP client exited with an error.\n' >&2
        exit 1
    fi
    offline_udp_client_pid=
    grep -Fq "udp-marker-received b'xray-bridge-offline-baseline'" "$udp_echo_log_file"
    grep -Fq "udp-marker-received b'xray-bridge-offline-recovered-" "$udp_echo_log_file"
    if grep -Fq "udp-marker-received b'xray-bridge-offline-no-worker'" "$udp_echo_log_file"; then
        printf 'The Edge LAN received the offline-only UDP marker after recovery.\n' >&2
        exit 1
    fi
    kill -0 "$hub_pid"
    kill -0 "$server_pid"
    kill -0 "$xray_pid"
    stop_tun_gateway
    printf 'Fixed Xray TLS Bridge UDP failed closed with no worker and recovered on the same live-TUN source/target tuple after reattachment.\n'
    exit 0
fi

nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket
import time

tcp_deadline = time.monotonic() + 12
while time.monotonic() < tcp_deadline:
    try:
        with socket.create_connection(("198.18.0.20", 39641), timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(b"office-to-xray-edge-tcp")
            reply = connection.recv(128)
            if reply == b"office-to-xray-edge-tcp":
                break
    except OSError:
        pass
    time.sleep(0.1)
else:
    raise SystemExit("Xray Edge TCP path did not recover within 12 seconds")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(0.5)
for payload in (b"office-to-xray-edge-udp", bytes(index % 251 for index in range(4096))):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        udp.sendto(payload, ("198.18.0.20", 39642))
        try:
            reply, source = udp.recvfrom(8192)
        except TimeoutError:
            continue
        if reply == payload and source == ("198.18.0.20", 39642):
            break
        raise SystemExit(f"unexpected Xray Edge UDP response: {len(reply)} bytes from {source!r}")
    else:
        raise SystemExit(f"Xray Edge UDP path did not recover for {len(payload)} bytes")
udp.close()

with socket.create_connection(("fd18:198:18::20", 39641), timeout=8) as connection:
    connection.settimeout(8)
    connection.sendall(b"office-to-xray-edge-v6-tcp")
    reply = connection.recv(128)
    if reply != b"office-to-xray-edge-v6-tcp":
        raise SystemExit(f"unexpected Xray Edge IPv6 TCP response: {reply!r}")

udp_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp_v6.settimeout(0.5)
for payload in (b"office-to-xray-edge-v6-udp", bytes(index % 251 for index in range(4096))):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        udp_v6.sendto(payload, ("fd18:198:18::20", 39642))
        try:
            reply, source = udp_v6.recvfrom(8192)
        except TimeoutError:
            continue
        if reply == payload and source[:2] == ("fd18:198:18::20", 39642):
            break
        raise SystemExit(f"unexpected Xray Edge IPv6 UDP response: {len(reply)} bytes from {source!r}")
    else:
        raise SystemExit(f"Xray Edge IPv6 UDP path did not recover for {len(payload)} bytes")
udp_v6.close()

def probe_denied_tcp(family, address, marker):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect((address, 39643))
            client.sendall(marker)
            try:
                reply = client.recv(128)
            except TimeoutError:
                return
            if reply == marker:
                raise SystemExit(f"disallowed TCP target replied with {reply!r}")
    except OSError:
        # Xray can close a denied TCP session before the LAN listener is dialed.
        pass

def probe_denied_udp(family, address, marker):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(1.5)
        client.sendto(marker, (address, 39644))
        try:
            reply, _ = client.recvfrom(4096)
        except TimeoutError:
            return
        raise SystemExit(f"disallowed UDP target replied with {reply!r}")

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    probe_denied_tcp(family, address, f"forbidden-{label}-tcp".encode())
    probe_denied_udp(family, address, f"forbidden-{label}-udp".encode())
PY

grep -Fq "tcp-received b'office-to-xray-edge-tcp'" "$tcp_echo_log_file"
grep -Fq 'udp-received 23 bytes' "$udp_echo_log_file"
grep -Fq 'udp-received 4096 bytes' "$udp_echo_log_file"
grep -Fq "tcp-v6-received b'office-to-xray-edge-v6-tcp'" "$tcp_echo_v6_log_file"
grep -Fq 'udp-v6-received 26 bytes' "$udp_echo_v6_log_file"
grep -Fq 'udp-v6-received 4096 bytes' "$udp_echo_v6_log_file"
sleep 0.25
for marker in forbidden-v4-tcp forbidden-v4-udp forbidden-v6-tcp forbidden-v6-udp; do
    if grep -Fq "$marker" "$policy_probe_log_file"; then
        printf 'Xray Edge policy allowed forbidden marker %s to reach the LAN.\n' "$marker" >&2
        exit 1
    fi
done

# Exercise the Office Gateway's TLS identity check through real TUN traffic.
# With only the SNI changed, neither TCP nor UDP probes may reach the live Edge
# LAN. Restoring the valid SNI must restore the same dual-stack paths.
sed 's/serverName: site-tls.test/serverName: wrong-site-tls.test/' \
    "$server_config_file" >"$wrong_server_config_file"
grep -Fq 'serverName: wrong-site-tls.test' "$wrong_server_config_file"
stop_tun_gateway
start_tun_gateway "$wrong_server_config_file"
nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp_target = (address, 39641) if family == socket.AF_INET else (address, 39641, 0, 0)
    tcp_marker = f"office-wrong-sni-{label}-tcp".encode()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(tcp_target)
            connection.sendall(tcp_marker)
            reply = connection.recv(128)
            if reply:
                raise SystemExit(f"wrong TLS SNI forwarded {label} TCP data: {reply!r}")
    except OSError:
        pass

    udp_target = (address, 39642) if family == socket.AF_INET else (address, 39642, 0, 0)
    udp_marker = f"office-wrong-sni-{label}-udp-no-reply".encode()
    with socket.socket(family, socket.SOCK_DGRAM) as datagram:
        datagram.settimeout(1)
        datagram.sendto(udp_marker, udp_target)
        try:
            reply, source = datagram.recvfrom(8192)
        except TimeoutError:
            continue
        raise SystemExit(f"wrong TLS SNI forwarded {label} UDP data: {reply!r} from {source!r}")
PY
sleep 0.25
for marker in office-wrong-sni-v4-tcp office-wrong-sni-v6-tcp; do
    if grep -Fq "$marker" "$tcp_echo_log_file" "$tcp_echo_v6_log_file"; then
        printf 'Wrong TLS SNI allowed marker %s to reach the Edge LAN.\n' "$marker" >&2
        exit 1
    fi
done
stop_tun_gateway
start_tun_gateway "$server_config_file"
nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp_target = (address, 39641) if family == socket.AF_INET else (address, 39641, 0, 0)
    tcp_marker = f"office-restored-after-wrong-sni-{label}-tcp".encode()
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(tcp_target)
        connection.sendall(tcp_marker)
        if connection.recv(128) != tcp_marker:
            raise SystemExit(f"valid TLS SNI did not restore {label} TCP forwarding")

    udp_target = (address, 39642) if family == socket.AF_INET else (address, 39642, 0, 0)
    udp_marker = f"office-restored-after-wrong-sni-{label}-udp".encode()
    with socket.socket(family, socket.SOCK_DGRAM) as datagram:
        datagram.settimeout(8)
        datagram.sendto(udp_marker, udp_target)
        reply, source = datagram.recvfrom(8192)
        if reply != udp_marker or source[:2] != (address, 39642):
            raise SystemExit(f"valid TLS SNI did not restore {label} UDP forwarding: {reply!r} from {source!r}")
PY
grep -Fq "tcp-received b'office-restored-after-wrong-sni-v4-tcp'" "$tcp_echo_log_file"
grep -Fq "tcp-v6-received b'office-restored-after-wrong-sni-v6-tcp'" "$tcp_echo_v6_log_file"

# Verify that both the Office VLESS/TLS outbound and the Xray TLS Reverse
# Bridge recover after the Hub process restarts with the same certificate.
kill -TERM "$hub_pid"
wait "$hub_pid"
hub_pid=
sleep 0.2
RUST_LOG=chimera_server_lib::handler::vless_reverse=info \
target/debug/chimera_server_app --config "$hub_config_file" >"$hub_log_file" 2>&1 &
hub_pid=$!
hub_ready=false
for _ in $(seq 1 300); do
    if python3 - <<'PY'
import socket

try:
    with socket.create_connection(("127.0.0.1", 39643), timeout=0.1):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
        hub_ready=true
        break
    fi
    if ! kill -0 "$hub_pid" 2>/dev/null; then
        printf 'TLS Hub exited while restarting for the Reverse reconnect test.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$hub_ready" != true ]]; then
    printf 'TLS Hub did not reopen its VLESS listener within 30 seconds.\n' >&2
    exit 1
fi
xray_worker_ready=false
for _ in $(seq 1 300); do
    if grep -q 'vless_reverse_portal_worker_attached' "$hub_log_file"; then
        xray_worker_ready=true
        break
    fi
    if ! kill -0 "$xray_pid" 2>/dev/null; then
        printf 'Xray Edge exited during TLS Hub reconnect.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$xray_worker_ready" != true ]]; then
    printf 'Xray TLS Reverse Bridge did not reattach within 30 seconds.\n' >&2
    exit 1
fi
nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket
import time

tcp_marker = b"office-to-xray-edge-tls-after-hub-restart"
tcp_deadline = time.monotonic() + 30
while time.monotonic() < tcp_deadline:
    try:
        with socket.create_connection(("198.18.0.20", 39641), timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(tcp_marker)
            if connection.recv(128) == tcp_marker:
                break
    except OSError:
        pass
    time.sleep(0.1)
else:
    raise SystemExit("TLS Reverse TCP path did not recover after Hub restart")

udp_marker = b"office-to-xray-edge-tls-udp-after-hub-restart"
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(0.5)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    udp.sendto(udp_marker, ("198.18.0.20", 39642))
    try:
        reply, source = udp.recvfrom(8192)
    except TimeoutError:
        continue
    if reply != udp_marker or source != ("198.18.0.20", 39642):
        raise SystemExit(f"unexpected TLS Reverse UDP response: {reply!r} from {source!r}")
    break
else:
    raise SystemExit("TLS Reverse UDP path did not recover after Hub restart")
udp.close()
PY
grep -Fq "tcp-received b'office-to-xray-edge-tls-after-hub-restart'" "$tcp_echo_log_file"
grep -Fq 'udp-received 45 bytes' "$udp_echo_log_file"

# Restart only the Xray Edge Bridge while the TLS Hub and Office Gateway stay
# alive. The Portal must accept a new TLS/VLESS worker before new TCP/UDP flows
# can use the site again.
portal_attach_count_before_edge_restart=$(grep -c 'vless_reverse_portal_worker_attached' "$hub_log_file" || true)
kill -TERM "$xray_pid"
wait "$xray_pid" || true
xray_pid=
sleep 0.2
nsenter --net="/proc/$edge_ns_pid/ns/net" "$XRAY_BIN" run -c "$xray_config_file" >>"$xray_log_file" 2>&1 &
xray_pid=$!
xray_worker_ready=false
for _ in $(seq 1 300); do
    portal_attach_count=$(grep -c 'vless_reverse_portal_worker_attached' "$hub_log_file" || true)
    if (( portal_attach_count > portal_attach_count_before_edge_restart )); then
        xray_worker_ready=true
        break
    fi
    if ! kill -0 "$xray_pid" 2>/dev/null; then
        printf 'Xray Edge exited while reconnecting to the live TLS Hub.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$xray_worker_ready" != true ]]; then
    printf 'Xray TLS Reverse Bridge did not reattach after its own restart within 30 seconds.\n' >&2
    exit 1
fi
nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket
import time

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp_target = (address, 39641) if family == socket.AF_INET else (address, 39641, 0, 0)
    tcp_marker = f"office-to-xray-edge-tls-after-edge-restart-{label}".encode()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(1)
                connection.connect(tcp_target)
                connection.sendall(tcp_marker)
                if connection.recv(128) == tcp_marker:
                    break
        except OSError:
            pass
        time.sleep(0.1)
    else:
        raise SystemExit(f"TLS Reverse {label} TCP path did not recover after Edge restart")

    udp_target = (address, 39642) if family == socket.AF_INET else (address, 39642, 0, 0)
    udp_marker = f"office-to-xray-edge-tls-udp-after-edge-restart-{label}".encode()
    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.settimeout(0.5)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        udp.sendto(udp_marker, udp_target)
        try:
            reply, source = udp.recvfrom(8192)
        except TimeoutError:
            continue
        if reply != udp_marker or source[:2] != (address, 39642):
            raise SystemExit(f"unexpected TLS Reverse {label} UDP response: {reply!r} from {source!r}")
        break
    else:
        raise SystemExit(f"TLS Reverse {label} UDP path did not recover after Edge restart")
    udp.close()
PY
grep -Fq "tcp-received b'office-to-xray-edge-tls-after-edge-restart-v4'" "$tcp_echo_log_file"
grep -Fq "tcp-v6-received b'office-to-xray-edge-tls-after-edge-restart-v6'" "$tcp_echo_v6_log_file"
edge_restart_udp_marker=office-to-xray-edge-tls-udp-after-edge-restart-v4
grep -Fq "udp-received ${#edge_restart_udp_marker} bytes" "$udp_echo_log_file"
edge_restart_udp_v6_marker=office-to-xray-edge-tls-udp-after-edge-restart-v6
grep -Fq "udp-v6-received ${#edge_restart_udp_v6_marker} bytes" "$udp_echo_v6_log_file"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
if ip link show dev chimera-xray >/dev/null 2>&1; then
    printf 'TUN device remained after Gateway shutdown.\n' >&2
    exit 1
fi
printf 'Ordinary Office LAN IPv4/IPv6 TCP and UDP (including 4 KiB) reached allowed Xray Edge LAN targets; live but disallowed TCP/UDP targets remained untouched for both families; wrong Office TLS SNI blocked dual-stack TCP/UDP and restoring the valid SNI restored forwarding; TLS Reverse IPv4/IPv6 TCP/UDP recovered after Hub restart and Edge restart; TUN teardown passed.\n'
NAMESPACE_SCRIPT
