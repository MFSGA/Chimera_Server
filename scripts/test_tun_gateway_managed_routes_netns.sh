#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
host_uid=$(id -u)
tun_gateway_mtu=${TUN_GATEWAY_MTU:-1500}
if [[ ! "$tun_gateway_mtu" =~ ^[0-9]+$ ]] \
    || (( tun_gateway_mtu < 1280 || tun_gateway_mtu > 9000 )); then
    printf 'TUN_GATEWAY_MTU must be an integer from 1280 to 9000.\n' >&2
    exit 2
fi
for command_name in cargo unshare ip python3; do
    command -v "$command_name" >/dev/null
done

cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features tun-gateway,vless-reverse --locked

unshare --user --map-users="0:${host_uid}:1" --net bash -s -- "$repo_root" "$tun_gateway_mtu" <<'NAMESPACE_SCRIPT'
set -euo pipefail
repo_root=$1
tun_gateway_mtu=$2
ip link set lo up
office_client_ns_pid=
site_lan_ns_pid=
echo_server_pid=
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
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route add 10.44.0.0/24 via 10.251.0.1
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route add 2001:db8:44::/64 via fd18:251::1

ip link add site-lan-gw type veth peer name site-lan-edge
ip addr add 10.250.0.1/24 dev site-lan-gw
ip -6 addr add fd18:250::1/64 nodad dev site-lan-gw
ip link set site-lan-gw up
unshare --net sleep infinity >/dev/null 2>&1 &
site_lan_ns_pid=$!
wait_for_network_namespace "$site_lan_ns_pid"
ip link set site-lan-edge netns "$site_lan_ns_pid"
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip addr add 10.250.0.2/24 dev site-lan-edge
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip -6 addr add fd18:250::2/64 nodad dev site-lan-edge
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip addr add 10.44.0.20/32 dev site-lan-edge
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip -6 addr add 2001:db8:44::20/128 nodad dev site-lan-edge
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip link set site-lan-edge up
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip route add 10.251.0.0/24 via 10.250.0.1
nsenter --net="/proc/$site_lan_ns_pid/ns/net" ip -6 route add fd18:251::/64 via fd18:250::1
ip route add 10.44.0.20/32 via 10.250.0.2 dev site-lan-gw
ip -6 route add 2001:db8:44::20/128 via fd18:250::2 dev site-lan-gw
config_file=$(mktemp --suffix=.yaml)
failure_config_file=$(mktemp --suffix=.yaml)
server_log_file=$(mktemp)
failure_log_file=$(mktemp)
server_pid=
echo_log_file=$(mktemp)
trap 'exit_status=$?; printf "Managed-route namespace test failed (%s): %s\\n" "$exit_status" "$BASH_COMMAND" >&2; ip -4 rule show >&2 || true; ip -6 rule show >&2 || true; ip -4 route show table 10001 >&2 || true; ip -6 route show table 10001 >&2 || true; ip -4 route get 10.44.0.20 from 10.251.0.2 iif office-gw >&2 || true; ip -6 route get 2001:db8:44::20 from fd18:251::2 iif office-gw >&2 || true; cat "$server_log_file" "$failure_log_file" "$echo_log_file" >&2 2>/dev/null || true' ERR
cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ -n "$echo_server_pid" ]] && kill -0 "$echo_server_pid" 2>/dev/null; then
        kill -TERM "$echo_server_pid" 2>/dev/null || true
        wait "$echo_server_pid" 2>/dev/null || true
    fi
    for namespace_pid in "$office_client_ns_pid" "$site_lan_ns_pid"; do
        if [[ -n "$namespace_pid" ]] && kill -0 "$namespace_pid" 2>/dev/null; then
            kill -TERM "$namespace_pid" 2>/dev/null || true
            wait "$namespace_pid" 2>/dev/null || true
        fi
    done
    rm -f "$config_file" "$failure_config_file" "$server_log_file" "$failure_log_file" "$echo_log_file"
}
trap cleanup EXIT

cat > "$config_file" <<YAML
log:
  loglevel: warning
inbounds: []
outbounds:
  - tag: direct
    protocol: freedom
tunGateway:
  name: chimera-route
  address: 10.254.0.1/24
  ipv6Address: fd00:254::1/64
  mtu: ${tun_gateway_mtu}
  routes:
    - 10.44.0.0/24
    - 2001:db8:44::/64
  routeFrom:
    - 10.251.0.0/24
    - fd18:251::/64
  routeInputInterface: office-gw
  routeTable: 10001
  routeRulePriority: 10001
  inboundTag: managed-routes
YAML

nsenter --net="/proc/$site_lan_ns_pid/ns/net" python3 -u - <<'PY' >"$echo_log_file" 2>&1 &
import socket
import threading

def echo_tcp(connection):
    with connection:
        while data := connection.recv(4096):
            connection.sendall(data)

def serve_tcp(family, address):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 39690))
    listener.listen()
    while True:
        connection, _ = listener.accept()
        threading.Thread(target=echo_tcp, args=(connection,), daemon=True).start()

def serve_udp(family, address):
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.bind((address, 39690))
    while True:
        payload, peer = server.recvfrom(65535)
        server.sendto(payload, peer)

for family, address in [
    (socket.AF_INET, "10.44.0.20"),
    (socket.AF_INET6, "2001:db8:44::20"),
]:
    threading.Thread(target=serve_tcp, args=(family, address), daemon=True).start()
    threading.Thread(target=serve_udp, args=(family, address), daemon=True).start()
print("echo-ready", flush=True)
threading.Event().wait()
PY
echo_server_pid=$!
for attempt in $(seq 1 50); do
    if grep -q 'echo-ready' "$echo_log_file"; then
        break
    fi
    if ! kill -0 "$echo_server_pid" 2>/dev/null; then
        cat "$echo_log_file" >&2
        exit 1
    fi
    sleep 0.02
done

target/debug/chimera_server_app --config "$config_file" >"$server_log_file" 2>&1 &
server_pid=$!
for attempt in $(seq 1 50); do
    if ip link show dev chimera-route >/dev/null 2>&1 \
        && ip -4 route show table 10001 2>/dev/null | grep -F '10.44.0.0/24 dev chimera-route' >/dev/null \
        && ip -6 route show table 10001 2>/dev/null | grep -F '2001:db8:44::/64 dev chimera-route' >/dev/null; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log_file" >&2
        exit 1
    fi
    sleep 0.1
done

ip -o link show dev chimera-route | grep -F "mtu ${tun_gateway_mtu}" >/dev/null

ip -4 rule show | grep -E '^10001:[[:space:]]+from 10\.251\.0\.0/24 iif office-gw lookup 10001$' >/dev/null
ip -6 rule show | grep -E '^10001:[[:space:]]+from fd18:251::/64 iif office-gw lookup 10001$' >/dev/null
ip -4 route get 10.44.0.20 from 10.251.0.2 iif office-gw | grep -F 'dev chimera-route table 10001' >/dev/null
ip -6 route get 2001:db8:44::20 from fd18:251::2 iif office-gw | grep -F 'dev chimera-route table 10001' >/dev/null
# Even a local socket bound to an address from routeFrom must bypass the Office
# ingress rule and use the host's ordinary LAN route.
ip -4 route get 10.44.0.20 from 10.251.0.1 | grep -F 'dev site-lan-gw' >/dev/null
ip -6 route get 2001:db8:44::20 from fd18:251::1 | grep -F 'dev site-lan-gw' >/dev/null
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.office-gw.rp_filter=0
sysctl -q -w net.ipv4.conf.chimera-route.rp_filter=0
python3 - <<'PY'
import socket

for family, source, target in [
    (socket.AF_INET, "10.251.0.1", "10.44.0.20"),
    (socket.AF_INET6, "fd18:251::1", "2001:db8:44::20"),
]:
    marker = f"server-local-route-{family}".encode()
    source_tuple = (source, 0) if family == socket.AF_INET else (source, 0, 0, 0)
    target_tuple = (target, 39690) if family == socket.AF_INET else (target, 39690, 0, 0)
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.settimeout(5)
    tcp.bind(source_tuple)
    tcp.connect(target_tuple)
    tcp.sendall(marker)
    if tcp.recv(len(marker)) != marker:
        raise SystemExit(f"{target}: server-local TCP echo mismatch")
    tcp.close()

    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.settimeout(5)
    udp.bind(source_tuple)
    udp.sendto(marker, target_tuple)
    payload, peer = udp.recvfrom(65535)
    if payload != marker or peer[0] != target:
        raise SystemExit(f"{target}: server-local UDP echo or source mismatch: {peer}")
    udp.close()
print("Server-local IPv4/IPv6 TCP and UDP using Office-prefix sources kept the LAN route.")
PY
nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import socket

for family, target in [
    (socket.AF_INET, "10.44.0.20"),
    (socket.AF_INET6, "2001:db8:44::20"),
]:
    marker = f"managed-route-{family}".encode()
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.settimeout(5)
    tcp.connect((target, 39690))
    tcp.sendall(marker)
    if tcp.recv(len(marker)) != marker:
        raise SystemExit(f"{target}: TCP echo mismatch")
    tcp.close()

    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.settimeout(5)
    udp.sendto(marker, (target, 39690))
    payload, peer = udp.recvfrom(65535)
    if payload != marker or peer[0] != target:
        raise SystemExit(f"{target}: UDP echo or source mismatch: {peer}")
    udp.close()
print("Office IPv4/IPv6 TCP and UDP traversed managed TUN policy routes.")
PY
if ip -4 route show table main | grep -F '10.44.0.0/24 dev chimera-route' >/dev/null \
    || ip -6 route show table main | grep -F '2001:db8:44::/64 dev chimera-route' >/dev/null; then
    printf 'Managed TUN route leaked into the main route table.\n' >&2
    exit 1
fi

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
if ip link show dev chimera-route >/dev/null 2>&1; then
    printf 'TUN interface survived managed-route shutdown.\n' >&2
    exit 1
fi
if ip -4 route show table 10001 2>/dev/null | grep -F '10.44.0.0/24' >/dev/null \
    || ip -6 route show table 10001 2>/dev/null | grep -F '2001:db8:44::/64' >/dev/null \
    || ip -4 rule show | grep -E '^10001:[[:space:]]+from 10\.251\.0\.0/24' >/dev/null \
    || ip -6 rule show | grep -E '^10001:[[:space:]]+from fd18:251::/64' >/dev/null; then
    printf 'Managed routes or source rules survived graceful shutdown.\n' >&2
    exit 1
fi

# A syntactically valid but absent ingress device must fail startup instead of
# silently leaving the source policy ineffective.
cat > "$failure_config_file" <<'YAML'
log:
  loglevel: warning
inbounds: []
outbounds:
  - tag: direct
    protocol: freedom
tunGateway:
  name: chimera-no-ingress
  address: 10.253.2.1/24
  routes:
    - 10.47.0.0/24
  routeFrom:
    - 10.253.0.0/24
  routeInputInterface: missing-office
  routeTable: 10003
  routeRulePriority: 10003
  inboundTag: missing-ingress-interface
YAML
if target/debug/chimera_server_app --config "$failure_config_file" >"$failure_log_file" 2>&1; then
    printf 'TUN startup unexpectedly succeeded with a missing routeInputInterface.\n' >&2
    exit 1
fi
if ip link show dev chimera-no-ingress >/dev/null 2>&1 \
    || ip -4 route show table 10003 2>/dev/null | grep -F '10.47.0.0/24' >/dev/null; then
    printf 'Missing routeInputInterface failure left the TUN device or route behind.\n' >&2
    exit 1
fi

# Force a source-rule collision after route creation. Startup must remove its
# route and TUN device while preserving the operator's pre-existing rule.
ip -4 rule add priority 10002 from 10.253.0.0/24 table 10002
cat > "$failure_config_file" <<'YAML'
log:
  loglevel: warning
inbounds: []
outbounds:
  - tag: direct
    protocol: freedom
tunGateway:
  name: chimera-fail
  address: 10.253.1.1/24
  routes:
    - 10.45.0.0/24
  routeFrom:
    - 10.253.0.0/24
  routeInputInterface: office-gw
  routeTable: 10002
  routeRulePriority: 10002
  inboundTag: managed-routes-failure
YAML
if target/debug/chimera_server_app --config "$failure_config_file" >"$failure_log_file" 2>&1; then
    printf 'TUN startup unexpectedly succeeded with a conflicting source rule.\n' >&2
    exit 1
fi
if ip link show dev chimera-fail >/dev/null 2>&1 \
    || ip -4 route show table 10002 2>/dev/null | grep -F '10.45.0.0/24' >/dev/null; then
    printf 'Failed TUN startup left its interface or partially installed route behind.\n' >&2
    exit 1
fi
ip -4 rule show | grep -E '^10002:[[:space:]]+from 10\.253\.0\.0/24 lookup 10002$' >/dev/null

# A route table with existing operator state must remain untouched, and its
# presence must roll back the newly created TUN device.
ip -4 route add blackhole 192.0.2.0/24 table 10004
cat > "$failure_config_file" <<'YAML'
log:
  loglevel: warning
inbounds: []
outbounds:
  - tag: direct
    protocol: freedom
tunGateway:
  name: chimera-busy-table
  address: 10.252.2.1/24
  routes:
    - 10.48.0.0/24
  routeFrom:
    - 10.253.0.0/24
  routeInputInterface: office-gw
  routeTable: 10004
  routeRulePriority: 10004
  inboundTag: occupied-route-table
YAML
if target/debug/chimera_server_app --config "$failure_config_file" >"$failure_log_file" 2>&1; then
    printf 'TUN startup unexpectedly succeeded with an occupied managed route table.\n' >&2
    exit 1
fi
if ip link show dev chimera-busy-table >/dev/null 2>&1; then
    printf 'Occupied route-table failure left the TUN device behind.\n' >&2
    exit 1
fi
ip -4 route show table 10004 | grep -F 'blackhole 192.0.2.0/24' >/dev/null

printf 'Managed IPv4/IPv6 TUN routes, Office and Server-local TCP/UDP, graceful cleanup, occupied-table preservation and startup rollback passed in an isolated namespace.\n'
NAMESPACE_SCRIPT
