#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_mode=${1:-full}
gateway_mtu=${TUN_GATEWAY_MTU:-1500}
stress_seconds=${TUN_GATEWAY_STRESS_SECONDS:-60}
# The fixture allows eight TCP/UDP sessions; keep room for iperf3's control flow.
stress_parallel=${TUN_GATEWAY_STRESS_PARALLEL:-4}
if (( $# > 1 )) || [[ "$test_mode" != full && "$test_mode" != --hub-policy-only && "$test_mode" != --tcp-iperf-diagnostic && "$test_mode" != --reverse-offline-only && "$test_mode" != --iperf-stress-only ]]; then
    printf 'Usage: TUN_GATEWAY_MTU=1280..9000 TUN_GATEWAY_STRESS_SECONDS=10..3600 TUN_GATEWAY_STRESS_PARALLEL=1..6 %s [--hub-policy-only|--tcp-iperf-diagnostic|--reverse-offline-only|--iperf-stress-only]\n' "$0" >&2
    exit 2
fi
if [[ "$test_mode" == --iperf-stress-only ]] \
    && { [[ ! "$stress_seconds" =~ ^[0-9]+$ ]] \
        || (( stress_seconds < 10 || stress_seconds > 3600 )); }; then
    printf 'TUN_GATEWAY_STRESS_SECONDS must be an integer from 10 to 3600 in --iperf-stress-only mode.\n' >&2
    exit 2
fi
if [[ "$test_mode" == --iperf-stress-only ]] \
    && { [[ ! "$stress_parallel" =~ ^[0-9]+$ ]] \
        || (( stress_parallel < 1 || stress_parallel > 6 )); }; then
    printf 'TUN_GATEWAY_STRESS_PARALLEL must be an integer from 1 to 6 in --iperf-stress-only mode.\n' >&2
    exit 2
fi
if [[ ! "$gateway_mtu" =~ ^[0-9]+$ ]] \
    || (( gateway_mtu < 1280 || gateway_mtu > 9000 )); then
    printf 'TUN_GATEWAY_MTU must be an integer from 1280 to 9000.\n' >&2
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
xray_bin=${XRAY_BIN:-}
if [[ -n "$xray_bin" ]]; then
    if [[ "$xray_bin" != /* ]]; then
        xray_bin="$repo_root/$xray_bin"
    fi
    if [[ ! -x "$xray_bin" ]]; then
        printf 'XRAY_BIN must name an executable Xray binary: %s\n' "$xray_bin" >&2
        exit 1
    fi
    xray_version=$("$xray_bin" version)
    if [[ "$xray_version" != "Xray 26.9.9 "* ]]; then
        printf 'TUN management interoperability requires the pinned Xray 26.9.9 baseline; got: %s\n' "$xray_version" >&2
        exit 1
    fi
    printf 'Using fixed Xray management client: %s\n' "$xray_version"
fi

for command_name in cargo unshare nsenter ip setpriv sysctl python3 iperf3; do
    command -v "$command_name" >/dev/null
done

cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features full,tun-gateway --locked
if [[ -z "$xray_bin" ]]; then
    cargo build -p chimera_server_app --no-default-features --features full,tun-gateway --example tun_policy_update --locked
fi

unshare \
    --user \
    --map-users="0:${test_host_uid}:1" \
    --map-users="1:${test_subuid_start}:${test_subuid_count}" \
    --net \
    bash -s -- "$test_mode" "$gateway_mtu" "$xray_bin" "$stress_seconds" "$stress_parallel" <<'NAMESPACE_SCRIPT'
set -euo pipefail
test_mode=$1
gateway_mtu=$2
xray_bin=$3
stress_seconds=$4
stress_parallel=$5
trap 'exit_status=$?; printf "Namespace smoke failed with status %s at line %s: %s\\n" "$exit_status" "$LINENO" "$BASH_COMMAND" >&2' ERR

lan_ns_pid=
office_client_ns_pid=
office_client_2_ns_pid=
ip link set lo up
ip addr add 198.18.0.1/32 dev lo
unshare --net sleep infinity >/dev/null 2>&1 &
lan_ns_pid=$!
unshare --net sleep infinity >/dev/null 2>&1 &
office_client_ns_pid=$!
unshare --net sleep infinity >/dev/null 2>&1 &
office_client_2_ns_pid=$!

ip link add office-gw type veth peer name office-client
ip addr add 10.251.0.1/24 dev office-gw
ip -6 addr add fd18:251::1/64 nodad dev office-gw
ip link set office-gw mtu "$gateway_mtu"
ip link set office-gw up
ip link set office-client netns "$office_client_ns_pid"
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip addr add 10.251.0.2/24 dev office-client
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 addr add fd18:251::2/64 nodad dev office-client
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip link set office-client mtu "$gateway_mtu"
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip link set office-client up
office_client_link=$(nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -o link show dev office-client)
case "$office_client_link" in
    *"mtu ${gateway_mtu}"*) ;;
    *) printf 'Office client veth did not use MTU %s: %s\n' "$gateway_mtu" "$office_client_link" >&2; exit 1 ;;
esac
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route add 10.44.0.0/24 via 10.251.0.1 mtu "$gateway_mtu"
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route add 2001:db8:44::/64 via fd18:251::1 mtu "$gateway_mtu"

ip link add office-gw2 type veth peer name office-cli2
ip addr add 10.252.0.1/24 dev office-gw2
ip link set office-gw2 mtu "$gateway_mtu"
ip link set office-gw2 up
ip link set office-cli2 netns "$office_client_2_ns_pid"
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip addr add 10.252.0.2/24 dev office-cli2
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip link set office-cli2 mtu "$gateway_mtu"
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip link set office-cli2 up
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip route add 10.44.0.0/24 via 10.252.0.1 mtu "$gateway_mtu"

ip link add site-lan-host type veth peer name site-lan-edge
ip addr add 10.250.0.1/30 dev site-lan-host
ip link set site-lan-host up
ip link set site-lan-edge netns "$lan_ns_pid"
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.250.0.2/30 dev site-lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 198.18.0.20/32 dev site-lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 198.18.0.21/32 dev site-lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 198.18.0.53/32 dev site-lan-edge
ip -6 addr add fd18:250::1/64 nodad dev site-lan-host
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:250::2/64 nodad dev site-lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:198:18::20/128 nodad dev site-lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set site-lan-edge up
ip route add 198.18.0.20/32 via 10.250.0.2 dev site-lan-host
ip route add 198.18.0.21/32 via 10.250.0.2 dev site-lan-host
ip route add 198.18.0.53/32 via 10.250.0.2 dev site-lan-host
ip -6 route add fd18:198:18::20/128 via fd18:250::2 dev site-lan-host

smoke_config_file=$(mktemp --suffix=.yaml)
ipv6_failure_config_file=$(mktemp --suffix=.yaml)
hub_config_file=$(mktemp --suffix=.yaml)
edge_config_file=$(mktemp --suffix=.yaml)
server_log_file=$(mktemp)
ipv6_failure_log_file=$(mktemp)
hub_log_file=$(mktemp)
edge_log_file=$(mktemp)
tcp_echo_log_file=$(mktemp)
udp_echo_log_file=$(mktemp)
edge_tcp_echo_log_file=$(mktemp)
active_tcp_result_file=$(mktemp)
edge_udp_echo_log_file=$(mktemp)
edge_udp_second_echo_log_file=$(mktemp)
edge_dns_log_file=$(mktemp)
edge_iperf_log_file=$(mktemp)
iperf_client_result_file=$(mktemp)
iperf_client_error_file=$(mktemp)
office_udp_client_a_log_file=$(mktemp)
office_udp_client_b_log_file=$(mktemp)
edge_tcp_v6_echo_log_file=$(mktemp)
edge_udp_v6_echo_log_file=$(mktemp)
edge_hub_policy_echo_log_file=$(mktemp)
live_update_client_log_file=$(mktemp)
live_update_ready_file=$(mktemp)
live_update_resume_file=$(mktemp)
live_update_rule_file=$(mktemp --suffix=.json)
live_update_api_log_file=$(mktemp)
live_update_rules_file=$(mktemp)
health_http_log_file=$(mktemp)
server_pid=
hub_pid=
edge_pid=
health_http_pid=
tcp_echo_pid=
udp_echo_pid=
edge_tcp_echo_pid=
active_tcp_client_pid=
active_udp_client_pid=
offline_udp_client_pid=
edge_udp_echo_pid=
edge_udp_second_echo_pid=
edge_dns_pid=
edge_iperf_server_pid=
office_udp_client_a_pid=
office_udp_client_b_pid=
edge_tcp_v6_echo_pid=
edge_udp_v6_echo_pid=
edge_hub_policy_echo_pid=
live_update_client_pid=
cleanup() {
    exit_status=$?
    trap - EXIT
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ -n "$health_http_pid" ]] && kill -0 "$health_http_pid" 2>/dev/null; then
        kill -TERM "$health_http_pid" 2>/dev/null || true
        wait "$health_http_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_pid" ]] && kill -0 "$edge_pid" 2>/dev/null; then
        kill -TERM "$edge_pid" 2>/dev/null || true
        wait "$edge_pid" 2>/dev/null || true
    fi
    if [[ -n "$office_udp_client_a_pid" ]] && kill -0 "$office_udp_client_a_pid" 2>/dev/null; then
        kill -TERM "$office_udp_client_a_pid" 2>/dev/null || true
        wait "$office_udp_client_a_pid" 2>/dev/null || true
    fi
    if [[ -n "$office_udp_client_b_pid" ]] && kill -0 "$office_udp_client_b_pid" 2>/dev/null; then
        kill -TERM "$office_udp_client_b_pid" 2>/dev/null || true
        wait "$office_udp_client_b_pid" 2>/dev/null || true
    fi
    if [[ -n "$lan_ns_pid" ]] && kill -0 "$lan_ns_pid" 2>/dev/null; then
        kill -TERM "$lan_ns_pid" 2>/dev/null || true
        wait "$lan_ns_pid" 2>/dev/null || true
    fi
    if [[ -n "$office_client_ns_pid" ]] && kill -0 "$office_client_ns_pid" 2>/dev/null; then
        kill -TERM "$office_client_ns_pid" 2>/dev/null || true
        wait "$office_client_ns_pid" 2>/dev/null || true
    fi
    if [[ -n "$office_client_2_ns_pid" ]] && kill -0 "$office_client_2_ns_pid" 2>/dev/null; then
        kill -TERM "$office_client_2_ns_pid" 2>/dev/null || true
        wait "$office_client_2_ns_pid" 2>/dev/null || true
    fi
    if [[ -n "$hub_pid" ]] && kill -0 "$hub_pid" 2>/dev/null; then
        kill -TERM "$hub_pid" 2>/dev/null || true
        wait "$hub_pid" 2>/dev/null || true
    fi
    if [[ -n "$active_tcp_client_pid" ]] && kill -0 "$active_tcp_client_pid" 2>/dev/null; then
        kill -TERM "$active_tcp_client_pid" 2>/dev/null || true
        wait "$active_tcp_client_pid" 2>/dev/null || true
    fi
    if [[ -n "$active_udp_client_pid" ]] && kill -0 "$active_udp_client_pid" 2>/dev/null; then
        kill -TERM "$active_udp_client_pid" 2>/dev/null || true
        wait "$active_udp_client_pid" 2>/dev/null || true
    fi
    if [[ -n "$offline_udp_client_pid" ]] && kill -0 "$offline_udp_client_pid" 2>/dev/null; then
        kill -TERM "$offline_udp_client_pid" 2>/dev/null || true
        wait "$offline_udp_client_pid" 2>/dev/null || true
    fi
    if [[ -n "$tcp_echo_pid" ]] && kill -0 "$tcp_echo_pid" 2>/dev/null; then
        kill -TERM "$tcp_echo_pid" 2>/dev/null || true
        wait "$tcp_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$udp_echo_pid" ]] && kill -0 "$udp_echo_pid" 2>/dev/null; then
        kill -TERM "$udp_echo_pid" 2>/dev/null || true
        wait "$udp_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_tcp_echo_pid" ]] && kill -0 "$edge_tcp_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_tcp_echo_pid" 2>/dev/null || true
        wait "$edge_tcp_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_udp_echo_pid" ]] && kill -0 "$edge_udp_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_udp_echo_pid" 2>/dev/null || true
        wait "$edge_udp_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_udp_second_echo_pid" ]] && kill -0 "$edge_udp_second_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_udp_second_echo_pid" 2>/dev/null || true
        wait "$edge_udp_second_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_dns_pid" ]] && kill -0 "$edge_dns_pid" 2>/dev/null; then
        kill -TERM "$edge_dns_pid" 2>/dev/null || true
        wait "$edge_dns_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_iperf_server_pid" ]] && kill -0 "$edge_iperf_server_pid" 2>/dev/null; then
        kill -TERM "$edge_iperf_server_pid" 2>/dev/null || true
        wait "$edge_iperf_server_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_tcp_v6_echo_pid" ]] && kill -0 "$edge_tcp_v6_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_tcp_v6_echo_pid" 2>/dev/null || true
        wait "$edge_tcp_v6_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_udp_v6_echo_pid" ]] && kill -0 "$edge_udp_v6_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_udp_v6_echo_pid" 2>/dev/null || true
        wait "$edge_udp_v6_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$edge_hub_policy_echo_pid" ]] && kill -0 "$edge_hub_policy_echo_pid" 2>/dev/null; then
        kill -TERM "$edge_hub_policy_echo_pid" 2>/dev/null || true
        wait "$edge_hub_policy_echo_pid" 2>/dev/null || true
    fi
    if [[ -n "$live_update_client_pid" ]] && kill -0 "$live_update_client_pid" 2>/dev/null; then
        kill -TERM "$live_update_client_pid" 2>/dev/null || true
        wait "$live_update_client_pid" 2>/dev/null || true
    fi
    if (( exit_status != 0 )); then
        printf '\n--- Hub log ---\n' >&2
        cat "$hub_log_file" >&2 || true
        printf '\n--- Edge log ---\n' >&2
        cat "$edge_log_file" >&2 || true
        printf '\n--- Chimera server log ---\n' >&2
        cat "$server_log_file" >&2 || true
        printf '\n--- IPv6 TUN startup failure log ---\n' >&2
        cat "$ipv6_failure_log_file" >&2 || true
        printf '\n--- TCP echo log ---\n' >&2
        cat "$tcp_echo_log_file" >&2 || true
        printf '\n--- UDP echo log ---\n' >&2
        cat "$udp_echo_log_file" >&2 || true
        printf '\n--- Edge TCP echo log ---\n' >&2
        cat "$edge_tcp_echo_log_file" >&2 || true
        printf '\n--- Edge UDP echo log ---\n' >&2
        cat "$edge_udp_echo_log_file" >&2 || true
        printf '\n--- Edge second-target UDP echo log ---\n' >&2
        cat "$edge_udp_second_echo_log_file" >&2 || true
        printf '\n--- Edge DNS fixture log ---\n' >&2
        cat "$edge_dns_log_file" >&2 || true
        printf '\n--- Edge iperf3 server log ---\n' >&2
        cat "$edge_iperf_log_file" >&2 || true
        printf '\n--- Office iperf3 client error log ---\n' >&2
        cat "$iperf_client_error_file" >&2 || true
        printf '\n--- Office client A UDP log ---\n' >&2
        cat "$office_udp_client_a_log_file" >&2 || true
        printf '\n--- Office client B UDP log ---\n' >&2
        cat "$office_udp_client_b_log_file" >&2 || true
        printf '\n--- Edge IPv6 TCP echo log ---\n' >&2
        cat "$edge_tcp_v6_echo_log_file" >&2 || true
        printf '\n--- Edge IPv6 UDP echo log ---\n' >&2
        cat "$edge_udp_v6_echo_log_file" >&2 || true
        printf '\n--- Edge Hub-policy target log ---\n' >&2
        cat "$edge_hub_policy_echo_log_file" >&2 || true
        printf '\n--- Live TUN policy-update client log ---\n' >&2
        cat "$live_update_client_log_file" >&2 || true
        printf '\n--- Site health HTTP log ---\n' >&2
        cat "$health_http_log_file" >&2 || true
        printf '\n--- Isolated LAN namespace ---\n' >&2
        if [[ -n "$lan_ns_pid" ]] && kill -0 "$lan_ns_pid" 2>/dev/null; then
            nsenter --net="/proc/$lan_ns_pid/ns/net" ip -o addr >&2 || true
            nsenter --net="/proc/$lan_ns_pid/ns/net" ip route >&2 || true
        fi
        printf '\n--- Office client namespace ---\n' >&2
        if [[ -n "$office_client_ns_pid" ]] && kill -0 "$office_client_ns_pid" 2>/dev/null; then
            nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -o addr >&2 || true
            nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route >&2 || true
            nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route >&2 || true
        fi
        printf '\n--- Second Office client namespace ---\n' >&2
        if [[ -n "$office_client_2_ns_pid" ]] && kill -0 "$office_client_2_ns_pid" 2>/dev/null; then
            nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip -o addr >&2 || true
            nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip route >&2 || true
        fi
    fi
    rm -f \
        "$smoke_config_file" \
        "$ipv6_failure_config_file" \
        "$hub_config_file" \
        "$edge_config_file" \
        "$server_log_file" \
        "$ipv6_failure_log_file" \
        "$hub_log_file" \
        "$edge_log_file" \
        "$tcp_echo_log_file" \
        "$udp_echo_log_file" \
        "$edge_tcp_echo_log_file" \
        "$active_tcp_result_file" \
        "$edge_udp_echo_log_file" \
        "$edge_udp_second_echo_log_file" \
        "$edge_dns_log_file" \
        "$edge_iperf_log_file" \
        "$iperf_client_result_file" \
        "$iperf_client_error_file" \
        "$office_udp_client_a_log_file" \
        "$office_udp_client_b_log_file" \
        "$edge_tcp_v6_echo_log_file" \
        "$edge_udp_v6_echo_log_file" \
        "$edge_hub_policy_echo_log_file" \
        "$live_update_client_log_file" \
        "$live_update_ready_file" \
        "$live_update_resume_file" \
        "$live_update_rule_file" \
        "$live_update_api_log_file" \
        "$live_update_rules_file" \
        "$health_http_log_file"
    exit "$exit_status"
}
trap cleanup EXIT

start_health_http() {
    nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$health_http_log_file" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer

class HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/hub-limited-identity-allow-"):
            print("hub-limited-identity-tcp-received", flush=True)
        body = b"site-health-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass

server = HTTPServer(("198.18.0.20", 39646), HealthHandler)
print("health-http-ready", flush=True)
server.serve_forever()
PY
    health_http_pid=$!
    for attempt in $(seq 1 50); do
        if grep -q 'health-http-ready' "$health_http_log_file"; then
            return 0
        fi
        if ! kill -0 "$health_http_pid" 2>/dev/null; then
            cat "$health_http_log_file" >&2
            return 1
        fi
        sleep 0.02
    done
    printf 'Site health HTTP fixture did not start.\n' >&2
    return 1
}

wait_health_observation() {
    local expected_alive=$1
    local minimum_count=$2
    for attempt in $(seq 1 100); do
        if python3 - "$server_log_file" "$expected_alive" "$minimum_count" <<'PY'
from pathlib import Path
import re
import sys

log = re.sub(r"\x1b\[[0-9;]*m", "", Path(sys.argv[1]).read_text(errors="replace"))
expected_alive = f"alive={sys.argv[2]}"
minimum_count = int(sys.argv[3])
matches = [
    line for line in log.splitlines()
    if "routing observatory probe completed" in line
    and "to-hub" in line
    and expected_alive in line
]
raise SystemExit(0 if len(matches) >= minimum_count else 1)
PY
        then
            return 0
        fi
        sleep 0.1
    done
    printf 'Did not observe VLESS site probe alive=%s at least %s time(s).\n' \
        "$expected_alive" "$minimum_count" >&2
    return 1
}

cat > "$smoke_config_file" <<'YAML'
log:
  loglevel: debug
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
  - tag: to-hub-limited
    protocol: vless
    settings:
      vnext:
        - address: 127.0.0.1
          port: 39643
          users:
            - id: 3ac9b383-75a1-431c-8184-106c80eb2275
              encryption: none
  - tag: to-hub-unprivileged
    protocol: vless
    settings:
      vnext:
        - address: 127.0.0.1
          port: 39643
          users:
            - id: 3ac9b383-75a1-431c-8184-106c80eb2276
              encryption: none
observatory:
  subjectSelector: [to-hub]
  probeURL: http://10.44.0.20:39646/health
  probeInterval: 1s
routing:
  rules:
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.0.20/32]
      port: "39644"
      outboundTag: to-hub-limited
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.0.20/32]
      port: "39645"
      outboundTag: to-hub-unprivileged
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.0.20/32]
      port: "39646"
      outboundTag: to-hub-limited
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.0.0/24, 2001:db8:44::/64]
      outboundTag: to-hub
shutdown:
  gracePeriodSeconds: 1
tunGateway:
  name: chimera-smoke
  address: 10.254.0.1/24
  ipv6Address: fd00:254::1/64
  inboundTag: smoke-tun
  # Keep headroom for health probes and iperf3's control/data flows; the
  # ordinary-flow test below still fills this budget and rejects a ninth.
  maxTcpConnections: 8
  maxUdpSessions: 8
YAML
sed -i "/^tunGateway:/a\\  mtu: ${gateway_mtu}" "$smoke_config_file"
if [[ "$test_mode" == --reverse-offline-only ]]; then
    sed -i '/^observatory:/,/^routing:/{ /^routing:/!d; }' "$smoke_config_file"
fi

cat > "$ipv6_failure_config_file" <<'YAML'
log:
  loglevel: debug
inbounds:
  - listen: 127.0.0.1
    port: 39644
    protocol: socks
    tag: rollback-probe
    settings:
      auth: noauth
      udp: false
    streamSettings:
      network: tcp
outbounds:
  - tag: direct
    protocol: freedom
tunGateway:
  name: chimera-fail
  address: 10.253.0.1/24
  ipv6Address: ff02::1/64
  inboundTag: tun-failure
YAML

cat > "$hub_config_file" <<'YAML'
log:
  loglevel: debug
shutdown:
  gracePeriodSeconds: 1
inbounds:
  - listen: 127.0.0.1
    port: 39643
    protocol: vless
    tag: hub-vless-in
    settings:
      clients:
        - id: 3ac9b383-75a1-431c-8184-106c80eb2273
          email: site-a-edge@example.test
          reverse:
            tag: site-a
        - id: 3ac9b383-75a1-431c-8184-106c80eb2274
          email: office-gateway@example.test
        - id: 3ac9b383-75a1-431c-8184-106c80eb2275
          email: office-limited@example.test
        - id: 3ac9b383-75a1-431c-8184-106c80eb2276
          email: office-unprivileged@example.test
      decryption: none
    streamSettings:
      network: tcp
      security: none
outbounds:
  - tag: direct
    protocol: freedom
  - tag: overlay-default-deny
    protocol: blackhole
api:
  listen: 127.0.0.1:39649
  services: [RoutingService]
routing:
  rules:
    - type: field
      inboundTag: [hub-vless-in]
      user: [office-gateway@example.test]
      network: [tcp, udp]
      ip: [10.44.0.0/24, 2001:db8:44::/64]
      port: ["53", "39641-39646", "5201"]
      outboundTag: site-a
    - type: field
      inboundTag: [hub-vless-in]
      user: [office-limited@example.test]
      network: [tcp, udp]
      ip: [10.44.0.20/32]
      port: ["39646"]
      outboundTag: site-a
    - type: field
      inboundTag: [hub-vless-in]
      ip: [10.44.0.0/24, 2001:db8:44::/64]
      outboundTag: overlay-default-deny
YAML

cat > "$edge_config_file" <<'YAML'
log:
  loglevel: debug
inbounds: []
outbounds:
  - tag: site-a-bridge
    protocol: vless
    settings:
      address: 127.0.0.1
      port: 39643
      id: 3ac9b383-75a1-431c-8184-106c80eb2273
      encryption: none
      reverse:
        tag: site-a-edge
        siteToSite:
          prefixMaps:
            - from: 10.44.0.0/24
              to: 198.18.0.0/24
            - from: 2001:db8:44::/64
              to: fd18:198:18::/64
          allow:
            - network: [tcp, udp]
              ip: [198.18.0.0/24, fd18:198:18::/64]
              ports: [39641-39642, 39644-39646]
            - network: [udp]
              ip: [198.18.0.53/32]
              ports: ["53"]
            - network: [tcp, udp]
              ip: [198.18.0.20/32]
              ports: ["5201"]
            - network: [tcp, udp]
              ip: [198.18.0.20/32]
              ports: ["39647"]
            - network: [tcp, udp]
              ip: [fd18:198:18::20/128]
              ports: ["39647"]
    streamSettings:
      network: tcp
      security: none
  - tag: direct
    protocol: freedom
    settings:
      finalRules:
        - action: allow
          network: [tcp, udp]
          ip: [198.18.0.0/24, fd18:198:18::/64]
          port: 39641-39646
        - action: allow
          network: [udp]
          ip: [198.18.0.53/32]
          port: "53"
        - action: allow
          network: [tcp, udp]
          ip: [198.18.0.20/32]
          port: "5201"
        - action: allow
          network: [tcp, udp]
          ip: [198.18.0.20/32]
          port: "39647"
        - action: allow
          network: [tcp, udp]
          ip: [fd18:198:18::20/128]
          port: "39647"
routing:
  rules:
    - type: field
      inboundTag: [site-a-edge]
      network: tcp
      outboundTag: direct
    - type: field
      inboundTag: [site-a-edge]
      network: udp
      outboundTag: direct
shutdown:
  gracePeriodSeconds: 1
YAML

python3 -u - <<'PY' >"$tcp_echo_log_file" 2>&1 &
import socket

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("198.18.0.1", 39641))
listener.listen(1)
print("tcp-ready", flush=True)
connection, _ = listener.accept()
payload = connection.recv(16)
print(f"tcp-received {payload!r}", flush=True)
connection.sendall(payload)
connection.close()
listener.close()
PY
tcp_echo_pid=$!

python3 -u - <<'PY' >"$udp_echo_log_file" 2>&1 &
import socket

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("198.18.0.1", 39642))
print("udp-ready", flush=True)
for _ in range(2):
    payload, peer = listener.recvfrom(8192)
    print(f"udp-received {len(payload)} bytes from {peer}", flush=True)
    listener.sendto(payload, peer)
listener.close()
PY
udp_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_tcp_echo_log_file" 2>&1 &
import socket
import hashlib
import threading

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("198.18.0.20", 39641))
listener.listen(32)
print("tcp-ready", flush=True)

def handle(connection, initial_payload):
    large_flow = initial_payload.startswith(b"site-smoke-large-tcp-v4\0")
    total_bytes = 0
    digest = hashlib.sha256()
    with connection:
        payload = initial_payload
        while payload:
            if large_flow:
                total_bytes += len(payload)
                digest.update(payload)
            else:
                print(f"tcp-received {payload!r}", flush=True)
            connection.sendall(payload)
            payload = connection.recv(4096)
    if large_flow:
        print(
            f"tcp-received large-flow bytes={total_bytes} sha256={digest.hexdigest()}",
            flush=True,
        )

workers = []
while True:
    connection, _ = listener.accept()
    initial_payload = connection.recv(4096)
    if initial_payload == b"__fixture_stop__":
        connection.close()
        break
    worker = threading.Thread(
        target=handle,
        args=(connection, initial_payload),
    )
    worker.start()
    workers.append(worker)
listener.close()
for worker in workers:
    worker.join()
PY
edge_tcp_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_udp_echo_log_file" 2>&1 &
import socket

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("198.18.0.20", 39642))
print("udp-ready", flush=True)
while True:
    payload, peer = listener.recvfrom(8192)
    if payload == b"__stop__":
        break
    if payload.startswith((
        b"udp-limit-",
        b"site-gateway-multi-client-",
        b"reverse-udp-after-hub-restart",
        b"reverse-udp-held-",
        b"office-lan-",
        b"hub-acl-office-lan-",
        b"live-update-",
        b"reverse-offline-",
    )):
        print(f"udp-limit-received {payload!r} from {peer}", flush=True)
    elif payload.startswith((b"fragment-pressure-v4-", b"fragment-pressure-v6-")):
        family, marker = payload.split(b"-", 2)[2].split(b"-", 1)
        print(
            f"udp-limit-received fragment-pressure family={family.decode()} "
            f"id={marker[:2].decode()} bytes={len(payload)} from {peer}",
            flush=True,
        )
    else:
        print(f"udp-received {len(payload)} bytes from {peer}", flush=True)
    listener.sendto(payload, peer)
listener.close()
PY
edge_udp_echo_pid=$!

# These mapped targets are explicitly permitted by the Edge policies. Port
# 39646 tests the limited identity's allow, 39644 its scope deny, 39645 an
# unauthorized identity, and 39647 the primary identity's default port deny.
nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_hub_policy_echo_log_file" 2>&1 &
import select
import socket

tcp4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp4.bind(("198.18.0.20", 39647))
tcp4.listen(4)
tcp6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
tcp6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
tcp6.bind(("fd18:198:18::20", 39647))
tcp6.listen(4)
tcp_unprivileged = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_unprivileged.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_unprivileged.bind(("198.18.0.20", 39645))
tcp_unprivileged.listen(4)
tcp_limited_deny = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_limited_deny.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_limited_deny.bind(("198.18.0.20", 39644))
tcp_limited_deny.listen(4)
udp4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp4.bind(("198.18.0.20", 39647))
udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
udp6.bind(("fd18:198:18::20", 39647))
udp_limited = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_limited.bind(("198.18.0.20", 39646))
udp_unprivileged = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_unprivileged.bind(("198.18.0.20", 39645))
udp_limited_deny = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_limited_deny.bind(("198.18.0.20", 39644))
print("hub-policy-targets-ready", flush=True)
while True:
    tcp_sockets = (tcp4, tcp6, tcp_unprivileged, tcp_limited_deny)
    udp_sockets = (udp4, udp6, udp_limited, udp_unprivileged, udp_limited_deny)
    readable, _, _ = select.select([*tcp_sockets, *udp_sockets], [], [], 1)
    for listener in readable:
        if listener in tcp_sockets:
            connection, peer = listener.accept()
            with connection:
                payload = connection.recv(128)
                if listener is tcp_unprivileged:
                    print(f"hub-unprivileged-tcp-received {payload!r} from {peer}", flush=True)
                    connection.sendall(payload)
                    continue
                if listener is tcp_limited_deny:
                    print(f"hub-limited-identity-deny-tcp-received {payload!r} from {peer}", flush=True)
                    connection.sendall(payload)
                    continue
                family = "v6" if listener is tcp6 else "v4"
                print(f"hub-policy-tcp-{family}-received {payload!r} from {peer}", flush=True)
                connection.sendall(payload)
        else:
            payload, peer = listener.recvfrom(128)
            if listener is udp_limited:
                print(f"hub-limited-identity-udp-received {payload!r} from {peer}", flush=True)
                listener.sendto(payload, peer)
                continue
            if listener is udp_unprivileged:
                print(f"hub-unprivileged-udp-received {payload!r} from {peer}", flush=True)
                listener.sendto(payload, peer)
                continue
            if listener is udp_limited_deny:
                print(f"hub-limited-identity-deny-udp-received {payload!r} from {peer}", flush=True)
                listener.sendto(payload, peer)
                continue
            family = "v6" if listener is udp6 else "v4"
            print(f"hub-policy-udp-{family}-received {payload!r} from {peer}", flush=True)
            listener.sendto(payload, peer)
PY
edge_hub_policy_echo_pid=$!
for attempt in $(seq 1 50); do
    if grep -q 'hub-policy-targets-ready' "$edge_hub_policy_echo_log_file"; then
        break
    fi
    if ! kill -0 "$edge_hub_policy_echo_pid" 2>/dev/null; then
        cat "$edge_hub_policy_echo_log_file" >&2
        exit 1
    fi
    sleep 0.1
done
grep -q 'hub-policy-targets-ready' "$edge_hub_policy_echo_log_file"

# A second LAN address uses the same UDP port. The Office client later sends
# to both Overlay addresses from one UDP socket to check target/session keys.
nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_udp_second_echo_log_file" 2>&1 &
import socket

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("198.18.0.21", 39642))
print("udp-second-target-ready", flush=True)
payload, peer = listener.recvfrom(8192)
print(f"udp-second-target-received {payload!r} from {peer}", flush=True)
listener.sendto(payload, peer)
listener.close()
PY
edge_udp_second_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_dns_log_file" 2>&1 &
import socket
import struct

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("198.18.0.53", 53))
print("dns-ready", flush=True)
question = b"\x07example\x04test\x00\x00\x01\x00\x01"
answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x35"
for cycle in range(1, 4):
    query, peer = listener.recvfrom(512)
    query_id = 0x1A2A + cycle
    expected_query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    if query != expected_query:
        raise SystemExit(f"unexpected DNS query bytes in recovery cycle {cycle}: {query!r}")
    response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer
    listener.sendto(response, peer)
    print(f"dns-query-served cycle={cycle} example.test A 192.0.2.53", flush=True)
listener.close()
PY
edge_dns_pid=$!

iperf_server_debug_args=()
if [[ "$test_mode" == --tcp-iperf-diagnostic ]]; then
    iperf_server_debug_args+=(--debug)
fi
nsenter --net="/proc/$lan_ns_pid/ns/net" iperf3 \
    --server \
    --bind 198.18.0.20 \
    --port 5201 \
    "${iperf_server_debug_args[@]}" \
    >"$edge_iperf_log_file" 2>&1 &
edge_iperf_server_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_tcp_v6_echo_log_file" 2>&1 &
import socket

listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("fd18:198:18::20", 39644))
listener.listen(2)
print("tcp-v6-ready", flush=True)
for _ in range(2):
    connection, _ = listener.accept()
    payload = connection.recv(32)
    print(f"tcp-v6-received {payload!r}", flush=True)
    connection.sendall(payload)
    connection.close()
listener.close()
PY
edge_tcp_v6_echo_pid=$!

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$edge_udp_v6_echo_log_file" 2>&1 &
import socket

listener = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
listener.bind(("fd18:198:18::20", 39645))
print("udp-v6-ready", flush=True)
for _ in range(68):
    payload, peer = listener.recvfrom(8192)
    if payload.startswith(b"fragment-pressure-v6-"):
        marker = b"fragment-pressure-v6-"
        print(
            f"udp-v6-fragment-pressure-received "
            f"id={payload[len(marker):len(marker) + 2].decode()} bytes={len(payload)}",
            flush=True,
        )
    elif payload.startswith(b"hub-acl-office-lan-"):
        print(f"udp-v6-received {payload!r} from {peer}", flush=True)
    else:
        print(f"udp-v6-received {len(payload)} bytes from {peer}", flush=True)
    listener.sendto(payload, peer)
listener.close()
PY
edge_udp_v6_echo_pid=$!

start_health_http

for echo_log_file in \
    "$tcp_echo_log_file" \
    "$udp_echo_log_file" \
    "$edge_tcp_echo_log_file" \
    "$edge_udp_echo_log_file" \
    "$edge_udp_second_echo_log_file" \
    "$edge_dns_log_file" \
    "$edge_tcp_v6_echo_log_file" \
    "$edge_udp_v6_echo_log_file" \
    "$health_http_log_file"; do
    echo_ready=false
    for attempt in $(seq 1 50); do
        if grep -q -- '-ready' "$echo_log_file"; then
            echo_ready=true
            break
        fi
        sleep 0.02
    done
    if [[ "$echo_ready" != true ]]; then
        printf 'An echo fixture did not start listening.\n' >&2
        exit 1
    fi
done

iperf_ready=false
for attempt in $(seq 1 50); do
    if nsenter --net="/proc/$lan_ns_pid/ns/net" python3 - <<'PY'
import socket

probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(0.2)
result = probe.connect_ex(("198.18.0.20", 5201))
probe.close()
raise SystemExit(result)
PY
    then
        iperf_ready=true
        break
    fi
    if ! kill -0 "$edge_iperf_server_pid" 2>/dev/null; then
        cat "$edge_iperf_log_file" >&2
        printf 'Edge iperf3 UDP fixture exited before listening.\n' >&2
        exit 1
    fi
    sleep 0.02
done
if [[ "$iperf_ready" != true ]]; then
    printf 'Edge iperf3 UDP fixture did not open port 5201.\n' >&2
    exit 1
fi

# Multicast cannot be assigned as a Linux interface unicast address. Let the
# Server create the TUN, bind the SOCKS inbound, and fail at the route-netlink
# address step; startup rollback must release both resources.
ipv6_failure_exit_status=0
target/debug/chimera_server_app \
    --config "$ipv6_failure_config_file" \
    >"$ipv6_failure_log_file" 2>&1 || ipv6_failure_exit_status=$?
if (( ipv6_failure_exit_status == 0 )); then
    printf 'Chimera unexpectedly accepted a multicast TUN IPv6 address.\n' >&2
    exit 1
fi
grep -Fq 'failed to configure tunGateway IPv6 address ff02::1/64 on chimera-fail' "$ipv6_failure_log_file"
grep -Fq 'server startup failed; startup resources rolled back' "$ipv6_failure_log_file"
if ip link show dev chimera-fail >/dev/null 2>&1; then
    printf 'TUN device remained after IPv6 address startup failure.\n' >&2
    exit 1
fi
python3 - <<'PY'
import socket

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 39644))
listener.listen(1)
listener.close()
PY

RUST_LOG=info,chimera_server_lib::handler::vless_reverse=debug target/debug/chimera_server_app \
    --config "$hub_config_file" \
    >"$hub_log_file" 2>&1 &
hub_pid=$!
hub_ready=false
for attempt in $(seq 1 50); do
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
        printf 'Hub Chimera exited before opening its VLESS listener.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$hub_ready" != true ]]; then
    printf 'Hub Chimera did not open its VLESS listener.\n' >&2
    exit 1
fi

RUST_LOG=info,chimera_server_lib::handler::vless_reverse=debug target/debug/chimera_server_app \
    --config "$edge_config_file" \
    >"$edge_log_file" 2>&1 &
edge_pid=$!
# The Bridge's supervised retry loop connects after its first failed dial.
sleep 2.3
if ! kill -0 "$edge_pid" 2>/dev/null; then
    printf 'Edge Chimera exited while connecting to Hub Reverse.\n' >&2
    exit 1
fi

server_log_filter=chimera_server_lib::routing_observer=debug,chimera_server_lib::tun_gateway=warn,chimera_server_lib::traffic::traffic_noop=error,watfaq_netstack=warn
if [[ "$test_mode" == --reverse-offline-only ]]; then
    server_log_filter=chimera_server_lib::routing_observer=debug,chimera_server_lib::tun_gateway=debug,chimera_server_lib::handler::vless_reverse=debug,chimera_server_lib::traffic::traffic_noop=error,watfaq_netstack=warn
fi
RUST_LOG="$server_log_filter" target/debug/chimera_server_app \
    --config "$smoke_config_file" \
    >"$server_log_file" 2>&1 &
server_pid=$!

tun_created=false
for attempt in $(seq 1 50); do
    if ip link show dev chimera-smoke >/dev/null 2>&1; then
        tun_created=true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        printf 'Chimera exited before creating its TUN device.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$tun_created" != true ]]; then
    printf 'Chimera did not create its TUN device.\n' >&2
    exit 1
fi
if [[ "$test_mode" != --reverse-offline-only ]]; then
    wait_health_observation true 1
fi

link_state=$(ip -o link show dev chimera-smoke)
case "$link_state" in
    *"mtu ${gateway_mtu}"*) ;;
    *) printf 'Unexpected TUN link state: %s\n' "$link_state" >&2; exit 1 ;;
esac
ip -o -4 addr show dev chimera-smoke | grep -F '10.254.0.1/24' >/dev/null
ip -o -6 addr show dev chimera-smoke | grep -F 'fd00:254::1/64' >/dev/null

# Keep routes and policy inside this disposable namespace. UID 1 acts as the
# client; UID 0 runs Chimera and dials local echo services.
ip route add 198.18.0.1/32 dev chimera-smoke table 100
ip route add 10.44.0.0/24 dev chimera-smoke table 100
ip -6 route add 2001:db8:44::/64 dev chimera-smoke table 100
ip route add 10.44.0.0/24 dev chimera-smoke
ip -6 route add 2001:db8:44::/64 dev chimera-smoke
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.office-gw.rp_filter=0
ip rule del pref 0
ip rule add pref 0 uidrange 1-1 lookup 100
ip rule add pref 10 lookup local
ip -6 rule del pref 0
ip -6 rule add pref 0 uidrange 1-1 lookup 100
ip -6 rule add pref 10 lookup local

# The direct Freedom echo target uses loopback. These settings let Linux accept
# its own source address when it returns via TUN.
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.chimera-smoke.rp_filter=0
sysctl -q -w net.ipv4.conf.all.accept_local=1
sysctl -q -w net.ipv4.conf.chimera-smoke.accept_local=1

client_route=$(ip route get 198.18.0.1 uid 1)
case "$client_route" in
    *"dev chimera-smoke"*) ;;
    *) printf 'Client route did not enter TUN: %s\n' "$client_route" >&2; exit 1 ;;
esac
reverse_route=$(ip route get 10.44.0.20 uid 1)
case "$reverse_route" in
    *"dev chimera-smoke"*) ;;
    *) printf 'Reverse client route did not enter TUN: %s\n' "$reverse_route" >&2; exit 1 ;;
esac
ip route get 10.44.0.21 uid 1 | grep -F 'dev chimera-smoke' >/dev/null
ip -6 route get 2001:db8:44::20 uid 1 | grep -F 'dev chimera-smoke' >/dev/null
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route get 10.44.0.20 | grep -F 'via 10.251.0.1 dev office-client' >/dev/null
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip route get 10.44.0.21 | grep -F 'via 10.251.0.1 dev office-client' >/dev/null
nsenter --net="/proc/$office_client_ns_pid/ns/net" ip -6 route get 2001:db8:44::20 | grep -F 'via fd18:251::1 dev office-client' >/dev/null
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" ip route get 10.44.0.20 | grep -F 'via 10.252.0.1 dev office-cli2' >/dev/null

if [[ "$test_mode" == --tcp-iperf-diagnostic ]]; then
    tcp_iperf_exit_status=0
    nsenter --net="/proc/$office_client_ns_pid/ns/net" iperf3 \
        --client 10.44.0.20 \
        --port 5201 \
        --time 3 \
        --json \
        >"$iperf_client_result_file" \
        2>"$iperf_client_error_file" || tcp_iperf_exit_status=$?
    printf 'TCP iperf3 diagnostic exit status: %s\n' "$tcp_iperf_exit_status"
    printf '\n--- TCP iperf3 client debug/error output ---\n'
    cat "$iperf_client_error_file"
    printf '\n--- TCP iperf3 client JSON output ---\n'
    cat "$iperf_client_result_file"
    printf '\n--- TCP iperf3 server debug output ---\n'
    cat "$edge_iperf_log_file"
    if (( tcp_iperf_exit_status != 0 )); then
        exit "$tcp_iperf_exit_status"
    fi
    exit 0
fi

if [[ "$test_mode" == --iperf-stress-only ]]; then
    run_stress_iperf() {
        local client_pid
        local monitor_pid
        local client_status

        nsenter --net="/proc/$office_client_ns_pid/ns/net" iperf3 \
            --client 10.44.0.20 \
            --port 5201 \
            "$@" \
            --json \
            >"$iperf_client_result_file" \
            2>"$iperf_client_error_file" &
        client_pid=$!

        python3 - "$client_pid" "$server_pid" "$hub_pid" "$edge_pid" <<'PY' &
import os
import sys
import time
from pathlib import Path

client_pid = int(sys.argv[1])
services = {
    "OfficeGateway": int(sys.argv[2]),
    "Hub": int(sys.argv[3]),
    "Edge": int(sys.argv[4]),
}
clock_ticks = os.sysconf("SC_CLK_TCK")

def state(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2 :].split()[0]

def sample(pid):
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
    rss_kib = int(values["VmRSS"].split()[0])
    cpu_ticks_total = 0
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            fields = (task / "stat").read_text()
        except FileNotFoundError:
            continue
        fields = fields[fields.rfind(")") + 2 :].split()
        cpu_ticks_total += int(fields[11]) + int(fields[12])
    return cpu_ticks_total, rss_kib

baseline = {name: sample(pid) for name, pid in services.items()}
sampled_peak_rss = {name: baseline[name][1] for name in services}
final = baseline.copy()

while True:
    try:
        if state(client_pid) in {"Z", "X"}:
            break
    except FileNotFoundError:
        break
    for name, pid in services.items():
        try:
            final[name] = sample(pid)
        except (FileNotFoundError, KeyError, ProcessLookupError) as error:
            raise SystemExit(f"resource monitor lost {name} process {pid}: {error}")
        sampled_peak_rss[name] = max(sampled_peak_rss[name], final[name][1])
    time.sleep(0.1)

for name, pid in services.items():
    try:
        final[name] = sample(pid)
    except (FileNotFoundError, KeyError, ProcessLookupError) as error:
        raise SystemExit(f"resource monitor lost {name} process {pid}: {error}")
    sampled_peak_rss[name] = max(sampled_peak_rss[name], final[name][1])
    cpu_seconds = max(0, final[name][0] - baseline[name][0]) / clock_ticks
    print(
        f"Resource sample {name}: CPU +{cpu_seconds:.2f}s, "
        f"RSS baseline={baseline[name][1]} KiB, sampled peak={sampled_peak_rss[name]} KiB"
    )
PY
        monitor_pid=$!

        if wait "$client_pid"; then
            client_status=0
        else
            client_status=$?
        fi
        wait "$monitor_pid"
        return "$client_status"
    }

    for attempt in $(seq 1 50); do
        if grep -q 'Server listening on 5201' "$edge_iperf_log_file"; then
            break
        fi
        sleep 0.1
    done
    grep -q 'Server listening on 5201' "$edge_iperf_log_file"

    run_stress_iperf \
        --parallel "$stress_parallel" \
        --time "$stress_seconds"
    python3 - "$iperf_client_result_file" "$stress_seconds" "$stress_parallel" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
expected_seconds = int(sys.argv[2])
parallel_streams = int(sys.argv[3])
streams = report["end"].get("streams", [])
if len(streams) != parallel_streams:
    raise SystemExit(f"TCP iperf3 expected {parallel_streams} parallel streams, got {len(streams)}")
sent = report["end"]["sum_sent"]
received = report["end"]["sum_received"]
for name, direction in (("sent", sent), ("received", received)):
    if direction["bytes"] <= 0 or direction["seconds"] < expected_seconds * 0.95:
        raise SystemExit(f"TCP iperf3 {name} stream did not sustain the requested interval: {direction!r}")
print(
    f"TCP sustained {expected_seconds}s across {parallel_streams} streams: sent={sent['bytes']} bytes "
    f"received={received['bytes']} bytes"
)
PY

    run_stress_iperf \
        --parallel "$stress_parallel" \
        --udp \
        --bandwidth 5M \
        --length 1200 \
        --time "$stress_seconds"
    python3 - "$iperf_client_result_file" "$stress_seconds" "$stress_parallel" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
expected_seconds = int(sys.argv[2])
parallel_streams = int(sys.argv[3])
streams = report["end"].get("streams", [])
if len(streams) != parallel_streams:
    raise SystemExit(f"UDP iperf3 expected {parallel_streams} parallel streams, got {len(streams)}")
sent = report["end"]["sum_sent"]
received = report["end"]["sum_received"]
for name, direction in (("sent", sent), ("received", received)):
    if direction["bytes"] <= 0 or direction["seconds"] < expected_seconds * 0.95:
        raise SystemExit(f"UDP iperf3 {name} stream did not sustain the requested interval: {direction!r}")
if received["packets"] <= 0 or not 0 <= received["lost_percent"] <= 1.0:
    raise SystemExit(f"UDP iperf3 loss exceeded the 1% stress threshold: {received!r}")
print(
    f"UDP sustained {expected_seconds}s at 5 Mbit/s across {parallel_streams} streams: sent={sent['bytes']} bytes "
    f"received={received['bytes']} bytes loss={received['lost_percent']:.2f}%"
)
PY

    printf 'Sustained TCP and UDP traffic completed across the live TUN/Reverse/Edge path with %s parallel streams.\n' "$stress_parallel"
    exit 0
fi

if [[ "$test_mode" == --hub-policy-only ]]; then
    for readiness_log in \
        "$edge_tcp_echo_log_file" \
        "$edge_udp_echo_log_file" \
        "$edge_tcp_v6_echo_log_file" \
        "$edge_udp_v6_echo_log_file" \
        "$edge_hub_policy_echo_log_file"; do
        for attempt in $(seq 1 50); do
            if grep -q -- '-ready' "$readiness_log"; then
                break
            fi
            sleep 0.1
        done
        grep -q -- '-ready' "$readiness_log"
    done

    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import socket

tcp_target = ("10.44.0.20", 39641)
with socket.create_connection(tcp_target, timeout=5) as connection:
    connection.settimeout(5)
    connection.sendall(b"hub-acl-office-lan-tcp")
    reply = connection.recv(128)
    if reply != b"hub-acl-office-lan-tcp":
        raise SystemExit(f"authorized Office TUN TCP did not echo: {reply!r}")

udp_target = ("10.44.0.20", 39642)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
for payload in (b"hub-acl-office-lan-udp", bytes(index % 251 for index in range(4096))):
    udp.sendto(payload, udp_target)
    reply, source = udp.recvfrom(8192)
    if reply != payload or source != udp_target:
        raise SystemExit(f"authorized Office TUN UDP did not echo payload length {len(payload)}: {len(reply)} from {source!r}")
udp.close()

tcp6_target = ("2001:db8:44::20", 39644)
with socket.create_connection(tcp6_target, timeout=5) as connection:
    connection.settimeout(5)
    connection.sendall(b"hub-acl-office-lan-v6-tcp")
    reply = connection.recv(128)
    if reply != b"hub-acl-office-lan-v6-tcp":
        raise SystemExit(f"authorized Office TUN IPv6 TCP did not echo: {reply!r}")

udp6_target = ("2001:db8:44::20", 39645)
udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp6.settimeout(5)
for payload in (b"hub-acl-office-lan-v6-udp", bytes(index % 251 for index in range(4096))):
    udp6.sendto(payload, udp6_target)
    reply, source = udp6.recvfrom(8192)
    if reply != payload or source[:2] != udp6_target:
        raise SystemExit(f"authorized Office TUN IPv6 UDP did not echo payload length {len(payload)}: {len(reply)} from {source!r}")
udp6.close()

limited_target = ("10.44.0.20", 39646)
limited_tcp_marker = (
    b"GET /hub-limited-identity-allow-tcp HTTP/1.1\r\n"
    b"Host: site-policy.test\r\nConnection: close\r\n\r\n"
)
with socket.create_connection(limited_target, timeout=5) as connection:
    connection.settimeout(5)
    connection.sendall(limited_tcp_marker)
    response = bytearray()
    while b"site-health-ok" not in response:
        chunk = connection.recv(256)
        if not chunk:
            break
        response.extend(chunk)
    if b"site-health-ok" not in response:
        raise SystemExit(f"limited Office identity was denied its TCP allow: {bytes(response)!r}")

limited_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
limited_udp.settimeout(5)
limited_udp_marker = b"hub-limited-identity-udp"
limited_udp.sendto(limited_udp_marker, limited_target)
response, source = limited_udp.recvfrom(128)
if response != limited_udp_marker or source != limited_target:
    raise SystemExit(f"limited Office identity TCP/UDP allow failed: {response!r} from {source!r}")
limited_udp.close()

limited_deny_target = ("10.44.0.20", 39644)
limited_deny_tcp_marker = b"hub-limited-identity-deny-tcp"
try:
    with socket.create_connection(limited_deny_target, timeout=3) as connection:
        connection.settimeout(1)
        connection.sendall(limited_deny_tcp_marker)
        try:
            response = connection.recv(128)
        except socket.timeout:
            response = b""
        if response:
            raise SystemExit(f"Limited Office identity got out-of-scope TCP reply: {response!r}")
except OSError:
    pass

limited_deny_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
limited_deny_udp.settimeout(1)
limited_deny_udp_marker = b"hub-limited-identity-deny-udp"
limited_deny_udp.sendto(limited_deny_udp_marker, limited_deny_target)
try:
    response, source = limited_deny_udp.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"Limited Office identity got out-of-scope UDP reply: {response!r} from {source!r}")
limited_deny_udp.close()

unprivileged_target = ("10.44.0.20", 39645)
unprivileged_tcp_marker = b"hub-unprivileged-office-lan-tcp"
try:
    with socket.create_connection(unprivileged_target, timeout=3) as connection:
        connection.settimeout(1)
        connection.sendall(unprivileged_tcp_marker)
        try:
            response = connection.recv(128)
        except socket.timeout:
            response = b""
        if response:
            raise SystemExit(f"Hub-unprivileged Office identity got TCP reply: {response!r}")
except OSError:
    pass

unprivileged_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
unprivileged_udp.settimeout(1)
unprivileged_udp_marker = b"hub-unprivileged-office-lan-udp"
unprivileged_udp.sendto(unprivileged_udp_marker, unprivileged_target)
try:
    response, source = unprivileged_udp.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"Hub-unprivileged Office identity got UDP reply {response!r} from {source!r}")
unprivileged_udp.close()

for family, target in (
    (socket.AF_INET, ("10.44.0.20", 39647)),
    (socket.AF_INET6, ("2001:db8:44::20", 39647)),
):
    denied_tcp_marker = b"hub-port-deny-office-lan-tcp"
    try:
        connection = socket.create_connection(target, timeout=3)
        connection.settimeout(1)
        with connection:
            connection.sendall(denied_tcp_marker)
            try:
                reply = connection.recv(128)
            except socket.timeout:
                reply = b""
            if reply:
                raise SystemExit(f"Hub-denied TCP received a reply: {reply!r}")
    except OSError:
        pass

    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.settimeout(1)
    denied_udp_marker = b"hub-port-deny-office-lan-udp"
    udp.sendto(denied_udp_marker, target)
    try:
        reply, source = udp.recvfrom(128)
    except socket.timeout:
        pass
    else:
        raise SystemExit(f"Hub-denied UDP received {reply!r} from {source!r}")
    udp.close()
PY

grep -Fq "tcp-received b'hub-acl-office-lan-tcp'" "$edge_tcp_echo_log_file"
grep -Fq "udp-limit-received b'hub-acl-office-lan-udp'" "$edge_udp_echo_log_file"
grep -Fq "tcp-v6-received b'hub-acl-office-lan-v6-tcp'" "$edge_tcp_v6_echo_log_file"
grep -Fq "udp-v6-received b'hub-acl-office-lan-v6-udp'" "$edge_udp_v6_echo_log_file"
grep -Fq 'hub-limited-identity-tcp-received' "$health_http_log_file"
grep -Fq "hub-limited-identity-udp-received b'hub-limited-identity-udp'" "$edge_hub_policy_echo_log_file"
if grep -Fq 'hub-limited-identity-deny-' "$edge_hub_policy_echo_log_file"; then
    printf 'Hub forwarded a limited identity outside its configured Overlay/port allow.\n' >&2
    exit 1
fi
if grep -Fq 'hub-unprivileged-office-lan-' "$health_http_log_file" "$edge_hub_policy_echo_log_file"; then
    printf 'Hub-denied Office LAN identity reached an Edge-allowed target.\n' >&2
    exit 1
fi
if grep -Fq 'hub-port-deny-office-lan-' "$edge_hub_policy_echo_log_file"; then
        printf 'Hub-denied Office LAN traffic reached an Edge-allowed target.\n' >&2
        exit 1
    fi

    nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 -u - \
        "$live_update_ready_file" "$live_update_resume_file" <<'PY' \
        >"$live_update_client_log_file" 2>&1 &
import pathlib
import socket
import sys
import time

ready_file = pathlib.Path(sys.argv[1])
resume_file = pathlib.Path(sys.argv[2])
primary_target = ("10.44.0.20", 39642)
changed_target = ("10.44.0.21", 39642)
tcp_target = ("10.44.0.20", 39641)

active = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
active.settimeout(5)
before = b"live-update-before"
active.sendto(before, primary_target)
reply, source = active.recvfrom(128)
if reply != before or source != primary_target:
    raise SystemExit(f"initial live-update UDP failed: {reply!r} from {source!r}")

active_tcp = socket.create_connection(tcp_target, timeout=5)
active_tcp.settimeout(5)
active_tcp_before = b"live-update-tcp-before"
active_tcp.sendall(active_tcp_before)
reply = active_tcp.recv(128)
if reply != active_tcp_before:
    raise SystemExit(f"initial live-update TCP failed: {reply!r}")
ready_file.write_text("ready")

deadline = time.monotonic() + 10
while not resume_file.exists():
    if time.monotonic() >= deadline:
        raise SystemExit("timed out waiting for RoutingService update")
    time.sleep(0.02)

after = b"live-update-active-after"
active.sendto(after, primary_target)
reply, source = active.recvfrom(128)
if reply != after or source != primary_target:
    raise SystemExit(f"active UDP flow failed after update: {reply!r} from {source!r}")

active_tcp_after = b"live-update-tcp-active-after"
active_tcp.sendall(active_tcp_after)
reply = active_tcp.recv(128)
if reply != active_tcp_after:
    raise SystemExit(f"active TCP flow failed after update: {reply!r}")

active.settimeout(0.7)
active.sendto(b"live-update-new-target", changed_target)
try:
    reply, source = active.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"changed target escaped updated policy: {reply!r} from {source!r}")

fresh = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fresh.settimeout(0.7)
fresh.sendto(b"live-update-new-source", primary_target)
try:
    reply, source = fresh.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"fresh source escaped updated policy: {reply!r} from {source!r}")
finally:
    fresh.close()
    active.close()
    active_tcp.close()

try:
    fresh_tcp = socket.create_connection(tcp_target, timeout=2)
except OSError:
    pass
else:
    fresh_tcp.settimeout(0.7)
    try:
        fresh_tcp.sendall(b"live-update-new-tcp")
        reply = fresh_tcp.recv(128)
    except (OSError, TimeoutError, socket.timeout):
        reply = b""
    finally:
        fresh_tcp.close()
    if reply:
        raise SystemExit(f"fresh TCP flow escaped updated policy: {reply!r}")

print("live RoutingService update preserved active TCP/UDP and denied new flows", flush=True)
PY
    live_update_client_pid=$!
    for attempt in $(seq 1 50); do
        if [[ -s "$live_update_ready_file" ]]; then
            break
        fi
        if ! kill -0 "$live_update_client_pid" 2>/dev/null; then
            cat "$live_update_client_log_file" >&2
            exit 1
        fi
        sleep 0.1
    done
    grep -q 'ready' "$live_update_ready_file"

    if [[ -n "$xray_bin" ]]; then
        cat > "$live_update_rule_file" <<'JSON'
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "ruleTag": "tun-live-update-tcp-udp-deny",
        "inboundTag": ["hub-vless-in"],
        "user": ["office-gateway@example.test"],
        "network": ["tcp", "udp"],
        "ip": ["10.44.0.0/24"],
        "outboundTag": "overlay-default-deny"
      }
    ]
  }
}
JSON
        "$xray_bin" api adrules --server=127.0.0.1:39649 "$live_update_rule_file" \
            >"$live_update_api_log_file" 2>&1
        "$xray_bin" api lsrules --server=127.0.0.1:39649 \
            >"$live_update_rules_file" 2>&1
        grep -q 'tun-live-update-tcp-udp-deny' "$live_update_rules_file"
    else
        target/debug/examples/tun_policy_update 127.0.0.1:39649
    fi
    touch "$live_update_resume_file"
    wait "$live_update_client_pid"
    live_update_client_pid=
    grep -q 'live RoutingService update preserved active TCP/UDP and denied new flows' "$live_update_client_log_file"
    grep -Fq "udp-limit-received b'live-update-before'" "$edge_udp_echo_log_file"
    grep -Fq "udp-limit-received b'live-update-active-after'" "$edge_udp_echo_log_file"
    grep -Fq "tcp-received b'live-update-tcp-before'" "$edge_tcp_echo_log_file"
    grep -Fq "tcp-received b'live-update-tcp-active-after'" "$edge_tcp_echo_log_file"
    if grep -Fq 'live-update-new-' \
        "$edge_udp_echo_log_file" \
        "$edge_udp_second_echo_log_file" \
        "$edge_tcp_echo_log_file"; then
        printf 'Hub forwarded a new TUN TCP/UDP flow after the live deny update.\n' >&2
        exit 1
    fi

    printf 'Ordinary Office LAN dual-stack TUN → identity-specific Hub TCP/UDP allow, scope-deny, wrong-identity and default-deny checks passed.\n'
    printf 'Live RoutingService update preserved active TUN TCP/UDP flows and denied new TCP/UDP flows.\n'
    exit 0
fi

if [[ "$test_mode" == --reverse-offline-only ]]; then
    offline_udp_client_program=$(cat <<'PY'
import socket
import sys

target = ("10.44.0.20", 39642)
baseline = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
baseline.settimeout(5)

baseline_payload = b"reverse-offline-before"
baseline.sendto(baseline_payload, target)
reply, source = baseline.recvfrom(128)
if reply != baseline_payload or source != target:
    raise SystemExit(f"unexpected baseline UDP echo: {reply!r} from {source!r}")

print("udp-ready", flush=True)

if sys.stdin.readline().strip() != "probe-offline":
    raise SystemExit("missing offline UDP probe trigger")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
sock.sendto(b"reverse-offline-no-worker", target)
source_port = sock.getsockname()[1]
try:
    reply, source = sock.recvfrom(128)
except TimeoutError:
    print("udp-dropped-without-worker", flush=True)
else:
    raise SystemExit(f"offline Reverse UDP unexpectedly replied: {reply!r} from {source!r}")

if sock.getsockname()[1] != source_port:
    raise SystemExit("UDP source port changed during the offline probe")
if sys.stdin.readline().strip() != "probe-recovered":
    raise SystemExit("missing recovered UDP probe trigger")

sent_payloads = set()
for attempt in range(1, 13):
    payload = f"reverse-offline-recovered-{attempt}".encode()
    sent_payloads.add(payload)
    sock.sendto(payload, target)
    sock.settimeout(0.5)
    try:
        reply, source = sock.recvfrom(128)
    except TimeoutError:
        continue
    if reply not in sent_payloads or source != target:
        raise SystemExit(f"unexpected recovered UDP reply: {reply!r} from {source!r}")
    if sock.getsockname()[1] != source_port:
        raise SystemExit("UDP source port changed during recovery")
    print(f"udp-recovered-same-tuple-{attempt}", flush=True)
    break
else:
    raise SystemExit("same-tuple Reverse UDP did not recover after Bridge reattachment")

baseline.close()
sock.close()
PY
)
    coproc REVERSE_OFFLINE_UDP_CLIENT {
        setpriv --reuid=1 python3 -u -c "$offline_udp_client_program"
    }
    offline_udp_client_pid=$REVERSE_OFFLINE_UDP_CLIENT_PID
    offline_udp_read_fd=${REVERSE_OFFLINE_UDP_CLIENT[0]}
    offline_udp_write_fd=${REVERSE_OFFLINE_UDP_CLIENT[1]}
    if ! IFS= read -r -t 5 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != udp-ready ]]; then
        printf 'Live TUN Reverse UDP baseline did not become ready.\n' >&2
        exit 1
    fi

    kill -TERM "$edge_pid"
    wait "$edge_pid"
    edge_pid=
    if ! kill -0 "$hub_pid" 2>/dev/null || ! kill -0 "$server_pid" 2>/dev/null; then
        printf 'Hub or TUN Gateway exited while stopping the Edge Bridge.\n' >&2
        exit 1
    fi
    printf 'probe-offline\n' >&"$offline_udp_write_fd"
    if ! IFS= read -r -t 5 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != udp-dropped-without-worker ]]; then
        printf 'Live TUN Reverse UDP did not fail closed while its only Bridge was offline.\n' >&2
        exit 1
    fi
    grep -Fq 'no ACTIVE Reverse Mux client worker available' "$hub_log_file"
    if grep -Fq "udp-limit-received b'reverse-offline-no-worker'" "$edge_udp_echo_log_file"; then
        printf 'The Edge LAN received a UDP packet while its Bridge was offline.\n' >&2
        exit 1
    fi

    target/debug/chimera_server_app \
        --config "$edge_config_file" \
        >>"$edge_log_file" 2>&1 &
    edge_pid=$!
    worker_attached=false
    for attempt in $(seq 1 100); do
        if (( $(grep -Fc 'attached VLESS Reverse Portal worker' "$hub_log_file") >= 2 )); then
            worker_attached=true
            break
        fi
        if ! kill -0 "$edge_pid" 2>/dev/null; then
            printf 'Edge Bridge exited before reattaching to the Hub.\n' >&2
            exit 1
        fi
        sleep 0.1
    done
    if [[ "$worker_attached" != true ]]; then
        printf 'Hub did not observe the Edge Reverse worker reattach.\n' >&2
        exit 1
    fi
    printf 'probe-recovered\n' >&"$offline_udp_write_fd"
    if ! IFS= read -r -t 8 offline_udp_state <&"$offline_udp_read_fd" \
        || [[ "$offline_udp_state" != udp-recovered-same-tuple-* ]]; then
        printf 'Live TUN UDP tuple did not recover after the Bridge reattached.\n' >&2
        exit 1
    fi
    if ! wait "$offline_udp_client_pid"; then
        printf 'Live TUN Reverse UDP outage client exited with an error.\n' >&2
        exit 1
    fi
    offline_udp_client_pid=
    grep -Fq "udp-limit-received b'reverse-offline-before'" "$edge_udp_echo_log_file"
    grep -Fq "udp-limit-received b'reverse-offline-recovered-" "$edge_udp_echo_log_file"
    if grep -Fq "udp-limit-received b'reverse-offline-no-worker'" "$edge_udp_echo_log_file"; then
        printf 'The Edge LAN received the offline-only UDP marker.\n' >&2
        exit 1
    fi
    kill -0 "$hub_pid"
    kill -0 "$server_pid"
    printf 'Live Linux TUN UDP failed closed with no Reverse worker and recovered on the same source/target tuple after Bridge reattachment.\n'
    exit 0
fi

# Exercise both the iperf3 control connection and sustained TCP data stream
# through the same TUN/Hub/Reverse/Edge route before opening the parallel LAN
# UDP clients below. This catches stale per-session close races that a single
# deterministic echo cannot expose.
for attempt in $(seq 1 50); do
    if grep -q 'Server listening on 5201' "$edge_iperf_log_file"; then
        break
    fi
    sleep 0.1
done
grep -q 'Server listening on 5201' "$edge_iperf_log_file"
nsenter --net="/proc/$office_client_ns_pid/ns/net" iperf3 \
    --client 10.44.0.20 \
    --port 5201 \
    --time 3 \
    --json \
    >"$iperf_client_result_file" \
    2>"$iperf_client_error_file"
python3 - "$iperf_client_result_file" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
sent = report["end"]["sum_sent"]
received = report["end"]["sum_received"]
if sent["bytes"] <= 0 or received["bytes"] <= 0:
    raise SystemExit(f"TCP iperf3 transferred no payload: {report['end']!r}")
print(
    "TCP iperf3 passed: "
    f"sent={sent['bytes']} bytes received={received['bytes']} bytes "
    f"throughput={received['bits_per_second'] / 1_000_000:.1f} Mbit/s"
)
PY

# Start two normal LAN hosts together. Client A opens two distinct UDP source
# tuples and client B opens one; both retain their sockets briefly so the
# independent client sessions overlap before the configured-capacity check.
nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 -u - <<'PY' >"$office_udp_client_a_log_file" 2>&1 &
import socket
import time

target = ("10.44.0.20", 39642)
markers = [b"site-gateway-multi-client-a-1", b"site-gateway-multi-client-a-2"]
sockets = []
for marker in markers:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    client.sendto(marker, target)
    sockets.append((client, marker))
for client, marker in sockets:
    reply, source = client.recvfrom(128)
    if reply != marker or source != target:
        raise SystemExit(f"unexpected first-client UDP reply: {reply!r} from {source!r}")
print("multi-client-a-passed", flush=True)
time.sleep(1)
for client, _ in sockets:
    client.close()
PY
office_udp_client_a_pid=$!
nsenter --net="/proc/$office_client_2_ns_pid/ns/net" python3 -u - <<'PY' >"$office_udp_client_b_log_file" 2>&1 &
import socket
import time

target = ("10.44.0.20", 39642)
marker = b"site-gateway-multi-client-b-1"
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(5)
client.sendto(marker, target)
reply, source = client.recvfrom(128)
if reply != marker or source != target:
    raise SystemExit(f"unexpected second-client UDP reply: {reply!r} from {source!r}")
print("multi-client-b-passed", flush=True)
time.sleep(1)
client.close()
PY
office_udp_client_b_pid=$!
wait "$office_udp_client_a_pid"
office_udp_client_a_pid=
wait "$office_udp_client_b_pid"
office_udp_client_b_pid=

setpriv --reuid=1 python3 - <<'PY'
import socket
import struct

target_ip = "198.18.0.1"

tcp = socket.create_connection((target_ip, 39641), timeout=3)
tcp.settimeout(3)
tcp.sendall(b"tun-tcp")
tcp_reply = tcp.recv(16)
if tcp_reply != b"tun-tcp":
    raise SystemExit(f"unexpected TCP echo: {tcp_reply!r}")
if tcp.recv(1) != b"":
    raise SystemExit("TUN TCP client received unexpected data after target close")
tcp.close()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
udp.sendto(b"tun-udp", (target_ip, 39642))
udp_reply, udp_source = udp.recvfrom(16)
if udp_reply != b"tun-udp":
    raise SystemExit(f"unexpected UDP echo: {udp_reply!r}")
if udp_source != (target_ip, 39642):
    raise SystemExit(f"unexpected UDP source: {udp_source!r}")
large_udp_payload = bytes(index % 251 for index in range(4096))
udp.sendto(large_udp_payload, (target_ip, 39642))
udp_reply, udp_source = udp.recvfrom(8192)
if udp_reply != large_udp_payload:
    raise SystemExit(f"unexpected large UDP echo length: {len(udp_reply)}")
if udp_source != (target_ip, 39642):
    raise SystemExit(f"unexpected large UDP source: {udp_source!r}")
udp.close()

overlay_target = "10.44.0.20"
held_tcp = []
for index in range(1, 9):
    payload = f"reverse-load-{index}".encode()
    connection = socket.create_connection((overlay_target, 39641), timeout=5)
    connection.settimeout(5)
    connection.sendall(payload)
    reply = connection.recv(64)
    if reply != payload:
        raise SystemExit(f"unexpected concurrent Reverse TCP echo: {reply!r}")
    held_tcp.append(connection)

try:
    excess = socket.create_connection((overlay_target, 39641), timeout=5)
    excess.settimeout(3)
    excess.sendall(b"reverse-load-excess")
    excess_reply = excess.recv(64)
except (OSError, TimeoutError, socket.timeout):
    excess_reply = None
finally:
    if "excess" in locals():
        excess.close()
if excess_reply not in (None, b""):
    raise SystemExit(f"over-limit Reverse TCP flow reached the LAN: {excess_reply!r}")
for connection in held_tcp:
    connection.close()

import time

recovery_deadline = time.monotonic() + 12
attempts = 0
while time.monotonic() < recovery_deadline:
    attempts += 1
    try:
        recovered = socket.create_connection((overlay_target, 39641), timeout=1)
        recovered.settimeout(1)
        recovered.sendall(b"reverse-load-recovered")
        recovered_reply = recovered.recv(64)
        recovered.close()
        if recovered_reply == b"reverse-load-recovered":
            print(f"TUN TCP permit and Reverse Mux worker recovered after {attempts} attempt(s)", flush=True)
            break
    except (OSError, TimeoutError, socket.timeout):
        pass
    time.sleep(0.1)
else:
    raise SystemExit("TUN TCP permit and Reverse Mux worker did not recover within 12 seconds")

tcp = socket.create_connection((overlay_target, 39641), timeout=5)
tcp.settimeout(5)
tcp.sendall(b"reverse-tcp")
tcp_reply = tcp.recv(16)
if tcp_reply != b"reverse-tcp":
    raise SystemExit(f"unexpected Reverse TCP echo: {tcp_reply!r}")
tcp.close()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(b"reverse-udp", (overlay_target, 39642))
udp_reply, udp_source = udp.recvfrom(16)
if udp_reply != b"reverse-udp":
    raise SystemExit(f"unexpected Reverse UDP echo: {udp_reply!r}")
if udp_source != (overlay_target, 39642):
    raise SystemExit(f"unexpected Overlay UDP source: {udp_source!r}")
large_udp_payload = bytes(index % 251 for index in range(4096))
udp.sendto(large_udp_payload, (overlay_target, 39642))
udp_reply, udp_source = udp.recvfrom(8192)
if udp_reply != large_udp_payload:
    raise SystemExit(f"unexpected large Reverse UDP echo length: {len(udp_reply)}")
if udp_source != (overlay_target, 39642):
    raise SystemExit(f"unexpected large Overlay UDP source: {udp_source!r}")
udp.close()

overlay_target_v6 = "2001:db8:44::20"
tcp = socket.create_connection((overlay_target_v6, 39644), timeout=5)
tcp.settimeout(5)
tcp.sendall(b"reverse-v6-tcp")
tcp_reply = tcp.recv(32)
if tcp_reply != b"reverse-v6-tcp":
    raise SystemExit(f"unexpected IPv6 Reverse TCP echo: {tcp_reply!r}")
tcp.close()

udp_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp_v6.settimeout(5)
for payload in (b"reverse-v6-udp", bytes(index % 251 for index in range(4096))):
    udp_v6.sendto(payload, (overlay_target_v6, 39645))
    udp_reply, udp_source = udp_v6.recvfrom(8192)
    if udp_reply != payload:
        raise SystemExit(f"unexpected IPv6 Reverse UDP echo length: {len(udp_reply)}")
    if udp_source[:2] != (overlay_target_v6, 39645):
        raise SystemExit(f"unexpected IPv6 Overlay UDP source: {udp_source!r}")
udp_v6.close()

held_udp = []
for payload in (b"udp-limit-admitted-1", b"udp-limit-admitted-2"):
    flow = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flow.settimeout(5)
    flow.sendto(payload, (overlay_target, 39642))
    reply, source = flow.recvfrom(128)
    if reply != payload or source != (overlay_target, 39642):
        raise SystemExit(f"unexpected admitted UDP session response: {reply!r} from {source!r}")
    held_udp.append(flow)

excess_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
excess_udp.settimeout(0.75)
excess_udp.sendto(b"udp-limit-excess", (overlay_target, 39642))
try:
    excess_reply, excess_source = excess_udp.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"over-limit UDP session reached the Edge: {excess_reply!r} from {excess_source!r}")
excess_udp.close()
for flow in held_udp:
    flow.close()

dns_target = ("10.44.0.53", 53)
dns_question = b"\x07example\x04test\x00\x00\x01\x00\x01"
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns.settimeout(5)
for recovery_cycle in range(1, 4):
    print(f"waiting 62 seconds for UDP idle expiry before recovery cycle {recovery_cycle}", flush=True)
    time.sleep(62)
    query_id = 0x1A2A + recovery_cycle
    dns_query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + dns_question
    dns.sendto(dns_query, dns_target)
    dns_response, dns_source = dns.recvfrom(512)
    expected_dns_response = (
        struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
        + dns_question
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x35"
    )
    if dns_response != expected_dns_response:
        raise SystemExit(f"unexpected UDP DNS response in recovery cycle {recovery_cycle}: {dns_response!r}")
    if dns_source != dns_target:
        raise SystemExit(f"unexpected recovered DNS source tuple in cycle {recovery_cycle}: {dns_source!r}")
    print(f"udp-idle-recovery-cycle-{recovery_cycle}-passed", flush=True)
dns.close()
PY

# Exercise the advertised site-gateway use case: a separate ordinary LAN
# host routes remote prefixes through this Linux gateway and has no proxy
# client. The gateway forwards those packets into the same TUN data path.
nsenter --net="/proc/$office_client_ns_pid/ns/net" python3 - <<'PY'
import ipaddress
import socket
import struct
import time

target = ("10.44.0.20", 39641)
with socket.create_connection(target, timeout=5) as connection:
    connection.settimeout(5)
    connection.sendall(b"office-lan-tcp")
    reply = connection.recv(64)
    if reply != b"office-lan-tcp":
        raise SystemExit(f"unexpected Office LAN TCP echo: {reply!r}")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
for payload in (b"office-lan-udp", bytes(index % 251 for index in range(4096))):
    udp.sendto(payload, ("10.44.0.20", 39642))
    reply, source = udp.recvfrom(8192)
    if reply != payload:
        raise SystemExit(f"unexpected Office LAN UDP echo length: {len(reply)}")
    if source != ("10.44.0.20", 39642):
        raise SystemExit(f"unexpected Office LAN UDP source: {source!r}")
udp.sendto(b"office-lan-multi-target", ("10.44.0.21", 39642))
reply, source = udp.recvfrom(128)
if reply != b"office-lan-multi-target":
    raise SystemExit(f"unexpected Office LAN same-port target echo: {reply!r}")
if source != ("10.44.0.21", 39642):
    raise SystemExit(f"unexpected Office LAN second Overlay source: {source!r}")
udp.close()

# The Edge ACL and Freedom finalRules both allow this test endpoint, but the
# Hub's identity/port allowlist deliberately omits port 39647.
tcp_marker = b"hub-port-deny-office-lan-tcp"
try:
    denied_tcp = socket.create_connection(("10.44.0.20", 39647), timeout=3)
    denied_tcp.settimeout(1)
    with denied_tcp:
        denied_tcp.sendall(tcp_marker)
        try:
            tcp_reply = denied_tcp.recv(128)
        except socket.timeout:
            tcp_reply = b""
        if tcp_reply:
            raise SystemExit(f"Hub-denied TCP received a reply: {tcp_reply!r}")
except OSError:
    pass

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1)
udp_marker = b"hub-port-deny-office-lan-udp"
udp.sendto(udp_marker, ("10.44.0.20", 39647))
try:
    udp_reply, udp_source = udp.recvfrom(128)
except socket.timeout:
    pass
else:
    raise SystemExit(f"Hub-denied UDP received {udp_reply!r} from {udp_source!r}")
udp.close()

def checksum(header):
    if len(header) % 2:
        header += b"\x00"
    total = sum((header[index] << 8) | header[index + 1] for index in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

source_ip = ipaddress.IPv4Address("10.251.0.2")
target_ip = ipaddress.IPv4Address("10.44.0.20")
source_port = 45_000
target_port = 39_642
fragmented_udp = {}
fragment_marker = {}
fragment_payloads = {}
for identification in range(65):
    marker = f"fragment-pressure-v4-{identification:02d}".encode()
    udp_payload = marker + bytes((identification + offset) % 251 for offset in range(1192 - len(marker)))
    datagram = struct.pack("!HHHH", source_port, target_port, 1200, 0) + udp_payload
    fragment_marker[identification] = marker
    fragment_payloads[identification] = udp_payload
    fragmented_udp[identification] = datagram

fragment_replies = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fragment_replies.bind((str(source_ip), source_port))
fragment_replies.settimeout(10)
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def ipv4_fragment(identification, offset, more_fragments, contents):
    flags_offset = offset // 8
    if more_fragments:
        flags_offset |= 0x2000
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(contents),
        identification,
        flags_offset,
        64,
        socket.IPPROTO_UDP,
        0,
        source_ip.packed,
        target_ip.packed,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + contents

for identification, datagram in fragmented_udp.items():
    raw.sendto(ipv4_fragment(identification, 0, True, datagram[:800]), (str(target_ip), 0))
    time.sleep(0.002)

# The 65th first fragment forces the stack to evict the oldest of the 64
# bounded reassembly entries. Complete the retained entries; leave ID 0's
# tail absent so it cannot allocate a replacement incomplete set.
for identification in range(64, 0, -1):
    raw.sendto(ipv4_fragment(identification, 800, False, fragmented_udp[identification][800:]), (str(target_ip), 0))
    time.sleep(0.002)
raw.close()

received_fragments = set()
while len(received_fragments) < 64:
    try:
        response, source = fragment_replies.recvfrom(2048)
    except socket.timeout:
        missing = sorted(set(range(1, 65)) - received_fragments)
        raise SystemExit(f"timed out after {len(received_fragments)} of 64 fragment-pressure replies; missing IDs: {missing!r}")
    if source != (str(target_ip), target_port):
        raise SystemExit(f"unexpected source after fragment pressure: {source!r}")
    identification = next(
        (index for index, marker in fragment_marker.items() if response.startswith(marker)),
        None,
    )
    if identification is None or identification == 0:
        raise SystemExit(f"unexpected or evicted fragment-set response: {response[:32]!r}")
    if response != fragment_payloads[identification]:
        raise SystemExit(f"reassembled UDP payload mismatch for fragment set {identification}")
    received_fragments.add(identification)
if received_fragments != set(range(1, 65)):
    raise SystemExit(f"unexpected completed fragment-set IDs: {sorted(received_fragments)!r}")
fragment_replies.close()
print("tun-fragment-pressure-v4-64-of-65-passed", flush=True)

source_ip_v6 = ipaddress.IPv6Address("fd18:251::2")
target_ip_v6 = ipaddress.IPv6Address("2001:db8:44::20")
source_port_v6 = 45_001
target_port_v6 = 39_645

fragment_replies_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
fragment_replies_v6.bind((str(source_ip_v6), source_port_v6, 0, 0))
fragment_replies_v6.settimeout(10)
raw_v6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw_v6.setsockopt(socket.IPPROTO_IPV6, 36, 1)  # Linux IPV6_HDRINCL.

def ipv6_udp_fragment(identification, offset, more_fragments, contents):
    fragment_offset_flags = (offset // 8) << 3
    if more_fragments:
        fragment_offset_flags |= 1
    header = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        8 + len(contents),
        44,
        64,
        source_ip_v6.packed,
        target_ip_v6.packed,
    )
    fragment_header = struct.pack(
        "!BBHI",
        socket.IPPROTO_UDP,
        0,
        fragment_offset_flags,
        identification,
    )
    return header + fragment_header + contents

fragment_markers_v6 = {}
fragment_payloads_v6 = {}
fragmented_udp_v6 = {}
for identification in range(65):
    marker = f"fragment-pressure-v6-{identification:02d}".encode()
    udp_payload = marker + bytes((identification + offset) % 251 for offset in range(1192 - len(marker)))
    udp_datagram = struct.pack("!HHHH", source_port_v6, target_port_v6, 1200, 0) + udp_payload
    pseudo_header = (
        source_ip_v6.packed
        + target_ip_v6.packed
        + struct.pack("!I3xB", len(udp_datagram), socket.IPPROTO_UDP)
    )
    udp_checksum = checksum(pseudo_header + udp_datagram) or 0xFFFF
    udp_datagram = udp_datagram[:6] + struct.pack("!H", udp_checksum) + udp_datagram[8:]
    fragment_markers_v6[identification] = marker
    fragment_payloads_v6[identification] = udp_payload
    fragmented_udp_v6[identification] = udp_datagram

for identification, datagram in fragmented_udp_v6.items():
    raw_v6.sendto(
        ipv6_udp_fragment(identification, 0, True, datagram[:800]),
        (str(target_ip_v6), 0, 0, 0),
    )
    time.sleep(0.002)

for identification in range(64, 0, -1):
    raw_v6.sendto(
        ipv6_udp_fragment(identification, 800, False, fragmented_udp_v6[identification][800:]),
        (str(target_ip_v6), 0, 0, 0),
    )
    time.sleep(0.002)
raw_v6.close()

received_fragments_v6 = set()
while len(received_fragments_v6) < 64:
    try:
        response, source = fragment_replies_v6.recvfrom(2048)
    except socket.timeout:
        missing = sorted(set(range(1, 65)) - received_fragments_v6)
        raise SystemExit(
            f"timed out after {len(received_fragments_v6)} of 64 IPv6 fragment-pressure replies; "
            f"missing IDs: {missing!r}"
        )
    if source[:2] != (str(target_ip_v6), target_port_v6):
        raise SystemExit(f"unexpected IPv6 source after fragment pressure: {source!r}")
    identification = next(
        (index for index, marker in fragment_markers_v6.items() if response.startswith(marker)),
        None,
    )
    if identification is None or identification == 0:
        raise SystemExit(f"unexpected or evicted IPv6 fragment-set response: {response[:40]!r}")
    if response != fragment_payloads_v6[identification]:
        raise SystemExit(f"IPv6 reassembled UDP payload mismatch for set {identification}")
    received_fragments_v6.add(identification)
if received_fragments_v6 != set(range(1, 65)):
    raise SystemExit(f"unexpected completed IPv6 fragment IDs: {sorted(received_fragments_v6)!r}")
fragment_replies_v6.close()
print("tun-fragment-pressure-v6-64-of-65-passed", flush=True)

target_v6 = ("2001:db8:44::20", 39644)
with socket.create_connection(target_v6, timeout=5) as connection:
    connection.settimeout(5)
    connection.sendall(b"office-lan-v6-tcp")
    reply = connection.recv(64)
    if reply != b"office-lan-v6-tcp":
        raise SystemExit(f"unexpected Office LAN IPv6 TCP echo: {reply!r}")

udp_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp_v6.settimeout(5)
for payload in (b"office-lan-v6-udp", bytes(index % 251 for index in range(4096))):
    udp_v6.sendto(payload, ("2001:db8:44::20", 39645))
    reply, source = udp_v6.recvfrom(8192)
    if reply != payload:
        raise SystemExit(f"unexpected Office LAN IPv6 UDP echo length: {len(reply)}")
    if source[:2] != ("2001:db8:44::20", 39645):
        raise SystemExit(f"unexpected Office LAN IPv6 UDP source: {source!r}")
udp_v6.close()
PY

# iperf3 uses TCP for control and UDP for test traffic on the same port. Keep
# UDP datagrams below the VLESS Reverse 8192-byte packet limit.
nsenter --net="/proc/$office_client_ns_pid/ns/net" iperf3 \
    --client 10.44.0.20 \
    --port 5201 \
    --udp \
    --bandwidth 1M \
    --length 1200 \
    --time 3 \
    --json \
    >"$iperf_client_result_file" \
    2>"$iperf_client_error_file"
python3 - "$iperf_client_result_file" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
sent = report["end"]["sum_sent"]
received = report["end"]["sum_received"]
if sent["bytes"] <= 0 or received["bytes"] <= 0 or received["packets"] <= 0:
    raise SystemExit(f"UDP iperf3 transferred no payload: {report['end']!r}")
if not 0 <= received["lost_percent"] <= 100:
    raise SystemExit(f"invalid UDP iperf3 loss percentage: {received['lost_percent']!r}")
print(
    "UDP iperf3 passed: "
    f"sent={sent['bytes']} bytes received={received['bytes']} bytes "
    f"loss={received['lost_percent']:.2f}%"
)
PY
setpriv --reuid=1 python3 - <<'PY'
import hashlib
import socket
import threading

prefix = b"site-smoke-large-tcp-v4\0"
payload = prefix + bytes(index % 251 for index in range(4 * 1024 * 1024))
received = bytearray()
send_errors = []
connection = socket.create_connection(("10.44.0.20", 39641), timeout=10)
connection.settimeout(30)

def send_and_half_close():
    try:
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
    except BaseException as error:
        send_errors.append(error)

sender = threading.Thread(target=send_and_half_close)
sender.start()
while True:
    chunk = connection.recv(65536)
    if not chunk:
        break
    received.extend(chunk)
sender.join(timeout=30)
connection.close()
if sender.is_alive():
    raise SystemExit("large TCP echo sender did not finish after half-close")
if send_errors:
    raise SystemExit(f"large TCP echo sender failed: {send_errors[0]!r}")
if received != payload:
    raise SystemExit(
        f"large TCP echo mismatch: sent={len(payload)} received={len(received)}"
    )
print(
    "TCP echo/half-close passed: "
    f"bytes={len(received)} sha256={hashlib.sha256(received).hexdigest()}"
)
PY
kill -TERM "$edge_iperf_server_pid"
wait "$edge_iperf_server_pid" 2>/dev/null || true
edge_iperf_server_pid=

# Observatory probes use the configured VLESS outbound and an HTTP endpoint
# inside the remote site. Exercise healthy, failed, and recovered states.
health_success_count=$(python3 - "$server_log_file" <<'PY'
from pathlib import Path
import re
import sys

text = re.sub(r"\x1b\[[0-9;]*m", "", Path(sys.argv[1]).read_text(errors="replace"))
print(sum(
    "routing observatory probe completed" in line
    and "to-hub" in line
    and "alive=true" in line
    for line in text.splitlines()
))
PY
)
kill -TERM "$health_http_pid"
wait "$health_http_pid" 2>/dev/null || true
health_http_pid=
wait_health_observation false 1
start_health_http
wait_health_observation true "$((health_success_count + 1))"

# The earlier LAN, policy and iperf probes intentionally exercise enough UDP
# tuples to reach maxUdpSessions. Let their normal 60-second idle timeout
# release the bounded session slots before the separate Hub-restart probe.
printf 'waiting 62 seconds for TUN UDP session expiry before Hub restart probes\n'
sleep 62

# Keep a site-to-site TCP flow open across Hub shutdown. The Hub's short
# configured drain deadline bounds how long an existing flow may remain open;
# once forced shutdown closes its owning stream, the TUN client must observe it.
setpriv --reuid=1 python3 -u - <<'PY' >"$active_tcp_result_file" 2>&1 &
import socket

target = ("10.44.0.20", 39641)
marker = b"reverse-held-during-hub-restart"
status = "setup-failed"
try:
    with socket.create_connection(target, timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(marker)
        if connection.recv(128) != marker:
            raise SystemExit("held TCP flow did not receive its initial echo")
        print("ready", flush=True)
        connection.settimeout(8)
        try:
            payload = connection.recv(1)
            status = "eof" if payload == b"" else f"unexpected-data:{payload!r}"
        except ConnectionResetError:
            status = "reset"
        except TimeoutError:
            status = "timeout"
except OSError as error:
    status = f"socket-error:{error.errno}"

print(status, flush=True)
if status not in ("eof", "reset"):
    raise SystemExit(f"active TCP close was not visible to the TUN client: {status}")
PY
active_tcp_client_pid=$!
active_tcp_ready=false
for attempt in $(seq 1 100); do
    if grep -qx 'ready' "$active_tcp_result_file"; then
        active_tcp_ready=true
        break
    fi
    if ! kill -0 "$active_tcp_client_pid" 2>/dev/null; then
        cat "$active_tcp_result_file" >&2
        printf 'Active TUN TCP flow did not reach the Edge before Hub shutdown.\n' >&2
        exit 1
    fi
    sleep 0.05
done
if [[ "$active_tcp_ready" != true ]]; then
    printf 'Active TUN TCP flow did not become ready before Hub shutdown.\n' >&2
    exit 1
fi

active_udp_client_program=$(cat <<'PY'
import socket
import sys
import time

target = ("10.44.0.20", 39642)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

before = b"reverse-udp-held-before-hub-restart"
sock.sendto(before, target)
reply, source = sock.recvfrom(128)
if reply != before or source != target:
    raise SystemExit(f"unexpected pre-restart UDP echo: {reply!r} from {source!r}")
print("udp-ready", flush=True)

if sys.stdin.readline().strip() != "after-restart":
    raise SystemExit("missing post-restart UDP test trigger")

after = b"reverse-udp-held-after-hub-restart"
sock.sendto(after, target)
reply, source = sock.recvfrom(128)
if reply != after or source != target:
    raise SystemExit(f"same-tuple UDP session did not recover: {reply!r} from {source!r}")
print("udp-hub-reconnected", flush=True)

for cycle in range(1, 4):
    expected_trigger = f"after-edge-restart-{cycle}"
    if sys.stdin.readline().strip() != expected_trigger:
        raise SystemExit(f"missing post-Edge-restart UDP trigger for cycle {cycle}")

    after = f"reverse-udp-held-after-edge-restart-{cycle}".encode()
    # One datagram may be lost while the Edge worker is replaced. Verify that
    # the next datagram on the same source tuple is delivered without
    # recreating the client socket or changing its target.
    sent_payloads = set()
    for attempt in range(12):
        payload = after + f"-try-{attempt + 1}".encode()
        sent_payloads.add(payload)
        sock.settimeout(0.5)
        sock.sendto(payload, target)
        try:
            reply, source = sock.recvfrom(128)
        except TimeoutError:
            continue
        if reply not in sent_payloads or source != target:
            raise SystemExit(f"same-tuple UDP reply mismatch after Edge restart cycle {cycle}: {reply!r} from {source!r}")
        print(f"udp-edge-reconnected-{cycle}-{attempt + 1}", flush=True)
        break
    else:
        raise SystemExit(f"same-tuple UDP session did not recover after Edge restart cycle {cycle}")

    stable = after + b"-stable"
    sock.sendto(stable, target)
    deadline = time.monotonic() + 5
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"stable UDP packet timed out after Edge restart cycle {cycle}")
        sock.settimeout(remaining)
        reply, source = sock.recvfrom(128)
        if source != target:
            raise SystemExit(f"unexpected UDP source after Edge restart cycle {cycle}: {source!r}")
        if reply == stable:
            break
        if reply not in sent_payloads:
            raise SystemExit(f"unexpected UDP payload after Edge restart cycle {cycle}: {reply!r}")
    print(f"udp-edge-session-stable-{cycle}", flush=True)
sock.close()
print("udp-test-complete", flush=True)
PY
)
coproc ACTIVE_UDP_CLIENT {
    setpriv --reuid=1 python3 -u -c "$active_udp_client_program"
}
active_udp_client_pid=$ACTIVE_UDP_CLIENT_PID
active_udp_read_fd=${ACTIVE_UDP_CLIENT[0]}
active_udp_write_fd=${ACTIVE_UDP_CLIENT[1]}
if ! IFS= read -r -t 5 udp_state <&"$active_udp_read_fd" || [[ "$udp_state" != udp-ready ]]; then
    printf 'TUN UDP flow did not become active before Hub shutdown.\n' >&2
    exit 1
fi

# Restart the Hub while the Edge Bridge process remains alive. Its supervised
# monitor should reconnect and restore new TUN TCP/UDP site-to-site flows.
kill -TERM "$hub_pid"
wait "$hub_pid"
hub_pid=
if ! wait "$active_tcp_client_pid"; then
    cat "$active_tcp_result_file" >&2
    exit 1
fi
active_tcp_client_pid=
grep -qx 'ready' "$active_tcp_result_file"
grep -Eq '^(eof|reset)$' "$active_tcp_result_file"
sleep 0.25
target/debug/chimera_server_app \
    --config "$hub_config_file" \
    >"$hub_log_file" 2>&1 &
hub_pid=$!
hub_ready=false
for attempt in $(seq 1 100); do
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
        printf 'Hub Chimera exited while restarting for the Reverse reconnect test.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$hub_ready" != true ]]; then
    printf 'Hub Chimera did not reopen its VLESS listener for the Reverse reconnect test.\n' >&2
    exit 1
fi

setpriv --reuid=1 python3 - <<'PY'
import socket
import time

target_ip = "10.44.0.20"
for attempt in range(60):
    try:
        tcp = socket.create_connection((target_ip, 39641), timeout=1)
        tcp.settimeout(1)
        tcp.sendall(b"reverse-after-hub-restart")
        reply = tcp.recv(64)
        tcp.close()
        if reply == b"reverse-after-hub-restart":
            break
    except (OSError, TimeoutError, socket.timeout):
        pass
    if attempt == 59:
        raise SystemExit("Reverse TCP did not recover after Hub restart")
    time.sleep(0.2)

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(b"reverse-udp-after-hub-restart", (target_ip, 39642))
reply, source = udp.recvfrom(128)
udp.close()
if reply != b"reverse-udp-after-hub-restart":
    raise SystemExit(f"unexpected UDP echo after Hub restart: {reply!r}")
if source != (target_ip, 39642):
    raise SystemExit(f"unexpected UDP source after Hub restart: {source!r}")
PY

printf 'after-restart\n' >&"$active_udp_write_fd"
    if ! IFS= read -r -t 5 udp_state <&"$active_udp_read_fd" || [[ "$udp_state" != udp-hub-reconnected ]]; then
        printf 'The same TUN UDP source tuple did not recover after Hub restart.\n' >&2
        exit 1
    fi
    printf 'same-tuple TUN UDP flow recovered after Hub restart\n'

# Restart only the Edge Bridge repeatedly, leaving Hub and Office TUN server
# untouched. Keep one UDP socket alive across all cycles so source tuple and
# server-side session/permit recovery are exercised together.
edge_udp_recovery_cycle=0
edge_udp_recovery_attempt=0
for edge_restart_cycle in 1 2 3; do
    kill -TERM "$edge_pid"
    wait "$edge_pid"
    edge_pid=
    sleep 0.25
    target/debug/chimera_server_app \
        --config "$edge_config_file" \
        >>"$edge_log_file" 2>&1 &
    edge_pid=$!

    if [[ "$edge_restart_cycle" == 1 ]]; then
        setpriv --reuid=1 python3 - <<'PY'
import socket
import time

target = ("10.44.0.20", 39641)
marker = b"reverse-after-edge-restart"
for attempt in range(60):
    try:
        with socket.create_connection(target, timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(marker)
            if connection.recv(64) == marker:
                break
    except (OSError, TimeoutError, socket.timeout):
        pass
    if attempt == 59:
        raise SystemExit("Reverse TCP did not recover after Edge restart")
    time.sleep(0.2)
PY
    fi

    printf 'after-edge-restart-%s\n' "$edge_restart_cycle" >&"$active_udp_write_fd"
    if ! IFS= read -r -t 8 udp_state <&"$active_udp_read_fd" || [[ "$udp_state" != "udp-edge-reconnected-${edge_restart_cycle}-"* ]]; then
        printf 'The same TUN UDP source tuple did not recover after Edge restart cycle %s.\n' "$edge_restart_cycle" >&2
        exit 1
    fi
    edge_udp_recovery_cycle=$edge_restart_cycle
    edge_udp_recovery_attempt=${udp_state##*-}
    if ! IFS= read -r -t 5 udp_state <&"$active_udp_read_fd" || [[ "$udp_state" != "udp-edge-session-stable-${edge_restart_cycle}" ]]; then
        printf 'The recovered same-tuple UDP session did not remain usable after Edge restart cycle %s.\n' "$edge_restart_cycle" >&2
        exit 1
    fi
    printf 'same-tuple TUN UDP flow remained stable after Edge restart cycle %s\n' "$edge_restart_cycle"
done
if ! IFS= read -r -t 5 udp_state <&"$active_udp_read_fd" || [[ "$udp_state" != udp-test-complete ]]; then
    printf 'The persistent TUN UDP restart client did not finish cleanly.\n' >&2
    exit 1
fi
if ! wait "$active_udp_client_pid"; then
    printf 'The persistent TUN UDP restart client exited with an error.\n' >&2
    exit 1
fi
active_udp_client_pid=

ip route get 198.18.0.20 | grep -F 'via 10.250.0.2 dev site-lan-host' >/dev/null
ip route get 198.18.0.21 | grep -F 'via 10.250.0.2 dev site-lan-host' >/dev/null
ip route get 198.18.0.53 | grep -F 'via 10.250.0.2 dev site-lan-host' >/dev/null
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -o addr show dev site-lan-edge | grep -F '198.18.0.20/32' >/dev/null
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -o addr show dev site-lan-edge | grep -F '198.18.0.21/32' >/dev/null
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -o addr show dev site-lan-edge | grep -F '198.18.0.53/32' >/dev/null
ip -6 route get fd18:198:18::20 | grep -F 'via fd18:250::2 dev site-lan-host' >/dev/null
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 -o addr show dev site-lan-edge | grep -F 'fd18:198:18::20/128' >/dev/null
grep -q "tcp-received b'reverse-tcp'" "$edge_tcp_echo_log_file"
[[ $(grep -Ec "tcp-received b'reverse-load-[1-8]'" "$edge_tcp_echo_log_file") -eq 8 ]]
grep -q "tcp-received b'reverse-load-recovered'" "$edge_tcp_echo_log_file"
grep -q "tcp-received b'reverse-after-hub-restart'" "$edge_tcp_echo_log_file"
grep -q "tcp-received b'reverse-after-edge-restart'" "$edge_tcp_echo_log_file"
grep -q "tcp-received b'office-lan-tcp'" "$edge_tcp_echo_log_file"
if grep -Fq 'hub-port-deny-office-lan-' "$edge_hub_policy_echo_log_file"; then
    printf 'Hub-denied Office LAN traffic reached an Edge-allowed target.\n' >&2
    exit 1
fi
grep -q 'hub-policy-targets-ready' "$edge_hub_policy_echo_log_file"
grep -q 'TUN TCP connection rejected at configured limit' "$server_log_file"
grep -Fq "udp-limit-received b'udp-limit-admitted-1'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'udp-limit-admitted-2'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'site-gateway-multi-client-a-1'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'site-gateway-multi-client-a-2'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'site-gateway-multi-client-b-1'" "$edge_udp_echo_log_file"
grep -Fq 'multi-client-a-passed' "$office_udp_client_a_log_file"
grep -Fq 'multi-client-b-passed' "$office_udp_client_b_log_file"
grep -Fq "udp-limit-received b'reverse-udp-held-before-hub-restart'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'reverse-udp-held-after-hub-restart'" "$edge_udp_echo_log_file"
for edge_restart_cycle in 1 2 3; do
    grep -Fq "udp-limit-received b'reverse-udp-held-after-edge-restart-${edge_restart_cycle}-stable'" "$edge_udp_echo_log_file"
done
grep -Fq "udp-limit-received b'reverse-udp-after-hub-restart'" "$edge_udp_echo_log_file"
grep -Fq "udp-limit-received b'office-lan-udp'" "$edge_udp_echo_log_file"
[[ $(grep -c 'udp-limit-received fragment-pressure family=v4 id=.* bytes=1192' "$edge_udp_echo_log_file") -eq 64 ]]
[[ $(grep -c 'udp-v6-fragment-pressure-received id=.* bytes=1192' "$edge_udp_v6_echo_log_file") -eq 64 ]]
grep -q 'evicting oldest UDP fragment reassembly because active limit (64) was reached' "$server_log_file"
grep -Fq "udp-second-target-received b'office-lan-multi-target'" "$edge_udp_second_echo_log_file"
[[ $(grep -c 'dns-query-served cycle=' "$edge_dns_log_file") -eq 3 ]]
grep -q 'Server listening on 5201' "$edge_iperf_log_file"
if grep -q 'udp-limit-excess' "$edge_udp_echo_log_file"; then
    printf 'Over-limit UDP session reached the Edge LAN.\n' >&2
    exit 1
fi
grep -q 'TUN UDP sessions rejected at configured limit' "$server_log_file"
grep -q 'udp-received 4096 bytes' "$edge_udp_echo_log_file"
grep -q "tcp-v6-received b'reverse-v6-tcp'" "$edge_tcp_v6_echo_log_file"
grep -q "tcp-v6-received b'office-lan-v6-tcp'" "$edge_tcp_v6_echo_log_file"
[[ $(grep -c 'udp-v6-received 17 bytes' "$edge_udp_v6_echo_log_file") -eq 1 ]]
[[ $(grep -c 'udp-v6-received 4096 bytes' "$edge_udp_v6_echo_log_file") -eq 2 ]]
grep -q 'udp-v6-received 4096 bytes' "$edge_udp_v6_echo_log_file"

python3 - "$edge_tcp_echo_log_file" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

prefix = b"site-smoke-large-tcp-v4\0"
payload = prefix + bytes(index % 251 for index in range(4 * 1024 * 1024))
expected = hashlib.sha256(payload).hexdigest()
text = Path(sys.argv[1]).read_text()
matches = re.findall(r"tcp-received large-flow bytes=(\d+) sha256=([0-9a-f]{64})", text)
if matches != [(str(len(payload)), expected)]:
    raise SystemExit(f"Edge did not verify the full TCP payload and half-close: {matches!r}")
print(f"Edge TCP receive check passed: bytes={len(payload)} sha256={expected}")
PY

python3 - <<'PY'
import socket

with socket.create_connection(("198.18.0.20", 39641), timeout=3) as stop:
    stop.sendall(b"__fixture_stop__")
    if stop.recv(1) != b"":
        raise SystemExit("TCP echo fixture did not close after its stop marker")
PY

python3 - <<'PY'
import socket

stop = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
stop.sendto(b"__stop__", ("198.18.0.20", 39642))
stop.close()
PY
wait "$tcp_echo_pid"
tcp_echo_pid=
wait "$udp_echo_pid"
udp_echo_pid=
wait "$edge_tcp_echo_pid"
edge_tcp_echo_pid=
wait "$edge_udp_echo_pid"
edge_udp_echo_pid=
wait "$edge_udp_second_echo_pid"
edge_udp_second_echo_pid=
wait "$edge_dns_pid"
edge_dns_pid=
wait "$edge_tcp_v6_echo_pid"
edge_tcp_v6_echo_pid=
wait "$edge_udp_v6_echo_pid"
edge_udp_v6_echo_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
if ip link show dev chimera-smoke >/dev/null 2>&1; then
    printf 'TUN device remained after server shutdown.\n' >&2
    exit 1
fi
kill -TERM "$edge_pid"
wait "$edge_pid"
edge_pid=
kill -TERM "$hub_pid"
wait "$hub_pid"
hub_pid=
kill -TERM "$lan_ns_pid"
wait "$lan_ns_pid" 2>/dev/null || true
lan_ns_pid=
kill -TERM "$office_client_ns_pid"
wait "$office_client_ns_pid" 2>/dev/null || true
office_client_ns_pid=
printf 'TUN forwarding/limits, concurrent UDP from two ordinary Office hosts, IPv4/IPv6 Office LAN TCP/UDP (including 4 KiB datagrams), same-port UDP to two Overlay targets, TCP/UDP iperf3, three-cycle UDP DNS idle-expiry recovery over one tuple, byte-verified 4 MiB TCP echo with half-close, VLESS HTTP health probe down/up transitions, active TCP close, same-source UDP recovery after Hub restart and %s sequential Edge restarts (last recovered on retry %s; a stable packet passed after every restart), veth LAN forwarding, and SIGTERM teardown passed in isolated namespaces.\n' "$edge_udp_recovery_cycle" "$edge_udp_recovery_attempt"
NAMESPACE_SCRIPT
