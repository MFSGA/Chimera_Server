#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)
host_uid=$(id -u)
user_name=$(id -un)
subuid_range=$(awk -F: -v name="$user_name" '$1 == name { print $2 ":" $3; exit }' /etc/subuid)
if [[ -z "$subuid_range" ]]; then
    printf 'A subordinate UID range for %s in /etc/subuid is required.\n' "$user_name" >&2
    exit 1
fi
subuid_start=$(cut -d: -f1 <<< "$subuid_range")
subuid_count=$(cut -d: -f2 <<< "$subuid_range")
for cmd in cargo unshare nsenter ip setpriv sysctl python3; do
    command -v "$cmd" >/dev/null
done
cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features tun-gateway,vless-reverse --locked

unshare --user --map-users="0:$host_uid:1" --map-users="1:$subuid_start:$subuid_count" --net bash -s <<'NS'
set -euo pipefail
trap 'exit_status=$?; printf "duplicate-LAN TUN namespace body failed with status %s at body line %s.\n" "$exit_status" "$LINENO" >&2' ERR
smoke=$(mktemp --suffix=.yaml)
hub=$(mktemp --suffix=.yaml)
edge_a=$(mktemp --suffix=.yaml)
edge_b=$(mktemp --suffix=.yaml)
log_hub=$(mktemp)
log_a=$(mktemp)
log_b=$(mktemp)
log_tun=$(mktemp)
log_echo_a=$(mktemp)
log_echo_b=$(mktemp)
log_policy_a=$(mktemp)
log_policy_b=$(mktemp)
server_pid=
hub_pid=
ns_a=
ns_b=
edge_a_pid=
edge_b_pid=
echo_a_pid=
echo_b_pid=
policy_a_pid=
policy_b_pid=
cleanup() {
    status=$?
    trap - EXIT
    if (( status != 0 )); then
        ip -s link show dev chimera-dupe >&2 || true
        ss -ntp >&2 || true
        printf '\n--- Hub ---\n' >&2; cat "$log_hub" >&2 || true
        printf '\n--- Edge A ---\n' >&2; cat "$log_a" >&2 || true
        printf '\n--- Edge B ---\n' >&2; cat "$log_b" >&2 || true
        printf '\n--- TUN ---\n' >&2; cat "$log_tun" >&2 || true
        printf '\n--- Echo A ---\n' >&2; cat "$log_echo_a" >&2 || true
        printf '\n--- Echo B ---\n' >&2; cat "$log_echo_b" >&2 || true
        printf '\n--- Policy A ---\n' >&2; cat "$log_policy_a" >&2 || true
        printf '\n--- Policy B ---\n' >&2; cat "$log_policy_b" >&2 || true
    fi
    for pid in "$server_pid" "$edge_a_pid" "$edge_b_pid" "$hub_pid" "$echo_a_pid" "$echo_b_pid" "$policy_a_pid" "$policy_b_pid" "$ns_a" "$ns_b"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -f "$smoke" "$hub" "$edge_a" "$edge_b" "$log_hub" "$log_a" "$log_b" "$log_tun" "$log_echo_a" "$log_echo_b" "$log_policy_a" "$log_policy_b"
    exit "$status"
}
trap cleanup EXIT

ip link set lo up
unshare --net sleep infinity >/dev/null 2>&1 &
ns_a=$!
unshare --net sleep infinity >/dev/null 2>&1 &
ns_b=$!
ip link add site-a-host type veth peer name site-a-edge
ip link add site-b-host type veth peer name site-b-edge
ip addr add 10.251.1.1/30 dev site-a-host
ip addr add 10.251.2.1/30 dev site-b-host
ip link set site-a-host up
ip link set site-b-host up
ip link set site-a-edge netns "$ns_a"
ip link set site-b-edge netns "$ns_b"
nsenter --net="/proc/$ns_a/ns/net" ip link set lo up
nsenter --net="/proc/$ns_a/ns/net" ip addr add 10.251.1.2/30 dev site-a-edge
nsenter --net="/proc/$ns_a/ns/net" ip link set site-a-edge up
nsenter --net="/proc/$ns_b/ns/net" ip link set lo up
nsenter --net="/proc/$ns_b/ns/net" ip addr add 10.251.2.2/30 dev site-b-edge
nsenter --net="/proc/$ns_b/ns/net" ip link set site-b-edge up
for netns in "$ns_a" "$ns_b"; do
    nsenter --net="/proc/$netns/ns/net" ip addr add 198.18.0.20/32 dev lo
    nsenter --net="/proc/$netns/ns/net" ip -6 addr add fd18:198:18::20/128 nodad dev lo
done

cat > "$smoke" <<'YAML'
log: {loglevel: debug}
inbounds: []
outbounds:
  - tag: to-hub
    protocol: vless
    settings:
      vnext:
        - address: 127.0.0.1
          port: 39643
          users:
            - id: 3ac9b383-75a1-431c-8184-106c80eb2274
              encryption: none
routing:
  rules:
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.1.0/24]
      outboundTag: to-hub
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [10.44.2.0/24]
      outboundTag: to-hub
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [fd18:44:1::/64]
      outboundTag: to-hub
    - type: field
      inboundTag: [smoke-tun]
      network: [tcp, udp]
      ip: [fd18:44:2::/64]
      outboundTag: to-hub
shutdown: {gracePeriodSeconds: 1}
tunGateway:
  name: chimera-dupe
  address: 10.254.0.1/24
  inboundTag: smoke-tun
  maxTcpConnections: 4
  maxUdpSessions: 8
YAML
cat > "$hub" <<'YAML'
log: {loglevel: debug}
inbounds:
  - listen: 0.0.0.0
    port: 39643
    protocol: vless
    tag: hub-vless-in
    settings:
      clients:
        - id: 3ac9b383-75a1-431c-8184-106c80eb2271
          email: site-a-edge@example.test
          reverse: {tag: site-a}
        - id: 3ac9b383-75a1-431c-8184-106c80eb2272
          email: site-b-edge@example.test
          reverse: {tag: site-b}
        - id: 3ac9b383-75a1-431c-8184-106c80eb2274
          email: office-gateway@example.test
      decryption: none
    streamSettings: {network: tcp, security: none}
outbounds:
  - {tag: direct, protocol: freedom}
routing:
  rules:
    - type: field
      ip: [10.44.1.0/24]
      outboundTag: site-a
    - type: field
      ip: [10.44.2.0/24]
      outboundTag: site-b
    - type: field
      ip: [fd18:44:1::/64]
      outboundTag: site-a
    - type: field
      ip: [fd18:44:2::/64]
      outboundTag: site-b
YAML
cat > "$edge_a" <<'YAML'
log: {loglevel: debug}
inbounds: []
outbounds:
  - tag: site-a-bridge
    protocol: vless
    settings:
      address: 10.251.1.1
      port: 39643
      id: 3ac9b383-75a1-431c-8184-106c80eb2271
      encryption: none
      reverse:
        tag: site-a-edge
        siteToSite:
          prefixMaps:
            - {from: 10.44.1.0/24, to: 198.18.0.0/24}
            - {from: fd18:44:1::/64, to: fd18:198:18::/64}
          allow:
            - network: [tcp, udp]
              ip: [198.18.0.0/24]
              ports: [39641-39642]
            - network: [tcp, udp]
              ip: [fd18:198:18::/64]
              ports: [39641-39642]
    streamSettings: {network: tcp, security: none}
  - tag: direct
    protocol: freedom
    settings:
      finalRules:
        - action: allow
          network: [tcp, udp]
          ip: [198.18.0.0/24]
          port: 39641-39644
        - action: allow
          network: [tcp, udp]
          ip: [fd18:198:18::/64]
          port: 39641-39644
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
shutdown: {gracePeriodSeconds: 1}
YAML
cat > "$edge_b" <<'YAML'
log: {loglevel: debug}
inbounds: []
outbounds:
  - tag: site-b-bridge
    protocol: vless
    settings:
      address: 10.251.2.1
      port: 39643
      id: 3ac9b383-75a1-431c-8184-106c80eb2272
      encryption: none
      reverse:
        tag: site-b-edge
        siteToSite:
          prefixMaps:
            - {from: 10.44.2.0/24, to: 198.18.0.0/24}
            - {from: fd18:44:2::/64, to: fd18:198:18::/64}
          allow:
            - network: [tcp, udp]
              ip: [198.18.0.0/24]
              ports: [39641-39642]
            - network: [tcp, udp]
              ip: [fd18:198:18::/64]
              ports: [39641-39642]
    streamSettings: {network: tcp, security: none}
  - tag: direct
    protocol: freedom
    settings:
      finalRules:
        - action: allow
          network: [tcp, udp]
          ip: [198.18.0.0/24]
          port: 39641-39644
        - action: allow
          network: [tcp, udp]
          ip: [fd18:198:18::/64]
          port: 39641-39644
routing:
  rules:
    - type: field
      inboundTag: [site-b-edge]
      network: tcp
      outboundTag: direct
    - type: field
      inboundTag: [site-b-edge]
      network: udp
      outboundTag: direct
shutdown: {gracePeriodSeconds: 1}
YAML

for spec in "a:$ns_a:$log_echo_a" "b:$ns_b:$log_echo_b"; do
    IFS=: read -r site netns echo_log <<< "$spec"
    nsenter --net="/proc/$netns/ns/net" python3 -u - "$site" <<'PY' >"$echo_log" 2>&1 &
import socket
import sys
import threading

site = sys.argv[1].encode()

def tcp_echo(listener, label):
    connection, _ = listener.accept()
    connection.sendall(site + b":" + connection.recv(8192))
    connection.close()
    listener.close()

def udp_echo(listener, label):
    for _ in range(2):
        payload, peer = listener.recvfrom(8192)
        listener.sendto(site + b":" + payload, peer)
    listener.close()

workers = []
for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    tcp.bind((address, 39641))
    tcp.listen(1)
    print(f"tcp-{label}-ready", flush=True)
    udp = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    udp.bind((address, 39642))
    print(f"udp-{label}-ready", flush=True)
    workers.extend((
        threading.Thread(target=tcp_echo, args=(tcp, label)),
        threading.Thread(target=udp_echo, args=(udp, label)),
    ))
for worker in workers:
    worker.start()
for worker in workers:
    worker.join()
PY
    if [[ "$site" == a ]]; then echo_a_pid=$!; else echo_b_pid=$!; fi
done
for spec in "a:$ns_a:$log_policy_a" "b:$ns_b:$log_policy_b"; do
    IFS=: read -r site netns policy_log <<< "$spec"
    nsenter --net="/proc/$netns/ns/net" python3 -u - "$site" <<'PY' >"$policy_log" 2>&1 &
import socket
import sys
import threading

site = sys.argv[1]
listeners = []
for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    tcp.bind((address, 39643))
    tcp.listen(8)
    udp = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    udp.bind((address, 39644))
    listeners.extend((("tcp", label, tcp), ("udp", label, udp)))
print("policy-listeners-ready", flush=True)

def tcp_loop(label, listener):
    while True:
        connection, _ = listener.accept()
        with connection:
            payload = connection.recv(4096)
            print(f"{site}-{label}-tcp-received {payload!r}", flush=True)
            if payload:
                connection.sendall(payload)

def udp_loop(label, listener):
    while True:
        payload, peer = listener.recvfrom(4096)
        print(f"{site}-{label}-udp-received {payload!r}", flush=True)
        listener.sendto(payload, peer)

for kind, label, listener in listeners:
    target = tcp_loop if kind == "tcp" else udp_loop
    threading.Thread(target=target, args=(label, listener), daemon=True).start()
threading.Event().wait()
PY
    if [[ "$site" == a ]]; then policy_a_pid=$!; else policy_b_pid=$!; fi
done
for policy_log in "$log_policy_a" "$log_policy_b"; do
    ready=false
    for attempt in $(seq 1 50); do
        if grep -q '^policy-listeners-ready$' "$policy_log"; then ready=true; break; fi
        sleep 0.02
    done
    if [[ "$ready" != true ]]; then printf 'A site policy probe listener did not start.\n' >&2; exit 1; fi
done
for echo_log in "$log_echo_a" "$log_echo_b"; do
    ready=false
    for attempt in $(seq 1 50); do
        if grep -q '^tcp-v4-ready$' "$echo_log" \
            && grep -q '^udp-v4-ready$' "$echo_log" \
            && grep -q '^tcp-v6-ready$' "$echo_log" \
            && grep -q '^udp-v6-ready$' "$echo_log"; then ready=true; break; fi
        sleep 0.02
    done
    if [[ "$ready" != true ]]; then printf 'A site LAN echo did not start.\n' >&2; exit 1; fi
done

target/debug/chimera_server_app --config "$hub" >"$log_hub" 2>&1 &
hub_pid=$!
hub_ready=false
for attempt in $(seq 1 50); do
    if python3 - <<'PY'
import socket
try:
    with socket.create_connection(("127.0.0.1", 39643), timeout=.1): pass
except OSError:
    raise SystemExit(1)
PY
    then hub_ready=true; break; fi
    if ! kill -0 "$hub_pid" 2>/dev/null; then printf 'Hub failed to start.\n' >&2; exit 1; fi
    sleep .1
done
if [[ "$hub_ready" != true ]]; then printf 'Hub listener did not start.\n' >&2; exit 1; fi
nsenter --net="/proc/$ns_a/ns/net" target/debug/chimera_server_app --config "$edge_a" >"$log_a" 2>&1 &
edge_a_pid=$!
nsenter --net="/proc/$ns_b/ns/net" target/debug/chimera_server_app --config "$edge_b" >"$log_b" 2>&1 &
edge_b_pid=$!
sleep 2.3
target/debug/chimera_server_app --config "$smoke" >"$log_tun" 2>&1 &
server_pid=$!
tun_ready=false
for attempt in $(seq 1 50); do
    if ip link show dev chimera-dupe >/dev/null 2>&1; then tun_ready=true; break; fi
    if ! kill -0 "$server_pid" 2>/dev/null; then printf 'TUN gateway failed to start.\n' >&2; exit 1; fi
    sleep .1
done
if [[ "$tun_ready" != true ]]; then printf 'TUN device did not appear.\n' >&2; exit 1; fi
ip -o link show dev chimera-dupe | grep -q 'mtu 1500'
ip -o -4 addr show dev chimera-dupe | grep -q '10.254.0.1/24'
ip -6 addr add fd00:254::1/64 nodad dev chimera-dupe
ip route add 10.44.0.0/16 dev chimera-dupe table 100
ip -6 route add fd18:44::/32 dev chimera-dupe table 100
ip -6 route add fd18:44::/32 dev chimera-dupe
ip rule del pref 0
ip rule add pref 0 uidrange 1-1 lookup 100
ip rule add pref 10 lookup local
ip -6 rule del pref 0
ip -6 rule add pref 0 uidrange 1-1 lookup 100
ip -6 rule add pref 10 lookup local
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.chimera-dupe.rp_filter=0
for ip_addr in 10.44.1.20 10.44.2.20; do
    ip route get "$ip_addr" uid 1 | grep -q 'dev chimera-dupe'
done
ip -6 route get fd18:44:1::20 uid 1 | grep -q 'dev chimera-dupe'
ip -6 route get fd18:44:2::20 uid 1 | grep -q 'dev chimera-dupe'

setpriv --reuid=1 python3 - <<'PY'
import socket
sites = {
    "a": ((socket.AF_INET, "10.44.1.20"), (socket.AF_INET6, "fd18:44:1::20")),
    "b": ((socket.AF_INET, "10.44.2.20"), (socket.AF_INET6, "fd18:44:2::20")),
}
for label, targets in sites.items():
    for family, target in targets:
        tcp = socket.socket(family, socket.SOCK_STREAM)
        tcp.settimeout(8)
        tcp.connect((target, 39641))
        tcp.sendall(b"tcp")
        reply = tcp.recv(128)
        if reply != label.encode() + b":tcp":
            raise SystemExit(f"TCP reached wrong site: {target} {reply!r}")
        tcp.close()
        udp = socket.socket(family, socket.SOCK_DGRAM)
        udp.settimeout(8)
        for payload in (b"udp", bytes(i % 251 for i in range(4096))):
            udp.sendto(payload, (target, 39642))
            reply, source = udp.recvfrom(8192)
            if reply != label.encode() + b":" + payload:
                raise SystemExit(f"UDP reached wrong site or payload changed: {target}")
            if source[:2] != (target, 39642):
                raise SystemExit(f"UDP source was not restored: {source!r}")
        udp.close()
print("two isolated sites with duplicate IPv4/IPv6 LAN prefixes passed TCP/UDP including 4 KiB")
PY
setpriv --reuid=1 python3 - <<'PY'
import socket

sites = {
    "a": ((socket.AF_INET, "10.44.1.20"), (socket.AF_INET6, "fd18:44:1::20")),
    "b": ((socket.AF_INET, "10.44.2.20"), (socket.AF_INET6, "fd18:44:2::20")),
}
for label, targets in sites.items():
    for family, target in targets:
        tcp_marker = f"forbidden-{label}-{target}-tcp".encode()
        try:
            with socket.socket(family, socket.SOCK_STREAM) as tcp:
                tcp.settimeout(2)
                tcp.connect((target, 39643))
                tcp.sendall(tcp_marker)
                tcp.settimeout(1)
                reply = tcp.recv(128)
                if reply == tcp_marker:
                    raise SystemExit(f"disallowed TCP target at Site {label} replied")
        except OSError:
            # A per-session policy rejection may close the TUN-side TCP flow.
            pass

        udp_marker = f"forbidden-{label}-{target}-udp".encode()
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(1)
            udp.sendto(udp_marker, (target, 39644))
            try:
                reply, _ = udp.recvfrom(4096)
            except TimeoutError:
                pass
            else:
                raise SystemExit(f"disallowed UDP target at Site {label} replied: {reply!r}")
PY
sleep 0.25
for marker in forbidden-a-10.44.1.20-tcp forbidden-a-10.44.1.20-udp \
    forbidden-a-fd18:44:1::20-tcp forbidden-a-fd18:44:1::20-udp \
    forbidden-b-10.44.2.20-tcp forbidden-b-10.44.2.20-udp \
    forbidden-b-fd18:44:2::20-tcp forbidden-b-fd18:44:2::20-udp; do
    if grep -Fq "$marker" "$log_policy_a" "$log_policy_b"; then
        printf 'Chimera siteToSite policy allowed forbidden marker %s to reach a LAN listener.\n' "$marker" >&2
        exit 1
    fi
done
wait "$echo_a_pid"
echo_a_pid=
wait "$echo_b_pid"
echo_b_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=
if ip link show dev chimera-dupe >/dev/null 2>&1; then printf 'TUN device remained after shutdown.\n' >&2; exit 1; fi
for pid in "$edge_a_pid" "$edge_b_pid" "$hub_pid" "$ns_a" "$ns_b"; do
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
done
edge_a_pid=
edge_b_pid=
hub_pid=
ns_a=
ns_b=
printf 'duplicate-LAN two-site dual-stack TUN/Reverse TCP/UDP passed; live IPv4/IPv6 LAN listeners on TCP 39643 and UDP 39644 stayed untouched under both Edge siteToSite policies; shutdown passed in isolated namespaces.\n'
NS
