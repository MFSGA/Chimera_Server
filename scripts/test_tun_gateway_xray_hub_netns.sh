#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
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
xray_version=$("$xray_bin" version | head -n 1)
printf 'Using %s\n' "$xray_version"
if [[ "$xray_version" != Xray\ 26.9.9* ]]; then
    printf 'This interoperability probe is pinned to Xray 26.9.9.\n' >&2
    exit 1
fi
wrong_reality_keypair=$("$xray_bin" x25519)
wrong_reality_public_key=$(awk '/^Password \(PublicKey\):/ { print $3; exit }' <<<"$wrong_reality_keypair")
reality_private_key='dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI'
reality_public_key='lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg'
if [[ -z "$wrong_reality_public_key" ]]; then
    printf 'Xray did not produce a wrong REALITY test public key.\n' >&2
    exit 1
fi
export REALITY_TEST_PRIVATE_KEY="$reality_private_key"
export REALITY_TEST_PUBLIC_KEY="$reality_public_key"
export REALITY_TEST_WRONG_PUBLIC_KEY="$wrong_reality_public_key"

cd "$repo_root"
cargo build -p chimera_server_app --no-default-features --features tun-gateway,vless-reverse-tls,ws,minimal-vless-reality --locked
export XRAY_BIN="$xray_bin"

unshare \
    --user \
    --map-users="0:${test_host_uid}:1" \
    --map-users="1:${test_subuid_start}:${test_subuid_count}" \
    --net \
bash -s <<'NAMESPACE_SCRIPT'
set -euo pipefail
trap 'exit_status=$?; printf "Xray Hub TUN smoke failed with status %s at line %s: %s\\n" "$exit_status" "$LINENO" "$BASH_COMMAND" >&2' ERR

edge_ns_pid=
lan_ns_pid=
office_ns_pid=
hub_pid=
edge_pid=
gateway_pid=
echo_pid=
smoke_dir=$(mktemp -d)
hub_config_file=$smoke_dir/xray-hub.json
edge_config_file=$smoke_dir/chimera-edge.yaml
gateway_config_file=$smoke_dir/chimera-office.yaml
hub_log_file=$smoke_dir/xray-hub.log
edge_log_file=$smoke_dir/chimera-edge.log
gateway_log_file=$smoke_dir/chimera-office.log
echo_log_file=$smoke_dir/lan-echo.log

cleanup() {
    exit_status=$?
    trap - EXIT
    for process_pid in "$gateway_pid" "$edge_pid" "$hub_pid" "$echo_pid"; do
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
        for diagnostic_file in "$hub_log_file" "$edge_log_file" "$gateway_log_file" "$echo_log_file"; do
            printf '\n--- %s ---\n' "$diagnostic_file" >&2
            case "$diagnostic_file" in
                "$hub_log_file")
                    grep -Ei 'REALITY|reality|fallback|invalid|failed|error|accepted.*39650' "$diagnostic_file" | tail -n 80 >&2 || true
                    ;;
                "$gateway_log_file")
                    grep -Ei 'REALITY|reality|handshake|failed|error|TUN TCP flow ended' "$diagnostic_file" | tail -n 80 >&2 || true
                    ;;
                "$edge_log_file")
                    grep -Ei 'REALITY|reality|failed|error|worker_connected' "$diagnostic_file" | tail -n 80 >&2 || true
                    ;;
                *)
                    cat "$diagnostic_file" >&2 2>/dev/null || true
                    ;;
            esac
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

# The fixed Xray Hub/Portal and Office Gateway share the root namespace.
# The Bridge and LAN endpoint stay isolated behind the Edge veth.
ip link add office-gw type veth peer name office-client
ip addr add 10.251.0.1/24 dev office-gw
ip -6 addr add fd18:251::1/64 nodad dev office-gw
ip link set office-gw up
ip link set office-client netns "$office_ns_pid"
nsenter --net="/proc/$office_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$office_ns_pid/ns/net" ip addr add 10.251.0.2/24 dev office-client
nsenter --net="/proc/$office_ns_pid/ns/net" ip -6 addr add fd18:251::2/64 nodad dev office-client
nsenter --net="/proc/$office_ns_pid/ns/net" ip link set office-client up
nsenter --net="/proc/$office_ns_pid/ns/net" ip route add 198.18.0.0/24 via 10.251.0.1
nsenter --net="/proc/$office_ns_pid/ns/net" ip -6 route add fd18:198:18::/64 via fd18:251::1

ip link add gateway-edge type veth peer name chimera-edge
ip addr add 10.252.0.1/30 dev gateway-edge
ip link set gateway-edge up
ip link set chimera-edge netns "$edge_ns_pid"
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$edge_ns_pid/ns/net" ip addr add 10.252.0.2/30 dev chimera-edge
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set chimera-edge up

ip link add edge-lan type veth peer name lan-edge
ip link set edge-lan netns "$edge_ns_pid"
ip link set lan-edge netns "$lan_ns_pid"
nsenter --net="/proc/$edge_ns_pid/ns/net" ip addr add 10.253.0.1/24 dev edge-lan
nsenter --net="/proc/$edge_ns_pid/ns/net" ip -6 addr add fd18:253::1/64 nodad dev edge-lan
nsenter --net="/proc/$edge_ns_pid/ns/net" ip link set edge-lan up
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set lo up
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.2/24 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.20/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.21/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.22/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.23/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.24/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.25/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.26/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.27/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.28/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.29/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.30/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.31/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.32/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.33/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.34/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip addr add 10.253.0.35/32 dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:253::2/64 nodad dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip -6 addr add fd18:253::20/128 nodad dev lan-edge
nsenter --net="/proc/$lan_ns_pid/ns/net" ip link set lan-edge up

cat >"$hub_config_file" <<'JSON'
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "10.252.0.1",
    "port": 39643,
    "protocol": "vless",
    "tag": "hub-vless-in",
    "settings": {
      "clients": [
        {"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"},
        {"id": "3ac9b383-75a1-431c-8184-106c80eb2275", "email": "site-edge@example.test", "reverse": {"tag": "site-edge"}}
      ],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      }
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39650,
    "protocol": "vless",
    "tag": "hub-vless-reality-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "10.252.0.1:39643",
        "xver": 0,
        "serverNames": ["www.apple.com"],
        "privateKey": "__REALITY_PRIVATE_KEY__",
        "shortIds": ["4ac97aaf8b9b0356"]
      }
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39644,
    "protocol": "vless",
    "tag": "hub-vless-ws-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "wsSettings": {"path": "/office-ws", "host": "site-tls.test"}
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39645,
    "protocol": "vless",
    "tag": "hub-vless-xhttp-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/office-xhttp", "mode": "packet-up"}
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39646,
    "protocol": "vless",
    "tag": "hub-vless-xhttp-stream-up-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/office-xhttp-stream", "mode": "stream-up"}
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39647,
    "protocol": "vless",
    "tag": "hub-vless-xhttp-auto-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/office-xhttp-auto", "mode": "auto"}
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39648,
    "protocol": "vless",
    "tag": "hub-vless-xhttp-h3-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h3"],
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/office-xhttp-h3", "mode": "packet-up"}
    }
  }, {
    "listen": "10.252.0.1",
    "port": 39649,
    "protocol": "vless",
    "tag": "hub-vless-xhttp-h3-stream-up-in",
    "settings": {
      "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2274", "email": "office-gateway@example.test"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h3"],
        "certificates": [{
          "certificateFile": "scripts/fixtures/reverse-site-tls-cert.pem",
          "keyFile": "scripts/fixtures/reverse-site-tls-key.pem"
        }]
      },
      "xhttpSettings": {"path": "/office-xhttp-h3-stream", "mode": "stream-up"}
    }
  }],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
  "routing": {"rules": [{
    "type": "field",
    "ip": ["198.18.0.0/24", "fd18:198:18::/64"],
    "outboundTag": "site-edge"
  }]}
}
JSON

python3 - "$hub_config_file" "$REALITY_TEST_PRIVATE_KEY" <<'PY'
import json
import sys

config_path, private_key = sys.argv[1:]
with open(config_path, encoding="utf-8") as config_file:
    config = json.load(config_file)
for inbound in config["inbounds"]:
    reality = inbound.get("streamSettings", {}).get("realitySettings")
    if reality is not None:
        reality["privateKey"] = private_key
        break
else:
    raise SystemExit("REALITY Hub inbound is missing from the test config")
with open(config_path, "w", encoding="utf-8") as config_file:
    json.dump(config, config_file, indent=2)
    config_file.write("\n")
PY

"$XRAY_BIN" run -test -c "$hub_config_file"

cat >"$edge_config_file" <<'YAML'
log:
  loglevel: warning
shutdown:
  gracePeriodSeconds: 1
inbounds: []
outbounds:
  - tag: site-edge
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39643
      id: 3ac9b383-75a1-431c-8184-106c80eb2275
      email: site-edge@example.test
      encryption: none
      reverse:
        tag: site-edge
        siteToSite:
          prefixMaps:
            - from: 198.18.0.0/24
              to: 10.253.0.0/24
            - from: fd18:198:18::/64
              to: fd18:253::/64
          allow:
            - network: [tcp, udp]
              ip: [10.253.0.0/24, fd18:253::/64]
              ports: ["39641-39642"]
    streamSettings:
      network: tcp
      security: tls
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: direct
    protocol: freedom
    settings:
      finalRules:
        - action: allow
          network: [tcp, udp]
      ip: [10.253.0.20/32, 10.253.0.21/32, 10.253.0.22/32, 10.253.0.23/32, 10.253.0.24/32, 10.253.0.25/32, 10.253.0.26/32, 10.253.0.27/32, 10.253.0.28/32, 10.253.0.29/32, 10.253.0.30/32, 10.253.0.31/32, 10.253.0.32/32, fd18:253::20/128]
routing:
  rules:
    - type: field
      inboundTag: [site-edge]
      network: [tcp, udp]
      outboundTag: direct
YAML

cat >"$gateway_config_file" <<'YAML'
log:
  loglevel: warning
shutdown:
  gracePeriodSeconds: 1
inbounds: []
outbounds:
  - tag: to-hub
    protocol: vless
    settings:
      vnext:
        - address: 10.252.0.1
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
  - tag: to-hub-ws
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39644
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      email: office-gateway@example.test
      encryption: none
    streamSettings:
      network: ws
      security: tls
      wsSettings:
        host: site-tls.test
        path: /office-ws
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-ws-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39644
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: ws
      security: tls
      wsSettings:
        host: site-tls.test
        path: /office-ws
      tlsSettings:
        serverName: wrong-site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-ws-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39644
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: ws
      security: tls
      wsSettings:
        host: site-tls.test
        path: /office-ws
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39645
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp
        mode: packet-up
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39645
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp
        mode: packet-up
      tlsSettings:
        serverName: wrong-site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39645
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp
        mode: packet-up
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-stream-up
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39646
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-stream
        mode: stream-up
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-auto
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39647
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-auto
        mode: auto
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39648
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3
        mode: packet-up
      tlsSettings:
        serverName: site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-stream-up
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39649
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3-stream
        mode: stream-up
      tlsSettings:
        serverName: site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-stream-up-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39649
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3-stream
        mode: stream-up
      tlsSettings:
        serverName: wrong-site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-stream-up-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39649
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3-stream
        mode: stream-up
      tlsSettings:
        serverName: site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-auto
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39648
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3
        mode: auto
      tlsSettings:
        serverName: site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39648
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3
        mode: packet-up
      tlsSettings:
        serverName: wrong-site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-h3-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39648
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-h3
        mode: packet-up
      tlsSettings:
        serverName: site-tls.test
        alpn: [h3]
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-stream-up-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39646
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-stream
        mode: stream-up
      tlsSettings:
        serverName: wrong-site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-stream-up-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39646
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-stream
        mode: stream-up
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-auto-bad-sni
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39647
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-auto
        mode: auto
      tlsSettings:
        serverName: wrong-site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-xhttp-auto-bad-user
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39647
      id: 3ac9b383-75a1-431c-8184-106c80eb2279
      encryption: none
    streamSettings:
      network: xhttp
      security: tls
      xhttpSettings:
        host: site-tls.test
        path: /office-xhttp-auto
        mode: auto
      tlsSettings:
        serverName: site-tls.test
        disableSystemRoot: true
        certificates:
          - certificateFile: scripts/fixtures/reverse-site-tls-cert.pem
            usage: verify
  - tag: to-hub-reality
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39650
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: tcp
      security: reality
      realitySettings:
        fingerprint: chrome
        serverName: www.apple.com
        publicKey: __REALITY_PUBLIC_KEY__
        shortId: 4ac97aaf8b9b0356
        spiderX: /
  - tag: to-hub-reality-bad-short-id
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39650
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: tcp
      security: reality
      realitySettings:
        fingerprint: chrome
        serverName: www.apple.com
        publicKey: __REALITY_PUBLIC_KEY__
        shortId: ffffffffffffffff
        spiderX: /
  - tag: to-hub-reality-bad-public-key
    protocol: vless
    settings:
      address: 10.252.0.1
      port: 39650
      id: 3ac9b383-75a1-431c-8184-106c80eb2274
      encryption: none
    streamSettings:
      network: tcp
      security: reality
      realitySettings:
        fingerprint: chrome
        serverName: www.apple.com
        publicKey: __REALITY_WRONG_PUBLIC_KEY__
        shortId: 4ac97aaf8b9b0356
        spiderX: /
routing:
  rules:
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.33/32]
      outboundTag: to-hub-reality
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.34/32]
      outboundTag: to-hub-reality-bad-short-id
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.35/32]
      outboundTag: to-hub-reality-bad-public-key
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.21/32]
      outboundTag: to-hub-ws-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.21/32]
      outboundTag: to-hub-ws-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.23/32]
      outboundTag: to-hub-xhttp-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.23/32]
      outboundTag: to-hub-xhttp-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.22/32]
      outboundTag: to-hub-xhttp
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.24/32]
      outboundTag: to-hub-xhttp-stream-up
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.25/32]
      outboundTag: to-hub-xhttp-auto
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.26/32]
      outboundTag: to-hub-xhttp-stream-up-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.26/32]
      outboundTag: to-hub-xhttp-stream-up-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.27/32]
      outboundTag: to-hub-xhttp-auto-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.27/32]
      outboundTag: to-hub-xhttp-auto-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.29/32]
      outboundTag: to-hub-xhttp-h3-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.29/32]
      outboundTag: to-hub-xhttp-h3-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp]
      ip: [198.18.0.32/32]
      outboundTag: to-hub-xhttp-h3-stream-up-bad-sni
    - type: field
      inboundTag: [office-tun]
      network: [udp]
      ip: [198.18.0.32/32]
      outboundTag: to-hub-xhttp-h3-stream-up-bad-user
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.28/32]
      outboundTag: to-hub-xhttp-h3
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.30/32]
      outboundTag: to-hub-xhttp-h3-stream-up
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.31/32]
      outboundTag: to-hub-xhttp-h3-auto
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [fd18:198:18::/64]
      outboundTag: to-hub-ws
    - type: field
      inboundTag: [office-tun]
      network: [tcp, udp]
      ip: [198.18.0.0/24, fd18:198:18::/64]
      outboundTag: to-hub
tunGateway:
  name: chimera-xhub
  address: 10.254.0.1/24
  ipv6Address: fd00:254::1/64
  inboundTag: office-tun
YAML

python3 - "$gateway_config_file" "$REALITY_TEST_PUBLIC_KEY" "$REALITY_TEST_WRONG_PUBLIC_KEY" <<'PY'
from pathlib import Path
import re
import sys

config_path = Path(sys.argv[1])
config = config_path.read_text(encoding="utf-8")
config = config.replace("__REALITY_PUBLIC_KEY__", sys.argv[2])
config = config.replace("__REALITY_WRONG_PUBLIC_KEY__", sys.argv[3])
if "__REALITY_" in config:
    raise SystemExit("REALITY public-key placeholders remain in the Office config")
keys = re.findall(r"^\s+publicKey: ([^\s]+)$", config, re.MULTILINE)
if len(keys) != 3 or any(
    len(key) != 43 or re.fullmatch(r"[A-Za-z0-9_-]{43}", key) is None
    for key in keys
):
    shapes = [(len(key), re.fullmatch(r"[A-Za-z0-9_-]+", key) is not None) for key in keys]
    raise SystemExit(f"generated Office REALITY public keys have invalid encoding: {shapes}")
print("Prepared three URL-safe 32-byte REALITY client public keys.", flush=True)
config_path.write_text(config, encoding="utf-8")
PY

nsenter --net="/proc/$lan_ns_pid/ns/net" python3 -u - <<'PY' >"$echo_log_file" 2>&1 &
import socket
import threading

addresses = (("10.253.0.20", socket.AF_INET), ("10.253.0.21", socket.AF_INET), ("10.253.0.22", socket.AF_INET), ("10.253.0.23", socket.AF_INET), ("10.253.0.24", socket.AF_INET), ("10.253.0.25", socket.AF_INET), ("10.253.0.26", socket.AF_INET), ("10.253.0.27", socket.AF_INET), ("10.253.0.28", socket.AF_INET), ("10.253.0.29", socket.AF_INET), ("10.253.0.30", socket.AF_INET), ("10.253.0.31", socket.AF_INET), ("10.253.0.32", socket.AF_INET), ("10.253.0.33", socket.AF_INET), ("10.253.0.34", socket.AF_INET), ("10.253.0.35", socket.AF_INET), ("fd18:253::20", socket.AF_INET6))

def serve_tcp(address, family, port):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(8)
    while True:
        connection, peer = listener.accept()
        print(f"tcp-accepted-{address}-{port} {peer!r}", flush=True)
        with connection:
            while payload := connection.recv(8192):
                print(f"tcp-{address}-{port} {payload!r}", flush=True)
                connection.sendall(payload)

def serve_udp(address, family, port):
    listener = socket.socket(family, socket.SOCK_DGRAM)
    listener.bind((address, port))
    while True:
        payload, peer = listener.recvfrom(8192)
        print(f"udp-{address}-{port} {len(payload)} bytes {payload[:40]!r}", flush=True)
        listener.sendto(payload, peer)

for address, family in addresses:
    for port in (39641, 39643):
        threading.Thread(target=serve_tcp, args=(address, family, port), daemon=True).start()
    for port in (39642, 39644):
        threading.Thread(target=serve_udp, args=(address, family, port), daemon=True).start()
print("lan-echo-ready", flush=True)
threading.Event().wait()
PY
echo_pid=$!
for _ in $(seq 1 100); do
    if grep -q '^lan-echo-ready$' "$echo_log_file"; then
        break
    fi
    if ! kill -0 "$echo_pid" 2>/dev/null; then
        printf 'LAN echo fixture exited before opening its listeners.\n' >&2
        exit 1
    fi
    sleep 0.05
done
grep -q '^lan-echo-ready$' "$echo_log_file"

nsenter --net="/proc/$edge_ns_pid/ns/net" python3 - <<'PY'
import socket

for family, address in ((socket.AF_INET, "10.253.0.20"), (socket.AF_INET6, "fd18:253::20")):
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect((address, 39641))
        client.sendall(b"edge-local-lan-check")
        if client.recv(64) != b"edge-local-lan-check":
            raise SystemExit(f"Edge namespace cannot echo through to LAN target {address}")
PY

"$XRAY_BIN" run -c "$hub_config_file" >"$hub_log_file" 2>&1 &
hub_pid=$!
sleep 0.2
if ! kill -0 "$hub_pid" 2>/dev/null; then
    printf 'Xray Hub exited before opening its VLESS/Portal listener.\n' >&2
    exit 1
fi

nsenter --net="/proc/$edge_ns_pid/ns/net" env RUST_LOG='warn,chimera_server_lib::handler::vless_reverse=debug,chimera_server_lib::session::udp::targeted=debug' \
    target/debug/chimera_server_app --config "$edge_config_file" >"$edge_log_file" 2>&1 &
edge_pid=$!
edge_worker_ready=false
for _ in $(seq 1 120); do
    if grep -q 'vless_reverse_bridge_worker_connected' "$edge_log_file"; then
        edge_worker_ready=true
        break
    fi
    if ! kill -0 "$edge_pid" 2>/dev/null; then
        printf 'Chimera Edge exited while connecting to the Xray Hub Portal.\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$edge_worker_ready" != true ]]; then
    printf 'Chimera Edge did not attach a Reverse worker to the Xray Hub within 12 seconds.\n' >&2
    exit 1
fi

env -u CHIMERA_TCP_RELAY_BACKEND \
    RUST_LOG='warn,chimera_server_lib::tun_gateway=debug,chimera_server_lib::session::udp::dokodemo=debug,chimera_server_lib::handler::vless_reverse=debug' \
    target/debug/chimera_server_app --config "$gateway_config_file" >"$gateway_log_file" 2>&1 &
gateway_pid=$!
tun_ready=false
for _ in $(seq 1 100); do
    if ip link show dev chimera-xhub >/dev/null 2>&1; then
        tun_ready=true
        break
    fi
    if ! kill -0 "$gateway_pid" 2>/dev/null; then
        printf 'Chimera Office Gateway exited before creating its TUN device.\n' >&2
        exit 1
    fi
    sleep 0.05
done
if [[ "$tun_ready" != true ]]; then
    printf 'Chimera Office Gateway did not create its TUN device within 5 seconds.\n' >&2
    exit 1
fi
ip route replace 198.18.0.0/24 dev chimera-xhub
ip -6 route replace fd18:198:18::/64 dev chimera-xhub
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.office-gw.rp_filter=0

nsenter --net="/proc/$office_ns_pid/ns/net" python3 - <<'PY'
import socket
import time

def tcp_echo(family, address, port, marker):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect((address, port))
                connection.sendall(marker)
                reply = connection.recv(8192)
                if reply == marker:
                    return
                raise SystemExit(f"unexpected TCP response from {address}:{port}: {reply!r}")
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"TCP path to {address}:{port} did not recover within 12 seconds")

def udp_echo(family, address, port, payload):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            client.sendto(payload, (address, port))
            try:
                reply, source = client.recvfrom(8192)
            except TimeoutError:
                continue
            if reply != payload or source[0] != address or source[1] != port:
                raise SystemExit(f"unexpected UDP response from {source!r}: {len(reply)} bytes")
            return
    raise SystemExit(f"UDP path to {address}:{port} did not recover for {len(payload)} bytes")

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET, "198.18.0.22", "v4-xhttp"),
    (socket.AF_INET, "198.18.0.24", "v4-xhttp-stream-up"),
    (socket.AF_INET, "198.18.0.25", "v4-xhttp-auto"),
    (socket.AF_INET, "198.18.0.28", "v4-xhttp-h3"),
    (socket.AF_INET, "198.18.0.30", "v4-xhttp-h3-stream-up"),
    (socket.AF_INET, "198.18.0.31", "v4-xhttp-h3-auto"),
    (socket.AF_INET, "198.18.0.33", "v4-reality"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    tcp_echo(family, address, 39641, f"office-to-xray-hub-{label}-tcp".encode())
    udp_echo(family, address, 39642, f"office-to-xray-hub-{label}-udp".encode())
    udp_echo(family, address, 39642, bytes(index % 251 for index in range(4096)))

def denied_tcp(family, address, marker):
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
                raise SystemExit(f"denied TCP target echoed {marker!r}")
    except OSError:
        pass

def denied_udp(family, address, marker):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(marker, (address, 39644))
        try:
            reply, _ = client.recvfrom(4096)
        except TimeoutError:
            return
        raise SystemExit(f"denied UDP target echoed {reply!r}")

def expect_tcp_failure(address, port, marker):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect((address, port))
            client.sendall(marker)
            try:
                reply = client.recv(128)
            except TimeoutError:
                return
            if reply == marker:
                raise SystemExit(f"failed VLESS transport identity echoed TCP marker {marker!r}")
    except OSError:
        return

def expect_udp_failure(address, port, marker):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(marker, (address, port))
        try:
            reply, _ = client.recvfrom(4096)
        except TimeoutError:
            return
        raise SystemExit(f"failed VLESS transport identity echoed UDP marker {reply!r}")

for family, address, label in (
    (socket.AF_INET, "198.18.0.20", "v4"),
    (socket.AF_INET6, "fd18:198:18::20", "v6"),
):
    denied_tcp(family, address, f"edge-denied-{label}-tcp".encode())
    denied_udp(family, address, f"edge-denied-{label}-udp".encode())

# These are live Edge targets whose prefix map, site ACL and Freedom policy all
# allow the traffic. Isolate failures to the Office VLESS transport SNI and Hub
# VLESS UUID authentication boundaries for each tested XHTTP profile.
expect_tcp_failure("198.18.0.21", 39641, b"ws-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.21", 39642, b"ws-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.23", 39641, b"xhttp-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.23", 39642, b"xhttp-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.26", 39641, b"xhttp-stream-up-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.26", 39642, b"xhttp-stream-up-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.27", 39641, b"xhttp-auto-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.27", 39642, b"xhttp-auto-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.29", 39641, b"xhttp-h3-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.29", 39642, b"xhttp-h3-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.32", 39641, b"xhttp-h3-stream-up-wrong-sni-must-not-reach-edge")
expect_udp_failure("198.18.0.32", 39642, b"xhttp-h3-stream-up-wrong-user-must-not-reach-edge")
expect_tcp_failure("198.18.0.34", 39641, b"reality-wrong-short-id-tcp-must-not-reach-edge")
expect_udp_failure("198.18.0.34", 39642, b"reality-wrong-short-id-udp-must-not-reach-edge")
expect_tcp_failure("198.18.0.35", 39641, b"reality-wrong-public-key-tcp-must-not-reach-edge")
expect_udp_failure("198.18.0.35", 39642, b"reality-wrong-public-key-udp-must-not-reach-edge")
PY

for marker in edge-denied-v4-tcp edge-denied-v4-udp edge-denied-v6-tcp edge-denied-v6-udp; do
    if grep -Fq "$marker" "$echo_log_file"; then
        printf 'Chimera Edge siteToSite policy allowed denied marker %s to reach the LAN.\n' "$marker" >&2
        exit 1
    fi
done
for marker in ws-wrong-sni-must-not-reach-edge ws-wrong-user-must-not-reach-edge xhttp-wrong-sni-must-not-reach-edge xhttp-wrong-user-must-not-reach-edge xhttp-stream-up-wrong-sni-must-not-reach-edge xhttp-stream-up-wrong-user-must-not-reach-edge xhttp-auto-wrong-sni-must-not-reach-edge xhttp-auto-wrong-user-must-not-reach-edge xhttp-h3-wrong-sni-must-not-reach-edge xhttp-h3-wrong-user-must-not-reach-edge xhttp-h3-stream-up-wrong-sni-must-not-reach-edge xhttp-h3-stream-up-wrong-user-must-not-reach-edge reality-wrong-short-id-tcp-must-not-reach-edge reality-wrong-short-id-udp-must-not-reach-edge reality-wrong-public-key-tcp-must-not-reach-edge reality-wrong-public-key-udp-must-not-reach-edge; do
    if grep -Fq "$marker" "$echo_log_file"; then
        printf 'Failed VLESS transport authentication allowed marker %s to reach the LAN.\n' "$marker" >&2
        exit 1
    fi
done
grep -Fq "tcp-10.253.0.20-39641 b'office-to-xray-hub-v4-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.22-39641 b'office-to-xray-hub-v4-xhttp-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.24-39641 b'office-to-xray-hub-v4-xhttp-stream-up-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.25-39641 b'office-to-xray-hub-v4-xhttp-auto-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.28-39641 b'office-to-xray-hub-v4-xhttp-h3-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.30-39641 b'office-to-xray-hub-v4-xhttp-h3-stream-up-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.31-39641 b'office-to-xray-hub-v4-xhttp-h3-auto-tcp'" "$echo_log_file"
grep -Fq "tcp-10.253.0.33-39641 b'office-to-xray-hub-v4-reality-tcp'" "$echo_log_file"
grep -Fq "tcp-fd18:253::20-39641 b'office-to-xray-hub-v6-tcp'" "$echo_log_file"
grep -Fq 'udp-10.253.0.20-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.22-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.24-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.25-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.28-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.30-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.31-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-10.253.0.33-39642 4096 bytes' "$echo_log_file"
grep -Fq 'udp-fd18:253::20-39642 4096 bytes' "$echo_log_file"

kill -TERM "$gateway_pid"
wait "$gateway_pid"
gateway_pid=
if ip link show dev chimera-xhub >/dev/null 2>&1; then
    printf 'TUN device remained after Office Gateway shutdown.\n' >&2
    exit 1
fi

printf 'Chimera Office TUN → Xray 26.9.9 VLESS Hub/Portal → Chimera Edge Bridge passed IPv4 RAW/TLS and REALITY, XHTTP/TLS H2 packet-up/stream-up/auto, XHTTP/TLS H3 packet-up/stream-up/auto, and IPv6 WebSocket/TLS TCP, UDP and 4 KiB UDP through explicit prefix maps; wrong REALITY short ID/public key, wrong SNI, and VLESS UUID on WebSocket/TLS and tested XHTTP profiles did not reach explicitly allowed LAN targets; siteToSite denied ports did not reach mapped LAN listeners; TUN cleanup passed.\n'
NAMESPACE_SCRIPT
