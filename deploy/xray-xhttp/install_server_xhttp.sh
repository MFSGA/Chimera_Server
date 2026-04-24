#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
UUID_VALUE=""
XHTTP_PATH="/xhttp"
LISTEN_PORT="443"
CERT_FILE=""
KEY_FILE=""
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
CONFIG_DIR="${CONFIG_DIR:-/usr/local/etc/xray}"
CONFIG_FILE="${CONFIG_FILE:-/usr/local/etc/xray/server-xhttp.json}"
CLIENT_EXPORT="${CLIENT_EXPORT:-/usr/local/etc/xray/client-from-server.json}"
SERVICE_DIR="${SERVICE_DIR:-/etc/systemd/system}"
SERVICE_NAME="${SERVICE_NAME:-xray-xhttp-server}"
INSTALL_XRAY="1"
START_SERVICE="1"
ALLOW_INSECURE_EXPORT="0"
PINNED_CERT_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  install_server_xhttp.sh --domain DOMAIN [options]

Options:
  --domain DOMAIN          Public domain name used by client and TLS SNI.
  --uuid UUID              VLESS UUID. Auto-generated when omitted.
  --path PATH              XHTTP path. Default: /xhttp
  --port PORT              Listen port. Default: 443
  --cert FILE              TLS certificate file. If omitted with --key, a self-signed cert is created.
  --key FILE               TLS private key file. If omitted with --cert, a self-signed cert is created.
  --xray-bin FILE          Xray binary target path. Default: /usr/local/bin/xray
  --config-dir DIR         Config directory. Default: /usr/local/etc/xray
  --config-file FILE       Server config output path.
  --client-export FILE     Matching client config export path.
  --service-dir DIR        Systemd unit directory. Default: /etc/systemd/system
  --service-name NAME      Systemd service name. Default: xray-xhttp-server
  --skip-install           Do not download/install Xray.
  --skip-service           Do not create or start systemd service.
  -h, --help               Show this help.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

arch_asset() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' 'Xray-linux-64.zip'
      ;;
    aarch64|arm64)
      printf '%s\n' 'Xray-linux-arm64-v8a.zip'
      ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
    return
  fi
  if [ -r /proc/sys/kernel/random/uuid ]; then
    tr 'A-Z' 'a-z' </proc/sys/kernel/random/uuid
    return
  fi
  need_cmd openssl
  openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
}

install_xray() {
  local asset url tmpdir
  need_cmd curl
  need_cmd unzip
  asset="$(arch_asset)"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/${asset}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  curl -fsSL "$url" -o "$tmpdir/xray.zip"
  unzip -oq "$tmpdir/xray.zip" -d "$tmpdir/xray"

  install -Dm755 "$tmpdir/xray/xray" "$XRAY_BIN"
  if [ -f "$tmpdir/xray/geoip.dat" ]; then
    install -Dm644 "$tmpdir/xray/geoip.dat" "$CONFIG_DIR/geoip.dat"
  fi
  if [ -f "$tmpdir/xray/geosite.dat" ]; then
    install -Dm644 "$tmpdir/xray/geosite.dat" "$CONFIG_DIR/geosite.dat"
  fi
}

create_self_signed_cert() {
  need_cmd openssl
  CERT_FILE="${CONFIG_DIR}/tls/${DOMAIN}.crt"
  KEY_FILE="${CONFIG_DIR}/tls/${DOMAIN}.key"
  mkdir -p "$(dirname "$CERT_FILE")"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 3650 \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName = DNS:${DOMAIN}" >/dev/null 2>&1
  ALLOW_INSECURE_EXPORT="1"
}

compute_pinned_cert_hash() {
  local hash_output
  hash_output="$("$XRAY_BIN" tls hash --cert "$CERT_FILE")"
  PINNED_CERT_SHA256="$(printf '%s\n' "$hash_output" | awk '/Leaf SHA256:/ {print $3}')"
  if [ -z "$PINNED_CERT_SHA256" ]; then
    echo "failed to calculate certificate pin" >&2
    exit 1
  fi
}

render_server_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-xhttp-in",
      "listen": "0.0.0.0",
      "port": ${LISTEN_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VALUE}",
            "email": "xhttp-client"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${DOMAIN}",
          "alpn": [
            "h2"
          ],
          "minVersion": "1.2",
          "certificates": [
            {
              "certificateFile": "${CERT_FILE}",
              "keyFile": "${KEY_FILE}"
            }
          ]
        },
        "xhttpSettings": {
          "path": "${XHTTP_PATH}",
          "mode": "auto"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ]
}
EOF
}

render_client_export() {
  local allow_insecure_line
  local host_line
  local pinned_line
  local verify_name_line

  allow_insecure_line=""
  if [ "$ALLOW_INSECURE_EXPORT" = "1" ] && [ -z "$PINNED_CERT_SHA256" ]; then
    allow_insecure_line='          "allowInsecure": true,'
  fi
  pinned_line=""
  verify_name_line=""
  if [ -n "$PINNED_CERT_SHA256" ]; then
    pinned_line='          "pinnedPeerCertSha256": "'"${PINNED_CERT_SHA256}"'",'
    verify_name_line='          "verifyPeerCertByName": "'"${DOMAIN}"'",'
  fi
  host_line='          "host": "'"${DOMAIN}"'",'

  mkdir -p "$(dirname "$CLIENT_EXPORT")"
  cat >"$CLIENT_EXPORT" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${DOMAIN}",
            "port": ${LISTEN_PORT},
            "users": [
              {
                "id": "${UUID_VALUE}",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${DOMAIN}",
          "fingerprint": "chrome",
${allow_insecure_line}
${pinned_line}
${verify_name_line}
          "alpn": [
            "h2"
          ]
        },
        "xhttpSettings": {
${host_line}
          "path": "${XHTTP_PATH}",
          "mode": "auto"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ]
}
EOF
}

write_systemd_service() {
  local service_file
  service_file="${SERVICE_DIR}/${SERVICE_NAME}.service"
  mkdir -p "$SERVICE_DIR"
  cat >"$service_file" <<EOF
[Unit]
Description=Xray XHTTP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain)
      DOMAIN="${2:-}"
      shift 2
      ;;
    --uuid)
      UUID_VALUE="${2:-}"
      shift 2
      ;;
    --path)
      XHTTP_PATH="${2:-}"
      shift 2
      ;;
    --port)
      LISTEN_PORT="${2:-}"
      shift 2
      ;;
    --cert)
      CERT_FILE="${2:-}"
      shift 2
      ;;
    --key)
      KEY_FILE="${2:-}"
      shift 2
      ;;
    --xray-bin)
      XRAY_BIN="${2:-}"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="${2:-}"
      shift 2
      ;;
    --config-file)
      CONFIG_FILE="${2:-}"
      shift 2
      ;;
    --client-export)
      CLIENT_EXPORT="${2:-}"
      shift 2
      ;;
    --service-dir)
      SERVICE_DIR="${2:-}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --skip-install)
      INSTALL_XRAY="0"
      shift
      ;;
    --skip-service)
      START_SERVICE="0"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$DOMAIN" ]; then
  echo "--domain is required" >&2
  usage
  exit 1
fi

if [ -z "$UUID_VALUE" ]; then
  UUID_VALUE="$(generate_uuid)"
fi

mkdir -p "$CONFIG_DIR"

if [ -z "$CERT_FILE" ] && [ -z "$KEY_FILE" ]; then
  create_self_signed_cert
elif [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then
  if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "certificate or key file does not exist" >&2
    exit 1
  fi
else
  echo "--cert and --key must be provided together" >&2
  exit 1
fi

if [ "$INSTALL_XRAY" = "1" ]; then
  install_xray
fi

if [ ! -x "$XRAY_BIN" ]; then
  echo "xray binary not found: $XRAY_BIN" >&2
  exit 1
fi

if [ "$ALLOW_INSECURE_EXPORT" = "1" ]; then
  compute_pinned_cert_hash
  ALLOW_INSECURE_EXPORT="0"
fi

render_server_config
render_client_export
"$XRAY_BIN" run -test -c "$CONFIG_FILE"

if [ "$START_SERVICE" = "1" ]; then
  need_cmd systemctl
  write_systemd_service
fi

cat <<EOF
Server config: ${CONFIG_FILE}
Client export: ${CLIENT_EXPORT}
UUID: ${UUID_VALUE}
Domain: ${DOMAIN}
Port: ${LISTEN_PORT}
Path: ${XHTTP_PATH}
AllowInsecure in exported client: ${ALLOW_INSECURE_EXPORT}
PinnedPeerCertSha256 in exported client: ${PINNED_CERT_SHA256}
EOF
