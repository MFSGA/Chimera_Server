#!/usr/bin/env bash
set -euo pipefail

SERVER=""
SERVER_NAME=""
HOST_HEADER=""
UUID_VALUE=""
XHTTP_PATH="/xhttp"
SERVER_PORT="443"
SOCKS_PORT="10808"
ALLOW_INSECURE="0"
PINNED_PEER_CERT_SHA256=""
VERIFY_PEER_CERT_BY_NAME=""
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.local/share/xray-xhttp-client}"
BIN_PATH="${BIN_PATH:-}"
CONFIG_FILE="${CONFIG_FILE:-}"
RUN_SCRIPT="${RUN_SCRIPT:-}"
STOP_SCRIPT="${STOP_SCRIPT:-}"
PID_FILE="${PID_FILE:-}"
LOG_FILE="${LOG_FILE:-}"
INSTALL_XRAY="1"
AUTO_START="1"

usage() {
  cat <<'EOF'
Usage:
  install_client_xhttp.sh --server HOST --uuid UUID [options]

Options:
  --server HOST           Remote server address or domain.
  --server-name NAME      TLS serverName. Default: same as --server
  --host HOST             XHTTP host header. Default: same as --server-name
  --uuid UUID             VLESS UUID.
  --path PATH             XHTTP path. Default: /xhttp
  --port PORT             Remote server port. Default: 443
  --socks-port PORT       Local SOCKS5 listen port. Default: 10808
  --allow-insecure        Enable TLS allowInsecure for self-signed test servers.
  --pinned-peer-cert-sha256 HASH
                          Pin the server leaf certificate SHA256 hash.
  --verify-peer-cert-by-name NAME
                          Verify peer certificate against this name.
  --install-root DIR      Client working directory.
  --bin-path FILE         Xray binary output path.
  --config-file FILE      Client config output path.
  --run-script FILE       Client start helper output path.
  --stop-script FILE      Client stop helper output path.
  --pid-file FILE         Client pid file path.
  --log-file FILE         Client log file path.
  --skip-install          Do not download/install Xray.
  --no-start              Generate config and helper scripts only.
  -h, --help              Show this help.
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

  install -Dm755 "$tmpdir/xray/xray" "$BIN_PATH"
  if [ -f "$tmpdir/xray/geoip.dat" ]; then
    install -Dm644 "$tmpdir/xray/geoip.dat" "${INSTALL_ROOT}/geoip.dat"
  fi
  if [ -f "$tmpdir/xray/geosite.dat" ]; then
    install -Dm644 "$tmpdir/xray/geosite.dat" "${INSTALL_ROOT}/geosite.dat"
  fi
}

render_config() {
  local allow_insecure_line
  local host_line
  local pinned_line
  local verify_name_line

  allow_insecure_line=""
  if [ "$ALLOW_INSECURE" = "1" ]; then
    allow_insecure_line='          "allowInsecure": true,'
  fi
  pinned_line=""
  if [ -n "$PINNED_PEER_CERT_SHA256" ]; then
    pinned_line='          "pinnedPeerCertSha256": "'"${PINNED_PEER_CERT_SHA256}"'",'
  fi
  verify_name_line=""
  if [ -n "$VERIFY_PEER_CERT_BY_NAME" ]; then
    verify_name_line='          "verifyPeerCertByName": "'"${VERIFY_PEER_CERT_BY_NAME}"'",'
  fi

  host_line=""
  if [ -n "$HOST_HEADER" ]; then
    host_line='          "host": "'"${HOST_HEADER}"'",'
  fi

  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": ${SOCKS_PORT},
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
            "address": "${SERVER}",
            "port": ${SERVER_PORT},
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
          "serverName": "${SERVER_NAME}",
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

render_helpers() {
  mkdir -p "$INSTALL_ROOT"
  cat >"$RUN_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

BIN_PATH="${BIN_PATH}"
CONFIG_FILE="${CONFIG_FILE}"
PID_FILE="${PID_FILE}"
LOG_FILE="${LOG_FILE}"

if [ -f "\$PID_FILE" ] && kill -0 "\$(cat "\$PID_FILE")" >/dev/null 2>&1; then
  echo "xray client already running with pid \$(cat "\$PID_FILE")"
  exit 0
fi

mkdir -p "\$(dirname "\$PID_FILE")"
nohup "\$BIN_PATH" run -c "\$CONFIG_FILE" >>"\$LOG_FILE" 2>&1 &
echo \$! >"\$PID_FILE"
sleep 1

if kill -0 "\$(cat "\$PID_FILE")" >/dev/null 2>&1; then
  echo "xray client started on 127.0.0.1:${SOCKS_PORT}"
else
  echo "failed to start xray client; check \$LOG_FILE" >&2
  exit 1
fi
EOF

  cat >"$STOP_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${PID_FILE}"

if [ ! -f "\$PID_FILE" ]; then
  echo "xray client is not running"
  exit 0
fi

if kill -0 "\$(cat "\$PID_FILE")" >/dev/null 2>&1; then
  kill "\$(cat "\$PID_FILE")"
  rm -f "\$PID_FILE"
  echo "xray client stopped"
else
  rm -f "\$PID_FILE"
  echo "stale pid file removed"
fi
EOF

  chmod +x "$RUN_SCRIPT" "$STOP_SCRIPT"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server)
      SERVER="${2:-}"
      shift 2
      ;;
    --server-name)
      SERVER_NAME="${2:-}"
      shift 2
      ;;
    --host)
      HOST_HEADER="${2:-}"
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
      SERVER_PORT="${2:-}"
      shift 2
      ;;
    --socks-port)
      SOCKS_PORT="${2:-}"
      shift 2
      ;;
    --allow-insecure)
      ALLOW_INSECURE="1"
      shift
      ;;
    --pinned-peer-cert-sha256)
      PINNED_PEER_CERT_SHA256="${2:-}"
      shift 2
      ;;
    --verify-peer-cert-by-name)
      VERIFY_PEER_CERT_BY_NAME="${2:-}"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="${2:-}"
      shift 2
      ;;
    --bin-path)
      BIN_PATH="${2:-}"
      shift 2
      ;;
    --config-file)
      CONFIG_FILE="${2:-}"
      shift 2
      ;;
    --run-script)
      RUN_SCRIPT="${2:-}"
      shift 2
      ;;
    --stop-script)
      STOP_SCRIPT="${2:-}"
      shift 2
      ;;
    --pid-file)
      PID_FILE="${2:-}"
      shift 2
      ;;
    --log-file)
      LOG_FILE="${2:-}"
      shift 2
      ;;
    --skip-install)
      INSTALL_XRAY="0"
      shift
      ;;
    --no-start)
      AUTO_START="0"
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

if [ -z "$SERVER" ] || [ -z "$UUID_VALUE" ]; then
  echo "--server and --uuid are required" >&2
  usage
  exit 1
fi

if [ -z "$SERVER_NAME" ]; then
  SERVER_NAME="$SERVER"
fi

if [ -z "$HOST_HEADER" ]; then
  HOST_HEADER="$SERVER_NAME"
fi

if [ -n "$PINNED_PEER_CERT_SHA256" ] && [ -z "$VERIFY_PEER_CERT_BY_NAME" ]; then
  VERIFY_PEER_CERT_BY_NAME="$SERVER_NAME"
fi

if [ -z "$BIN_PATH" ]; then
  BIN_PATH="${INSTALL_ROOT}/bin/xray"
fi

if [ -z "$CONFIG_FILE" ]; then
  CONFIG_FILE="${INSTALL_ROOT}/client-xhttp.json"
fi

if [ -z "$RUN_SCRIPT" ]; then
  RUN_SCRIPT="${INSTALL_ROOT}/run-client.sh"
fi

if [ -z "$STOP_SCRIPT" ]; then
  STOP_SCRIPT="${INSTALL_ROOT}/stop-client.sh"
fi

if [ -z "$PID_FILE" ]; then
  PID_FILE="${INSTALL_ROOT}/xray.pid"
fi

if [ -z "$LOG_FILE" ]; then
  LOG_FILE="${INSTALL_ROOT}/xray.log"
fi

mkdir -p "$INSTALL_ROOT"

if [ "$INSTALL_XRAY" = "1" ]; then
  install_xray
fi

if [ ! -x "$BIN_PATH" ]; then
  echo "xray binary not found: $BIN_PATH" >&2
  exit 1
fi

render_config
render_helpers
"$BIN_PATH" run -test -c "$CONFIG_FILE"

if [ "$AUTO_START" = "1" ]; then
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" >/dev/null 2>&1; then
    "$STOP_SCRIPT"
  fi
  "$RUN_SCRIPT"
fi

cat <<EOF
Client config: ${CONFIG_FILE}
Client run script: ${RUN_SCRIPT}
Client stop script: ${STOP_SCRIPT}
Server: ${SERVER}:${SERVER_PORT}
ServerName: ${SERVER_NAME}
Host: ${HOST_HEADER}
Path: ${XHTTP_PATH}
Local SOCKS5: 127.0.0.1:${SOCKS_PORT}
AllowInsecure: ${ALLOW_INSECURE}
PinnedPeerCertSha256: ${PINNED_PEER_CERT_SHA256}
VerifyPeerCertByName: ${VERIFY_PEER_CERT_BY_NAME}
EOF
