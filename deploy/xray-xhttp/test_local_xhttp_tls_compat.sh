#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

XRAY_BIN="${XRAY_BIN:-${REPO_ROOT}/xray}"
CHIMERA_PACKAGE="${CHIMERA_PACKAGE:-chimera_server_app}"
CHIMERA_FEATURES="${CHIMERA_FEATURES:-minimal-vless-tls}"
CHIMERA_PORT="${CHIMERA_PORT:-19443}"
SOCKS_PORT="${SOCKS_PORT:-10809}"
TARGET_PORT="${TARGET_PORT:-18082}"
HOST_NAME="${HOST_NAME:-localhost}"
XHTTP_PATH="${XHTTP_PATH:-/xhttp}"
UUID_VALUE="${UUID_VALUE:-ddb573cb-55f8-4d8d-a609-bd444b14b19b}"
KEEP_TEMP="0"

TMP_DIR=""
SUCCESS="0"
TARGET_PID=""
CHIMERA_PID=""
XRAY_PID=""

usage() {
  cat <<'EOF'
Usage:
  test_local_xhttp_tls_compat.sh [options]

Options:
  --xray-bin FILE        xray binary path. Default: ./xray in repo root
  --chimera-port PORT    local chimera listen port. Default: 19443
  --socks-port PORT      local xray socks port. Default: 10809
  --target-port PORT     local target http port. Default: 18082
  --host NAME            tls serverName and xhttp host. Default: localhost
  --path PATH            xhttp path. Default: /xhttp
  --uuid UUID            vless uuid used for test traffic
  --keep-temp            keep generated temp files even on success
  -h, --help             show this help
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

stop_pid() {
  local pid="$1"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  stop_pid "$XRAY_PID"
  stop_pid "$CHIMERA_PID"
  stop_pid "$TARGET_PID"

  if [ "$SUCCESS" = "1" ] && [ "$KEEP_TEMP" != "1" ] && [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
    return
  fi

  if [ -n "$TMP_DIR" ]; then
    echo "artifacts kept at: $TMP_DIR"
  fi
}

trap cleanup EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --xray-bin)
      XRAY_BIN="${2:-}"
      shift 2
      ;;
    --chimera-port)
      CHIMERA_PORT="${2:-}"
      shift 2
      ;;
    --socks-port)
      SOCKS_PORT="${2:-}"
      shift 2
      ;;
    --target-port)
      TARGET_PORT="${2:-}"
      shift 2
      ;;
    --host)
      HOST_NAME="${2:-}"
      shift 2
      ;;
    --path)
      XHTTP_PATH="${2:-}"
      shift 2
      ;;
    --uuid)
      UUID_VALUE="${2:-}"
      shift 2
      ;;
    --keep-temp)
      KEEP_TEMP="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd cargo
need_cmd curl
need_cmd openssl
need_cmd python3

if [ ! -x "$XRAY_BIN" ]; then
  echo "xray binary not found or not executable: $XRAY_BIN" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chimera-xhttp-tls.XXXXXX")"
CERT_FILE="${TMP_DIR}/server.crt"
KEY_FILE="${TMP_DIR}/server.key"
SERVER_CONFIG="${TMP_DIR}/chimera_server.json"
CLIENT_CONFIG="${TMP_DIR}/xray_client.json"
TARGET_LOG="${TMP_DIR}/target.log"
CHIMERA_LOG="${TMP_DIR}/chimera.log"
XRAY_LOG="${TMP_DIR}/xray.log"

openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -subj "/CN=${HOST_NAME}" \
  -addext "subjectAltName = DNS:${HOST_NAME}" >/dev/null 2>&1

PINNED_CERT_SHA256="$("$XRAY_BIN" tls hash --cert "$CERT_FILE" | awk '/Leaf SHA256:/ {print $3}')"
if [ -z "$PINNED_CERT_SHA256" ]; then
  echo "failed to compute pinnedPeerCertSha256" >&2
  exit 1
fi

cat >"$SERVER_CONFIG" <<EOF
{
  "log": { "level": "debug" },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${CHIMERA_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VALUE}",
            "email": "local@test"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${HOST_NAME}",
          "minVersion": "1.2",
          "maxVersion": "1.3",
          "alpn": ["h2"],
          "certificates": [
            {
              "certificateFile": "${CERT_FILE}",
              "keyFile": "${KEY_FILE}"
            }
          ]
        },
        "xhttpSettings": {
          "host": "${HOST_NAME}",
          "path": "${XHTTP_PATH}",
          "xPaddingBytes": { "from": 100, "to": 1000 },
          "scMaxEachPostBytes": { "from": 1000000, "to": 1000000 },
          "scMaxBufferedPosts": 30,
          "scStreamUpServerSecs": { "from": 20, "to": 80 }
        }
      },
      "tag": "xhttp-in"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {}, "tag": "direct" },
    { "protocol": "blackhole", "settings": {}, "tag": "block" }
  ]
}
EOF

cat >"$CLIENT_CONFIG" <<EOF
{
  "log": {
    "loglevel": "debug"
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
            "address": "127.0.0.1",
            "port": ${CHIMERA_PORT},
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
          "serverName": "${HOST_NAME}",
          "pinnedPeerCertSha256": "${PINNED_CERT_SHA256}",
          "verifyPeerCertByName": "${HOST_NAME}",
          "alpn": ["h2"]
        },
        "xhttpSettings": {
          "host": "${HOST_NAME}",
          "path": "${XHTTP_PATH}",
          "mode": "auto"
        }
      }
    }
  ]
}
EOF

python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 >"$TARGET_LOG" 2>&1 &
TARGET_PID="$!"

cargo run -p "$CHIMERA_PACKAGE" --no-default-features --features "$CHIMERA_FEATURES" -- \
  --config "$SERVER_CONFIG" >"$CHIMERA_LOG" 2>&1 &
CHIMERA_PID="$!"

for _ in $(seq 1 30); do
  if curl -sk --http2 --resolve "${HOST_NAME}:${CHIMERA_PORT}:127.0.0.1" \
    "https://${HOST_NAME}:${CHIMERA_PORT}${XHTTP_PATH}" \
    -X POST --data-binary 'probe' -o /dev/null -w '%{http_code}' | grep -qx '200'; then
    break
  fi
  if ! kill -0 "$CHIMERA_PID" >/dev/null 2>&1; then
    echo "chimera server exited early" >&2
    tail -n 80 "$CHIMERA_LOG" >&2 || true
    exit 1
  fi
  sleep 1
done

if ! kill -0 "$CHIMERA_PID" >/dev/null 2>&1; then
  echo "chimera server exited before readiness" >&2
  tail -n 80 "$CHIMERA_LOG" >&2 || true
  exit 1
fi

"$XRAY_BIN" run -c "$CLIENT_CONFIG" >"$XRAY_LOG" 2>&1 &
XRAY_PID="$!"

RESPONSE_HEADERS=""
for _ in $(seq 1 15); do
  if ! kill -0 "$XRAY_PID" >/dev/null 2>&1; then
    echo "xray client exited early" >&2
    tail -n 80 "$XRAY_LOG" >&2 || true
    exit 1
  fi
  RESPONSE_HEADERS="$(curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" --max-time 10 -I \
    "http://127.0.0.1:${TARGET_PORT}/" 2>/dev/null || true)"
  if printf '%s\n' "$RESPONSE_HEADERS" | grep -q '^HTTP/1\.[01] 200'; then
    SUCCESS="1"
    break
  fi
  sleep 1
done

if [ "$SUCCESS" != "1" ]; then
  echo "compatibility test failed" >&2
  echo "--- chimera.log ---" >&2
  tail -n 120 "$CHIMERA_LOG" >&2 || true
  echo "--- xray.log ---" >&2
  tail -n 120 "$XRAY_LOG" >&2 || true
  echo "--- target.log ---" >&2
  tail -n 40 "$TARGET_LOG" >&2 || true
  exit 1
fi

printf '%s\n' "local xhttp tls/h2 compatibility test passed"
printf '%s\n' "chimera: 127.0.0.1:${CHIMERA_PORT}"
printf '%s\n' "xray socks: 127.0.0.1:${SOCKS_PORT}"
printf '%s\n' "target: 127.0.0.1:${TARGET_PORT}"
printf '%s\n' "$RESPONSE_HEADERS"
