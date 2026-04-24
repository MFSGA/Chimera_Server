#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VALUES_FILE="${VALUES_FILE:-${SCRIPT_DIR}/local-ready-values.env}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/.generated/local-ready}"

usage() {
  cat <<'EOF'
Usage:
  render_local_ready_bundle.sh

Environment overrides:
  VALUES_FILE   preset values file path
  OUTPUT_DIR    output directory for generated certs/configs/logs
  XRAY_BIN      xray binary path; auto-downloads into OUTPUT_DIR/bin when missing
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

ensure_xray_bin() {
  if [ -n "${XRAY_BIN:-}" ] && [ -x "${XRAY_BIN}" ]; then
    return
  fi

  if [ -x "${REPO_ROOT}/xray" ]; then
    XRAY_BIN="${REPO_ROOT}/xray"
    return
  fi

  if command -v xray >/dev/null 2>&1; then
    XRAY_BIN="$(command -v xray)"
    return
  fi

  need_cmd curl
  need_cmd unzip

  local asset url tmpdir
  asset="$(arch_asset)"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/${asset}"
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/xray-download.XXXXXX")"
  trap 'rm -rf "${tmpdir}"' RETURN

  mkdir -p "${OUTPUT_DIR}/bin"
  curl -fsSL "${url}" -o "${tmpdir}/xray.zip"
  unzip -oq "${tmpdir}/xray.zip" -d "${tmpdir}/xray"
  install -Dm755 "${tmpdir}/xray/xray" "${OUTPUT_DIR}/bin/xray"
  XRAY_BIN="${OUTPUT_DIR}/bin/xray"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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

need_cmd openssl
need_cmd awk

if [ ! -f "${VALUES_FILE}" ]; then
  echo "preset values file not found: ${VALUES_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${VALUES_FILE}"

ensure_xray_bin
mkdir -p "${OUTPUT_DIR}"

CERT_FILE="${OUTPUT_DIR}/server.crt"
KEY_FILE="${OUTPUT_DIR}/server.key"
SERVER_CONFIG="${OUTPUT_DIR}/server-ready.local.json"
CLIENT_CONFIG="${OUTPUT_DIR}/client-ready.local.json"
METADATA_FILE="${OUTPUT_DIR}/ready-bundle.env"

openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -subj "/CN=${HOST_NAME}" \
  -addext "subjectAltName = DNS:${HOST_NAME}" >/dev/null 2>&1

PINNED_CERT_SHA256="$("${XRAY_BIN}" tls hash --cert "${CERT_FILE}" | awk '/Leaf SHA256:/ {print $3}')"
if [ -z "${PINNED_CERT_SHA256}" ]; then
  echo "failed to compute pinnedPeerCertSha256" >&2
  exit 1
fi

cat >"${SERVER_CONFIG}" <<EOF
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

cat >"${CLIENT_CONFIG}" <<EOF
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

cat >"${METADATA_FILE}" <<EOF
XRAY_BIN=${XRAY_BIN}
HOST_NAME=${HOST_NAME}
UUID_VALUE=${UUID_VALUE}
XHTTP_PATH=${XHTTP_PATH}
CHIMERA_PORT=${CHIMERA_PORT}
SOCKS_PORT=${SOCKS_PORT}
TARGET_PORT=${TARGET_PORT}
CHIMERA_FEATURES=${CHIMERA_FEATURES}
CERT_FILE=${CERT_FILE}
KEY_FILE=${KEY_FILE}
PINNED_CERT_SHA256=${PINNED_CERT_SHA256}
SERVER_CONFIG=${SERVER_CONFIG}
CLIENT_CONFIG=${CLIENT_CONFIG}
EOF

printf '%s\n' "ready bundle generated at ${OUTPUT_DIR}"
printf '%s\n' "server config: ${SERVER_CONFIG}"
printf '%s\n' "client config: ${CLIENT_CONFIG}"
printf '%s\n' "xray bin: ${XRAY_BIN}"
