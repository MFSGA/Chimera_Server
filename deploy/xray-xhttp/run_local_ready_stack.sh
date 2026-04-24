#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/.generated/local-ready}"
VALUES_FILE="${VALUES_FILE:-${SCRIPT_DIR}/local-ready-values.env}"

usage() {
  cat <<'EOF'
Usage:
  run_local_ready_stack.sh

Environment overrides:
  OUTPUT_DIR    ready bundle and runtime directory
  VALUES_FILE   preset values file path
EOF
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

"${SCRIPT_DIR}/render_local_ready_bundle.sh"

METADATA_FILE="${OUTPUT_DIR}/ready-bundle.env"
if [ ! -f "${METADATA_FILE}" ]; then
  echo "missing metadata file: ${METADATA_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${METADATA_FILE}"

TARGET_PID_FILE="${OUTPUT_DIR}/target.pid"
CHIMERA_PID_FILE="${OUTPUT_DIR}/chimera.pid"
XRAY_PID_FILE="${OUTPUT_DIR}/xray.pid"
TARGET_LOG="${OUTPUT_DIR}/target.log"
CHIMERA_LOG="${OUTPUT_DIR}/chimera.log"
XRAY_LOG="${OUTPUT_DIR}/xray.log"

stop_if_running() {
  local pid_file="$1"
  if [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" >/dev/null 2>&1; then
    kill "$(cat "${pid_file}")" >/dev/null 2>&1 || true
    rm -f "${pid_file}"
    sleep 1
  else
    rm -f "${pid_file}"
  fi
}

stop_if_running "${XRAY_PID_FILE}"
stop_if_running "${CHIMERA_PID_FILE}"
stop_if_running "${TARGET_PID_FILE}"

nohup python3 -m http.server "${TARGET_PORT}" --bind 127.0.0.1 >"${TARGET_LOG}" 2>&1 &
echo "$!" >"${TARGET_PID_FILE}"

nohup cargo run -p chimera_server_app --no-default-features --features "${CHIMERA_FEATURES}" -- \
  --config "${SERVER_CONFIG}" >"${CHIMERA_LOG}" 2>&1 &
echo "$!" >"${CHIMERA_PID_FILE}"

for _ in $(seq 1 30); do
  if curl -sk --http2 --resolve "${HOST_NAME}:${CHIMERA_PORT}:127.0.0.1" \
    "https://${HOST_NAME}:${CHIMERA_PORT}${XHTTP_PATH}" \
    -X POST --data-binary 'probe' -o /dev/null -w '%{http_code}' | grep -qx '200'; then
    break
  fi
  if ! kill -0 "$(cat "${CHIMERA_PID_FILE}")" >/dev/null 2>&1; then
    echo "chimera server exited early; inspect ${CHIMERA_LOG}" >&2
    exit 1
  fi
  sleep 1
done

nohup "${XRAY_BIN}" run -c "${CLIENT_CONFIG}" >"${XRAY_LOG}" 2>&1 &
echo "$!" >"${XRAY_PID_FILE}"

for _ in $(seq 1 15); do
  if curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" --max-time 10 -I \
    "http://127.0.0.1:${TARGET_PORT}/" >/dev/null 2>&1; then
    READY="1"
    break
  fi
  if ! kill -0 "$(cat "${XRAY_PID_FILE}")" >/dev/null 2>&1; then
    echo "xray client exited early; inspect ${XRAY_LOG}" >&2
    exit 1
  fi
  sleep 1
done

if [ "${READY:-0}" != "1" ]; then
  echo "xray socks proxy did not become ready; inspect ${XRAY_LOG} and ${CHIMERA_LOG}" >&2
  exit 1
fi

printf '%s\n' "local ready stack started"
printf '%s\n' "server config: ${SERVER_CONFIG}"
printf '%s\n' "client config: ${CLIENT_CONFIG}"
printf '%s\n' "xray socks: 127.0.0.1:${SOCKS_PORT}"
printf '%s\n' "test with: curl --socks5-hostname 127.0.0.1:${SOCKS_PORT} -I http://127.0.0.1:${TARGET_PORT}/"
