#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/.generated/local-ready}"

usage() {
  cat <<'EOF'
Usage:
  stop_local_ready_stack.sh
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

stop_pid_file() {
  local pid_file="$1"
  if [ ! -f "${pid_file}" ]; then
    return
  fi

  local pid
  pid="$(cat "${pid_file}")"
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${pid_file}"
}

stop_pid_file "${OUTPUT_DIR}/xray.pid"
stop_pid_file "${OUTPUT_DIR}/chimera.pid"
stop_pid_file "${OUTPUT_DIR}/target.pid"

printf '%s\n' "local ready stack stopped"
