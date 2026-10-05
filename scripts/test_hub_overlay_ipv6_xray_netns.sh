#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
host_uid=$(id -u)
for command_name in cargo ip unshare; do
    command -v "$command_name" >/dev/null
done

xray_bin=${XRAY_BIN:-"$repo_root/xray"}
if [[ "$xray_bin" != /* ]]; then
    xray_bin="$repo_root/$xray_bin"
fi
if [[ ! -x "$xray_bin" ]]; then
    printf 'Xray client binary is required for this interoperability test: %s\n' "$xray_bin" >&2
    exit 1
fi

unshare --user --map-users="0:${host_uid}:1" --net bash -s -- "$repo_root" <<'NAMESPACE_SCRIPT'
set -euo pipefail
repo_root=$1
cd "$repo_root"

# The host may have IPv6 disabled. The disposable namespace owns its loopback
# setup and leaves the host network configuration untouched.
ip link set lo up
if ! ip -6 addr show dev lo | grep -F 'inet6 ::1/128' >/dev/null; then
    ip -6 addr add ::1/128 dev lo
fi

REQUIRE_HUB_IPV6_OVERLAY=1 cargo test \
    -p chimera_server_app \
    --test vless_reverse_xray_e2e \
    xray_clients_are_isolated_by_hub_overlay_access_rules_before_edge_dispatch \
    --locked -- --exact --nocapture
NAMESPACE_SCRIPT
