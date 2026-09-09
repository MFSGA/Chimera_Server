#!/usr/bin/env bash
set -euo pipefail

# Reproducible real-network A/B driver for Chimera_Server.
# Required:
#   TARGET_HOST=<host running wan_probe server>
#   BASELINE_PROXY=<local SOCKS5 host:port, or direct>
#   CANDIDATE_PROXY=<local SOCKS5 host:port, or direct>
# Optional variables below may be overridden by the environment.

: "${TARGET_HOST:?set TARGET_HOST to the WAN probe target host}"
: "${BASELINE_PROXY:?set BASELINE_PROXY to SOCKS5 host:port or direct}"
: "${CANDIDATE_PROXY:?set CANDIDATE_PROXY to SOCKS5 host:port or direct}"

TARGET_PORT="${TARGET_PORT:-20000}"
BASELINE_LABEL="${BASELINE_LABEL:-xray}"
CANDIDATE_LABEL="${CANDIDATE_LABEL:-chimera}"
CONCURRENCY="${CONCURRENCY:-1,16,64}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-67108864}"
WARMUP="${WARMUP:-3}"
RUNS="${RUNS:-10}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
OUTPUT_DIR="${OUTPUT_DIR:-bench/results/online-$(date +%Y%m%d-%H%M%S)}"
MAX_REGRESSION_PCT="${MAX_REGRESSION_PCT:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/bench/chimera_perf/Cargo.toml"
PROBE="$ROOT_DIR/bench/chimera_perf/target/release/wan_probe"
COMPARE="$ROOT_DIR/bench/online_compare.py"

if [[ "$OUTPUT_DIR" != /* ]]; then
  OUTPUT_DIR="$ROOT_DIR/$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

cargo build --release --manifest-path "$MANIFEST" --bin wan_probe

common=(
  client
  --target-host "$TARGET_HOST"
  --target-port "$TARGET_PORT"
  --endpoint "$BASELINE_LABEL=$BASELINE_PROXY"
  --endpoint "$CANDIDATE_LABEL=$CANDIDATE_PROXY"
  --concurrency "$CONCURRENCY"
  --payload-bytes "$PAYLOAD_BYTES"
  --warmup "$WARMUP"
  --runs "$RUNS"
  --timeout-secs "$TIMEOUT_SECS"
)

roundtrip_json="$OUTPUT_DIR/roundtrip.json"
duplex_json="$OUTPUT_DIR/duplex.json"
roundtrip_md="$OUTPUT_DIR/roundtrip.md"
duplex_md="$OUTPUT_DIR/duplex.md"

"$PROBE" "${common[@]}" --output "$roundtrip_json"
"$PROBE" "${common[@]}" --mode duplex --output "$duplex_json"

compare_args=(--baseline "$BASELINE_LABEL" --strict-stability)
if [[ -n "$MAX_REGRESSION_PCT" ]]; then
  compare_args+=(--max-regression-pct "$MAX_REGRESSION_PCT")
fi

roundtrip_status=0
python3 "$COMPARE" "$roundtrip_json" "${compare_args[@]}" > "$roundtrip_md" || roundtrip_status=$?
duplex_status=0
python3 "$COMPARE" "$duplex_json" "${compare_args[@]}" > "$duplex_md" || duplex_status=$?

printf 'Roundtrip summary: %s\n' "$roundtrip_md"
printf 'Duplex summary:    %s\n' "$duplex_md"
printf 'Raw reports:       %s , %s\n' "$roundtrip_json" "$duplex_json"

if (( roundtrip_status != 0 || duplex_status != 0 )); then
  printf 'A/B result did not pass the configured stability/regression gate.\n' >&2
  exit 2
fi
