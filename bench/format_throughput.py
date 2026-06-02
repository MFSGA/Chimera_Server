#!/usr/bin/env python3
"""Format throughput test JSON-lines results as grouped Markdown tables.

Usage:
    python3 bench/format_throughput.py results.jsonl [--output comment.md]
                                                     [--run-url URL]
                                                     [--env-json JSON]

Each line of results.jsonl must be a JSON object with:
    label               – test name in "<protocol>-<transport>" format (e.g. "socks-direct")
    scenario            – scenario identifier (e.g. "tier1_socks_direct")
    upload_mbps         – upload throughput in Mbps (median across runs)
    download_mbps       – download throughput in Mbps (median across runs)
    upload_stdev_mbps   – upload stdev in Mbps (optional, 0 if absent)
    download_stdev_mbps – download stdev in Mbps (optional, 0 if absent)
    runs                – number of iterations (optional)
    total_bytes         – payload size in bytes
    engine              – engine name (e.g. "chimera")

Output groups rows by scenario, with one table per scenario group.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

# Display name and canonical sort order for each protocol prefix.
PROTOCOL_META = {
    "socks": ("SOCKS", 0),
    "vless": ("VLESS", 1),
}

# Canonical sort order for transport variants.
# Transports not listed here sort last (key 99), then alphabetically.
TRANSPORT_ORDER = {
    "direct": 0,
    "tcp": 1,
    "kcp": 2,
    "ws": 3,
    "tls": 4,
    "h2": 5,
    "grpc": 6,
    "quic": 7,
    "http": 8,
}


def parse_scenario(scenario: str) -> tuple[str, str, str]:
    """Parse 'tier1_socks_direct' into (tier_label, proto, transport).

    Returns ("unknown", "unknown", "unknown") for unrecognised formats.
    """
    parts = scenario.split("_", 2)
    if len(parts) < 3:
        return ("unknown", "unknown", "unknown")

    tier_raw = parts[0]  # "tier1"
    proto = parts[1]  # "socks"
    transport = parts[2]  # "direct"

    # Humanize the tier part
    tier_num = tier_raw.replace("tier", "")
    tier_label = f"Tier {tier_num}" if tier_num.isdigit() else tier_raw

    return tier_label, proto, transport


def fmt_mbps(value: float, stdev: float) -> str:
    """Format throughput value with optional stdev."""
    if stdev > 0:
        return f"{value:.1f} ±{stdev:.1f}"
    return f"{value:.1f}"


def render_table(rows: list, lines: list) -> None:
    """Append a Markdown throughput table for *rows* to *lines*."""
    has_change = any("regression_pct" in r for r in rows)

    if has_change:
        lines += [
            "| Transport | Payload | Runs | Upload Mbps (&plusmn;&sigma;) | Download Mbps (&plusmn;&sigma;) | Change |",
            "|-----------|---------|:----:|:----------------------------:|:------------------------------:|:------:|",
        ]
    else:
        lines += [
            "| Transport | Payload | Runs | Upload Mbps (&plusmn;&sigma;) | Download Mbps (&plusmn;&sigma;) |",
            "|-----------|---------|:----:|:----------------------------:|:------------------------------:|",
        ]

    for r in rows:
        label = r.get("label", "?")
        transport = label.split("-", 1)[1] if "-" in label else label
        payload_mb = r.get("total_bytes", 0) // (1024 * 1024)
        runs = r.get("runs", 1)
        upload = fmt_mbps(r.get("upload_mbps", 0.0), r.get("upload_stdev_mbps", 0.0))
        download = fmt_mbps(r.get("download_mbps", 0.0), r.get("download_stdev_mbps", 0.0))

        if has_change:
            regression_pct = r.get("regression_pct")
            if regression_pct is not None:
                if regression_pct < -10:
                    change = f"**`{regression_pct:+.1f}%` ⚠\uFE0F**"
                else:
                    change = f"`{regression_pct:+.1f}%`"
            else:
                change = "—"
            lines.append(f"| `{transport}` | {payload_mb} MB | {runs} | {upload} | {download} | {change} |")
        else:
            lines.append(f"| `{transport}` | {payload_mb} MB | {runs} | {upload} | {download} |")
    lines.append("")


def scenario_sort_key(scenario: str) -> tuple:
    """Sort key: protocol order first, then tier number, then transport order."""
    tier_label, proto, transport = parse_scenario(scenario)

    meta = PROTOCOL_META.get(proto)
    proto_order = meta[1] if meta else 99

    transport_order = TRANSPORT_ORDER.get(transport, 99)

    # Extract numeric tier for sorting
    try:
        tier_num = int(scenario.split("_")[0].replace("tier", ""))
    except (ValueError, IndexError):
        tier_num = 99

    return (proto_order, tier_num, transport_order)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Format throughput JSON-lines results as Markdown tables."
    )
    parser.add_argument("results", help="JSON-lines result file")
    parser.add_argument("--output", "-o", help="Write markdown to this file (default: stdout)")
    parser.add_argument("--run-url", help="URL to the GitHub Actions workflow run")
    parser.add_argument("--env-json", help="JSON string with test environment info")
    args = parser.parse_args()

    # --- Read JSON-lines ---------------------------------------------------
    rows = []
    try:
        with open(args.results) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: skipping invalid JSON line: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(
            f"Warning: result file not found: {args.results}; generating empty report",
            file=sys.stderr,
        )

    # --- Build Markdown ----------------------------------------------------
    if not rows:
        md_lines = ["## Proxy Throughput Results", "", "_No results recorded._", ""]
    else:
        # Group by scenario
        groups: dict[str, list] = defaultdict(list)
        for r in rows:
            scenario = r.get("scenario", "unknown")
            groups[scenario].append(r)

        md_lines = ["## Proxy Throughput Results", ""]

        for scenario in sorted(groups, key=scenario_sort_key):
            tier_label, proto, transport_part = parse_scenario(scenario)
            display_name, _ = PROTOCOL_META.get(proto, (proto.upper(), 99))
            heading = f"### {display_name} ({tier_label} &mdash; {transport_part})"
            md_lines.append(heading)
            md_lines.append("")

            scenario_rows = list(groups[scenario])
            # Sort rows by transport order
            scenario_rows.sort(
                key=lambda r: TRANSPORT_ORDER.get(
                    r.get("label", "").split("-", 1)[1] if "-" in r.get("label", "") else "plain",
                    99,
                )
            )
            render_table(scenario_rows, md_lines)

        # Append regression summary if any result carries baseline info
        regression_rows = [r for r in rows if "regression_pct" in r]
        if regression_rows:
            bad = sum(1 for r in regression_rows if r["regression_pct"] < -10)
            if bad > 0:
                md_lines.append(
                    f"⚠️ **{bad} regression(s) detected (>10% upload throughput drop)**"
                )
            else:
                md_lines.append("✓ All results within baseline range")
            md_lines.append("")

        md_lines.append(
            f"_Ran {len(rows)} variant(s) in parallel; each direction transfers the full payload._"
        )
        md_lines.append("")

    md = "\n".join(md_lines)

    # --- Append environment info table -------------------------------------
    if args.env_json:
        try:
            env = json.loads(args.env_json)
            env_lines = ["", "### Test Environment", ""]
            env_lines.append("| | |")
            env_lines.append("|---|---|")
            os_info = env.get("os", {})
            if os_info.get("system"):
                os_str = f"{os_info['system']} {os_info.get('release', '')}".strip()
                env_lines.append(f"| **OS** | {os_str} |")
            if os_info.get("machine"):
                env_lines.append(f"| **Architecture** | {os_info['machine']} |")
            if env.get("cpu"):
                env_lines.append(f"| **CPU** | {env['cpu']} |")
            if env.get("cpu_cores"):
                env_lines.append(f"| **CPU Cores** | {env['cpu_cores']} |")
            if env.get("memory_gb"):
                env_lines.append(f"| **Memory** | {env['memory_gb']} GB |")
            md = md.rstrip("\n") + "\n" + "\n".join(env_lines) + "\n"
        except (json.JSONDecodeError, KeyError):
            pass

    # --- Append workflow run link ------------------------------------------
    if args.run_url:
        md = md.rstrip("\n") + f"\n\n[View workflow run and artifacts]({args.run_url})\n"

    # --- Output ------------------------------------------------------------
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(args.output, "w") as f:
            f.write(md)
        print(f"Written to {args.output}")
    else:
        print(md)


if __name__ == "__main__":
    main()
