#!/usr/bin/env python3
"""Summarize and A/B compare a `wan_probe client` JSON report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def pct_delta(value: float | None, baseline: float | None) -> float | None:
    if value is None or baseline in (None, 0):
        return None
    return (value - baseline) / baseline * 100.0


def fmt(value: float | None, digits: int = 2) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def fmt_pct(value: float | None) -> str:
    return "-" if value is None else f"{value:+.2f}%"


def load_report(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        report = json.load(handle)
    if report.get("schema_version") != 1:
        raise ValueError(f"unsupported schema_version {report.get('schema_version')!r}")
    if not isinstance(report.get("summaries"), list):
        raise ValueError("report does not contain summaries")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare WAN probe endpoint summaries")
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", required=True, help="Endpoint label used as the A/B baseline")
    parser.add_argument(
        "--max-regression-pct",
        type=float,
        help="Return non-zero if a stable candidate is slower than baseline by more than this percent",
    )
    parser.add_argument(
        "--strict-stability",
        action="store_true",
        help="Return non-zero if any formal endpoint/concurrency summary fails the 3%% CV gate",
    )
    args = parser.parse_args()

    if args.max_regression_pct is not None and args.max_regression_pct < 0:
        parser.error("--max-regression-pct must be >= 0")

    report = load_report(args.report)
    mode = report.get("mode")
    summaries = report["summaries"]
    by_key = {(row["endpoint"], row["concurrency"]): row for row in summaries}
    concurrencies = sorted({row["concurrency"] for row in summaries})
    endpoints = report.get("endpoints", [])
    if args.baseline not in endpoints:
        parser.error(f"baseline endpoint {args.baseline!r} is not in report endpoints {endpoints!r}")

    failed = False
    print(
        f"# WAN A/B summary\n\n"
        f"Target: `{report['target_host']}:{report['target_port']}`  \n"
        f"Mode: `{mode}`  \n"
        f"Payload: `{report['payload_bytes_per_direction_per_flow']}` bytes/flow/direction  \n"
        f"Warmup/formal: `{report['warmup_runs']}/{report['formal_runs']}`\n"
    )

    if mode == "roundtrip":
        print("| c | endpoint | stable | connect success | upload Mbps | Δ upload | upload CV | download Mbps | Δ download | download CV | setup p99 ms |")
        print("|---:|---|:---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    else:
        print("| c | endpoint | stable | connect success | duplex Mbps | Δ duplex | duplex CV | setup p99 ms |")
        print("|---:|---|:---:|---:|---:|---:|---:|---:|")

    for concurrency in concurrencies:
        baseline = by_key.get((args.baseline, concurrency))
        if baseline is None:
            raise ValueError(f"missing baseline summary for concurrency {concurrency}")
        for endpoint in endpoints:
            row = by_key.get((endpoint, concurrency))
            if row is None:
                continue
            stable = bool(row["stable_at_3pct_cv"])
            if args.strict_stability and not stable:
                failed = True

            if mode == "roundtrip":
                upload_delta = pct_delta(
                    row.get("aggregate_upload_mbps_median"),
                    baseline.get("aggregate_upload_mbps_median"),
                )
                download_delta = pct_delta(
                    row.get("aggregate_download_mbps_median"),
                    baseline.get("aggregate_download_mbps_median"),
                )
                print(
                    f"| {concurrency} | {endpoint} | {'yes' if stable else 'NO'} | "
                    f"{row['connection_success_rate'] * 100:.2f}% | "
                    f"{fmt(row.get('aggregate_upload_mbps_median'))} | {fmt_pct(upload_delta)} | "
                    f"{fmt((row.get('aggregate_upload_cv') or 0) * 100)}% | "
                    f"{fmt(row.get('aggregate_download_mbps_median'))} | {fmt_pct(download_delta)} | "
                    f"{fmt((row.get('aggregate_download_cv') or 0) * 100)}% | "
                    f"{fmt(row.get('setup_p99_ms_median'))} |"
                )
                if (
                    endpoint != args.baseline
                    and stable
                    and baseline["stable_at_3pct_cv"]
                    and args.max_regression_pct is not None
                    and (
                        (upload_delta is not None and upload_delta < -args.max_regression_pct)
                        or (download_delta is not None and download_delta < -args.max_regression_pct)
                    )
                ):
                    failed = True
            else:
                duplex_delta = pct_delta(
                    row.get("aggregate_duplex_mbps_median"),
                    baseline.get("aggregate_duplex_mbps_median"),
                )
                print(
                    f"| {concurrency} | {endpoint} | {'yes' if stable else 'NO'} | "
                    f"{row['connection_success_rate'] * 100:.2f}% | "
                    f"{fmt(row.get('aggregate_duplex_mbps_median'))} | {fmt_pct(duplex_delta)} | "
                    f"{fmt((row.get('aggregate_duplex_cv') or 0) * 100)}% | "
                    f"{fmt(row.get('setup_p99_ms_median'))} |"
                )
                if (
                    endpoint != args.baseline
                    and stable
                    and baseline["stable_at_3pct_cv"]
                    and args.max_regression_pct is not None
                    and duplex_delta is not None
                    and duplex_delta < -args.max_regression_pct
                ):
                    failed = True

    print("\n`stable=yes` requires every formal run to pass correctness and the relevant throughput CV(s) to be ≤3%.")
    if args.max_regression_pct is not None:
        print(
            f"Regression gate: stable candidates may not be more than {args.max_regression_pct:.2f}% slower than the stable baseline."
        )
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
