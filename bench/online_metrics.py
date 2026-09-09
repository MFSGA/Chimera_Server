#!/usr/bin/env python3
"""Low-overhead Linux host/process sampler for real-network Chimera benchmarks.

The sampler is intentionally read-only and uses /proc plus /sys so it can run on
minimal production-like hosts without pidstat/sar. It emits JSON Lines and does
not read process command-line arguments or environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any


PROC = Path("/proc")
SYS_NET = Path("/sys/class/net")


def read_text(path: Path) -> str | None:
    try:
        return path.read_text()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def parse_status(pid: int) -> dict[str, int | None]:
    text = read_text(PROC / str(pid) / "status")
    result: dict[str, int | None] = {
        "rss_kib": None,
        "hwm_kib": None,
        "threads": None,
        "voluntary_context_switches": None,
        "nonvoluntary_context_switches": None,
    }
    if text is None:
        return result

    keys = {
        "VmRSS": "rss_kib",
        "VmHWM": "hwm_kib",
        "Threads": "threads",
        "voluntary_ctxt_switches": "voluntary_context_switches",
        "nonvoluntary_ctxt_switches": "nonvoluntary_context_switches",
    }
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep or key not in keys:
            continue
        token = rest.strip().split()[0] if rest.strip() else ""
        try:
            result[keys[key]] = int(token)
        except ValueError:
            pass
    return result


def parse_stat_cpu_ticks(pid: int) -> int | None:
    text = read_text(PROC / str(pid) / "stat")
    if not text:
        return None
    close = text.rfind(")")
    if close < 0:
        return None
    fields = text[close + 2 :].split()
    # fields[0] is field 3 (state); utime/stime are fields 14/15.
    if len(fields) <= 12:
        return None
    try:
        return int(fields[11]) + int(fields[12])
    except ValueError:
        return None


def count_fds(pid: int) -> int | None:
    try:
        return len(os.listdir(PROC / str(pid) / "fd"))
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def read_netdev(interface: str | None) -> dict[str, int] | None:
    if not interface:
        return None
    base = SYS_NET / interface / "statistics"
    names = (
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_errors",
        "tx_errors",
        "rx_dropped",
        "tx_dropped",
    )
    values: dict[str, int] = {}
    for name in names:
        text = read_text(base / name)
        if text is None:
            return None
        try:
            values[name] = int(text.strip())
        except ValueError:
            return None
    return values


def read_softirqs() -> dict[str, Any] | None:
    text = read_text(PROC / "softirqs")
    if not text:
        return None
    result: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("NET_RX:") or stripped.startswith("NET_TX:")):
            continue
        name, _, rest = stripped.partition(":")
        try:
            per_cpu = [int(value) for value in rest.split()]
        except ValueError:
            continue
        result[name.lower()] = {
            "total": sum(per_cpu),
            "per_cpu": per_cpu,
        }
    return result or None


def read_tcp_snmp() -> dict[str, int] | None:
    text = read_text(PROC / "net" / "snmp")
    if not text:
        return None
    lines = text.splitlines()
    for index in range(len(lines) - 1):
        if not lines[index].startswith("Tcp:") or not lines[index + 1].startswith("Tcp:"):
            continue
        keys = lines[index].split()[1:]
        values = lines[index + 1].split()[1:]
        if len(keys) != len(values):
            continue
        parsed: dict[str, int] = {}
        for key, value in zip(keys, values):
            if key not in {"CurrEstab", "InErrs", "OutRsts", "RetransSegs", "ActiveOpens", "PassiveOpens"}:
                continue
            try:
                parsed[key] = int(value)
            except ValueError:
                pass
        return parsed
    return None


def read_interface_metadata(interface: str | None) -> dict[str, Any] | None:
    if not interface:
        return None
    base = SYS_NET / interface
    if not base.exists():
        return None
    result: dict[str, Any] = {"name": interface}
    for name in ("mtu", "operstate", "address"):
        value = read_text(base / name)
        if value is not None:
            result[name] = value.strip()
    speed = read_text(base / "speed")
    if speed is not None:
        try:
            result["speed_mbps"] = int(speed.strip())
        except ValueError:
            result["speed_mbps"] = speed.strip()
    return result


def delta_rate(current: dict[str, int] | None, previous: dict[str, int] | None, elapsed: float) -> dict[str, float] | None:
    if current is None or previous is None or elapsed <= 0:
        return None
    result: dict[str, float] = {}
    for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
        if key not in current or key not in previous:
            continue
        delta = current[key] - previous[key]
        result[f"{key}_per_sec"] = delta / elapsed
    if "rx_bytes_per_sec" in result:
        result["rx_mbps"] = result["rx_bytes_per_sec"] * 8 / 1_000_000
    if "tx_bytes_per_sec" in result:
        result["tx_mbps"] = result["tx_bytes_per_sec"] * 8 / 1_000_000
    return result


def diff_counter_map(current: dict[str, int] | None, previous: dict[str, int] | None) -> dict[str, int] | None:
    if current is None or previous is None:
        return None
    return {key: current[key] - previous.get(key, current[key]) for key in current}


def diff_softirq(current: dict[str, Any] | None, previous: dict[str, Any] | None) -> dict[str, int] | None:
    if current is None or previous is None:
        return None
    result: dict[str, int] = {}
    for key in ("net_rx", "net_tx"):
        if key in current and key in previous:
            result[f"{key}_delta"] = current[key]["total"] - previous[key]["total"]
    return result or None


def metadata(pid: int | None, interface: str | None) -> dict[str, Any]:
    return {
        "kind": "metadata",
        "timestamp_unix": time.time(),
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "pid": pid,
        "interface": read_interface_metadata(interface),
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
    }


def sample(pid: int | None, interface: str | None) -> dict[str, Any]:
    process: dict[str, Any] | None = None
    if pid is not None:
        status = parse_status(pid)
        ticks = parse_stat_cpu_ticks(pid)
        process = {
            "alive": (PROC / str(pid)).exists(),
            **status,
            "cpu_ticks": ticks,
            "fd_count": count_fds(pid),
        }
    return {
        "kind": "sample",
        "timestamp_unix": time.time(),
        "monotonic": time.monotonic(),
        "process": process,
        "interface": read_netdev(interface),
        "tcp": read_tcp_snmp(),
        "softirq": read_softirqs(),
    }


def enrich_delta(current: dict[str, Any], previous: dict[str, Any] | None, hz: int) -> None:
    if previous is None:
        return
    elapsed = current["monotonic"] - previous["monotonic"]
    current["sample_interval_seconds"] = elapsed

    process = current.get("process")
    previous_process = previous.get("process")
    if process and previous_process:
        ticks = process.get("cpu_ticks")
        previous_ticks = previous_process.get("cpu_ticks")
        if ticks is not None and previous_ticks is not None and elapsed > 0:
            cpu_seconds = (ticks - previous_ticks) / hz
            process["cpu_seconds_delta"] = cpu_seconds
            # 100% means one logical CPU fully occupied during the interval.
            process["cpu_percent_one_core_100"] = cpu_seconds / elapsed * 100
        for key in ("voluntary_context_switches", "nonvoluntary_context_switches"):
            value = process.get(key)
            old = previous_process.get(key)
            if value is not None and old is not None:
                process[f"{key}_delta"] = value - old

    current["interface_rate"] = delta_rate(
        current.get("interface"), previous.get("interface"), elapsed
    )
    current["tcp_delta"] = diff_counter_map(current.get("tcp"), previous.get("tcp"))
    current["softirq_delta"] = diff_softirq(current.get("softirq"), previous.get("softirq"))


def emit(record: dict[str, Any], output) -> None:
    output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    output.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Linux metrics sampler for online proxy benchmarks")
    parser.add_argument("--pid", type=int, help="Process PID to sample")
    parser.add_argument("--interface", help="Network interface to sample, e.g. eth0")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval seconds (default: 1.0)")
    parser.add_argument("--count", type=int, default=0, help="Number of samples; 0 means until interrupted")
    parser.add_argument("--output", help="JSONL output path; default stdout")
    args = parser.parse_args()

    if args.pid is None and args.interface is None:
        parser.error("provide at least --pid or --interface")
    if args.pid is not None and args.pid <= 0:
        parser.error("--pid must be > 0")
    if args.interval <= 0:
        parser.error("--interval must be > 0")
    if args.count < 0:
        parser.error("--count must be >= 0")
    if args.interface and not (SYS_NET / args.interface).exists():
        parser.error(f"interface {args.interface!r} does not exist")

    output = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    stop = False

    def handle_signal(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        meta = metadata(args.pid, args.interface)
        emit(meta, output)
        hz = int(meta["clock_ticks_per_second"])
        previous: dict[str, Any] | None = None
        emitted = 0
        next_deadline = time.monotonic()
        while not stop and (args.count == 0 or emitted < args.count):
            current = sample(args.pid, args.interface)
            enrich_delta(current, previous, hz)
            emit(current, output)
            previous = current
            emitted += 1
            if args.count and emitted >= args.count:
                break
            next_deadline += args.interval
            sleep_for = next_deadline - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)
        return 0
    finally:
        if output is not sys.stdout:
            output.close()


if __name__ == "__main__":
    raise SystemExit(main())
