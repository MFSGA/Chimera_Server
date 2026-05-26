#!/usr/bin/env python3
"""Proxy throughput benchmark orchestrator for Chimera_Server.

Tests two scenarios with the sync-byte protocol (0xAC barrier):
  Tier 1 (SOCKS direct): echo server -> Chimera SOCKS inbound -> measure throughput
  Tier 2 (VLESS direct): echo server -> Chimera VLESS inbound + xray client -> measure throughput

Usage:
  python3 bench/throughput.py [--only socks|vless|all] [--payload-size N]
      [--runs N] [--output FILE] [--chimera-bin PATH] [--xray-bin PATH]
      [--verbose]

Outputs JSON-lines with upload_mbps, download_mbps, and statistics.

Protocol detail (fixed-size reads, no TCP half-close):

  1. Client opens TCP connection through proxy to echo server
  2. Client sends N bytes of payload (upload)
  3. Echo server reads exactly N bytes, then sends sync byte 0xAC
  4. Client receives 0xAC -> stops upload timer (true E2E delivery)
  5. Client starts download timer
  6. Echo server echoes N bytes back
  7. Client receives all bytes -> stops download timer

  The echo server uses fixed-size reads (knows payload_size upfront)
  so we never need TCP half-close (which SOCKS5 proxies don't support).
"""

import argparse
import json
import os
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

PORT_RANGE = (30000, 40000)
SYNC_BYTE = b"\xAC"
UUID = "114cb5a6-3787-4357-a5da-69b5782cb74f"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "configs")


# ─── Port allocation ────────────────────────────────────────────────────────────


def alloc_port() -> int:
    """Allocate a random port in PORT_RANGE by binding to verify availability."""
    for _ in range(100):
        port = random.randint(*PORT_RANGE)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"Could not find a free port in range {PORT_RANGE}")


# ─── SOCKS5 protocol helpers ────────────────────────────────────────────────────


def socks5_negotiate(sock: socket.socket) -> None:
    """Perform SOCKS5 no-auth negotiation.

    Wire format: send [0x05, 0x01, 0x00], expect [0x05, 0x00].
    """
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 negotiation failed: {resp!r}")


def socks5_connect(sock: socket.socket, host: str, port: int) -> None:
    """Send SOCKS5 CONNECT request to target host:port (IPv4).

    Wire format:
      [0x05, 0x01, 0x00, 0x01, ip4[0..3], port[0..1]]
    Expected: 10-byte response with byte[0]==0x05 and byte[1]==0x00.
    """
    ip = socket.gethostbyname(host)
    ip_octets = [int(b) for b in ip.split(".")]
    port_bytes = port.to_bytes(2, "big")
    request = bytes([0x05, 0x01, 0x00, 0x01] + ip_octets + list(port_bytes))
    sock.sendall(request)
    resp = sock.recv(10)
    if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
        raise RuntimeError(f"SOCKS5 connect failed: {resp!r}")


# ─── Echo server (inline thread, no subprocess) ─────────────────────────────────


class EchoServer:
    """Sync-byte echo server that reads exactly payload_size bytes.

    Runs on a background daemon thread.  No TCP half-close needed — the
    server reads a fixed number of bytes, then sends sync byte + echo.
    """

    def __init__(self, port: int, payload_size: int):
        self.port = port
        self.payload_size = payload_size
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", port))
        self._server.listen(10)
        self._server.settimeout(1.0)
        self._running = True
        self._thread: threading.Thread | None = None

    def _serve(self) -> None:
        """Accept connections and echo with sync byte."""
        while self._running:
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Read exactly payload_size bytes (no EOF needed)
            data = b""
            while len(data) < self.payload_size:
                try:
                    chunk = conn.recv(
                        min(65536, self.payload_size - len(data))
                    )
                    if not chunk:
                        break
                    data += chunk
                except OSError:
                    break
            # Send sync byte then echoed data
            try:
                conn.sendall(SYNC_BYTE)
                conn.sendall(data)
            except OSError:
                pass
            finally:
                conn.close()

    def start(self) -> None:
        """Start the echo server thread."""
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the echo server to stop and release its socket."""
        self._running = False
        try:
            self._server.close()
        except OSError:
            pass


# ─── Throughput measurement (sync-byte protocol) ────────────────────────────────


def measure_throughput(sock: socket.socket, payload_size: int):
    """Measure upload/download Mbps through an established connection.

    Fixed-size sync-byte protocol (no TCP half-close):

      1. Send N bytes through the proxy (upload)
      2. Read sync byte 0xAC -> stop upload timer
      3. Read remaining echoed data -> stop download timer

    Returns (upload_mbps, download_mbps).
    """
    payload = os.urandom(payload_size)

    # Upload phase: send all bytes (no shutdown — SOCKS proxies don't
    # support half-close; the echo server reads exactly payload_size)
    start = time.perf_counter()
    sock.sendall(payload)

    # Read until we find the sync byte
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("Connection closed before receiving sync byte")
        buf += chunk
        idx = buf.find(SYNC_BYTE)
        if idx != -1:
            upload_end = time.perf_counter()
            echoed_data = buf[idx + 1 :]
            break

    # Download phase: read remaining echoed data
    download_start = time.perf_counter()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        echoed_data += chunk
    download_end = time.perf_counter()

    upload_time = upload_end - start
    download_time = download_end - download_start

    # Guard against division-by-zero for degenerate timings
    if upload_time <= 0:
        upload_time = 1e-9
    if download_time <= 0:
        download_time = 1e-9

    upload_mbps = (payload_size * 8) / upload_time / 1_000_000
    download_mbps = (payload_size * 8) / download_time / 1_000_000

    return upload_mbps, download_mbps


# ─── Port readiness check ───────────────────────────────────────────────────────


def wait_for_port(host: str, port: int, timeout: float = 10) -> bool:
    """Wait for a TCP port to become ready (connect succeeds)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.05)
    return False


# ─── Subprocess lifecycle manager ───────────────────────────────────────────────


class ProcManager:
    """Manages benchmark subprocesses, temp dirs, and echo server threads."""

    def __init__(self, verbose: bool = False):
        self.processes: list[subprocess.Popen] = []
        self.temp_dirs: list[str] = []
        self.echo_servers: list[EchoServer] = []
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[bench] {msg}", file=sys.stderr, flush=True)

    def _spawn(self, args: list[str], **kwargs) -> subprocess.Popen:
        self.log(f"spawning: {' '.join(args)}")
        proc = subprocess.Popen(args, **kwargs)
        self.processes.append(proc)
        return proc

    def start_echo_server(self, port: int, payload_size: int) -> EchoServer:
        """Create, start, and track an inline echo server thread."""
        srv = EchoServer(port, payload_size)
        srv.start()
        self.echo_servers.append(srv)
        if not wait_for_port("127.0.0.1", port):
            raise RuntimeError(
                f"Echo server on port {port} did not become ready in time"
            )
        return srv

    def spawn_chimera(
        self, config_path: str, chimera_bin: str
    ) -> subprocess.Popen:
        """Start chimera server with the given config file."""
        stderr = None if self.verbose else subprocess.DEVNULL
        stdout = None if self.verbose else subprocess.DEVNULL
        return self._spawn(
            [chimera_bin, "--config", config_path],
            stdout=stdout,
            stderr=stderr,
        )

    def spawn_xray(self, config_path: str, xray_bin: str) -> subprocess.Popen:
        """Start xray with the given config file."""
        stderr = None if self.verbose else subprocess.DEVNULL
        stdout = None if self.verbose else subprocess.DEVNULL
        return self._spawn(
            [xray_bin, "-c", config_path],
            stdout=stdout,
            stderr=stderr,
        )

    def cleanup(self) -> None:
        """Kill all managed subprocesses, stop echo servers, remove temp dirs."""
        # Stop echo server threads first
        for es in self.echo_servers:
            es.stop()
        self.echo_servers.clear()

        # Terminate subprocesses
        for proc in self.processes:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        for proc in self.processes:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except OSError:
                        pass
        # Remove temp directories
        for td in self.temp_dirs:
            shutil.rmtree(td, ignore_errors=True)
        self.processes.clear()
        self.temp_dirs.clear()

    def mktemp(self, prefix: str = "chimera-bench-") -> str:
        """Create a managed temporary directory."""
        td = tempfile.mkdtemp(prefix=prefix)
        self.temp_dirs.append(td)
        return td


# ─── Baseline comparison ────────────────────────────────────────────────────────


def load_baseline(path: str) -> dict:
    """Load and return the baseline throughput JSON file."""
    with open(path) as f:
        return json.load(f)


def compare_baseline(results: list[dict], baseline_path: str) -> int:
    """Compare current results against a stored baseline.

    For each result where upload_mbps dropped more than 10 % relative to the
    baseline entry (matched by *label*), a warning is printed to stderr.

    Adds ``regression_pct`` and ``baseline_upload_mbps`` fields to each
    matched result dict.

    Returns the number of regressions (results >10 % below baseline).
    """
    baseline = load_baseline(baseline_path)
    baseline_by_label = {r["label"]: r for r in baseline["results"]}
    regression_count = 0

    for result in results:
        label = result["label"]
        bl = baseline_by_label.get(label)
        if bl is None:
            print(
                f"[baseline] No baseline entry for '{label}', skipping",
                file=sys.stderr,
            )
            continue

        bl_upload = bl["upload_mbps"]
        current_upload = result["upload_mbps"]
        if bl_upload > 0:
            regression_pct = (current_upload - bl_upload) / bl_upload * 100
        else:
            regression_pct = 0.0

        result["regression_pct"] = round(regression_pct, 2)
        result["baseline_upload_mbps"] = bl_upload

        if regression_pct < -10:
            regression_count += 1
            print(
                f"⚠️  REGRESSION: {label} upload dropped {abs(regression_pct):.1f}% "
                f"({current_upload:.1f} vs baseline {bl_upload:.1f} Mbps)",
                file=sys.stderr,
            )

    if regression_count > 0:
        print(
            f"⚠️  {regression_count} regression(s) detected "
            "(>10% drop in upload throughput)",
            file=sys.stderr,
        )
    else:
        print(
            "✓ All results within baseline range (threshold: 10%)",
            file=sys.stderr,
        )

    return regression_count


# ─── Statistics helpers ─────────────────────────────────────────────────────────


def compute_stats(values: list[float], runs: int):
    """Compute median and stdev for a list of throughput measurements."""
    if runs < 1 or not values:
        return 0.0, 0.0
    if runs == 1:
        return values[0], 0.0
    median = statistics.median(values)
    stdev = statistics.stdev(values)
    return median, stdev


# ─── Tier 1: SOCKS direct test ──────────────────────────────────────────────────


def run_socks_test(
    pm: ProcManager,
    payload_size: int,
    runs: int,
    chimera_bin: str,
) -> dict:
    """Run the Tier 1 SOCKS-direct throughput test.

    Architecture:
      echo_server <--direct-- chimera(socks-in) <--socks5-- client
    """
    pm.log("=== Starting SOCKS direct test ===")

    echo_port = alloc_port()
    socks_port = alloc_port()
    pm.log(f"echo_port={echo_port}  socks_port={socks_port}")

    # 1. Start echo server (inline thread)
    pm.start_echo_server(echo_port, payload_size)

    # 2. Build chimera config from template, replacing port
    template = os.path.join(CONFIG_DIR, "socks-direct.json5")
    with open(template) as f:
        config_text = f.read()
    config_text = config_text.replace('"port": 0', f'"port": {socks_port}')

    temp_dir = pm.mktemp()
    config_path = os.path.join(temp_dir, "config.json5")
    with open(config_path, "w") as f:
        f.write(config_text)

    # 3. Start chimera
    pm.spawn_chimera(config_path, chimera_bin)

    # 4. Wait for SOCKS port
    if not wait_for_port("127.0.0.1", socks_port):
        raise RuntimeError(f"Chimera SOCKS port {socks_port} did not become ready")

    # 5. Run throughput iterations
    upload_results: list[float] = []
    download_results: list[float] = []

    for i in range(runs):
        pm.log(f"  Run {i + 1}/{runs}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect(("127.0.0.1", socks_port))
            socks5_negotiate(sock)
            socks5_connect(sock, "127.0.0.1", echo_port)
            up, down = measure_throughput(sock, payload_size)
            upload_results.append(up)
            download_results.append(down)
            pm.log(f"    upload={up:.2f} Mbps  download={down:.2f} Mbps")
        finally:
            sock.close()

    up_median, up_stdev = compute_stats(upload_results, runs)
    down_median, down_stdev = compute_stats(download_results, runs)

    result = {
        "label": "socks-direct",
        "scenario": "tier1_socks_direct",
        "upload_mbps": round(up_median, 2),
        "download_mbps": round(down_median, 2),
        "upload_stdev_mbps": round(up_stdev, 2),
        "download_stdev_mbps": round(down_stdev, 2),
        "runs": runs,
        "total_bytes": payload_size,
        "engine": "chimera",
    }

    pm.log(f"SOCKS result: {json.dumps(result)}")
    return result


# ─── Tier 2: VLESS direct test ──────────────────────────────────────────────────


def run_vless_test(
    pm: ProcManager,
    payload_size: int,
    runs: int,
    chimera_bin: str,
    xray_bin: str,
):
    """Run the Tier 2 VLESS-direct throughput test.

    Architecture:
      echo_server <--direct-- chimera(vless-in) <--vless-- xray <--socks5-- client

    Returns None if xray binary is not found (graceful skip).
    """
    pm.log("=== Starting VLESS direct test ===")

    # Resolve xray binary
    xray_path: str | None = (
        shutil.which(xray_bin) if "/" not in xray_bin else (
            xray_bin if os.path.isfile(xray_bin) else None
        )
    )
    if xray_path is None:
        print(
            "VLESS skipped: xray not found",
            file=sys.stderr,
        )
        return None

    echo_port = alloc_port()
    vless_port = alloc_port()
    xray_socks_port = alloc_port()
    pm.log(
        f"echo_port={echo_port}  vless_port={vless_port}"
        f"  xray_socks_port={xray_socks_port}"
    )

    # 1. Start echo server (inline thread)
    pm.start_echo_server(echo_port, payload_size)

    # 2. Build chimera config from template, replacing port and UUID
    template = os.path.join(CONFIG_DIR, "vless-direct.json5")
    with open(template) as f:
        config_text = f.read()
    config_text = config_text.replace('"port": 0', f'"port": {vless_port}')
    config_text = config_text.replace("PLACEHOLDER_UUID", UUID)

    temp_dir = pm.mktemp()
    config_path = os.path.join(temp_dir, "config.json5")
    with open(config_path, "w") as f:
        f.write(config_text)

    # 3. Start chimera
    pm.spawn_chimera(config_path, chimera_bin)

    # 4. Wait for VLESS port (Chimera's VLESS inbound)
    if not wait_for_port("127.0.0.1", vless_port):
        raise RuntimeError(f"Chimera VLESS port {vless_port} did not become ready")

    # 5. Write xray client config on-the-fly
    xray_config = {
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "settings": {"auth": "noaccount"},
                "tag": "socks-in",
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": vless_port,
                            "users": [
                                {"id": UUID, "encryption": "none"}
                            ],
                        }
                    ],
                },
                "tag": "out",
            }
        ],
    }

    xray_config_path = os.path.join(temp_dir, "xray_config.json")
    with open(xray_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    # 6. Start xray
    pm.spawn_xray(xray_config_path, xray_path)

    # 7. Wait for xray SOCKS port
    if not wait_for_port("127.0.0.1", xray_socks_port):
        raise RuntimeError(
            f"xray SOCKS port {xray_socks_port} did not become ready"
        )

    # 8. Run throughput iterations (through xray's SOCKS port)
    upload_results: list[float] = []
    download_results: list[float] = []

    for i in range(runs):
        pm.log(f"  Run {i + 1}/{runs}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect(("127.0.0.1", xray_socks_port))
            socks5_negotiate(sock)
            socks5_connect(sock, "127.0.0.1", echo_port)
            up, down = measure_throughput(sock, payload_size)
            upload_results.append(up)
            download_results.append(down)
            pm.log(f"    upload={up:.2f} Mbps  download={down:.2f} Mbps")
        finally:
            sock.close()

    up_median, up_stdev = compute_stats(upload_results, runs)
    down_median, down_stdev = compute_stats(download_results, runs)

    result = {
        "label": "vless-direct",
        "scenario": "tier2_vless_direct",
        "upload_mbps": round(up_median, 2),
        "download_mbps": round(down_median, 2),
        "upload_stdev_mbps": round(up_stdev, 2),
        "download_stdev_mbps": round(down_stdev, 2),
        "runs": runs,
        "total_bytes": payload_size,
        "engine": "chimera",
    }

    pm.log(f"VLESS result: {json.dumps(result)}")
    return result


# ─── Main ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proxy throughput benchmark orchestrator for Chimera_Server",
    )
    parser.add_argument(
        "--only",
        choices=["socks", "vless", "all"],
        default="all",
        help="Which scenario to run (default: all)",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=32 * 1024 * 1024,
        help="Payload size in bytes (default: 32MB = 33554432)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of iterations per scenario (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write JSON-lines results to FILE",
        metavar="FILE",
    )
    parser.add_argument(
        "--chimera-bin",
        type=str,
        default="./target/release/chimera_server_app",
        help="Path to chimera_server_app binary (default: ./target/release/...)",
    )
    parser.add_argument(
        "--xray-bin",
        type=str,
        default="xray",
        help="Path to xray binary (default: xray; VLESS skipped if not found)",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Path to baseline-throughput.json for regression comparison",
        metavar="PATH",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug logs to stderr",
    )
    args = parser.parse_args()

    if args.runs < 1:
        print("Error: --runs must be >= 1", file=sys.stderr)
        sys.exit(1)

    if args.payload_size < 1:
        print("Error: --payload-size must be >= 1", file=sys.stderr)
        sys.exit(1)

    # Resolve chimera binary path
    chimera_bin = os.path.abspath(args.chimera_bin)
    if not os.path.isfile(chimera_bin):
        print(
            f"Error: chimera binary not found at '{chimera_bin}'",
            file=sys.stderr,
        )
        sys.exit(1)

    pm = ProcManager(verbose=args.verbose)
    results: list[dict] = []

    # Register cleanup for early exits (e.g. SIGINT, SIGTERM)
    def _signal_cleanup(signum, frame):
        pm.cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _signal_cleanup)
    signal.signal(signal.SIGTERM, _signal_cleanup)

    try:
        if args.only in ("socks", "all"):
            result = run_socks_test(
                pm, args.payload_size, args.runs, chimera_bin
            )
            results.append(result)

        if args.only in ("vless", "all"):
            result = run_vless_test(
                pm, args.payload_size, args.runs, chimera_bin, args.xray_bin
            )
            if result is not None:
                results.append(result)

    except Exception:
        pm.cleanup()
        raise

    pm.cleanup()

    # Baseline comparison (if requested)
    if args.baseline:
        if os.path.isfile(args.baseline):
            compare_baseline(results, args.baseline)
        else:
            print(
                f"[baseline] File '{args.baseline}' not found, skipping comparison",
                file=sys.stderr,
            )

    # Output JSON-lines
    output_lines = [json.dumps(r, ensure_ascii=False) for r in results]

    if args.output:
        with open(args.output, "w") as f:
            for line in output_lines:
                f.write(line + "\n")
        if args.verbose:
            print(
                f"Results written to {args.output}",
                file=sys.stderr,
            )
    else:
        for line in output_lines:
            print(line)


if __name__ == "__main__":
    main()
