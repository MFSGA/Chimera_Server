#!/usr/bin/env python3
"""Hysteria2 congestion benchmark under controlled RTT/loss.

Runs Xray as the Hysteria2 client and Chimera as the server.  The QUIC path is
isolated with a Linux network namespace + veth pair so netem only affects the
Hysteria2 transport, not the local SOCKS client or echo target.

Loss is applied symmetrically per direction.  RTT is split evenly across the
host and namespace egress qdiscs.
"""

from __future__ import annotations

import argparse
import hashlib
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
from pathlib import Path

AUTH = "chimera-hysteria2-benchmark"
SYNC_BYTE = b"\xAC"
DOWNLOAD_GO = b"\xAD"
DEFAULT_MODES = ("brutal", "bbr", "reno")
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


def log(message: str, verbose: bool) -> None:
    if verbose:
        print(f"[hy2-bench] {message}", file=sys.stderr, flush=True)


def run_checked(args: list[str], *, verbose: bool = False) -> subprocess.CompletedProcess[str]:
    log("run: " + " ".join(args), verbose)
    return subprocess.run(args, check=True, text=True, capture_output=not verbose)


def parse_csv_floats(raw: str, *, name: str, minimum: float, maximum: float) -> list[float]:
    values: list[float] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            value = float(item)
        except ValueError as exc:
            raise ValueError(f"{name} contains non-number {item!r}") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} value {value} must be between {minimum} and {maximum}")
        values.append(value)
    if not values:
        raise ValueError(f"{name} must contain at least one value")
    return values


def parse_modes(raw: str) -> list[str]:
    modes: list[str] = []
    for item in raw.split(","):
        mode = item.strip().lower()
        if not mode:
            continue
        if mode not in DEFAULT_MODES:
            raise ValueError(f"unsupported congestion mode {mode!r}; expected brutal,bbr,reno")
        if mode not in modes:
            modes.append(mode)
    if not modes:
        raise ValueError("--modes must contain at least one congestion mode")
    return modes


def fmt_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:g}"


def alloc_host_port() -> int:
    for _ in range(100):
        port = random.randint(30000, 45000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("failed to allocate host TCP port")


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {host}:{port}")


def socks5_connect(proxy: tuple[str, int], target: tuple[str, int], timeout: float) -> socket.socket:
    sock = socket.create_connection(proxy, timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    response = sock.recv(2)
    if response != b"\x05\x00":
        sock.close()
        raise RuntimeError(f"SOCKS5 negotiation failed: {response!r}")

    host, port = target
    ip = socket.inet_aton(host)
    request = b"\x05\x01\x00\x01" + ip + port.to_bytes(2, "big")
    sock.sendall(request)
    response = sock.recv(10)
    if len(response) < 2 or response[:2] != b"\x05\x00":
        sock.close()
        raise RuntimeError(f"SOCKS5 CONNECT failed: {response!r}")
    return sock


def measure_throughput(sock: socket.socket, payload_size: int) -> tuple[float, float]:
    payload = b"P" * payload_size

    upload_start = time.perf_counter()
    sock.sendall(payload)

    sync = sock.recv(1)
    if sync != SYNC_BYTE:
        raise RuntimeError(f"missing benchmark sync byte: {sync!r}")
    upload_end = time.perf_counter()

    # Keep the echo payload behind an explicit GO byte so no response bytes can
    # be buffered before the download timer starts. Starting before sendall()
    # makes the directional measurements symmetric: upload includes the sync
    # response path, download includes the GO request path.
    download_start = time.perf_counter()
    sock.sendall(DOWNLOAD_GO)
    received = 0
    while received < payload_size:
        chunk = sock.recv(min(65536, payload_size - received))
        if not chunk:
            raise RuntimeError(f"connection closed after {received}/{payload_size} echoed bytes")
        received += len(chunk)
    download_end = time.perf_counter()

    upload_seconds = max(upload_end - upload_start, 1e-9)
    download_seconds = max(download_end - download_start, 1e-9)
    bits = payload_size * 8
    return bits / upload_seconds / 1_000_000, bits / download_seconds / 1_000_000


def run_echo_server(bind: str, port: int, payload_size: int, connections: int) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, port))
    listener.listen(16)
    listener.settimeout(1.0)

    handled = 0
    deadline = time.monotonic() + 600
    while handled < connections:
        if time.monotonic() > deadline:
            return 2
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(120)
            data = bytearray()
            while len(data) < payload_size:
                chunk = conn.recv(min(65536, payload_size - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != payload_size:
                return 3
            conn.sendall(SYNC_BYTE)
            if conn.recv(1) != DOWNLOAD_GO:
                return 4
            conn.sendall(data)
        handled += 1
    return 0


def quic_params(mode: str, bandwidth_mbps: int) -> dict:
    params: dict[str, object] = {
        "congestion": mode,
        "initStreamReceiveWindow": 16 * 1024 * 1024,
        "maxStreamReceiveWindow": 32 * 1024 * 1024,
        "initConnectionReceiveWindow": 32 * 1024 * 1024,
        "maxConnectionReceiveWindow": 64 * 1024 * 1024,
    }
    if mode == "brutal":
        params["brutalUp"] = f"{bandwidth_mbps} mbps"
        params["brutalDown"] = f"{bandwidth_mbps} mbps"
    return params


def build_chimera_config(
    *, server_ip: str, server_port: int, cert_path: str, key_path: str, mode: str, bandwidth_mbps: int
) -> dict:
    return {
        "inbounds": [
            {
                "listen": server_ip,
                "port": server_port,
                "protocol": "hysteria",
                "tag": "hy2-bench",
                "settings": {"version": 2, "clients": [{"auth": AUTH}]},
                "streamSettings": {
                    "network": "quic",
                    "security": "tls",
                    "hysteriaSettings": {
                        "version": 2,
                        "up": f"{bandwidth_mbps} mbps",
                        "down": f"{bandwidth_mbps} mbps",
                    },
                    "finalmask": {"quicParams": quic_params(mode, bandwidth_mbps)},
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "certificates": [
                            {"certificateFile": cert_path, "keyFile": key_path}
                        ],
                    },
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def build_xray_config(
    *, server_ip: str, server_port: int, socks_port: int, cert_sha256: str, mode: str, bandwidth_mbps: int
) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [
            {
                "tag": "to-chimera",
                "protocol": "hysteria",
                "settings": {"version": 2, "address": server_ip, "port": server_port},
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": cert_sha256,
                        "alpn": ["h3"],
                    },
                    "hysteriaSettings": {"version": 2, "auth": AUTH},
                    "finalmask": {"quicParams": quic_params(mode, bandwidth_mbps)},
                },
            }
        ],
    }


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def generate_certificate(work_dir: Path, verbose: bool) -> tuple[Path, Path, str]:
    cert = work_dir / "cert.pem"
    key = work_dir / "key.pem"
    run_checked(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        verbose=verbose,
    )
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return cert, key, hashlib.sha256(der).hexdigest()


class ManagedProcess:
    def __init__(self, popen: subprocess.Popen[bytes], actual_pid: int, root: bool):
        self.popen = popen
        self.actual_pid = actual_pid
        self.root = root

    def assert_running(self, name: str) -> None:
        if self.popen.poll() is not None:
            raise RuntimeError(f"{name} exited early with status {self.popen.returncode}")

    def stop(self) -> None:
        if self.popen.poll() is not None:
            return
        try:
            if self.root:
                subprocess.run(["sudo", "-n", "kill", "-TERM", str(self.actual_pid)], check=False)
            else:
                os.kill(self.actual_pid, signal.SIGTERM)
            self.popen.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if self.popen.poll() is None:
                if self.root:
                    subprocess.run(["sudo", "-n", "kill", "-KILL", str(self.actual_pid)], check=False)
                else:
                    self.popen.kill()
                try:
                    self.popen.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass


def read_proc_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    return int(fields[13]) + int(fields[14])


def read_rss_kib(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


class MetricsSampler:
    def __init__(self, pid: int):
        self.pid = pid
        self.start_ticks = read_proc_ticks(pid)
        self.max_rss_kib = read_rss_kib(pid)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(0.05):
            try:
                self.max_rss_kib = max(self.max_rss_kib, read_rss_kib(self.pid))
            except (FileNotFoundError, ProcessLookupError):
                return

    def start(self) -> None:
        self._thread.start()

    def finish(self) -> tuple[float, int]:
        self._stop.set()
        self._thread.join(timeout=1)
        try:
            end_ticks = read_proc_ticks(self.pid)
            self.max_rss_kib = max(self.max_rss_kib, read_rss_kib(self.pid))
        except (FileNotFoundError, ProcessLookupError):
            end_ticks = self.start_ticks
        return max(0, end_ticks - self.start_ticks) / CLOCK_TICKS, self.max_rss_kib


class NetemNamespace:
    def __init__(self, rtt_ms: float, loss_pct: float, verbose: bool):
        suffix = f"{os.getpid()}{random.randint(100, 999)}"
        self.name = f"hy2b-{suffix}"
        self.host_if = f"hyh{suffix}"[:15]
        self.ns_if = "hyns0"
        subnet = random.randint(120, 220)
        self.host_ip = f"10.203.{subnet}.1"
        self.server_ip = f"10.203.{subnet}.2"
        self.rtt_ms = rtt_ms
        self.loss_pct = loss_pct
        self.verbose = verbose
        self.created = False

    def _sudo(self, *args: str) -> None:
        run_checked(["sudo", "-n", *args], verbose=self.verbose)

    def setup(self) -> None:
        self._sudo("ip", "netns", "add", self.name)
        self.created = True
        self._sudo("ip", "link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if)
        self._sudo("ip", "link", "set", self.ns_if, "netns", self.name)
        self._sudo("ip", "addr", "add", f"{self.host_ip}/24", "dev", self.host_if)
        self._sudo("ip", "link", "set", self.host_if, "up")
        self._sudo("ip", "netns", "exec", self.name, "ip", "link", "set", "lo", "up")
        self._sudo("ip", "netns", "exec", self.name, "ip", "addr", "add", f"{self.server_ip}/24", "dev", self.ns_if)
        self._sudo("ip", "netns", "exec", self.name, "ip", "link", "set", self.ns_if, "up")

        delay_ms = self.rtt_ms / 2.0
        if delay_ms > 0 or self.loss_pct > 0:
            netem = ["netem", "limit", "100000"]
            if delay_ms > 0:
                netem += ["delay", f"{delay_ms:g}ms"]
            if self.loss_pct > 0:
                netem += ["loss", f"{self.loss_pct:g}%"]
            self._sudo("tc", "qdisc", "replace", "dev", self.host_if, "root", *netem)
            self._sudo("ip", "netns", "exec", self.name, "tc", "qdisc", "replace", "dev", self.ns_if, "root", *netem)

    def spawn(self, command: list[str], *, pid_file: Path | None = None, quiet: bool = True) -> ManagedProcess:
        if pid_file is None:
            pid_file = Path(tempfile.mkstemp(prefix="hy2bench-pid-")[1])
            pid_file.unlink(missing_ok=True)
        shell_command = 'echo $$ > "$1"; shift; exec "$@"'
        args = [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            self.name,
            "sh",
            "-c",
            shell_command,
            "sh",
            str(pid_file),
            *command,
        ]
        stdout = subprocess.DEVNULL if quiet else None
        stderr = subprocess.DEVNULL if quiet else None
        popen = subprocess.Popen(args, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if pid_file.exists() and pid_file.read_text().strip():
                return ManagedProcess(popen, int(pid_file.read_text().strip()), root=True)
            if popen.poll() is not None:
                raise RuntimeError(f"network namespace process exited early: {command[0]}")
            time.sleep(0.02)
        popen.terminate()
        raise RuntimeError(f"timed out obtaining pid for {command[0]}")

    def cleanup(self) -> None:
        if self.created:
            subprocess.run(["sudo", "-n", "ip", "netns", "del", self.name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.created = False


def spawn_host(command: list[str], *, quiet: bool) -> ManagedProcess:
    stdout = subprocess.DEVNULL if quiet else None
    stderr = subprocess.DEVNULL if quiet else None
    popen = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    return ManagedProcess(popen, popen.pid, root=False)


def median_stdev(values: list[float]) -> tuple[float, float]:
    if len(values) == 1:
        return values[0], 0.0
    return statistics.median(values), statistics.stdev(values)


def run_case(
    *,
    chimera_bin: str,
    xray_bin: str,
    mode: str,
    rtt_ms: float,
    loss_pct: float,
    payload_size: int,
    runs: int,
    bandwidth_mbps: int,
    verbose: bool,
) -> dict:
    case_start = time.perf_counter()
    ns = NetemNamespace(rtt_ms, loss_pct, verbose)
    work_dir = Path(tempfile.mkdtemp(prefix=f"hy2bench-{mode}-"))
    processes: list[ManagedProcess] = []

    try:
        ns.setup()
        cert, key, cert_sha256 = generate_certificate(work_dir, verbose)
        server_port = 24443
        echo_port = 29000
        socks_port = alloc_host_port()

        chimera_config = build_chimera_config(
            server_ip=ns.server_ip,
            server_port=server_port,
            cert_path=str(cert),
            key_path=str(key),
            mode=mode,
            bandwidth_mbps=bandwidth_mbps,
        )
        xray_config = build_xray_config(
            server_ip=ns.server_ip,
            server_port=server_port,
            socks_port=socks_port,
            cert_sha256=cert_sha256,
            mode=mode,
            bandwidth_mbps=bandwidth_mbps,
        )
        chimera_config_path = work_dir / "chimera.json"
        xray_config_path = work_dir / "xray.json"
        write_json(chimera_config_path, chimera_config)
        write_json(xray_config_path, xray_config)

        echo = ns.spawn(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--echo-server",
                "--echo-port",
                str(echo_port),
                "--payload-size",
                str(payload_size),
                "--echo-connections",
                str(runs),
            ],
            pid_file=work_dir / "echo.pid",
            quiet=not verbose,
        )
        processes.append(echo)
        time.sleep(0.1)
        echo.assert_running("echo server")

        chimera = ns.spawn(
            [chimera_bin, "--config", str(chimera_config_path)],
            pid_file=work_dir / "chimera.pid",
            quiet=not verbose,
        )
        processes.append(chimera)
        time.sleep(0.4)
        chimera.assert_running("Chimera")

        xray = spawn_host([xray_bin, "-c", str(xray_config_path)], quiet=not verbose)
        processes.append(xray)
        wait_for_port("127.0.0.1", socks_port, timeout=10)
        xray.assert_running("Xray")

        chimera_metrics = MetricsSampler(chimera.actual_pid)
        xray_metrics = MetricsSampler(xray.actual_pid)
        chimera_metrics.start()
        xray_metrics.start()

        upload_values: list[float] = []
        download_values: list[float] = []
        timeout = max(30.0, 10.0 + rtt_ms / 1000.0 * 100)
        measure_start = time.perf_counter()
        for run_index in range(runs):
            log(
                f"mode={mode} rtt={rtt_ms:g}ms loss={loss_pct:g}% run={run_index + 1}/{runs}",
                verbose,
            )
            sock = socks5_connect(
                ("127.0.0.1", socks_port), ("127.0.0.1", echo_port), timeout
            )
            try:
                upload, download = measure_throughput(sock, payload_size)
            finally:
                sock.close()
            upload_values.append(upload)
            download_values.append(download)
        measure_seconds = time.perf_counter() - measure_start

        chimera_cpu_seconds, chimera_rss = chimera_metrics.finish()
        xray_cpu_seconds, xray_rss = xray_metrics.finish()
        upload_median, upload_stdev = median_stdev(upload_values)
        download_median, download_stdev = median_stdev(download_values)

        return {
            "label": f"hy2-{mode}-rtt{fmt_number(rtt_ms)}-loss{fmt_number(loss_pct)}",
            "scenario": "hysteria2_netem",
            "engine": "chimera-server+xray-client",
            "mode": mode,
            "rtt_ms": rtt_ms,
            "one_way_delay_ms": rtt_ms / 2.0,
            "loss_pct_per_direction": loss_pct,
            "bandwidth_mbps": bandwidth_mbps,
            "payload_bytes": payload_size,
            "runs": runs,
            "upload_mbps": round(upload_median, 2),
            "download_mbps": round(download_median, 2),
            "upload_stdev_mbps": round(upload_stdev, 2),
            "download_stdev_mbps": round(download_stdev, 2),
            "chimera_cpu_seconds": round(chimera_cpu_seconds, 4),
            "chimera_cpu_pct": round(chimera_cpu_seconds / max(measure_seconds, 1e-9) * 100, 2),
            "chimera_max_rss_kib": chimera_rss,
            "xray_cpu_seconds": round(xray_cpu_seconds, 4),
            "xray_cpu_pct": round(xray_cpu_seconds / max(measure_seconds, 1e-9) * 100, 2),
            "xray_max_rss_kib": xray_rss,
            "measurement_seconds": round(measure_seconds, 4),
            "case_seconds": round(time.perf_counter() - case_start, 4),
        }
    finally:
        for proc in reversed(processes):
            proc.stop()
        ns.cleanup()
        shutil.rmtree(work_dir, ignore_errors=True)


def write_summary(path: Path, results: list[dict]) -> None:
    lines = [
        "# Hysteria2 netem benchmark",
        "",
        "Loss is configured independently on both veth egress directions. RTT is split evenly across the two directions.",
        "",
        "| Mode | RTT ms | Loss %/dir | Upload Mbps | Download Mbps | Chimera CPU % | Chimera RSS MiB |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        lines.append(
            f"| {result['mode']} | {result['rtt_ms']:g} | {result['loss_pct_per_direction']:g} | "
            f"{result['upload_mbps']:.2f} | {result['download_mbps']:.2f} | "
            f"{result['chimera_cpu_pct']:.2f} | {result['chimera_max_rss_kib'] / 1024:.2f} |"
        )
    path.write_text("\n".join(lines) + "\n")


def self_test() -> int:
    assert parse_csv_floats("1,20,50", name="rtt", minimum=0, maximum=10000) == [1, 20, 50]
    assert parse_csv_floats("0,0.5,5", name="loss", minimum=0, maximum=100) == [0, 0.5, 5]
    assert parse_modes("brutal,bbr,reno,brutal") == ["brutal", "bbr", "reno"]
    params = quic_params("brutal", 200)
    assert params["brutalUp"] == "200 mbps"
    assert "brutalUp" not in quic_params("bbr", 200)
    chimera = build_chimera_config(
        server_ip="10.203.150.2",
        server_port=24443,
        cert_path="/tmp/cert.pem",
        key_path="/tmp/key.pem",
        mode="reno",
        bandwidth_mbps=200,
    )
    assert chimera["inbounds"][0]["streamSettings"]["finalmask"]["quicParams"]["congestion"] == "reno"
    xray = build_xray_config(
        server_ip="10.203.150.2",
        server_port=24443,
        socks_port=30001,
        cert_sha256="00" * 32,
        mode="brutal",
        bandwidth_mbps=200,
    )
    assert xray["outbounds"][0]["streamSettings"]["network"] == "hysteria"
    print("hysteria2_netem self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chimera-bin", default="./target/release/chimera_server_app")
    parser.add_argument("--xray-bin", default="./xray/xray")
    parser.add_argument("--rtts", default="1,20,50,100,200", help="comma-separated target RTTs in ms")
    parser.add_argument("--losses", default="0,0.5,1,3,5", help="comma-separated per-direction loss percentages")
    parser.add_argument("--modes", default="brutal,bbr,reno")
    parser.add_argument("--bandwidth-mbps", type=int, default=200)
    parser.add_argument("--payload-size", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--output", default="target/hysteria2-netem.jsonl")
    parser.add_argument("--summary", default="target/hysteria2-netem.md")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--echo-server", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--echo-port", type=int, default=29000, help=argparse.SUPPRESS)
    parser.add_argument("--echo-connections", type=int, default=1, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.echo_server:
        return run_echo_server("127.0.0.1", args.echo_port, args.payload_size, args.echo_connections)
    if args.self_test:
        return self_test()
    if sys.platform != "linux":
        parser.error("the netem benchmark requires Linux network namespaces")
    if args.payload_size < 1 or args.runs < 1 or args.bandwidth_mbps < 1:
        parser.error("payload size, runs and bandwidth must all be >= 1")

    try:
        rtts = parse_csv_floats(args.rtts, name="--rtts", minimum=0, maximum=10000)
        losses = parse_csv_floats(args.losses, name="--losses", minimum=0, maximum=100)
        modes = parse_modes(args.modes)
    except ValueError as exc:
        parser.error(str(exc))

    chimera_bin = str(Path(args.chimera_bin).resolve())
    xray_bin = str(Path(args.xray_bin).resolve())
    for label, binary in (("Chimera", chimera_bin), ("Xray", xray_bin)):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            parser.error(f"{label} binary is not executable: {binary}")
    for command in ("ip", "tc", "openssl", "sudo"):
        if shutil.which(command) is None:
            parser.error(f"required command not found: {command}")
    run_checked(["sudo", "-n", "true"], verbose=args.verbose)

    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    summary_path.unlink(missing_ok=True)

    results: list[dict] = []
    try:
        for mode in modes:
            for rtt_ms in rtts:
                for loss_pct in losses:
                    result = run_case(
                        chimera_bin=chimera_bin,
                        xray_bin=xray_bin,
                        mode=mode,
                        rtt_ms=rtt_ms,
                        loss_pct=loss_pct,
                        payload_size=args.payload_size,
                        runs=args.runs,
                        bandwidth_mbps=args.bandwidth_mbps,
                        verbose=args.verbose,
                    )
                    results.append(result)
                    print(json.dumps(result), flush=True)
                    with output_path.open("a") as output:
                        output.write(json.dumps(result) + "\n")
                    write_summary(summary_path, results)
    except KeyboardInterrupt:
        return 130

    write_summary(summary_path, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
