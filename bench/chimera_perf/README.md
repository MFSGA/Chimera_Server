# Chimera native throughput harness

This standalone Rust crate measures streaming TCP proxy throughput without buffering the full payload in either endpoint.

## Protocol

1. The generator opens all connections and sends a fixed-size request header.
2. Connections synchronize on an upload barrier.
3. The generator streams a deterministic payload; the target counts it and optionally verifies every byte.
4. The target returns a fixed-size upload ACK.
5. Connections synchronize on a download barrier.
6. The generator sends `DOWNLOAD_READY`; only then does the target stream the response.
7. Each warmup and measured run is emitted as JSON, followed by a summary record.

The explicit download-ready barrier prevents response bytes coalesced with the ACK from escaping the download timer.

## Build and test

```bash
cargo test --manifest-path bench/chimera_perf/Cargo.toml
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml
```

## Raw TCP baseline

Terminal 1:

```bash
bench/chimera_perf/target/release/target \
  --listen 127.0.0.1:52080
```

Terminal 2:

```bash
bench/chimera_perf/target/release/generator \
  --target 127.0.0.1:52080 \
  --label raw-tcp \
  --upload-bytes 268435456 \
  --download-bytes 268435456 \
  --warmup 3 \
  --runs 10 \
  --output bench/results/raw-tcp.jsonl
```

## Through a SOCKS5 endpoint

Point `--socks5` at Chimera Client, Xray, or a Chimera SOCKS inbound while keeping `--target` set to the benchmark target:

```bash
bench/chimera_perf/target/release/generator \
  --target 127.0.0.1:52080 \
  --socks5 127.0.0.1:1080 \
  --label vless-reality-vision \
  --concurrency 64 \
  --upload-bytes 67108864 \
  --download-bytes 67108864 \
  --warmup 3 \
  --runs 10 \
  --output bench/results/vless-reality-vision-c64.jsonl
```

Use `--full-verify` for correctness runs. Throughput runs may omit it, but the result records always state whether full verification was enabled.

## REALITY + Vision Direct workload

A plaintext target exercises Vision `END`, not Vision `DIRECT`. Performance claims about the raw fast path therefore require a real inner TLS connection.

Start a local TLS decoy for the REALITY handshake:

```bash
bench/chimera_perf/target/release/decoy \
  --listen 127.0.0.1:52081 \
  --cert cert/cert.pem \
  --key cert/key.pem
```

Start the streaming payload target with TLS enabled:

```bash
bench/chimera_perf/target/release/target \
  --listen 127.0.0.1:52080 \
  --tls-cert cert/cert.pem \
  --tls-key cert/key.pem \
  --tcp-nodelay
```

Start Chimera Server and the bundled Xray client with:

```bash
CHIMERA_TCP_RELAY_BACKEND=auto \
CHIMERA_TCP_COPY_BUFFER_SIZE=32768 \
CHIMERA_TCP_SPLICE_PIPE_SIZE=65536 \
CHIMERA_TCP_AUTO_MAX_CONNECTIONS=8 \
  target/release/chimera_server_app \
  --config bench/configs/vless-reality-vision-perf-server.json

./xray run -c bench/configs/vless-reality-vision-perf-xray.json
```

Then run the generator through Xray SOCKS with a real inner TLS session:

```bash
bench/chimera_perf/target/release/generator \
  --target 127.0.0.1:52080 \
  --socks5 127.0.0.1:52101 \
  --inner-tls \
  --tcp-nodelay \
  --label reality-vision-auto-c1 \
  --upload-bytes 4294967296 \
  --download-bytes 4294967296 \
  --warmup 3 \
  --runs 10 \
  --max-cv 0.03 \
  --output bench/results/reality-vision-auto-c1.jsonl
```

The target and generator support `--worker-threads` so each process can be pinned to a controlled CPU set with `taskset`.

## Relay backends

`CHIMERA_TCP_RELAY_BACKEND` accepts:

- `handoff`: safe general-purpose path. It uses the handoff barrier, then continues with userspace copy.
- `auto`: Linux low-concurrency optimization. It uses downlink splice only while the number of active auto-relay connections is at or below `CHIMERA_TCP_AUTO_MAX_CONNECTIONS`; otherwise it falls back to handoff.
- `splice-downlink`: always splice target-to-client traffic while keeping client-to-target traffic in userspace. This mirrors the currently enabled direction in Xray.
- `splice`: experimental full bidirectional splice. It is retained for diagnostics and must not be selected as a production default without new data.
- `copy`: legacy direct Tokio bidirectional copy, retained only as a control. It does not provide the handoff flush barrier required by REALITY Vision.

`CHIMERA_TCP_COPY_BUFFER_SIZE` accepts 4096 through 1048576 bytes. The measured production default is 32768 bytes: it preserved the 64 KiB candidate's 64-connection throughput while reducing peak RSS, and it was dramatically faster than 8 KiB for a single long flow.

`CHIMERA_TCP_SPLICE_PIPE_SIZE` accepts 4096 through 1048576 bytes. The current measured default is 65536 bytes. Increasing it to 262144 bytes reduced throughput in the recorded high-concurrency experiment.

External-process E2E suites should be run with one test thread:

```bash
cargo test -p chimera_server_app \
  --test chimera_client_reality_vision_e2e \
  -- --ignored --test-threads=1
```

This prevents multiple test runtimes from racing while starting Chimera Client subprocesses.

## Relay microbenchmark and io_uring gate

`relay_probe` is a short-lived, single-direction TCP relay process. Unlike the full server, it exits after every experiment, so `strace -c` can collect reliable syscall counts even when host ptrace policy prevents attaching to an existing process.

Build it with:

```bash
cargo build --manifest-path bench/chimera_perf/Cargo.toml \
  --release --bin relay_probe
```

Compare the three candidates:

```bash
for backend in copy splice uring-splice; do
  taskset -c 0,2,4 \
    bench/chimera_perf/target/release/relay_probe \
    --backend "$backend" \
    --bytes 1073741824 \
    --chunk-size 65536 \
    --uring-batch-depth 64 \
    --warmup 2 \
    --runs 10
done
```

Run correctness with full payload verification:

```bash
bench/chimera_perf/target/release/relay_probe \
  --backend uring-splice \
  --bytes 67108864 \
  --chunk-size 65536 \
  --uring-batch-depth 64 \
  --warmup 1 \
  --runs 2 \
  --verify
```

Collect syscall counts:

```bash
strace -f -c \
  -e trace=read,write,recvfrom,sendto,splice,io_uring_setup,io_uring_enter,io_uring_register,futex \
  bench/chimera_perf/target/release/relay_probe \
  --backend uring-splice \
  --bytes 268435456 \
  --uring-batch-depth 64 \
  --warmup 0 \
  --runs 1
```

The io_uring implementation is intentionally benchmark-only. It must not be connected to the production relay until it beats ordinary splice in throughput and CPU/GiB with acceptable variance. The current measured candidate does not meet that gate.

## Required experiment discipline

- Build every compared binary in release mode using the same toolchain.
- Pin processes and IRQs consistently when running formal tests.
- Run raw TCP, reference Xray, and each Chimera candidate in randomized order.
- Keep payload, concurrency, network conditions, CPU governor, and socket settings identical.
- Do not accept a throughput result unless correctness runs pass first.
- Record at least three warmups and ten measured runs.
- Treat coefficient of variation above 3% as an unstable environment, not as proof of a performance change.
