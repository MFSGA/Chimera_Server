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

Completed TCP-forward logs include three structured relay-attribution fields:

- `relay_backend`: the configured backend (`copy`, `handoff`, `splice`, `splice-downlink`, or `auto`);
- `relay_path`: the path that actually carried the steady-state connection (`userspace-copy`, `splice`, or `splice-downlink`);
- `relay_fallback`: `none` when the configured fast path was used, otherwise the reason it continued with userspace copy.

Current fallback values are:

- `direct-not-reached`: the connection completed before both streams reached the raw Direct barrier;
- `auto-connection-limit`: `auto` exceeded `CHIMERA_TCP_AUTO_MAX_CONNECTIONS` or the limit was set to zero;
- `missing-left-tcp-fd`, `missing-right-tcp-fd`, or `missing-tcp-fds`: the stream wrappers could not expose the required raw TCP descriptors;
- `splice-initialization`: pipe or splice-direction initialization failed and the connection safely continued with userspace copy.

These fields make `auto` suitable for controlled production observation: operators can aggregate actual splice hit rate and fallback causes instead of assuming the configured backend was used.

External-process E2E suites should be run with one test thread:

```bash
cargo test -p chimera_server_app \
  --test chimera_client_reality_vision_e2e \
  -- --ignored --test-threads=1
```

This prevents multiple test runtimes from racing while starting Chimera Client subprocesses.

## Duration-based soak and process leak monitoring

The generator can continue measured runs for a minimum wall-clock duration while preserving the existing `--runs` contract. Both conditions must be satisfied before it stops.

Use `--monitor-pid` to sample a long-running target or proxy process after every measured run. The final summary records start/end/peak fd count, RSS, HWM, and thread count without retaining every sample in memory. Use `--emit-every-runs` to keep long-run JSON output bounded; the first and final measured runs are always emitted.

Example one-hour REALITY + Vision soak:

```bash
server_pid=$(pgrep -n chimera_server_app)

bench/chimera_perf/target/release/generator \
  --target 127.0.0.1:52080 \
  --socks5 127.0.0.1:52101 \
  --inner-tls \
  --tcp-nodelay \
  --full-verify \
  --label reality-vision-handoff-soak-1h \
  --upload-bytes 67108864 \
  --download-bytes 67108864 \
  --concurrency 16 \
  --warmup 3 \
  --runs 1 \
  --duration-secs 3600 \
  --monitor-pid "$server_pid" \
  --cooldown-secs 10 \
  --max-fd-delta 0 \
  --max-rss-delta-kib 65536 \
  --emit-every-runs 100 \
  --output bench/results/reality-vision-handoff-soak-1h.jsonl
```

For a 24-hour run, change `--duration-secs` to `86400`. The summary fields most relevant to leak detection are:

- `monitored_process.fd_delta`;
- `monitored_process.vm_rss_delta_kib`;
- `monitored_process.max_fd_count`;
- `monitored_process.max_vm_rss_kib` and `max_vm_hwm_kib`;
- `monitored_process.max_threads`;
- `completed_connections` and total transferred bytes.

A non-zero final fd delta is not automatically a leak if connections remain active at sampling time. `--cooldown-secs` delays the final process snapshot after the measured duration so completed connections and allocator caches can settle. `--max-fd-delta` and `--max-rss-delta-kib` make the run fail after emitting its summary when the configured growth gate is exceeded.

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

## TCP pacing probe

`tcp_pacing_probe` is a Linux-only loopback sender/sink benchmark for TCP Brutal2 pacing design. It compares the same payload under two send backends (`send` and `splice`) and three pacing modes:

- `unpaced`: no rate limiting;
- `kernel`: set `SO_MAX_PACING_RATE` on the sending TCP socket;
- `userspace`: sleep after each write chunk to follow the same target byte rate.

Build and verify the socket option first:

```bash
cargo test --manifest-path bench/chimera_perf/Cargo.toml --bin tcp_pacing_probe
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml --bin tcp_pacing_probe
```

Compare both backends and all modes at the same target rate:

```bash
for backend in send splice; do
  for mode in unpaced kernel userspace; do
    taskset -c 0,1 \
      bench/chimera_perf/target/release/tcp_pacing_probe \
      --backend "$backend" \
      --mode "$mode" \
    --bytes 134217728 \
    --chunk-size 65536 \
    --rate-bytes-per-sec 52428800 \
      --warmup 1 \
      --runs 5
  done
done
```

The important output fields are `requested_rate_ratio`, `cpu_seconds_per_gib`, and total context switches. A successful `setsockopt` is not enough evidence that kernel pacing is effective: the observed/requested rate ratio should remain close to 1 on the target host and network path. The `splice` backend feeds a memfd through a pipe into the paced TCP socket so the paced output operation uses the same pipe-to-socket splice shape as the production relay.

To probe a dynamic rate publication, set `--second-rate-bytes-per-sec`; the probe switches once after half the bytes have been submitted and computes the expected aggregate rate from the two equal-byte phases:

```bash
bench/chimera_perf/target/release/tcp_pacing_probe \
  --backend splice \
  --mode kernel \
  --bytes 67108864 \
  --rate-bytes-per-sec 104857600 \
  --second-rate-bytes-per-sec 26214400 \
  --warmup 1 \
  --runs 5
```

Dynamic results also report `pacing_updates`. Treat them as a queue-response probe rather than a guarantee that an already-buffered TCP send queue changes rate instantaneously.

Use `strace` to attribute userspace pacing wakeups:

```bash
strace -f -c \
  -e trace=write,sendto,sendmsg,clock_nanosleep,nanosleep,futex,poll,ppoll,epoll_wait,setsockopt,getsockopt \
  bench/chimera_perf/target/release/tcp_pacing_probe \
  --backend splice \
  --mode kernel \
  --bytes 33554432 \
  --chunk-size 65536 \
  --rate-bytes-per-sec 52428800 \
  --warmup 0 \
  --runs 1
```

Run the same command with `--mode userspace`. This probe is benchmark-only; production TCP Brutal2 should not adopt kernel pacing until the target rate lifecycle and fallback semantics are defined through the normal config/runtime/handler layering.

### Pacing-rate publication policy

`tcp_pacing_policy_bench` isolates the userspace policy that decides when a high-frequency Brutal2 rate estimate should be published to `SO_MAX_PACING_RATE`. It has two deterministic trace modes: `synthetic` contains 10 kHz estimator samples with jitter/ramp noise and large bandwidth steps, while `brutal-loss` reproduces the current Brutal 5-second ACK/loss window and its `tx_bps / ack_rate` compensation (including the 50-sample warmup and 0.8 minimum ACK-rate clamp). Sweep minimum update intervals and normal rate-delta hysteresis without involving TCP queue behavior:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin tcp_pacing_policy_bench

bench/chimera_perf/target/release/tcp_pacing_policy_bench \
  --trace synthetic \
  --sample-interval-us 100 \
  --samples 400000 \
  --min-update-ms 5,10,20 \
  --delta-percent 1,5 \
  --emergency-delta-percent 25 \
  --cpu-repetitions 100
```

The important fields are `publications_per_second`, mean/p95/peak absolute tracking error, `target_rate_min`/`target_rate_max`, and `cpu_nanoseconds_per_sample`. A minimum update interval by itself can leave a stale pacing rate in place across a sharp bandwidth step. `--emergency-delta-percent` models an immediate publication path for large relative changes so normal jitter can remain rate-limited without delaying a major correction.

To test the publication rule against the current Brutal loss-compensation behavior instead of arbitrary estimator noise, rerun with `--trace brutal-loss`. That mode deliberately keeps the configured base rate fixed and varies deterministic packet loss in phases; the resulting target changes only as the same 5-second ACK/loss accounting used by the production Brutal controller evolves. It is still a deterministic model rather than a captured production trace, but it is suitable for checking whether timer debounce or rate-delta hysteresis actually matters for the current algorithm before wiring a TCP Brutal2 publisher into the data path.

### Brutal ACK accounting microbenchmark

`brutal_ack_rate_bench` isolates the current per-ACK loss-window accounting. It reports both the floating-point ACK-rate calculation alone and a full 10 kHz `record()` model that includes timestamp-to-second conversion, slot lookup, rolling totals, and ACK-rate refresh:

```bash
cargo run --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin brutal_ack_rate_bench
```

The benchmark intentionally includes a rejected optimization: skipping ACK-rate division while the rolling loss count is zero helps a pristine window but regresses the path once a loss remains in the five-second window. The `cached-second-record` comparison instead caches the active second and slot, avoiding repeated duration-to-seconds conversion and modulo work for events in the same second while preserving the slow path for rollovers and reordered timestamps. Use the latter comparison when evaluating changes to `BrutalState::record`.

The final section models Quinn's ACK callback batching contract: each acknowledged packet reaches `Controller::on_ack`, followed by one `Controller::on_end_acks` for the batch. `per-packet-record` recomputes Brutal accounting and the derived congestion window after every acknowledged packet, while `batched-record` pays a per-packet pending-counter update and publishes the same final ACK rate and window once per ACK batch. Sweep batch sizes when evaluating whether moving work to `on_end_acks` is worthwhile; batch size 1 is the regression guard for paths that receive mostly singleton ACKs.

## Required experiment discipline

- Build every compared binary in release mode using the same toolchain.
- Pin processes and IRQs consistently when running formal tests.
- Run raw TCP, reference Xray, and each Chimera candidate in randomized order.
- Keep payload, concurrency, network conditions, CPU governor, and socket settings identical.
- Do not accept a throughput result unless correctness runs pass first.
- Record at least three warmups and ten measured runs.
- Treat coefficient of variation above 3% as an unstable environment, not as proof of a performance change.

## UDP syscall batching probe

`udp_probe` is a Linux-only loopback UDP relay microbenchmark. It keeps the
source and sink on batched `sendmmsg`/`recvmmsg` in both variants so the
measured difference is concentrated in the relay itself. A shared in-process
progress window keeps both legs below the UDP socket queue limit so the probe
compares no-loss relay paths instead of buffer-overflow behavior:

- `single`: one `recv` plus one `send` syscall per relayed datagram;
- `mmsg`: `recvmmsg` plus `sendmmsg` with a configurable batch size.

Build and run correctness first:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml --bin udp_probe
bench/chimera_perf/target/release/udp_probe \
  --backend mmsg --packets 10000 --datagram-size 1200 \
  --batch-size 32 --inflight-window 64 --warmup 1 --runs 2 --verify
```

Then compare stable samples and syscall counts:

```bash
for backend in single mmsg; do
  taskset -c 0,1,2 \
    bench/chimera_perf/target/release/udp_probe \
    --backend "$backend" --packets 200000 --datagram-size 1200 \
    --batch-size 32 --inflight-window 64 --warmup 2 --runs 10

done

strace -f -c -e trace=recvfrom,sendto,recvmmsg,sendmmsg \
  bench/chimera_perf/target/release/udp_probe \
  --backend mmsg --packets 20000 --datagram-size 1200 \
  --batch-size 32 --inflight-window 64 --warmup 0 --runs 1
```

This probe is benchmark-only. Production UDP paths should adopt batching only
when packet-rate and CPU-per-million-packets measurements improve without
changing protocol/session semantics.
