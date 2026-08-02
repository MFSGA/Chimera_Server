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

## Required experiment discipline

- Build every compared binary in release mode using the same toolchain.
- Pin processes and IRQs consistently when running formal tests.
- Run raw TCP, reference Xray, and each Chimera candidate in randomized order.
- Keep payload, concurrency, network conditions, CPU governor, and socket settings identical.
- Do not accept a throughput result unless correctness runs pass first.
- Record at least three warmups and ten measured runs.
- Treat coefficient of variation above 3% as an unstable environment, not as proof of a performance change.
