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

`CHIMERA_TCP_COPY_BUFFER_SIZE` accepts 4096 through 1048576 bytes. The measured production default is 32768 bytes: it preserved the 64 KiB candidate's 64-connection throughput while reducing peak RSS, and it was dramatically faster than 8 KiB for a single long flow. On Linux `auto`, when this environment variable is unset, the successful `splice-downlink` path uses a measured 64 KiB buffer only for its remaining userspace uplink direction. Prelude, fallback, and all-userspace relays keep the 32 KiB default, and any explicit `CHIMERA_TCP_COPY_BUFFER_SIZE` value is preserved unchanged.

`CHIMERA_TCP_SPLICE_PIPE_SIZE` accepts 4096 through 1048576 bytes. The current measured default is 131072 bytes; the larger pipe reduces steady-state splice syscall frequency while bounding the two-direction pipe capacity to 256 KiB per full-splice relay. A September 2026 concurrency recheck below still favors 128 KiB over either 64 KiB or 256 KiB, so the default remains unchanged.

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

Compare the relay candidates. `tokio-copy` mirrors Chimera's single-direction
userspace fast path by using Tokio `BufReader + copy_buf`, so use it when
measuring copy-buffer size and syscall-granularity changes:

```bash
for backend in copy tokio-copy splice uring-splice; do
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

For copy-buffer experiments, sweep `--chunk-size` with `--backend tokio-copy`
and confirm the result with `strace -f -c` before changing
`CHIMERA_TCP_COPY_BUFFER_SIZE` defaults. A single-flow win is not sufficient to
override the recorded high-concurrency RSS/throughput tradeoff above. For the
Linux `auto` fast path, also test eight simultaneous `tokio-copy` probes because
the default auto splice threshold is eight connections; the single-direction
uplink buffer is intentionally tuned independently from the all-userspace
32 KiB default.

For splice-pipe experiments, add `--splice-pipe-size N` with `--backend splice`.
When that flag is absent, `relay_probe` preserves its historical pipe behavior;
when present, it mirrors production by requesting `F_SETPIPE_SZ`, reporting the
actual kernel capacity, and using that capacity as the source-to-pipe splice
length. On the September 2026 host, 64/128/256 KiB were all granted exactly.
A 32 MiB `strace -f -c -e splice,pipe2,fcntl` run measured 1025, 643, and 533
`splice` calls respectively: moving 64→128 KiB removed about 37% of calls, while
128→256 KiB removed only another 17%, showing clear diminishing syscall returns.

The same candidate was then tested as concurrent batches of independent
single-direction probes pinned to CPUs 0-7. With c16 and 512 MiB/flow, aggregate
throughput medians were 75.05, 80.91, and 79.72 Gbit/s for 64/128/256 KiB; CVs
were 1.54%, 1.16%, and 1.91%, while CPU cost was 0.638, 0.603, and 0.612
seconds/GiB. Thus 128 KiB beat 64 KiB by about 7.8% throughput and 5.5% CPU/GiB,
and beat 256 KiB by about 1.5% throughput and 1.4% CPU/GiB. With c64 and
256 MiB/flow, medians were 70.17, 70.78, and 68.74 Gbit/s with 0.45%, 0.58%,
and 2.03% CV; CPU/GiB was 0.680, 0.687, and 0.692 seconds. At that concurrency
128 KiB retained a small throughput gain over 64 KiB and was about 3.0% faster
than 256 KiB with slightly lower CPU cost. Service-level cgroup `memory.current`
peak deltas were not monotonic across pipe sizes and are treated as noise rather
than pipe-memory evidence. The deterministic capacity bound still matters:
raising a full-splice relay from 128 to 256 KiB adds up to 256 KiB of two-direction
pipe capacity per connection, or 16 MiB across c64. These results support keeping
the 128 KiB production default rather than trading more capacity for the smaller
remaining syscall reduction.

`tcp_copy_finish_bench` isolates the EOF completion path used by the
single-direction userspace relay. Tokio `copy_buf` already polls `flush` after
observing EOF, so polling `flush` again before `shutdown` only traverses the
writer wrapper chain a second time. Compare the old and single-flush shapes with:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin tcp_copy_finish_bench
for mode in redundant-flush copy-buf-flush; do
  bench/chimera_perf/target/release/tcp_copy_finish_bench \
    --mode "$mode" --iterations 20000000 --warmup 2 --runs 7
done
```

This is a completion-path microbenchmark, not a bulk-throughput benchmark. Its
flush counters are the semantic guard: `redundant-flush` must report two flush
polls per transfer and `copy-buf-flush` one, while both still perform one write
and one shutdown.

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

Production splice does not write through the original Tokio `TcpStream` fd: it duplicates each raw TCP endpoint with `F_DUPFD_CLOEXEC` before registering the duplicate with `AsyncFd`. Use `--pacing-fd duplicate --splice-destination-fd duplicate` to mirror that ownership shape. The probe reuses one duplicate for both roles, and the unit test verifies that `SO_MAX_PACING_RATE` set through either fd is immediately visible through the other because both descriptors reference the same TCP socket. On the September 2026 loopback host, 128 MiB at 50 MiB/s produced essentially identical rate control across the placement matrix: original/original was 1.002645x requested rate, original/duplicate was 1.002802x, and duplicate/duplicate was 1.002654x. A 100→25 MiB/s midpoint update also matched closely (0.959763x original/original vs 0.961140x duplicate/duplicate), confirming that later publications through the duplicate affect an active splice sender.

`strace -f -c -e trace=fcntl,setsockopt,getsockopt,splice` shows one extra `fcntl(F_DUPFD_CLOEXEC)` in the duplicate/duplicate benchmark setup and no per-transfer fd-management calls. Production splice already pays that duplication to build `SpliceDirection`, so a future pacing publisher can target the existing destination duplicate without adding another fd duplication syscall. This still does not define the TCP Brutal2 rate lifecycle or configuration semantics; it only proves the low-level socket placement is viable.

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

Dynamic results also report `pacing_updates`. Treat them as a queue-response probe rather than a guarantee that an already-buffered TCP send queue changes rate instantaneously. On Linux, add `--notsent-lowat-bytes N` to set `TCP_NOTSENT_LOWAT`; the probe reports the requested socket override, the value returned by `getsockopt`, the host-wide `/proc/sys/net/ipv4/tcp_notsent_lowat`, and `SIOCOUTQNSD` `notsent_bytes_at_rate_update` at the exact midpoint publication. `--splice-wait-mode poll` makes the splice destination nonblocking and counts each `EAGAIN → poll(POLLOUT)` recovery as `writable_waits`, approximating the readiness pressure that production `AsyncFd` would see more faithfully than the default blocking benchmark.

On the September 2026 loopback host (`tcp_notsent_lowat=4294967295` globally), production-like duplicate/duplicate nonblocking splice with a 100→25 MiB/s midpoint change had a median 2.40 MB of unsent data at the update and tracked 0.961697x of the ideal aggregate rate. A 512 KiB socket low-water reduced the update backlog to 336,613 bytes and improved tracking to 0.996108x, while writable waits rose from 67 to 203 per 64 MiB, context switches from 1113 to 1233, and CPU/GiB from 0.826 to 0.837 seconds. Smaller 64/128 KiB values reduced the backlog to roughly 90 KiB but raised writable waits to 511 and CPU/GiB to about 0.92 seconds. In steady 50 MiB/s traffic, 512 KiB still raised writable waits from 71 to 203, context switches from 1107 to 1236, and CPU/GiB from 0.882 to 0.920 seconds. A focused 32 MiB `strace` likewise increased tracked `splice + poll + socket-option/fcntl` calls from 1130 at the default to 1335 at 512 KiB; 128 KiB reached 1791. The low-water knob therefore materially reduces stale queued data after a pacing decrease, but it buys that response with persistent readiness/syscall churn. The current data does not support enabling it globally in the generic TCP relay; keep it benchmark-only until a TCP Brutal2-specific socket lifecycle and workload justify the trade-off.

`tcp_asyncfd_pacing_probe` removes the remaining wait-model mismatch by reproducing the production one-direction relay shape with Tokio `AsyncFd<OwnedFd>`, duplicated nonblocking TCP endpoints, a 128 KiB nonblocking splice pipe, and concurrent writer/sink tasks on one multi-thread runtime. It also supports `--connections N`, so the same `TCP_NOTSENT_LOWAT` choice can be measured under reactor contention instead of only as a single blocking or `poll(2)` flow:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin tcp_asyncfd_pacing_probe

bench/chimera_perf/target/release/tcp_asyncfd_pacing_probe \
  --connections 64 \
  --worker-threads 4 \
  --bytes-per-connection 8388608 \
  --rate-bytes-per-sec 33554432 \
  --second-rate-bytes-per-sec 8388608 \
  --notsent-lowat-bytes 524288 \
  --pipe-size 131072 \
  --warmup 1 \
  --runs 3
```

`--unpaced` skips `SO_MAX_PACING_RATE` entirely and rejects rate-update, low-water, and pacing-recovery options. In this mode the requested-rate and rate-ratio JSON fields are `null`, while `actual_pipe_capacity_min/max` report the real capacities returned by the kernel across every relay in the measured runs. A `strace -f -e trace=setsockopt` smoke check showed no `SO_MAX_PACING_RATE` call in unpaced mode; 64, 128, and 256 KiB requests all reached their requested capacities on the September 2026 host.

A shared-reactor unpaced pipe-size recheck used one Tokio runtime with eight workers pinned to CPUs 0-7, 64 KiB payload chunks, and interleaved pipe-size ordering. At c64 with 256 MiB/flow (16 GiB per batch), both 128 and 256 KiB were stable (throughput CV 0.86% and 0.91%). The 128 KiB default measured 71.904 Gbit/s, 0.6466 CPU seconds/GiB, and 34.83 destination `WouldBlock` events/connection; 256 KiB measured 71.724 Gbit/s, 0.6522 CPU seconds/GiB, and 47.84 `WouldBlock` events/connection. Thus 256 KiB was about 0.25% slower, used about 0.9% more CPU/GiB, and caused about 37% more destination readiness misses. At c16 with 1 GiB/flow, 128 KiB remained stable at 75.452 Gbit/s (0.98% CV), while 256 KiB reached a similar 75.667 Gbit/s median but remained unstable at 4.71% CV and therefore fails the benchmark acceptance rule. A focused c16 `strace` still showed the expected syscall reduction—`splice` fell from 18,231 calls / 873 errors at 128 KiB to 10,551 / 844 at 256 KiB—but the nearly unchanged EAGAIN count means the larger pipe mainly removes successful transfer calls rather than readiness boundaries. This closes the current pipe-size line in favor of retaining the 128 KiB production default; 256 KiB does not convert its extra pipe capacity into a stable shared-reactor throughput or CPU win.

`--destination-drain-mode` is a benchmark-only check of whether reusing one Tokio destination writable guard after a successful partial `pipe → socket` splice saves meaningful data-plane work. `single` mirrors production, `two-splices` permits one immediate second splice under the same guard, and `until-would-block` keeps reusing the guard until the pipe empties or `try_io` clears readiness on `WouldBlock`. Non-single modes accept steady pacing with an optional static `TCP_NOTSENT_LOWAT`, or `--unpaced`; dynamic rate/low-water publication and recovery-sampling options remain rejected so the benchmark branch cannot bypass publication accounting. The JSON report includes `destination_ready_acquisitions` to distinguish saved user-space guard fast paths from actual reactor/syscall reductions.

A September 2026 interleaved steady 50 MiB/s-per-flow run with eight Tokio workers and the production 128 KiB pipe found that `two-splices` already captured essentially all of full drain's guard reduction. At c16, `single` / `two-splices` / `until-would-block` measured about 650.3 / 581.8 / 581.9 destination guard acquisitions per connection; throughput was 6.7047 / 6.7056 / 6.7065 Gbit/s with CV below 0.12% for all three. `two-splices` therefore saved about 10.5% of guard acquisitions but improved throughput by only about 0.01%, while CPU/GiB was about 1.1% higher and context switches about 2.0% higher than `single`. At c64, `two-splices` reduced guard acquisitions from about 652.1 to 579.6 per connection (~11.1%) and moved throughput from 25.789 to 25.908 Gbit/s (~0.46%), but context switches rose from about 41,450 to 47,214 (~13.9%); CPU samples drifted strongly with run order and were excluded from the decision. A focused c16 `strace -f -c` showed why the guard count does not translate into a kernel win: tracked calls were 16,587 / 16,628 / 17,030 and `splice` calls were 9,324 / 9,309 / 9,333 for `single` / `two-splices` / full drain, while `epoll_wait` was 6,939 / 6,995 / 7,373. The optimization removes already-ready Tokio guard reacquisitions, not meaningful syscalls or readiness boundaries.

The same hypothesis was then retested with a static 32 ms `TCP_NOTSENT_LOWAT`, which is closer to the current Brutal2 pacing experiments because it deliberately increases destination backpressure without adding any mid-flow publication. Twelve c64 independent-process pairs in each rate bucket, alternating execution order on CPUs 0-7, showed that `two-splices` cut destination guard acquisitions by about **21.2% at 16 MiB/s** and **14.2% at 32 MiB/s**, but the CPU/GiB ratios remained **0.981x** and **1.006x** with wide run-to-run overlap; throughput ratios were only **1.001x** and **1.001x**. A focused c16/16 MiB/s `strace -f -c` likewise changed `splice` only from 1,427 to 1,422 calls while `epoll_wait` fell from 1,514 to 1,225. The saved guard acquisitions therefore still do not reduce the dominant splice syscall count, and the scheduler/reactor benefit is too noisy to justify changing the production loop. Keep production `SpliceDirection` unchanged; even under deliberate Brutal2-style low-water backpressure, the bounded two-splice variant lacks a stable CPU or throughput win.

A follow-up instrumented the probe's successful `socket → pipe` and `pipe → socket` splice sizes plus partial-success counts, so the remaining syscall volume can be attributed instead of inferred from readiness counts. At c64 / 16 MiB/s / 32 ms low-water / 128 KiB pipe, five measured runs showed the source side averaging about **129.0 KiB per successful splice** with only **~3.1% partial successes** and a median **2 source `WouldBlock` events** across all 64 flows. The paced destination side averaged only **~92.1 KiB per successful splice** and about **27.0% of successful destination splices were partial**. In `single` mode the median was **1,536 destination partial successes and exactly 1,536 destination `WouldBlock`s**; `two-splices` produced essentially the same successful splice count/size distribution and `WouldBlock` count while reducing destination writable acquisitions from **7,233 to 5,695**. This pins the extra guard churn on a socket-side pattern: a partial `pipe → socket` splice is commonly followed by an immediate EAGAIN under pacing/low-water, while `socket → pipe` is almost always pipe-capacity-sized. The bottleneck is therefore not source wakeup or an undersized 128 KiB pipe in this workload. Since reusing the guard still does not reduce successful splice count and earlier paired CPU results were unstable, keep production unchanged and focus future work on the paced socket send-queue boundary rather than source-side draining.

`--sample-partial-notsent-every N` is an opt-in attribution mode for that destination boundary. It samples `SIOCOUTQNSD` after every Nth successful partial `pipe → socket` splice and reports the sample count plus mean/min/max unsent bytes. The extra ioctl is deliberately excluded from throughput claims; use a sparse cadence such as 8 and compare queue state, not CPU. On the same c64 / 128 KiB pipe workload, five 16 MiB/s runs with a 32 ms low-water configured **536,870 B** sampled means of about **583-587 KiB**, with every run sharing a **571,392 B minimum** and **589,347 B maximum**. At 32 MiB/s the configured low-water was **1,073,741 B** and five runs sampled means around **1.110-1.113 MiB**, with minima **1,095,168-1,113,211 B**. Halving the 16 MiB/s queue time to 16 ms configured **268,435 B** and three runs still sampled above it, with a **285,696 B minimum** and roughly **310-317 KiB means**. In all three buckets, the destination partial-splice count remained effectively one-for-one with destination `WouldBlock`. This directly confirms that paced partial splices are being truncated at the destination TCP unsent-queue/writable boundary, with a modest kernel send-granularity overshoot above `TCP_NOTSENT_LOWAT`; it does not yet identify a safe lower production low-water, so keep the pacing policy unchanged until a paired low-water experiment shows fewer partial/EAGAIN events *and* a stable CPU/GiB or tracking improvement.

A no-ioctl static queue-time sweep then tested whether simply allowing a deeper unsent queue converts that mechanism into a CPU win. At c64 / 16 MiB/s / 128 KiB pipe / 8 MiB per flow, interleaved 16/24/32/48/64 ms samples showed the expected monotonic reduction in destination pressure: median partial splices fell from about **2676 at 16 ms** to **832 at 64 ms**, and destination `WouldBlock` from about **41.8 to 13.0 events/connection**. The short samples were too noisy for CPU claims, so a second six-pair run used 32 MiB per flow and compared only 32/48/64 ms. Against 32 ms, 48 ms reduced `WouldBlock` by about **25.0%** and destination-ready acquisitions by **11.0%**, while 64 ms reduced them by about **43.9%** and **19.2%**. CPU/GiB ratios were only **0.991x** and **0.987x** respectively, with each deeper setting winning just **4/6** pairs; 64 ms also reduced throughput and per-flow rate tracking by about **0.13%**. This is not stable evidence for lengthening the production Brutal2 low-water queue time. The data confirms that a deeper low-water cheaply suppresses partial/EAGAIN wakeups, but the saved readiness work is too small to outweigh the pacing-response trade-off consistently. Retain 32 ms as the benchmark policy reference and stop tuning this knob for steady-state CPU unless a representative WAN transition workload shows a materially better end-to-end trade-off.

`tcp_splice_setup_probe` isolates the fixed connection-setup cost of the Linux full-splice path. `--mode arc` models the production endpoint ownership shape (`Arc<AsyncFd<OwnedFd>>` plus one clone per direction), while `--mode owned` keeps the same two fd duplications, two AsyncFd registrations, two nonblocking pipes, and pipe-size checks but stores the AsyncFd endpoints directly. On the September 2026 host, six CPU-0-pinned paired runs at 50,000 setups/sample produced owned-vs-arc deltas of about `+1.26%, -1.29%, -0.72%, +0.08%, +0.96%, +1.15%`; the median advantage was only about **0.52%**. A focused 2,000-setup `strace -f -c` reported exactly 36,015 tracked `fcntl + epoll_ctl + pipe2 + close` calls for both modes, confirming that the candidate only removes heap/refcount work and does not reduce kernel setup cost. A temporary production ownership refactor passed all TCP relay correctness/half-close tests, but the paired benchmark was too close to noise, so the production code remains unchanged. Keep this probe for future short-flow regressions rather than adding ownership complexity for a sub-1% median setup win.

`tcp_short_flow_relay_probe` measures the next question directly: once TCP connections already exist, where does production-like Tokio userspace copy become cheaper than paying full-splice setup for a short direct TCP flow? Connection establishment and source payload preload are outside the timed region; the timed cN burst includes relay task execution, copy buffers or full-splice `F_DUPFD_CLOEXEC + AsyncFd + two pipe` setup, payload transfer, half-close, and sink drain. On the September 2026 host with c64, eight workers pinned to CPUs 0-7, a 32 KiB copy buffer, and the production 128 KiB splice pipe, nine interleaved independent-process samples put the CPU crossover between 64 and 128 KiB. Median splice/copy CPU ratios were about **1.41x at 4 KiB, 1.39x at 8 KiB, 1.33x at 16 KiB, 1.25x at 32 KiB, 1.09x at 64 KiB, 0.97x at 128 KiB, and 0.68x at 256 KiB**. CPU/flow CVs were roughly 5-9%; splice wall-time had occasional scheduler stalls and is therefore not used to choose the crossover.

The probe also keeps a rejected `prefix-splice` model for the only deployable way to exploit that crossover without knowing final flow length in advance: copy a fixed prefix, finish in userspace if EOF arrives, otherwise initialize splice for the remainder. A 64 KiB prefix plus a nonblocking one-byte EOF probe successfully avoids splice setup for flows at or below 64 KiB, but it creates a new middle-size penalty because 128 KiB flows pay both 64 KiB of userspace copy and the complete splice setup. Interleaved medians were about 108 / 132 / 119 CPU µs per 128 KiB flow for copy / prefix-splice / splice, while 256 KiB measured about 220 / 167 / 147 µs. A focused c64 `strace -f -c` explains the penalty: at 32 KiB, copy and prefix-splice avoid all per-flow `pipe2`/splice-fd setup while full splice adds 128 `pipe2`, 386 `fcntl`, and 256 `splice` calls; at 128 KiB, prefix-splice still pays the full 128 `pipe2` + 386 `fcntl` setup **in addition to** 576 `recvfrom` and 256 `sendto` calls from the copied prefix. There is therefore no single fixed prefix that safely improves the whole size range. Keep backend selection unchanged rather than adding a speculative short-flow handoff state machine; use this probe if a future workload trace provides an actual flow-size distribution that can justify a distribution-specific policy.

`splice-downlink` models the lower-fixed-cost shape used by the production `auto` backend after raw TCP handoff: only the payload-carrying direction gets duplicated `AsyncFd` endpoints and one splice pipe instead of constructing pipes for both directions. Five interleaved independent-process c32 samples on CPUs 0-7 still kept userspace copy ahead at 64/96/128 KiB: median downlink-splice/copy CPU ratios were about **1.20x, 1.15x, and 1.12x**. At 160 KiB the two were approximately even in a focused run, while 192 KiB and 256 KiB favored downlink splice by about **22%** and **23%** respectively. A focused c32/128 KiB `strace -f -c` counted 909 tracked calls for copy, 1,164 for downlink splice, and 1,356 for full splice. Relative to full splice, the one-direction path halves per-flow `pipe2` (64→32) and reduces `fcntl` (194→130), but it still pays enough fd/epoll/pipe setup that the short-flow crossover does not move below 128 KiB. This strengthens the negative result for speculative size-based switching: production `auto` is already the cheaper splice shape, yet short flows still prefer copy and the final flow size remains unknown at handoff time.

On the same host, the c64 dynamic 32→8 MiB/s-per-flow workload reduced median update backlog from 1,942,016 bytes with the default socket behavior to 586,930 bytes at 512 KiB, and improved the per-flow rate ratio from 0.672233x to 0.907811x. CPU/GiB moved from 0.582588 to 0.589456 seconds, context switches from 7530 to 8053, and destination `try_io` `WouldBlock` events from 6.02 to 23.98 per connection. A c64 sweep keeps the expected response/churn curve: 256 KiB reacts fastest but reaches roughly 40.7 `WouldBlock` events/connection, 512 KiB is intermediate, and 1 MiB cuts the event count to roughly 13 while accepting a larger queued tail.

A five-run c64 32→25 MiB/s workload is closer to the 20-25% rate reductions seen while the live Brutal loss window recovers. The default path reported 2,286,358 bytes of midpoint backlog, 0.880580x rate tracking, 0.698475 CPU seconds/GiB, 12,908 context switches, and 14.73 destination `WouldBlock` events/connection. A static 512 KiB low-water reduced the backlog to 527,913 bytes and improved tracking to 0.954609x, but raised `WouldBlock` to 49.48/connection and context switches to 14,350. A static 1 MiB low-water retained most of the response benefit at 799,711 bytes and 0.944164x while limiting `WouldBlock` to 26.98/connection and context switches to 12,988; its measured CPU/GiB was 0.624781 seconds. Across c64 steady 16/32/64 MiB/s sweeps, 1 MiB stayed much closer to the default scheduler cost than 512 KiB while roughly halving the latter's destination `WouldBlock` count. This makes about 1 MiB the lower-churn static candidate for a future Brutal2-specific socket policy, but still not evidence for changing the generic relay default.

`--notsent-lowat-ms T` expresses the static queue bound as pacing time instead of a fixed byte count. The probe derives the initial socket value as `rate_bytes_per_sec * T / 1000`; if `--second-rate-bytes-per-sec` is present, the initial value is still derived from the **current** rate, then the low-water is updated to `second_rate_bytes_per_sec * T / 1000` at the same midpoint publication as `SO_MAX_PACING_RATE`. This timing matters: pre-sizing the socket from the future lower rate would be an oracle benchmark that cannot be implemented in a live Brutal2 publisher. Optional `--notsent-lowat-min-bytes` and `--notsent-lowat-max-bytes` clamp each derived active-rate value, and are rejected unless queue-time mode is enabled. `--notsent-lowat-ms` remains mutually exclusive with the fixed byte-based and adaptive modes, and the JSON output reports the requested bounds plus both effective byte values.

A September 2026 isolated user/network namespace run used `tc netem delay 5ms` on its private loopback (measured `TCP_INFO` RTT roughly 11-14 ms), c16, and equal-duration 16→12.5, 32→25, and 64→50 MiB/s rate changes. A deployable 32 ms policy improved rate tracking from 0.970460x to 0.988630x at 16 MiB/s, 0.971094x to 0.979031x at 32 MiB/s, and 0.969825x to 0.973067x at 64 MiB/s. Midpoint `SIOCOUTQNSD` backlog fell from 2.60 MiB to 392 KiB, 2.69 MiB to 878 KiB, and 2.62 MiB to 1.78 MiB respectively; destination `WouldBlock` events rose from 29.7 to 112, 47.1 to 127, and 88.8 to 131 per connection. The response benefit therefore shrinks as pacing rate rises even though queue-time scaling keeps the readiness cost far more comparable than one fixed byte value.

A 64 ms queue-time is lower churn but eventually becomes ineffective: the same matrix produced about 63, 64, and 81 destination `WouldBlock` events/connection, but the 64 MiB/s initial low-water is 4.0 MiB, above the roughly 2.6 MiB natural unsent backlog, so tracking only moved from 0.969825x to 0.970681x and the sampled backlog was actually 2.92 MiB. Steady-state 16/32/64 MiB/s measurements show the same normalization: 64 ms produced roughly 54/58/89 `WouldBlock` events/connection versus defaults of 29/48/89, with context-switch deltas of about +4%, +1%, and -2%. This is evidence that queue-time is a useful benchmark coordinate, **not** that an unbounded `rate * T` formula is a production policy; a future candidate needs independently benchmarked byte floors/caps.

A focused c16 `strace -f -c` at 32→25 MiB/s and the same netem delay measured 9300 tracked `splice + epoll + socket-option/ioctl/fcntl` calls for the default and 9844 for 32 ms (+5.8%). `setsockopt` increased from 128 to 160 exactly, matching one initial low-water and one midpoint low-water update per 16 flows; `splice` rose from 4709 calls / 312 errors to 5279 / 582.

A follow-up bounded-policy sweep tested `clamp(rate * 32 ms, 512 KiB, cap)` under the same c16/netem setup. At 16→12.5 MiB/s, the 512 KiB floor reduced destination `WouldBlock` from 112 to 99 events/connection while keeping tracking essentially unchanged (0.988500x unbounded vs 0.988884x with a 1 MiB cap); the floor therefore prevents the low-rate side from becoming needlessly aggressive. At 64→50 MiB/s, however, tightening the cap had sharply diminishing returns: unbounded 32 ms used a 2.0→1.6 MiB low-water, tracked at 0.972853x with 131 `WouldBlock` events/connection and 1.60 MiB midpoint backlog; a 1.5 MiB cap improved tracking only to 0.974296x and backlog to 1.38 MiB while raising `WouldBlock` to 154/connection. A 1 MiB cap reached 0.973955x and about 996 KiB backlog but increased `WouldBlock` to 223/connection. Steady 64 MiB/s confirms that the cap cost persists without a rate change: unbounded 32 ms measured 117 `WouldBlock` events/connection, while the 1.5 MiB cap measured 154, with no meaningful steady rate benefit. `strace` at 64→50 MiB/s likewise increased tracked calls from 15,697 to 15,884 and failed `splice` calls from 622 to 705 for the 1.5 MiB cap. This is a negative result for a hard upper cap in the tested range: a byte floor is useful to prevent over-aggressive low-rate queue times, but 1-1.5 MiB caps buy very little extra transition accuracy for persistent readiness cost. Keep all bounded policies benchmark-only until a TCP Brutal2-specific configuration/rate lifecycle exists and a rule survives broader Internet-path testing.

`--rate-updates-bytes-per-sec A,B,...` replays a sequence of pacing publications across equal-byte phases and is mutually exclusive with `--second-rate-bytes-per-sec`. These rates are intentionally treated as values that have **already passed** the pacing publication policy; the probe does not reimplement the Brutal estimator or its 5% pacing hysteresis. With queue-time mode enabled, `--notsent-lowat-update-threshold-percent P` then independently gates `TCP_NOTSENT_LOWAT` updates against the last low-water value actually published. The JSON report exposes per-connection pacing and low-water publication counts so a coarse low-water gate can be measured without adding extra per-update `SIOCOUTQNSD` instrumentation.

A September 2026 c16/netem replay used the already-published wave `32→30→28→30→32→30→28→30→32 MiB/s` with a 32 ms queue-time. Updating low-water on every one of the eight pacing publications measured 0.982964x rate tracking and 128.25 destination `WouldBlock` events/connection. A 12.5% or 25% low-water gate made **zero** low-water updates for that ±12.5% wave, yet measured 0.982516x / 0.982409x tracking and about 125 `WouldBlock` events/connection. A wider `32→30→28→26→28→30→32` loss/recovery wave repeated twice forced the 12.5% gate to act: it reduced low-water publications from 12 to 4 per connection while tracking moved only from 0.988315x to 0.988019x and `WouldBlock` from 192.19 to 189.06. A 25% gate again made no low-water updates and measured 0.988650x with 181.81 `WouldBlock` events/connection. These results support decoupling low-water publication from every pacing publication; 12.5% is the conservative benchmark candidate because it cut updates by two thirds on the wider wave while still following material queue-size changes. The 25% result should not be generalized because the tested wave never crossed that byte-delta threshold.

`strace -f -c` on the wider wave confirmed that the publication count maps directly to socket-option syscalls: 0%, 12.5%, and 25% low-water gates made 512, 384, and 320 total `setsockopt` calls respectively, with differences exactly matching 12, 4, and 0 low-water updates × 16 flows while pacing publications remained fixed at 12/flow. Failed `splice` calls were 1619, 1599, and 1549 respectively; there was no evidence that suppressing small low-water updates increased readiness churn. Keep this as a benchmark policy until a real TCP Brutal2 socket/rate lifecycle exists; the result argues for a separate low-water delta gate, not for wiring the current probe policy into generic relay sockets.

`--adaptive-notsent-lowat-bytes N` models a rejected event-driven alternative: on a pacing decrease, it sets `TCP_NOTSENT_LOWAT` only if the already-queued bytes exceed `N`, waits until the low-water has caused a destination `WouldBlock`, then restores the socket override to zero at the next writable notification. This avoids a timer and, in `strace`, costs exactly two additional `setsockopt` calls per connection plus one restore-time `SIOCOUTQNSD` sample. It does **not** solve the queue problem because the stale bytes were already admitted before the rate decrease. In the c64 32→25 MiB/s workload, 512 KiB adaptive mode restored at a median 261,932 queued bytes but improved tracking only from 0.880580x to 0.892072x, far behind either static low-water. The probe keeps this negative result so future work does not repeat the same post-update strategy.

Use `--sample-tcp-info` when the experiment needs the destination socket's measured RTT and congestion-window state at the midpoint update. The flag adds one `getsockopt(TCP_INFO)` per dynamic flow and is off by default so existing syscall baselines remain unchanged. The report includes `tcp_rtt_us_at_rate_update_median`, approximate unacked bytes, and approximate sender-cwnd bytes. An isolated user/network namespace can add real kernel delay without modifying the host qdisc:

```bash
unshare -Urn sh -c '
  ip link set lo up
  tc qdisc add dev lo root netem delay 15ms limit 100000
  bench/chimera_perf/target/release/tcp_asyncfd_pacing_probe \
    --connections 16 \
    --worker-threads 4 \
    --bytes-per-connection 16777216 \
    --rate-bytes-per-sec 33554432 \
    --second-rate-bytes-per-sec 26214400 \
    --notsent-lowat-bytes 1048576 \
    --sample-tcp-info \
    --warmup 1 \
    --runs 3
'
```

A September 2026 c16 32→25 MiB/s RTT sweep showed that the static 1 MiB candidate is useful only while unsent queue depth is a material part of the transition. With no netem, measured RTT was about 1.5 ms: 1 MiB reduced midpoint `SIOCOUTQNSD` from 2.39 MiB to 0.80 MiB and improved the aggregate rate ratio from 0.967x to 0.995x. With 5 ms one-way netem (about 11.6 ms measured RTT), it reduced 2.75 MiB to 0.80 MiB and improved 0.895x to 0.922x. With 15 ms one-way netem (about 31.5 ms RTT), it reduced 2.52 MiB to 0.99 MiB and improved 0.726x to 0.752x; a focused c16 `strace` increased tracked calls from 5045 to 5298 (+5.0%), mainly additional failed `splice` attempts. At roughly 31 ms RTT, 512 KiB gained only another ~0.5 percentage point of rate tracking while nearly doubling destination `WouldBlock` events relative to 1 MiB.

The high-RTT boundary is a negative result. At about 82 ms measured RTT, a longer c4/64 MiB-per-flow run reported about 2.68 MiB unacked and a 5.6 MiB sender cwnd at the update, while unsent backlog was only around 0.6-1.0 MiB. Default, 1 MiB, 2 MiB, and 4 MiB low-water variants all tracked only about 0.76-0.78x, with no repeatable low-water gain. The new 25 MiB/s target has roughly a 2 MiB one-RTT BDP at that RTT, so even choosing a low-water near one BDP does not rescue the transition once RTT/cwnd rather than unsent queue is dominant. Do not infer a universal fixed or BDP-scaled `TCP_NOTSENT_LOWAT` rule from the low-RTT data; any future Brutal2-specific policy needs an applicability gate and representative Internet-path validation.

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

To test the publication rule against the current Brutal loss-compensation behavior instead of arbitrary estimator noise, rerun with `--trace brutal-loss`. That mode deliberately keeps the configured base rate fixed and varies deterministic packet loss in phases; the resulting target changes only as the same 5-second ACK/loss accounting used by the production Brutal controller evolves. It is still a deterministic model rather than a captured production trace, but it is suitable for checking whether timer debounce or rate-delta hysteresis actually matters for the current algorithm before wiring a TCP Brutal2 publisher into the data path. Add `--emit-publication-rates` to include the exact published byte-rate sequence in each JSON record; the first value can be passed as `tcp_asyncfd_pacing_probe --rate-bytes-per-sec` and the remaining values as `--rate-updates-bytes-per-sec`, which makes the policy output directly replayable against real Linux socket pacing/backpressure behavior.

For a live estimator trace, enable the benchmark-only `brutal-pacing-trace` feature and run the ignored Xray Hysteria2 probe. The test inserts an unprivileged userspace UDP proxy between Xray and Chimera, keeps the handshake/warmup lossless, drops every tenth server-to-client datagram during the loss phase, then disables loss again so the five-second Brutal window can recover:

```bash
cargo test -p chimera_server_app --features brutal-pacing-trace \
  --test xray_client_proxy_e2e \
  xray_hysteria2_brutal_pacing_publication_trace \
  -- --ignored --nocapture
```

The trace is compiled out unless the feature is enabled and is runtime-gated by `HYSTERIA_BRUTAL_DEBUG`, so normal data-plane builds pay no trace-state cost. It evaluates the real `tx_bps / ack_rate` sequence against 1%, 5%, and 10% delta gates plus the previous 5% + 10 ms minimum interval + 25% emergency candidate. The benchmark-only report now also includes `delta_5_rates`, capped at the first 64 publications, so a live controller sequence can be copied directly into the AsyncFd socket probe. In three September 2026 loopback runs, each final report contained 1024 estimator samples over 12.3-13.0 seconds with the measured ACK rate falling to roughly 0.90-0.91. The 5% gate published 3-5 times (0.24-0.38/s) with about 1.93-2.85% mean and 4.55-5.26% peak tracking error. Adding the 10 ms interval and emergency bypass produced exactly the same publication count and error in all three runs. A 1% gate published 13-16 times (1.04-1.30/s) for roughly 1% peak error, while 10% published only 1-2 times but allowed about 8.97-11.04% peak stale-rate error. These are controlled loopback traces rather than Internet-wide tuning data, but they support using delta hysteresis as the primary publication gate and do not show a benefit from adding a periodic pacing timer.

A follow-up live run captured `delta_5_rates=[13107200,13775934]` while ACK rate fell to 0.9110, then replayed that exact sequence through the AsyncFd probe at c16 with a 32 ms rate-scaled low-water. Five-run loopback medians were effectively unchanged whether the low-water followed the single 5% pacing update or used a separate 12.5%/25% publication gate: rate ratios were 1.009022x, 1.009039x, and 1.008918x respectively, while destination `WouldBlock` events were 126.56, 129.31, and 128.25 per connection. The separate gates eliminate one `TCP_NOTSENT_LOWAT` `setsockopt` per flow in this trace, but the live pacing gate is already sparse enough that no measurable data-plane benefit remains. This is a negative result for adding another production hysteresis layer solely to optimize low-water publication frequency; keep the independent gate benchmark-only until a broader live trace shows materially more pacing publications.

A longer staged live trace now drives the benchmark-only loss proxy through roughly 5%, 10%, and 16.7% server-to-client packet loss before recovery. One September 2026 run recorded 2048 estimator samples over 20.9 seconds, ACK rate down to 0.8327, and only six 5% pacing publications: `13.11→13.78→14.48→15.20→14.44→13.29 MB/s`. Replaying those five updates through c16 AsyncFd exposed an important asymmetry in queue-time low-water gating. Updating low-water on every pacing publication measured 171.06 destination `WouldBlock` events/connection and 1.006035x tracking. A symmetric 12.5% low-water gate reduced updates from five to two but increased `WouldBlock` to 179.25/connection; a 25% gate made zero updates and reached 191.63/connection, with tracking still about 1.006x. The reason is that suppressing a low-water **increase** after a pacing-rate increase leaves an unnecessarily small writable threshold and creates persistent wakeup pressure. `--notsent-lowat-gate-decreases-only` models the asymmetric alternative: increases publish immediately, while decreases still use `--notsent-lowat-update-threshold-percent`. At 12.5% it made four updates/flow, restored `WouldBlock` to 171.75/connection, and tracked at 1.006162x. This is better benchmark behavior than symmetric hysteresis, but saving one socket-option update across a ~21-second live trace is still too small to justify production policy complexity; retain the asymmetric rule as a profiling candidate rather than wiring it into generic TCP relay sockets.

`--sample-rate-decrease-recovery` adds a benchmark-only view of what happens after each pacing-rate decrease when queue-time low-water is active. The probe samples `SIOCOUTQNSD` at the decrease, then samples again only after a destination `WouldBlock` has cleared and Tokio reports the socket writable. A recovery completes when that readiness-bound sample is at or below the new rate's desired `rate × queue-time` threshold. Reports include completed/incomplete recoveries plus median elapsed time, bytes forwarded during recovery, `WouldBlock` count, starting queue depth, and target queue depth. This deliberately avoids polling the queue on every splice, but the elapsed value is therefore the time when userspace **observed** recovery at a writable wake, not an exact high-frequency measurement of the kernel queue crossing the threshold.

A September 2026 rerun of the staged live trace produced exact 5% publication rates `13,107,200→13,762,560→14,454,669→15,262,292→14,497,357→13,772,258 B/s`. Replaying that sequence at c16 with a 32 ms queue-time low-water completed all 32 observed decreases (two decreases × 16 flows) with zero incomplete recoveries both when low-water followed every pacing update and when 12.5% decrease-only gating suppressed both low-water decreases. Both variants observed median recovery at about 22.3 ms, after one destination `WouldBlock`, with zero additional forwarded bytes in the median sample. The gated variant reduced low-water updates from five to three per flow without extending the observed stale-queue drain. A deliberately larger 32→25 MiB/s stress step validated that the instrumentation can see a real queued excess: the follow-every-update variant started near 1.09 MiB against an 0.80 MiB target and observed recovery at 26.8 ms, while a 25% decrease-only gate suppressed the low-water decrease yet still observed recovery at 21.9 ms with one `WouldBlock`; destination `WouldBlock` frequency also fell from about 128.8 to 112.1 per connection. Because recovery is sampled only at writable wakes, the latter timing should not be interpreted as proof that suppressing low-water decreases makes the kernel queue cross the target sooner. The useful result is narrower: current live 5% Brutal decreases do not show stale-queue persistence from asymmetric gating, so there is still no evidence for adding this policy to production before Internet-path validation.

A follow-up pipe-capacity sweep found an important paced-only inversion relative to the earlier unpaced result. At c16, 50 MiB/s per flow, 32 ms `TCP_NOTSENT_LOWAT`, and 128 MiB/flow, increasing the splice pipe from 128 KiB to 256/512 KiB reduced median destination readiness acquisitions from about **1315/connection** to **803/547** while destination `WouldBlock` stayed fixed at about **145/connection**. The 512 KiB sample reduced CPU/GiB from roughly 0.417 to 0.385 seconds in the initial three-run sweep. At c64 with 64 MiB/flow, 512 KiB similarly reduced readiness acquisitions from about 657 to 272 per connection while `WouldBlock` remained about 72; CPU/GiB moved from roughly 0.531 to 0.519 seconds, but aggregate throughput also fell from about 26.34 to 26.16 Gbit/s, so the CPU benefit is not yet strong enough to claim a production win. A focused c16/32 MiB `strace -f -c -e splice,epoll_wait,epoll_ctl,fcntl,pipe2,setsockopt` explains the mechanism: 128 KiB made 9,395 `splice` calls with 560 failures and 7,480 `epoll_wait` calls, while 512 KiB made only 3,319 `splice` calls with the **same 560 failures and the same 7,480 `epoll_wait` calls**. The larger pipe therefore removes successful transfer syscalls and cached-ready guard churn, not pacing wakeup boundaries. This is specific to paced backpressure: earlier unpaced c64 measurements found no stable throughput/CPU benefit from 256 KiB and more `WouldBlock`, so do not raise the generic 128 KiB relay default.

The high-concurrency follow-up closes the current large-pipe line more decisively. The host has `fs.pipe-user-pages-soft=16384` with 4 KiB pages (64 MiB soft per-user pipe budget). At c128 / 32 MiB/s / 32 ms low-water, 128 and 256 KiB requests were fully honored, but 512 KiB already fell back to the kernel's 8 KiB pipe on a median **13/128** connections. At c256, 128 KiB was still fully honored, while 256 KiB fell short on **25/256** connections and 512 KiB on **141/256**. Those mixed-capacity runs also lost the low-concurrency readiness advantage: c256/512 KiB reported about **1155 destination-ready acquisitions/connection** versus about **166** for the fully honored 128 KiB case. `tcp_asyncfd_pacing_probe` now reports `pipe_capacity_shortfall_connections` per run and its median in the summary so future sweeps cannot silently treat a requested capacity as the effective capacity. The cgroup/RSS side measurement showed no meaningful userspace RSS growth from the larger pipe; the limiting resource is kernel pipe accounting. Do not introduce a Brutal2-specific 512 KiB pipe default on this host: it is not robust at c128/c256 under the default per-user pipe soft limit, and fallback creates heterogeneous relay behavior that invalidates the expected syscall/readiness benefit.

A second c128 check shows that avoiding the soft-limit fallback is **not sufficient** to make a larger pipe safe. The probe now records each relay's completion time from the shared start barrier and reports the per-run median, maximum, and max/median ratio. With 32 MiB/flow at 32 MiB/s and a 32 ms low-water, five CPU-0-7-pinned runs of a fully honored 128 KiB pipe delivered **32.71 Gbit/s**, **0.603 s/GiB**, about **367 destination-ready acquisitions/connection**, and a median max/median completion ratio of **1.023**. A fully honored 256 KiB pipe reduced ready acquisitions to about **226/connection**, but aggregate throughput collapsed to **22.55 Gbit/s**, CPU rose to **0.660 s/GiB**, and the completion ratio widened to **1.170**; source-side `WouldBlock` also became materially more common. This is a scheduler/fairness warning, not just a pipe-budget warning: the larger buffer batches successful splices more aggressively and can reduce destination-side churn while worsening per-flow completion spread under high contention. A shorter c128 `strace` sample still showed the expected syscall reduction (about 19.3k→11.5k `splice` calls), so syscall count alone is an unsafe optimization target here. Do not implement a connection-count/pipe-budget adaptive enlargement policy from the current evidence; 128 KiB remains the robust high-concurrency choice on this host.

The next c128 pacing-rate sweep adds writer and sink completion distributions so relay fairness is not blamed on Brutal2 after the synthetic producer/consumer is already saturated. With 16 MiB/flow, 128 KiB pipes, 32 ms queue-time low-water, eight pinned workers, and five measured runs, 16/32/48/64 MiB/s per-flow pacing produced relay max/median completion ratios of about **1.024/1.044/1.077/1.095**, but writer ratios widened sooner to about **1.055/1.091/1.136/1.150**. The 64 MiB/s case delivered only **52.12 Gbit/s** (0.758× requested per-flow rate), while the same harness without pacing topped out near **70.80 Gbit/s** and already had writer/relay completion ratios of about **1.315/1.179**. Destination `WouldBlock` simultaneously fell from about 49.5/connection at 16 MiB/s to 11.6 at 64 MiB/s. Therefore the high-rate completion spread is not evidence of a Brutal2 wakeup regression: the synthetic writer/sink/runtime is approaching its own loopback throughput ceiling before the requested aggregate 68.7 Gbit/s rate is cleanly sustained. Future high-concurrency pacing comparisons should report writer/sink completion alongside relay completion and should not attribute tail growth to pacing when the producer or unpaced baseline shows comparable or larger spread.

A c64 replay below that harness ceiling checks whether the real staged-loss 5% publication sequence itself is a meaningful data-plane hotspot. The six equal-byte phases `13,107,200→13,762,560→14,454,669→15,262,292→14,497,357→13,772,258 B/s` have a harmonic-mean fixed-rate baseline of about **14.11 MB/s**. Five CPU-0-7-pinned paired runs at 8 MiB/flow and 32 ms queue-time low-water measured dynamic/fixed medians of **1.003× throughput**, **0.995× CPU/GiB**, **0.978× destination-ready acquisitions**, **0.952× destination `WouldBlock`**, and **1.004× relay max/median completion spread**. The dynamic case made exactly five pacing and five low-water updates per flow, but showed no readiness, CPU, or completion-tail penalty beyond run noise. A c16 `strace -f -c` attribution likewise increased `setsockopt` from **128 to 288 calls**, exactly the expected extra 10 updates × 16 flows, while `splice` fell slightly from 3,006 to 2,989 and `epoll_wait` from 2,744 to 2,681. On this controlled low-saturation workload, live Brutal publication frequency is therefore too sparse to be a meaningful syscall/wakeup hotspot. Do not add timer batching, extra pacing hysteresis, or a more complex publication scheduler for performance alone unless broader Internet-path traces show materially denser publications.

### Brutal ACK accounting microbenchmark

`brutal_ack_rate_bench` isolates the current per-ACK loss-window accounting. It reports both the floating-point ACK-rate calculation alone and a full 10 kHz `record()` model that includes timestamp-to-second conversion, slot lookup, rolling totals, and ACK-rate refresh:

```bash
cargo run --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin brutal_ack_rate_bench
```

The arithmetic-only section intentionally retains a rejected optimization: branching inside every ACK-rate update to special-case zero loss helps a pristine window but regresses the isolated arithmetic path once a loss remains in the five-second window. The full `record()` section now distinguishes three cached-second shapes. `cached-second-record` is the pre-fast-path arithmetic baseline; `pristine-assign-record` mirrors current production, where a non-debug pristine window skips the division but still writes `ack_rate = 1.0` on every ACK; `skip-pristine-rate-record` also avoids that redundant write until the next rollover or loss. In seven CPU-0-pinned September 2026 runs, `pristine-assign-record` measured 6.159-7.403 ns/event while `skip-pristine-rate-record` measured 6.137-7.224 ns/event. The candidate was usually only about 0-3% faster and was slower in one run, so the data does not justify another production branch/state change. The benchmark keeps the comparison as a rejected micro-optimization and verifies that both shapes remain bit-for-bit equivalent across a loss/expiry lifecycle. Debug mode remains unchanged so periodic accounting logs keep their existing semantics.

The `window arithmetic` section checks a second rejected candidate: special-case `ack_rate == 1.0` before the Brutal congestion-window division. Across pinned runs, both versions remained roughly 1.2-1.3 ns/window with run-to-run noise larger than the difference, including loss-rate inputs down to the 0.8 clamp. Do not add a pristine branch to `BrutalState::window()` on this evidence.

The final section models Quinn's ACK callback batching contract: each acknowledged packet reaches `Controller::on_ack`, followed by one `Controller::on_end_acks` for the batch. `per-packet-record` recomputes Brutal accounting and the derived congestion window after every acknowledged packet, while `batched-record` pays a per-packet pending-counter update and publishes the same final ACK rate and window once per ACK batch. This is currently a rejected production optimization: batch size 1 is slower in the microbenchmark, and real loopback Xray interoperability traces are overwhelmingly singleton ACK batches.

To re-measure that distribution on the actual Hysteria2 and XHTTP/3 server paths, build the application with the benchmark-only `brutal-ack-batch-trace` feature and run the ignored probes:

```bash
cargo test -p chimera_server_app --features brutal-ack-batch-trace \
  --test xray_client_proxy_e2e xray_hysteria2_brutal_ack_batch_trace \
  -- --ignored --nocapture

cargo test -p chimera_server_app --features brutal-ack-batch-trace \
  --test xhttp_security_matrix_e2e xhttp_http3_brutal_ack_batch_trace \
  -- --ignored --nocapture
```

The trace feature is not part of the default `full` feature and adds no ACK-batch counters to normal builds. The probes enable the existing Brutal debug switch only in the spawned Chimera process and report cumulative buckets for sizes `1`, `2`, `3-4`, `5-8`, `9-16`, `17-32`, and `33+`. On the September 2026 loopback probe used to reject batching, Hysteria2 reported 124 singleton batches out of 128 (96.9%, four size-2 batches), while XHTTP/3 reported 832 singleton batches out of 832. These are loopback/debug-build workload observations, not a claim about Internet RTT distributions; rerun the probes under representative network conditions before reconsidering ACK-batch deferral.

The same benchmark-only trace now also counts ACK callbacks where both inputs to the cached Brutal congestion-window calculation (`last_rtt` and `ack_rate`) remain unchanged. This tests whether production should branch around `refresh_brutal_window()` on most ACKs instead of always recomputing it. The September 2026 Hysteria2 loopback run observed only **4/132 (3.0%)** ACK callbacks with unchanged inputs, and XHTTP/3 observed **0/832**. RTT estimator movement therefore invalidates the appealing pristine/no-loss assumption on these live paths: an input-equality guard would almost always fall through to the existing floating-point window calculation while adding another branch/comparison pair. Keep the equality check trace-only unless representative Internet-path traces show a materially higher unchanged-input fraction; there is no current benchmark evidence for changing the production ACK path.

A follow-up component attribution keeps the same 10 kHz timestamp progression and adds a small deterministic RTT movement on every modeled ACK, matching the live observation that RTT is rarely unchanged. On CPU 0, repeated release runs put the existing pristine `record()` path around **6.3-6.5 ns/ACK** and `record + window refresh` around **10.2-10.8 ns/ACK**. The exact difference is not additive because the loops share timestamp/RTT setup, but it establishes that the congestion-window refresh is a material fraction of this controller-only model rather than a sub-percent arithmetic detail. A minimal candidate that caches only the exact `tx_bps as f64` conversion (preserving the production multiplication order and therefore its numeric semantics) did not produce a stable isolated win: five `window-only` samples were roughly **-3.0% to +3.6%** versus the baseline, while the combined path showed a small order-sensitive improvement. That inconsistency is insufficient evidence for adding another cached controller field. Keep the component benchmark as a target for better arithmetic or RTT/window designs, but do not change production on the conversion-cache result alone.

A second attribution isolates RTT-to-seconds conversion. Calling `Duration::as_secs_f64()` alone remains cheaper than a branchy subsecond helper on this CPU (roughly **1.44-1.49 ns** versus **1.70-1.76 ns** for 80 ms through just-under-1 s RTTs, and the helper is also slower above one second), so the conversion microbenchmark by itself would reject the helper. In the full modeled window expression, however, the helper consistently reduced `window-only` from roughly **6.26-6.64 ns/ACK** to **5.62-5.86 ns/ACK**, and seven reversed-order `record + window` pairs favored it in every run (about **9.67-10.51 ns/ACK** versus **10.40-10.95 ns/ACK**). The branch uses `subsec_nanos()` only while RTT is below one second and falls back to `as_secs_f64()` otherwise. Boundary tests confirm byte-for-byte-equal `f64` results against `Duration::as_secs_f64()` from nanosecond-scale RTTs through multi-second RTTs, so the existing congestion-window integer result and Xray-compatible multiplication order remain unchanged. This supports the small production subsecond RTT conversion fast path, but it should remain narrowly scoped; the isolated conversion result shows that its gain comes from the surrounding window expression/code generation rather than from a universally faster Duration conversion primitive.

A follow-up checks the zero-RTT guard that precedes the same window expression. `Duration::is_zero()` is semantically identical to the existing `as_nanos() == 0` test without constructing the total nanosecond count. In five CPU-0-pinned release runs with moving ~80 ms RTT, `window-subsecond-rtt-is-zero` measured about **6.20-6.32 ns/ACK** versus **6.25-6.62 ns/ACK** for the `as_nanos()` guard; the full `record + window` candidate was faster in three of five paired runs (by about 2.4-3.0%) and effectively tied/slightly slower in the other two (about 0.1-0.4%). Because the production change is a one-line exact-equivalence substitution with no new state, allocation, branch policy, or protocol behavior, the data supports using `Duration::is_zero()` while keeping the benchmark comparison to detect future compiler/toolchain reversals.

A further `record()` attribution tests the two `Instant` bounds on the cached-current-second fast path. Once a callback has entered a rolling second, dropping the `now >= current_second_start` comparison and checking only `rolling_timestamp.is_some() && now < next_rollover` is measurably cheaper for monotonic callback streams. The benchmark now offers `BRUTAL_RECORD_BENCH_MODE=cached|monotonic` so the two shapes can be run in separate CPU-pinned processes rather than being distorted by in-process order/layout effects. Ten cached→monotonic process pairs measured median pristine cost at roughly **6.82 vs 6.25 ns/event**, while ten reverse-order pairs measured roughly **6.66 vs 6.16 ns/event**, a repeatable ~7-8% isolated `record()` reduction. A 50k-event monotonic loss trace verifies identical rolling counters, slots, and ACK rate. Follow-up inspection of the vendored Quinn connection input contract established that connection event time is monotonic, so production now uses the one-bound form; deliberately backdated callbacks remain a useful benchmark proof of which invalid input assumption enables the optimization.

The next cached-second attribution removes the remaining `rolling_timestamp.is_some()` guard. `reset_samples()` sets `next_rolling_second` to the same `now` that activates Brutal, so the first legal callback cannot satisfy `now < next_rolling_second`; after the first slow-path record, that comparison alone also proves the rolling timestamp is initialized. Twenty CPU-0-pinned independent-process pairs, split evenly across both execution orders, favored the rollover-only guard every time: the existing monotonic path was roughly **6.0-7.4 ns/event**, while the rollover-only path was roughly **5.5-6.9 ns/event**, typically a further **7-10%** isolated `record()` reduction. The production state therefore stores the rolling timestamp as a plain `u64` (zero before the first record) and uses only `now < next_rolling_second` on the hot path. A 50k-event monotonic loss trace plus an exact activation-time boundary test verify identical counters, slots, and ACK rate, without adding unsafe code, timers, locks, allocation, or protocol-visible behavior.

A follow-up attribution splits the overwhelmingly common ACK callback from the generic `(ack_count, loss_count)` record shape. On a cached second, an ACK can increment only the current slot's ACK counter and rolling ACK total; the generic path also carries zero-valued loss arguments and updates through the shared record shape. `BRUTAL_ON_ACK_BENCH_MODE=rollover-only|split-ack` runs the two production-shaped paths in separate processes while retaining the moving-RTT and current congestion-window arithmetic. Fourteen CPU-0-pinned paired runs, split across both execution orders, measured the generic path at roughly **10.1-13.1 ns/ACK** and the ACK-specialized path at roughly **7.1-9.0 ns/ACK**, with every pair favoring the specialization. Production therefore uses the specialized cached-second ACK update and falls back to the existing generic `record()` only at second rollover; congestion/loss events continue through the generic path unchanged. A 50k-event loss/rollover lifecycle test verifies identical slots, rolling totals, timestamp/slot selection, and ACK rate.

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

- `single`: one receive plus one send per relayed datagram;
- `mmsg`: `recvmmsg` plus `sendmmsg` with a configurable relay batch size;
- `--relay-model blocking`: original blocking-thread model;
- `--relay-model tokio`: nonblocking `tokio::net::UdpSocket` using
  `readable`/`writable` plus `try_io` and `MSG_DONTWAIT`, which mirrors the
  readiness contract a production Linux batching helper would need.

`--harness-batch-size` decouples the source/sink generator capacity from the
relay batch size. The Tokio model also uses a `Notify` wakeup when the bounded
inflight window fills instead of repeatedly `yield_now`-polling sink progress;
this matters because the busy-yield model could perform tens of millions of
scheduler yields in a 200k-packet run and dominate the relay being measured.
Reports include actual packets per receive/send syscall, bounded-window wait
events, whole-process CPU per million packets, and the CPU charged to the
thread calling `Runtime::block_on`. The latter deliberately excludes CPU spent
on Tokio worker/reactor threads, so whole-process CPU remains the end-to-end
cost metric.

Build and run correctness first:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml --bin udp_probe
bench/chimera_perf/target/release/udp_probe \
  --backend mmsg --relay-model tokio --worker-threads 8 \
  --packets 20000 --datagram-size 1200 \
  --batch-size 16 --harness-batch-size 64 --inflight-window 64 \
  --warmup 1 --runs 2 --verify
```

A September 2026 eight-worker comparison pinned to CPUs 0-7 used 300k
1200-byte datagrams/run, relay batch 16, harness batch 64, and the 64-packet
no-loss inflight window. Five measured runs were stable for both variants:
`single` delivered about **149.7k packets/s** with **14.92 CPU seconds per
million packets** (throughput CV 2.42%, CPU CV 2.39%), while `mmsg` delivered
about **167.1k packets/s** with **12.39 CPU seconds per million packets**
(throughput CV 1.19%, CPU CV 0.97%). That is roughly **+11.7% packet rate** and
**-16.9% whole-process CPU/Mpkt**. The batched relay carried about **15.4
packets per `recvmmsg`/`sendmmsg` call**. On a one-worker runtime, batching
showed a larger median gain, but the eight-worker result is the more useful
production-side bound because runtime/reactor CPU reduces the relative win.

A focused eight-worker 50k-packet `strace -f -c` with the same relay/harness
batch sizes counted about **282,146** tracked
`recvfrom/sendto/recvmmsg/sendmmsg/epoll_wait/epoll_ctl` calls for `single`
versus **40,161** for `mmsg` (about **-85.8%**). `epoll_wait` fell from about
82.3k to 16.5k calls. This confirms that the Tokio-ready batching model turns
its reduced datagram syscalls into materially fewer reactor waits rather than
merely moving work into userspace.

This remains benchmark-only. The socket-only result motivated the separate
production-shaped session probe below; do not wire `recvmmsg`/`sendmmsg` into
production from this result alone.

## Traffic recorder shard probe

`chimera_server_lib/tests/traffic_record_probe.rs` is an ignored release-mode
probe for the production `traffic` recorder. It compares the existing owned
`record_transfer(Some(context.clone()), ...)` call shape with the borrowed
`record_transfer_ref(Some(&context), ...)` shape while preserving the exact
snapshot delta for both `connections` and bytes. Writer threads live for the
whole warmup/measurement schedule and alternate clone/ref order by pair, which
mirrors long-lived Tokio worker threads more closely than spawning a new OS
thread for every sample.

Run it explicitly with the real main-workspace dependency graph:

```bash
CHIMERA_TRAFFIC_PROBE_WRITERS=4 \
CHIMERA_TRAFFIC_PROBE_TOTAL_RECORDS=10000000 \
CHIMERA_TRAFFIC_PROBE_WARMUP=3 \
CHIMERA_TRAFFIC_PROBE_RUNS=10 \
CHIMERA_TRAFFIC_PROBE_SHAPE=inbound-outbound \
taskset -c 0-7 cargo test -p chimera_server_lib --features traffic \
  --test traffic_record_probe --release \
  compare_owned_clone_and_borrowed_ref_recording -- \
  --ignored --exact --nocapture
```

The probe exposed a larger recorder-level contention source before the context
clone itself. The previous recorder performed a shared `AtomicUsize::fetch_add`
on **every traffic record** and then round-robined each record across all 32
`RwLock<StatsInner>` shards. With long-lived writers this makes every worker
bounce through the same atomic cache line and all shard lock/cache lines. The
production change assigns a shard once on first traffic activity in each OS
thread and reuses that shard thereafter. Tokio tasks may still migrate between
workers, but each synchronous record is written to the shard local to the
worker executing it; snapshots already merge every shard, so public totals are
unchanged.

A strict same-probe A/B was run by temporarily compiling the committed legacy
round-robin implementation and then restoring the thread-local implementation.
The realistic dokodemo context had an inbound and outbound tag and 1,200 bytes
per record. Legacy clone-mode CPU cost was **0.158566 / 0.195667 / 0.227842 CPU
seconds per million records** at 2/4/8 writers. Legacy CPU CVs were **0.86% /
0.70% / 2.64%**. With stable per-thread shards, clone-mode cost was **0.097692 /
0.114417 / about 0.120234** at 2/4/8 writers: roughly **-38.4% / -41.5% /
-47.2% CPU**. Corresponding record rates improved about **+62.9% / +57.3% /
+68.1%**. The new 2/4-writer CPU CVs were **1.70% / 2.62%**, within the 3%
acceptance threshold; the saturated 8-writer rerun remained noisy at about
5-6% CV, so the c8 magnitude is directional only. Single-writer measurements
before and after remained around 0.085-0.086 CPU seconds/Mrecord, with no
material regression visible.

The same probe also explains why removing `TrafficContext::clone` needed to be
a **separate** follow-up rather than bundled into the shard change. Under the
legacy round-robin recorder, borrowed recording helped at 2/4 writers but became
about 6% more CPU-expensive at 8 writers because faster callers simply hit the
shared recorder bottleneck sooner. After per-thread sharding, the stable
2/4-writer samples changed from **0.097692 -> 0.081434** and **0.114417 ->
0.090054 CPU seconds/Mrecord**, about **-16.6% / -21.3%**, with both clone and
borrowed CPU CVs below 3%. The 8-writer direction was also favorable (about
-18% CPU) but remained too noisy for an accepted magnitude. The follow-up
production change therefore replaces only the two per-datagram owned clones in
`run_freedom_udp_session` with `record_transfer_ref(Some(&traffic_context),
...)`. It preserves one recorder call per successful uplink/downlink datagram,
all byte and `connections` accounting, idle-reset timing, socket ordering, and
error behavior.

The remaining owned-clone hot call was the Shadowsocks UDP freedom uplink,
where the same context must survive for the later downlink record. The probe now
has a `shadowsocks` shape with protocol, identity, inbound tag, outbound tag,
and client IP. At 10 million records/sample with 3 warmup + 10 measured pairs,
2 writers changed from **0.174991 -> 0.150815 CPU seconds/Mrecord (-13.8%)**
and 4 writers from **0.192497 -> 0.167367 (-13.1%)**; both clone/ref CPU CVs
were below 3% in those accepted samples. The 8-writer direction was also
favorable (about -18% CPU) but remained noisy. Production therefore borrows the
context for only the successful Shadowsocks uplink record and still moves the
original context into the downlink record, preserving exactly one record per
successful direction and all existing socket/error ordering.

After the owned context clones were removed, the same full Shadowsocks shape
was used to attribute the remaining steady-state identity indexing cost. The
legacy `StatsInner::apply` checked `known_identities.contains(identity)` on
every record before performing the per-protocol identity-map lookup, so a hot
identity paid one redundant string hash even though an existing
`per_identity[protocol][identity]` entry already proves that identity was seen
on that shard. The optimized path makes `accumulate_string_key` report whether
it inserted the per-protocol identity and only checks/inserts
`known_identities` on that first insertion. A strict same-host A/B with 10
million records/sample and 3 warmup + 10 measured pairs reduced borrowed-ref
CPU cost from **0.149605 -> 0.134064 CPU seconds/Mrecord (-10.4%)** at 2 writers
and **0.166674 -> 0.146966 (-11.8%)** at 4 writers. Candidate CPU CVs were
**1.75% / 0.91%**; both legacy baselines were also below 3%. An identity-free
inbound+outbound c4 control showed no regression (**0.075768 -> 0.073670 CPU
seconds/Mrecord**), with both CVs below 3%; that small difference is treated
only as a no-regression check. A pre-registered identity spanning multiple
protocol maps is covered by a unit test so the public `known_identities` set,
per-identity totals, bytes, and record counts remain unchanged.

## UDP freedom session batching probe

`udp_session_probe` is a Linux-only follow-up that mirrors the hot structure of
`run_freedom_udp_session`: a bounded Tokio `mpsc` request channel, an idle
timer, an unbiased bidirectional `tokio::select!`, a connected outbound UDP
socket, and a second UDP send for responses. `single` keeps one datagram per
channel/socket operation. `mmsg` defaults to the original full-batching model,
but `--batch-path` can now isolate `uplink-only`, `downlink-recv-only`,
`downlink-send-only`, `downlink-full`, or `full`. `--uplink-batch-size` and
`--downlink-batch-size` override the legacy shared `--batch-size` while leaving
its old behavior unchanged when omitted. This makes it possible to attribute
channel draining, target `recvmmsg`, and response `sendmmsg` independently.
Batch sizes are bounded and reported explicitly; correctness tests verify
request/response payload boundaries, component isolation, split-size
validation, and the quiet-session idle timeout.

The external echo target and sink use batched blocking syscalls so they do not
intentionally become the measured hot path. A separate `--inflight-window`
(default 64, matching the production session channel capacity) throttles only
the source harness using sink progress. This is required for a no-loss
loopback comparison: without the harness window a 20k-packet single-session
smoke run could enqueue all 20k uplink packets but forward only about 13.4k
responses before the default UDP receive queue overflowed and the idle timer
expired. The window is therefore measurement scaffolding, not a proposed
production flow-control rule.

Build and verify both paths first:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin udp_session_probe
for backend in single mmsg; do
  taskset -c 0-7 bench/chimera_perf/target/release/udp_session_probe \
    --backend "$backend" --worker-threads 8 \
    --packets 100000 --datagram-size 1200 --batch-size 16 \
    --channel-capacity 64 --inflight-window 64 \
    --warmup 3 --runs 10 --verify
done
```

On the September 2026 host, the formal 3-warmup/10-run sample gave `single`
**78.4k packets/s** (CV **2.98%**) and **29.00 CPU seconds/Mpkt** (CV
**1.93%**). `mmsg-16` gave **86.0k packets/s** (about +9.6%) and **23.50 CPU
seconds/Mpkt** (about -19.0%), with average observed batch fill around **12.7
uplink packets** and **15.7 downlink packets** per socket call. However, the
batched run's packet-rate CV was **3.54%** and CPU CV **3.12%**, both just over
the repository's 3% acceptance threshold. A second ten-pair interleaved run
remained noisy for both backends (roughly 4.7% single and 6.0% mmsg packet-rate
CV), so the median speedup is not accepted as stable production evidence.

The fairness counters also reject one early concern but do not prove Internet
fairness: under the 64-packet no-loss harness both `single` and `mmsg-16`
reached a maximum steady outstanding count of 64 and a maximum steady
consecutive-uplink count of 64. In other words, the existing always-ready
channel plus unbiased `select!` can already fill the window one packet at a
time; batching did not worsen these particular extrema. More representative
latency/fairness testing would still be required before changing the real
session loop.

Syscall evidence is much stronger than wall-time evidence. A focused
50k-packet `strace -f -c` counted **424,418** tracked
`recvfrom/sendto/recvmmsg/sendmmsg/epoll_wait/epoll_ctl` calls for `single`
versus **64,433** for `mmsg-16` (about **-84.8%**). `epoll_wait` fell from
**135,711** to **31,278** calls (about **-77.0%**). This confirms that batching
still removes real network/reactor calls after adding the production-shaped
`mpsc`/timer/`select!` state machine.

The component follow-up shows that the full result is strongly **synergistic**
rather than the sum of three independent wins. In a same-binary 50k-packet
`strace -f -c` attribution, `single` made about **425,843** tracked network and
reactor calls. `uplink-only` made **384,095** (-9.8%), `downlink-recv-only`
**361,079** (-15.2%), `downlink-send-only` **330,146** (-22.5%), and
`downlink-full` **291,027** (-31.7%). Only coordinated `full` batching reached
about **66,123** calls (-84.5%). The corresponding 100k randomized component
matrix was too noisy for throughput claims (most absolute CPU/packet-rate CVs
were above 3%), but the mechanism counters were stable: uplink-only averaged
only about **1.62 packets/sendmmsg**, either isolated downlink component about
**2.8 packets/batched call**, and `downlink-full` still only about **2.77**.
`full` instead sustained roughly **12.7 uplink** and **15.8 downlink packets per
socket call**. Uplink bursting therefore creates the response burst that makes
the downlink batching efficient; there is no current evidence that one narrow
component can be enabled independently and retain most of the full benefit.

A split batch-size sweep narrows that coordination requirement. With downlink
fixed at 16, uplink batches of 2/4/8/16 produced roughly **5.0/8.9/14.0/15.75**
downlink packets per batched call. Focused 50k `strace` runs counted about
**172,020 / 104,806 / 74,209 / 66,596** tracked calls respectively. Relative
to the same `single` baseline, uplink=8/downlink=16 therefore captures roughly
**98% of the syscall reduction** achieved by 16/16, while bounding each uplink
channel drain at eight packets. This is a useful future fairness/semantics
candidate, not accepted throughput evidence: a formal 3-warmup/10-run 8/16
sample still had **5.6% packet-rate CV** and **3.85% CPU CV**, above the
repository threshold.

Keep all of this benchmark-only for now. The real freedom session also performs
traffic accounting, uses an unconnected outbound socket with response-address
validation, and sends responses through a server socket shared by multiple
sessions; this probe's response socket remains single-session and connected.
The decomposition now shows that the large syscall win requires coordinated
uplink and downlink batching, so a supposedly "small" production patch would
not retain most of the measured benefit.

## UDP shared response socket probe

`udp_shared_socket_probe` closes the largest remaining topology gap. It creates
multiple freedom-like session tasks, each with its own **unconnected** outbound
UDP socket and bounded request channel, while every session sends responses via
one shared **unconnected** server socket. All sessions use the same echo target
but distinct 127/8 client addresses, so the shared response socket exercises a
real destination address on every `sendto`/`sendmmsg`. The sink binds one
wildcard socket and decodes a session id plus per-session sequence number from
each payload. This makes response-address validation, per-session ordering,
completion spread, cross-session queue composition, and shared-socket write
readiness observable without modifying production.

The benchmark intentionally keeps cross-session send batching disabled: each
session may batch only its own responses. That matches the current production
task ownership model. A central worker would require transferring owned
response buffers between session tasks and would be a separate architecture,
not a drop-in syscall replacement. The probe reports this explicitly as
`shared_send_cross_session_batching=false`.

Build and verify the production-shaped paths with a conservative aggregate
window first:

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin udp_shared_socket_probe
for backend in single mmsg; do
  taskset -c 0-7 bench/chimera_perf/target/release/udp_shared_socket_probe \
    --backend "$backend" --worker-threads 8 \
    --sessions 16 --packets-per-session 4096 --datagram-size 1200 \
    --inflight-window 16 --uplink-batch-size 8 --downlink-batch-size 16 \
    --warmup 2 --runs 5 --verify
done
```

The fixed-total 65,536-packet c1/c16/c64 sweep shows that the single-session
result does **not** survive realistic session concurrency. With one session,
8/16 batching still averaged about **7.13 uplink packets**, **8.81 downlink
packets**, and **8.81 shared-send packets per socket call**. The session data
path therefore fell from 196,608 measured socket attempts to about **24,070**
(roughly **-87.8%**). The corresponding CPU median fell from about **33.46** to
**28.03 CPU seconds/Mpkt**, but the batched CPU CV was **3.10%** and packet-rate
CV **4.41%**, just outside the repository stability gate, so that wall-time
improvement remains directional rather than accepted production evidence.

At 16 sessions the batching opportunity collapses. `single` measured about
65,536 uplink attempts, 69,212 response receive attempts (including EAGAIN
retries), and 65,536 shared sends: **200,284** session data-path socket
attempts. The 8/16 path measured about 57,579 / 60,605 / 56,287 respectively:
**174,471**, only about **-12.9%**. Average useful fill was just **1.14 uplink**,
**1.08 response receive**, and **1.16 shared-send packets per call**. CPU was
stable enough to reject the candidate on cost: **25.70 -> 27.69 CPU
seconds/Mpkt** (about **+7.7%**, batched CPU CV **1.91%**). Packet-rate CV for
the batched sample was **3.76%**, so no throughput claim is accepted.

At 64 sessions the result is the same. `single` used about **200,721** measured
session socket attempts versus **169,614** for 8/16 (about **-15.5%**), while
useful fill remained only **1.18 uplink**, **1.11 response receive**, and
**1.20 shared-send packets per call**. CPU rose from **25.46** to **27.08 CPU
seconds/Mpkt** (about **+6.3%**); both CPU CVs were below 3%. Packet-rate medians
were essentially equal, but their CVs were above 3%, so the stable conclusion
is increased CPU cost for a modest syscall reduction, not a throughput win.

The shared socket itself did not show write-readiness pressure in these runs:
`shared_send_would_block` stayed at **zero** for c1, c16, and c64. The lost
batching therefore comes primarily from per-session scheduling and independent
outbound receive queues, not from the shared server socket becoming
non-writable. Fairness counters also showed no obvious starvation under the
16-packet per-session harness window: c16/c64 both kept the longest observed
single-session run at 16 packets, and completion spread remained a small
fraction of total run time. These are loopback mechanism checks, not WAN
latency/fairness proof.

Cross-session queue composition argues against immediately adding a central
send worker. In focused c16/c64 samples, the wildcard sink received only about
**1.48-1.52 packets per `recvmmsg` batch** and roughly **1.46 distinct sessions
per batch** on average, despite occasional maxima of 12-17 sessions. In other
words, the kernel queue usually exposes only about one and a half packets at a
time. A central worker could not approach a 16-packet batch without deliberately
waiting to coalesce traffic, which would introduce a new latency/fairness
policy that current Xray-compatible semantics do not have.

A traced c16/c64 run did show substantially fewer total network/reactor calls
under mmsg, but `strace` slowed scheduling enough to inflate observed batch fill
from roughly 1.1 untraced to around 4 packets/call. Treat those traced totals as
syscall attribution only, not as representative batching efficiency or
throughput evidence. The probe's own nonblocking attempt counters are the
preferred untraced mechanism metric.

Correctness coverage includes both backends over multiple concurrent sessions,
per-session payload/sequence verification through the shared wildcard sink,
distinct loopback client destinations, response-source validation, a real
multi-destination `sendmmsg` roundtrip, and a deterministic partial-send offset
test proving that a short batch send resumes at the first unsent datagram and
rejects zero/overrun progress.

**Production decision:** keep `run_freedom_udp_session` unchanged. Per-session
8/16 mmsg loses most of its batching at c16/c64 and costs about 6-8% more CPU in
the stable samples. A central cross-session worker is also not justified by the
observed queue depth without adding deliberate coalescing delay. Any future UDP
work should first find a workload where naturally available multi-session
queue depth is materially larger, or move to a different measured hotspot,
rather than introducing batching policy into the Xray-compatible data path.
