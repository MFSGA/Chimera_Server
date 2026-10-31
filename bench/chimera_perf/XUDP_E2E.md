# Xray client to Chimera Global XUDP end-to-end probe

This manually triggered Linux integration test measures real Xray VLESS/XUDP
traffic through a release Chimera server and a local UDP echo target. It reports
roundtrips per second, client-visible RTT p50/p99, process CPU time, current RSS,
and each process's `/proc` high-water RSS. The local UDP echo endpoint also
counts received and successfully echoed datagrams to help localize missing
responses. The echo endpoint attributes receive and echo counts to the tagged
run id in each payload, so delayed traffic from an earlier run cannot inflate a
later run's target counters. Every response is checked for source, session id,
sequence, length, and payload contents. A duplicate or unexpected response for
the current run, or a malformed or corrupted response, fails the sample. Delayed
responses tagged with an earlier run are counted as stale and ignored. If a session receives no
response for one second, that session stops and the sample reports how many
packets were sent without a response and how many offered packets were never
sent. `response_timeout_packets` means no response arrived within this local
one-second inactivity window; it does not by itself prove where a packet was
dropped. Goodput counts received roundtrips only. The record reports both the
rate from the first successful UDP send through the last received reply and the
wall-clock rate from the synchronized run start through task completion,
including any one-second timeout wait. This keeps task creation out of the
active rate while preserving missing-response time in the end-to-end rate.

The probe uses VLESS over TCP without TLS/REALITY, Xray's SOCKS UDP inbound,
`xudpConcurrency: 4`, and a Freedom rule limited to the test's loopback UDP echo
port. RTT includes the local SOCKS client, both processes, the local socket path,
and Tokio scheduling; it is not a WAN latency estimate. The test measures steady
state after opening the SOCKS UDP associations and sending warmup datagrams. It
reuses the same associations across runs. Run-tagged payloads let the probe
discard and count delayed responses from an earlier run without mixing them
into the current sample. It does not measure GlobalID reconnect/expiry or
production routing over a remote network.

Build the release server and run the ignored test:

```bash
cargo build --release -p chimera_server_app
CHIMERA_XUDP_E2E_SESSIONS=16 \
CHIMERA_XUDP_E2E_PACKETS_PER_SESSION=2048 \
CHIMERA_XUDP_E2E_DATAGRAM_SIZE=1200 \
CHIMERA_XUDP_E2E_INFLIGHT_WINDOW=4 \
CHIMERA_XUDP_E2E_WARMUP_PACKETS=16 \
CHIMERA_XUDP_E2E_RUNS=5 \
cargo test -p chimera_server_app \
  --test xray_client_proxy_e2e \
  xray_client_global_xudp_end_to_end_perf_probe \
  -- --ignored --exact --nocapture
```

The test uses `./xray` by default. Set `XRAY_BIN` to select another binary; the
actual client version is printed with the results. Set `CHIMERA_BIN` to select
another release server binary. Without it, the test uses
`target/release/chimera_server_app`.

Available workload variables are:

| Variable | Default | Accepted range |
| --- | ---: | ---: |
| `CHIMERA_XUDP_E2E_SESSIONS` | 16 | 1–128 |
| `CHIMERA_XUDP_E2E_PACKETS_PER_SESSION` | 2048 | 1–`u32::MAX` |
| `CHIMERA_XUDP_E2E_DATAGRAM_SIZE` | 1200 | 8–4096 bytes |
| `CHIMERA_XUDP_E2E_INFLIGHT_WINDOW` | 4 | 1–256 |
| `CHIMERA_XUDP_E2E_WARMUP_PACKETS` | 16 | 0 or greater |
| `CHIMERA_XUDP_E2E_RUNS` | 5 | 1–20 |

Run one workload at a time and keep the host, CPU affinity, Xray version,
release binary, and variables identical when comparing revisions. The current
RSS fields are sampled at each run boundary; `peak_rss_kib` is the process
high-water mark since startup, not a per-run peak. CPU percentage is normalized
to one core and can exceed 100% when a process uses multiple cores. The JSON
record includes `offered_packets`, `sent_packets`,
`received_packets`, `response_timeout_packets`, and `not_sent_packets`, plus
`echo_target_received_packets` and `echo_target_echoed_packets`,
`stale_response_packets`, `received_roundtrips_per_active_second`, and
`wall_received_roundtrips_per_second`. Compare the packet counts alongside the
rates so a higher rate is not mistaken for an improvement when it comes with
more missing responses.

## Measured in-flight window sweep

On 2026-10-31, I swept `CHIMERA_XUDP_E2E_INFLIGHT_WINDOW` across 1, 2, 3, 4,
5, 6, 8 and 16. Each setting used 16 SOCKS UDP associations, 2,048 offered
1200-byte datagrams per association, 16 warmup packets and five measured runs.
Xray Mux and `xudpConcurrency` were both 4. Rates and RTT columns are medians
of the five per-run measurements; rates count received roundtrips only.

| Window | Active roundtrips/s | RTT p50 / p99 (µs) | Delivery across five runs |
| ---: | ---: | ---: | --- |
| 1 | 54.7k | 272 / 594 | 32,768/32,768 in every run |
| 2 | 72.7k | 411 / 888 | 32,768/32,768 in every run |
| 3 | 80.2k | 561 / 1,192 | 32,768/32,768 in every run |
| 4 | 84.7k | 720 / 1,471 | 32,768/32,768 in every run |
| 5 | 81.1k | 830 / 1,639 | 32,761–32,763 received; 5–7 response timeouts/run |
| 6 | 74.1k | 821 / 1,594 | 32,747–32,748 received; 20–21 response timeouts/run |
| 8 | 60.4k | 764 / 1,646 | 30,705–32,715 received; 51–55 timeouts and 0–2,009 unsent/run |
| 16 | 71.8k | 708 / 1,810 | 28,546–32,588 received; 177–181 timeouts and 0–4,041 unsent/run |

Window 4 had the highest median rate among the tested zero-loss settings,
about 5.5% above window 3. Window 5 was slower and had a small number of
missing responses; windows 6–16 increased timeout and unsent counts. In every
sample, per-run echo received and echoed counts matched the client-received
count. This is consistent with request-side losses before the echo target, but
aggregate counters cannot locate each missing packet: a lost request and a lost
reply could offset each other. The benchmark's one-second
per-session inactivity timeout also lowers wall-clock completion rate when any
reply is missing: the median was about 23.3k/s at window 5, 22.7k/s at 6,
21.2k/s at 8 and 20.5k/s at 16. Read active rates together with delivery and
wall-clock rates.

Environment: Linux 6.18.35 x86_64, AMD Ryzen 7 5800 (8 cores / 16 threads,
boost enabled), loopback networking, no CPU affinity set; Xray client 26.9.9
Custom (`go1.27rc2 linux/amd64`, source commit not identified) and the Chimera
release binary (package 26.10.26).
The repository was at HEAD `974d72a` with a dirty worktree. This is a local
synthetic workload, not a remote-network capacity result or a before/after
comparison of server code.

## Measured session-count sweep

On 2026-10-31, I held the in-flight window at 4 and swept the number of
long-lived SOCKS UDP associations across 1, 4, 16, 32 and 64. Each association
offered 8,192 1200-byte datagrams after 16 warmup packets, with three measured
runs per setting. `xudpConcurrency` remained 4. Rates and RTTs below are
medians across the three runs; active rate counts received roundtrips from the
first successful send through the last received reply. Delivery is shown as
the per-run received-count range over the constant offered count.

| Sessions | Active roundtrips/s | RTT p50 / p99 (µs) | Delivery | Median unsent / timeouts |
| ---: | ---: | ---: | --- | ---: |
| 1 | 25.4k | 152 / 262 | 8,192/8,192 in every run | 0 / 0 |
| 4 | 42.3k | 366 / 659 | 32,768/32,768 in every run | 0 / 0 |
| 16 | 82.8k | 743 / 1,459 | 131,072/131,072 in every run | 0 / 0 |
| 32 | 62.1k | 780 / 1,841 | 204,830–213,459 of 262,144 | 56,163 / 56 |
| 64 | 66.1k | 758 / 1,839 | 256,606–304,175 of 524,288 | 229,220 / 184 |

Throughput increased through 16 sessions, then fell at 32 and did not recover
at 64. At 32 and 64 sessions, the Xray client left a substantial portion of
the offered datagrams unsent; the remaining sent datagrams also had 55–186
one-second response timeouts per run. Thus these higher-session rows measure
the combined Xray client, local loopback and Chimera path under overload, not
server capacity in isolation. They do not establish that the server itself
dropped every missing datagram. RTT p99 also rose from 1.46 ms at 16 sessions
to about 1.84 ms at 32/64. Increasing session count beyond 16 is not beneficial
for this exact client configuration and workload; larger-scale conclusions
require a client with enough send capacity and separate client/server resource
profiling.

The setup was unchanged from the window sweep above: Linux 6.18.35 x86_64,
AMD Ryzen 7 5800 (8 cores / 16 threads, boost enabled), loopback networking,
no CPU affinity, Xray 26.9.9 Custom (`go1.27rc2 linux/amd64`, source commit not
identified) and the Chimera release binary (package 26.10.26). Each run reused
its SOCKS UDP associations. The repository was at HEAD `974d72a` with a dirty
worktree. This is a synthetic single-host result, not a WAN capacity result or
a before/after code comparison.

## Repeated session-count sweep with Xray v26.10.29

I repeated the session-count workload on 2026-10-31 with the current official
Xray release, v26.10.29. The Linux x86-64 release archive was downloaded from
the XTLS/Xray-core GitHub release and verified against its published SHA-256:
`8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2`. The
server binary, machine, and workload stayed the same as in the preceding sweep:
8,192 1200-byte datagrams per session, 16 warmup packets, in-flight window 4,
`xudpConcurrency: 4`, and three measured runs. The comparison is to the
preceding unpinned runs with the local v26.9.9 Custom binary; active rates and
RTTs are medians across three runs.

| Sessions | v26.9.9 Custom active rate | v26.10.29 active rate | Rate change | v26.10.29 RTT p50 / p99 (µs) | v26.10.29 delivery; median unsent / timeouts |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 25.4k/s | 20.5k/s | −19.0% | 189 / 325 | 8,192/8,192 in every run; 0 / 0 |
| 4 | 42.3k/s | 33.3k/s | −21.3% | 453 / 1,098 | 32,768/32,768 in every run; 0 / 0 |
| 16 | 82.8k/s | 68.9k/s | −16.8% | 862 / 1,861 | 131,072/131,072 in every run; 0 / 0 |
| 32 | 62.1k/s | 57.0k/s | −8.2% | 840 / 1,924 | 204,843–237,618 of 262,144; 32,740 / 58 |
| 64 | 66.1k/s | 64.2k/s | −2.9% | 774 / 2,059 | 240,943–286,885 of 524,288; 278,269 / 186 |

With v26.10.29, all offered packets completed at 1, 4 and 16 sessions. At 32
and 64 sessions, the client still failed to send all offered packets and the
probe saw response timeouts. In these unpinned samples, v26.10.29 had lower
median rates than the local v26.9.9 Custom binary at every tested session
count. The controlled interleaved comparison below did not reproduce that
ordering. These first samples therefore do not establish a release regression;
they confound client artifact, Go toolchain, CPU placement and sequential run
variation. Larger-load server conclusions still need a client generator with
independently demonstrated send capacity.

Reproduce one row with the verified v26.10.29 binary by setting `XRAY_BIN` to
its path:

```bash
XRAY_BIN=/path/to/xray \
CHIMERA_XUDP_E2E_SESSIONS=16 \
CHIMERA_XUDP_E2E_PACKETS_PER_SESSION=8192 \
CHIMERA_XUDP_E2E_DATAGRAM_SIZE=1200 \
CHIMERA_XUDP_E2E_INFLIGHT_WINDOW=4 \
CHIMERA_XUDP_E2E_WARMUP_PACKETS=16 \
CHIMERA_XUDP_E2E_RUNS=3 \
cargo test -p chimera_server_app \
  --test xray_client_proxy_e2e \
  xray_client_global_xudp_end_to_end_perf_probe \
  -- --ignored --exact --nocapture
```

Change only `CHIMERA_XUDP_E2E_SESSIONS` to repeat the other rows. This run used
the same Linux 6.18.35 / Ryzen 7 5800 host and Chimera release binary (package
26.10.26) as the previous sweep; repository HEAD was `974d72a` with a dirty
worktree.

## Interleaved, CPU-pinned client comparison

To check whether the earlier apparent drop was a client-version regression, I
ran one-sample invocations at 16 sessions under the same `taskset -c 0-7`
affinity, interleaving binaries to reduce time-order bias. The rest of the
workload was unchanged: 8,192 1200-byte datagrams per session, window 4,
16 warmup packets, and `xudpConcurrency: 4`; every invocation used the same
Chimera release binary. Each comparison had three samples per binary and all
samples delivered 131,072/131,072 packets with zero unsent packets or response
timeouts.

The official [v26.9.9 prerelease](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9)
archive was verified against SHA-256
`1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df`; its
binary reports commit `52a412d` and Go 1.27.1. Official v26.10.29, recorded
above, reports commit `0afec66` and Go 1.27.3. The older workspace `./xray`
reports `26.9.9 Custom (go1.27rc2 linux/amd64)` but does not identify its source
commit.

| Pair and order | First client: active rate range (median), RTT p50 / p99 | Second client: active rate range (median), RTT p50 / p99 | Second vs first |
| --- | --- | --- | ---: |
| Official 26.9.9 / 26.10.29; A/B/B/A/A/B | 77.0–79.4k/s (77.2k/s), 768 / 1,831 µs | 81.6–83.8k/s (82.6k/s), 731 / 1,620 µs | +7.1% |
| Local custom 26.9.9 / official 26.10.29; C/B/B/C/C/B | 77.8–79.9k/s (79.1k/s), 764 / 1,735 µs | 82.1–83.0k/s (82.5k/s), 730 / 1,648 µs | +4.4% |

In this controlled sample, the v26.10.29 client was faster than both older
artifacts, reversing the ordering seen in the earlier unpinned sequential
three-run sweep. The earlier result is therefore not evidence that the newer
Xray release is slower. The older custom binary's unidentified source and the
different CPU placement prevent attributing the reversal to one specific
factor; broader performance claims still require more repetitions and separate
client/server profiling.

For reproduction, run the same test once per invocation with
`CHIMERA_XUDP_E2E_RUNS=1` and `taskset -c 0-7 env XRAY_BIN=<binary>`, changing
only the client path in the balanced order recorded in the table. These
measurements are pinned to CPU IDs 0–7 and should not be compared directly with
the earlier unpinned tables.
