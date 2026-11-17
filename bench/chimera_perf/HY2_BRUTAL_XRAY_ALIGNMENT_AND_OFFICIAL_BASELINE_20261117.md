# HY2 Brutal pacing alignment and official baseline (2026-11-17)

**Status: loopback evidence captured. No remote push or deployment.**

## Scope

The rate-limited Chimera release binary was built from clean source commit
`4dbe6286b5113c24179fd6cee1ffb11eb81195e0`, based on
`35f970d9f5fd687e3191b2fa5d08984fed928df9`. Its BLAKE3 is
`db8a19530fc126270bc412602047dc660704c0ec6544ecffdd11640df879ab1c`.
The fixed-rate pacer's minimum-capacity path now follows Xray's budget and
send-eligibility rules:

- At the minimum 10-datagram bucket, recompute budget from the latest send
  using the current rate during pacing checks and actual transmission, including
  PTO/loss-probe sends that bypass `delay()`. A stale timestamp cannot move the
  send anchor backward.
- If the current budget can send an MTU-sized packet, send immediately. When
  the budget is short, schedule from the last-send anchor and apply Xray's 1 ms
  minimum timer delay. Larger buckets retain the existing 75% early-wake policy.
- `fixed_rate_minimum_capacity_wake_matches_xray_packet_delay` checks 65,536
  and 2,000,000 B/s, including an ACK callback at `t0 + 500 µs`, the original
  deadline, and the next deadline after a send.
- Additional tests cover ACK-rate increases and decreases, budget becoming
  ready before 1 ms, PTO/loss-probe sends without a preceding pacing check, and
  stale send timestamps.

The first candidate revision's midpoint-callback test exposed a 500 µs
deadline extension. That revision was not merged. The report's earlier
measurements are superseded by the exact-source five-run measurements below.

This aligns the minimum-capacity fixed-rate path; it does not make every Quinn
pacing path identical to Xray. Quinn preserves the handshake's remaining
initial tokens, uses different pacing accounting for pure ACK packets, and
keeps its existing batching policy above the minimum bucket.

Reference implementations used:

- Xray Core 26.11.9, build `f781c68`.
- Official Hysteria 2.14.0, commit
  `c2b181e0b0e72b077e4b0b7297735af14d1f9929`, quic-go
  `v0.65.1-0.20261109005002-2895f039137a`.
- The fixed-rate minimum interval is 1 ms in the pinned Xray quic-go reference.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo test -p chimera_server_lib --lib --locked --offline`: 1708 passed,
  6 ignored.
- Isolated `vendor/quinn-proto` tests against the exact source: 287 library
  tests and 3 documentation tests passed. The vendor package is tested from a
  temporary copy because it is not a root workspace member.
- Isolated Quinn Clippy with default features passed with
  `-D warnings -A clippy::manual_filter`; without the specific allowance it
  reports an existing `manual_filter` lint in `packet_crypto.rs`. Isolated
  `--all-features` Clippy could not build the optional AWS-LC FIPS dependency
  because the temporary environment has no Make executable.
- `cargo clippy -p chimera_server_lib --all-targets --all-features --locked
  --offline -- -D warnings`: passed.
- Optimized server application build with `--release --locked --offline`:
  passed.
- Fresh local loopback requests used Xray 26.11.9, one warmup and five measured
  runs per case, with full content verification. Generator metadata records
  source SHA `4dbe6286…` and a clean worktree; the server binary hash is listed
  above.

## Xray Brutal client: official server vs Chimera server

The same Xray 26.11.9 client was used against official Hysteria 2.14.0 and the
native Chimera Hysteria2 inbound. Both endpoints used Brutal hints at the same
rate; the Chimera server used native QUIC mode and 8 MiB stream / 20 MiB
connection receive windows. The official server used the client's advertised
rate, as specified by its bandwidth negotiation behavior. The test alternated
which server ran first by configured rate. Each case used one warmup and five
measured runs. Payloads were 1 MiB at 1 Mbps and 4 MiB at 16/60 Mbps; all
measured uploads and downloads passed full verification.

| Configured rate | Official up / down Mbps (CV) | Chimera up / down Mbps (CV) | Chimera vs official, up / down |
|---:|---:|---:|---:|
| 1 Mbps | 0.992 / 0.993 (0.0% / 0.0%) | 0.989 / 0.994 (0.0% / 0.1%) | -0.30% / +0.10% |
| 16 Mbps | 15.706 / 15.749 (0.0% / 0.0%) | 15.668 / 15.768 (0.0% / 0.1%) | -0.24% / +0.12% |
| 60 Mbps | 59.015 / 59.146 (0.1% / 0.1%) | 58.848 / 57.080 (0.1% / 0.4%) | -0.28% / -3.49% |

All three rate-limited cases are within 4% of the official server on this
loopback test. They show Xray interoperability and that the configured rates
are respected. They do not establish maximum throughput because each case is
rate-limited. The 60 Mbps download is the largest observed gap. Raw logs are
in `/tmp/chimera-server-merge-check-20261116-ratefix/final-4dbe628-xray-rates/`.

## Historical exact-binary BBR single-flow and concurrent loopback comparison

The same official Hysteria 2.14.0 client was used against the official
Hysteria 2.14.0 server and a Chimera server binary built from source commit
`9d7087b0de9273699161ee2d92708998d4f94d63` (BLAKE3
`c799642d49323abdc09e89145c45bb8b2d29133863cdee3eb0f3ef007efeaf2d`). These
BBR runs predate the `4dbe628` fixed-rate pacing change; the BBR path has no
fixed-rate override, but BBR was not rerun on the final binary. Benchmark
metadata records a clean generator tree at `1d385923` (a documentation-only
descendant of `9d7087b`). Each case used one warmup and five measured runs,
full payload verification and 65,536-byte buffers. Single-flow cases
transferred 128 MiB per direction per run; eight-flow cases transferred 32 MiB
per flow per direction. The host was pinned to CPUs 6-7. Server groups ran
sequentially rather than interleaved, so environmental drift remains a
limitation.

| Flows | Server | Upload median Mbps (CV) | Download median Mbps (CV) | Chimera vs official, up / down |
|---:|---|---:|---:|---:|
| 1 | Official Hysteria 2.14.0 | 2498.795 (2.2%) | 2379.739 (1.9%) | — |
| 1 | Chimera Server candidate | 3447.802 (2.0%) | 827.067 (62.6%) | +38.0% / -65.2% |
| 8 | Official Hysteria 2.14.0 | 2397.510 (1.3%) | 2303.834 (1.5%) | — |
| 8 | Chimera Server candidate | 3566.070 (2.6%) | 2065.676 (1.6%) | +48.7% / -10.3% |

All measured payloads passed full verification. Chimera single-flow download
rates fell across the five samples (1817.596, 846.241, 827.067, 470.468,
460.600 Mbps), which requires a repeatable longer profile before attributing
the behavior to a specific code path. In the eight-flow case, upload exceeded
the official server while download was 10.3% lower. This BBR path is separate
from the fixed-rate Brutal override changed here. It does not meet the ≤10%
target for maximum-throughput BBR traffic and is a follow-up optimization
target. Raw logs are in
`/tmp/chimera-server-merge-check-20261116-reviewfix/bbr-exact-9d7087-5runs/`.

## Remaining evidence gaps

- The repository netem harness did not produce valid measurements: both its
  BBR and Brutal runs reset while reading the benchmark sync byte after auth.
  It must be repaired or replaced before reporting RTT/loss results.
- No BSY or other WAN comparison, download p95, or multi-client fairness result
  was captured in this follow-up. The ≤10% goal is met for the tested
  rate-limited loopback cases, but not for the exact-source BBR maximum-
  throughput comparison above, and has not been established on WAN links.
- A short `perf` sample points to QUIC packet population and memory movement in
  the Chimera server path, but is not sufficient to establish the root cause.
  The BBR download gap needs a longer profile and a profile-guided change before
  it can be considered resolved.
