# HY2 Brutal pacing alignment and official baseline (2026-11-16)

**Status: exact-source loopback evidence captured; independent review pending. No remote push or deployment.**

## Scope

The measured Chimera release binary was built from clean source commit
`9d7087b0de9273699161ee2d92708998d4f94d63` on top of
`35f970d9f5fd687e3191b2fa5d08984fed928df9`. Its BLAKE3 is
`c799642d49323abdc09e89145c45bb8b2d29133863cdee3eb0f3ef007efeaf2d`.
The fixed-rate pacer's minimum-capacity deadline now follows Xray's send-time
anchor:

- At the minimum 10-datagram bucket, schedule the next MTU budget from the
  latest transmitted packet, with Xray's 1 ms minimum. ACK and timer callbacks
  account partial credit without moving that deadline. Larger buckets retain
  the existing 75% early-wake policy.
- `fixed_rate_minimum_capacity_wake_matches_xray_packet_delay` checks 65,536
  and 2,000,000 B/s, including an ACK callback at `t0 + 500 µs`, the original
  deadline, and the next deadline after a send.

The first candidate revision's midpoint-callback test exposed a 500 µs
deadline extension. That revision was not merged. The report's earlier
unbound 1/16/60 Mbps candidate measurements are superseded by the fresh
measurements below.

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
- Isolated `vendor/quinn-proto` library tests against the exact working source:
  282 passed and 3 documentation tests passed. The vendor package is tested
  from a temporary copy because it is not a root workspace member.
- Isolated Quinn Clippy with default features and warnings denied: passed.
  Isolated `--all-features` Clippy could not build the optional AWS-LC FIPS
  dependency because the temporary environment has no Make executable.
- `cargo clippy -p chimera_server_lib --all-targets --all-features --locked
  --offline -- -D warnings`: passed.
- Optimized server application build with `--release --locked --offline`:
  passed.
- Fresh local loopback requests used Xray 26.11.9 and full content verification.
  Every measured run completed with the expected upload and download byte
  counts. The generator metadata records the exact source SHA and a clean
  worktree; the server binary hash is listed above.

## Xray Brutal client: official server vs Chimera server

The same Xray 26.11.9 client was used against official Hysteria 2.14.0 and the
native Chimera Hysteria2 inbound. Both endpoints used Brutal hints at the same
rate; the Chimera server used native QUIC mode and 8 MiB stream / 20 MiB
connection receive windows. The official server used the client's advertised
rate, as specified by its bandwidth negotiation behavior. Runs alternated
which server was tested first by rate. Each case used one warmup, full payload
verification, one measured run at 1 Mbps and three measured runs at 16/60 Mbps.

| Configured rate | Payload / measured runs | Official up / down Mbps | Chimera up / down Mbps | Chimera vs official |
|---:|---:|---:|---:|---:|
| 1 Mbps | 1 MiB / 1 | 0.992 / 0.993 | 0.989 / 0.995 | -0.30% / +0.20% |
| 16 Mbps | 4 MiB / 3 | 15.711 / 15.747 | 15.667 / 15.764 | -0.28% / +0.11% |
| 60 Mbps | 4 MiB / 3 | 58.961 / 59.200 | 58.959 / 56.973 | -0.00% / -3.76% |

All three rate-limited cases are within 4% of the official server on this
loopback test. They show Xray interoperability and that the configured rates
are respected. They do not establish maximum throughput because each case is
rate-limited. The 60 Mbps download is the largest observed gap.

## BBR single-flow and concurrent loopback baseline

The same official Hysteria client was used against the official server and
native Chimera server, with 8 MiB / 20 MiB receive windows. Each row is the
median of three full-checksum runs. The 8-flow case uses 32 MiB per flow.
These exploratory BBR logs record an unavailable source commit (`c450cf8…`)
and are not bound to the exact `9d7087b` release binary above. Treat them as a
direction for further profiling, not as final-SHA performance evidence.

| Flows | Server | Upload Mbps | Download Mbps |
|---:|---|---:|---:|
| 1 | Official Hysteria 2.14.0 | 4469 | 4532 |
| 1 | Chimera Server candidate | 5219 | 3310 |
| 8 | Official Hysteria 2.14.0 | 4268 | 4340 |
| 8 | Chimera Server candidate | 5862 | 2757 |

The Chimera server's BBR download was 27% below the official server in the
single-flow case and 36% below in the 8-flow case. Upload exceeded the official
server in both cases. This BBR path is separate from the fixed-rate Brutal
override changed here, but the observed download gap is a clear follow-up
optimization target. These are local loopback results, not BSY or WAN results;
the run order was not fully interleaved, so the percentages are preliminary.

## Remaining evidence gaps

- The repository netem harness did not produce valid measurements: both its
  BBR and Brutal runs reset while reading the benchmark sync byte after auth.
  It must be repaired or replaced before reporting RTT/loss results.
- No BSY or other WAN comparison, download p95, or multi-client fairness result
  was captured in this follow-up. The ≤10% goal is met only for these
  rate-limited loopback cases; it has not been established for WAN or BBR
  maximum-throughput traffic.
- A short `perf` sample points to QUIC packet population and memory movement in
  the Chimera server path, but is not sufficient to establish the root cause.
  The BBR download gap needs a longer profile and a profile-guided change before
  it can be considered resolved.
