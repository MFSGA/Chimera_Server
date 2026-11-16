# HY2 Brutal pacing alignment and official baseline (2026-11-16)

**Status: local candidate evidence; independent review pending. No remote push or deployment.**

## Scope

The candidate started from `codex/hy2-brutal-pacing-clean-20261114` at
`5454718b9ff9c40253d1345a8f7a41625883e274` (base
`35f970d9f5fd687e3191b2fa5d08984fed928df9`). The only source change in this
follow-up is the fixed-rate pacer's minimum-capacity wake deadline:

- At the minimum 10-datagram bucket, schedule the next datagram's byte budget,
  with Xray's 1 ms minimum pacing interval. This removes the 3 ms delay at
  2,000,000 B/s while retaining the existing 75% early-wake policy for larger
  buckets.
- `fixed_rate_minimum_capacity_wake_matches_xray_packet_delay` checks 65,536
  and 2,000,000 B/s. The former expects the 1200-byte budget interval; the
  latter expects Xray's 1 ms minimum.

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
  282 passed. The vendor package is tested from a temporary copy because its
  manifest is excluded from the root Cargo workspace.
- Quinn and server-library Clippy checks with warnings denied: passed.
- Optimized server application build with `--release --locked --offline`:
  passed.
- Local loopback requests used full content verification. No UDP socket drops
  were observed in the measurements below.

## Xray Brutal client: official server vs Chimera server

The same Xray 26.11.9 client was used against official Hysteria 2.14.0 and the
native Chimera Hysteria2 inbound. Both endpoints used Brutal hints at the same
rate; the Chimera server used native QUIC mode and 8 MiB stream / 20 MiB
connection receive windows. The official server used the client's advertised
rate, as specified by its bandwidth negotiation behavior.

| Configured rate | Payload / measured runs | Official up / down Mbps | Chimera up / down Mbps | Chimera vs official |
|---:|---:|---:|---:|---:|
| 1 Mbps | 1 MiB / 1 | 0.992 / 0.993 | 0.989 / 0.995 | -0.3% / +0.2% |
| 16 Mbps | 4 MiB / 3 | 15.713 / 15.753 | 15.667 / 15.771 | -0.3% / +0.1% |
| 60 Mbps | 4 MiB / 3 | 59.065 / 59.211 | 58.945 / 57.512 | -0.2% / -2.9% |

The three rate-limited Brutal cases are within 3% of the official server on this
loopback test. They show Xray interoperability and that the configured rates
are respected. They do not establish maximum throughput because each case is
rate-limited.

## BBR single-flow and concurrent loopback baseline

The same official Hysteria client was used against the official server and
native Chimera server, with 8 MiB / 20 MiB receive windows. Each row is the
median of three full-checksum runs. The 8-flow case uses 32 MiB per flow.

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
  was captured in this follow-up.
- A short `perf` sample points to QUIC packet population and memory movement in
  the Chimera server path, but is not sufficient to establish the root cause.
  The BBR download gap needs a longer profile and a profile-guided change before
  it can be considered resolved.
