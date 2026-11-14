# HY2 Brutal Pacer: idle-credit burst and rapid rate changes (2026-11-14)

**Status: L3 HOLD — isolated candidate; Rust unit/Clippy/real network verification pending. Do not merge, push or deploy.**

## Owner and problem

- Owner: vendored quinn-proto 0.11.14 Pacer, vendor/quinn-proto/src/connection/pacing.rs. Prior candidate tip 1bec917 carries fractional nanobytes.
- Source-derived defect: Pacer::delay returned early when tokens >= bytes_to_send without settling elapsed time. With a full bucket at t0, after 1 second idle an initial 10-MTU burst could be sent with the old time anchor. A subsequent empty-bucket delay used the full 1 second of already elapsed idle time to refill a second full 10-MTU burst at the same Instant.
- This was identified in code and demonstrated with a simplified arithmetic model. No claim that actual WAN recordings have yet observed it.

## Minimal change

1. For the fixed-rate early-allow case only, credit elapsed tokens up to the bounded capacity and advance the monotonic anchor before returning permission to send. After transmission, the prior idle period cannot replenish a second bucket.
2. If tokens are already at capacity, credit_fixed_rate discards any subbyte residue and avoids a costly 128-bit multiplication. No change to legacy RTT/window pacing.
3. Test fixed_rate_idle_does_not_allow_a_second_full_bucket uses 65,536 B/s, 1200 MTU, 10-MTU capacity, and 1s idle. Ten immediate datagrams are permitted, the eleventh at that Instant must wait exactly ceil(1200*1e9/65536) = 18,310,547 ns.
4. Test fixed_rate_alternating_ack_updates_integrate_old_rate uses twenty 10us ACK-driven rate changes alternating 50,000 and 70,000 bytes/s. Sum of prior-rate credits must be 12 whole bytes, zero fractional remainder; bucket must not overfill. Test asks for realistic 1200-byte datagrams.

## Real evidence and limits

- Changes only in isolated standalone Quinn source at /tmp/chimera-brutal-pacing-candidate-20261113-aCeObM.
- Rustfmt --edition 2021 --emit stdout (candidate source) passed syntax parsing, with no whole-file formatting rewrite.
- Small independent Python integer model: source-equivalent old idle logic permits 24,000B at one Instant, corrected logic limits it to 12,000B with 12,000B capacity. This is NOT compiled Rust evidence.
- Candidate source SHA256 b8ceb9571369efce977f71b6225342f16c3c8fbb09b6e69c3013201d198691b2.
- Host high Tctl; **no Rust compilation, unit test, Clippy, full application binary, Hysteria 2/Xray benchmark, or independent review has run for this revision**. Older results (272/272) belong to the parent-before-fractional source and do not validate this revision.

## Required gates

- Under thermally safe conditions, run both new tests, all prior fractional-byte and stale-time regressions, complete Quinn lib/docs suite, and strict Clippy.
- Build the exact signed source and repeat current pinned client full-byte interop, long-idle, loss/reordering, stream fairness and p99 tests.
- Protected vendor path requires independent L3 reviewer and maintainer approval before integration. No master edit, system config change, remote push or deployment took place.
