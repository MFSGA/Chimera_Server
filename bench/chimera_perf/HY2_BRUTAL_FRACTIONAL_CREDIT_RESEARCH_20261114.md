# HY2 Brutal Pacer fractional byte accounting — 2026-11-14

**L3 HOLD: SOURCE AND TESTS WRITTEN; RUST COMPILATION/TESTS NOT VERIFIED.**

## Root cause identified from source

Original fixed-rate Pacer computed integer bytes by flooring bytes_per_second * elapsed_nanoseconds / 1e9, then advanced its time anchor. For frequent calls yielding <1 byte, every fractional credit was discarded, causing potentially significant under-delivery. On a rate transition the old policy settled whole-byte credit but also lost fractional credit. This is a code arithmetic issue, not a measured WAN throughput regression.

## Isolated candidate

Only vendor/quinn-proto/src/connection/pacing.rs plus this report change against prior signed candidate 9b86f95. A u32 fractional_tokens stores the nanobyte remainder; a small credit_fixed_rate helper uses saturating u128 math to aggregate partial credits across frequent calls and fixed-rate transitions. When the bucket fills, surplus fraction is dropped. When leaving fixed-rate for legacy RTT/window pacing, the fractional credit resets. Target rate, capacity, wake delay and legacy pacing are not deliberately changed.

## Four new regression tests (written, not executed yet)

- fixed_rate_subbyte_credit_survives_frequent_pacing_checks: 65,536 B/s for 100us with checks every 10us should credit 6 bytes and retain the subbyte part.
- fixed_rate_switch_keeps_accrued_subbyte_credit: 50k B/s for 10us plus 70k B/s for 10us should mint 1 byte.
- fixed_rate_fraction_is_discarded_when_bucket_is_full: no hidden extra credit after bucket fills.
- fixed_rate_fraction_does_not_leak_into_legacy_pacing: reset fractional credits across fixed/legacy controller boundaries.

## Real verification state

- rustfmt parsing via --emit stdout: passed; does not constitute a compile/test pass.
- Exact Python arithmetic check: 6 bytes plus 553,600,000 nanobyte remainder for 65,536 B/s over 100us, and 1 byte for the mixed-rate example. This is mathematical cross-check only.
- Cargo test attempt under existing thermal guard at Tctl 73.38C was refused at preflight (limit 70C). A preceding guarded test attempt was aborted at 75.62C. Neither attempt validates this new source.
- Full Quinn unit/doc tests, Clippy, real Xray/Hysteria2 interoperability, and independent L3 review are NOT complete for this new candidate. Avoid treating historical 272/272 tests on the parent version as validation of this commit.

Next: under safe thermal conditions, compile and test the exact signed source, run the four tests, full Quinn regression, strict Clippy, and negative boundary cases; review before merge. No master modification, push or deployment.
