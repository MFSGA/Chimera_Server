# HY2 Brutal: fractional token credit in next wake calculation (2026-11-14)

**Status: L3 HOLD — source written and statically checked; Rust tests NOT RUN for this revision. Do not integrate, push or deploy.**

## Scope and exact behavior

- Path: vendor/quinn-proto/src/connection/pacing.rs, on the signed review branch codex/brutal-pacing-review-20261113. Parent signed candidate ffb9da4 already includes fixed-rate sub-byte token carry and idle interval settlement.
- Existing fixed-rate Pacer carried earned fractional bytes (billionths) in fractional_tokens but used only whole self.tokens in calculating the next wake deadline. It scheduled ceil(needed_whole_bytes * 1e9 / rate) from the current anchor, ignoring the already earned fraction. Frequent callbacks can move the scheduled wake progressively later than the correct cumulative byte budget.
- New delay formula subtracts fractional_tokens from required nanobytes before rounding the wait time upward. The packet, MTU, capacity, rate, and congestion control policies are unchanged; legacy RTT/window scheduling still uses its previous path.
- Invariant: needed >= 1 whenever the fixed-rate delay is computed, and 0 <= fractional_tokens < 1e9, so remaining_nanobytes is strictly positive even before saturating the resulting Duration to u64 nanoseconds.

## Added deterministic Rust tests, not yet executed

1. fixed_rate_subbyte_credit_advances_next_wake: 65,536 B/s after a 10us callback earns 0.65536 byte, which should advance the next 1,200-byte wake by 10us; actual deadline should match direct ceil(1200*1e9/65536) from initial anchor.
2. fixed_rate_rate_change_reuses_fraction_in_next_wake: after 50k B/s for 10us earns 0.5 byte, changing to 70k B/s must use the preexisting half byte in the next deadline, using ceil((1200*1e9 - 0.5e9)/70000).

## Evidence actually obtained

- Isolated source written in /tmp/chimera-brutal-pacing-candidate-20261113-aCeObM, matching the immediately prior commit before this two-test change.
- rustfmt --edition 2021 --emit stdout completed, showing Rust source parses. No actual Rust compiler was run.
- Independent Python integer oracle for the scenario: initial baseline 18,310,547 ns; previous frequent-callback wake 18,320,547 ns; revised wake 18,310,547 ns. For the mixed-rate scenario the prior deadline 17,152,858 ns versus corrected 17,145,715 ns.
- The source difference is one 5-line wake-time adjustment and two new deterministic unit tests. No unrelated source formatting changes.
- Existing host Tctl was measured around 87.5-94.5 C under light activity. Therefore no compilation, test run, Clippy, full server build or network performance test was attempted for this commit. Past pass counts from older candidate revisions MUST NOT be represented as validation here.

## Remaining gates

On a thermally stable build host, run newly added tests, existing fractional-token and idle-burst tests, full isolated Quinn unit/documentation suite, strict Clippy, and then freshly built pinned-version Hysteria2/Xray interoperability and fairness/latency tests. Obtain independent L3 reviewer findings and maintainer authorization before merging vendor code to master.

No master modification, service configuration, remote ref or deployment was made by this study.
