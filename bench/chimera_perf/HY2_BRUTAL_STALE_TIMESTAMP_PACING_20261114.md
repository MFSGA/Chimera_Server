# Quinn fixed-rate Pacer: stale timestamp budget accounting (2026-11-14)

**Status: L3 HOLD.** Isolated regression candidate on codex/brutal-pacing-review-20261113. No modification to production master or external deployment.

## Scope and root cause

- Owner: vendored Quinn Pacer, vendor/quinn-proto/src/connection/pacing.rs.
- Its delay path already uses checked_duration_since(previous) and treats a backwards Instant as zero elapsed (warning). However, before this change it still assigned prev=now unconditionally, allowing a backwards timestamp to move the refill anchor into the past.
- Later a call at the original time could mint extra tokens for an interval that did not pass since the original anchor. This is an event-order robustness problem for fixed-rate and dynamic-rate pacing; it does NOT prove that real Quinn monotonic timestamps regularly arrive out of order.

## Deterministic RED-to-GREEN cases

1. A Pacer at 1,000,000 bytes/s is initialized at t0 with zero tokens; a stale call at t0-1ms switches to 2,000,000 bytes/s, followed by a call at t0. The original code rewound prev, contrary to the intended no-rewind invariant.
2. A constant-rate 2,000,000 bytes/s Pacer receives a stale call at t0-1ms and then a call at t0. The original code rewound prev in the regular refill path.

Both tests FAILED on the original signed candidate and passed when the two assignments were replaced with prev=max(prev,now). Normal monotonic elapsed-time calculations and all other capacity, RTT/cwnd and wake-up policies remain unchanged.

## Verification actually executed

- Isolated Quinn version 0.11.14 source under /tmp/chimera-brutal-pacing-candidate-20261113-aCeObM.
- With old code: cargo test --locked --offline --lib backwards_timestamp_ produced **0/2 pass**, both failing on prev equality.
- After targeted change: 2/2 pass; full lib **272/272 pass**, docs **3/3 pass**; cargo clippy --locked --offline --lib --tests -- -D warnings -A clippy::manual_filter passed. The one manual_filter exception is the already-known upstream lint, not a new exception.
- The change is limited to two monotonic-time assignments plus two deterministic unit tests. No broad rustfmt rewrite or other modified source included.

## Unverified

- The source change was tested as an independent Quinn crate, not in a fresh full Chimera server binary; external Xray/Hysteria2 compatibility and WAN fairness/latency remain unverified.
- No performance gain is claimed; ordinary in-order time remains semantically identical. Independent human L3 reviewer and explicit approval remain required before merging vendor code.

No Git worktree created; master and its dirty files, origin and deployment are unchanged.
