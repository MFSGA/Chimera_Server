# XUDP session lookup clone attribution

## Hypothesis

For data frames on an existing XUDP session, `decode_frame_with_control_count()` previously cloned the entire `XudpSessionState` twice and then cloned the target a third time before returning an owned `DecodedFrame::Data`. For hostname targets, each full-state/target clone duplicates the backing `String` allocation. The session map is immutable during the final lookup stage, so the decoder can borrow the stored state and clone only the target that must escape in the decoded frame.

## Benchmark

`xudp_session_lookup_bench` models the exact known-session lookup shapes with a hostname target and GlobalID. Both modes perform the same HashMap lookups and produce the same checksum:

- `cloned`: clone the initial existing session, clone the session again for data extraction, then clone the target from that second owned state.
- `borrowed`: inspect the existing GlobalID by reference, borrow the session for final data extraction, and clone only the target that must be returned as owned data.

The benchmark runs 5,000,000 events per independent process. Formal runs were built in release mode, pinned to CPU 0, preceded by three warmup pairs, and measured as ten alternating-order pairs.

## Result

Measured `ns/frame` pairs (cloned, borrowed):

1. 48.964, 29.056
2. 47.917, 29.322
3. 44.534, 26.472
4. 44.641, 26.569
5. 44.788, 26.660
6. 44.233, 26.599
7. 44.170, 26.661
8. 45.035, 26.783
9. 44.672, 26.557
10. 44.881, 26.839

Medians:

- cloned: **44.730 ns/frame**
- borrowed: **26.661 ns/frame**
- paired borrowed/cloned ratio median: **0.595x**
- pair ratio range: **0.593x–0.612x**
- favorable pairs: **10/10**

Every run produced checksum `632500000`.

## Production slice

The decoder now keeps only the existing session's copyable GlobalID snapshot for duplicate-New validation, then borrows the final session state. Existing-session Keep data clones only the `NetLocation` that must be owned by `DecodedFrame::Data`; it no longer clones `XudpSessionState` values solely to inspect them.

This does not change framing, GlobalID takeover rules, target updates, session lifetime, channel behavior, resolver behavior, syscalls, timers, locks, or unsafe code. The benefit is specifically fewer hostname `String` allocations/copies on the XUDP data path.

A focused regression test verifies that a Keep frame without inline metadata reuses a hostname target and GlobalID from the stored session.
