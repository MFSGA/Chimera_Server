# TCP auto splice slot-scope probe

This probe validates the production `auto` relay slot-scope change with a mixed connection lifecycle instead of an atomic-only microbenchmark.

`tcp_auto_slot_scope_probe` is derived from the production-shaped short-flow relay probe. It creates 64 already-established TCP flows, uses 256 KiB per flow (where the existing probe has repeatedly measured downlink splice as cheaper than userspace copy), limits concurrent splice-downlink relays to eight, and marks eight connections as slow handoff-prelude sessions for 20 ms.

Two benchmark-only modes model the policy boundary:

- `auto-before-prelude`: the eight slow-prelude sessions reserve all eight splice slots before their delay, matching the old production scope.
- `auto-after-prelude`: a connection competes for a slot only after its prelude delay, matching the current production scope.

The benchmark records effective splice hits and copy fallbacks as well as CPU, wall time, throughput, and context switches. The synthetic prelude delay is outside protocol semantics; its purpose is to keep otherwise idle prelude sessions alive long enough to test whether they consume scarce splice capacity.

On the September 2026 Linux host, release builds pinned to CPUs 0-7 with eight Tokio workers were run as ten independent-process pairs with alternating execution order. Each process used one warmup and one measured run, `--verify`, 64 connections, 256 KiB/flow, eight slots, eight slow-prelude connections, and a 20 ms prelude delay.

Results:

- old-scope mode: splice hits were exactly 8/64 in all 10 runs; copy fallbacks were exactly 56/64.
- current-scope mode: median copy fallbacks fell to 42.5/64; splice hits varied with scheduler timing because freed slots can be reused by later contenders, but were always above the old fixed eight in the paired sample.
- median CPU cost was about 329.6 us/flow for old scope versus 292.1 us/flow for current scope.
- the paired current/old CPU ratio had a 0.875x median; current scope used less CPU in 10/10 pairs. The observed ratio range was about 0.595x-0.970x.
- median paired throughput ratio was about 1.016x. Wall time remains sensitive to scheduler timing and is not the primary basis for the conclusion.

This supports the production change that reserves `CHIMERA_TCP_AUTO_MAX_CONNECTIONS` capacity only after both sides become raw-TCP ready: slow protocol-prelude sessions should not evict raw-ready flows from a relay backend that is already measurably cheaper at this payload size. It does not support raising the default slot limit or adding a more complex adaptive capacity algorithm; those require separate profiling.
