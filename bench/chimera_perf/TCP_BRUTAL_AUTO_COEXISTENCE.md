# TCP Brutal2 pacing and auto-splice coexistence check

This note records a September 2026 local coexistence check between the current
32-slot TCP `auto` downlink-splice policy and a Brutal2-shaped paced splice workload.
It is intentionally a profiling asset, not a production-policy change.

## Question

Raising the measured `auto` splice limit from 8 to 32 creates more simultaneous
128 KiB relay pipes. Before increasing that limit further, verify that the current
32-slot default does not immediately collide with Brutal2 pacing through Linux pipe
accounting or readiness/wakeup behavior.

## Paced splice scaling sanity check

`tcp_asyncfd_pacing_probe` was pinned to CPU 0-7 with eight Tokio workers, 128 KiB
pipes, 16 MiB/s per connection, a 32 ms `TCP_NOTSENT_LOWAT`, 8 MiB per connection,
one warmup and four measured runs. Increasing concurrency from 16 to 32 to 64 kept
reported pipe capacity at the requested 128 KiB with zero shortfall connections.
Median CPU cost was 1.549, 1.480 and 1.476 seconds/GiB respectively. The 32- and
64-connection cases therefore did not show a pipe-capacity or CPU/GiB cliff at this
resource level.

## Concurrent auto-relay interference check

A second experiment ran the production-shaped `tcp_auto_slot_scope_probe` with 64
simultaneously-ready 256 KiB flows and a 32-slot `auto-after-prelude` limit. Four
independent samples were collected alone and while a separate 32-connection paced
splice workload was active on the same CPU 0-7 set. The paced workload used 64 MiB
per connection, 16 MiB/s per connection, 128 KiB pipes and a 32 ms low-water mark.

The auto probe selected exactly 32 splice flows and 32 copy fallbacks in every sample,
both alone and under paced load. Median auto-relay CPU cost moved from about 172.5 to
184.9 us/flow (+7.2%). Aggregate wall-time/throughput was highly scheduler-sensitive
and is not used as a policy signal. The concurrent paced samples reported zero pipe
capacity shortfalls; their median CPU cost was about 0.517 s/GiB and relay
max/median completion-tail ratios stayed around 1.002-1.004.

## Decision

Keep the production default at 32 slots. There is no evidence here that 32 slots
cause Linux pipe-capacity scarcity or destabilize Brutal2 pacing, but shared-CPU
interference is already measurable. Combined with the separate 64-slot contention
sweep, this is evidence against increasing the global default further without a more
representative end-to-end workload.

No production relay, pacing, controller, unsafe, io_uring, eBPF or XDP code is changed
by this result.
