# TCP Brutal2 pristine ACK reciprocal-rate store

## Hypothesis

After the cached-second ACK specialization, the common no-loss/non-debug path still calls the ACK-rate refresh helper on every ACK. That helper observes `rolling_loss_count == 0`, writes `reciprocal_ack_rate = 1.0`, and returns. Every legal transition into the cached-second pristine state has already established that exact value, so the store is redundant until a loss enters the rolling window or debug accounting is enabled.

The production candidate keeps the existing cached-second branch and counters, but only recomputes the reciprocal ACK rate when `rolling_loss_count != 0 || debug`. Loss-active and debug behavior therefore remain on the existing `update_ack_rate()` path.

## Benchmark

`brutal_ack_rate_bench` exposes `BRUTAL_PRISTINE_STORE_BENCH_MODE=baseline|skip`. The benchmark models the current cached-second ACK body, the pristine/debug condition, a moving ~80 ms RTT, and the current cached transmit-rate/window arithmetic. It runs 100,000,000 ACK events per process.

Release build, CPU 0 pinned, three warmup pairs, then 12 independent measured pairs with alternating execution order:

- baseline median: 3.777 ns/ACK
- skip-store median: 3.655 ns/ACK
- paired candidate/baseline ratio median: 0.965x
- favorable pairs: 11/12
- non-outlier paired ratio range: 0.944x to 0.985x

One candidate process was a clear scheduling/frequency outlier at 4.926 ns/ACK (1.296x versus its baseline pair). The other eleven pairs all favored the candidate, so the robust median still shows a repeatable ~3.5% controller-only reduction rather than relying on that outlier.

The earlier pre-specialization benchmark for merely avoiding the pristine rate assignment was too noisy to justify a change. This rerun targets the current split-ACK/rollover-only production shape; after those later optimizations, the redundant store is now a repeatable ~3.5% controller-only cost by paired median on this CPU.

This is a microbenchmark result, not a claim of a 2.6% server throughput improvement.

## Semantics and validation

The optimized path does not change the five-second ACK/loss window, minimum ACK-rate clamp, RTT input, congestion-window multiplication order, pacing target, BBR fallback, debug accounting, timers, syscalls, allocation, or locking.

Focused production tests verify that the specialized ACK path remains identical to the generic record path across loss entry/expiry and that a pristine window returns to an exact ACK rate of 1.0 after old loss samples expire.
