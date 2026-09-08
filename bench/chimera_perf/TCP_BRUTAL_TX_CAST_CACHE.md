# TCP Brutal2 cached transmit-rate conversion

## Hypothesis

After the reciprocal ACK-rate optimization, the active Brutal2 ACK path still refreshes the cached congestion window on every ACK. `brutal_tx_bps` is fixed at Brutal activation, but `BrutalState::window(u64)` converts that same `u64` rate to `f64` on every refresh. The candidate caches the exact `tx_bps as f64` value once at activation and uses it only for the active cached-window refresh.

This does not change rate publication, ACK/loss accounting, RTT estimation, congestion-window multiplication order, BBR fallback, or Xray/shoes compatibility semantics. The original `u64` value remains stored for pacing/debug trace calculations.

## Benchmark

`brutal_ack_rate_bench` exposes `BRUTAL_TX_CAST_BENCH_MODE=baseline|cached`. The loop models the current loss-active arithmetic with 10% modeled loss, the reciprocal ACK-rate representation, moving ~80 ms RTT, the production sub-second RTT conversion, and 10 million ACK events. The only difference is whether the loop converts the `u64` transmit rate on every event or consumes a precomputed `f64` rate.

Formal runs used a release binary pinned to CPU 0. Twelve independent pairs alternated execution order.

| Metric | baseline cast/ACK | cached f64 |
| --- | ---: | ---: |
| median ns/ACK | 11.536 | 5.440 |
| final ACK rate | 0.909091 | 0.909091 |
| final modeled cwnd | 3,541,999 B | 3,541,999 B |

The paired candidate/baseline ratio median was **0.474x**. All **12/12** pairs favored the cached conversion; the ratio range was **0.390x-0.658x**. There were a few noisy samples, but the direction and magnitude survived alternating process order.

A unit test covers representative transmit rates, sub-second and >1 s RTT values, and reciprocal ACK-rate values through the 0.8 clamp. The cached conversion produces exactly the same integer congestion-window result as converting the same `u64` at each call.

## Production slice

`BrutalController` now stores both the original `brutal_tx_bps: u64` and `brutal_tx_bps_f64: f64`. Activation initializes both from the same atomic rate snapshot. Active `refresh_brutal_window()` calls `BrutalState::window_f64()` so the repeated integer-to-float conversion disappears from the per-ACK path. The existing `window(u64)` wrapper remains for pre-activation/fallback queries where the rate can still be loaded dynamically.

This is intentionally narrower than caching a larger pre-multiplied factor. Keeping the multiplication order unchanged reduces the semantic and numerical surface of the optimization.

## Side observation: traffic recorder lock

A temporary benchmark also compared the existing per-thread-shard `RwLock` write path with `Mutex` under an 8-thread, four-index HashMap update workload. `Mutex` was not consistently faster and was usually slower, so no traffic locking change was retained. This rejects the easy lock-substitution hypothesis without mixing an unrelated production change into this slice.
