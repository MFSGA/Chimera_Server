# TCP Brutal2 reciprocal ACK-rate benchmark

This pass targets a per-ACK arithmetic cost in the Brutal congestion controller after prior relay, pipe, readiness, and pacing-publication profiling had already bounded those paths. With loss in the rolling window, the production shape computed `ack_rate = ack / total` and then immediately computed the congestion window by dividing by that rate. That means two floating-point divisions on each ACK while loss remains active.

The candidate stores `1 / ack_rate` instead. The rolling update computes `total / ack` once (clamped to `1 / MIN_ACK_RATE`), and the window calculation multiplies by the reciprocal. Pristine/no-loss behavior remains exactly `1.0`. Debug and benchmark-only pacing traces recover the ordinary ACK rate only when they need to report it.

## Microbenchmark

`brutal_ack_rate_bench` now accepts `BRUTAL_RECIP_BENCH_MODE=baseline|reciprocal`. The focused loop models 10% loss, moving sub-second RTT input, the same 0.8 minimum ACK-rate clamp, and 10 million ACK events. Runs were release builds pinned to CPU 0, with 12 independent paired samples and alternating execution order.

Observed medians:

- baseline: **10.280 ns/ACK**
- reciprocal: **8.208 ns/ACK**
- paired candidate/baseline ratio median: **0.786x**
- favorable pairs: **12/12**

Individual paired ratios ranged from roughly **0.696x to 0.875x**. Every run produced the same final ACK rate (`0.909091`) and final modeled congestion window (`3,541,999` bytes).

This benchmark intentionally isolates the arithmetic shape; it is not an end-to-end throughput claim. The production change is justified because the removed division is on the real Brutal loss-path ACK hot loop, the controller already caches the derived window, and the change adds no allocation, lock, syscall, timer, unsafe code, or protocol-visible state.

## Compatibility and scope

The change does not alter the five-second ACK/loss window, Xray-compatible minimum ACK-rate clamp, Brutal activation semantics, RTT handling, BBR fallback, pacing trace rates, or congestion-window formula. It changes only the internal representation of ACK-rate compensation.

Do not infer from this result that other floating-point operations in Brutal should be rewritten. The benefit here comes from an exact algebraic removal of a repeated division with benchmark evidence and existing controller equivalence tests.