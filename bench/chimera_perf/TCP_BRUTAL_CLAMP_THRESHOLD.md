# TCP Brutal2 minimum ACK-rate clamp threshold

## Question

After the reciprocal ACK-rate optimization, a loss-active Brutal2 ACK still computes
`total / ack` on every ACK before clamping the reciprocal rate to `1 / 0.8`. When loss is
severe enough that the minimum ACK rate is continuously active, an appealing follow-up is
to test the clamp with integer arithmetic first and skip the floating-point division.

For the current 0.8 minimum ACK rate, the exact threshold is:

```text
ack / (ack + loss) < 0.8
ack < 4 * loss
```

The candidate therefore checks `ack < loss.saturating_mul(4)` and directly publishes the
1.25 reciprocal when true. The production code was not changed while measuring this.

## Benchmark

`brutal_ack_rate_bench` now accepts:

```bash
BRUTAL_CLAMP_BENCH_MODE=baseline|integer \
  taskset -c 0 bench/chimera_perf/target/release/brutal_ack_rate_bench
```

The focused loop uses:

- 100,000,000 ACK events per process;
- one modeled loss per three ACKs, giving a steady ACK rate near 75%, below the 0.8 clamp;
- the existing reciprocal ACK-rate representation;
- moving ~80 ms RTT input and the existing modeled congestion-window multiplication;
- release mode pinned to CPU 0;
- three alternating warmup pairs followed by ten measured pairs with alternating order.

A unit test checks the integer threshold against the floating-point clamp relation around the
0.8 boundary for loss counts from 0 through 10,000.

## Results

Measured medians:

| variant | median ns/ACK | mean ns/ACK | CV |
| --- | ---: | ---: | ---: |
| baseline floating divide + clamp | 6.777 | 6.814 | 1.90% |
| integer threshold before divide | 7.194 | 7.253 | 2.24% |

The paired candidate/baseline ratio median was **1.060x**. None of the ten measured pairs
favored the integer-threshold candidate; paired ratios ranged from about **1.013x to 1.121x**.
Both variants ended with ACK rate `0.800000` and modeled window `4,024,995` bytes.

## Conclusion

Reject the production change. Even when the 0.8 clamp remains active for essentially the
entire measured loss window, the integer threshold adds enough branch/multiply work to be
about 6% slower in this controller-shaped loop. Skipping the floating-point division is not a
win on this CPU/toolchain.

This also narrows the remaining Brutal2 per-ACK optimization space: the reciprocal conversion
removed a demonstrably expensive second floating-point division, but trying to avoid the
remaining division only in the clamped severe-loss regime is counterproductive. Future work
should return to higher-cost data-plane or estimator/publication behavior rather than adding
more arithmetic policy branches to this ACK path.
