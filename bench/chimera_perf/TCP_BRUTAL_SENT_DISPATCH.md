# TCP Brutal2 post-activation send dispatch

This experiment tests whether the active Brutal2 send callback should return immediately after the required `brutal_active` test instead of continuing to the now-empty BBR option check. After Brutal activation, `activate_brutal_if_configured()` returns immediately and activation has already set `bbr = None`, so `Controller::on_sent()` currently executes two highly predictable control-flow checks for every sent packet.

The candidate is intentionally narrow: once `brutal_active` is true, return from `on_sent()` immediately. Before activation, behavior is unchanged: the controller still observes the atomic configured rate, activates Brutal at the same boundary, or forwards the event to BBR when Brutal has not been requested. No pacing, congestion, ACK/loss, RTT, buffer, syscall, timer, allocation, or compatibility behavior would change.

## Benchmark

`brutal_ack_rate_bench` now accepts `BRUTAL_SENT_DISPATCH_BENCH_MODE=baseline|active-fast`. The modeled active path performs 200 million sent callbacks per process. `baseline` keeps the current active check followed by the empty-BBR check; `active-fast` returns after the active check. Both variants consume the same event stream and produce the same checksum.

The release binary was pinned to CPU 0. Three warmup pairs preceded twelve independent measured pairs, with execution order alternating between baseline-first and candidate-first.

Measured medians were:

- baseline: **1.377 ns/sent**;
- active-fast: **1.367 ns/sent**;
- paired candidate/baseline ratio median: **0.981x**.

The result is not stable enough to support production code. Only **8/12** pairs favored the candidate, and the paired ratio ranged from **0.823x to 1.184x**. Samples were visibly bimodal around roughly 1.15-1.18 and 1.36-1.46 ns/sent, consistent with CPU frequency/scheduling variation being larger than the candidate effect.

The twelve paired ratios were:

`0.9375, 1.1844, 0.8324, 0.9871, 0.9736, 1.1764, 1.0000, 0.9949, 1.1645, 0.9746, 0.8392, 0.8226`.

## Decision

Do **not** restructure production `Controller::on_sent()` from this result. The candidate removes one predictable empty-option branch, but its apparent median gain is only about 2% and repeatedly reverses under alternating independent runs. This is the same pattern already seen when attempting to remove the post-activation BBR check from `on_ack`: dispatch cleanup is now below the reliable signal floor on this host.

Keep the benchmark as a regression/profiling asset. Future Brutal2 work should prefer larger costs such as rate-publication timing, ACK/loss estimator work under real loss, timer/wakeup behavior, or data-plane copy/syscall hotspots rather than adding duplicated active-state control flow for a sub-nanosecond effect.
