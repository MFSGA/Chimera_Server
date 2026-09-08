# TCP Brutal2 rate-decrease admitted-flight attribution

This pass measures how much data has already been admitted to the TCP send path when a Brutal2 pacing-rate decrease is published. Earlier probes showed that post-`EAGAIN` writable wakes are real `TCP_NOTSENT_LOWAT` threshold events and that higher RTT increasingly moves the transition limit into already-unacked data. The remaining question was whether live Brutal rate publications arrive early enough that a userspace queue policy could still prevent most stale data from entering flight.

## Probe

`tcp_asyncfd_pacing_probe --sample-rate-decrease-flight` adds benchmark-only sampling at every pacing-rate decrease. Immediately before publishing the new `SO_MAX_PACING_RATE`, it records:

- `SIOCOUTQNSD` unsent bytes;
- `TCP_INFO` approximate unacked bytes;
- sender congestion-window bytes;
- one-RTT BDP at the new rate, computed as `new_rate * measured_rtt`.

The run and summary records report medians for each quantity plus `(unsent + unacked) / new_rate_bdp` and `unacked / new_rate_bdp`. The mode requires at least one pacing decrease and is rejected for unpaced or non-single destination-drain modes. Sampling adds one ioctl and one `TCP_INFO` getsockopt per decrease, so CPU and throughput from these runs are sanity checks only, not optimization evidence.

## Workload

The replay uses the previously captured staged live Brutal 5% publication sequence:

`13,107,200 -> 13,762,560 -> 14,454,669 -> 15,262,292 -> 14,497,357 -> 13,772,258 B/s`

The last two publications are decreases. The AsyncFd relay used the production-shaped 128 KiB splice pipe, a 32 ms rate-scaled `TCP_NOTSENT_LOWAT`, payload verification, equal-byte phases, and CPUs 0-7. Each environment used one warmup plus three measured runs.

### About 34 ms RTT

An unprivileged network namespace used `tc netem delay 15ms`; the sampled BDP implies a measured TCP RTT around 33-34 ms. Eight connections and eight Tokio workers transferred 48 MiB/connection.

Across the three measured runs, the summary medians were:

- two sampled decreases per connection;
- unsent bytes at decrease: **425,908 B**;
- unacked bytes: **458,381 B**;
- sender cwnd: **1,178,694 B**;
- new-rate one-RTT BDP: **473,817 B**;
- `(unsent + unacked) / BDP`: **1.866x**;
- `unacked / BDP`: **1.014x**.

The admitted TCP send-path state was therefore already almost **1.9 RTTs of new-rate data** at the publication point. About one full new-rate RTT was already unacked; the remaining excess sat in the unsent queue.

### About 85 ms RTT

A second namespace used `tc netem delay 40ms`, producing a sampled RTT around 84-86 ms. Four connections and four workers kept the aggregate request below the local harness ceiling.

Summary medians were:

- two sampled decreases per connection;
- unsent bytes at decrease: **376,654 B**;
- unacked bytes: **1,309,660 B**;
- sender cwnd: **2,619,320 B**;
- new-rate one-RTT BDP: **1,201,729 B**;
- `(unsent + unacked) / BDP`: **1.411x**;
- `unacked / BDP`: **1.090x**.

At this RTT, **unacked data alone already exceeded one RTT of the new target rate**. The unsent queue was no longer the dominant stale-flight component.

## Interpretation

The result strengthens the earlier negative findings around post-publication queue tricks. A `TCP_NOTSENT_LOWAT` update can stop admitting additional unsent data sooner, but it cannot retract bytes that are already unacked. At roughly 85 ms RTT, the live staged-loss replay reaches the rate-decrease publication with more than one new-rate BDP already in flight, so a readiness-loop or low-water-only optimization is acting too late to remove the dominant stale bytes.

This does **not** justify forcing a smaller congestion window or inventing a new TCP control loop. The probe only shows where the state sits when the current Brutal-derived rate is published. Any production candidate would need to change the estimator/publication or admission policy *before* those bytes become unacked, while preserving Xray/shoes-compatible semantics and proving rate tracking, CPU/GiB, and completion tail on representative Internet paths.

## Decision

Do not change production TCP relay readiness, splice pipe size, or `TCP_NOTSENT_LOWAT` from this result. Keep `--sample-rate-decrease-flight` as a profiling asset for future live traces. The next useful experiment is to compare publication timing against the Brutal loss-window evolution itself: measure how much target-rate error and admitted-flight excess exist one RTT before each 5% publication, and determine whether a safe earlier publication signal exists. If not, the remaining transition cost is fundamentally RTT-bound rather than a local relay hot loop.
