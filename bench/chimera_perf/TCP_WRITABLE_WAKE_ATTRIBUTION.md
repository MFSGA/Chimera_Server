# TCP Brutal2 writable-wake attribution

This pass adds a benchmark-only view of the actual kernel state observed after a paced `pipe -> TCP` splice returns `EAGAIN` and Tokio next reports the destination writable. The goal is to distinguish a real `TCP_NOTSENT_LOWAT` threshold crossing from a userspace readiness artifact or a wake dominated by congestion-window availability before changing production relay logic.

## Instrumentation

`tcp_asyncfd_pacing_probe --sample-writable-wake-every N` samples every Nth destination writable notification that follows a destination `WouldBlock`. Sampling happens immediately after `AsyncFd::writable().await` and before the next splice attempt. Each sample records `SIOCOUTQNSD` plus `TCP_INFO`; the run report exposes sample count, the fraction whose unsent queue is at or below the currently published `TCP_NOTSENT_LOWAT`, and mean unsent, unacked, and sender-cwnd bytes.

The option is benchmark-only, requires paced single-drain mode plus a static or queue-time `TCP_NOTSENT_LOWAT`, and adds one `ioctl(SIOCOUTQNSD)` plus one `getsockopt(TCP_INFO)` per sampled wake. CPU/throughput from sampling runs is therefore not used to justify production changes.

## 31.5 ms RTT result

An unprivileged network namespace used `tc netem delay 15ms`, producing about 31.55 ms measured TCP RTT. The workload used CPUs 0-7, eight Tokio workers, eight connections, 32 MiB/connection, a `32 -> 25 MiB/s` midpoint pacing decrease, a 32 ms rate-scaled low-water (`1,073,741 -> 838,860 B`), 128 KiB splice pipes, payload verification, one warmup, and three measured runs. Every post-EAGAIN wake was sampled.

Across the three measured runs there were 485, 487, and 490 sampled wakes. `writable_wake_at_or_below_lowat_ratio` was **1.0 in every run**. Mean unsent bytes at those wakes were about **444,062, 443,966, and 444,662 B** (about 433.6-434.2 KiB), well below the active low-water. Mean unacked bytes were about **945 KiB**, while sender cwnd was about **2.20 MiB**. Midpoint TCP RTT was 31.54-31.57 ms.

This directly shows that the EAGAIN -> writable cycle in this workload is not primarily a Tokio cached-readiness artifact: the next writable notification arrives after the kernel unsent queue has crossed below the configured low-water threshold.

## 82 ms RTT result

A second namespace used `tc netem delay 40ms`, producing about 81.9 ms measured TCP RTT. To keep the run below the local harness ceiling it used four connections and four workers; all other pacing, queue-time, pipe, payload, and verification settings remained the same.

The three measured runs produced 205, 204, and 205 sampled wakes. Again, `writable_wake_at_or_below_lowat_ratio` was **1.0 in every run**. Mean unsent bytes at the wake were about **354,391, 337,527, and 340,023 B**. Mean unacked bytes were about **2.21-2.25 MiB**, while mean sender cwnd was about **5.19-5.29 MiB**. Midpoint TCP RTT was 81.88-81.94 ms and midpoint unacked bytes were about 2.68 MiB.

The higher-RTT case is important because previous low-water sweeps lost most transition benefit there. These samples show why: writable notifications still line up with the notsent-lowat crossing, but a much larger amount of data is already unacked/in flight. Changing Tokio readiness handling cannot remove that flight-size/RTT limitation, and raising the low-water has already failed end-to-end CPU/throughput validation.

## Decision

Do **not** change production `SpliceDirection`, clear Tokio readiness manually, enlarge the pipe, or raise the Brutal2 queue-time low-water from this result. The remaining destination wake is a real kernel send-queue threshold event, not an obviously redundant userspace wake. At high RTT, the dominant transition limitation increasingly sits in already-unacked data rather than unsent queue depth.

Future work should move above the readiness loop: use representative loss/rate-transition traces to test whether the *rate publication / admitted-flight policy* can reduce stale bytes before they become unacked, while preserving Xray/shoes-compatible transport semantics. Any such candidate still needs paired CPU/GiB, rate-tracking, and completion-tail evidence; this profiling result alone does not justify a production pacing-policy change.
