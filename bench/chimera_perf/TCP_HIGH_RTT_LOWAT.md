# TCP Brutal2 high-RTT low-water boundary

This experiment checks whether increasing the queue-time based `TCP_NOTSENT_LOWAT` target at higher RTT can turn fewer destination writable wakeups into a measurable Brutal2 data-plane win.

## Hypothesis

Earlier AsyncFd pacing attribution showed that destination `WouldBlock` and writable readiness dominate the paced splice control path. At roughly 80 ms TCP RTT, a 32 ms queue-time low-water could plausibly wake the relay more often than necessary. A 64 ms low-water should admit roughly twice as much unsent data and therefore reduce writable wake pressure. The question is whether that mechanism actually improves CPU/GiB or throughput enough to justify a larger queue.

No production code was changed for this experiment.

## Workload

The formal comparison used an unprivileged network namespace with `tc netem delay 40ms`, producing about 81.8-82.2 ms measured TCP RTT. Each process was pinned to CPUs 0-7 and used 8 Tokio workers, 8 connections, 32 MiB per connection, a 32 -> 25 MiB/s pacing step, a 128 KiB splice pipe, payload verification, one warmup, and one measured sample. Six independent pairs alternated 32 ms and 64 ms low-water execution order.

## Paired result

| metric | 32 ms median | 64 ms median | paired 64/32 median |
| --- | ---: | ---: | ---: |
| CPU seconds/GiB | 1.1228 | 1.1988 | 1.0090x |
| aggregate throughput | 1.1623 Gbit/s | 1.1144 Gbit/s | 0.9634x |
| destination `WouldBlock` / connection | 50.94 | 24.13 | 0.4712x |
| destination readiness acquisitions / connection | 364.63 | 311.69 | 0.8531x |
| voluntary context switches / process | 6520 | 6073 | 0.9278x |

The mechanism is real: 64 ms cuts destination `WouldBlock` by roughly 53%, readiness acquisitions by roughly 15%, and voluntary context switches by roughly 7%. It does not produce a stable CPU win. Pairwise CPU ratios were approximately `0.980, 1.130, 0.959, 1.018, 1.061, 1.001`; only two of six pairs were clearly favorable. Throughput also moved the wrong way in four of six pairs, with a paired median around 0.963x.

Rate-decrease recovery does not rescue the larger low-water case. With a 64 ms target, the queue at the 32 -> 25 MiB/s publication was already below the new 1.60 MiB target in these samples, so recovery was usually reported immediately with zero additional writable wake. The 32 ms target was about 0.80 MiB and samples that started above it typically observed recovery after one writable wake, around 25-31 ms. That confirms the larger threshold changes queue semantics rather than merely removing redundant user-space work.

## Syscall attribution

A smaller c4 / 16 MiB-per-flow `strace -f -c` replay under the same 40 ms one-way netem showed the same direction:

| metric | 32 ms | 64 ms |
| --- | ---: | ---: |
| destination `WouldBlock` / connection | 24.25 | 10.00 |
| `splice` calls | 1303 | 1186 |
| failed `splice` | 140 | 80 |
| `epoll_wait` calls | 1484 | 1453 |
| `epoll_ctl` calls | 34 | 34 |
| `setsockopt` calls | 40 | 40 |
| tracked syscalls | 2901 | 2751 |

The larger low-water removes failed splice work, but `epoll_wait` barely changes. The formal paired CPU results likewise remain noisy-to-negative. This means the dominant high-RTT cost is not simply the number of userspace-visible destination EAGAINs; increasing the amount of queued unsent data mostly changes batching and queue occupancy rather than eliminating the kernel wait boundary.

## Decision

Do **not** raise the Brutal2 queue-time low-water from 32 ms to 64 ms based on high RTT alone. The 64 ms setting materially reduces wake-related counters, but the six-pair result does not show a stable CPU/GiB improvement and shows a modest aggregate-throughput regression while allowing substantially more unsent data to remain queued.

A future candidate should target the actual writable wake/wait boundary without increasing queue residence time. Useful next attribution is to separate socket writable wakeups caused by `TCP_NOTSENT_LOWAT` from pacing/cwnd availability during RTT/loss transitions, ideally by correlating `SIOCOUTQNSD`, `TCP_INFO`, epoll wake counts, and relay completion tail in the same phase.
