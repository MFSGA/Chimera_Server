# TCP paced partial-splice readiness clearing

This experiment tests a narrowly scoped Tokio readiness hypothesis for the Linux TCP splice relay used by the Brutal2 pacing probes.

## Hypothesis

Earlier pacing attribution showed that a partial `pipe -> TCP socket` splice is commonly followed by an immediate `EAGAIN` while Tokio still has cached writable readiness. A benchmark-only candidate therefore called `AsyncFdReadyGuard::clear_ready()` immediately after a partial successful destination splice. The goal was to avoid the predictable next failed `splice` without adding a timer, allocation, lock, or syscall.

The candidate was implemented only in an isolated worktree and was removed after measurement. Production relay code was never changed.

## Moderate-RTT paired result

The formal comparison used an unprivileged network namespace with `tc netem delay 15ms`, which produced roughly 31.5 ms measured TCP RTT. Each process was pinned to CPUs 0-7 and used 8 Tokio workers, 16 connections, 64 MiB per connection, a 32 -> 25 MiB/s pacing step, a 32 ms rate-scaled `TCP_NOTSENT_LOWAT`, a 128 KiB splice pipe, payload verification, one warmup, and one measured sample. Six independent pairs alternated execution order.

The mechanism worked exactly as intended: baseline destination readiness acquisitions were about 768-770 per connection with about 125-126 destination `WouldBlock` events, while the clear-on-partial candidate used about 643-644 readiness acquisitions and almost zero observed `WouldBlock` events. That is roughly a 16% reduction in readiness acquisitions and removes the predictable cached-ready failed attempt.

CPU did not improve. Candidate/baseline CPU-seconds-per-GiB ratios for the six pairs were approximately 1.114, 0.979, 1.116, 1.077, 1.052, and 1.021. Five of six pairs regressed, with a paired-ratio median of about **1.065x**. Median CPU/GiB was about **0.770 s/GiB baseline versus 0.834 s/GiB candidate**. Aggregate throughput was broadly similar and was not used to override the CPU result.

## Syscall attribution

A focused c8 / 32 MiB-per-flow run under the same 15 ms one-way netem used `strace -f -c -e trace=splice,epoll_wait,epoll_ctl,setsockopt,fcntl,ioctl`.

| metric | baseline | clear partial readiness |
| --- | ---: | ---: |
| destination readiness acquisitions / connection | 383.75 | 320.63 |
| destination `WouldBlock` / connection | 61.88 | 0.13 |
| `splice` calls | 5,225 | 4,715 |
| failed `splice` calls | 562 | 65 |
| `epoll_wait` calls | 4,628 | 5,421 |
| `setsockopt` calls | 80 | 80 |
| total tracked calls | 10,073 | 10,356 |

The candidate therefore does not eliminate work; it exchanges cached-readiness retry work for more reactor waits/wakeups. This explains why the large reduction in failed `splice` calls does not become a stable CPU win and can instead regress CPU on the longer paired workload.

## Decision

Reject proactive `clear_ready()` after a partial destination splice for production. The current Tokio `try_io` behavior should remain unchanged. This result also cautions against treating fewer failed syscalls or fewer readiness acquisitions as sufficient evidence by themselves: the corresponding `epoll_wait` and scheduler behavior must be measured.

A future revisit would need a materially different readiness/pacing mechanism that reduces both failed destination splice attempts and kernel wake/wait work under representative RTT/loss conditions, rather than shifting cost between them.
