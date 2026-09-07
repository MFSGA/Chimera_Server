# TCP auto splice slot contention follow-up

This note extends the `CHIMERA_TCP_AUTO_MAX_CONNECTIONS` capacity work after the default was raised from 8 to 32. The goal is to determine whether the same evidence supports increasing the limit again, not to assume that more splice concurrency is always better.

## Hypothesis

At 192-256 KiB per flow, downlink splice is cheaper in CPU than the userspace-copy fallback, so a larger auto slot budget can reduce CPU. However, each simultaneously selected splice flow also creates an `AsyncFd` pipe and adds splice/epoll work. Past pacing probes already showed that Linux pipe accounting and high-concurrency scheduling can become limiting resources. A higher slot limit is therefore useful only if the CPU reduction does not come with a material throughput or wakeup regression.

## Controlled raw-ready sweep

The existing `tcp_auto_slot_scope_probe` was run with `--synchronize-ready` so all 128 flows reach the reservation point before any flow begins moving payload. This makes the selected splice count equal to the requested slot limit instead of allowing completed flows to recycle slots during the same sample.

Common parameters:

```text
CPU affinity: 0-7
connections: 128
Tokio workers: 8
payload: 256 KiB/flow
copy buffer: 64 KiB
splice pipe: 128 KiB
slow prelude connections: 0
verify payload: enabled
10 independent paired rounds, alternating slot order
```

Median results:

| auto slots | splice hits | CPU us/flow | throughput Gbit/s | context switches |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 8 | 364.2 | 28.56 | 61.0 |
| 32 | 32 | 344.1 | 21.53 | 62.5 |
| 64 | 64 | 307.7 | 14.88 | 56.5 |

Paired CPU ratios were 0.934x for 32/8 (8/10 favorable), 0.880x for 64/32 (10/10 favorable), and 0.856x for 64/8 (10/10 favorable). The CPU result alone would encourage a larger limit, but wall throughput moves sharply in the opposite direction: the 64-slot median is only about 69% of the 32-slot throughput in this synchronized high-contention workload.

The synchronized barrier intentionally amplifies simultaneous contention and is not a production traffic model, so the absolute throughput values are not defaults guidance. The important signal is that the next capacity step is no longer a one-dimensional CPU win.

## Syscall attribution

A focused `strace -f -c` run used the same c128/256 KiB workload. Moving from 32 to 64 slots doubled the expected splice-side setup and transfer work:

| syscall / metric | 32 slots | 64 slots |
| --- | ---: | ---: |
| `pipe2` | 32 | 64 |
| `splice` | 224 | 448 |
| `fcntl` | 130 | 258 |
| `epoll_ctl` | 898 | 1026 |
| `epoll_wait` | 509 | 512 |
| measured throughput | 10.08 Gbit/s | 8.51 Gbit/s |
| measured context switches under strace | 8718 | 9113 |

`epoll_wait` call count is essentially flat while its cumulative time rises from about 169.5 ms to 218.4 ms. The 64-slot case therefore does not reveal a missed userspace readiness optimization; it simply places twice as many flows on the splice/pipe path at once, with more pipe setup and kernel scheduling work. `strace` perturbs absolute timings heavily, so only the syscall-count mechanism is used for attribution.

## Decision

Do **not** raise the production default above 32 from this evidence. The 64-slot candidate reliably lowers userspace CPU per flow in the synthetic contention case, but it also produces a large and repeatable wall-throughput tradeoff and doubles splice/pipe work. That is not a safe production optimization without representative mixed relay + Brutal2 pacing data showing that the extra CPU saving matters more than the concurrency penalty.

Keep 32 as the current default and retain `CHIMERA_TCP_AUTO_MAX_CONNECTIONS` for deployments that can benchmark a different balance. The next useful experiment should combine paced Brutal2 bulk traffic with auto-splice relay contention and observe CPU/GiB, relay completion tail, pipe capacity shortfalls, context switches, and pacing `WouldBlock`/readiness behavior in the same run. If that mixed workload remains stable at 32, move hotspot work away from slot-count tuning rather than continuing toward 64/128 by default.
