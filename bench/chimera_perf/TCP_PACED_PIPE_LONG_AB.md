# TCP paced splice-pipe long A/B

## Question

Earlier `tcp_asyncfd_pacing_probe` sweeps showed that a 512 KiB splice pipe can reduce successful
`splice(2)` calls and Tokio readiness-guard acquisitions under pacing backpressure. The short
samples were not strong enough to justify changing the production 128 KiB relay default. This
follow-up asks whether the mechanism survives a longer paired run as a stable CPU or throughput
improvement.

The production relay is intentionally unchanged unless the larger pipe wins on end-to-end cost,
not merely on an internal counter.

## Workload

The probe used the production-shaped Tokio `AsyncFd<OwnedFd>` relay, duplicated nonblocking TCP
fds, one nonblocking splice pipe per direction, `SO_MAX_PACING_RATE`, and a 32 ms rate-scaled
`TCP_NOTSENT_LOWAT`.

Common parameters:

- 16 concurrent connections;
- 8 Tokio worker threads;
- 64 MiB per connection;
- 16 MiB/s requested pacing rate per connection;
- 32 ms `TCP_NOTSENT_LOWAT` (`536870` bytes at this rate);
- payload verification enabled;
- one warmup plus three measured runs per process;
- independent processes, alternating 128 KiB / 512 KiB execution order.

The command shape was:

```sh
bench/chimera_perf/target/release/tcp_asyncfd_pacing_probe \
  --connections 16 \
  --worker-threads 8 \
  --bytes-per-connection 67108864 \
  --rate-bytes-per-sec 16777216 \
  --notsent-lowat-ms 32 \
  --pipe-size <131072|524288> \
  --warmup 1 \
  --runs 3 \
  --verify
```

A timeout interrupted the tenth pair after nine complete pairs. The incomplete pair was excluded;
all numbers below use the nine complete before/after pairs only.

## Results

Median summaries across the nine complete process pairs:

| metric | 128 KiB | 512 KiB |
| --- | ---: | ---: |
| CPU seconds/GiB | 1.264085 | 1.257218 |
| aggregate throughput | 2.156500 Gbit/s | 2.154698 Gbit/s |
| destination readiness acquisitions/connection | 915.8125 | 531.6875 |
| destination `WouldBlock`/connection | 201.5000 | 201.3125 |
| source readiness acquisitions/connection | 514.3125 | 130.2500 |
| relay max/median completion ratio | 1.002093 | 1.001080 |
| context switches/process | 22444 | 22617 |

Per-pair candidate/baseline CPU/GiB ratios were:

```text
0.9870, 1.0676, 1.0020, 0.9701, 0.9731, 0.9408, 0.8877, 1.0278, 1.0298
```

The median ratio was `0.987x`, but only **5/9** pairs favored the 512 KiB pipe. The variance is too
large to call the roughly 1.3% median reduction a stable CPU win.

Per-pair throughput ratios were:

```text
0.9990, 0.9987, 0.9986, 0.9997, 0.9993, 0.9992, 0.9994, 0.9991, 0.9990
```

All **9/9** pairs were slightly lower with 512 KiB; the median ratio was `0.9991x`. The absolute
change is small, but it provides no countervailing throughput reason to accept the extra pipe
memory.

The mechanism itself is real: the larger pipe reduced median destination readiness acquisitions by
about 42% and source readiness acquisitions by about 75%, while destination `WouldBlock` stayed
essentially fixed. This matches the earlier `strace` attribution: a larger paced pipe coalesces
successful transfer work between the same pacing/writable boundaries rather than eliminating those
boundaries.

## Decision

Do **not** raise the generic production splice-pipe default from 128 KiB to 512 KiB based on paced
traffic alone.

The long paired run does not reproduce a stable end-to-end CPU win, and it adds four times the pipe
capacity per active splice direction. The result also reinforces a recurring finding from the
Brutal2 pacing work: reducing cached readiness work or successful `splice(2)` calls is insufficient
unless the change also reduces real kernel wait/wakeup boundaries or produces a repeatable CPU/GiB,
throughput, or tail improvement.

Keep the existing `CHIMERA_TCP_SPLICE_PIPE_SIZE` override for deployments that can benchmark their
own workload. Future Brutal2 work should prioritize rate-transition paths that can reduce actual
`epoll_wait`/wakeup pressure, not further pipe-capacity expansion.
