# TCP Brutal2 pacing-rate syscall profile

This note records a focused syscall attribution pass for the production-shaped Tokio `AsyncFd` splice relay. The goal was to identify whether the remaining Brutal2 steady-state cost is dominated by source-side work, successful transfer calls, or destination writable wakeups before proposing another production change.

## Setup

- Linux loopback, 16 concurrent TCP flows, 8 Tokio workers.
- 16 MiB payload per flow, payload verification enabled.
- Production 128 KiB nonblocking splice pipe.
- Static rate-scaled `TCP_NOTSENT_LOWAT = rate * 32 ms`.
- `destination-drain-mode=single`, `source-readiness-mode=guarded` (production shape).
- One focused `strace -f -c` sample per rate, tracing `splice` and `epoll_wait`. These are mechanism samples, not throughput tuning samples.

## 8 MiB/s per flow

- Effective low-water: 268,435 bytes.
- Destination readiness acquisitions: 300.5/connection.
- Destination `WouldBlock`: 85.94/connection.
- Source readiness acquisitions: 130.0/connection; source `WouldBlock`: 0.
- Source successful splice size: about 130.1 KiB, close to the 128 KiB pipe capacity.
- Destination successful splice size: about 78.2 KiB.
- `splice`: 6,888 calls, 1,375 failures.
- `epoll_wait`: 6,385 calls.

## 16 MiB/s per flow

- Effective low-water: 536,870 bytes.
- Destination readiness acquisitions: 227.31/connection.
- Destination `WouldBlock`: 49.13/connection.
- Source readiness acquisitions: 130.06/connection; source `WouldBlock`: 0.
- Source successful splice size: about 130.0 KiB.
- Destination successful splice size: about 94.2 KiB.
- `splice`: 5,718 calls, 786 failures.
- `epoll_wait`: 5,045 calls.

## Interpretation

Doubling the pacing rate while keeping queue time fixed doubles the low-water byte threshold and materially reduces destination pressure: failed `splice` falls by about 43%, destination readiness acquisitions by about 24%, and `epoll_wait` calls by about 21%. Source-side work is effectively unchanged and remains pipe-capacity-sized with no observed source `WouldBlock`.

This strengthens the existing conclusion that the remaining steady-state Brutal2 relay cost is generated at the paced TCP send-queue / writable boundary, not by socket-to-pipe draining or source readiness. It also shows why a fixed-byte interpretation of the low-water would be misleading across rates: the 32 ms queue-time policy changes the actual kernel wakeup regime as rate changes.

No production change follows from these two mechanism samples. Raising low-water has already failed end-to-end CPU/throughput validation at high RTT, and lowering it increases failed splice/wakeup pressure. The next useful experiment should correlate actual kernel writable wakes with `SIOCOUTQNSD` and `TCP_INFO` (`rtt`, `unacked`, `snd_cwnd`) during a rate decrease or loss transition, rather than changing readiness bookkeeping or pipe/source behavior.
