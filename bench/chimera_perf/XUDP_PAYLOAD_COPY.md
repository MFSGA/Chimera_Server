# XUDP payload handoff copy benchmark

This iteration re-ranked a non-TCP data-plane hotspot after the current TCP Brutal2 relay/readiness and ACK arithmetic lines had largely converged. The XUDP reader already owns each complete frame in a `BytesMut`, then `split_to()` isolates the payload. The production path immediately called `.to_vec()` on that split before sending it through the bounded reader channel, which adds one heap allocation and one full payload copy before `poll_read_session_message()` copies the payload into the caller's `ReadBuf`.

The candidate keeps the `BytesMut` returned by `split_to()` as the private `DecodedFrame`/`IncomingMessage` payload. Frame parsing, channel capacity/backpressure, target resolution, session state, and the final `ReadBuf::put_slice()` copy are unchanged. This removes only the intermediate allocation/copy; no unsafe code or new syscall path is introduced.

## Focused benchmark

`xudp_payload_copy_bench` models the exact ownership choice for a 1200-byte UDP payload. Both modes allocate/fill the same input `BytesMut`, parse the same two-byte length, and call `split_to(payload_len)`. `vec` then performs the production `.to_vec()` copy while `split` retains the split buffer. Each process handles two million payloads.

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin xudp_payload_copy_bench

XUDP_PAYLOAD_BENCH_MODE=vec taskset -c 0 \
  bench/chimera_perf/target/release/xudp_payload_copy_bench
XUDP_PAYLOAD_BENCH_MODE=split taskset -c 0 \
  bench/chimera_perf/target/release/xudp_payload_copy_bench
```

After three warmup pairs, ten independent alternating-order pairs measured:

- `vec` median: **89.442 ns/payload**
- `split` median: **64.148 ns/payload**
- paired `split / vec` ratio median: **0.710x**
- paired ratio range: **0.640x-0.747x**
- favorable pairs: **10/10**
- all runs produced the same checksum

Paired ratios were `0.7126, 0.6935, 0.7085, 0.7466, 0.7116, 0.7342, 0.7183, 0.6401, 0.6685, 0.6944`.

This is a component benchmark, not an end-to-end packet-rate claim. It establishes that the intermediate allocation/copy is large enough to be a real per-datagram CPU cost and that retaining the existing split buffer materially reduces that cost.

## Correctness scope

The production type change is private to `handler/xudp/message_stream.rs`. Existing XUDP tests cover fragmented/coalesced frames, maximum-size UDP payloads, channel backpressure, session takeover, keep/end/error handling, and runtime UDP roundtrips. The candidate does not retain external references to the mutable reader buffer; `BytesMut::split_to()` transfers the split region into its own handle while the reader continues with the remaining region.

Grouped XUDP runs expose an existing asynchronous response-order flake in `global_id_takeover_across_session_ids_rebinds_responses` (`24` observed where the test expects `25`). The candidate reproduced it, while five immediate exact candidate reruns passed. A separate pristine `b6961635` worktree then reproduced the same grouped failure in **3/3** baseline runs; one baseline run also reordered the `repeated_global_new_preserves_queued_payload_and_udp_socket` payloads. This establishes that the grouped-order failure predates the payload representation change. Full workspace test output should still report it explicitly if it recurs.

## Brutal2 screening in this pass

Before moving to XUDP, a small Brutal2 hypothesis was tested: cache the MTU-derived minimum congestion-window floor instead of recomputing `max_datagram_size.saturating_mul(MIN_CONGESTION_WINDOW_DATAGRAMS)` on every ACK. Twelve CPU-pinned process pairs were strongly bimodal (roughly 2.8-3.1 and 5.6-7.0 ns/ACK), with candidate direction reversing repeatedly. The effect is below the current host noise floor, so no Brutal production change or benchmark mode is retained from that experiment.
