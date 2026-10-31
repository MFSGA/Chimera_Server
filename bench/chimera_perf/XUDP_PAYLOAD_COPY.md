# XUDP session payload handoff

The XUDP frame decoder already uses `BytesMut::split_to()` to isolate the
payload and passes that owned buffer through the bounded reader channel. The
old session handoff then copied the payload into a per-connection 64 KiB
`ReadBuf`, after which `run_session_based_udp()` copied it again into the
`Vec<u8>` required by the existing worker sender.

`SessionMessage::Data` now owns a `Vec<u8>`. `XudpMessageStream` copies the
decoded payload into that vector once, and the session owner moves it directly
to the worker path. This removes one payload copy and the fixed 64 KiB scratch
allocation per session-based UDP connection. Routing, target selection,
GlobalID attachment, traffic accounting, queue backpressure, retries, and XUDP
wire framing are unchanged. A single payload copy remains deliberately: it
releases the decoder's shared read-buffer allocation before routing or worker
queue delays can extend its lifetime.

## Focused component benchmark

`xudp_payload_copy_bench` compares the old session handoff (`buffered`: copy
into the legacy 64 KiB scratch buffer, then copy into a `Vec`) with the new
handoff (`direct`: copy the split payload directly into the owned `Vec`). Both
modes construct and parse the same length-prefixed `BytesMut` payload and run
two million 1,200-byte payloads per invocation.

```bash
cargo build --release --manifest-path bench/chimera_perf/Cargo.toml \
  --bin xudp_payload_copy_bench

XUDP_PAYLOAD_BENCH_MODE=buffered taskset -c 0 \
  bench/chimera_perf/target/release/xudp_payload_copy_bench
XUDP_PAYLOAD_BENCH_MODE=direct taskset -c 0 \
  bench/chimera_perf/target/release/xudp_payload_copy_bench
```

On Linux 6.18.35, an AMD Ryzen 7 5800, Rust 1.98.0, and CPU 0 pinned, three
warmup pairs were followed by 20 alternating-order pairs. All results had the
same checksum:

| Mode | Median ns/payload | Across-invocation CV |
| --- | ---: | ---: |
| Old buffered handoff | 78.511 | 0.96% |
| Direct owned handoff | 74.480 | 1.81% |

The median paired `direct / buffered` ratio was **0.945x** (about **5.5% less
handoff time**), ranging from 0.917x to 1.014x; 19 of 20 pairs favored the new
path. This is a component benchmark of payload copies and allocation. It does
not include sockets, Tokio scheduling, routing, worker queues, or network
latency and is not an end-to-end throughput claim.

## Correctness and known test ordering race

The XUDP stream tests cover the new message handoff for ordinary and maximum
65,535-byte payloads, fragmented/coalesced frames, channel backpressure,
session takeover, keep/end/error handling, and runtime UDP roundtrips. The
fixed Xray 26.9.9 client smoke
`xray_client_remote_policy_update_reaches_new_xudp_session` passes after its
local UDP echo fixture explicitly allows `127.0.0.1/32` and its selected UDP
port through Freedom `finalRules`. It was rerun with official Xray 26.10.29
(`0afec66`, Go 1.27.3, Linux amd64) using that port-scoped rule and passed.

`global_id_takeover_across_session_ids_rebinds_responses` has a pre-existing
response-order race: it can observe session 24 where the test assumes session
25. This was reproduced against a pristine `b6961635` worktree in 3/3 grouped
runs before this handoff change; the exact test also passes on repeated
isolated runs. Treat a recurrence as a test-ordering failure requiring separate
investigation, not as a payload truncation result.
