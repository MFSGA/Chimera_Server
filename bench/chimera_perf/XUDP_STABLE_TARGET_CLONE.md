# XUDP stable-target clone attribution

## Hypothesis

For an established XUDP session, `SessionStatus::Keep` may repeat the same hostname target. The decoder previously cloned that target into the stored session state on every such frame even when the value was unchanged. Because hostname `NetLocation` owns a `String`, this creates a payload-independent allocation/copy in the packet decode path.

The candidate first compares the borrowed metadata target with the session target and clones only when the target actually changes. The returned frame still owns the metadata target, and a changed target is still copied into session state, preserving the existing framing and session semantics.

## Benchmark

`xudp_session_target_update_bench` models an established hostname session and 5,000,000 repeated Keep target updates per process. Release binaries were pinned to CPU 0. Three warm-up pairs preceded ten measured pairs with alternating execution order.

Measured `clone` samples (ns/frame):

`19.106, 16.499, 15.817, 18.826, 18.430, 18.432, 26.419, 15.952, 15.689, 15.714`

Measured `compare` samples (ns/frame):

`10.870, 10.336, 9.125, 9.057, 10.691, 10.544, 14.122, 9.397, 8.976, 8.913`

Every measured pair favored the compare-before-clone candidate. Both variants produced checksum `177500000` in every run. The host showed some run-to-run frequency noise, but the direction stayed stable across all alternating-order pairs and the candidate remained substantially separated from baseline.

## Production slice

For `SessionStatus::Keep` on a known session, borrow `metadata.target`, compare it to the stored target, and clone only when the target differs. No new state, unsafe code, task, lock, syscall, timer, or protocol branch is introduced beyond the equality check needed to avoid the allocation.

The existing changed-target regression test continues to verify that a Keep frame carrying a different target updates both the emitted target and stored session state.
