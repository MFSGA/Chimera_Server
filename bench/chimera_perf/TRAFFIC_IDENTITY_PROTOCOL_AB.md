# Traffic identity/protocol lookup A/B

Date: 2026-09-07

This note records a negative follow-up to the traffic-recorder string-index work. The working tree already contained an uncommitted candidate that changes identity-bearing records from separate `per_protocol[protocol]` and `per_identity[protocol][identity]` updates to an `IdentityProtocolStats` entry containing both protocol totals and the per-identity map. The intended mechanism is to avoid hashing the same static protocol key twice.

To avoid comparing against an older build or relying on the candidate's existing README claim, a clean detached worktree at HEAD (`4c2e76607b21289f7aa8923429f0697606b727bb`) was built independently and compared with the current candidate. Both sides used the production `traffic_record_probe` in release mode, four writers pinned to CPUs 0-3, borrowed-ref recording, and the same context shapes.

## Long-sample identity-only result

Configuration: 10,000,000 records/sample, 2 warmup pairs, 10 measured pairs.

- HEAD baseline borrowed-ref CPU median: **0.083582 s/Mrecord**.
- Candidate borrowed-ref CPU median: **0.083166 s/Mrecord**.
- Candidate/baseline ratio: **0.9950x** (about **0.5% lower CPU**).
- Baseline ref CPU CV: **3.43%**; candidate ref CPU CV: **1.88%**.

This is too small to support a production layout change on the claimed duplicate-protocol-hash mechanism.

## Full Shadowsocks control

Configuration: 5,000,000 records/sample, 1 warmup pair, 8 measured pairs.

- HEAD baseline borrowed-ref CPU median: **0.135009 s/Mrecord**.
- Candidate borrowed-ref CPU median: **0.129265 s/Mrecord**.
- Candidate/baseline ratio: **0.9575x** (about **4.3% lower CPU**).
- Baseline ref CPU CV: **1.82%**; candidate ref CPU CV: **6.04%**.

The full-shape signal is larger, but it is not reproduced by the isolated `identity-only` shape that directly exercises the proposed mechanism. Because the candidate changes snapshot reconstruction and internal ownership for all identity-bearing protocols, the inconsistent component attribution is insufficient evidence for committing the production change.

## Decision

Do **not** commit the `IdentityProtocolStats` production candidate based on the current data. Keep the already-proven inbound-index sharing optimization from HEAD, and treat protocol/identity outer-lookup fusion as rejected until a stricter paired harness can reproduce a stable isolated benefit. A useful next step is to benchmark the map operation itself or add an in-process implementation selector so baseline and candidate share one binary/code layout; avoid extrapolating from full-context noise.
