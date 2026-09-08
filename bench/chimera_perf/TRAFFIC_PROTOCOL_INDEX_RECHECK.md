# Traffic protocol index independent recheck

## Scope

This round started from committed HEAD `adbccae17044a8d69d717ad4995af74b10f20ecc` in an isolated clean worktree. While preparing to merge a benchmark-backed traffic-recorder optimization, the source checkout was found to already contain an unrelated, uncommitted implementation of the same hotspot: identity-bearing records avoid a second outer protocol lookup by storing identity protocol totals together with the nested identity map, while the identity-free `per_protocol` path stays unchanged.

Because that production code predates this round's merge step and belongs to the existing dirty checkout, it was not overwritten, staged, or committed here. Instead, its exact `traffic_impl.rs` diff against committed HEAD was exported and reapplied in the isolated worktree for an independent benchmark recheck.

## Hotspot and hypothesis

For an identity-bearing traffic record, the committed baseline updates `per_protocol[protocol]` and then separately updates `per_identity[protocol][identity]`. That hashes and looks up the same `&'static str` protocol key twice. The existing uncommitted candidate keeps identity-free traffic on the original `per_protocol` map, but for records with an identity performs one lookup into `IdentityProtocolStats`, updating both its protocol totals and nested identity totals. Snapshot reconstruction merges identity-bearing protocol totals back into the public `per_protocol` map, so the public `TrafficSnapshot` representation is unchanged.

## Exact-candidate benchmark

The committed HEAD baseline and the exact source-checkout candidate were each compiled once into separate release test binaries. The existing ignored `traffic_record_probe` then ran the binaries directly to avoid rebuild/layout changes between paired samples.

Common settings:

- CPU affinity: 0-3
- four long-lived writer threads
- five million records per sample
- one warmup pair plus one measured clone/ref pair per process
- comparison metric: borrowed-ref CPU seconds per million records
- eight independent pairs per shape
- baseline/candidate execution order alternated by pair

### Identity-only

Paired candidate/baseline CPU ratios:

`0.8172, 0.6801, 0.7638, 0.6977, 0.6902, 0.7925, 0.7307, 0.7626`

- baseline median: **0.084398 s/Mrecord**
- candidate median: **0.064210 s/Mrecord**
- paired ratio median: **0.7466x**
- favorable pairs: **8/8**
- ratio range: **0.6801x-0.8172x**

### Full Shadowsocks context

Paired candidate/baseline CPU ratios:

`0.7341, 0.8922, 0.8744, 0.7807, 0.8336, 0.8545, 0.9830, 0.8909`

- baseline median: **0.142342 s/Mrecord**
- candidate median: **0.122800 s/Mrecord**
- paired ratio median: **0.8644x**
- favorable pairs: **8/8**
- ratio range: **0.7341x-0.9830x**

The exact candidate also passed the focused traffic implementation test set: **8/8** tests, including the protocol-total/per-identity snapshot equivalence test.

## Related clean-worktree experiment

Before the pre-existing checkout candidate was discovered, a simpler isolated candidate combined all protocol totals and identities into one `ProtocolStats` map. Eight full-Shadowsocks pairs also favored that shape, with a **0.8868x** paired CPU-ratio median. Full required root-workspace gates passed for that clean experiment: `cargo fmt --all -- --check`, `cargo build --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, and `cargo test --locked`; the library suite reported **1167 passed / 0 failed**.

The existing checkout candidate is preferable structurally because it keeps identity-free protocol accounting on the established narrow value type instead of making every protocol record touch a larger nested structure. This round therefore does not merge the simpler candidate.

## Conclusion

The duplicate outer protocol lookup is independently confirmed as a real traffic-recorder CPU hotspot for identity-bearing data-plane traffic. The exact candidate already present in the checkout shows a strong and repeatable reduction in the production-shaped recorder probe without changing public snapshot semantics. No production file is committed in this round because the validated implementation was already an unrelated uncommitted checkout modification; this report records the independent evidence without taking ownership of that work.

For TCP Brutal2 specifically, previous controller/readiness iterations have already pushed many local micro-candidates toward the noise floor. The next useful Brutal2 iteration should return to production-shaped estimator/publication or connection-scale profiling rather than add another sub-percent ACK dispatch branch.
