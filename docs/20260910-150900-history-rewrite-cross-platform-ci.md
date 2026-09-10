# History rewrite and cross-platform CI incident — 2026-09-10

## Summary

This note records two related release-preparation lessons from the `v0.8.0` candidate:

1. how to handle the noisy release-preparation tail if Git history cleanup is desired; and
2. why the exact source commit passed the Linux release gates while the normal Windows CI test job failed.

No history rewrite is authorized by this document. Rewriting `master`, moving/deleting a published tag, deleting a GitHub Release, force-pushing, or republishing requires a separate explicit decision.

## Repository state at the time of analysis

The relevant tail is:

```text
8efe668 test(udp): avoid DNS in trojan routing test
99bef46 test(udp): stabilize trojan routing timeout
432579f chore(release): prepare v0.8.0
99cca7d docs(compat): correct hysteria udp evidence
92261b1 test(hysteria2): account for legacy xray udp limit
```

At the time this note was written:

- `master` and `origin/master` pointed to `8efe6689917275323e845ec4541fc2da72a29171`;
- annotated tag `v0.8.0` pointed to the same commit;
- a GitHub Release for `v0.8.0` already existed;
- the normal push CI run for `8efe668` was red because `Tests (windows-latest)` failed;
- the release workflow could nevertheless complete its Linux release gates and publish before the independent Windows CI result was used as a release prerequisite.

This last point is a workflow gap: a green Linux release job is not sufficient evidence that the exact commit is cross-platform clean.

## Cross-platform CI incident

### Failure

The failing command in the normal CI matrix was:

```sh
cargo test --workspace --all-features
```

on `windows-latest`.

Compilation failed in:

```text
chimera_server_lib/tests/traffic_record_probe.rs
```

because the performance probe directly referenced Unix/POSIX `libc` APIs:

```rust
libc::rusage
libc::getrusage
libc::RUSAGE_SELF
libc::timeval
```

These symbols are not available from the Windows `libc` target, producing `E0425` before the test suite could run.

### Why `#[ignore]` did not protect CI

The affected performance test is marked `#[ignore]`, but an ignored Rust test is still compiled. `#[ignore]` suppresses execution under ordinary `cargo test`; it is not a platform compilation gate.

If a test target, helper, benchmark-like integration test, or support module contains target-specific APIs, the code itself must use an appropriate `#[cfg(...)]` boundary or a portable abstraction.

### Why release preparation missed it

The required repository release commands were run on Linux and passed:

```sh
cargo fmt --all -- --check
cargo build --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --locked
```

The release workflow also runs these gates on `ubuntu-latest`. Its Windows job currently runs only after the Linux job has created the tag and GitHub Release, and that Windows release job builds the application binary rather than running `cargo test --workspace --all-features`.

Meanwhile `.github/workflows/ci.yml` does contain a Windows test matrix entry. The process failure was that successful release preparation was treated as sufficient without first requiring the exact source SHA's normal cross-platform CI matrix to be green.

### Preventive actions

P0 — source/test fix:

- Make `traffic_record_probe.rs` explicitly portable or explicitly Unix-only at compile time.
- If CPU-time measurement remains Unix-specific, put the Unix symbols behind `#[cfg(unix)]`; do not rely on `#[ignore]`.
- If the probe is expected to work on Windows, implement a Windows CPU-time backend rather than compiling Unix `libc` calls there.

P0 — release workflow ordering:

- Do not create a release tag or GitHub Release until Windows test compilation/testing for the exact candidate SHA is green.
- Prefer restructuring the release workflow into preflight jobs (`ubuntu` + `windows`), artifact build jobs, and a final publish job that `needs` all required jobs.
- The Windows release binary should be built before the final publish step, not appended only after a Release already exists.

P1 — exact-SHA release rule:

- Before a release, verify that the normal CI matrix for the exact candidate SHA is green, including at least `Tests (ubuntu-latest)`, `Tests (windows-latest)`, and the supported build targets.
- A local Linux gate or an Ubuntu-only release gate must never be used as a substitute for cross-platform CI.

P1 — code review rule:

- Treat direct uses of `libc`, Unix signals, file-descriptor APIs, socket options, path assumptions, shell commands, and OS-specific process APIs as platform-sensitive.
- Every such use in shared code or test targets needs an explicit portability decision and corresponding `cfg` coverage.

## History rewrite analysis

### Recommended default: do not rewrite tagged history

Because `v0.8.0` already points to `8efe668`, rewriting any commit at or before that SHA changes the source identity of an already published version.

The safest path is therefore:

1. keep the published tag immutable;
2. add a normal follow-up commit that fixes the Windows test compilation;
3. make future release workflow changes as normal commits;
4. if a corrected release is needed, use a new version rather than silently reusing `v0.8.0` with different source history.

This preserves auditability and avoids breaking clones, CI references, checksums, links, or anyone who already fetched the tag.

### If a clean rewrite is explicitly chosen

If the repository owner decides that history cleanliness outweighs preserving the published `v0.8.0` identity, use a surgical tail rewrite only. Do not rewrite the full `v0.7.21..HEAD` range.

The useful base is `99cca7d`. The net effect of the next three commits is:

- workspace version becomes `0.8.0`;
- the Trojan UDP routing test uses a literal TEST-NET IP instead of `origin.example`;
- the final timeout is back to 5 seconds.

Therefore `99bef46 test(udp): stabilize trojan routing timeout` had no useful final-state effect and was intentionally removed from the curated history. The authorized rewrite uses `99cca7d` as the stable base and orders the release tail by dependency rather than discovery chronology:

```text
<new> test(udp): avoid DNS in trojan routing test
<new> fix(platform): restore Windows compatibility
<new> ci(release): gate publishing on Windows and Linux
<new> docs(workflow): document cross-platform release safeguards
<new> chore(release): prepare v0.8.0
99cca7d docs(compat): correct hysteria udp evidence
```

This keeps the version bump last, after the candidate tests, platform behavior and release gates are already clean.

### Executed rewrite procedure

The rewrite was explicitly authorized and performed surgically from `99cca7d`; the much larger pre-existing project history was not rewritten. Recovery refs were created before each destructive branch rewrite stage, the expected old `origin/master` SHA was recorded, and the final tree is verified against the pre-rewrite tree before any shared-branch update.

The remote branch update, when performed, must use `--force-with-lease` against the recorded old SHA. The existing published `v0.8.0` tag/Release remains a separate pointer decision and must not be silently moved merely because `master` history was curated.

Never use `git reset --hard` or a blind `git push --force` as the rewrite procedure.

## Release-operation boundary

Release preparation and actual publication are separate operations. Preparing a version, running release gates, or discussing a release must not by itself authorize any of the following:

- pushing a release tag;
- publishing or deleting a GitHub Release;
- moving an existing tag;
- force-pushing rewritten history;
- deleting remote refs.

Before an irreversible remote operation, state the exact candidate SHA and the remote mutation that will occur, then obtain explicit authorization for that operation.

## Follow-up checklist

- [x] Scope the Unix CPU-time performance probe so Windows test compilation does not reference `getrusage`.
- [x] Make the SOCKS external echo helper's socket mode explicit across platforms.
- [x] Align unsupported `SO_REUSEPORT` behavior with Xray's Windows no-op semantics instead of panicking.
- [x] Keep Unix-domain webhook assertions out of non-Unix test paths.
- [x] Add permanent cross-platform and irreversible-operation rules to `AGENTS.md`.
- [x] Add Linux/Windows preflight to `.github/workflows/release.yml` and pin default checkout to the dispatch SHA.
- [x] Curate the noisy release tail and remove the superseded timeout-only commit.
- [ ] Verify the rewritten exact SHA in normal Linux/Windows CI before a future stable publication.
- [ ] Decide separately whether the already-published `v0.8.0` tag/Release pointer should remain immutable.
