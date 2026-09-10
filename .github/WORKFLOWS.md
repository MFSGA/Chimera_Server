# GitHub Actions layout

The repository uses four entry-point workflows and two shared local actions. Keep each workflow focused on one responsibility instead of copying setup and release logic between files.

## Workflows

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `ci.yml` | `master` push, pull request, manual | Fast correctness gate: format, clippy, cross-platform tests, release-target builds |
| `proxy-throughput.yml` | Relevant pull requests, manual | End-to-end proxy throughput benchmark against the pinned Xray binary |
| `hysteria2-performance.yml` | Hysteria2-relevant pull requests, manual | RTT/loss/congestion benchmark under Linux netem |
| `release.yml` | Manual only | Resolve one immutable candidate, validate it, build every release artifact, then publish |

Tag pushes do not run the ordinary CI workflow. A release already runs its own exact-SHA gates before creating the tag, and historical release sources may predate the current local composite actions.

## Shared actions

`actions/rust-ci-setup/action.yml` is for workflows that always run from the current repository revision. It owns stable Rust setup, Rust caching, and the pinned `cross` revision.

`actions/setup-pinned-xray/action.yml` owns benchmark Xray download and checksum verification. The selected version and checksum remain in `bench/.xray-version` and `bench/.xray-linux-64.sha256`.

The release workflow intentionally does not depend on these local actions. `source_ref` supports historical commits, and an old candidate may not contain the current `.github/actions` directory. Release setup therefore remains self-contained while using the same pinned tool revision.

## CI contract

The ordinary CI workflow has three independent job classes so failures are easy to classify:

```text
lint            fmt + clippy

test            Ubuntu + Windows workspace tests

build           Linux GNU + Linux musl + Windows MSVC release-target builds
```

Jobs run in parallel. A formatting failure should not hide a Windows compile failure, and one target failure should not cancel the other matrix entries.

Build/reference rules:

- `chimera_server_lib/build.rs` uses vendored `protoc`; CI must not install a second system Protoc without a demonstrated need.
- `ref/shoes`, `ref/clash-rs`, and `ref/xray-core` are behavior references, not Cargo build dependencies; ordinary CI does not fetch submodules.
- GNU and Windows builds use native `cargo`; only musl uses `cross`.
- CI commands use the committed lockfile.
- Platform-specific code and ignored tests must still compile on every supported CI target unless explicitly guarded by `cfg`.

## Release contract

A release is an orchestration pipeline, not a second general CI system:

```text
resolve exact candidate
        |
        +--> Linux/Windows preflight tests
        |
        +--> repository release gates
                    |
          +---------+---------+
          |                   |
     Linux artifacts      Windows artifacts
          |                   |
          +---------+---------+
                    |
             verify artifacts
                    |
              create tag
                    |
             publish release
```

Only the final publish job has `contents: write`. Tests and artifact jobs run with read-only repository permissions. No tag may be created until both platform artifact jobs have succeeded and all expected checksums are present and verified.

The candidate is resolved once to a full commit SHA. Every subsequent release job checks out that SHA, even when the dispatch input used a branch, short SHA, or historical tag.

## Benchmark contract

Performance workflows are deliberately separate from correctness CI. They are path-filtered on pull requests and can also be dispatched manually for larger matrices.

Both benchmark workflows:

- use the repository-pinned and checksum-verified Xray binary;
- build Chimera in release mode with the lockfile;
- upload raw logs/results even when the benchmark fails;
- publish a readable GitHub Actions summary.

The throughput benchmark job is read-only. Its PR comment is handled by a separate best-effort job that does not check out PR code; failure to obtain comment permissions, such as on a fork pull request, must not turn a completed benchmark into a failed benchmark job.

## Maintenance rules

When changing workflow infrastructure:

1. Keep repository permissions at `contents: read` unless a specific job requires more.
2. Add shared setup to `.github/actions` only when historical checkout compatibility is not required.
3. Pin external build tools that are installed from Git rather than following their moving HEAD.
4. Avoid global secrets and environment variables unless every job needs them.
5. Prefer explicit job timeouts for network, benchmark, build, and release work.
6. Keep platform tests independent so one operating system cannot hide another operating system's failure.
7. Do not trigger `release.yml` merely to validate workflow edits; validate through ordinary CI and only dispatch a release when publication is explicitly requested.
