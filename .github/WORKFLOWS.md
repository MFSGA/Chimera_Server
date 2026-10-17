# GitHub Actions layout

The repository uses six entry-point workflows and two shared local actions. Keep each workflow focused on one responsibility instead of copying setup and release logic between files.

## Workflows

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `ci.yml` | `master` push, pull request, manual | Fast correctness gate: format, clippy, cross-platform tests, release-target builds |
| `auto-merge.yml` | Successful `CI` completion and Dependabot PR state/review updates | Auto-merges only same-repository Dependabot Cargo dependency PRs targeting `master`, after required gates pass |
| `xray-compatibility.yml` | Manual only | Runs a small real-client smoke suite against the checksum-verified pinned Xray binary |
| `proxy-throughput.yml` | Relevant pull requests, manual | End-to-end proxy throughput benchmark against the pinned Xray binary |
| `hysteria2-performance.yml` | Hysteria2-relevant pull requests, manual | RTT/loss/congestion benchmark under Linux netem |
| `release.yml` | Manual only | Generate an Xray-style UTC calendar version, validate/build a temporary release commit, then atomically advance `master` with the tag and publish |

Tag pushes do not run the ordinary CI workflow. A release already runs its own exact-SHA gates before creating the tag.

## AI-assisted development governance

The authoritative Codex workflow and risk-based approval policy are in
[`docs/ai-development-governance.md`](../docs/ai-development-governance.md),
with independent review checks in
[`docs/ai-review-checklist.md`](../docs/ai-review-checklist.md).
Pull requests use `.github/pull_request_template.md`; confirmed failures
are recorded in `LESSONS.md`. These are **procedural rules**, not proof that
an autonomous coding or AI review GitHub Action has already been installed.

- The existing Rust CI jobs remain the authoritative mechanical quality gates.
  AI feedback is additive and cannot replace format, Clippy, Windows/Linux tests,
  feature-matrix checks or release candidate validation.
- The auto-merge workflow is limited to same-repository Dependabot Cargo
  dependency PRs targeting `master`. It merges only after every required CI job
  succeeds and GitHub reports all merge gates satisfied. Ordinary PRs, other
  bots, GitHub Actions dependency updates under `.github/**`, and other L3
  changes remain manual. Confirmed branch protections must be enabled for it
  to activate; fork PRs are excluded, and labels do not grant authorization.
- AI review workflows must not run untrusted PR code with writable credentials
  or invoke privileged tooling on untrusted Issue/PR content.
- Stable releases remain **manual** via `release.yml`. Do not attach release
  publication to PR auto-merge, push events or an AI verdict.
- Any future nightly retrospective may suggest Lessons or PRs but cannot bypass
  review or weaken required checks.

## Shared actions

`actions/rust-ci-setup/action.yml` is for workflows that always run from the current repository revision. It owns stable Rust setup, Rust caching, and the pinned `cross` revision.

`actions/setup-pinned-xray/action.yml` owns benchmark Xray download and checksum verification. The selected version and checksum remain in `bench/.xray-version` and `bench/.xray-linux-64.sha256`.

The release workflow uses `actions/rust-ci-setup/action.yml` after it creates the candidate commit. Stable releases always start from the current `master`; historical backfills are intentionally kept out of the normal release path so the main workflow has one predictable versioning model.

`.github/scripts/release_version.py` owns the Xray-style calendar version and workspace-version edit. It formats the workflow's UTC date as `YY.M.D` (for example, `26.10.12`), writes that value to the workspace manifests and lockfile, and advances the final component when another release is made on the same date. Existing tags remain available as the changelog comparison point; generated versions must remain newer than the latest tag.

## CI contract

The ordinary CI workflow has three independent job classes so failures are easy to classify:

```text
lint            fmt + clippy

test            Ubuntu + Windows workspace tests

build           Linux GNU + Linux musl + Windows MSVC release-target builds
required-checks stable aggregate over every required CI job
```

Jobs run in parallel. A formatting failure should not hide a Windows compile failure, and one target failure should not cancel the other matrix entries.

## Xray compatibility smoke contract

`xray-compatibility.yml` is a manual smoke workflow and is not a required check. Select `master`
when dispatching it; a runtime check fails fast if another ref was selected. This check prevents
accidental ref selection but is not a security boundary: GitHub runs the workflow definition from
the selected ref. The job has read-only repository permissions, uses no secrets, and downloads Xray
through the existing checksum-verifying `setup-pinned-xray` action. It then runs exact ignored
real-client tests for VLESS over TCP, gRPC, and HTTPUpgrade against local TCP echo targets. The
workflow records the client version and Xray source-reference commit and uploads each test log for
30 days. A missing or unmatched test is treated as a failure rather than a successful empty run.

The client binary version comes from `bench/.xray-version` (currently `v26.7.28`) and its checksum
from `bench/.xray-linux-64.sha256`. This published client build is distinct from the checked-out
Xray source reference (`ref/xray-core` v26.10.10, commit
`701af60772cda123492f86e383e1fdba066614a9`); the workflow reports both and does not claim that the
older client binary is the reference source build. This smoke suite does not certify TLS/REALITY,
UDP, the full compatibility matrix, or Xray TUN/system-namespace behavior. Those checks still need
their explicitly recorded client versions and prerequisites.

`auto-merge.yml` checks successful PR CI completions and Dependabot PR state/review events. The live PR must be authored by `dependabot[bot]`, come from this repository, target `master`, be open and ready for review. The changed files must be Cargo manifests or lockfiles only. Ordinary PRs and other bots are skipped without changing their merge state. Dependabot PRs touching `.github/**`, `docs/ai-*`, `ref/**`, `vendor/**`, release/install paths, `AGENTS.md`, `LESSONS.md`, `CODEOWNERS`, or any non-Cargo file stay manual. Events are serialized per PR. The workflow checks every expected CI job on the matching head SHA and never checks out pull-request code or consumes its artifacts. It re-reads the PR, base, head and complete file list immediately before merging, and only proceeds when all of the following hold:

- The PR author is `dependabot[bot]`; it comes from this repository, targets `master`, is open, is not a draft, and its head has not changed since the successful CI run.
- The complete changed-file list is available and every changed path is a `Cargo.toml` or `Cargo.lock`; this excludes `.github/**` workflow dependency updates and other L3 paths.
- Every expected CI job succeeded on that exact head SHA and run attempt.
- `CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED=true` is set. An administrator uses that variable to confirm that `CI / Required checks`, required approvals and stale-approval dismissal apply to the workflow token, with no merge queue configured. The configured administrator exception may remain; the Actions token must not be granted a bypass.
- GitHub reports the PR as clean and mergeable; the workflow immediately uses the pull-request merge API pinned to the verified head SHA. If gates are still pending, it skips and retries on the next CI completion or review event. It does not create a persistent GitHub Auto-merge request. The job needs `contents: write` for the merge API call and executes only this trusted script from the default branch.

The synchronous merge API does not support merge queues. The final live PR read and head-SHA pin also cannot atomically pin the base branch; if someone retargets a PR in the small interval before the merge request, GitHub may evaluate the then-current base. The workflow compares the base SHA and rechecks the file list immediately before merging to narrow this race.

The workflow skips when a prerequisite is absent. GitHub Actions `GITHUB_TOKEN` cannot read repository administration settings, so the workflow does not inspect branch protection or rulesets itself; setting the confirmation variable without those protections would allow an unsafe immediate merge. An administrator must verify the protections and set the confirmation variable before this automation can activate. GitHub's repository Auto-merge setting is not needed because the workflow uses only the synchronous merge API. The current read-only account could not verify those administrator settings through the API.

Required CI, up-to-date branch and review protections remain enforced by GitHub when the workflow requests or completes an eligible Dependabot merge. All human-authored PRs and Dependabot PRs touching protected L3 paths remain manual-merge decisions. The administrator exception permits administrators to bypass those protections for their own actions; the workflow token is not an administrator and must not be added as a bypass actor.

Build/reference rules:

- `chimera_server_lib/build.rs` uses vendored `protoc`; CI must not install a second system Protoc without a demonstrated need.
- `ref/shoes`, `ref/clash-rs`, and `ref/xray-core` are behavior references, not Cargo build dependencies; ordinary CI does not fetch submodules.
- GNU and Windows builds use native `cargo`; only musl uses `cross`.
- CI commands use the committed lockfile.
- Platform-specific code and ignored tests must still compile on every supported CI target unless explicitly guarded by `cfg`.

## Release contract

A release is an orchestration pipeline, not a second general CI system. The manual dispatch asks only for the release goal; the workflow generates the `YY.M.D` version from the UTC date so callers do not type a version manually.

```text
read current UTC date
            |
   format version as YY.M.D
            |
 update Cargo.toml + Cargo.lock
            |
 create temporary candidate commit/branch
            |
        +---+----------------+------------------+
        |                    |                  |
 Linux/Windows tests   feature matrix    repository release gates
        |                    |                  |
        +-----------+--------+------------------+
                    |
          +---------+---------+
          |                   |
     Linux artifacts      Windows artifacts
          |                   |
          +---------+---------+
                    |
      verify artifacts + checksums
                    |
 re-check that origin/master did not move
                    |
 atomic push: master + annotated tag
                    |
             publish release
                    |
       delete candidate branch
```

The release candidate is a direct child of the `master` commit captured when the workflow starts. It is first pushed to a temporary `release-candidate-*` branch so all operating-system tests and release artifacts can validate the exact version-bump commit without modifying `master`. If validation fails, `master` and stable tags remain unchanged and cleanup removes the temporary branch.

The candidate release also runs the ordinary CI feature compatibility matrix, release-version
helper check, and locked builds on that exact commit. Its platform tests and release artifacts cover
the same Windows, Linux GNU, and Linux musl targets as normal CI before the tag can be published.

Before publication, the workflow verifies that remote `master` is still the original base commit. It then uses one atomic Git push for both the fast-forward of `master` and creation of the annotated stable tag. A concurrent change to `master` therefore fails closed and requires a fresh release dispatch.

Repository permissions default to `contents: read`. Only the prepare, publish, and cleanup jobs receive `contents: write`, and each uses it for a narrowly defined release mutation. No stable tag or `master` version bump may become visible until both platform artifact jobs have succeeded and all expected checksums are present and verified.

Release pages use the `Chimera Server vYY.M.D` title and a concise English release highlight,
platform downloads, compatibility link, and full changelog comparison. Release
archives follow the Xray-style platform ZIP layout for the targets Chimera currently builds:
Linux x86_64 GNU, Linux x86_64 musl, and Windows x86_64. Each archive contains the executable,
README, license, and a minimal example config; a sibling `.dgst` file contains SHA-256 and
SHA-512. The Linux installer downloads `Chimera-linux-64.zip`, verifies SHA-256, and extracts
the server binary. Cargo's three-part version field follows the same `YY.M.D` calendar format;
the components identify year, month, and day (or a same-day sequence) rather than SemVer
compatibility increments. Multiple releases on one UTC day use the next available final component,
matching Xray's same-day release sequence behavior.

The pinned Xray-core `v26.10.10` workflow builds and uploads artifacts after a GitHub Release is
published. Chimera follows its calendar version, platform ZIP, and `.dgst` conventions while
keeping candidate creation, cross-platform preflight, artifact verification, atomic tag/master
push, and Release creation in one gated workflow. This keeps the public tag and Release downstream
of the validation gates.

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

## Dependency update policy

Dependency maintenance must preserve reproducibility and reviewability:

- Do not perform unrelated dependency upgrades during feature or bug-fix changes.
- Review dependency updates as behavior changes, including transitive changes that affect security, build reproducibility, or platform support.
- Keep `Cargo.lock` changes limited to intentional dependency updates or release version changes.
- Prefer updating dependencies through normal pull requests with CI coverage rather than changing versions directly in release workflows.
- Document compatibility-impacting dependency changes in the relevant change notes.

## Feature compatibility checks

Workflow changes and new capabilities must keep compatibility boundaries explicit:

- New protocol, transport, security, or platform capabilities require corresponding validation coverage before being described as supported.
- CI configuration must not silently skip required compatibility checks through feature flags, conditional jobs, or missing matrix entries.
- When a feature depends on optional Cargo features, verify the intended feature combination explicitly.
- Keep unsupported combinations visible through diagnostics or documentation rather than silently accepting them.

## Benchmark policy

Benchmarks are engineering measurements, not release substitutes:

- Benchmark changes must record the workload, binary versions, build mode, and environment assumptions.
- Compare measurements only when the client, server, transport, and security settings are equivalent.
- Avoid using benchmark results to justify compatibility claims unless correctness validation has also passed.
- Keep benchmark artifacts and logs available for investigation of regressions.

## GitHub Actions supply-chain policy

Actions and workflow dependencies must be controlled:

- Pin third-party GitHub Actions to reviewed versions or immutable references where practical.
- Avoid executing unreviewed remote scripts from workflows.
- Keep downloaded tools checksum-verified when they affect compatibility testing or releases.
- Limit workflow permissions and secrets to the smallest scope required by each job.
- Review changes to workflow dependencies with the same care as application dependencies.

## Version source of truth

Repository versioning must have one predictable source of truth:

- Workspace package versions and release tags must remain synchronized through the release workflow.
- Release automation calculates the next version from repository state rather than accepting arbitrary user-provided tags.
- Manual workflow inputs select the release increment or goal, not the final published version string.
- Development changes must not create stable release tags outside the documented release process.
