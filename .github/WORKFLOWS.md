# GitHub Actions layout

The repository uses five entry-point workflows and two shared local actions. Keep each workflow focused on one responsibility instead of copying setup and release logic between files.

## Workflows

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `ci.yml` | `master` push, pull request, manual | Fast correctness gate: format, clippy, cross-platform tests, release-target builds |
| `auto-merge.yml` | Successful `CI` completion, PR authorization changes, and review updates | Revalidates low-risk PRs, cancels stale Auto-merge requests, and queues or completes the merge only after every gate passes |
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
- Low-risk L0/L1 auto-merge requires protected branch rules, independent checks
  and constrained tokens; L2/L3 remain human-merged. AI-generated PR labels or
  checkboxes alone cannot grant merge authorization.
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

`auto-merge.yml` runs after the trusted `CI` workflow completes, when a PR is synchronized, edited, labeled, or unlabeled, and when its review is submitted, edited, or dismissed. Events are serialized per PR. It checks every expected CI job on the matching head SHA and never checks out pull-request code or consumes its artifacts. For a PR with current or historical auto-merge risk labeling, a head or label change first cancels any queued native Auto-merge request; each relevant PR or review event then revalidates the live PR state. It re-reads head, labels, and changed files immediately before requesting or completing the merge, and only proceeds when all of the following hold:

- The PR comes from this repository, targets `master`, is open, and its head has not changed since the successful CI run.
- A username listed in `CHIMERA_AUTOMERGE_MAINTAINERS`, other than the PR author, applied exactly one of `automerge:l0` or `automerge:l1`; the label is a risk classification, not a review substitute.
- Every changed file is one of the root README files (`README.md`, `README.en.md`, `README.fa.md`, `README.ru.md`). Code, workflow, configuration, reference, vendor, and other documentation changes remain manual-merge only.
- Repository Auto-merge is enabled, and the repository variables `CHIMERA_AUTOMERGE_MAINTAINERS` and `CHIMERA_AUTOMERGE_PROTECTION_CONFIRMED=true` are configured. The maintainer variable is a comma-separated list of GitHub usernames permitted to apply the risk labels. The confirmation variable is an administrator's assertion that classic `master` branch protection enforces strict/up-to-date `CI / Required checks`, at least one approval, stale-approval dismissal, and admin enforcement; no active ruleset, merge queue, or bypass actor can skip those gates.
- If GitHub reports that the PR is already clean and mergeable, the workflow completes it through the pull-request merge API pinned to the verified head SHA. Otherwise it requests native GitHub Auto-merge, which waits for remaining required reviews/checks. The job needs `contents: write` for the ready-to-merge API call and executes only this trusted script from the default branch.

The workflow skips when a prerequisite is absent. GitHub Actions `GITHUB_TOKEN` cannot read repository administration settings, so the workflow does not inspect branch protection or rulesets itself; setting the confirmation variable without those protections would allow an unsafe immediate merge. An administrator must verify the protections, enable GitHub Auto-merge, set both variables, and create the two labels before this automation can activate. The current repository settings do not meet those prerequisites.

Label revocation is best-effort: GitHub does not provide an atomic operation that combines the final label check with enabling native Auto-merge. If all merge gates become satisfied in the small interval before the cancellation event is handled, GitHub may merge first. Required CI, up-to-date branch and review protections remain enforced by GitHub.

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
