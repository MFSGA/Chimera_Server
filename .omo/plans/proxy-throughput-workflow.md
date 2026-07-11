# Proxy Throughput CI Workflow

## TL;DR

> **Quick Summary**: Design and implement a GitHub Actions workflow + Python benchmark harness that measures Chimera_Server's proxy throughput (SOCKS and VLESS inbound → freedom outbound → echo server), producing per-protocol Markdown tables on PR comments with baseline regression comparison.
>
> **Deliverables**:
> - `bench/echo_server.py` — Independent TCP echo server with sync byte protocol for accurate timing
> - `bench/throughput.py` — Main test orchestrator (stdlib-only Python, no pip deps)
> - `bench/format_throughput.py` — JSON-lines → Markdown formatter (adapted from ref/clash-rs)
> - `bench/configs/socks-direct.json5` — Chimera config: SOCKS inbound + freedom outbound
> - `bench/configs/vless-direct.json5` — Chimera config: VLESS inbound + freedom outbound
> - `bench/.xray-version` — Pinned xray-core version for reproducible CI
> - `bench/baseline-throughput.json` — Committed baseline for regression detection
> - `.github/workflows/proxy-throughput.yml` — CI workflow definition
>
> **Estimated Effort**: Medium (~80-120 tasks across 4 waves)
> **Parallel Execution**: YES — 4 waves with up to 3 parallel tasks
> **Critical Path**: echo_server.py → throughput.py → format_throughput.py → workflow.yml → baseline commit

---

## Context

### Original Request
Design a targeted GitHub Actions workflow that can test the proxy throughput/performance of Chimera_Server, following the structural pattern of clash-rs's `proxy-throughput.yml` but adapted for Chimera's current architecture (inbound-first, SOCKS working, VMess `todo!()`, VLESS/Trojan implemented).

### Interview Summary
**Key Discussions**:
- **Test scope**: Tier 1 (SOCKS → freedom → echo) + Tier 2 (VLESS → freedom → echo). VMess excluded (todo!()).
- **Test toolchain**: Python stdlib-only scripts. No pip/requirements.txt.
- **CI xray source**: Precompiled binary downloaded from GitHub releases, version pinned in `bench/.xray-version`.
- **Test parameters**: 32MB payload × 3 runs per scenario, median ± stdev.
- **Baseline**: Committed `bench/baseline-throughput.json`, compared on each run. Regression >10% warns.
- **Echo server**: Independent `bench/echo_server.py` with sync byte protocol for accurate upload timing.
- **No Docker**: Zero Docker dependency (unlike clash-rs reference).
- **No netem/iperf3**: Excluded from v1, documented as future enhancement.
- **runs-on**: `ubuntu-latest` only. No Windows/macOS.

### Research Findings
- **VMess is todo!()** at `chimera_server_lib/src/config/server_config/builder/mod.rs:311`. Cannot test Tier 2 VMess.
- **VLESS implemented**: `handler/vless_handler/` with Vision variant, feature-gated (`vless`).
- **Trojan implemented**: `handler/trojan.rs`, feature-gated (`trojan`). Excluded per user's "VLESS only (最简)" decision.
- **SOCKS inbound**: Fully verified via `socks_external_integration.rs` e2e tests.
- **Release profile**: `opt-level = "s"` (size-optimized), not speed-optimized. This is the production profile users will run.
- **Existing CI build time**: ~15-30 min with `cross` on ubuntu-latest.
- **Python 3**: Pre-installed on ubuntu-latest GitHub runners. No additional setup needed.
- **gRPC compat tests**: Already produce `target/grpc-xray-compat/report.{json,md}` — pattern to follow for throughput artifacts.

### Metis Review
**Identified Gaps** (addressed):
- **Critical**: VMess `todo!()` — Scope reduced to VLESS-only for Tier 2.
- **Missing**: Echo server not in initial deliverable list — Added as `bench/echo_server.py`.
- **Missing**: xray version management — Added as `bench/.xray-version`.
- **Scope creep**: Trojan, netem, iperf3, flamegraphs, historical trends — All explicitly excluded from v1.
- **First-run baseline**: Script handles missing baseline gracefully (skip comparison, generate).
- **Port conflicts**: Random port allocation via `TcpListener::bind(0)` equivalent in Python.

---

## Work Objectives

### Core Objective
Build an automated CI pipeline (test harness + GitHub Actions workflow) that measures Chimera_Server's proxy throughput for SOCKS and VLESS inbounds, reports results as Markdown tables on PRs, and flags regressions against a committed baseline.

### Concrete Deliverables
1. `bench/echo_server.py` — TCP echo server with sync byte protocol
2. `bench/throughput.py` — Multi-scenario throughput orchestrator (SOCKS + VLESS)
3. `bench/format_throughput.py` — JSON-lines → grouped Markdown tables
4. `bench/configs/socks-direct.json5` — Chimera config: SOCKS inbound
5. `bench/configs/vless-direct.json5` — Chimera config: VLESS inbound
6. `bench/.xray-version` — Pinned xray-core version (e.g., `v25.1.1`)
7. `bench/baseline-throughput.json` — Initial committed baseline
8. `.github/workflows/proxy-throughput.yml` — CI workflow definition

### Definition of Done
- [x] All 8 deliverables exist in the repo with correct content
- [x] `python3 bench/echo_server.py --port 20000` starts a server; `echo "hello" | nc -q1 127.0.0.1 20000` returns `hello`
- [x] `python3 bench/throughput.py --only socks` runs SOCKS throughput test and exits 0
- [ ] `python3 bench/throughput.py --only vless` runs VLESS throughput test and exits 0 (requires xray binary)
- [x] `python3 bench/throughput.py --output /tmp/results.jsonl` produces valid JSON-lines
- [x] `python3 bench/format_throughput.py /tmp/results.jsonl` produces Markdown with expected table headers
- [x] `cargo build --release --package chimera_server_app --all-features` succeeds
- [x] Git tag `proxy-throughput-initial-baseline` exists for first baseline commit
- [ ] Workflow appears in GitHub Actions and can be triggered via `workflow_dispatch`
- [ ] Workflow run produces artifact with throughput results and posts PR comment

### Must Have
- [x] Python stdlib-only — no `pip install`, no `requirements.txt`
- [x] Release build of chimera_server_app for meaningful throughput
- [x] Sync byte protocol (`0xAC`) in echo server for accurate upload timing
- [x] 3 runs per scenario, reporting median ± stdev
- [x] 32MB (33,554,432 bytes) payload per test
- [x] SOCKS Tier 1 works without any external dependency (no xray needed)
- [x] VLESS Tier 2 auto-skips if xray binary not found (graceful degradation)
- [x] Baseline comparison: if `bench/baseline-throughput.json` exists → compare; if missing → skip comparison, generate
- [x] Regression warning (>10% drop) printed to step summary and PR comment
- [x] PR comment lifecycle: update existing comment if found, otherwise create new
- [x] PR comment includes link to workflow run artifacts
- [x] Artifacts uploaded: `throughput-results.jsonl`, `throughput-report.md`
- [x] Concurrency group with cancel-in-progress on new pushes

### Must NOT Have (Guardrails)
- [x] NO Docker containers in the test pipeline
- [x] NO netem / iperf3 tests (v1 only)
- [x] NO pip dependencies or requirements.txt
- [x] NO Windows/macOS runners (ubuntu-latest only)
- [x] NO auto-update of committed baseline (requires separate PR)
- [x] NO flamegraph generation or profiling
- [x] NO historical trend tracking beyond single-run comparison
- [x] NO VMess tests (todo!() — blocked until separate implementation)
- [x] NO Trojan tests (not in scope for v1 — "VLESS only" decision)
- [x] NO Hysteria2, TUIC, WireGuard, or other protocol tests
- [x] NO modification of Chimera's release profile (`opt-level = "s"`)
- [x] NO UDP testing (TCP-only for v1)

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: YES (Python 3 on ubuntu-latest)
- **Automated tests**: N/A (benchmark/performance CI, not unit testing)
- **Agent-Executed QA**: MANDATORY — each task includes exact commands, assertions, and evidence paths

### QA Policy
Every task MUST include agent-executed QA scenarios. Evidence saved to `.omo/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Python scripts**: Run with known inputs, verify stdout/stderr and exit code
- **Chimera config**: Start Chimera, connect via curl/nc, verify data round-trips
- **GitHub workflow**: Dry-run validation via `act` or manual trigger on test branch
- **Baseline**: Compare script output against known values, check regression detection

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Foundation — all independent):
├── Task 1: bench/echo_server.py — Sync-byte TCP echo server
├── Task 2: bench/.xray-version — Pinned xray-core version file
├── Task 3: bench/format_throughput.py — JSON-lines → Markdown formatter
├── Task 4: bench/configs/socks-direct.json5 — SOCKS Chimera config
└── Task 5: bench/configs/vless-direct.json5 — VLESS Chimera config

Wave 2 (Core tools — depends on Wave 1):
├── Task 6: bench/throughput.py — Main orchestrator (depends: 1, 2, 4, 5)
└── Task 7: bench/baseline-throughput.json — Initial baseline (depends: 6)

Wave 3 (CI workflow — depends on Wave 2):
└── Task 8: .github/workflows/proxy-throughput.yml — CI workflow (depends: 3, 6, 7)

Wave 4 (End-to-end validation):
├── Task 9: Manual `workflow_dispatch` trigger on test branch — verify full pipeline
└── Task 10: Final regression check — commit baseline, verify comparison

Wave FINAL (4 parallel reviews):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay

Critical Path: Task 1 → Task 6 → Task 7 → Task 8 → Task 9 → F1-F4 → user okay
Parallel Speedup: ~40% faster than sequential
Max Concurrent: 5 (Wave 1)
```

### Dependency Matrix
- **1-5**: None — can start immediately
- **6**: 1, 2, 4, 5 — orchestrator needs echo server, xray version, config templates
- **7**: 6 — baseline needs throughput.py to work first
- **8**: 3, 6, 7 — workflow needs format script, orchestrator, baseline
- **9**: 8 — manual trigger on test branch
- **10**: 9 — final check after workflow verified
- **F1-F4**: All tasks complete

---

## TODOs

- [x] 1. Create `bench/echo_server.py` — Sync-byte TCP echo server

  **What to do**:
  - Create `bench/echo_server.py` as a standalone Python script (stdlib only: `socket`, `argparse`, `threading`, `sys`, `os`, `json`, `time`)
  - Implement a TCP echo server that:
    - Binds to `127.0.0.1:<port>` (configurable via `--port`, default 20000)
    - Accepts one connection at a time (sequential, for accurate measurement)
    - Reads incoming bytes until the client closes the write side or sends a special "end-of-upload" marker
    - After receiving all upload bytes, sends a single sync byte `0xAC` back to signal upload completion
    - Then echoes back all received bytes as the download phase
    - Logs connection stats: bytes received, bytes sent, connection duration
    - Handles `SIGTERM` gracefully (clean shutdown)
  - Supported CLI arguments:
    - `--port PORT` — Listen port (default: 20000)
    - `--bind ADDR` — Bind address (default: 127.0.0.1)
    - `--sync-byte HEX` — Sync byte value (default: `AC`)
    - `--log-json` — Output connection logs as JSON-lines to stdout
    - `--timeout SEC` — Connection idle timeout (default: 30)
  - Server lifecycle: prints `LISTENING on <addr>:<port>` to stderr when ready (parsed by orchestrator)
  - Must handle: partial reads, connection resets, timeout, `SIGTERM`

  **Must NOT do**:
  - Do NOT use `asyncio` — use `socket` + `threading` for simplicity
  - Do NOT add any pip dependencies
  - Do NOT implement HTTP protocol — raw TCP only
  - Do NOT handle UDP (TCP only)

  **Recommended Agent Profile**:
  - **Category**: `writing` — focused Python script, straightforward logic
  - **Skills**: None needed (stdlib-only Python)

  **Parallelization**:
  - **Wave**: 1

  **Acceptance Criteria**:
  - [ ] `python3 bench/echo_server.py --port 20001 &` starts and prints `LISTENING on 127.0.0.1:20001`
  - [ ] `echo -n "hello" | nc -q1 127.0.0.1 20001` returns `hello`
  - [ ] Larger payload: `python3 -c "import sys; sys.stdout.buffer.write(b'x'*100000)" | nc -q1 127.0.0.1 20001` returns 100000 bytes
  - [ ] Sync byte: send 10 bytes, receive `0xAC` before echo starts (verify with hexdump)

  **Evidence**:
  - [ ] `python3 bench/echo_server.py --help` exits 0 and shows all arguments
  - [ ] Start server + send payload + verify response shown via `nc`

- [x] 2. Create `bench/.xray-version` — Pinned xray-core version file

  **What to do**:
  - Create `bench/.xray-version` containing a single line: the xray-core release tag (e.g., `v25.1.1`)
  - This is the version downloaded by the CI workflow and used by throughput.py
  - Choose the latest stable xray-core release as of May 2026

  **Must NOT do**:
  - Do NOT include a trailing newline (optional, but be consistent)
  - Do NOT add version range or semver constraints — exact pin only

  **Parallelization**:
  - **Wave**: 1

  **Acceptance Criteria**:
  - [ ] `cat bench/.xray-version` outputs a version string like `v25.1.1`
  - [ ] `curl -L "https://github.com/XTLS/Xray-core/releases/download/$(cat bench/.xray-version)/Xray-linux-64.zip" -o /tmp/xray-test.zip` exits 0 and downloads a valid zip

  **Evidence**:
  - [ ] File exists with valid content

- [x] 3. Create `bench/format_throughput.py` — JSON-lines → Markdown formatter

  **What to do**:
  - Create `bench/format_throughput.py` (stdlib only: `json`, `argparse`, `sys`, `os`)
  - Adapt the structure from `ref/clash-rs/bench/format_throughput.py` for Chimera's protocol set
  - Reads a JSON-lines file where each line has:
    ```json
    {
      "label": "socks-direct",
      "scenario": "tier1_socks_direct",
      "upload_mbps": 1234.5,
      "download_mbps": 1100.2,
      "upload_stdev_mbps": 12.3,
      "download_stdev_mbps": 15.7,
      "runs": 3,
      "total_bytes": 33554432,
      "engine": "chimera"
    }
    ```
  - Groups results by scenario, outputs Markdown tables
  - Supported CLI:
    - `bench/format_throughput.py <results.jsonl>` — prints Markdown to stdout
    - `--output FILE` — Write to file
    - `--run-url URL` — Append workflow run link
    - `--env-json JSON` — Append environment info table
  - Protocol metadata for Chimera:
    - `socks` → "SOCKS"
    - `vless` → "VLESS"
  - Sort order: SOCKS first, then VLESS
  - Output format (per scenario group):
    ```markdown
    ### SOCKS (Tier 1 — direct)
    | Transport | Payload | Runs | Upload Mbps (±σ) | Download Mbps (±σ) |
    |-----------|---------|:----:|:----------------:|:------------------:|
    | `direct` | 32 MB | 3 | 1234.5 ±12.3 | 1100.2 ±15.7 |
    ```
  - If netem section exists in data (future use), show in separate "Netem Tests" section
  - Append environment info if `--env-json` provided
  - Append `[View workflow run and artifacts](URL)` if `--run-url` provided

  **Must NOT do**:
  - Do NOT import pandas, numpy, or any non-stdlib module
  - Do NOT add emoji unless user explicitly requests

  **Parallelization**:
  - **Wave**: 1

  **Acceptance Criteria**:
  - [ ] `python3 bench/format_throughput.py` with a valid JSON-lines file produces Markdown with correct table headers
  - [ ] Output contains rows for each scenario
  - [ ] `--output /tmp/test.md` writes to file
  - [ ] `--env-json '{"os":{"system":"Linux"},"cpu":"Test CPU","memory_gb":8}'` includes environment table in output

  **Evidence**:
  - [ ] Run with sample data, verify output format

- [x] 4. **Create bench/configs/socks-direct.json5 — SOCKS Chimera config template**

  **What to do**:
  - Create Chimera config template: SOCKS inbound → freedom outbound
  - JSON5 format, port as `0` placeholder (dynamically replaced)
  - Structure: `{ inbounds: [{ listen:"127.0.0.1", port:0, protocol:"socks", settings:{auth:"noauth"}, tag:"socks-throughput" }], outbounds: [{ protocol:"freedom", tag:"direct" }] }`
  - Follow patterns from `socks_external_integration.rs`

  **Must NOT do**: No API, MCP, routing, TLS/WS

  **Parallelization**: Wave 1

  **Acceptance Criteria**:
  - [ ] Contains `socks`, `freedom`, port placeholder

- [x] 5. **Create bench/configs/vless-direct.json5 — VLESS Chimera config template**

  **What to do**:
  - Create Chimera config template: VLESS inbound → freedom outbound
  - Port as `0`, UUID as `"PLACEHOLDER_UUID"` (both dynamically replaced)
  - Structure: `{ inbounds: [{ listen:"127.0.0.1", port:0, protocol:"vless", settings:{ clients:[{ id:"PLACEHOLDER_UUID", email:"test@local" }], decryption:"none" }, tag:"vless-throughput" }], outbounds: [{ protocol:"freedom", tag:"direct" }] }`

  **Must NOT do**: No stream settings, no routing

  **Parallelization**: Wave 1

  **Acceptance Criteria**:
  - [ ] Contains `vless`, `freedom`, `decryption`, port placeholder

- [x] 6. **Create bench/throughput.py — Main test orchestrator**

  **What to do**:
  - Most critical deliverable. Python stdlib-only orchestrator.
  - Tests two scenarios:
    1. **SOCKS** (Tier 1): echo server + Chimera SOCKS → SOCKS5 connect → measure throughput
    2. **VLESS** (Tier 2): echo server + Chimera VLESS + xray client → SOCKS5 to xray → xray tunnels VLESS to Chimera → measure throughput
  - **SOCKS5 handshake**: Implement raw protocol via `socket`:
    - `sock.sendall(b"\\x05\\x01\\x00")` negotiate no-auth
    - `sock.sendall(b"\\x05\\x01\\x00\\x01" + ip4 + port_bytes)` connect
    - Parse 10-byte response
  - **Throughput measurement**:
    - Send N bytes (--payload-size), shutdown write side
    - Read until sync byte `0xAC`
    - Record upload time
    - Read remaining echo data
    - Record download time
    - Calculate Mbps: `bytes * 8 / time_sec / 1_000_000`
  - Run N iterations (--runs), compute median + stdev via `statistics.median()`, `statistics.stdev()`
  - CLI: `--only {socks,vless,all}`, `--payload-size`, `--runs`, `--output`, `--chimera-bin`, `--xray-bin`, `--verbose`
  - Subprocess management: `subprocess.Popen`, track PIDs, `atexit` cleanup
  - Port allocation: random port in [30000-40000], verify free via `socket.bind()`
  - Output to JSON-lines: `{"label":"socks-direct","scenario":"tier1_socks_direct","upload_mbps":1234.5,"download_mbps":1100.2,"upload_stdev_mbps":12.3,"download_stdev_mbps":15.7,"runs":3,"total_bytes":33554432,"engine":"chimera"}`
  - VLESS skipped if xray not found (graceful, exit 0)
  - xray config generated on-the-fly in temp directory

  **Must NOT do**: No pip, no asyncio, no sudo, no Docker

  **Parallelization**: Wave 2 (depends on Tasks 1-5)

  **Pattern Ref**: `socks_external_integration.rs` for SOCKS handshake, `ref/clash-rs/bench/README.md` for sync byte protocol

  **Acceptance Criteria**:
  - [ ] `--help` exits 0
  - [ ] Quick SOCKS test: `--only socks --payload-size 1048576 --runs 1` exits 0, produces JSON-lines
  - [ ] VLESS skipped gracefully when xray not found
  - [ ] JSON-lines output has all required fields

- [x] 7. **Create bench/baseline-throughput.json — Initial baseline (after test run)**

  **What to do**:
  - After throughput.py works, run against master branch to generate initial baseline
  - Run: `python3 bench/throughput.py --all --payload-size 33554432 --runs 3 --output target/throughput-results.jsonl`
  - Convert to baseline format: JSON object with `created_at`, `results` array
  - Commit to repo as starting point for regression detection

  **Must NOT do**: Do NOT fake numbers — must be from real test run

  **Parallelization**: Wave 3 (depends on Task 6)

  **Acceptance Criteria**:
  - [ ] Valid JSON, contains `results` array
  - [ ] Each result has `upload_mbps` > 0

- [x] 8. **Create .github/workflows/proxy-throughput.yml — GitHub Actions workflow**

  **What to do**:
  - Create the CI workflow file. Structure follows user's reference:
  ```yaml
  name: Proxy Throughput

  on:
    pull_request:
      branches: ["master"]
      paths:
        - "chimera_server_app/**"
        - "chimera_server_lib/src/**"
        - "Cargo.toml"
        - "Cargo.lock"
        - "bench/**"
        - ".github/workflows/proxy-throughput.yml"
    workflow_dispatch:

  permissions:
    contents: read
    pull-requests: write

  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
    cancel-in-progress: true

  env:
    RUST_TOOLCHAIN: stable
    RUST_LOG: chimera_server_lib=info
    XRAY_BIN: ${{ github.workspace }}/xray/xray

  jobs:
    throughput:
      name: Proxy throughput benchmark
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v6
        - uses: dtolnay/rust-toolchain@stable
        - uses: Swatinem/rust-cache@v2
        - run: sudo apt-get update && sudo apt-get install -y protobuf-compiler iperf3
        - name: Download xray-core
          run: |
            VERSION=$(cat bench/.xray-version)
            mkdir -p xray
            curl -L "https://github.com/XTLS/Xray-core/releases/download/$VERSION/Xray-linux-64.zip" -o /tmp/xray.zip
            unzip -o /tmp/xray.zip -d xray/
            chmod +x xray/xray
            xray/xray version
        - name: Build Chimera release
          run: cargo build --release --package chimera_server_app --all-features
        - name: Print environment
          run: |
            echo "OS: $(uname -a)"; echo "CPUs: $(nproc)"
            echo "Memory: $(free -h | awk '/^Mem/{print $2}')"
            rustc --version; cargo --version; ./target/release/chimera_server_app --version || true; xray/xray version
        - name: Run throughput tests
          run: |
            python3 bench/throughput.py --all --payload-size 33554432 --runs 3 \
              --chimera-bin ./target/release/chimera_server_app \
              --xray-bin ./xray/xray \
              --output target/throughput-results.jsonl --verbose \
              2>&1 | tee target/throughput-run.log
        - name: Generate report
          if: always()
          run: |
            ENV_JSON=$(python3 -c "import json,platform,os; print(json.dumps({'os':{'system':platform.system()},'cpu_cores':os.cpu_count()}))")
            python3 bench/format_throughput.py target/throughput-results.jsonl \
              --output target/throughput-report.md \
              --env-json "$ENV_JSON" \
              --run-url "https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}"
            cat target/throughput-report.md >> $GITHUB_STEP_SUMMARY
        - uses: actions/upload-artifact@v7
          if: always()
          with:
            name: proxy-throughput
            path: |
              target/throughput-results.jsonl
              target/throughput-report.md
              target/throughput-run.log
            retention-days: 90
        - name: Post PR comment
          if: always() && github.event_name == 'pull_request'
          uses: actions/github-script@v9
          with:
            github-token: ${{ secrets.GITHUB_TOKEN }}
            script: |
              const fs = require('fs');
              const report = 'target/throughput-report.md';
              let body = fs.existsSync(report) ? fs.readFileSync(report, 'utf8') : '## Proxy Throughput Report\\n\\nNo report produced.';
              body += '\\n\\n[View workflow run and artifacts](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})';
              const { data: comments } = await github.rest.issues.listComments({ owner: context.repo.owner, repo: context.repo.repo, issue_number: context.issue.number });
              const existing = comments.find(c => c.user.type === 'Bot' && c.body.includes('Proxy Throughput Report'));
              if (existing) {
                await github.rest.issues.updateComment({ owner: context.repo.owner, repo: context.repo.repo, comment_id: existing.id, body });
              } else {
                await github.rest.issues.createComment({ owner: context.repo.owner, repo: context.repo.repo, issue_number: context.issue.number, body });
              }
  ```

  **Must NOT do**: No Docker, no Windows/macOS, no auto-update baseline

  **Parallelization**: Wave 3 (depends on Tasks 3, 6, 7)

  **Acceptance Criteria**:
  - [ ] Valid YAML syntax
  - [ ] All required steps present: checkout, rust, deps, xray, build, env, test, format, upload, comment
  - [ ] Concurrency group + cancel-in-progress
  - [ ] PR comment: find existing → update, else create

---

## Final Verification Wave

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read plan end-to-end. Verify: each deliverable file exists and matches spec. Check Must Have / Must NOT Have compliance.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT`

- [x] F2. **Code Quality Review** — `unspecified-high`
  Review all Python scripts for: stdlib-only, no credentials, proper subprocess handling, error handling, cleanup.
  Output: `Issues [N] | VERDICT`

- [x] F3. **Real Manual QA** — `unspecified-high`
  From clean checkout: execute EVERY QA scenario from every task. Capture evidence.
  Output: `Scenarios [N/N pass] | VERDICT`

- [x] F4. **Scope Fidelity Check** — `deep`
  Verify 1:1 — everything specified was built, nothing beyond was built. Check Must NOT Have compliance.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | VERDICT`

---

## Commit Strategy

- **Commit A** (Tasks 1-5): `feat(bench): add throughput test infrastructure (echo server, configs, formatter, xray pin)`
  Files: `bench/echo_server.py`, `bench/.xray-version`, `bench/format_throughput.py`, `bench/configs/socks-direct.json5`, `bench/configs/vless-direct.json5`

- **Commit B** (Task 6): `feat(bench): add throughput test orchestrator`
  Files: `bench/throughput.py`

- **Commit C** (Task 7): `chore(bench): add initial throughput baseline`
  Files: `bench/baseline-throughput.json`

- **Commit D** (Task 8): `ci: add proxy throughput workflow`
  Files: `.github/workflows/proxy-throughput.yml`

---

## Success Criteria

### Verification Commands
```bash
# Echo server
python3 bench/echo_server.py --port 20000 &
echo -n "hello" | nc -q1 127.0.0.1 20000  # Expected: hello
kill %1

# Throughput quick test
python3 bench/throughput.py --only socks --payload-size 65536 --runs 1
# Expected: target/throughput-results.jsonl produced

# Format test
python3 bench/format_throughput.py target/throughput-results.jsonl
# Expected: Markdown table
```

### Final Checklist
- [x] All 8 deliverables created and verified
- [x] Echo server: TCP echo + sync byte working
- [x] Throughput.py: SOCKS test produces valid JSON-lines
- [x] Format.py: produces correct Markdown tables
- [x] Workflow YAML: structurally valid
- [ ] PR comment: created/updated on workflow run (requires GitHub Actions trigger)


