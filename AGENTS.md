# AGENTS

These instructions apply to contributions in Chimera_Server. Read them before changing code,
then inspect the affected modules and any more specific `AGENTS.md` files. Follow the user's
current task instructions when they conflict with this document. Keep changes focused and
report any necessary deviation from the project conventions.

## Required Architecture Reference

- Read [ARCHITECTURE.md](ARCHITECTURE.md) at the start of each new task, before planning or
  editing code; then inspect the relevant implementation and more specific instructions.
  It records the user's intended server architecture and is the primary internal design reference.
- Follow its boundaries for configuration compilation, inbound lifecycle, transport/protocol
  separation, connection/session ownership, and control/data-plane capabilities.
- The document describes a target architecture, not completed implementation. Check its migration
  status and actual code; do not assume proposed types or modules already exist.
- Current user instructions take precedence. AGENTS governs workflow, ARCHITECTURE governs internal
  design, and the recorded Xray baseline governs external compatibility. Do not copy another
  project's behavior where it conflicts with Xray; document justified design deviations.
- Exercise independent architectural judgment. Reference projects provide evidence and alternatives,
  not mandatory internal templates. Prefer designs justified by Chimera's server compatibility,
  ownership, maintenance and operational needs, even when no reference uses the same structure.
  Evaluate the current design, a reference-derived option and a simpler local option when useful;
  explain tradeoffs and validation. Neither resemblance to upstream nor novelty proves quality.
- For architecture work, identify the affected boundary and ownership, choose one reviewable
  migration slice, and state the compatibility checks. The roadmap does not authorize an entire
  rewrite or unrelated feature work. Routine fixes need only the relevant portions of the design.
- When a major design decision changes or a migration stage is completed, update ARCHITECTURE.md
  with the rationale, implementation status and verification evidence so later agents inherit
  the decision. Keep support claims synchronized with the compatibility matrix.

## Project Goal, Scope and References

- The ultimate goal is full xray-core compatibility **as a server**, with inbound compatibility
  as the current primary objective. Existing Xray-compatible clients should connect without
  client changes, and supported Xray server configurations should retain equivalent behavior.
- Inbound scope includes protocols, transports, TLS/REALITY, authentication, fallback, listeners,
  socket options, sniffing, user policy, and the management/statistics APIs needed to operate
  those inbounds. Track platform-specific behavior explicitly.
- Defer broad outbound protocol and routing feature expansion until the inbound objective is
  complete, unless the user changes priorities. Preserve existing outbound behavior. Implement
  the destination connection, DNS resolution, TCP/UDP forwarding, timeout and routing/policy
  integration necessary to validate an inbound end to end; those dependencies remain in scope.
- Use `ref/xray-core/` as the canonical reference for server configuration **and observable
  protocol/runtime behavior**, including defaults, validation and failure handling.
  Use `ref/shoes/` as an implementation aid and `ref/clash-rs/` for architectural layering.
  When shoes differs from Xray, follow Xray for the compatibility contract and document the choice.
- Record the actual Xray reference commit/tag and client binary version for compatibility work.
  Prefer checked-out sources over assumptions about upstream. Do not call a local snapshot
  "latest" without verification, and do not silently change the baseline during a task.
- Improve internal safety, lifecycle management, resource use and maintainability while retaining
  external compatibility. Establish a concrete failure or measured cost before calling an Xray
  design deficient; a Rust rewrite alone does not demonstrate an improvement.
- Keep the data flow explicit: configuration → validated runtime state → listener/transport
  → protocol handler → outbound session. Control-plane services must stay decoupled from forwarding.
- Preserve Chimera naming and existing extensions, but do not let Chimera-only features displace
  the inbound compatibility goal. Do not modify `ref/` unless reference updates are in scope.

## Compatibility Contract and Evidence

- Compatibility covers configuration acceptance/defaults, wire behavior, authentication and
  replay handling, fallback selection, TCP/UDP semantics, timeouts, EOF/half-close, user policy,
  dynamic management and statistics where applicable. Successful parsing or a single successful
  handshake does not establish full compatibility.
- Implement options through every applicable layer: literal config → validation/defaults →
  `ServerConfig` or owning runtime state → behavior → focused tests and configuration docs.
  Route file configuration and management API input through shared validation/building logic
  where practical; equivalent inputs must not acquire different defaults through separate paths.
- Never silently accept a recognized, behavior-changing option as a no-op and count it as
  supported. Until implemented, provide an explicit unsupported-field error or a clearly
  documented compatibility diagnostic. Security-critical unsupported behavior must fail closed.
- Match Xray's treatment of omitted, explicit, unknown and server-inapplicable fields deliberately.
  Do not apply blanket unknown-field rejection without checking its compatibility impact.
  Any intentional stricter behavior must be documented as a deviation, not full parity.
- Maintain the inbound support matrix in `examples/xray-compatible/README.md` and adjacent
  configuration docs. Distinguish missing, parse/build only, runtime implemented, and verified
  interoperability, with partial support and limitations stated explicitly. Verify code and tests
  before reusing a documentation claim; keep changing gap inventories out of this instruction file.
- Define coverage by protocol × transport × security × TCP/UDP, plus relevant user, policy,
  fallback and platform variants. Enumerate supported combinations rather than implying that
  separate support for two features proves their combination works.
- For an affected compatibility claim, run a real versioned Xray-compatible client against Chimera
  and, where behavior is ambiguous, run the same case against the reference Xray server.
  Cover valid traffic and relevant invalid authentication, replay, malformed/truncated frames,
  cancellation and connection teardown. Use deterministic local fixtures when possible.
- Record exact test commands, versions, outcomes and prerequisites. Ignored tests do not run under
  ordinary `cargo test`; execute the relevant ones explicitly before declaring interoperability
  verified. If prerequisites are unavailable, report the unverified scope instead of claiming parity.
- Full compatibility claims require a defined baseline and coverage matrix with no unresolved gaps
  in the claimed scope. Do not invent a compatibility percentage from code size or protocol counts.

## Improvement Priorities and Design Guardrails

- Prioritize evidenced credential exposure, silent configuration misbehavior, protocol correctness
  and lifecycle/resource failures before adding breadth or optimizing throughput.
- Complete one bounded inbound behavior at a time. Prefer closing gaps in deployed protocol and
  transport combinations, then extend coverage toward the full server contract. A broad request
  to improve the project is not a reason to mix unrelated protocol goals in one change.
- Never log full configurations, authentication payloads, passwords, private keys or tokens.
  Keep diagnostics useful through safe fields such as inbound tag, protocol and config field path;
  parsing errors must not echo the original secret-bearing configuration.
- Give listeners, connections and background tasks explicit owners and shutdown behavior.
  Account for startup rollback, stop-accepting, draining, cancellation and bounded cleanup;
  dropping a task handle is not task cancellation. Test these paths when changing lifecycle code.
- Bound handshake concurrency, buffering, queues and session state where appropriate. Preserve
  backpressure and isolate control-plane work from forwarding. Introduce limits with documented
  defaults and overload behavior, and check that legitimate reference-client traffic still works.
- Keep wire-level compatibility separate from internal implementation choices. Do not reproduce
  an unsafe implementation detail merely because the reference uses it; document any externally
  visible security hardening, especially if it changes probe/fallback or error behavior.
- Justify performance changes using comparable workloads and equivalent security/transport
  semantics. Record client/server versions, hardware, network conditions and measurement method;
  evaluate CPU, memory, latency, throughput and loss recovery as relevant. Performance gains do
  not excuse broken authentication, fallback, accounting or shutdown behavior.
- Keep improvements incremental and reviewable; use concrete regression tests or measurements
  to justify architectural changes rather than undertaking an unbounded rewrite.

## Code Map

Paths below are relative to the repository root.

| Path | Responsibility |
| --- | --- |
| `chimera_server_app/src/main.rs` | Main CLI, config source selection, validation and startup |
| `chimera_server_lib/src/lib.rs` | Library entry points, runtime preparation and server lifecycle |
| `chimera_server_lib/src/config_loader.rs` | Local and external configuration loading |
| `chimera_server_lib/src/config/def.rs` | Literal configuration structures |
| `chimera_server_lib/src/config/server_config/` | Server configuration types and builders |
| `chimera_server_lib/src/config/rule/` | Routing configuration |
| `chimera_server_lib/src/beginning/` | Listeners and transport entry points |
| `chimera_server_lib/src/handler/` | Protocol and transport handler layers |
| `chimera_server_lib/src/outbound.rs` | Outbound connection behavior |
| `chimera_server_lib/src/runtime.rs` | Shared runtime state and management |
| `chimera_server_lib/src/routing_*.rs` | Routing state, observation, process lookup and webhooks |
| `chimera_server_lib/src/traffic.rs`, `traffic_impl.rs` | Traffic interface and implementation (both under `src/`) |
| `chimera_server_lib/src/grpc/`, `chimera_server_lib/src/mcp.rs` | Control-plane APIs and streams |
| `chimera_server_lib/src/reality/` | REALITY handshake and cryptographic helpers |
| `chimera_server_lib/proto/`, `chimera_server_lib/build.rs` | Protobuf sources and binding generation |
| `chimera_cli/` | CLI utilities |
| `chimera_tcp_reality_server/` | Dedicated TCP REALITY server crate |
| `chimera_server_lib/tests/`, `chimera_server_app/tests/` | Integration tests |
| `chimera_server_lib/src/config/README.md`, `examples/xray-compatible/` | Configuration documentation and examples |
| `bench/chimera_perf/` | Performance probes in a separate Cargo workspace |
| `vendor/quinn-proto/` | Locally patched dependency selected by the root Cargo manifest |
| `.github/workflows/` | CI, release and performance workflows |

## Working Procedure

1. Run `git status --short` before editing. Inspect relevant diffs and preserve unrelated work.
2. Trace the affected configuration and runtime path, and read the relevant reference code
   before changing compatibility behavior.
3. Choose a small, reviewable change with a clear observable result. Avoid unrelated cleanup,
   dependency upgrades, or broad formatting churn.
4. Add or update tests for changed behavior, including invalid input and boundary cases when
   applicable. Update configuration docs and examples when user-visible semantics change.
5. Run the checks appropriate to the change. Report what passed, what failed, and what could
   not be run; distinguish pre-existing failures from regressions introduced by the change.
6. Summarize the result, compatibility differences and remaining limitations. Update this
   document only when durable workflow, architecture or setup guidance changes.

## Rust and Runtime Conventions

- Follow surrounding module style and workspace rustfmt settings. Use explicit imports,
  conventional Rust names, and small modules with clear responsibilities.
- Keep literal parsing and validation in the config layer; reuse `TryFrom`/`TryInto` conversions
  where established. Validate addresses, tags and API bindings before starting listeners.
- Preserve the distinction between omitted and explicit config values when the reference does.
  Document intentional default differences and cover them with tests.
- Use existing error types, including `Error::InvalidConfig` for configuration validation.
  Prefer typed errors in the library and `anyhow` at application boundaries. Add context without
  exposing credentials. Avoid production `unwrap`/`expect` unless an invariant is established.
- Keep runtime creation at the application/library startup boundary. Do not create nested
  runtimes or call blocking runtime entry points from async request handlers.
- Keep forwarding non-blocking. Precompute expensive work at startup or use `spawn_blocking`
  for blocking I/O and CPU work where needed. A mutex alone is not a reason to add a thread.
- Do not hold blocking mutex guards across `.await`. Keep critical sections short and preserve
  backpressure, cancellation, EOF, half-close and error propagation in relay changes.
- Futures may be awaited, spawned, selected or combined as the design requires. Apply `Send`
  and lifetime bounds where the executor or API requires them; do not require `Sync` universally.
- Preserve server task supervision and shutdown behavior. Inspect the existing lifecycle before
  adding tasks; handle termination and errors instead of silently detaching essential services.
- Reuse `tracing` for logs, `traffic` for metrics, and gRPC/MCP for control-plane exposure.
  Use structured tags and addresses where useful; avoid noisy per-packet logs in normal operation.
  Preserve public statistics and serialization compatibility.
- Keep optional behavior consistent with Cargo feature gates and runtime configuration. Test
  affected reduced-feature builds when changing gates or shared imports.
- Document new or changed public APIs and non-obvious protocol choices. Prefer reference file
  paths or symbols in comments. Keep TODOs concrete and remove them when resolved.
- Treat changes to `vendor/quinn-proto/` as dependency patches: explain their purpose and test
  the affected transport behavior. Do not hand-edit generated protobuf bindings.

## Feature Isolation and Diagnostics

- Follow ARCHITECTURE.md section 11: modules define responsibility, Cargo features select compiled
  capabilities, and runtime configuration selects enabled behavior. Do not add a feature per module.
- Audit existing gates before adding more. Keep protocol, transport, security, control-plane,
  optimization and diagnostic capabilities explicit; preserve mandatory correctness and lifecycle
  guarantees. Distinguish gRPC transport from the Xray gRPC management API.
- Features should be additive. Preserve release/default feature behavior unless changing it is in
  scope. Document required/shared dependencies, app-to-library forwarding, platform constraints,
  runtime activation and missing-capability errors in the owning manifest/docs or support matrix.
- An uncompiled recognized capability must produce an explicit configuration error, not silently
  ignored fields or a security downgrade. Never disable authentication or replay protection for diagnosis.
- Verify the actual dependency feature graph for the selected package and target; feature unification
  can invalidate an assumed minimal build. Test affected minimal, deployed, default/full and important
  interaction combinations as appropriate, plus existing all-feature gates. Record commands and results;
  all-feature success does not establish reduced-feature correctness.
- For fault isolation, first reproduce with the same binary and change one runtime variable at a time;
  then use minimal feature builds if needed. Keep versions, target, build settings and workload comparable.
  A disappearing fault is evidence of a changed condition, not proof of the responsible module.
- Recheck the original deployment combination after a fix. Use existing safe diagnostics and respect
  deployment authorization; this workflow does not authorize disabling live services.

## Validation Commands

Run commands from the repository root unless stated otherwise. The root workspace contains
`chimera_server_app`, `chimera_server_lib`, `chimera_cli`, and `chimera_tcp_reality_server`.
`--all-features` enables all features of selected packages; it is not the default feature set.

For Rust changes, run formatting, Clippy, and the smallest meaningful tests:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p chimera_server_lib --lib
```

Inspect formatting diffs so unrelated changes are not swept into the task. Select the affected
package or integration target instead of library tests when appropriate. For documentation-only
changes, verify paths, commands and the diff; Rust builds and tests are unnecessary unless the
edit also changes executable examples or build behavior.

Useful targeted commands (replace angle-bracket placeholders before running):

```sh
cargo test -p chimera_server_lib --lib -- --list
cargo test -p chimera_server_lib --lib <fully_qualified_test_name> -- --exact
cargo test -p chimera_server_lib --test <integration_target>
cargo test -p chimera_server_app
cargo test -p chimera_server_lib --doc
cargo check -p chimera_server_app --no-default-features --features minimal-vless
cargo check -p chimera_server_app --no-default-features --features minimal-vless-tls
```

- `--exact` matches the full test name. Confirm that the intended test actually ran;
  a successful run with zero matching tests is not validation.
- Keep unit tests in `#[cfg(test)]` modules and integration tests in the owning crate's `tests/`.
  Reuse existing helpers when available; do not assume a `tests/common` module exists.
- Read prerequisites before running ignored or environment-dependent tests. Select related
  tests with `cargo test -p <package> <filter> -- --ignored`; do not run every network or
  performance probe by default.
- `cargo test --locked` requires the existing lockfile to remain unchanged; it does not update
  or pin dependencies itself. After an intentional lockfile update, use it to verify the result.
- Root workspace commands do not cover `bench/chimera_perf/`. For probe changes, use
  `--manifest-path bench/chimera_perf/Cargo.toml` with the relevant Cargo command and read its README.
- `build.rs` uses `protoc-bin-vendored`; inspect build errors before requiring a system `protoc`.
  Consult the current workflows for platform-specific build requirements.

Validate a configuration or start the app using an existing configuration file:

```sh
cargo run -p chimera_server_app -- --config <config_path> --check
cargo run -p chimera_server_app -- --config <config_path>
```

Inspect `start.sh` before using it: it requires `cargo-watch` and references a particular local
configuration. Do not assume launcher scripts or example configs fit the current environment.

## Release Discipline

- After `v0.7.5`, advance only one primary protocol goal per release. Do not mix unrelated
  protocol behavior into the same release cycle.
- A release goal must be vertically complete: user-facing config (when applicable) →
  validation/defaults → `ServerConfig` or owning runtime state → runtime/handler behavior →
  focused tests. Protocol compatibility releases also require the relevant real-client
  interoperability checks and an updated support matrix for the recorded Xray baseline.
- Parsing, validation or field preservation not consumed by runtime behavior is development
  groundwork, not a completed protocol goal. Keep it out of a stable release unless the release
  goal is explicitly configuration/schema alignment.
- Prepare the workspace package version before release. The release workflow must not silently
  bump source versions or push `master` on behalf of the release.
- Every release must pass all of the following before a tag is created:

```sh
cargo fmt --all -- --check
cargo build --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --locked
```

- Also check the current CI matrix for applicable platform and feature coverage. CI coverage
  does not replace the required release checks above.
- Publish the completed goal directly as `vX.Y.Z`, then deploy and validate that released
  version before beginning the next primary protocol goal.
- If deployed validation fails, fix that same goal and publish a new patch version before
  moving on. Record validation evidence and unresolved limitations.
- Apply this sequence when a release is in scope; an ordinary code or documentation task does
  not itself request tagging, publishing or deployment.

## Git and Collaboration

- Preserve other contributors' modified and untracked files. Do not revert unrelated changes
  or include them in a commit. Keep commits focused on the requested behavior.
- Never amend a commit unless you created HEAD in this conversation and no hook rejected it.
- Do not run destructive commands such as `git reset --hard` or `git checkout --` without
  explicit instruction.
- Check for applicable editor or contributor instructions when needed rather than relying on
  dated claims that particular rule files do not exist.
- A TODO describes unfinished work; it does not override current instructions or authorize
  expanding the task. Resolve routine implementation choices using the task and existing code.
