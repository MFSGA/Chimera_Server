# AGENTS

This AGENTS document explains the expectations for automatic contributors running inside Chimera_Server.
It captures the current project priorities, key architecture references, and the commands/style guidance you should follow before touching core logic.
Treat it as the first read for any new change: you do not need to repeat its recommendations unless you diverge.
Use the references here when you feel direction is missing rather than guessing defaults.

## Compass
- Chimera_Server is a Rust networking core whose behavior should stay aligned with xray-core and shoes when it comes to inbound parsing and protocols.
- Maintain an inbound-first focus while the outbound/routing/policy surface is still materializing.
- Keep the data path lean: configuration → runtime state → handler chain → outbound session.
- Data plane logic must stay non-blocking; push heavy work into the control plane or dedicated threads.
- Observability should reuse the `traffic` / gRPC / MCP channels and not invent new telemetry surfaces without coordination.
- Contributors join the code path at the config layer, pass through handler/transport, and surface in runtime/traffic metrics.

## Architecture Reference
- Follow clash-rs for the layered thought process: parse config, build runtime state, isolate handler chain, then expose control-plane APIs.
- Keep the handoff between inbound listener, handler pipeline, and outbound connection explicit in code and documentation.
- Controller services (gRPC, MCP, stats) must stay decoupled from the forwarding data path to avoid blocking.
- As features grow, prefer the existing async task mesh instead of adding custom threads unless mutex-protected state justifies it.

## Implementation Reference
- Protocol behavior is best modeled after https://github.com/cfal/shoes; when in doubt, compare handshake flows, defaults, and error handling.
- New outbound or inbound protocols must update config parsing, the `ServerConfig` conversions, and the handler layer.
- Keep compatibility with xray-core semantics; treat xray as the canonical snapshot for inbound configuration structures and defaults.
- When adding new options, sync them through `config` → `ServerConfig` → `handler` to ensure end-to-end coverage.

## Code Map
- Entry application: `chimera_server_app/src/main.rs` contains the CLI harness for the workspace.
- Core library bootstrap: `chimera_server_lib/src/lib.rs` orchestrates config parsing, runtime creation, and server startup.
- Configuration parsing: `chimera_server_lib/src/config` houses literal config definitions, validation, and serde maps.
- Inbound services: `chimera_server_lib/src/beginning` handles socket acceptance and transport wrappers.
- Handler stack: `chimera_server_lib/src/handler` organizes the protocol-specific layers that sit between transport and outbound.
- gRPC control plane: `chimera_server_lib/src/grpc` exposes APIs for runtime introspection, management, and stats.
- MCP push service: `chimera_server_lib/src/mcp` implements the MCP data stream.
- Runtime and traffic state: `chimera_server_lib/src/runtime` and `chimera_server_lib/src/traffic` manage statistics and service registry.
- TLS and REALITY helpers: `chimera_server_lib/src/reality` contains TLS setup, certificate wiring, and crypto utilities.
- Build-time protos: `chimera_server_lib/build.rs` generates gRPC bindings used by the control plane.
- CLI helpers: `chimera_cli` hosts utilities for interacting with the server while the main app remains lean.

## Development Conventions
- Keep `tokio` runtimes explicit: choose between multi-thread and current-thread builders near `start` and never mix runtime types inside a single server task.
- Derive `ServerConfig` via `TryFrom`/`TryInto`; each inbound entry must validate addresses, tags, and optional API bindings.
- Use `tracing` for logs, `anyhow`/`thiserror` for error aggregation, and ensure each module owns a helper to map string configs to enums.
- When adding observability, follow the existing channels: `traffic` for metrics, `tracing` for logs, `mcp` for control-plane pushes.
- Respect the config layering: literal JSON5 → `config::def` structures → `ServerConfig` → handler builder; do not bypass this chain.
- Avoid blocking in the data path; if you need `std::fs` or complex parsing, spawn a blocking task or precompute during start-up.
- Document new config options in the literal schema and describe them in adjacent README fragments (add to the `config` folder docs if necessary).
- Coordinate new features by updating documentation or AGENTS when extra setup steps become necessary.
- Prefer `#[cfg(test)]` modules for helpers so test scaffolding is gated away from production builds.

## Build / Lint / Test Commands
- `cargo build --all-features` builds `chimera_server_app`, `chimera_server_lib`, and `chimera_cli` with default features.
- `cargo run --package chimera_server_app -- --config config.json5` boots the main app using the local config file.
- `./start.sh` or `start_server.ps1` (Windows) perform scripted hot-reload sequences; inspect them for environment assumptions before running.
- `cargo fmt --all` ensures every crate follows rustfmt; run this before opening PRs.
- `cargo clippy --all-targets --all-features -- -D warnings` enforces lint gates; fix new warnings locally before pushing.
- `cargo test` runs the full test suite across the workspace; it includes integration and unit tests defined under `chimera_server_lib` and `chimera_server_app`.
- `cargo test -p chimera_server_lib --lib` focuses on the core library, while `cargo test --package chimera_server_app` targets the application.
- `cargo test --locked` pins dependencies; locally run it while updating `Cargo.lock`.
- `cargo test --workspace -- --ignored` executes slow tests that are currently gated; run these when iterating on related features.

## Single-Test Workflow
- To run one test function: `cargo test <testname> -p chimera_server_lib -- --exact`; the name can be module-qualified, e.g., `cargo test config::server::parse_basic -- --exact`.
- When a test name is ambiguous, combine module path and function, such as `cargo test handler::tcp::inbound_parse_settings -- --exact`.
- For doc tests in a module, add the crate flag `cargo test --doc <module>` or run `cargo test -p chimera_server_lib doc_tests::api` if they are grouped.
- If a test requires runtime service mocks, prefer helpers under `chimera_server_lib/tests` and run `cargo test --test helper_name` to exercise them.

## Style Guidelines
### Imports
- Group `use` statements by crate group: `std`, workspace, external dependencies, then local modules; keep each group sorted alphabetically.
- Avoid glob imports unless a module exposes a carefully curated prelude; prefer explicit names so the compiler and reviewers know what is imported.
- In nested modules, prefer relative imports (`crate::`, `super::`, `self::`) over absolute paths to keep the structure digestible.

### Formatting
- Run `cargo fmt` with the workspace settings for every change; do not hand-tune spacing unless rustfmt is misguided (explain the exemption in a comment).
- Keep line lengths around 100 characters; break expressions across lines with trailing commas to keep diffs readable.
- Use trailing commas in multi-line arrays, maps, enums, and match arms to reduce churn when items move.

### Types & Config
- Prefer small, focused structs (e.g., `ServerConfig`, `ApiConfig`, `McpConfig`) and keep serde derives close to literal config types.
- Align config defaults with xray-core; if new defaults differ, add comments referencing the reason and spike with tests for both nil and explicit values.
- When exposing public constructors, use `impl Default` or builder helpers so callers do not replicate configuration plumbing.
- Wrap configuration validation logic in helper methods inside config modules; keep verification close to parsing so invalid states are rejected early.

### Naming
- Use `snake_case` for functions, variables, and modules, `CamelCase` for structs/enums, and `SCREAMING_SNAKE` for constants.
- Keep tag names short but descriptive; follow xray semantics when deriving tags from inbound entries.
- Use verbs for functions (e.g., `start_server`), nouns for structs (`InboundConfig`), and `maybe_`/`try_` prefixes for fallible helpers.
- When a function returns `Option`, name it to match the `None` semantic (e.g., `next_handler`, `api_listen_addr`).

### Error Handling
- Prefer `Result<T, Error>` with `thiserror` to derive error enums; include context in `#[error("...")]` strings.
- Use `anyhow` at application boundaries only when you need to bubble multiple error kinds to the CLI layer; internal logic should use explicit error enums.
- Map parsing errors (e.g., invalid addresses) to `Error::InvalidConfig` before they escape to the runtime.
- Log recoverable errors at `tracing::warn`, fatal errors at `tracing::error`, and only `panic!` when invariants cannot be recovered.
- Avoid `unwrap`/`expect` in production code unless invariants are proven; prefer `?` or `match` to surface failures.

### Async & Runtime
- Use `tokio::spawn`/`tokio::task::spawn_blocking` from `start_async` and prefer `async move` when capturing owned state.
- Keep `async fn` bodies small; split complex flows into helpers for readability and easier test coverage.
- Always call `.await` directly on futures you create; avoid storing raw futures in struct fields unless they implement `Send` and `Sync` properly.
- When running multiple servers, gather `JoinHandles` and `select_all` on them just like `start_async` does, so any finished server triggers shutdown.

### Observability
- Instrument critical transitions with `tracing::info` and `tracing::warn`; capture tags and addresses to tether logs to inbound entries.
- Add structured fields when logging `join_handles`, listen addresses, or config tags to make debugging easier.
- When exposing stats over `runtime` or `traffic`, keep the serialization format stable; add versioned fields only after ensuring backward compatibility.

### Testing Practices
- Place unit tests inline with modules for small helpers and use `#[cfg(test)] mod tests` to keep them close to the code they verify.
- For integration tests, drop them under `tests/` or use `#[tokio::test]` in `chimera_server_lib` when async context is needed.
- Run slow or environment-dependent tests manually and annotate them with `#[ignore]`; make it easy to find them via `cargo test -- --ignored`.
- When mocking sockets or control-plane services, reuse helpers in `chimera_server_lib/tests/common` to keep behavior consistent.

### Module Layout
- Keep each module focused on a single responsibility and limit file size to maintain readability.
- Organize handler chain layers so that transport, parsing, and outbound flow remain obvious to readers.
- Avoid circular references by pulling shared helpers into `util` or dedicated submodules.

### Feature Flags & Conditional Code
- Prefer Cargo features for optional transports or protocols and keep feature flags well-documented in Cargo.toml.
- Combine feature flags with runtime configuration so feature-intensive code paths are easy to toggle during tests.
- When using `#[cfg(feature = "x")]`, document the runtime impact in the same module to help future maintainers understand why the gate exists.

### Documentation & Comments
- Document every exported function, struct, and enum with doc comments explaining its role in the pipeline; focus on why it exists rather than how it works.
- When a comment is needed, explain the non-obvious decision or cross-reference the xray/shoes equivalent behavior.
- Keep TODOs actionable (who, what, why) and remove them once the change is implemented.

## Diagnostics & Debugging
- Prefer bringing up a full-featured trace (via `tracing` subscribers) when a runtime path is ambiguous.
- Capture configuration tags and listen addresses in logs before and after each server start to correlate later with metrics.
- Use `cargo test -- --nocapture` sparingly to troubleshoot tests that fail silently under the default harness.
- Validate generated config structures (`ServerConfig`, API wrappers) during startup by invoking the same helpers used in production.
- When investigating threading issues, lean on `tokio-console` when enabled or add temporary `tracing::debug!` statements gated by verbose settings.
- Before filing a bug, reproduce it with the config that triggered it and describe which module's handler chain is responsible.

## Git & Collaboration
- Always run `git status` before editing to understand unrelated changes; do not revert files modified by other contributors unless explicitly asked.
- Keep commits focused; describe why the change exists rather than how it was implemented, mirroring this AGENTS file's style.
- Never amend commits unless you created the HEAD commit in this conversation and no hook rejected the original commit.
- Do not run destructive git commands like `reset --hard` or `checkout --` without explicit instruction.
- Coordinate with other agents by referencing this AGENTS document when introducing new commands, features, or conventions that will affect workflow.

## Cursor / Copilot Rules
- Cursor rules: there are no `.cursor/rules/` directories or `.cursorrules` files in this workspace as of Jan 2026.
- Copilot rules: the repo does not contain `.github/copilot-instructions.md`; rely on this AGENTS file for guidance.

## Next Steps for Agents
- Always run `cargo fmt` and `cargo clippy` locally after editing layout or logic, then select the smallest meaningful scope for `cargo test`.
- When adding features, update this AGENTS document as needed to capture any new setup steps or conventions you introduced.
- If you encounter conflicting guidance, prefer what the humans last committed to `AGENTS.md` unless a TODO describes a future change.
