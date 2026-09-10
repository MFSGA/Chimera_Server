# Chimera Server Compatibility Matrix

This document records the current user-facing compatibility boundary for Chimera Server.
It is intentionally conservative: a protocol or option is listed as supported only when the
current code has an explicit config path and runtime handler path for it.

## Status Labels

| Status | Meaning |
| --- | --- |
| Supported | Expected to parse, start, and have handler coverage in the current workspace. |
| Partial | The main path exists, but important xray-core or shoes behavior is missing or restricted. |
| Experimental | The path exists, but production semantics still need more compatibility tests. |
| Not supported | The config is rejected, ignored, feature-gated away, or can panic if forced. |

## Inbound Protocols

| Inbound | Status | Current boundary |
| --- | --- | --- |
| `vless` over TCP | Supported | Requires at least one `settings.clients` entry. |
| `vless` + WebSocket | Supported | Uses `streamSettings.wsSettings`; `xtls-rprx-vision` cannot use WebSocket. |
| `vless` + XHTTP | Experimental | Use `protocol: "vless"` with `streamSettings.network: "xhttp"` and `xhttpSettings`. |
| `vless` + TLS | Supported | Requires `streamSettings.security: "tls"` and `tlsSettings` certificates. |
| `vless` + REALITY | Partial | Inbound-only REALITY. `publicKey`, `fingerprint`, `spiderX`, and non-zero `xver` are rejected. |
| `vless` Vision | Partial | Only `flow: "xtls-rprx-vision"` is accepted. Direct TLS/REALITY VLESS now uses a stable mixed-capable handler, so plain and Vision users may share one inbound; transports that do not support Vision (for example WebSocket, gRPC, HTTPUpgrade and XHTTP) still reject/avoid Vision semantics. |
| `vmess` over TCP | Partial | Requires `settings.clients`; cipher handling is currently normalized internally. |
| `vmess` + WebSocket | Partial | Uses `streamSettings.wsSettings`; compatibility coverage should be expanded before calling it stable. |
| `trojan` over TCP | Partial | Requires non-empty client passwords. Fallbacks require explicit `host:port` destinations. |
| `trojan` + WebSocket | Partial | Uses `streamSettings.wsSettings`; fallback and TLS behavior need more xray/shoes comparison tests. |
| `socks` | Supported | Supports no-auth and username/password accounts. |
| `dokodemo-door` | Supported | Supports explicit target address/port and `followRedirect` parsing. |
| `hysteria2` | Experimental | Requires QUIC/TLS certificate files and at least one client. |
| `tuic` / `tuicV5` | Experimental | Requires UUID, password, QUIC/TLS certificate files, and optional zero-RTT flag. |
| `xhttp` as top-level protocol | Not supported | Use VLESS with `streamSettings.network: "xhttp"` instead. |

## Transports And Security Layers

| Area | Status | Current boundary |
| --- | --- | --- |
| TCP transport | Supported | Default transport when `streamSettings.network` is absent or `tcp`. |
| WebSocket transport | Partial | Wrapped around supported TCP protocols when the `ws` feature is enabled. |
| XHTTP transport | Experimental | Currently attached through VLESS; top-level `protocol=xhttp` is rejected. |
| QUIC transport | Experimental | Used by Hysteria2 and TUIC server paths. |
| UDP transport | Not supported | `streamSettings.network: "udp"` maps to UDP transport, but server startup currently rejects it. |
| TLS security | Supported | Requires at least one certificate. Inline certificate/key and file paths are parsed. |
| REALITY security | Partial | Inbound server path exists, but unsupported xray-core client-side fields are rejected. |
| Unknown security value | Partial | Non-XHTTP paths currently pass through unknown values as no extra security layer. |

## Config Surface

| Area | Status | Notes |
| --- | --- | --- |
| JSON | Supported | Use `--format json` or a `.json` file. |
| JSON5 | Supported | Recommended for local config files and examples. |
| YAML | Partial | File parsing exists for `.yaml` and `.yml`; examples and tests are lighter than JSON5. |
| TOML | Not supported | Explicitly rejected by config parsing. |
| Environment placeholders | Supported | `%(NAME)s` expansion is handled by the config loader. |
| `api.listen` gRPC control plane | Supported | Starts gRPC directly on the configured listen address. |
| xray-style API inbound routing | Partial | Resolves API listen address through routing, but local gRPC currently listens without TLS. |
| MCP push service | Partial | Listen/path/update interval are parsed and served, but operational docs are still thin. |
| Outbounds | Partial | Tags and protocol names are surfaced in runtime state; forwarding behavior is still materializing. |
| Routing and policy | Partial | Routing state and gRPC controls exist; policy parsing is mostly a compatibility placeholder. |

## Re-certification evidence (2026-09-11)

The current pre-M5 compatibility baseline was refreshed against the repository-pinned `xray` binary (`Xray 26.2.6`) and the local fixed xray-core reference. Passing real-client/server checks in this refresh include:

- Xray client -> Chimera: VLESS TLS+Vision TCP, VLESS gRPC h2c, VLESS HTTPUpgrade, HTTP/Mixed TCP proxying, legacy Shadowsocks TCP, Shadowsocks 2022 TCP + AES UDP, and Hysteria2 TCP + UDP with Xray defaults.
- XHTTP security matrix with a real Xray peer: none, TLS, HTTP/3, and REALITY, each with 64 KiB payload coverage.
- REALITY Vision parity: payload/framing boundary transfer and TCP half-close behavior compared with an Xray server baseline.
- gRPC control-plane dual-server matrix: 18 strict/baseline-supported cases passed, 2 Xray-unsupported probes skipped, and 2 informational cases recorded; the VLESS multi-user flow also matched the Xray baseline.
- Inbound lifecycle parity: RemoveInbound rejects new SOCKS TCP connections while preserving an already accepted tunnel on both Xray and Chimera; lifecycle failure gRPC codes match Xray. Chimera intentionally differs from Xray on AddInbound bind failure by rolling the failed instance back instead of retaining a dead handler tag.

One top-level Xray-client REALITY+Vision test remains environment-blocked on this machine because its IPv6 echo bind fails with `EADDRNOTAVAIL`; the IPv4 REALITY parity tests above pass and exercise the same server handler path. Plain VLESS TCP, VLESS WS/WSS, VMess TCP/WS/TLS, and Trojan TCP/TLS/WS still need refreshed real Xray-client evidence before the pre-M5 certification pass is considered complete.

## Known Engineering Gaps

- Replace production `todo!`, `panic!`, and input-path `unwrap` calls with typed errors or connection-level failures.
- Promote more protocol paths from partial or experimental only after xray-core/shoes compatibility tests cover success and failure cases.
- Document exact xray-core field differences next to each protocol builder.
- Split the compatibility tests by protocol so regressions can be traced to one inbound surface quickly.
- Remove global dead-code suppression once unfinished surfaces are either implemented or gated behind explicit features.
