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
| `vless` over TCP | Supported | Requires `settings.decryption: "none"`; `settings.clients` may be an explicit empty array, in which case the listener starts with no authenticated users until users are added through the management API. |
| `vless` + WebSocket | Supported | Uses `streamSettings.wsSettings`; `xtls-rprx-vision` cannot use WebSocket. |
| `vless` + XHTTP | Experimental | Use `protocol: "vless"` with `streamSettings.network: "xhttp"` and `xhttpSettings`. |
| `vless` + TLS | Supported | Requires `streamSettings.security: "tls"` and `tlsSettings` certificates. |
| `vless` + REALITY | Partial | Inbound-only REALITY. `publicKey`, `fingerprint`, `spiderX`, and non-zero `xver` are rejected. |
| `vless` Vision | Partial | Only `flow: "xtls-rprx-vision"` is accepted. Direct TLS/REALITY VLESS now uses a stable mixed-capable handler, so plain and Vision users may share one inbound; transports that do not support Vision (for example WebSocket, gRPC, HTTPUpgrade and XHTTP) still reject/avoid Vision semantics. |
| `vmess` over TCP | Partial | Requires the `settings.clients` field; an empty array starts with no authenticated users. Cipher handling is currently normalized internally. |
| `vmess` + WebSocket | Partial | Uses `streamSettings.wsSettings`; compatibility coverage should be expanded before calling it stable. |
| `trojan` over TCP | Partial | Requires a `settings` object; an explicit empty `clients` array starts with no authenticated users, while every listed client must have a non-empty password. Fallbacks require explicit `host:port` destinations. |
| `trojan` + WebSocket | Partial | Uses `streamSettings.wsSettings`; fallback and TLS behavior need more xray/shoes comparison tests. |
| `socks` | Supported | Supports no-auth and username/password accounts. |
| `dokodemo-door` | Supported | Supports explicit target address/port and `followRedirect` parsing. |
| `hysteria2` | Experimental | Requires a QUIC/TLS certificate and `settings`; `clients`/`users` may be empty when no user is configured, or Xray's transport-level `hysteriaSettings.auth` can provide the fallback credential. |
| `tuic` / `tuicV5` | Experimental | Requires UUID, password, QUIC/TLS certificate files, and optional zero-RTT flag. |
| `xhttp` as top-level protocol | Not supported | Use VLESS with `streamSettings.network: "xhttp"` instead. |

## Transports And Security Layers

| Area | Status | Current boundary |
| --- | --- | --- |
| TCP transport | Supported | Default transport when `streamSettings.network` is absent or `tcp`. |
| WebSocket transport | Partial | Wrapped around supported TCP protocols when the `ws` feature is enabled. |
| XHTTP transport | Experimental | Currently attached through VLESS; top-level `protocol=xhttp` is rejected. |
| QUIC transport | Experimental | Used by Hysteria2 and TUIC server paths. |
| UDP transport | Partial | `streamSettings.network: "udp"` is implemented for `dokodemo-door`; Shadowsocks also supports UDP-only or combined `tcp,udp` listeners. Other inbound protocol/transport combinations are rejected explicitly. Linux-only `dokodemo-door` `followRedirect` behavior remains platform-specific. |
| TLS security | Supported | Requires at least one certificate. Inline certificate/key and file paths are parsed. |
| REALITY security | Partial | Inbound server path exists, but unsupported xray-core client-side fields are rejected. |
| Unknown security value | Not supported | Recognized but unimplemented `streamSettings.security` values are rejected explicitly; they are never silently downgraded to plaintext. |

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
| Routing and policy | Partial | Xray-style routing state and gRPC controls exist. The Chimera-only `userDomainAccess` extension is parsed and enforced before outbound selection, including `TestRoute`, protocol identity aliases for VLESS/VMess, credential identities for Trojan/Hysteria2, HTTP Basic Auth username identity, and the verified Shadowsocks email identity. Known domains follow per-user allow/reject rules; IP-only, missing or invalid domains are always allowed and audited, while native Xray `routing.rules` may still independently match other conditions. `dns.hosts` mappings now support Xray custom host rule forms (default/`full:`, `domain:`, `keyword:`, `regexp:`, `dotless:`), static IP values, bounded `proxiedDomain` replacement and response-code values such as `#3` (`#0` is an empty response); plain UDP `dns.servers` IP endpoints are also supported with default/explicit ports, A/AAAA queries and ordered server attempts, string `tcp://IP[:port]` endpoints use Xray's two-byte DNS-over-TCP framing, and basic nameserver objects support `address`, `port`, `clientIp`, `domains`, per-server `queryStrategy`, `timeoutMs`, `expectedIPs`/`expectIPs`, `unexpectedIPs`, `skipFallback` and `finalQuery`, with global/per-server EDNS Client Subnet, matching nameservers prioritized before fallback, per-server timeout default/zero semantics aligned to Xray, and returned addresses filtered according to Xray IP rules. `enableParallelQuery` is supported for selected direct UDP/TCP nameservers with Xray-style policy-group gating. These DNS capabilities are normalized and shared by `TestRoute` and the main runtime resolver. Geosite/ext rules, other per-server fallback controls, URL schemes, remote dispatcher routing and DoH/DoT settings are explicitly rejected until implemented; global query strategies `UseIP`, `UseIPv4`, `UseIPv6` and `UseSystem` plus DNS fallback controls `disableFallback` and `disableFallbackIfMatch` are supported for the shared resolver. Session-based XUDP now preserves the original domain and applies shared routing before resolving; dynamic policy updates have local and real Xray-over-gRPC evidence for new XUDP sessions; DNS errors are exposed separately as `GetPolicyStatus.stats.dnsFailures` and are not counted as domain-policy rejects; recent unknown-target audit events are exposed through the Chimera-only `GetAuditEvents` RPC with bounded storage and hashed routing users; REALITY fallback and observatory still use separate native resolvers. `AsIs`, `IpIfNonMatch` and `IpOnDemand` now have local tests for both domain routing and route-only sniffed-domain/original-IP boundaries, with `TestRoute` preserving caller-provided candidate IP semantics. Xray 26.2.6 VLESS/VMess/HTTP TCP, VLESS XUDP, and Shadowsocks TCP/legacy UDP/2022 EIH UDP allow/reject interoperability, plus Trojan/Hysteria2/Socks5 TCP/UDP user-domain allow/reject interoperability, VLESS TCP unknown-target allow/audit interoperability, and VLESS TCP route-only HTTP `Host` allow/reject interoperability are verified; native Xray `routing.rules` `user + domain` interoperability is verified for VLESS TCP only; existing-session lifecycle, GlobalID reattachment, EIH TCP and other transport combinations remain pending. It is not an Xray-native policy object. |

The current user-domain routing iteration targets VLESS, VLESS over XHTTP, Hysteria2, Socks5,
Trojan, and the verified Shadowsocks TCP/legacy UDP/2022 EIH UDP paths on Linux. XHTTP over
TCP with `security: none`/TLS, Socks5 TCP/UDP, Hysteria2 TCP/UDP, Trojan TCP/UDP, and those
Shadowsocks paths have passing Xray 26.2.6 allow/reject interoperability checks; EIH TCP and
the remaining target combinations are tracked separately.
Other protocol identities and transport combinations are not expanded in this iteration and
must not be presented as verified support. When an active user-domain policy is evaluated from
one of those inbound protocols, Chimera emits a bounded
`user_domain_access_unsupported_protocol` warning; the diagnostic does not change the existing
decision. Shadowsocks EIH TCP and other transports remain pending.

## Re-certification evidence (2026-09-11)

`userDomainAccess.protocolIdentity.shadowsocksEmail` maps to the authenticated Shadowsocks
user email, matching Xray's `MemoryUser.Email` routing identity. The field is optional for
backward compatibility; a policy that omits it does not acquire a Shadowsocks identity by
accident. The Linux Xray 26.2.6 Shadowsocks TCP, legacy UDP, and 2022 EIH UDP domain
allow/reject interoperability tests pass; EIH TCP and other transports remain outside that
claim.

The current pre-M5 compatibility baseline was refreshed against the repository-pinned `xray` binary (`Xray 26.2.6`) and the local fixed xray-core reference. Passing real-client/server checks in this refresh include:

- Xray client -> Chimera: plain VLESS TCP, VLESS WebSocket/WSS, VLESS TLS+Vision TCP, VLESS gRPC h2c, VLESS HTTPUpgrade, VMess TCP/WebSocket/WSS, Trojan TCP/TLS/WebSocket+TLS, HTTP/Mixed TCP proxying, legacy Shadowsocks TCP, Shadowsocks 2022 TCP + AES UDP, and Hysteria2 TCP + UDP with Xray defaults.
- XHTTP security matrix with a real Xray peer: none, TLS, HTTP/3, and REALITY, each with 64 KiB payload coverage.
- REALITY Vision parity: payload/framing boundary transfer and TCP half-close behavior compared with an Xray server baseline.
- gRPC control-plane dual-server matrix: 18 strict/baseline-supported cases passed, 2 Xray-unsupported probes skipped, and 2 informational cases recorded; the VLESS multi-user flow also matched the Xray baseline.
- Inbound lifecycle parity: RemoveInbound rejects new SOCKS TCP connections while preserving an already accepted tunnel on both Xray and Chimera; lifecycle failure gRPC codes match Xray. Chimera intentionally differs from Xray on AddInbound bind failure by rolling the failed instance back instead of retaining a dead handler tag.

The pre-M5 certification pass is complete for the matrix above. One top-level Xray-client REALITY+Vision test remains environment-blocked on this machine because its IPv6 echo bind fails with `EADDRNOTAVAIL`; the IPv4 REALITY parity tests above pass and exercise the same server handler path, so this is recorded as an environment limitation rather than a protocol failure. The refreshed VMess matrix also caught and fixed a real data-plane issue: `VmessStream::poll_write` could acknowledge an application write while random global padding left the final plaintext remainder buffered until a later write/flush, stalling interactive or tail traffic; accepted VMess writes now drain every generated frame before being acknowledged. Trojan 64 KiB coverage is intentionally exercised after a small first payload on the same authenticated tunnel: fixed Xray 26.2.6 buffers its first Trojan payload before disabling the outbound buffer and reports `common/buf: buffer is full` if a single 64 KiB payload is presented as that first write. The staged test still validates 64 KiB Chimera data-plane transfer without misclassifying that Xray-client limitation as a server incompatibility.

## Known Engineering Gaps

- Replace production `todo!`, `panic!`, and input-path `unwrap` calls with typed errors or connection-level failures.
- Promote more protocol paths from partial or experimental only after xray-core/shoes compatibility tests cover success and failure cases.
- Document exact xray-core field differences next to each protocol builder.
- Split the compatibility tests by protocol so regressions can be traced to one inbound surface quickly.
- Keep the remaining dead-code exceptions local and documented; the crate-wide suppression has been removed, while generated Xray protobuf bindings and optional control-plane/WIP surfaces retain narrowly scoped exceptions where their wire/API surface is intentionally broader than the current feature build.
