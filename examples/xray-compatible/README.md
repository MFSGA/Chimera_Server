# Xray-compatible examples

This directory is the authoritative materialized config matrix for Chimera Server examples that intentionally use xray-core-shaped JSON/JSON5 fields such as `inbounds`, `outbounds`, `settings`, and `streamSettings`.

Current implementation reference: local `ref/xray-core` at Xray-core `v26.9.9`
(`52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`, pre-release).

The release-prep real-client checks recorded below were run on 2026-09-10 with two Xray client builds:

```text
repository fixture: Xray 26.2.6 / 12ee51e / go1.25.7 linux/amd64
fixed reference used then: Xray 26.7.28 source at 5ca6f4b7d4dc20a881d4330e498892697627ec0c, built with go1.26.5 linux/amd64
```

The source baseline was subsequently advanced to Xray-core `v26.9.9`. The historical
release-prep results below retain the exact Xray source and client versions used when each
test ran; they are not retroactively relabeled as `v26.9.9` verification.

## 2026-09-20 verification refresh

The repository-local Linux client was rebuilt from `ref/xray-core` commit
`52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120` with the Nix development shell's Go `1.27rc2`:

```text
Xray 26.9.9 Custom (go1.27rc2 linux/amd64)
sha256: 3626389b26d5b5b97663ca6ee60960d2075c0d4a442c8c0165f64e7c9e9624bc
```

Rust formatting, Nix flake evaluation, workspace locked tests, all-feature workspace build and
Clippy passed. The ordinary XHTTP and example matrices also passed. After constraining Xray
compatible Hysteria2 response frames to Xray's fixed 1200-byte UDP reader limit, all 47 ignored
`xray_client_proxy_e2e` cases passed with this client. The REALITY+Vision test explicitly skipped
only its IPv6 localhost subcase because this machine has no IPv6 localhost bind capability; its
IPv4, TLS and REALITY checks passed. Xray's direct config checks now accept all 25 materialized
examples. The examples use the Xray 26.9.9 UDP/Hysteria syntax and the project certificate paths
`cert/cert.pem` and `cert/key.pem`; TLS checks still require those local certificate fixtures.

The mKCP interoperability refresh on 2026-09-13 additionally used the then-newest published Xray pre-release and the latest non-pre-release GitHub release:

```text
latest published:   Xray 26.9.9 / 52a412d / go1.27.1 linux/amd64 (pre-release)
latest stable:      Xray 26.3.27 / d2758a0 / go1.26.1 linux/amd64
```

The official release archives used for that mKCP refresh were checksum-verified before execution. The older repository fixture remains useful for compatibility coverage, but its Hysteria UDP writer has a client-side 4096-byte serialization-buffer limit described in the Hysteria evidence section below. Fixed-reference release claims use the second build where that distinction matters.

## Evidence levels

- **config-validated**: the materialized JSON5 file passes Chimera's public config validation path in `chimera_server_lib/tests/xray_compatible_examples.rs`.
- **runtime-covered**: focused unit/integration tests exercise the relevant runtime path, but this label alone is not a real Xray-client compatibility claim.
- **Xray-verified**: an ignored real-client test was explicitly executed against the client build named for that combination in this release-prep round.
- **release-blocked**: current real-client verification exposed a reproducible server-side or unresolved interoperability failure. A known limitation isolated to an older client fixture is documented separately rather than attributed to Chimera.

Config validation is necessary but is not protocol interoperability evidence. Tests marked `#[ignore]` are not executed by ordinary `cargo test` and must be run explicitly when they support a release claim.

## Materialized examples

| Example | Inbound | Transport | Security | Current evidence |
| --- | --- | --- | --- | --- |
| `socks-tcp-noauth.json5` | socks | tcp | none | config-validated |
| `socks-tcp-password.json5` | socks | tcp | none | config-validated |
| `socks-tcp-udp.json5` | socks | tcp + UDP associate | none | config-validated |
| `dokodemo-door-tcp.json5` | dokodemo-door | tcp | none | config-validated |
| `dokodemo-door-udp.json5` | dokodemo-door | udp | none | config-validated |
| `dokodemo-door-udp-routing-blackhole.json5` | dokodemo-door | udp | none | config-validated; routing example |
| `dns-hosts-dokodemo-tcp.json5` | dokodemo-door | tcp | none | config-validated; `dns.hosts` example |
| `http-tcp-password.json5` | http | tcp | none | config-validated; Xray-verified Basic-auth CONNECT with repository fixture |
| `vless-tcp-none.json5` | vless | tcp | none | config-validated |
| `vless-mkcp-none.json5` | vless | mkcp | none | config-validated; Xray-verified TCP stream interoperability with Xray 26.9.9 and 26.3.27 |
| `vless-ws-none.json5` | vless | websocket | none | config-validated |
| `vless-ws-tls.json5` | vless | websocket | tls | config-validated |
| `vless-tcp-tls-vision.json5` | vless | tcp | tls + vision | config-validated; Xray-verified TCP stream + inner TLS Vision with repository fixture |
| `vless-xhttp-none.json5` | vless | xhttp | none | config-validated; runtime-covered |
| `vless-xhttp-tls.json5` | vless | xhttp | tls | config-validated; Xray 26.9.9-verified TLS/H2 packet-up (including xPadding obfuscation, multi-request session reassembly and out-of-order sequence delivery), error-status parity, and stream-up profiles |
| `vless-xhttp-tls-h2-stream-one.json5` | vless | xhttp | tls + h2 + stream-one | config-validated; Xray 26.9.9-verified 1 MiB bidirectional echo, client-cancellation liveness, and raw HTTP/2 half-close parity |
| `vmess-tcp-none.json5` | vmess | tcp | none | config-validated; runtime-covered |
| `vmess-ws-none.json5` | vmess | websocket | none | config-validated; runtime-covered |
| `vmess-ws-tls.json5` | vmess | websocket | tls | config-validated; runtime-covered |
| `trojan-tcp-none.json5` | trojan | tcp | none | config-validated; runtime-covered |
| `trojan-tcp-tls.json5` | trojan | tcp | tls | config-validated; runtime-covered |
| `trojan-ws-tls.json5` | trojan | websocket | tls | config-validated; runtime-covered |
| `hysteria-quic-tls.json5` | hysteria | hysteria (H3) | tls | current Xray syntax; filename retained for compatibility; legacy 26.2.6 client has a documented 4 KiB serialization limit |
| `shadowsocks-tcp-udp.json5` | shadowsocks | tcp + udp | none | config-validated; Xray-verified |
| `shadowsocks-2022-eih-tcp-udp.json5` | shadowsocks 2022 EIH | tcp + udp | none | config-validated; Xray-verified |
| `wireguard-inbound.json5` | wireguard | UDP + system TUN | WireGuard | config-validated; Linux runtime requires TUN/CAP_NET_ADMIN and host forwarding/NAT; interoperability not yet verified |

The two Shadowsocks examples intentionally omit `streamSettings`: Chimera's combined Shadowsocks `network: "tcp,udp"` listener rejects `streamSettings` because the same inbound also owns a UDP listener.

VLESS, VMess, Trojan, and Hysteria2 inbound configurations may explicitly contain an empty
`clients` array. Chimera starts the listener with no authorized users, so authentication
fails until a user is added through the management API; this matches the checked-in Xray
server behavior and is covered by configuration-builder regression tests.

For Chimera's `userDomainAccess` extension, a Shadowsocks user's configured `email` is the
authenticated routing identity and can be supplied as `protocolIdentity.shadowsocksEmail`.
This follows Xray's `MemoryUser.Email` convention; the Linux Xray 26.2.6 Shadowsocks TCP and
legacy UDP and 2022 EIH UDP domain-policy allow/reject tests pass, while EIH TCP and other
transports remain pending.

## Routing and DNS compatibility scope

| Area | Current evidence |
| --- | --- |
| Xray `routing.rules` domain/user matching | Runtime-covered by native routing tests, including `AsIs`, `IpIfNonMatch` and `IpOnDemand` domainStrategy behavior plus route-only sniffed-domain/original-IP unit coverage; Xray 26.2.6 VLESS TCP `user + domain` and route-only HTTP `Host` allow/reject interoperability pass, while other protocol/transport combinations remain pending. |
| Chimera `userDomainAccess` known domains | Runtime-covered before outbound selection, including session-based XUDP domain preservation; local and real Xray-over-gRPC dynamic updates for new XUDP sessions pass; DNS failures are exposed separately from policy rejects; Xray 26.2.6 VLESS TCP/XUDP, Trojan TCP/UDP, Hysteria2 TCP/UDP, Socks5 TCP/UDP and VLESS XHTTP over TCP, plus Xray 26.9.9 XHTTP/3 TLS and XHTTP + REALITY allow/reject interoperability, pass. Existing-session lifecycle, GlobalID reattachment and other inbound protocols remain pending. |
| Unknown target domain access | Runtime-covered as allow + structured audit; direct IP, missing SNI/Host and unrecognized domains are not rejected by this policy. VLESS TCP direct-IP allow/audit interoperability passes with Xray 26.2.6. Recent events are queryable through Chimera's bounded `UserDomainAccessService/GetAuditEvents` extension. |
| Xray `dns.hosts` | Config-validated and runtime-covered for IP, `proxiedDomain` and response-code mappings (for example `"#3"`; `"#0"` is an empty response) using Xray custom host rules: default/`full:`, `domain:`, `keyword:`, `regexp:`, and `dotless:`; matching entries are combined, with case, trailing-dot and IDN normalization for literal domain patterns. `proxiedDomain` chains are bounded and fall through to the final alias resolver when no static alias is present. Geosite/ext rules remain unsupported. |
| Xray `dns.servers` and advanced DNS options | Plain UDP IP nameservers are config-validated and runtime-covered, including default port 53, explicit ports, A/AAAA queries, ordered server attempts and global `queryStrategy` family selection (`UseIP`, `UseIPv4`, `UseIPv6`, `UseSystem`), and top-level `disableFallback` / `disableFallbackIfMatch` fallback controls. String endpoints using `tcp://IP[:port]` are also runtime-covered with Xray's two-byte DNS-over-TCP framing; advanced object entries remain UDP-only. Basic nameserver objects with `address`, `port`, `clientIp`, `domains`, per-server `queryStrategy`, `timeoutMs`, `expectedIPs`/`expectIPs`, `unexpectedIPs`, `skipFallback` and `finalQuery` are also supported; top-level `clientIp` applies to plain UDP/TCP queries and a server object's value overrides it, emitting Xray-compatible EDNS Client Subnet (/24 IPv4, /96 IPv6). Matching nameservers are prioritized before the normal fallback order, per-server timeouts follow Xray's 4000ms default/zero semantics, and returned addresses are filtered according to the configured IP rules. `enableParallelQuery` is supported for the selected direct UDP/TCP nameservers: equivalent adjacent policies race, while lower-priority policy groups remain gated until higher-priority groups fail. Other fallback controls, URL schemes, remote dispatcher routing and DoH/DoT remain unsupported and are rejected explicitly. |

The current user-domain policy iteration targets VLESS, VLESS over XHTTP, Hysteria2, Socks5,
Trojan, and the verified Shadowsocks TCP/legacy UDP/2022 EIH UDP paths on Linux. Other inbound
protocols and unverified transport combinations are not claimed as supported; an active policy
emits a bounded `user_domain_access_unsupported_protocol` warning when one of them reaches the
policy check. Shadowsocks EIH TCP and other transports remain pending.

## Real Xray-client verification recorded on 2026-09-10 and 2026-09-13

### HTTP inbound Basic authentication: PASS

On 2026-09-13 the repository-local Xray 26.2.6 / `12ee51e` client was configured with a SOCKS inbound and an HTTP outbound pointing at Chimera's password-protected HTTP inbound. The positive CONNECT tunnel completed a TCP echo roundtrip, while a second Xray client using the wrong HTTP proxy password failed to establish the tunnel and left the Chimera listener running.

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_through_chimera_http \
  -- --ignored --exact --nocapture
```

This refresh covers Xray HTTP-outbound interoperability for TCP CONNECT and Basic authentication success/failure. Chimera's separate `http_and_mixed_inbounds_proxy_tcp` test continues to cover direct absolute-form forwarding and `allowTransparent`; those paths were not exercised through the Xray HTTP outbound in this certification.

### VLESS TCP + TLS + Vision: PASS with repository fixture

On 2026-09-14 the repository-local Xray 26.2.6 / `12ee51e` client was run as a SOCKS5 front end with a VLESS outbound using TCP, TLS and `xtls-rprx-vision`. Chimera used its repository certificate, and the Xray client pinned that certificate's SHA-256 fingerprint. The interoperability test completed a small TCP echo, deterministic 64 KiB and 1 MiB TCP echo roundtrips, and a real inner TLS application-data exchange through Vision direct mode.

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_through_chimera_tls_vision \
  -- --ignored --exact --nocapture
```

This certifies the positive TCP/TLS/Vision path with the repository fixture. A companion negative-authentication case runs the same TLS/Vision transport with a validly formed but unconfigured VLESS UUID and verifies that Xray cannot proxy the request, Chimera does not dial the requested target, and the Chimera listener remains running:

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_with_wrong_uuid_cannot_proxy_through_chimera_tls_vision \
  -- --ignored --exact --nocapture
```

A third case uses plain TLS clients to send the correct VLESS version and UUID, then truncates the request at several authenticated header boundaries: before the addon-length byte, inside the Vision addon payload, before the command byte, and inside an IPv4 address. Every malformed connection must fail before target dial, leave Chimera running, and a subsequent real Xray TLS/Vision request must still succeed through the same listener:

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  truncated_vless_request_over_tls_vision_does_not_dial_target \
  -- --ignored --exact --nocapture
```

Together these cases cover successful VLESS authentication, rejection of an unknown UUID, and authenticated truncation across addon, command, and address parsing boundaries for this TCP/TLS/Vision combination. They do not by themselves certify every TLS option, fallback selection, every malformed VLESS value, half-close semantics, or other Xray client versions.

### VLESS over mKCP: PASS with current Xray clients

On 2026-09-13 the ignored mKCP fixture was run with Xray as a SOCKS5 client front end and Chimera as a VLESS-over-mKCP server. The path was `SOCKS5 -> Xray VLESS client -> mKCP -> Chimera -> local TCP echo`. Each run verifies a small request plus 64 KiB and 256 KiB deterministic payload roundtrips and checks that both client and server processes remain alive afterward.

```sh
XRAY_BIN=/path/to/xray cargo test -p chimera_server_app \
  --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_through_chimera_vless_mkcp \
  -- --ignored --exact --nocapture
```

The fixture passed 3/3 runs with Xray 26.9.9 / `52a412d` / go1.27.1 linux/amd64, which was the newest published Xray build and marked pre-release at verification time. It also passed 1/1 with the latest non-pre-release GitHub release, Xray 26.3.27 / `d2758a0` / go1.26.1 linux/amd64.

A second ignored test places a deterministic UDP fault proxy between Xray and Chimera. In each direction it drops every 17th datagram and holds every 13th datagram until the next packet so the pair is delivered out of order. The test requires a 256 KiB TCP echo roundtrip and asserts that client-to-server and server-to-client loss and reordering were all actually exercised:

```sh
XRAY_BIN=/path/to/xray cargo test -p chimera_server_app \
  --test xray_client_proxy_e2e \
  xray_client_vless_mkcp_recovers_from_loss_and_reordering \
  -- --ignored --exact --nocapture
```

That recovery test passed 3/3 runs with Xray 26.9.9 / `52a412d` on 2026-09-13. It specifically exercises mKCP ACK/RTO retransmission and out-of-order receive behavior after successful UDP sends. Chimera's listener also mirrors Xray's `RetryableWriter` policy for local segment-write failures: one connection serializes each segment, makes at most five write attempts separated by 100 ms, and waits the final 100 ms before giving up, without stalling unrelated mKCP sessions. Focused injected-sender tests cover that local failure path; the real-client fault proxy still does not force kernel `send_to` failures. Arbitrary burst-loss distributions, every protocol/security combination, and masking modes remain outside this certification.

### Shadowsocks candidate release goal: PASS

The strongest currently refreshed release-goal evidence is **Shadowsocks inbound Xray compatibility**. The following tests all passed against Xray 26.2.6 / `12ee51e`:

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_through_chimera_shadowsocks \
  -- --ignored --exact --nocapture

cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_clients_can_use_multiple_legacy_shadowsocks_users \
  -- --ignored --exact --nocapture

cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_clients_can_use_shadowsocks_2022_eih_users \
  -- --ignored --exact --nocapture

cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_and_aes_udp_through_chimera_shadowsocks_2022 \
  -- --ignored --exact --nocapture
```

Coverage from those tests includes legacy AEAD methods, TCP and UDP relay, multiple legacy users with different methods on one inbound, Shadowsocks 2022 AES/ChaCha methods, and 2022 EIH multi-user TCP/UDP behavior. Dynamic UserManager semantics are additionally covered by focused runtime/gRPC tests, including `shadowsocks_user_mutations_match_xray_legacy_and_2022_semantics` and `handler_alter_shadowsocks_users_does_not_restart_listener`.

This evidence selects a candidate primary goal; it does **not** make the current multi-goal `master` history eligible for a stable tag by itself. The release-scope rules in `AGENTS.md` and the release-prep audit still apply.

### Hysteria2: fixed-reference TCP/UDP PASS; legacy fixture has a client-side 4 KiB limit

The initial release-prep run of the positive Hysteria2 test failed three times with the repository-local Xray 26.2.6 fixture when the test sent a 4096-byte UDP payload. Diagnosis showed that the first small UDP packet completed end to end, and payloads through 4000 bytes also completed. Payloads of 4095/4096 bytes were dropped before any Hysteria fragment reached Chimera.

The cause is in Xray 26.2.6 / `12ee51e`, not the Chimera server: that Xray revision allocates `MaxUDPSize` (4096 bytes) for the **complete** serialized Hysteria `UDPMessage`, including its protocol header. If payload plus header exceeds that buffer, `UDPWriter.sendMsg` treats the serialization failure as a silent drop before calling QUIC, so its `DatagramTooLargeError` fragmentation fallback cannot run. Xray commit `1d62941b` enlarged the writer buffer to the regular 8192-byte `buf.Size`; that commit is present before the first `v26.5.3` release and in the fixed `v26.7.28` reference.

The interoperability test now preserves both forms of evidence: clients at or after v26.5.3 must pass the original 4096-byte UDP case, while older clients use a 4000-byte large-payload case that stays within their own serialization buffer. The exact test is:

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_can_proxy_tcp_and_udp_through_chimera_hysteria2_with_xray_defaults \
  -- --ignored --exact
```

It passed 3/3 repeated runs with the bundled Xray 26.2.6 client and 3/3 repeated runs with `XRAY_BIN` pointing to a build from fixed reference `5ca6f4b7d4dc20a881d4330e498892697627ec0c`. The fixed-reference runs exercised the full 4096-byte payload and therefore verify Chimera's Hysteria fragmentation path against the selected Xray baseline.

The following Hysteria2 TCP/auth checks also passed in the same release-prep round:

```text
xray_hysteria2_empty_user_auth_can_proxy_tcp                         PASS
xray_hysteria2_uuid_auth_routes_by_embedded_vless_route             PASS
xray_client_rejects_invalid_hysteria2_auth_without_tunnel           PASS
```

Hysteria2 is therefore **not currently release-blocked by the previously observed 4 KiB timeout**. The repository-local Xray 26.2.6 limitation remains documented so future failures at that exact boundary are not misattributed to the server.

## Runtime coverage not re-certified in this release-prep round

| Area | Current status |
| --- | --- |
| VLESS + TCP + REALITY + Vision | Runtime and ignored real-client matrices exist; not re-run as release evidence in this round. |
| VLESS + XHTTP + none/TLS/REALITY | Ordinary XHTTP protocol/security matrices pass; the routing goal has real Xray 26.2.6/Linux allow/reject certification for XHTTP over TCP with `none` and TLS, plus Xray 26.9.9/Linux allow/reject and direct-IP audit certification for XHTTP/3 over TLS (`stream-one`, `packet-up`, and `stream-up`) and XHTTP + REALITY over TCP. |
| VLESS + gRPC | Inbound and real Xray-client tests exist; not re-run as release evidence in this round. |
| VLESS + HTTPUpgrade | Inbound and real Xray-client tests exist; not re-run as release evidence in this round. |
| Mixed inbound | Runtime/config support exists; no materialized example or refreshed real Xray-client release certification in this directory. |
| Chimera-only TUIC inbound | Runtime/config tests exist; xray-core does not provide a TUIC inbound baseline. |

## Not currently claimed as Xray-compatible here

| Area | Status |
| --- | --- |
| mKCP combinations beyond verified VLESS + none | Plain VLESS TCP streams over default mKCP settings are Xray-verified, including the deterministic bidirectional loss/reordering profile described above. Xray's five-attempt/100 ms local segment-write retry policy is runtime-implemented and unit-covered, but kernel `send_to` failure injection is not part of the real-client evidence. Other proxy/security combinations, broader loss/error profiles, and masking variants are not yet certified; mKCP + DokodemoDoor `followRedirect` still fails closed because UDP original-destination extraction is not implemented. |
| Legacy QUIC transport | Not materialized or release-verified in this matrix. |
| TUN | Not part of this inbound compatibility matrix. |
| WireGuard inbound | Linux system-TUN runtime slice is implemented behind the `wireguard` feature; decrypted packets use host IP routing after TUN injection, so forwarding/NAT and a peer-covering `address` prefix are deployment prerequisites. Xray-client interoperability, routing/statistics parity, IPv6-only devices, `noKernelTun`, and non-Linux support remain unverified or unsupported. |
| VLESS Reverse | **TCP RAW/TLS/XHTTP-TLS + UDP RAW roles: Partial / verified with fixed Xray.** Reverse account metadata (`reverse = 7`), command `0x04`, Xray Mux/control wire, Portal registry/routing, bounded client/server Mux workers, ACTIVE/DRAIN control, DokodemoDoor fixed-port routing, and ordinary Reverse UDP packet sessions are implemented. Fixed Xray-core `v26.9.9` interoperability passes in both directions for RAW/TLS TCP, RAW Reverse UDP, WebSocket (no early data), and XHTTP TLS/H2 `auto`, `stream-up`, and `packet-up`: Xray Bridge -> Chimera Portal and Chimera Bridge -> Xray Portal. In this TLS/H2 context, Xray `auto` selects packet-up. Explicit packet-up tests cover custom header sequence placement, header payload chunks, and `uplinkChunkSize`; header/cookie payload placement and GET are accepted only with explicit `mode: "packet-up"`, matching Xray config validation. Stream-up tests cover authority/`host` vs TLS SNI, path query, custom headers, session header placement, reconnect, and `xPaddingObfsMode` query-in-header/tokenish; they also verify transport-level trusted `X-Forwarded-For` does not replace the logical Reverse source passed to Chimera/PROXY protocol. Local regressions cover metadata/padding placements, session sequence/data headers/cookies, and custom config fields. Reverse sniffing is fixed-Xray-verified over RAW for HTTP Host, TLS SNI, routeOnly, domainsExcluded, and ipsExcluded. Bridge email/level routing context, UUID policy identity, traffic accounting, PROXY protocol, and AddUser/RemoveUser behavior have fixed-Xray interoperability or local regression coverage. `metadataOnly` and FakeDNS remain fail-closed; Reverse Mux source/local metadata and ordinary Mux XUDP GlobalID are mutually exclusive, so no private GlobalID reattachment wire is added. `stream-one`, xmux, `downloadSettings`, H1/H3, WebSocket early data, HTTPUpgrade/gRPC/REALITY and broader transport/security combinations remain pending or unverified. See [`VLESS_REVERSE_DESIGN.md`](../../VLESS_REVERSE_DESIGN.md). |

## Notes

- Materialized examples emphasize inbound compatibility. Runtime outbound support also includes SOCKS, VLESS, Trojan, Freedom and Blackhole paths used by routing and observatory tests.
- Trojan outbound supports raw TCP, TLS, WebSocket/WSS, HTTPUpgrade/TLS, REALITY, and gRPC Tun/TunMulti over raw TCP, TLS, or REALITY. These outbound combinations are not automatically Xray-verified merely because an inbound example validates.
- Trojan UDP outbound is wired into fixed-target, targeted, ordinary XUDP session, SOCKS shared/UDP_ASSOCIATE, Shadowsocks UDP, and Dokodemo UDP routing paths. GlobalID XUDP + Trojan remains intentionally unsupported because the proxy tunnel does not yet preserve detach/reattach semantics across inbound reconnects.
- VLESS examples explicitly set `settings.decryption: "none"` to match Xray semantics and Chimera validation.
- Hysteria uses the Xray protocol name `hysteria`; Chimera maps it internally to the Hysteria2 path.
