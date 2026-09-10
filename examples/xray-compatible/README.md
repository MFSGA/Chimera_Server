# Xray-compatible examples

This directory is the authoritative materialized config matrix for Chimera Server examples that intentionally use xray-core-shaped JSON/JSON5 fields such as `inbounds`, `outbounds`, `settings`, and `streamSettings`.

Fixed implementation reference: local `ref/xray-core` at `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

The real-client checks recorded below were run on 2026-09-10 with two Xray client builds:

```text
repository fixture: Xray 26.2.6 / 12ee51e / go1.25.7 linux/amd64
fixed reference:    Xray 26.7.28 source at 5ca6f4b7d4dc20a881d4330e498892697627ec0c, built with go1.26.5 linux/amd64
```

The older repository fixture remains useful for compatibility coverage, but its Hysteria UDP writer has a client-side 4096-byte serialization-buffer limit described in the Hysteria evidence section below. Fixed-reference release claims use the second build where that distinction matters.

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
| `vless-tcp-none.json5` | vless | tcp | none | config-validated |
| `vless-ws-none.json5` | vless | websocket | none | config-validated |
| `vless-ws-tls.json5` | vless | websocket | tls | config-validated |
| `vless-tcp-tls-vision.json5` | vless | tcp | tls + vision | config-validated |
| `vless-xhttp-none.json5` | vless | xhttp | none | config-validated; runtime-covered |
| `vless-xhttp-tls.json5` | vless | xhttp | tls | config-validated; runtime-covered |
| `vmess-tcp-none.json5` | vmess | tcp | none | config-validated; runtime-covered |
| `vmess-ws-none.json5` | vmess | websocket | none | config-validated; runtime-covered |
| `vmess-ws-tls.json5` | vmess | websocket | tls | config-validated; runtime-covered |
| `trojan-tcp-none.json5` | trojan | tcp | none | config-validated; runtime-covered |
| `trojan-tcp-tls.json5` | trojan | tcp | tls | config-validated; runtime-covered |
| `trojan-ws-tls.json5` | trojan | websocket | tls | config-validated; runtime-covered |
| `hysteria-quic-tls.json5` | hysteria | quic | tls | config-validated; Xray-verified TCP/UDP with fixed reference; legacy 26.2.6 client has a documented 4 KiB serialization limit |
| `shadowsocks-tcp-udp.json5` | shadowsocks | tcp + udp | none | config-validated; Xray-verified |
| `shadowsocks-2022-eih-tcp-udp.json5` | shadowsocks 2022 EIH | tcp + udp | none | config-validated; Xray-verified |

The two Shadowsocks examples intentionally omit `streamSettings`: Chimera's combined Shadowsocks `network: "tcp,udp"` listener rejects `streamSettings` because the same inbound also owns a UDP listener.

## Real Xray-client verification recorded on 2026-09-10

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
| VLESS + XHTTP + none/TLS/REALITY | Active XHTTP protocol/security matrices pass under ordinary tests; no goal-specific real Xray-client certification was refreshed in this round. |
| VLESS + gRPC | Inbound and real Xray-client tests exist; not re-run as release evidence in this round. |
| VLESS + HTTPUpgrade | Inbound and real Xray-client tests exist; not re-run as release evidence in this round. |
| HTTP inbound | Runtime/config support exists; no materialized example or refreshed real Xray-client release certification in this directory. |
| Mixed inbound | Runtime/config support exists; no materialized example or refreshed real Xray-client release certification in this directory. |
| Chimera-only TUIC inbound | Runtime/config tests exist; xray-core does not provide a TUIC inbound baseline. |

## Not currently claimed as Xray-compatible here

| Area | Status |
| --- | --- |
| mKCP transport | Not materialized or release-verified in this matrix. |
| Legacy QUIC transport | Not materialized or release-verified in this matrix. |
| TUN | Not part of this inbound compatibility matrix. |
| WireGuard | Not part of this inbound compatibility matrix. |

## Notes

- Materialized examples emphasize inbound compatibility. Runtime outbound support also includes SOCKS, VLESS, Trojan, Freedom and Blackhole paths used by routing and observatory tests.
- Trojan outbound supports raw TCP, TLS, WebSocket/WSS, HTTPUpgrade/TLS, REALITY, and gRPC Tun/TunMulti over raw TCP, TLS, or REALITY. These outbound combinations are not automatically Xray-verified merely because an inbound example validates.
- Trojan UDP outbound is wired into fixed-target, targeted, ordinary XUDP session, SOCKS shared/UDP_ASSOCIATE, Shadowsocks UDP, and Dokodemo UDP routing paths. GlobalID XUDP + Trojan remains intentionally unsupported because the proxy tunnel does not yet preserve detach/reattach semantics across inbound reconnects.
- VLESS examples explicitly set `settings.decryption: "none"` to match Xray semantics and Chimera validation.
- Hysteria uses the Xray protocol name `hysteria`; Chimera maps it internally to the Hysteria2 path.
