# Xray-compatible examples

This directory is the authoritative first-stage example matrix for Chimera Server configs that intentionally use xray-core shaped JSON/JSON5 fields: `inbounds`, `outbounds`, `settings`, and `streamSettings`.

Baseline reference: local `ref/xray-core` at `acb06e83`.

These examples are parse/build examples. TLS and QUIC examples use placeholder certificate paths so they can validate configuration shape without requiring the server to start successfully on a live machine.

## Materialized examples in this directory

| Example | Inbound | Transport | Security | Status |
| --- | --- | --- | --- | --- |
| `socks-tcp-noauth.json5` | socks | tcp | none | supported parse/build |
| `socks-tcp-password.json5` | socks | tcp | none | supported parse/build |
| `dokodemo-door-tcp.json5` | dokodemo-door | tcp | none | supported parse/build |
| `vless-tcp-none.json5` | vless | tcp | none | supported parse/build |
| `vless-ws-none.json5` | vless | ws | none | supported parse/build |
| `vless-ws-tls.json5` | vless | ws | tls | supported parse/build |
| `vless-tcp-tls-vision.json5` | vless | tcp | tls + vision | supported parse/build |
| `vless-xhttp-none.json5` | vless | xhttp | none | experimental parse/build |
| `vless-xhttp-tls.json5` | vless | xhttp | tls | experimental parse/build |
| `vmess-tcp-none.json5` | vmess | tcp | none | partial parse/build |
| `vmess-ws-none.json5` | vmess | ws | none | partial parse/build |
| `vmess-ws-tls.json5` | vmess | ws | tls | partial parse/build |
| `trojan-tcp-none.json5` | trojan | tcp | none | partial parse/build |
| `trojan-tcp-tls.json5` | trojan | tcp | tls | partial parse/build |
| `trojan-ws-tls.json5` | trojan | ws | tls | partial parse/build |
| `hysteria-quic-tls.json5` | hysteria | quic | tls | experimental parse/build |

## Compatibility covered by unit tests but not yet materialized here

| Combination | Coverage |
| --- | --- |
| vless + tcp + reality + vision | `realitySettings.target` alias and nested Reality(Vless) config are covered by unit tests. |
| vless + xhttp + reality | Reality(Xhttp(Vless)) nesting is covered by unit tests. |
| Chimera-only TUIC inbound | TUIC settings are covered by unit tests; xray-core does not support TUIC inbound. |

## Planned compatibility, not part of this stage

| Area | Planned status |
| --- | --- |
| HTTP inbound | Not implemented in this stage |
| Shadowsocks inbound | Not implemented in this stage |
| Mixed inbound | Not implemented in this stage |
| gRPC transport | Inbound is supported; Trojan outbound supports Xray Tun and TunMulti over raw TCP, TLS, or REALITY, including gRPC keepalive/window tuning. |
| HTTPUpgrade transport | Inbound is supported; Trojan outbound supports raw/TLS HTTPUpgrade, including Xray `ed` behavior. |
| mKCP transport | Not implemented in this stage |
| Legacy QUIC transport | Not implemented in this stage |
| TUN | Not implemented in this stage |
| WireGuard | Not implemented in this stage |

## Notes

- The materialized examples still emphasize inbound compatibility, but runtime outbound support now also includes SOCKS, VLESS, and Trojan paths used by routing and observatory tests.
- Trojan outbound supports raw TCP, TLS, WebSocket/WSS (including Xray `ed`), HTTPUpgrade/TLS (including Xray `ed`), REALITY, and gRPC Tun/TunMulti over raw TCP, TLS, or REALITY. gRPC keepalive and initial-window settings are mapped to the underlying HTTP/2 client with Xray/grpc-go-compatible defaults.
- Trojan UDP outbound uses the same transport stack and is wired into fixed-target, targeted, ordinary XUDP session, SOCKS shared/UDP_ASSOCIATE, Shadowsocks UDP, and Dokodemo UDP routing paths. GlobalID XUDP + Trojan remains intentionally unsupported until the proxy tunnel can preserve detach/reattach semantics across inbound reconnects.
- REALITY remains broader on the inbound/server side, but Trojan outbound can consume Xray client-side `publicKey`, `serverName`, `shortId`, and related REALITY settings for raw TCP and gRPC transports.
- VLESS examples explicitly set `settings.decryption: "none"` to match xray semantics and Chimera validation.
- Hysteria uses xray protocol name `hysteria`; Chimera maps it internally to the existing Hysteria2 path.
