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
| gRPC transport | Not implemented in this stage |
| HTTPUpgrade transport | Not implemented in this stage |
| mKCP transport | Not implemented in this stage |
| Legacy QUIC transport | Not implemented in this stage |
| TUN | Not implemented in this stage |
| WireGuard | Not implemented in this stage |

## Notes

- Examples use `freedom` and `blackhole` outbounds because Chimera Server is currently inbound-first.
- REALITY support is inbound/server-side only. Client-side fields such as `publicKey`, `fingerprint`, and `spiderX` are intentionally rejected.
- VLESS examples explicitly set `settings.decryption: "none"` to match xray semantics and Chimera validation.
- Hysteria uses xray protocol name `hysteria`; Chimera maps it internally to the existing Hysteria2 path.
