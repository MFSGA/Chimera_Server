# Config Notes

This folder defines literal config structs and the conversion into runtime `ServerConfig`.

## TUIC v5 inbound (feature: tuic)

- `protocol`: `"tuic"` (alias `"tuicV5"`)
- `settings`:
  - `uuid`: string (required)
  - `password`: string (required)
  - `zeroRttHandshake`: bool (optional, default `false`)
- `streamSettings.tlsSettings` is required and provides the certificate/key used for QUIC.

## Xray DNS hosts subset

The top-level `dns.hosts` object accepts Xray custom domain-rule keys (`full:`, `domain:`, `keyword:`, `regexp:`, and `dotless:`; an unprefixed key means `full:`) mapped to one IP string, an array of IP strings, a proxied domain string, or a response-code string such as `"#3"`. A response-code mapping returns the corresponding DNS error immediately (`"#0"` is an empty response), without falling through to an upstream nameserver. A proxied domain is recursively resolved through the same hosts table with a bounded depth; if the final alias is not statically mapped, the shared resolver continues with that final alias. Literal domain patterns are normalized case-insensitively, with a trailing dot removed and IDN converted to ASCII, before the mapping is used by the shared runtime resolver. Matching IP entries are combined, and an unmatched hostname falls through to the system resolver.

```json
{
  "dns": {
    "hosts": {
      "example.com": "192.0.2.10",
      "api.example.com.": ["192.0.2.11", "2001:db8::11"],
      "alias.example": "mapped.example"
    }
  }
}
```

Top-level `dns.disableCache: true` is supported and bypasses the shared DNS result cache. The per-nameserver `disableCache` override is still rejected explicitly until per-server cache ownership is implemented.

Plain `dns.servers` IP endpoints (a single string or an array, with port 53 as the default) use the shared direct UDP resolver. A string endpoint using `tcp://IP[:port]` uses direct DNS-over-TCP with Xray's two-byte length framing; advanced object entries remain UDP-only in this slice. Basic Xray nameserver objects are also accepted with `address`, `port`, `clientIp`, `domains`, an optional per-server `queryStrategy`, `skipFallback`/`finalQuery`, `timeoutMs` and `expectedIPs`/`expectIPs`/`unexpectedIPs`; an omitted object port and Xray's `port: 0` both use 53. Top-level `dns.clientIp` applies to plain UDP/TCP nameservers, while an object's `clientIp` overrides it for that nameserver. Each such query carries Xray-compatible EDNS Client Subnet data with /24 for IPv4 or /96 for IPv6; invalid addresses are rejected. `domains` uses Xray's default substring matching and supports `domain:`, `full:`, `keyword:`, `regexp:` and `dotless:` forms; matching nameservers are tried before the remaining servers, which retain the normal fallback order. Returned addresses are filtered by the configured IP rules, and an empty filtered result moves to the next nameserver. `dns.queryStrategy` accepts Xray's `UseIP`, `UseIPv4`, `UseIPv6` and `UseSystem` forms (including Xray's separator/case aliases) and limits the A/AAAA family accordingly, unless a server object overrides it. `dns.enableParallelQuery: true` starts selected nameservers concurrently; equivalent adjacent nameserver policies form a group, and a lower-priority group's result is not accepted until all higher-priority groups fail. `timeoutMs` controls the total wait for the current nameserver lookup; omitted or explicit `0` uses Xray's 4000ms default. `dns.disableFallback` disables ordinary fallback, while `dns.disableFallbackIfMatch` disables it only after a domain nameserver matched. Other fallback controls, URL schemes, remote dispatcher routing and DoH/DoT settings are recognized concepts but are not implemented in this slice; configuration validation rejects them explicitly.
