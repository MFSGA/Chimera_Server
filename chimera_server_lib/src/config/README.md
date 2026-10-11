# Config Notes

This folder defines literal config structs and the conversion into runtime `ServerConfig`.

## TUIC v5 inbound (feature: tuic)

- `protocol`: `"tuic"` (alias `"tuicV5"`)
- `settings`:
  - `uuid`: string (required)
  - `password`: string (required)
  - `zeroRttHandshake`: bool (optional, default `false`)
- `streamSettings.tlsSettings` is required and provides the certificate/key used for QUIC.

## VLESS Reverse over REALITY

The app feature `vless-reverse-reality` enables VLESS Reverse plus REALITY for
both Portal and Bridge roles. Fixed Xray 26.9.9 interoperability verifies
TCP/REALITY in both directions: Xray Bridge → Chimera Portal and Chimera Bridge
→ Xray Portal. Wrong `shortId` is rejected without a usable worker or target
traffic in both directions. The outbound client sends X25519MLKEM768 with an
X25519 fallback share and handles either selected key exchange; the exact Xray
baseline requires the hybrid share during REALITY admission. Other Bridge combinations, including
XHTTP/3, remain separately gated by their own interoperability evidence.

## VLESS outbound over TCP/TLS, TCP/REALITY, WebSocket/TLS, and XHTTP/TLS

Ordinary static VLESS outbounds accept `network: tcp` (or `raw`) with
`security: reality` when the app is built with `minimal-vless-reality` (or
another feature set enabling both `vless` and `reality`). For the optional
Linux site gateway, combine it with `tun-gateway`, for example:
`--no-default-features --features tun-gateway,minimal-vless-reality`.
The outbound uses `realitySettings.serverName`, a URL-safe Base64 32-byte
`publicKey`, and hexadecimal `shortId`; omitted `fingerprint` defaults to
`chrome`, and omitted `spiderX` defaults to `/`. Only the `chrome` fingerprint
and `/` spider path are currently supported. Nonempty `tcpSettings` or
`sockopt` are rejected instead of ignored. A build without `reality` returns an
explicit capability error.

The fixed-Xray site-gateway namespace test verifies this Office TCP/REALITY
outbound to an Xray 26.9.9 VLESS Hub/Reverse Portal for TCP, UDP and 4 KiB UDP
through the TUN, Edge prefix map/ACL and LAN fixture. Wrong short IDs and a
wrong public key fail before packets reach explicitly allowed LAN targets.
This is evidence for Chimera as the ordinary VLESS client on this topology; it
does not claim Xray TUN configuration support or complete REALITY option
compatibility.

Ordinary static VLESS outbounds accept `streamSettings` with `network: tcp` (or
`raw`) and `security: tls` with the `vless` and `tls` features. They also accept
`network: ws` (or `websocket`) and `security: tls` when the `ws` feature is
enabled in addition to `vless` and `tls`. The app exposes this capability as
`ws = ["chimera_server_lib/ws"]`; for example, build with
`--features tun-gateway,vless-reverse-tls,ws` to use a WebSocket/TLS Office
outbound alongside the optional TUN gateway. WebSocket settings support the
configured host, path and headers.

Ordinary static VLESS outbounds also accept `network: xhttp` (or `splithttp`)
with `security: tls` when `vless` and `tls` are compiled. The existing XHTTP
sender is available without a separate Cargo feature and currently requires
HTTP/2 (`alpn: ["h2"]`, or the default). XHTTP supports the configured host,
path, headers, and `auto`, `packet-up`, or `stream-up` mode, subject to the
sender's existing validation. The fixed-Xray TUN test covers all three modes
with TCP, UDP, and 4 KiB UDP.
Missing `tls` produces an explicit configuration error rather than dropping
transport security.

The TLS client uses `serverName`, `alpn`,
`disableSystemRoot`, and `certificates` with `usage: verify` for explicit trust
roots. The app's `minimal-vless-tls` feature enables VLESS TCP/TLS; its
`vless-reverse-tls` feature does as well. Add `ws` to either app feature set to
enable VLESS WebSocket/TLS. Missing `tls` or `ws` capabilities produce
explicit configuration errors. The fixed Xray 26.9.9 namespace path verifies
Office IPv4 RAW/TLS, TCP/REALITY, IPv4 XHTTP/TLS `packet-up`/`stream-up`/`auto`, and IPv6 WebSocket/TLS to a Hub;
each combination carries TCP, UDP, and a 4 KiB UDP datagram through the TUN,
Reverse Portal, Edge prefix map/ACL, and LAN fixture. Wrong SNI and unknown UUID
probes over XHTTP/TLS `packet-up`, `stream-up`, and `auto`, plus WebSocket/TLS,
do not reach explicitly allowed Edge LAN targets. Xray 26.9.9 logs WebSocket as deprecated and recommends
XHTTP. Static VLESS XHTTP supports TLS ALPN `h2` and `h3`; H3 uses a UDP/QUIC
socket and is covered with fixed Xray 26.9.9 for `packet-up`, `stream-up`, and
`auto` over TCP, UDP, and 4 KiB UDP through the Office TUN → Hub → Reverse
Portal → Edge mapping path. H3 wrong-SNI and unknown-UUID denial is verified
for `packet-up` and `stream-up`. H3 custom header/cookie placements and non-default QUIC
tuning remain unverified. VLESS Reverse Bridge supports XHTTP with TLS ALPN `h2` or `h3`;
fixed Xray 26.9.9 loopback tests verify H2 and H3 `packet-up`, `stream-up`, and `auto`
in both Bridge/Portal directions, with Bridge-to-Portal restart recovery. Reverse H3
custom sequence/data placement and non-default QUIC tuning remain unverified. Other
ordinary VLESS transport or security combinations remain explicitly unsupported.
Nonempty `tcpSettings` and `sockopt` options remain
unsupported; XHTTP also rejects `finalmask` instead of silently ignoring it.
`allowInsecure` is rejected, in line with the current Xray baseline; use a
trusted certificate or explicit CA instead. Outbound client certificates are
not implemented.

## VLESS Reverse site-to-site Edge policy (feature: `vless-reverse`)

Complete Hub, Edge, and Office Gateway configuration templates are available
under [`examples/site-to-site/`](../../../examples/site-to-site/). They use
TLS certificate and server-name verification, identity-scoped Hub routing, protected-prefix
default deny, Edge prefix maps and mapped-destination allow rules. The Office
example also shows the optional source/ingress-scoped Linux route policy; it
requires deployment-specific upstream routes and interfaces.

The simplified VLESS outbound `settings.reverse` accepts an optional Chimera-only
`siteToSite` policy. It runs on the Edge Bridge after the Hub selects the Reverse
destination, so the Hub can route on the original Overlay address while the Edge
dials the mapped LAN address. If omitted, the existing VLESS Reverse behavior is
unchanged. If present, unmatched targets are denied.

The same object accepts optional `maxActiveSessions`, a positive integer that
caps concurrent logical TCP and UDP sessions across all physical Bridge workers
owned by that outbound. When the cap is full, the Bridge sends an error END for
the new logical session without dispatching it to a target; existing sessions
and the physical worker remain available. The option is a Chimera resource
policy, not an Xray setting. Omitting it leaves the Bridge unlimited, preserving
the Xray-compatible default.

```json
{
  "protocol": "vless",
  "tag": "home-bridge",
  "settings": {
    "address": "hub.example.net",
    "port": 443,
    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
    "encryption": "none",
    "reverse": {
      "tag": "home-edge",
      "maxActiveSessions": 512,
      "siteToSite": {
        "prefixMaps": [
          { "from": "10.200.1.0/24", "to": "192.168.50.0/24" }
        ],
        "allow": [
          {
            "network": ["tcp", "udp"],
            "ip": ["192.168.50.0/24"],
            "ports": ["22", "80-443"]
          }
        ]
      }
    }
  }
}
```

`prefixMaps` requires non-overlapping source and destination CIDRs with the same
address family and prefix length. Each `allow` rule must name `tcp` and/or `udp`,
one or more destination IP CIDRs and one or more nonzero ports or ascending port
ranges. The ACL is applied to the mapped LAN target; hostname targets are denied.
UDP responses are returned with the source IP mapped back into the Overlay prefix. Chimera Hub/Edge peers also support directional TCP half-close with Mux END option bit `0x04`, so a TCP FIN in one direction does not discard a response in the other direction. Standard Xray END without that bit still closes the whole session; Xray peers do not implement the Chimera half-close extension.
When `siteToSite` is present, active `reverse.sniffing.destOverride` is rejected
unless `routeOnly` is true. A non-route-only HTTP/TLS override can replace the
mapped IP target after this ACL has run; route-only sniffing keeps the checked
target and may still contribute the sniffed domain to route selection.
Separate Edge Bridge policies may map different Overlay prefixes to the same LAN CIDR. Hub routing must select the Reverse tag using the original Overlay destination before the Edge applies its local map. An in-memory two-site TCP/UDP test covers that flow and response address restoration; `bash scripts/test_tun_gateway_duplicate_lan_netns.sh` also verifies the running Hub and two Bridge processes in isolated network namespaces, mapping distinct IPv4/IPv6 Overlay prefixes to the same IPv4 `/24` and IPv6 `/64` LAN prefixes and returning site-specific dual-stack TCP/UDP responses. That smoke keeps IPv4/IPv6 LAN listeners on TCP 39643 and UDP 39644 while each Chimera Edge ACL allows only 39641–39642; dual-stack denied probes reach neither listener even though the underlying Freedom rules permit those ports. Configuration sizes are bounded to 128 maps, 256 allow rules, and 128 IP prefixes
or port ranges per rule; unknown fields fail validation. This policy is not Xray's
Freedom `finalRules` or TUN `prefixRedirect` implementation and does not claim
Xray TUN-inbound compatibility. Chimera's separately feature-gated Linux TUN Gateway is documented below; optional source-scoped routes manage only the Gateway host namespace, while upstream LAN routing remains deployment-managed. Fixed Xray Edge passthrough without prefix mapping is verified separately.

## Hub-side Overlay ingress authorization (Xray routing)

The Hub should authorize Office traffic before dispatching it to a Reverse
Bridge. This is a route excerpt: the `hub-vless-in` VLESS inbound must define
those client email values, and the active Bridge account must register the
`site-edge` tag with `reverse.tag`. Use the authenticated VLESS client email
together with the original Overlay destination, network and port in ordered
`routing.rules`; send the remaining protected Overlay space to a `blackhole`
outbound. Keep the allow
rule before the protected-prefix deny rule, and keep both ahead of broader
fallback routes. This uses the existing Xray-shaped router and does not add a
second policy engine. When one site advertises multiple Overlay CIDRs, include
every protected prefix in the relevant allow rules and in the following deny
rule; routing one destination range does not protect a sibling range.

```json5
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "overlay-default-deny", "protocol": "blackhole" }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["hub-vless-in"],
        "user": ["office-allowed@example.test"],
        "network": ["tcp", "udp"],
        "ip": ["10.200.1.0/24", "10.200.2.0/24"],
        "port": "22,53,443",
        "outboundTag": "site-edge"
      },
      {
        "type": "field",
        "inboundTag": ["hub-vless-in"],
        "ip": ["10.200.1.0/24", "10.200.2.0/24"],
        "outboundTag": "overlay-default-deny"
      }
    ]
  }
}
```

The Hub sees the authenticated user and original Overlay target; the Edge policy
sees the mapped LAN target. Keep both checks: the Hub rule prevents an
unauthorized identity or port from reaching any Bridge, while the Edge
`siteToSite` allow list enforces the final mapped destination. The fixed Xray
26.9.9 RAW/TCP test (SOCKS TCP) and VLESS UDP-over-TCP test (Xray SOCKS UDP)
verify an authorized identity across two IPv4 `/24` Overlay prefixes, including
two target addresses within one prefix and a second prefix; the same SOCKS UDP
association reaches all three targets. A wrong identity and unlisted port are
denied for TCP and UDP before Edge dispatch across those targets. The Edge
deliberately allows the tested ports so the test isolates Hub routing. The same
test now also covers one IPv6 `2001:db8:30::/64` Overlay CIDR with an exact IPv6
loopback Edge target; `bash scripts/test_hub_overlay_ipv6_xray_netns.sh` runs it
in a disposable namespace with IPv6 loopback enabled and requires that subcase
to run. The fixed Xray 26.9.9 client exercises RAW/TCP, TLS/TCP, WebSocket/TLS, XHTTP/TLS
H2 (`packet-up`, `stream-up`, and `auto`), XHTTP/TLS H3 (`packet-up`, `stream-up`, and `auto`), and REALITY/TCP Hub inbounds for TCP and UDP, including
wrong-user and unlisted-port denial. Unregistered H3 UUIDs in `packet-up`, `stream-up`, and `auto` also fail to reach Edge over TCP and UDP. TLS clients pin the generated test certificate SHA-256. The same live topology
then exercises Hub `RoutingService.AddRule`,
`RemoveRule` and `ListRule`: CIDR rules use the nested Xray `IPRule.custom` /
`CIDRRule` wire shape from the pinned reference, replacing the policy revokes a
protected IPv4 `/24`, adding an IPv6 `/64` permits its TCP/UDP targets, and
removing that allow rule denies new sessions before Edge dispatch over
RAW, TLS, WebSocket/TLS, all three XHTTP/TLS H2 modes and all three H3 modes, and REALITY/TCP client links. Runtime
custom GeoIP file paths return an explicit unsupported-field error; the
default GeoIP code and CIDR forms are covered by routing tests. Other IPv6 prefixes, nondefault XHTTP/QUIC settings, security combinations beyond the tested
RAW/TLS TCP, WebSocket/TLS and REALITY/TCP cases, and broader management mutations remain outside this test. A TCP connection routed before `RemoveRule` continues
to echo, while a new TCP connection is denied. For UDP, an already attached
association continues to its previously selected target after removal; a fresh
association and a different target on the existing association are denied. The
pinned Xray 26.9.9 server/client comparison also confirms active-session
continuity and fresh-association denial over RAW VLESS with a live
`RoutingService.RemoveRule`. The
real Linux TUN namespace smoke also sends ordinary
Office-LAN IPv4/IPv6 TCP/UDP traffic through the Office Gateway's VLESS identity
and Hub route policy. Its `--hub-policy-only` mode verifies allowed TCP/UDP echo
for both address families plus TCP/UDP port 39647 omitted from the Hub allowlist;
the Edge `siteToSite` and Freedom policies explicitly allow the mapped IPv4 and
IPv6 targets, and none of the denied markers reaches the Edge fixture. The same mode also verifies a second registered VLESS identity can reach its IPv4 TCP/UDP allow on port 39646 but is denied Edge-allowed port 39644, while a third registered but unauthorized identity cannot reach Edge-allowed IPv4 TCP/UDP targets on port 39645.

On the TUN/Dokodemo UDP path, the selected outbound stays attached to the
worker for that client/target flow. Updating routing rules affects new source
or destination tuples immediately; an existing tuple keeps its worker until
the UDP idle timeout, then its route pin is removed and a later packet uses
the current rules. A paused-time relay test covers live route replacement,
new-tuple denial, idle cleanup and re-selection. This is local runtime
coverage; it does not claim Xray TUN interoperability.

The focused namespace mode `bash scripts/test_tun_gateway_netns.sh
--hub-policy-only` also exposes Hub `RoutingService` on the test-only listener
and sends the pinned Xray `AddRule` wire format while an ordinary Office-LAN
TCP stream and UDP socket are active. The established TCP and UDP flows continue
after the protected Overlay `/24` is denied; a new TCP connection, a different
target on that socket and the same UDP target from a fresh socket are dropped
before Edge. This is Linux namespace evidence for a real TUN-to-management
update path; it does not cover physical LANs or other rule mutation shapes.

The full `bash scripts/test_tun_gateway_netns.sh` smoke passes with the full
server feature set. Its `TUN_GATEWAY_MTU=1280` run checked the live TUN and
Office routes at MTU 1280, session limits, three UDP idle-expiry cycles,
dual-stack fragment pressure, TCP and UDP iperf3, Hub recovery, three Edge-only
restarts, and TUN teardown. TCP iperf3 sent 59,899,904 bytes and received
58,064,896 bytes (154.1 Mbit/s receiver rate); UDP iperf3 sent and received
375,600 bytes with 0% loss. A 4 MiB TCP echo was compared byte-for-byte at both
ends and completed after client write-half-close; the verified payload was
4,194,328 bytes with SHA-256
`4b7d55b3179211492095a48e98d3e3175c48a0f4ba9e27b934cd15a10f7d3f99`. The
current smoke admits eight TCP flows, rejects the ninth, then verifies the
permit recovers. It also runs TCP iperf3 through the same TUN/Hub/Reverse/Edge
path and requires a complete JSON control result with nonzero sent and received
bytes. That check exposed a Bridge lifecycle race: a stale KEEP or directional
END could fail delivery to an already-finished logical session and terminate the
shared Mux reader. The Bridge now closes only that logical session and keeps the
physical worker alive; a deterministic regression sends both stale frame kinds
before a valid session and verifies the valid session still transfers data.
Five independent `--tcp-iperf-diagnostic` namespace runs passed with iperf3 3.20
after the fix. The throughput figures are functional probe output, not a
performance benchmark. The harness waits 62 seconds before its final restart
probe so the configured 8-session UDP cap can release earlier flows through its
normal 60-second idle timeout. This remains controlled namespace evidence
rather than a physical-LAN or production-load claim.

The full Reverse site path also passed at MTU 9000 with
`TUN_GATEWAY_MTU=9000 bash scripts/test_tun_gateway_netns.sh`. The Office host's
static route and both Office veth endpoints used MTU 9000 so the disposable LAN
link matched its jumbo route; the run covered dual-stack forwarding, 4 KiB LAN
UDP, TCP/UDP iperf3, fragment pressure, idle-expiry recovery, Hub/Edge restarts
and TUN cleanup. TCP iperf3 sent 69,861,376 bytes and received 67,895,296 bytes
(180.9 Mbit/s receiver rate). The earlier upper-bound managed-route smoke also
passed. These namespace runs verify a configured jumbo path, not PMTU behavior
or a physical LAN whose links may remain at MTU 1500.

### Probing a site through the Office VLESS outbound

The existing Xray Observatory can check a real service inside a remote site
through the selected Office-to-Hub outbound; this tests the VLESS/Hub/Reverse/
Edge route rather than ICMP reachability. For example:

```yaml
observatory:
  subjectSelector: [office-to-hub]
  probeURL: http://10.200.1.10:8080/health
  probeInterval: 10s
```

The Hub must route the probe address to the intended Reverse tag, and the Edge
prefix map and ACL must allow the probe's TCP port. `ObservatoryService`'s
`GetOutboundStatus` returns the selected outbound's alive/delay observation
when that management service is enabled. This is endpoint-level HTTP(S) status,
not a site registry or a count of active Reverse workers; select an endpoint
whose availability represents the service you want to monitor. As in Xray, an
HTTP response with valid headers counts as reachable regardless of status code.
The isolated TUN namespace smoke verifies the probe over VLESS/Reverse changes
from alive to unavailable when the remote endpoint stops, then back to alive
after it restarts. A separate app integration test uses a local HTTP fixture
and reads the status transitions from `ObservatoryService.GetOutboundStatus`;
the two tests cover the site path and RPC projection independently. Both Xray's
`probeURL` spelling and the serialized `probeUrl` spelling are accepted.

## Freedom `finalRules` subset

Freedom outbound settings support ordered `finalRules` matching `action`,
`network`, `port`, and literal IPv4/IPv6 `ip` CIDRs. The first matching rule
decides whether the target is allowed. `network` accepts a string, a comma-
separated string, or an array; when omitted it follows Xray's TCP default.
`port` accepts a number or a comma-separated string of ports/ranges. `ip`
accepts a string or array of literal IP/CIDR strings and positive Xray GeoIP
references (`geoip:CODE`, `ext:geoip.dat:CODE`, or
`ext-ip:geoip.dat:CODE`). GeoIP references are expanded from the Xray
`geoip.dat` asset selected by `xray.location.asset` /
`XRAY_LOCATION_ASSET` (or the executable directory and standard Xray asset
directories). Missing files, unknown codes, and empty code entries fail
configuration compilation so a requested rule cannot be silently dropped.
For a hostname target, all resolved addresses are checked before Freedom dials;
any blocked candidate rejects the request. These checks use the same rule matcher from the shared
TCP/UDP outbound selector and Dokodemo's dedicated UDP route, including new
and per-packet sessions.

Xray's default Freedom rule blocks every target for a `vless-reverse` inbound,
and blocks its private-IP set for VLESS/VMess/Trojan/Hysteria/WireGuard and
Shadowsocks inbounds. An explicit matching `allow` rule overrides that default.
The Edge `reverse.siteToSite` map/ACL remains a separate, narrower Chimera
extension: it maps Overlay destinations and checks the mapped LAN endpoint.

This is a partial compatibility slice. IP reverse-match,
`blockDelay`, non-default `domainStrategy`/`targetStrategy`, redirect/destination
override, nonzero `userLevel`, fragment/noise, and Freedom socket/dialer settings
fail explicitly until implemented. A denied connection is closed or its UDP
packet dropped immediately; Xray's configurable/default delayed blackhole is
not reproduced yet.

## API tunnel inbound

The API-routed `protocol: "tunnel"` inbound accepts a TCP `listen` plus `port`
and starts the management gRPC server on that address. A Linux abstract Unix
name (`listen: "@name"` without `port`) remains supported. Xray-shaped tunnel
settings may include `rewriteAddress`; Chimera validates the address but does
not use it as a proxy destination because the inbound is reserved for the API
control route and gRPC binds directly. Other tunnel settings, stream settings,
and sniffing remain rejected.

## Xray metrics HTTP endpoint

The top-level `metrics.listen` setting starts an HTTP listener that serves
`GET /debug/vars` with the Xray-shaped `memstats`, `stats`, and `observatory`
objects. Traffic counters use Chimera's current inbound/outbound/user totals;
observatory entries expose the existing outbound observation state. This is
the endpoint 3x-ui polls for its Xray metrics history.

Rust has no Go runtime heap or garbage collector. On Linux, `memstats.HeapAlloc`
and `memstats.Sys` therefore report process resident and virtual memory from
`/proc/self/status` as useful memory-history approximations; they are not
equivalent to Go allocator counters. `HeapObjects`, `NumGC`, and `PauseNs` are
zero, and a `chimera` object identifies this distinction. Other operating
systems currently report zero for process memory until a native source is
implemented and verified.

When `metrics.tag` is also set, Chimera logs that the Xray tagged outbound
access path is unavailable while still serving the configured HTTP listener.
A tag-only metrics config is rejected because it cannot start the 3x-ui HTTP
endpoint and the outbound routing mode is not implemented.

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

## Xray TUN inbound (feature: `xray-tun`, Linux only)

`protocol: "tun"` is a device inbound and does not bind `listen` or `port`.
Enable it with `--features xray-tun` on Linux. The server creates a Linux L3
TUN, applies configured `gateway` CIDRs, and forwards IPv4/IPv6 TCP and UDP
through the vendored `watfaq-netstack` and existing Dokodemo dispatcher.
`mtu` defaults to 1500 and currently must be 1280–65535 to satisfy the shared
netstack; an omitted `name` selects an unused `utun10`–`utun1024` name.
`userLevel` and TCP HTTP/TLS sniffing reach the existing dispatcher.
IPv4/IPv6 ICMP Echo requests receive local Echo replies from the stack; this
does not test remote ICMP reachability. The `xray-tun` netstack also opts into
unknown IPv6 Destination Options action-bit handling after Fragment reassembly;
the default Chimera `tun-gateway` remains strict. The live Linux Xray 26.9.9
probe verifies unicast types `0x1e` (skip), `0x5e` (drop) and `0x9e`/`0xde`
(Parameter Problem, code 2/pointer 42); a further Linux TUN probe checks
first-fragment ICMPv6 header completeness behind Destination Options. A
complete 16-byte options header and ICMPv6 header in fragment zero still
returns Parameter Problem for an unknown action-10 option (pointer 48),
while the tested incomplete or mismatched header-chain layouts are dropped.
A chained two-Destination-Options / ICMPv6 fixture also requires the complete
ICMPv6 header within fragment zero: 16 fragmentable bytes are rejected, whereas
24 bytes permit Echo or an action-10 Parameter Problem (pointer 50) from the
second options header. In the UDP path, Xray-only first-fragment validation
similarly requires the full eight-byte UDP header after one or two padding-only
Destination Options headers; default `tun-gateway` retains its prior policy.
A further TCP probe with one or two padding-only Destination Options headers
shows pinned Xray drops a first fragment with zero TCP bytes, yet accepts as
few as eight TCP bytes and replies SYN-ACK, even if the full TCP SYN/MSS header
is split across fragments. The Xray-only guard follows this measured minimum.
A follow-up pinned-Xray live matrix also checks valid 20-byte option-free,
24-byte MSS and 40-byte MSS/NOP TCP headers, with the first fragment ending
within TCP options; the same minimum holds for one/two Destination Options
headers without changing the runtime. The pinned-Xray live malformed-SYN
comparison additionally confirms that MSS lengths 0/3/5, short window-scale
and zero-length unknown TCP options are accepted rather than dropping the
entire fragmented SYN; the opt-in Xray TUN path now preserves this behavior
only for reassembled IPv6 SYNs after validating the original TCP checksum.
Default `tun-gateway` stays strict. A further pinned Xray 26.9.9 probe
shows that fragmented IPv6 SYN Data Offset 0/4 or overdeclared 15 are
dropped on both TUNs, whereas valid 5 and 6 (four NOP bytes) receive SYN-ACK
behind one or two Destination Options headers. This needs no runtime change.
A live non-SYN comparison also confirms that unmatched fragmented IPv6
ACK and FIN+ACK with malformed TCP option lengths yield a bare RST on pinned
Xray, whereas input RST produces no reply; the opt-in compatibility parser
now extends the malformed-option fallback only to pure ACK and FIN+ACK.
A subsequent active-flow Linux namespace matrix verifies established IPv6
TCP ACK data and FIN+ACK tail data echo across both Chimera and pinned Xray
with valid NOP, malformed MSS and malformed unknown options after Fragment
and one/two Destination Options headers. The strict site gateway retains its
original parser; original TCP checksum errors remain rejected. Follow-up
half-close testing confirms that the inbound FIN is acknowledged on both TUNs
and that Xray's peer FIN typically appears about two seconds later, while
Chimera's is immediate; a four-second live observation checks both events
separately. A vendor regression additionally keeps the TCP send half usable
after receiving FIN/EOF. A live pinned-Xray comparison additionally
confirms that RST+ACK with malformed MSS or unknown TCP option lengths
releases established IPv6 TCP connections and allows a new SYN to reuse the
same four-tuple. The opt-in Xray-only option normalizer now includes precisely
RST+ACK. Further real-TUN testing shows that far-out-of-window RST+ACK is
ignored without ending the connection on both Xray and Chimera; the current
connection still echoes data. Pinned Xray also accepts checksum-valid
fragmented **bare RST** with malformed option lengths and allows the tuple
to reopen; the Xray-only normalizer now includes exact bare-RST flags `0x04`
without weakening the original checksum check or default strict gateway.
A near-window probe also confirms that a fragmented RST at TCP receive
sequence RCV.NXT-1 with a nonempty trailing payload must not close the flow,
while RCV.NXT+1 inside the window does close it. The opt-in Xray-only path
validates the original TCP checksum and strips RST trailing payload so smoltcp
does not incorrectly count those bytes when testing reset acceptability.
Chimera still emits an ACK for the RCV.NXT-1 probe while pinned Xray does not;
this narrower Challenge ACK mismatch remains Partial. In a repeated-RST
control, Chimera emits the initial ACK, suppresses a quick duplicate and
ACKs again about 1.12 seconds later even for header-only RST, whereas pinned
Xray emits no ACK on any of the three. A vendored regression confirms that
an originally invalid-checksum RST with valid or malformed options never
closes the connection after Xray-only normalization. Other flag variants,
A separate active-flow pure ACK matrix shows that both TUNs ACK sequence
RCV.NXT-1 or a far-out-of-window sequence and silently accept RCV.NXT+1,
but an ACK number 64 bytes beyond the peer's transmitted data causes
Chimera/smoltcp to reply with a pure ACK while pinned Xray emits none.
All eight cases per implementation continue echoing application data;
a vendor regression pins the local future-ACK response and stream
survival. This is a documented Partial response mismatch, not a
justification to filter TCP ACKs. A live zero-window flow-control probe
further establishes that, after an established client advertises a zero
TCP receive window and sends fragmented data, both Chimera and pinned
Xray ACK the input but withhold full outbound application payload,
send one-byte zero-window probes, and return the exact Echo bytes once
a fragmented window-update ACK reopens the window. Both then echo
additional new data. Chimera uses the first unacknowledged server
sequence for its 1-byte probe; Xray/gVisor probes the previous
already-acknowledged sequence. A vendor regression verifies zero-window
outbound buffering and delivery upon window update in both constructors.
Follow-up live loss injection deliberately drops the trailing fragment
of the first TCP window-update ACK and waits for a fresh one-byte probe;
a complete update with a fresh fragment ID then reopens the window.
Losing the first ACK for the recovered Echo forces a TCP retransmission
with identical sequence and payload bytes, without duplicate application
delivery. Both Chimera and pinned Xray pass two extension-header layouts;
the vendor test covers incomplete update reassembly and recovery in both
stack modes. An extended one/two-Destination-Options comparison now
holds the two-header case at zero window for roughly 14 seconds,
measures the persist-probe backoff and requires full Echo recovery
after a complete new-fragment-ID window update. Chimera's one-byte
probes showed approximately 2- and 4-second intervals; pinned Xray
showed about 0.4, 0.8, 1.6, 3.2 and 6.4 seconds. After reopening,
the intentionally unacknowledged first Echo retransmitted after about
1 second on Chimera but 12.8 seconds on Xray; both then continued
to echo new data. The vendored test
keeps its incomplete window update pending for 3.4 seconds per mode
and observes probes before the window opens. Arbitrary packet loss,
multi-minute retransmission/resource-pressure behavior, other TCP
window positions, general TCP option negotiation and RFC 7112
coverage remain unverified. A focused window-scale case additionally
offers WS=3 in SYN, requiring a Window Scale SYN-ACK. Chimera replies
with its own receive WS=3, while pinned Xray replies with receive WS=8;
both correctly interpret the *client's* advertised field 1 as just
eight bytes on server→client data. Neither sends the remainder until
the client's full window update, and both recover the original Echo
and continue with new data. The vendor regression covers scaled and
unscaled modes in both constructors. No production sender change was
made. The valid-SYN follow-up additionally tests WS=0 and WS=1
against the existing WS=3 baseline: a raw advertised receive-window
field of one limits the sender to **1, 2 and 8 bytes**, respectively.
An out-of-order IPv6-fragmented SYN carrying MSS=1280, SACK-Permitted,
WS=1 and TCP Timestamp also establishes and recovers correctly.
Chimera's SYN-ACK offers MSS/SACK/WS but *declines* Timestamp, whereas
pinned Xray advertises it. The fixture only uses Timestamp on
non-SYN packets if it was mutually negotiated. All five live
zero-window flows per implementation passed, including WS=0/1/3 and
the compound-SYN case. The data retransmission following an intentionally
lost ACK in the compound case appeared after about 1 second on Chimera
and 6.14 seconds on pinned Xray, without losing application data.
A vendor regression tests WS=0/1/7/14 mixed valid SYN options and live
application data in both stack constructors. A separate receiver SACK
regression now injects a *later* IPv6-fragmented TCP segment before
its deliberately missing first five application bytes, in both
one/two-Destination-Options layouts. On a SYN with SACK Permitted,
Chimera and pinned Xray both send the exact selective-ACK block
above the missing prefix, without advancing the cumulative ACK or
echoing the tail before the hole is filled; without SACK Permitted,
neither sends unsolicited SACK. All **four** cases per live TUN
recover the exact Echo and continue with a new message. In both
ordinary/default and Xray-opt-in constructors, a vendored regression
also verifies that retransmitting a formerly SACKed tail cannot
deliver duplicate application bytes. Outbound sender SACK-scoreboard
recovery, multiple simultaneous holes, DSACK, PAWS, large
scaled-window throughput and other combinations remain Partial.
A new **sender-side SACK feedback** probe additionally acknowledges
only the first actual outbound TCP segment of a 2100-byte Echo and
emulates a missing next segment while selectively reporting a later
segment that was actually observed. Four duplicate ACKs with or
without an RFC-valid SACK block trigger retransmission of the missing
bytes. Chimera and pinned Xray each recovered **2/2** real-TUN
flows and continued sending application data; the default and
opt-in vendor regression also tests both SYN SACK configurations.
The raw client advances its cumulative ACK only over bytes that were
actually received. This is one emulated send-side loss; gVisor's
SACK scoreboard and smoltcp's duplicate-ACK/RTO handling are not
declared equivalent for multi-hole selective recovery. A 3500-byte
double-gap sender probe additionally treats the second and fourth
real outbound segments as missing, selectively reports two
separate subsequent actual segments (when SACK was negotiated),
then sends a **partial cumulative ACK** stopping at the second
hole after the first hole's retransmission. Both Chimera and
pinned Xray retransmit the second gap correctly, recover every
byte and continue sending new data; all **four** sender cases
(single vs double gaps × SACK on/off) pass each live TUN.
The vendor test covers default and Xray-opt-in constructors.
This does not establish optimized scoreboard or congestion
parity. A follow-up SACK reneging check first reports a genuinely
received later segment as selectively ACKed, then deliberately
discards it from the synthetic client buffer and stops reporting
SACK; both Chimera and pinned Xray retransmit the missing data
and recover the complete 2100-byte Echo with normal continuation.
A distinct true-DSACK check withholds a small Echo ACK until two
identical TCP copies actually arrive, then sends a cumulative ACK
with the valid duplicate SACK block *below* the ACK and verifies
another Echo succeeds. Chimera's duplicate appeared at about
1 second; pinned Xray's at about 0.2 seconds in this fixture.
Both default and opt-in stack constructors have the corresponding
vendored regression. Neither observation proves equivalent
multi-hole SACK scoreboard, sustained reneging under real memory
pressure or DSACK congestion-control effects.

A focused TCP Timestamp/PAWS test establishes two new IPv6 TCP
flows per live TUN with Timestamp offered in SYN. Chimera's current
smoltcp listener does **not** negotiate Timestamp; pinned Xray 26.9.9
does. Sending a new in-order TCP segment with a stale TSval below the
previous valid TSval is therefore tested **only** on the negotiated
Xray connection: in both one/two Destination Options layouts, pinned
Xray actually **accepts and echoes** the stale-Timestamp data rather
than enforcing strict PAWS rejection in this established-flow case.
Chimera's equivalent packet has no Timestamp option because it was
not negotiated, so it does not assert PAWS semantics. Both reject
an old TCP **sequence-number replay** after receiving/ACKing the
original bytes and continue echoing new TCP data. Four default/opt-in
vendor cases explicitly pin the no-Timestamp SYN-ACK and protect
once-only delivery across both IPv6 fragment chains.

The follow-up 32-bit TSval boundary fixture adds two independent
live TCP streams per implementation, with SYN TSval `0xfffffff0`
and fresh TCP data stepping `0xfffffff8 -> 0x00000008`.
Pinned Xray **negotiates Timestamp**, accepts that wrapped increase,
and includes TSecr in its real data replies. The measured TSecr
sequence on the four server Echo payloads was
`[0xfffffff8, 8, 8, 0x38]`: the third data packet deliberately
**omitted Timestamp after it was negotiated** and was accepted,
so its Echo reflected the previous TSval (8) rather than an
invented timestamp. The old-sequence replay was not redelivered;
a later valid TCP message succeeded. Chimera again **declines**
Timestamp in SYN-ACK, so its analogous plain TCP path cannot
be presented as a PAWS/wraparound validation. The vendor
regression now covers **eight** default/opt-in × one/two
fragment-chain × normal/near-wrap SYN Timestamp cases and
also verifies recovery after an anomalous unnegotiated
Timestamp-bearing data packet. Full PAWS rejection,
timestamp wrap under genuine long-lived clocks, expiry,
reordering and TIME_WAIT remain unverified; Xray TUN stays Partial.

The 14.14 active-close probe adds a test-only Echo marker that
makes the destination socket close **before** the TUN client
sends FIN. In both one/two IPv6 Destination Options layouts,
Chimera sends FIN first, accepts the client FIN/ACK and enters
the server-side TIME_WAIT direction, then accepts a higher-ISN
SYN on the *same source and destination address/port tuple*
with a fresh Echo. Fixed Xray 26.9.9 delivers the original
Echo but does not send a server-first FIN within the same
initial bounded window; the test then closes from the client
side, and a later same-four-tuple SYN and fresh Echo work.
That fallback is a **client-first / LAST_ACK direction**, not
proof of gVisor TIME_WAIT behavior. Duplicate FIN under a fresh
IPv6 fragment identifier does not produce application payload.
The vendored regression tests active FIN, duplicate FIN and
same-tuple reuse across default and Xray-opt-in constructors.
Xray TIME_WAIT PAWS, longer timers, old SYN/data after tuple
reuse and physical-network disconnects remain unverified.

A follow-up target-side close-cause matrix also explicitly calls
`shutdown(SHUT_WR)` on the downstream Echo socket **while keeping
its read half open**, in addition to full `close()`. Across
one/two IPv6 fragment layouts, Chimera forwarded server-first
FIN under **both** triggers; fixed Xray 26.9.9 returned the
full Echo without server-first FIN during the 3.2-second
observation under **either** trigger. Its client-first FIN
fallback still allowed a clean FIN/ACK and a fresh higher-ISN
same-four-tuple Echo. Thus even explicit downstream TCP EOF
does **not** establish the fixed Xray's server-side
gVisor TIME_WAIT path via the standard TUN/Freedom dispatcher.
The vendored default/opt-in test now exercises **both**
server-first and client-first close directions in each
fragment layout. This is a bounded namespace observation,
not proof of gVisor TIME_WAIT timing, RST protection or PAWS.

The 14.16 follow-up **does** reach a distinct Xray
server-FIRST-FIN and duplicate FIN ACK path. It starts a
second isolated pinned Xray 26.9.9 process **only after**
the complete normal-policy suite and its TUN/routes have
been cleaned up. This second test-only process uses a
two-second level-0 connection idle timeout and a special
no-response Blackhole outbound for TCP destination port
39647; it does not change Chimera config or the default
Xray reference. Under that short policy, six one/two
IPv6-chain flows with target socket fully closed,
write-half-closed or entirely **held open** still did not
send Xray server-first FIN in the 5.5-second observation.
In contrast the pinned Xray Blackhole handler **immediately
returns** after TCP handshake, causing the TUN handler
to close its gVisor connection: two independent raw TCP
flows observed server-first FIN, client FIN acknowledgment
and a **fresh ACK to a duplicate client FIN after
closing**. This matches the pinned gVisor TIME_WAIT
duplicate-FIN branch on the wire, without proving
its timer expiry, RST assassination protection or
Timestamp/PAWS semantics. The two triggering mechanisms
are distinct and should not be conflated.

The Linux TUN fixture routes TCP port 39647 through a dedicated
`immediate-blackhole` outbound for both Chimera and pinned Xray 26.9.9.
An earlier comparison found that Chimera omitted the duplicate-FIN ACK
and accepted a higher-ISN SYN on the old four-tuple, unlike the pinned
Xray Blackhole path (2/2 per implementation). The Xray-TUN-only
vendored netstack now retains smoltcp TIME-WAIT sockets (10-second
close timer), reserves the old four-tuple and keeps the socket available
for duplicate-FIN ACKs. The default Chimera `tun-gateway` still uses its
original immediate socket removal/reuse policy. The separate
`tcp_blackhole_like_stream_close_obeys_xray_timewait_opt_in`
in-memory test checks both close-owner patterns in both modes and
confirms tuple admission after the Xray-opt-in TIME-WAIT timer expires.
An additional checksum-valid IPv6-fragmented RST probe demonstrates that
the pinned Xray 26.9.9 ignores a RST during TIME_WAIT while the earlier
Chimera path prematurely reopened the same four-tuple. The Xray-only
netstack packet pump now drops RST for retained TIME_WAIT tuples after
the original TCP checksum check. A 32-short-flow in-memory test verifies
new-source admission, old-tuple expiry/reuse and listener shutdown.
Neither test reaches the 512-flow configured cap. In the original
Blackhole comparison Xray negotiated TCP Timestamps but Chimera did not;
the later **Xray-TUN-only** Timestamp change enables a monotonic
Timestamp generator (randomized per process) on sockets whose client
SYN offers the option. Default `tun-gateway` and Xray connections with
no client Timestamp stay unmodified. Pinned Xray/gVisor explicitly
states it does not yet implement PAWS in TIME_WAIT, and the fixed Xray
oracle accepts select older and missing Timestamp packets. Chimera now
negotiates Timestamp and accepts the same tested application data. A
later Xray-TUN-only packet-pump recency fix preserves the more recent
TSecr when a valid but older TSval arrives; both Chimera and Xray now
produce `[41000,41000,44000]` for the original mismatch probe. The
state now merges up to 32 previously received out-of-order ranges
within 256 KiB when a missing TCP prefix fills their gap; the pinned
Xray TUN IPv6 test checks that both endpoints emit TSecr 45000 after
this gap is filled and 46000 after the next in-order data. This remains
an approximation of gVisor's **actual transmitted cumulative ACK**,
not a full server receive-window or forged-ACK state machine. A
follow-up pinned-Xray Linux TUN comparison shows Chimera and Xray
produce the same TSecr **46010, 62000, 62000** after a far-forward TCP
sequence, a valid-sequence/future-ACK-number probe, and an advertised
zero *client receive* window with subsequent reopening. The unusual
future ACK update is reference behavior and is now strictly tested;
no production TCP modification was needed. The Timestamp clock offset
is still per process rather than per connection. A later explicit
Xray-TUN memory-stack test additionally filled the actual **server
receive window** to zero by pausing application reads, then injected a
rejected one-byte high-TSval probe. The Xray-only Timestamp adapter now
prevents that rejected data from poisoning TSecr; after a genuine window
reopen, the accepted retransmission ACK echoed TSval 50000 rather than
the rejected probe's 75000. The criterion includes negotiated TCP
Window Scale rounding, and ordinary `tun-gateway` does not change.
A subsequent **explicit pinned-Xray 26.9.9 real TUN pressure fixture**
now pauses a separate destination TCP/39648 target's reads. Chimera
(server WS=3) and the pinned Xray TUN (server WS=8) both advertise a
real zero receive window after 1,196,016 and 1,048,320 accepted bytes,
respectively, reject a 1-byte high-TSval probe, and reopen/ACK an
accepted TSval=50000 retransmission with TSecr=50000. Transient initial
zero-window advertisements are refilled before the valid comparison.
Run the separate heavy oracle explicitly with
`XRAY_TUN_SERVER_RX_PRESSURE=1 XRAY_BIN=./xray bash scripts/test_xray_tun_routes_netns.sh`;
the normal dual-stack smoke is unchanged. A later opt-in paired oracle
compares four rejected zero-window bytes (initial, duplicate, future
sequence and already-ACKed overlap) and post-reopen out-of-order gap
repair. Both Chimera and pinned Xray retain the zero-window cumulative
ACK and echo TSecr **50000**, **50010**, then **50020** after accepted
retransmit, gap repair and one more fresh byte. The in-memory regression
also checks exact stream byte order and excludes rejected payloads.
A later explicitly enabled paired run verifies four independent normal
TCP echoes completing concurrently while the server-side zero-window
flow is stalled, plus four new flows after reopening. It also delays
and reorders four four-byte segments in that same recovering connection,
requiring cumulative ACK not to advance before the missing prefix;
Chimera and pinned Xray both echo TSecr **50010** after repair and
**50020** on fresh data. This remains **Partial** Timestamp support,
not full PAWS, random network-loss bursts, arbitrary concurrent
stalled streams, receive autotuning, ACK timers or high-load parity.
A separate opt-in two-pressure-stream Linux namespace oracle using
`XRAY_TUN_SERVER_RX_MULTISTALL=1` has additionally confirmed that
**two streams simultaneously advertising actual zero receive windows**
can be released together and independently recover with TSecr
**50000 → 50010 → 50020** on both Chimera and fixed Xray 26.9.9.
Per-connection Window Scale and actual ACK window fields determine
zero; thresholds differ between gVisor flows. This does **not** prove
larger stressed cohorts or random packet loss. A subsequent opt-in,
real Linux `tc netem loss random 3% seed 31991` probe tests four
128 KiB kernel-TCP/IPv6 echo flows in 1 KiB request/response chunks;
Chimera and pinned Xray both passed with nonzero actual qdisc drops
and kernel TCP retransmissions, followed by qdisc teardown and clean
echo recovery. The subsequently diagnosed **single-write 8 KiB TCP
downlink stall** at TUN MTU 1400 was caused by smoltcp 0.13.1 sending
full-MSS data without reserving 12 bytes for negotiated TCP Timestamp
options. An isolated capture found exactly **8040 bytes missing** at the
start of the TUN downlink; the Xray-only **internal SYN MSS clamp** now
reserves a 40-byte option budget, retaining the real TUN MTU and the
unchanged default `tun-gateway`. The precise MSS-1460+Timestamp in-memory
regression went red-to-green, and the real zero-loss one-shot 8 KiB echo
is now byte-correct with MTU-safe 1300-byte segments. The independent
`XRAY_TUN_BULK_ECHO=1` namespace oracle checks both Chimera and pinned
Xray. Further network conditions, congestion/MSS pacing and general
PAWS compatibility remain **Partial**.
Longer gVisor TIME_WAIT, broader RST/PAWS semantics, FIN timing and
production load remain outside the verified scope.

Linux `autoSystemRoutingTable` entries install main-table routes with metric 1
and remove them on startup rollback and shutdown. Default routes are accepted
to match Xray; they can capture the server's own outbound connections, so add
an escape route when the deployment needs one. Xray's Linux backend ignores
`desc`, `dns`, and `autoOutboundsInterface`; Chimera keeps those Linux semantics.
The service bounds active TCP flows at 512 and UDP destination sessions at
1024; excess TCP flows are dropped before outbound dispatch and new UDP flows
are dropped at the session limit. Xray QUIC v1, v2, and draft-29 Initial
packets can supply a ClientHello SNI for UDP route matching when sniffing uses
`destOverride: ["quic"]` with `routeOnly: true`; the original IP and port stay
the actual UDP destination. The route-only result is pinned for that UDP flow.
QUIC Initial CRYPTO fragments are assembled across UDP datagrams for up to
500 ms. Until the ClientHello is complete, the bounded TUN path buffers at most
8 datagrams / 8 KiB per flow; if sniffing times out or exceeds those limits, the
buffered traffic falls back to the original IP route. Xray's QUIC sniffing uses
an outer SNI even when an ECH extension is present, matching the reference
dispatcher; the separate TCP TLS sniffer continues to treat ECH as opaque.
QUIC destination rewriting without `routeOnly` is rejected explicitly.

```json
{
  "inbounds": [{
    "protocol": "tun",
    "tag": "xray-tun",
    "settings": {
      "name": "utun10",
      "mtu": 1500,
      "gateway": ["10.20.0.1/24", "fd10:20::1/64"],
      "autoSystemRoutingTable": ["10.20.0.0/24", "fd10:20::/64"],
      "userLevel": 0
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["quic"],
      "routeOnly": true
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
```

`autoSystemRoutingTable` routes are validated as IP CIDRs before device
creation. `prepare_server_runtime` and `prepare_server_inbounds` reject TUN
inbounds because only `start()` owns their device lifecycle. Builds without
`xray-tun` and non-Linux builds return explicit configuration errors. Memory
TUN tests cover config compilation, TCP/UDP echo, IPv4/IPv6 ICMP Echo, route
message semantics, the MTU boundary, QUIC v1/v2 SNI extraction from pinned
Xray fixtures, real Xray 26.9.9 fragmented Initials, and route-only domain
selection plus UDP-flow pinning through MemoryTun. `bash scripts/test_xray_tun_routes_netns.sh`
also injects a pinned QUIC v1 Initial through the live kernel TUN and confirms
the SNI route blocks it and a subsequent datagram on the same flow before
ordinary dual-stack echo checks. Set `XRAY_BIN=./xray` to additionally start the
pinned Xray 26.9.9 VLESS/XHTTP H3 server and client. The client first verifies
the QUIC Initial SNI block, then completes an H3 `packet-up` VLESS session
through the live TUN and returns both TCP and UDP SOCKS echo payloads. The
probe asserts the Chimera log contains the route-only `site-tls.test` flow. It
creates a real device in a disposable Linux user/network namespace and verifies
IPv4/IPv6 main-table metric-1 route installation, TCP/UDP echo through the
TUN/netstack/Dokodemo/Freedom path, partial-route rollback after a conflict,
and graceful-shutdown cleanup of routes, gateway addresses, and the interface.
This is one Xray 26.9.9 Linux H3 `packet-up` combination; other client versions,
profiles and security/transport combinations, ICMP errors and dynamic TUN
management remain unverified, so this capability remains Partial.

## Linux Reverse site-to-site TUN gateway (feature: `tun-gateway`)

Chimera's top-level `tunGateway` extension creates one Linux layer-3 TUN device
and feeds its IP packets through a vendored snapshot of Chimera_Client
`clash-netstack/` (Cargo package `watfaq-netstack`). It is a separate
device-owned service and is not an Xray TUN inbound. The runtime
forwards IPv4 and IPv6 TCP through the existing Dokodemo `followRedirect`
dispatcher and IPv4 and IPv6 UDP through Dokodemo's normal outbound selection
and UDP session relay. UDP responses retain the original packet destination as
their source address when written back through the netstack.

```json
{
  "inbounds": [],
  "outbounds": [],
  "tunGateway": {
    "name": "site-tun",
    "address": "10.254.0.1/24",
    "ipv6Address": "fd00:254::1/64",
    "mtu": 1500,
    "routes": ["10.44.0.0/24", "2001:db8:44::/64"],
    "routeFrom": ["10.251.0.0/24", "fd18:251::/64"],
    "routeInputInterface": "office-gw",
    "routeTable": 10001,
    "routeRulePriority": 10001,
    "inboundTag": "office-tun",
    "userLevel": 0,
    "maxTcpConnections": 64,
    "maxUdpSessions": 256
  }
}
```

`name` is a Linux interface name (1-15 ASCII letters, digits, `.`, `_` or
`-`). `address` must be an IPv4 CIDR. Optional `ipv6Address` must be an IPv6
CIDR; when set, Chimera assigns it to the TUN after device creation. If omitted,
configure any needed IPv6 interface address externally. `inboundTag` supplies
the routing and statistics identity; `userLevel` defaults to 0. `maxTcpConnections` defaults
to 64 and must be 1-512. `maxUdpSessions` defaults to 256 and must be 1-1024;
it bounds concurrent destination sessions and their relay queues. At the TCP
limit, excess netstack flows are dropped before outbound dispatch; at the UDP
limit, new-flow datagrams are dropped until a session expires. Memory packet tests verify that an excess TCP flow does not dial a second
target and that an over-limit UDP flow does not reach its target. The Linux
namespace smoke also sets `maxTcpConnections` to 2, holds two real Reverse
flows open, confirms a third is rejected before reaching the Edge LAN, then
closes the admitted flows and verifies a new connection succeeds. The stack
UDP case sets `maxUdpSessions` to 8, fills the budget across direct, IPv4 and
IPv6 baseline flows plus five additional source tuples, and confirms the ninth
flow is rejected before dispatch. The namespace smoke keeps one UDP socket and its source/target tuple
open across three cycles of 62 seconds of silence followed by a Reverse DNS
request/reply. All three are admitted after the production 60-second idle
timeout, and each response retains the Overlay source tuple. An in-memory Hub
Reverse-to-Edge test reuses one slot for three successive same-tuple sessions;
it verifies one tracked relay stays active through each echo and is removed
before the next cycle. That focused integration test uses a test-only 250 ms
idle timeout. A separate paused-time unit test advances the 60-second Freedom
UDP idle timer and verifies session-map removal and permit return. These checks
cover bounded session admission and three controlled production-timeout
recovery cycles, not sustained device-load or high-frequency churn rates.
The in-memory TUN UDP-limit test also keeps an admitted relay active during
service cancellation and verifies the runtime task owner cancels and removes it
when the drain window is zero. The `mtu` field defaults to 1500 and accepts
values from 1280 to 9000 bytes. Chimera applies the same value to the Linux TUN
device, the userspace TCP stack, packet read buffer, and UDP output fragmenter.
The 1280-byte minimum preserves IPv6's minimum link MTU; the 9000-byte cap
bounds per-packet buffers. Each stack
TCP flow may reserve about 1 MiB of socket buffers, so the default TCP cap
bounds that portion of memory to roughly 64 MiB. The feature is optional and
is not included in `full`; enable it with
`--features tun-gateway` (or `full,tun-gateway`).

The server requires Linux TUN permissions, normally root or `CAP_NET_ADMIN`.
With `routes` and `routeFrom` omitted, it creates and closes the named interface
without changing system routing. When both are configured, Chimera installs
the destination routes in a dedicated Linux route table and adds rules matching
the listed source prefixes and `routeInputInterface`. This keeps
Server-originated connections out of the TUN policy even when the server's LAN
address belongs to a listed Office subnet. Both lists must
contain specific, non-default CIDRs; the lists are limited to 128 prefixes each,
must cover matching address families, and must not include the TUN interface
address. `routeInputInterface` must name an existing Linux interface other than
the TUN device. IPv6 routes require `ipv6Address`. The table defaults to 10001 and the
rule priority defaults to 10001; choose unused values when the host has custom
policy routing. The selected table must be empty, and the selected rule priority
must be unused. A collision fails startup; partial routes are rolled back, and
the routes/rules created by Chimera are removed on graceful shutdown.
`routeFrom` chooses a routing path; it does not authorize traffic, so Hub
identity policy and Edge destination ACLs remain necessary.
If the process is killed without graceful shutdown, Linux removes routes when
the TUN link closes but may retain the source rule. Its empty table lets lookups
continue to later rules; remove that stale rule before restarting with the same
priority.

This manages routing only in Chimera's Linux network namespace. It does not
configure upstream Office routers, forwarding, firewall policy, NAT, or DNS;
the Office router must still direct client traffic to this host, and the host
must permit the required forwarding. The namespace smoke verifies that
forwarded IPv4/IPv6 TCP and UDP echoes use the managed TUN routes, while real
Server-local IPv4/IPv6 TCP and UDP sockets bound to addresses from the same
Office prefixes still reach the LAN echo service over the normal LAN route.
It also checks both address families stay out of `main`,
normal shutdown cleanup, rollback after a rule-priority collision, and that a
non-empty route table is preserved when startup fails. When
automatic local route management is omitted, configure desired routes externally,
for example:

```sh
ip -6 route add 2001:db8:44::/64 dev site-tun
```

The manual route example assumes `ipv6Address` has already configured the TUN
address. Add the address manually only when `ipv6Address` is omitted.

The repeatable namespace smoke configures `ipv6Address`, sets the Overlay route
externally, then verifies IPv6 TCP, UDP, 4 KiB UDP and an Overlay-to-LAN IPv6
prefix map through VLESS Reverse. This validates dual-stack forwarding and
automatic local IPv6 address assignment, not IPv6-only operation. Startup binds ordinary inbounds before creating the TUN; a
Linux rollback regressions cover both device creation failure and a netlink
IPv6 address-assignment failure after TUN creation; each confirms the previously
bound listener is released, and the latter confirms the TUN device is removed.
The device-creation case also checks that the original I/O error kind is
retained (for example, an interface-name conflict is not reported as a
permission failure). Server shutdown signals the TUN service
to leave its packet loop and awaits the service task, which then drops the
device and netstack handles. Server calls the vendored
`TcpListener::shutdown` and awaits its internal TCP packet-engine task before
releasing the device; `Drop` remains an abort fallback if graceful shutdown is
not reached.
In-memory IPv4 packet tests cover TCP and UDP through local Freedom echo and
an integrated Hub Reverse Portal → Edge mapping/ACL → loopback LAN socket path,
including Overlay response address and port restoration. An out-of-order IPv4
fragment test also reassembles a 4 KiB UDP datagram before Reverse forwarding.
The repeatable `bash scripts/test_tun_gateway_netns.sh` smoke creates a real
Linux TUN in a disposable user/network namespace, verifies direct Freedom
TCP/UDP plus the real TUN→Office VLESS→Hub Reverse→Edge mapping/ACL→veth-routed
LAN namespace TCP/UDP path, checks 4 KiB UDP round trips across the 1500-byte
MTU, the TUN address and Overlay UDP response source, and confirms SIGTERM
removes the device. It also creates a separate ordinary Office-LAN client with
no proxy process, installs routes for both Overlay families through the
Gateway, enables forwarding only inside the disposable namespace, and verifies
IPv4/IPv6 TCP, UDP and 4 KiB UDP to the remote LAN. That case caught oversized
UDP replies emitted by the vendored stack: the Server now source-fragments
IPv4/IPv6 UDP packets to 1500 bytes and reserves queue slots for the full
fragment set before emitting any fragment. Its unit tests verify reverse-order
reassembly and whole-datagram drop when the bounded packet queue cannot accept
all fragments. The smoke's LAN target binds to the veth peer interface in a
separate namespace; it does not modify host routes. The
`scripts/test_tun_gateway_duplicate_lan_netns.sh` smoke adds two isolated Edge
namespaces with identical LAN `/24` prefixes and verifies site-specific TCP/UDP
(including 4 KiB UDP) through the real TUN/Hub/Reverse path. Both scripts keep
routes and sysctl changes in disposable namespaces; the duplicate
LAN smoke disables strict reverse-path filtering there to admit the synthetic
return routes. In-memory regressions reject a truncated IPv4 UDP fragment and a
conflicting IPv4 overlap, then confirm a later valid UDP datagram still reaches
Reverse. Reverse Mux UDP datagrams are capped at 8192 bytes: tests cover the
accepted boundary and rejection of 8193 bytes, which closes that packet
session; the server does not split larger datagrams across Mux frames. A
separate direct Freedom regression sends a 16 KiB fragmented UDP datagram to
its local target socket, confirming this Mux limit is specific to the Reverse
route. Other
malformed/overlapping fragment cases, production route policy, physical LAN
traffic, full Xray TUN-inbound compatibility, and Xray Edge prefix mapping remain unverified. Fixed Xray 26.9.9 Edge Bridge IPv4/IPv6 passthrough through the TUN/Hub Reverse path is verified by scripts/test_tun_gateway_xray_edge_netns.sh; its Overlay and LAN target addresses are identical. In that topology Xray `finalRules` also allows TCP 39641 and UDP 39642, while live TCP 39643 and UDP 39644 listeners receive no probes for either address family. The pinned
netstack keeps at most 64 active fragment sets per reassembler and expires entries older than 30 seconds with a one-second scan while state is active; an empty reassembler does not schedule expiry wakeups. Paused-time unit tests verify idle expiry for UDP and TCP/ICMP consumers. The Linux namespace smoke injects 65 incomplete IPv4 and separately 65 incomplete IPv6 UDP fragment sets through the real TUN, observes oldest-set eviction at the 64-set cap, then verifies all 64 retained 1,192-byte datagrams and their Overlay source tuples end to end. This is a live boundary probe, not sustained device-load or memory evidence; additional malformed/overlapping patterns remain unverified. Unknown fields inside this
Chimera extension are rejected instead of ignored. The Xray 26.9.9 TLS
interop smoke validates explicit SAN trust roots for both Office Gateway→Hub
and Edge Bridge→Hub; it restarts the Hub and then only the Edge, requiring a
new Portal worker attachment and new Office IPv4/IPv6 TCP/UDP recovery after each
restart. The same smoke changes only Office `serverName` to an invalid value and
confirms that dual-stack TCP/UDP traffic does not reach the live Edge LAN; restoring
the valid SNI restores both paths. The TLS fixture is test-only, and physical LANs
remain unverified.
