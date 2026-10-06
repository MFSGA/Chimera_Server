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
accepts a string or array of literal IP/CIDR strings. For a hostname target, all
resolved addresses are checked before Freedom dials; any blocked candidate
rejects the request. These checks use the same rule matcher from the shared
TCP/UDP outbound selector and Dokodemo's dedicated UDP route, including new
and per-packet sessions.

Xray's default Freedom rule blocks every target for a `vless-reverse` inbound,
and blocks its private-IP set for VLESS/VMess/Trojan/Hysteria/WireGuard and
Shadowsocks inbounds. An explicit matching `allow` rule overrides that default.
The Edge `reverse.siteToSite` map/ACL remains a separate, narrower Chimera
extension: it maps Overlay destinations and checks the mapped LAN endpoint.

This is a partial compatibility slice. GeoIP/ext IP rules, IP reverse-match,
`blockDelay`, non-default `domainStrategy`/`targetStrategy`, redirect/destination
override, nonzero `userLevel`, fragment/noise, and Freedom socket/dialer settings
fail explicitly until implemented. A denied connection is closed or its UDP
packet dropped immediately; Xray's configurable/default delayed blackhole is
not reproduced yet.

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
