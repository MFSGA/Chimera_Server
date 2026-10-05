# Vendored `watfaq-netstack`

This source snapshot comes from `MFSGA/Chimera_Client/clash-netstack`, package
version `0.26.3`. The upstream base is commit
`6e951d59976c22a65238e8a70069971a6dfea4ae`; the vendored source includes the
two subsequent Client commits `925d4b1b66a543956c61239776196cd9d17e5c5d` and
`8fc9b2b3821a571f806cda6cc4df68bef8ad1b46`.

Those changes add an explicit, awaitable TCP listener shutdown path and redact
packet payloads from malformed-packet diagnostics. The latter is required for
the Server's no-secret-in-logs rule. The Client commits are local and not yet in
the public Git history, so the Server carries this reviewable source snapshot
instead of depending on an unpublished revision or another checkout's path.

The Server also carries a local change in `src/udp_socket.rs`: `SplitWrite`
fragments oversized IPv4 and IPv6 UDP IP packets to the configured MTU (1500
by default). `NetStack::new_with_mtu` applies that same value to smoltcp's
device capabilities and UDP fragmentation. It reserves queue capacity for the complete fragment set before sending
any fragment, so bounded-queue pressure drops a whole UDP datagram instead of
publishing a partial one. A routed Office-LAN-host namespace test exposed this
gap: returning a 4 KiB UDP response as one oversized IP packet failed across a
1500-byte veth. The Server-only fragmentation tests cover reverse-order
reassembly for both address families, configured 1280-byte IPv4/IPv6 output,
and atomic drop when the packet queue cannot fit the whole datagram. The
reassembler also has a 30-second state TTL;
UDP readers and the TCP/ICMP packet loop scan once per second only while
fragment state exists, so incomplete sets are released during quiet periods
without waking ordinary empty readers. Tokio paused-time unit tests cover both
consumer paths. This is a Server-only lifecycle delta from the Client snapshot.

Keep the `tun-gateway` Cargo feature optional. When these commits become
available from a reproducible upstream ref, compare the complete `clash-netstack`
tree before replacing this snapshot; preserve the Server-side regression
coverage for shutdown and diagnostic redaction.

## Verification

The vendored base was compared with the Client checkout at
`8fc9b2b3821a571f806cda6cc4df68bef8ad1b46`; Client changes are retained and
the Server delta adds UDP source fragmentation, idle fragment-state expiry
scans, and their regression tests. The package tests pass: 19 unit tests and 34 integration tests. Its
all-target/all-feature Clippy check passes with warnings denied:

```sh
cargo test --manifest-path vendor/watfaq-netstack/Cargo.toml
cargo clippy --manifest-path vendor/watfaq-netstack/Cargo.toml --all-targets --all-features -- -D warnings
```

The Server integration is separately covered by
`cargo test -p chimera_server_lib --no-default-features --features tun-gateway,vless-reverse --lib tun_gateway --locked`
(24 passed) and the single-site namespace smoke. The duplicate-LAN and Xray-edge
smoke scripts remain separate interoperability checks.
