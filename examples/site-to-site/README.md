# Reverse site-to-site example

These three Chimera-native YAML files form one Hub → Edge → Office topology:

- [`hub.yaml`](hub.yaml) is the public VLESS Reverse Portal. It authenticates
  separate Edge and Office UUIDs, selects the Edge by the original Overlay
  destination, allows only the configured Office identity and service ports,
  then blackholes the protected Overlay prefixes by default.
- [`edge.yaml`](edge.yaml) is the LAN-side Reverse Bridge. It maps the Overlay
  prefixes onto one site's LAN prefixes, applies a default-deny mapped-target
  allow list, and repeats that boundary in Freedom `finalRules`.
- [`office-gateway.yaml`](office-gateway.yaml) is the Linux TUN gateway. It
  routes the selected Overlay prefixes through its verified TLS VLESS
  connection to the Hub and installs optional source/ingress-scoped routes for
  Office LAN clients.

The example ranges are documentation values. Replace both UUIDs with distinct
random credentials, use a publicly reachable Hub name and valid certificate,
replace the sample Overlay/LAN prefixes and service ports with non-overlapping
values for the deployment. Edge and Office use the system root store and verify
`hub.example.net`; for a private CA, add an Xray-compatible `usage: verify`
certificate entry using a real, readable CA file before running `--check`.
The placeholder credentials are intentionally valid UUID syntax so the files
can be checked; they are public and must never be deployed unchanged. Configure
the Hub certificate and private key with appropriate ownership and permissions.

Build the optional Linux gateway and VLESS Reverse/TLS capabilities, then run
the same configuration compiler used by startup against each role:

```sh
cargo run -p chimera_server_app --no-default-features \
  --features tun-gateway,vless-reverse-tls -- \
  --config examples/site-to-site/hub.yaml --check
cargo run -p chimera_server_app --no-default-features \
  --features tun-gateway,vless-reverse-tls -- \
  --config examples/site-to-site/edge.yaml --check
cargo run -p chimera_server_app --no-default-features \
  --features tun-gateway,vless-reverse-tls -- \
  --config examples/site-to-site/office-gateway.yaml --check
```

The same role configs are kept covered by an integration test when both
capabilities are selected:

```sh
cargo test -p chimera_server_app --no-default-features \
  --features tun-gateway,vless-reverse-tls --test site_to_site_examples
```

`--check` verifies parsing, feature availability, and configuration compilation;
it does not create a TUN device or prove network reachability. The Hub loads its
server certificate and key when starting its TLS listener. Start each role with
its checked config only after installing those files and replacing the example
identities.

For `office-gateway.yaml`, create `br-office` before starting Chimera. The
Office LAN router must send the listed Overlay prefixes to this gateway, and
the gateway's forwarding firewall must permit the intended clients. Chimera's
managed routes affect only its own Linux network namespace and only packets
matching `routeFrom` plus `routeInputInterface`; upstream routes, forwarding,
firewall policy, return routes and NAT remain deployment responsibilities.
The sample does not provide Xray TUN-inbound schema compatibility or arbitrary
IP protocols such as ICMP. It handles IPv4/IPv6 TCP and UDP through the
vendored Chimera_Client `clash-netstack` (`watfaq-netstack`) implementation.

This is a secure-by-default starting topology, not evidence of physical-LAN or
production-route validation. See the site-to-site design and Xray support
matrix for verified combinations and remaining interoperability gaps.
