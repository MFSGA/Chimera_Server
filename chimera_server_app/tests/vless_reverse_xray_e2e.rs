mod xhttp_support;

use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::{
        IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{SHA256, digest};
use prost::Message;
use rustls_pemfile::certs;
use serde_json::json;
use tonic::{
    Request, Status,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard,
    start_chimera, start_xray, wait_for_tcp, workspace_root, write_json,
    xray_binary,
};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const REVERSE_READY_TIMEOUT: Duration = Duration::from_secs(12);
// The Hub policy matrix has rejection-only phases longer than the regular
// readiness timeout between allowed UDP probes. Keep these test fixtures alive
// through the later dynamic IPv6 checks.
const UDP_ECHO_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const WRONG_TEST_UUID: &str = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
const HUB_OVERLAY_PROTECTED_PREFIXES: [&str; 3] =
    ["10.200.1.0/24", "10.200.2.0/24", "2001:db8:30::/64"];
const ROUTING_ADD_RULE_PATH: &str =
    "/xray.app.router.command.RoutingService/AddRule";
const ROUTING_REMOVE_RULE_PATH: &str =
    "/xray.app.router.command.RoutingService/RemoveRule";
const ROUTING_LIST_RULE_PATH: &str =
    "/xray.app.router.command.RoutingService/ListRule";

#[derive(Clone, Copy)]
enum ReverseSecurity {
    Raw,
    Tls,
    #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
    Reality,
    Websocket,
    XhttpTls,
    XhttpTlsAuto,
    XhttpTlsPacketUp,
    XhttpTlsH3PacketUp,
    XhttpTlsH3StreamUp,
    XhttpTlsH3Auto,
    XhttpTlsObfs,
}

impl ReverseSecurity {
    fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Tls => "tls",
            #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
            Self::Reality => "reality",
            Self::Websocket => "websocket",
            Self::XhttpTls => "xhttp-tls",
            Self::XhttpTlsAuto => "xhttp-tls-auto",
            Self::XhttpTlsPacketUp => "xhttp-tls-packet-up",
            Self::XhttpTlsH3PacketUp => "xhttp-tls-h3-packet-up",
            Self::XhttpTlsH3StreamUp => "xhttp-tls-h3-stream-up",
            Self::XhttpTlsH3Auto => "xhttp-tls-h3-auto",
            Self::XhttpTlsObfs => "xhttp-tls-obfs",
        }
    }

    fn has_negative_auth_case(self) -> bool {
        match self {
            Self::Raw => true,
            #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
            Self::Reality => true,
            _ => false,
        }
    }

    fn is_reality(self) -> bool {
        #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
        {
            matches!(self, Self::Reality)
        }
        #[cfg(not(any(feature = "full", feature = "vless-reverse-reality")))]
        {
            false
        }
    }

    fn is_xhttp_h3(self) -> bool {
        matches!(
            self,
            Self::XhttpTlsH3PacketUp
                | Self::XhttpTlsH3StreamUp
                | Self::XhttpTlsH3Auto
        )
    }

    fn xhttp_mode(self) -> &'static str {
        match self {
            Self::XhttpTlsAuto | Self::XhttpTlsH3Auto => "auto",
            Self::XhttpTlsPacketUp | Self::XhttpTlsH3PacketUp => "packet-up",
            _ => "stream-up",
        }
    }
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_tcp_over_raw_vless_reverse() {
    run_reverse_interop(ReverseSecurity::Raw);
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_tcp_over_tls_vless_reverse() {
    run_reverse_interop(ReverseSecurity::Tls);
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_raw_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Raw, None);
}

#[test]
fn chimera_bridge_preserves_reverse_source_for_freedom_proxy_protocol() {
    run_chimera_bridge_proxy_protocol_interop();
}

#[test]
fn chimera_bridge_xhttp_forwarded_source_does_not_replace_reverse_client_source() {
    run_chimera_bridge_xhttp_forwarded_source_interop();
}

#[cfg(any(feature = "full", feature = "vless-reverse"))]
#[test]
fn multiple_xray_bridges_keep_chimera_portal_usable_after_one_disconnects() {
    run_multiple_xray_bridge_failover();
}

#[test]
fn chimera_bridge_preserves_reverse_routing_user_over_raw_vless_reverse() {
    run_chimera_bridge_interop(
        ReverseSecurity::Raw,
        Some("reverse-routing@example.test"),
    );
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_tls_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Tls, None);
}

#[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
#[test]
fn xray_bridge_round_trips_chimera_portal_over_reality_vless_reverse() {
    run_reverse_interop(ReverseSecurity::Reality);
}

#[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
#[test]
fn chimera_bridge_round_trips_xray_portal_over_reality_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Reality, None);
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_websocket_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Websocket, None);
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_xhttp_tls_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::XhttpTls, None);
}

#[test]
fn xray_bridge_round_trips_public_chimera_portal_over_xhttp_tls_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTls);
}

#[test]
fn chimera_bridge_round_trips_xray_portal_over_xhttp_tls_packet_up_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::XhttpTlsPacketUp, None);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_tls_packet_up_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsPacketUp);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_h3_packet_up_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsH3PacketUp);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_h3_stream_up_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsH3StreamUp);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_h3_auto_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsH3Auto);
}

#[test]
fn chimera_bridge_round_trips_xray_portal_over_xhttp_tls_auto_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::XhttpTlsAuto, None);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_tls_auto_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsAuto);
}

#[test]
fn chimera_bridge_round_trips_xray_portal_over_xhttp_tls_obfs_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::XhttpTlsObfs, None);
}

#[test]
fn xray_bridge_round_trips_chimera_portal_over_xhttp_tls_obfs_vless_reverse() {
    run_reverse_interop(ReverseSecurity::XhttpTlsObfs);
}

#[test]
fn chimera_bridge_sniffs_http_host_over_raw_vless_reverse() {
    run_chimera_bridge_sniffing_interop(
        "http-override",
        "192.0.2.1",
        json!({"enabled": true, "destOverride": ["http"]}),
        b"GET /sniff HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_sniffs_tls_sni_over_raw_vless_reverse() {
    let payload = tls_client_hello_payload("localhost");
    run_chimera_bridge_sniffing_interop(
        "tls-override",
        "192.0.2.1",
        json!({"enabled": true, "destOverride": ["tls"]}),
        &payload,
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_route_only_keeps_original_target() {
    run_chimera_bridge_sniffing_interop(
        "http-route-only",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "routeOnly": true
        }),
        b"GET /sniff HTTP/1.1\r\nHost: route-only.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_honors_domain_exclusions() {
    run_chimera_bridge_sniffing_interop(
        "http-domain-excluded",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "domainsExcluded": ["full:excluded.test"]
        }),
        b"GET /sniff HTTP/1.1\r\nHost: excluded.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_honors_ip_exclusions() {
    run_chimera_bridge_sniffing_interop(
        "http-ip-excluded",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "ipsExcluded": ["127.0.0.0/8"]
        }),
        b"GET /sniff HTTP/1.1\r\nHost: ip-excluded.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_udp_over_raw_vless_reverse() {
    run_reverse_udp_interop(false);
}

#[test]
fn xray_socks_udp_reattaches_global_id_after_vless_tcp_disconnect() {
    run_reverse_udp_interop(true);
}

#[test]
fn xray_socks_udp_fails_closed_recovers_after_attach_and_idle_expiry() {
    run_xray_socks_udp_without_worker_recovery();
}

#[test]
fn xray_clients_are_isolated_by_hub_overlay_access_rules_before_edge_dispatch() {
    run_hub_overlay_access_interop();
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_udp_over_raw_vless_reverse() {
    run_chimera_bridge_udp_interop();
}

struct HubOverlayEchoTarget {
    overlay_prefix: &'static str,
    overlay_ip: IpAddr,
    tcp_allowed: SocketAddr,
    tcp_allowed_bytes: Arc<AtomicUsize>,
    tcp_denied: SocketAddr,
    tcp_denied_bytes: Arc<AtomicUsize>,
    udp_allowed: SocketAddr,
    udp_allowed_bytes: Arc<AtomicUsize>,
    udp_denied: SocketAddr,
    udp_denied_bytes: Arc<AtomicUsize>,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicRouterConfig {
    #[prost(int32, tag = "1")]
    domain_strategy: i32,
    #[prost(message, repeated, tag = "2")]
    rule: Vec<DynamicRoutingRule>,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicRoutingRule {
    #[prost(oneof = "dynamic_routing_rule::TargetTag", tags = "1, 12")]
    target_tag: Option<dynamic_routing_rule::TargetTag>,
    #[prost(string, tag = "19")]
    rule_tag: String,
    #[prost(message, repeated, tag = "10")]
    ip: Vec<DynamicIpRule>,
    #[prost(int32, repeated, tag = "13")]
    networks: Vec<i32>,
    #[prost(string, repeated, tag = "7")]
    user_email: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    inbound_tag: Vec<String>,
}

mod dynamic_routing_rule {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum TargetTag {
        #[prost(string, tag = "1")]
        Tag(String),
        #[prost(string, tag = "12")]
        BalancingTag(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct DynamicIpRule {
    #[prost(message, optional, tag = "2")]
    custom: Option<DynamicCidrRule>,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicCidrRule {
    #[prost(message, optional, tag = "1")]
    cidr: Option<DynamicCidr>,
    #[prost(bool, tag = "2")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicCidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicTypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicAddRuleRequest {
    #[prost(message, optional, tag = "1")]
    config: Option<DynamicTypedMessage>,
    #[prost(bool, tag = "2")]
    should_append: bool,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicAddRuleResponse {}

#[derive(Clone, PartialEq, Message)]
struct DynamicRemoveRuleRequest {
    #[prost(string, tag = "1")]
    rule_tag: String,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicRemoveRuleResponse {}

#[derive(Clone, PartialEq, Message)]
struct DynamicListRuleRequest {}

#[derive(Clone, PartialEq, Message)]
struct DynamicListRuleItem {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, tag = "2")]
    rule_tag: String,
}

#[derive(Clone, PartialEq, Message)]
struct DynamicListRuleResponse {
    #[prost(message, repeated, tag = "1")]
    rules: Vec<DynamicListRuleItem>,
}

impl HubOverlayEchoTarget {
    fn new(
        overlay_prefix: &'static str,
        overlay_ip: IpAddr,
        edge_ip: IpAddr,
    ) -> Self {
        let (tcp_allowed, tcp_allowed_bytes) =
            start_observed_echo_server_on(edge_ip);
        let (tcp_denied, tcp_denied_bytes) = start_observed_echo_server_on(edge_ip);
        let (udp_allowed, udp_allowed_bytes) =
            start_observed_udp_echo_server_on(edge_ip);
        let (udp_denied, udp_denied_bytes) =
            start_observed_udp_echo_server_on(edge_ip);
        Self {
            overlay_prefix,
            overlay_ip,
            tcp_allowed,
            tcp_allowed_bytes,
            tcp_denied,
            tcp_denied_bytes,
            udp_allowed,
            udp_allowed_bytes,
            udp_denied,
            udp_denied_bytes,
        }
    }

    fn overlay_target(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.overlay_ip, port)
    }

    fn edge_ports(&self) -> [u16; 4] {
        [
            self.tcp_allowed.port(),
            self.tcp_denied.port(),
            self.udp_allowed.port(),
            self.udp_denied.port(),
        ]
    }
}

fn run_hub_overlay_access_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping Hub Overlay access interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-hub-overlay-access");
    let hub_dir = work_dir.join("hub");
    let edge_dir = work_dir.join("edge");
    let allowed_client_dir = work_dir.join("allowed-client");
    let denied_client_dir = work_dir.join("denied-client");
    let allowed_tls_client_dir = work_dir.join("allowed-tls-client");
    let denied_tls_client_dir = work_dir.join("denied-tls-client");
    let allowed_ws_client_dir = work_dir.join("allowed-ws-client");
    let denied_ws_client_dir = work_dir.join("denied-ws-client");
    let allowed_xhttp_client_dir = work_dir.join("allowed-xhttp-client");
    let denied_xhttp_client_dir = work_dir.join("denied-xhttp-client");
    let allowed_xhttp_stream_up_client_dir =
        work_dir.join("allowed-xhttp-stream-up-client");
    let denied_xhttp_stream_up_client_dir =
        work_dir.join("denied-xhttp-stream-up-client");
    let allowed_xhttp_auto_client_dir = work_dir.join("allowed-xhttp-auto-client");
    let denied_xhttp_auto_client_dir = work_dir.join("denied-xhttp-auto-client");
    let allowed_xhttp_h3_client_dir = work_dir.join("allowed-xhttp-h3-client");
    let denied_xhttp_h3_client_dir = work_dir.join("denied-xhttp-h3-client");
    let unauthenticated_xhttp_h3_client_dir =
        work_dir.join("unauthenticated-xhttp-h3-client");
    let unauthenticated_xhttp_h3_stream_up_client_dir =
        work_dir.join("unauthenticated-xhttp-h3-stream-up-client");
    let unauthenticated_xhttp_h3_auto_client_dir =
        work_dir.join("unauthenticated-xhttp-h3-auto-client");
    let allowed_xhttp_h3_stream_up_client_dir =
        work_dir.join("allowed-xhttp-h3-stream-up-client");
    let denied_xhttp_h3_stream_up_client_dir =
        work_dir.join("denied-xhttp-h3-stream-up-client");
    let allowed_xhttp_h3_auto_client_dir =
        work_dir.join("allowed-xhttp-h3-auto-client");
    let denied_xhttp_h3_auto_client_dir =
        work_dir.join("denied-xhttp-h3-auto-client");
    let allowed_reality_client_dir = work_dir.join("allowed-reality-client");
    let denied_reality_client_dir = work_dir.join("denied-reality-client");
    for directory in [
        &hub_dir,
        &edge_dir,
        &allowed_client_dir,
        &denied_client_dir,
        &allowed_tls_client_dir,
        &denied_tls_client_dir,
        &allowed_ws_client_dir,
        &denied_ws_client_dir,
        &allowed_xhttp_client_dir,
        &denied_xhttp_client_dir,
        &allowed_xhttp_stream_up_client_dir,
        &denied_xhttp_stream_up_client_dir,
        &allowed_xhttp_auto_client_dir,
        &denied_xhttp_auto_client_dir,
        &allowed_xhttp_h3_client_dir,
        &denied_xhttp_h3_client_dir,
        &unauthenticated_xhttp_h3_client_dir,
        &unauthenticated_xhttp_h3_stream_up_client_dir,
        &unauthenticated_xhttp_h3_auto_client_dir,
        &allowed_xhttp_h3_stream_up_client_dir,
        &denied_xhttp_h3_stream_up_client_dir,
        &allowed_xhttp_h3_auto_client_dir,
        &denied_xhttp_h3_auto_client_dir,
        &allowed_reality_client_dir,
        &denied_reality_client_dir,
    ] {
        fs::create_dir_all(directory).expect("create isolated process directory");
    }

    let mut targets = vec![
        HubOverlayEchoTarget::new(
            "10.200.1.0/24",
            Ipv4Addr::new(10, 200, 1, 20).into(),
            Ipv4Addr::new(127, 0, 0, 20).into(),
        ),
        HubOverlayEchoTarget::new(
            "10.200.1.0/24",
            Ipv4Addr::new(10, 200, 1, 21).into(),
            Ipv4Addr::new(127, 0, 0, 21).into(),
        ),
        HubOverlayEchoTarget::new(
            "10.200.2.0/24",
            Ipv4Addr::new(10, 200, 2, 30).into(),
            Ipv4Addr::new(127, 0, 1, 30).into(),
        ),
    ];
    let ipv6_probe = TcpListener::bind(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        0,
    ));
    match ipv6_probe {
        Ok(listener) => {
            drop(listener);
            targets.push(HubOverlayEchoTarget::new(
                "2001:db8:30::/64",
                "2001:db8:30::20"
                    .parse()
                    .expect("parse IPv6 Overlay target"),
                "::1".parse().expect("parse IPv6 Edge target"),
            ));
        }
        Err(error) => {
            assert!(
                std::env::var_os("REQUIRE_HUB_IPV6_OVERLAY").is_none(),
                "IPv6 Overlay test was required but IPv6 loopback is unavailable: {error}"
            );
            eprintln!(
                "skipping IPv6 Overlay CIDR subcase because IPv6 loopback is unavailable: {error}"
            );
        }
    }
    let hub_grpc_port = free_localhost_port();
    let hub_port = free_localhost_port();
    let hub_tls_port = free_localhost_port();
    let hub_ws_port = free_localhost_port();
    let hub_xhttp_port = free_localhost_port();
    let hub_xhttp_stream_up_port = free_localhost_port();
    let hub_xhttp_auto_port = free_localhost_port();
    let hub_xhttp_h3_port = free_localhost_udp_port();
    let hub_xhttp_h3_stream_up_port = free_localhost_udp_port();
    let hub_xhttp_h3_auto_port = free_localhost_udp_port();
    let hub_reality_port = free_localhost_port();
    let allowed_client_socks = free_localhost_port();
    let denied_client_socks = free_localhost_port();
    let allowed_tls_client_socks = free_localhost_port();
    let denied_tls_client_socks = free_localhost_port();
    let allowed_ws_client_socks = free_localhost_port();
    let denied_ws_client_socks = free_localhost_port();
    let allowed_xhttp_client_socks = free_localhost_port();
    let denied_xhttp_client_socks = free_localhost_port();
    let allowed_xhttp_stream_up_client_socks = free_localhost_port();
    let denied_xhttp_stream_up_client_socks = free_localhost_port();
    let allowed_xhttp_auto_client_socks = free_localhost_port();
    let denied_xhttp_auto_client_socks = free_localhost_port();
    let allowed_xhttp_h3_client_socks = free_localhost_port();
    let denied_xhttp_h3_client_socks = free_localhost_port();
    let unauthenticated_xhttp_h3_client_socks = free_localhost_port();
    let unauthenticated_xhttp_h3_stream_up_client_socks = free_localhost_port();
    let unauthenticated_xhttp_h3_auto_client_socks = free_localhost_port();
    let allowed_xhttp_h3_stream_up_client_socks = free_localhost_port();
    let denied_xhttp_h3_stream_up_client_socks = free_localhost_port();
    let allowed_xhttp_h3_auto_client_socks = free_localhost_port();
    let denied_xhttp_h3_auto_client_socks = free_localhost_port();
    let allowed_reality_client_socks = free_localhost_port();
    let denied_reality_client_socks = free_localhost_port();
    let hub_config = work_dir.join("hub.json");
    let edge_config = work_dir.join("edge.json");
    let allowed_client_config = work_dir.join("allowed-client.json");
    let denied_client_config = work_dir.join("denied-client.json");
    let allowed_tls_client_config = work_dir.join("allowed-tls-client.json");
    let denied_tls_client_config = work_dir.join("denied-tls-client.json");
    let allowed_ws_client_config = work_dir.join("allowed-ws-client.json");
    let denied_ws_client_config = work_dir.join("denied-ws-client.json");
    let allowed_xhttp_client_config = work_dir.join("allowed-xhttp-client.json");
    let denied_xhttp_client_config = work_dir.join("denied-xhttp-client.json");
    let allowed_xhttp_stream_up_client_config =
        work_dir.join("allowed-xhttp-stream-up-client.json");
    let denied_xhttp_stream_up_client_config =
        work_dir.join("denied-xhttp-stream-up-client.json");
    let allowed_xhttp_auto_client_config =
        work_dir.join("allowed-xhttp-auto-client.json");
    let denied_xhttp_auto_client_config =
        work_dir.join("denied-xhttp-auto-client.json");
    let allowed_xhttp_h3_client_config =
        work_dir.join("allowed-xhttp-h3-client.json");
    let denied_xhttp_h3_client_config = work_dir.join("denied-xhttp-h3-client.json");
    let unauthenticated_xhttp_h3_client_config =
        work_dir.join("unauthenticated-xhttp-h3-client.json");
    let unauthenticated_xhttp_h3_stream_up_client_config =
        work_dir.join("unauthenticated-xhttp-h3-stream-up-client.json");
    let unauthenticated_xhttp_h3_auto_client_config =
        work_dir.join("unauthenticated-xhttp-h3-auto-client.json");
    let allowed_xhttp_h3_stream_up_client_config =
        work_dir.join("allowed-xhttp-h3-stream-up-client.json");
    let denied_xhttp_h3_stream_up_client_config =
        work_dir.join("denied-xhttp-h3-stream-up-client.json");
    let allowed_xhttp_h3_auto_client_config =
        work_dir.join("allowed-xhttp-h3-auto-client.json");
    let denied_xhttp_h3_auto_client_config =
        work_dir.join("denied-xhttp-h3-auto-client.json");
    let allowed_reality_client_config = work_dir.join("allowed-reality-client.json");
    let denied_reality_client_config = work_dir.join("denied-reality-client.json");
    let (hub_tls_cert, hub_tls_key) = generate_test_certificate(&hub_dir);
    let hub_tls_cert_sha256 = first_cert_sha256_hex(&hub_tls_cert);

    const EDGE_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb7271";
    const ALLOWED_OFFICE_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb7272";
    const DENIED_OFFICE_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb7273";
    const UNREGISTERED_OFFICE_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb7274";
    const REALITY_PRIVATE_KEY: &str = "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI";
    const REALITY_PUBLIC_KEY: &str = "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg";
    const REALITY_SHORT_ID: &str = "4ac97aaf8b9b0356";

    let mut hub_rules = Vec::new();
    for target in &targets {
        hub_rules.push(json!({
            "type": "field",
            "inboundTag": ["hub-vless-in", "hub-vless-tls-in", "hub-vless-ws-in", "hub-vless-xhttp-in", "hub-vless-xhttp-stream-up-in", "hub-vless-xhttp-auto-in", "hub-vless-xhttp-h3-in", "hub-vless-xhttp-h3-stream-up-in", "hub-vless-xhttp-h3-auto-in", "hub-vless-reality-in"],
            "user": ["office-allowed@example.test"],
            "network": ["tcp"],
            "ip": [target.overlay_prefix],
            "port": target.tcp_allowed.port().to_string(),
            "outboundTag": "site-edge"
        }));
        hub_rules.push(json!({
            "type": "field",
            "inboundTag": ["hub-vless-in", "hub-vless-tls-in", "hub-vless-ws-in", "hub-vless-xhttp-in", "hub-vless-xhttp-stream-up-in", "hub-vless-xhttp-auto-in", "hub-vless-xhttp-h3-in", "hub-vless-xhttp-h3-stream-up-in", "hub-vless-xhttp-h3-auto-in", "hub-vless-reality-in"],
            "user": ["office-allowed@example.test"],
            "network": ["udp"],
            "ip": [target.overlay_prefix],
            "port": target.udp_allowed.port().to_string(),
            "outboundTag": "site-edge"
        }));
    }
    for prefix in HUB_OVERLAY_PROTECTED_PREFIXES {
        hub_rules.push(json!({
            "type": "field",
            "inboundTag": ["hub-vless-in", "hub-vless-tls-in", "hub-vless-ws-in", "hub-vless-xhttp-in", "hub-vless-xhttp-stream-up-in", "hub-vless-xhttp-auto-in", "hub-vless-xhttp-h3-in", "hub-vless-xhttp-h3-stream-up-in", "hub-vless-xhttp-h3-auto-in", "hub-vless-reality-in"],
            "ip": [prefix],
            "outboundTag": "overlay-default-deny"
        }));
    }
    let edge_ports = targets
        .iter()
        .flat_map(HubOverlayEchoTarget::edge_ports)
        .map(|port| port.to_string())
        .collect::<Vec<_>>();

    write_json(
        &hub_config,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": hub_port,
                    "protocol": "vless",
                    "tag": "hub-vless-in",
                    "settings": {
                        "clients": [
                            {
                                "id": EDGE_UUID,
                                "email": "site-edge@example.test",
                                "reverse": {"tag": "site-edge"}
                            },
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_tls_port,
                    "protocol": "vless",
                    "tag": "hub-vless-tls-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_ws_port,
                    "protocol": "vless",
                    "tag": "hub-vless-ws-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "wsSettings": {"path": "/hub-ws"}
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp",
                            "mode": "packet-up",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_stream_up_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-stream-up-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp-stream-up",
                            "mode": "stream-up",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_auto_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-auto-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp-auto",
                            "mode": "auto",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_h3_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-h3-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "alpn": ["h3"],
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp-h3",
                            "mode": "packet-up",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_h3_stream_up_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-h3-stream-up-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "alpn": ["h3"],
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp-h3-stream-up",
                            "mode": "stream-up",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_xhttp_h3_auto_port,
                    "protocol": "vless",
                    "tag": "hub-vless-xhttp-h3-auto-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "alpn": ["h3"],
                            "certificates": [{
                                "certificateFile": hub_tls_cert,
                                "keyFile": hub_tls_key
                            }]
                        },
                        "xhttpSettings": {
                            "path": "/hub-xhttp-h3-auto",
                            "mode": "auto",
                            "noGRPCHeader": true,
                            "noSSEHeader": true,
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": hub_reality_port,
                    "protocol": "vless",
                    "tag": "hub-vless-reality-in",
                    "settings": {
                        "clients": [
                            {
                                "id": ALLOWED_OFFICE_UUID,
                                "email": "office-allowed@example.test"
                            },
                            {
                                "id": DENIED_OFFICE_UUID,
                                "email": "office-unprivileged@example.test"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": format!("127.0.0.1:{hub_tls_port}"),
                            "serverNames": ["site-reality.test"],
                            "privateKey": REALITY_PRIVATE_KEY,
                            "shortIds": [REALITY_SHORT_ID]
                        }
                    }
                }
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "overlay-default-deny", "protocol": "blackhole"}
            ],
            "routing": {"rules": hub_rules},
            "api": {
                "listen": format!("127.0.0.1:{hub_grpc_port}"),
                "services": ["RoutingService"]
            }
        }),
    );

    write_json(
        &edge_config,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "site-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": hub_port,
                        "id": EDGE_UUID,
                        "encryption": "none",
                        "reverse": {
                            "tag": "site-edge",
                            "siteToSite": {
                                "prefixMaps": [
                                    {
                                        "from": "10.200.1.0/24",
                                        "to": "127.0.0.0/24"
                                    },
                                    {
                                        "from": "10.200.2.0/24",
                                        "to": "127.0.1.0/24"
                                    },
                                    {
                                        "from": "2001:db8:30::20/128",
                                        "to": "::1/128"
                                    }
                                ],
                                "allow": [{
                                    "network": ["tcp", "udp"],
                                    "ip": ["127.0.0.0/24", "127.0.1.0/24", "::1/128"],
                                    "ports": edge_ports.clone()
                                }]
                            }
                        }
                    }
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [{
                            "action": "allow",
                            "network": ["tcp", "udp"],
                            "ip": ["127.0.0.0/8", "::1/128"],
                            "port": edge_ports.join(",")
                        }]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["site-edge"],
                    "network": ["tcp", "udp"],
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    for (path, socks_port, user_id, server_port, tls) in [
        (
            &allowed_client_config,
            allowed_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_port,
            false,
        ),
        (
            &denied_client_config,
            denied_client_socks,
            DENIED_OFFICE_UUID,
            hub_port,
            false,
        ),
        (
            &allowed_tls_client_config,
            allowed_tls_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_tls_port,
            true,
        ),
        (
            &denied_tls_client_config,
            denied_tls_client_socks,
            DENIED_OFFICE_UUID,
            hub_tls_port,
            true,
        ),
    ] {
        let stream_settings = if tls {
            json!({
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "pinnedPeerCertSha256": hub_tls_cert_sha256
                }
            })
        } else {
            json!({"network": "tcp", "security": "none"})
        };
        write_json(
            path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-hub",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": server_port,
                            "users": [{"id": user_id, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": stream_settings
                }]
            }),
        );
    }

    for (path, socks_port, user_id) in [
        (
            &allowed_ws_client_config,
            allowed_ws_client_socks,
            ALLOWED_OFFICE_UUID,
        ),
        (
            &denied_ws_client_config,
            denied_ws_client_socks,
            DENIED_OFFICE_UUID,
        ),
    ] {
        write_json(
            path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-hub-ws",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": hub_ws_port,
                            "users": [{"id": user_id, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "pinnedPeerCertSha256": hub_tls_cert_sha256
                        },
                        "wsSettings": {"path": "/hub-ws"}
                    }
                }]
            }),
        );
    }

    for (path, socks_port, user_id, server_port, xhttp_path, mode, http3) in [
        (
            &allowed_xhttp_client_config,
            allowed_xhttp_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_port,
            "/hub-xhttp",
            "packet-up",
            false,
        ),
        (
            &denied_xhttp_client_config,
            denied_xhttp_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_port,
            "/hub-xhttp",
            "packet-up",
            false,
        ),
        (
            &allowed_xhttp_stream_up_client_config,
            allowed_xhttp_stream_up_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_stream_up_port,
            "/hub-xhttp-stream-up",
            "stream-up",
            false,
        ),
        (
            &denied_xhttp_stream_up_client_config,
            denied_xhttp_stream_up_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_stream_up_port,
            "/hub-xhttp-stream-up",
            "stream-up",
            false,
        ),
        (
            &allowed_xhttp_auto_client_config,
            allowed_xhttp_auto_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_auto_port,
            "/hub-xhttp-auto",
            "auto",
            false,
        ),
        (
            &denied_xhttp_auto_client_config,
            denied_xhttp_auto_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_auto_port,
            "/hub-xhttp-auto",
            "auto",
            false,
        ),
        (
            &allowed_xhttp_h3_client_config,
            allowed_xhttp_h3_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_h3_port,
            "/hub-xhttp-h3",
            "packet-up",
            true,
        ),
        (
            &denied_xhttp_h3_client_config,
            denied_xhttp_h3_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_h3_port,
            "/hub-xhttp-h3",
            "packet-up",
            true,
        ),
        (
            &unauthenticated_xhttp_h3_client_config,
            unauthenticated_xhttp_h3_client_socks,
            UNREGISTERED_OFFICE_UUID,
            hub_xhttp_h3_port,
            "/hub-xhttp-h3",
            "packet-up",
            true,
        ),
        (
            &unauthenticated_xhttp_h3_stream_up_client_config,
            unauthenticated_xhttp_h3_stream_up_client_socks,
            UNREGISTERED_OFFICE_UUID,
            hub_xhttp_h3_stream_up_port,
            "/hub-xhttp-h3-stream-up",
            "stream-up",
            true,
        ),
        (
            &unauthenticated_xhttp_h3_auto_client_config,
            unauthenticated_xhttp_h3_auto_client_socks,
            UNREGISTERED_OFFICE_UUID,
            hub_xhttp_h3_auto_port,
            "/hub-xhttp-h3-auto",
            "auto",
            true,
        ),
        (
            &allowed_xhttp_h3_stream_up_client_config,
            allowed_xhttp_h3_stream_up_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_h3_stream_up_port,
            "/hub-xhttp-h3-stream-up",
            "stream-up",
            true,
        ),
        (
            &denied_xhttp_h3_stream_up_client_config,
            denied_xhttp_h3_stream_up_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_h3_stream_up_port,
            "/hub-xhttp-h3-stream-up",
            "stream-up",
            true,
        ),
        (
            &allowed_xhttp_h3_auto_client_config,
            allowed_xhttp_h3_auto_client_socks,
            ALLOWED_OFFICE_UUID,
            hub_xhttp_h3_auto_port,
            "/hub-xhttp-h3-auto",
            "auto",
            true,
        ),
        (
            &denied_xhttp_h3_auto_client_config,
            denied_xhttp_h3_auto_client_socks,
            DENIED_OFFICE_UUID,
            hub_xhttp_h3_auto_port,
            "/hub-xhttp-h3-auto",
            "auto",
            true,
        ),
    ] {
        let tls_settings = if http3 {
            json!({
                "serverName": "localhost",
                "pinnedPeerCertSha256": hub_tls_cert_sha256,
                "alpn": ["h3"]
            })
        } else {
            json!({
                "serverName": "localhost",
                "pinnedPeerCertSha256": hub_tls_cert_sha256
            })
        };
        write_json(
            path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-hub",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": server_port,
                            "users": [{"id": user_id, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": tls_settings,
                        "xhttpSettings": {
                            "path": xhttp_path,
                            "mode": mode,
                            "noGRPCHeader": true,
                            "sessionPlacement": "header",
                            "sessionKey": "X-Session",
                            "sessionIDPlacement": "header",
                            "sessionIDKey": "X-Session",
                            "seqPlacement": "header",
                            "seqKey": "X-Seq",
                            "uplinkDataPlacement": "body"
                        }
                    }
                }]
            }),
        );
    }

    for (path, socks_port, user_id) in [
        (
            &allowed_reality_client_config,
            allowed_reality_client_socks,
            ALLOWED_OFFICE_UUID,
        ),
        (
            &denied_reality_client_config,
            denied_reality_client_socks,
            DENIED_OFFICE_UUID,
        ),
    ] {
        write_json(
            path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-hub-reality",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": hub_reality_port,
                            "users": [{"id": user_id, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "site-reality.test",
                            "fingerprint": "chrome",
                            "publicKey": REALITY_PUBLIC_KEY,
                            "shortId": REALITY_SHORT_ID
                        }
                    }
                }]
            }),
        );
    }

    let mut hub = start_chimera(&workspace, &hub_dir, &hub_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_tls_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_ws_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_xhttp_port)));
    wait_for_tcp(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        hub_xhttp_stream_up_port,
    )));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_xhttp_auto_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_reality_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, hub_grpc_port)));
    let grpc_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create dynamic routing gRPC client runtime");
    let grpc_channel = grpc_runtime.block_on(connect_grpc_channel(
        SocketAddr::from((Ipv4Addr::LOCALHOST, hub_grpc_port)),
    ));
    let mut edge = start_chimera(&workspace, &edge_dir, &edge_config);
    let mut allowed_client =
        start_xray(&workspace, &allowed_client_dir, &allowed_client_config);
    let mut denied_client =
        start_xray(&workspace, &denied_client_dir, &denied_client_config);
    let mut allowed_tls_client = start_xray(
        &workspace,
        &allowed_tls_client_dir,
        &allowed_tls_client_config,
    );
    let mut denied_tls_client = start_xray(
        &workspace,
        &denied_tls_client_dir,
        &denied_tls_client_config,
    );
    let mut allowed_ws_client = start_xray(
        &workspace,
        &allowed_ws_client_dir,
        &allowed_ws_client_config,
    );
    let mut denied_ws_client =
        start_xray(&workspace, &denied_ws_client_dir, &denied_ws_client_config);
    let mut allowed_xhttp_client = start_xray(
        &workspace,
        &allowed_xhttp_client_dir,
        &allowed_xhttp_client_config,
    );
    let mut denied_xhttp_client = start_xray(
        &workspace,
        &denied_xhttp_client_dir,
        &denied_xhttp_client_config,
    );
    let mut allowed_xhttp_stream_up_client = start_xray(
        &workspace,
        &allowed_xhttp_stream_up_client_dir,
        &allowed_xhttp_stream_up_client_config,
    );
    let mut denied_xhttp_stream_up_client = start_xray(
        &workspace,
        &denied_xhttp_stream_up_client_dir,
        &denied_xhttp_stream_up_client_config,
    );
    let mut allowed_xhttp_auto_client = start_xray(
        &workspace,
        &allowed_xhttp_auto_client_dir,
        &allowed_xhttp_auto_client_config,
    );
    let mut denied_xhttp_auto_client = start_xray(
        &workspace,
        &denied_xhttp_auto_client_dir,
        &denied_xhttp_auto_client_config,
    );
    let mut allowed_xhttp_h3_client = start_xray(
        &workspace,
        &allowed_xhttp_h3_client_dir,
        &allowed_xhttp_h3_client_config,
    );
    let mut denied_xhttp_h3_client = start_xray(
        &workspace,
        &denied_xhttp_h3_client_dir,
        &denied_xhttp_h3_client_config,
    );
    let mut unauthenticated_xhttp_h3_client = start_xray(
        &workspace,
        &unauthenticated_xhttp_h3_client_dir,
        &unauthenticated_xhttp_h3_client_config,
    );
    let mut unauthenticated_xhttp_h3_stream_up_client = start_xray(
        &workspace,
        &unauthenticated_xhttp_h3_stream_up_client_dir,
        &unauthenticated_xhttp_h3_stream_up_client_config,
    );
    let mut unauthenticated_xhttp_h3_auto_client = start_xray(
        &workspace,
        &unauthenticated_xhttp_h3_auto_client_dir,
        &unauthenticated_xhttp_h3_auto_client_config,
    );
    let mut allowed_xhttp_h3_stream_up_client = start_xray(
        &workspace,
        &allowed_xhttp_h3_stream_up_client_dir,
        &allowed_xhttp_h3_stream_up_client_config,
    );
    let mut denied_xhttp_h3_stream_up_client = start_xray(
        &workspace,
        &denied_xhttp_h3_stream_up_client_dir,
        &denied_xhttp_h3_stream_up_client_config,
    );
    let mut allowed_xhttp_h3_auto_client = start_xray(
        &workspace,
        &allowed_xhttp_h3_auto_client_dir,
        &allowed_xhttp_h3_auto_client_config,
    );
    let mut denied_xhttp_h3_auto_client = start_xray(
        &workspace,
        &denied_xhttp_h3_auto_client_dir,
        &denied_xhttp_h3_auto_client_config,
    );
    let mut allowed_reality_client = start_xray(
        &workspace,
        &allowed_reality_client_dir,
        &allowed_reality_client_config,
    );
    let mut denied_reality_client = start_xray(
        &workspace,
        &denied_reality_client_dir,
        &denied_reality_client_config,
    );
    let allowed_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_client_socks));
    let denied_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_client_socks));
    let allowed_tls_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_tls_client_socks));
    let denied_tls_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_tls_client_socks));
    let allowed_ws_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_ws_client_socks));
    let denied_ws_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_ws_client_socks));
    let allowed_xhttp_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_xhttp_client_socks));
    let denied_xhttp_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_xhttp_client_socks));
    let allowed_xhttp_stream_up_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        allowed_xhttp_stream_up_client_socks,
    ));
    let denied_xhttp_stream_up_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_xhttp_stream_up_client_socks));
    let allowed_xhttp_auto_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_xhttp_auto_client_socks));
    let denied_xhttp_auto_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_xhttp_auto_client_socks));
    let allowed_xhttp_h3_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_xhttp_h3_client_socks));
    let denied_xhttp_h3_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_xhttp_h3_client_socks));
    let unauthenticated_xhttp_h3_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        unauthenticated_xhttp_h3_client_socks,
    ));
    let unauthenticated_xhttp_h3_stream_up_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        unauthenticated_xhttp_h3_stream_up_client_socks,
    ));
    let unauthenticated_xhttp_h3_auto_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        unauthenticated_xhttp_h3_auto_client_socks,
    ));
    let allowed_xhttp_h3_stream_up_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        allowed_xhttp_h3_stream_up_client_socks,
    ));
    let denied_xhttp_h3_stream_up_socks_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        denied_xhttp_h3_stream_up_client_socks,
    ));
    let allowed_xhttp_h3_auto_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_xhttp_h3_auto_client_socks));
    let denied_xhttp_h3_auto_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_xhttp_h3_auto_client_socks));
    let allowed_reality_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, allowed_reality_client_socks));
    let denied_reality_socks_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, denied_reality_client_socks));
    wait_for_tcp(allowed_socks_addr);
    wait_for_tcp(denied_socks_addr);
    wait_for_tcp(allowed_tls_socks_addr);
    wait_for_tcp(denied_tls_socks_addr);
    wait_for_tcp(allowed_ws_socks_addr);
    wait_for_tcp(denied_ws_socks_addr);
    wait_for_tcp(allowed_xhttp_socks_addr);
    wait_for_tcp(denied_xhttp_socks_addr);
    wait_for_tcp(allowed_xhttp_stream_up_socks_addr);
    wait_for_tcp(denied_xhttp_stream_up_socks_addr);
    wait_for_tcp(allowed_xhttp_auto_socks_addr);
    wait_for_tcp(denied_xhttp_auto_socks_addr);
    wait_for_tcp(allowed_xhttp_h3_socks_addr);
    wait_for_tcp(denied_xhttp_h3_socks_addr);
    wait_for_tcp(unauthenticated_xhttp_h3_socks_addr);
    wait_for_tcp(unauthenticated_xhttp_h3_stream_up_socks_addr);
    wait_for_tcp(unauthenticated_xhttp_h3_auto_socks_addr);
    wait_for_tcp(allowed_xhttp_h3_stream_up_socks_addr);
    wait_for_tcp(denied_xhttp_h3_stream_up_socks_addr);
    wait_for_tcp(allowed_xhttp_h3_auto_socks_addr);
    wait_for_tcp(denied_xhttp_h3_auto_socks_addr);
    wait_for_tcp(allowed_reality_socks_addr);
    wait_for_tcp(denied_reality_socks_addr);

    for (index, target) in targets.iter().enumerate() {
        let marker = format!("hub-multi-prefix-tcp-allow-{index}");
        assert_socks5_echo_with_retry(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            marker.as_bytes(),
            &target.tcp_allowed_bytes,
        );
    }
    let allowed_tcp_bytes_before_denials = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_target_denied(
            allowed_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-prefix-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-prefix-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            allowed_tcp_bytes_before_denials[index],
            "unauthorized Hub TCP requests must not reach target {index}"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "Hub must deny an unlisted TCP port before Edge dispatch for target {index}"
        );
    }

    // The same identity and CIDR policy must apply to Office clients using
    // the Hub's TLS-protected VLESS listener.
    let tls_tcp_before = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_echo_with_retry(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-tls-static-tcp",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_target_denied(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-tls-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-tls-tcp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            tls_tcp_before[index] + b"hub-tls-static-tcp".len(),
            "TLS-authorized TCP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "TLS Hub must deny an unlisted TCP port before Edge dispatch for target {index}"
        );
    }

    let ws_tcp_before = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_echo_with_retry(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-ws-static-tcp",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_target_denied(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-ws-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-ws-tcp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            ws_tcp_before[index] + b"hub-ws-static-tcp".len(),
            "WebSocket/TLS-authorized TCP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "WebSocket/TLS Hub must deny an unlisted TCP port before Edge dispatch for target {index}"
        );
    }

    let allowed_udp_association =
        XraySocksUdpAssociation::connect(allowed_socks_addr);
    let denied_udp_association = XraySocksUdpAssociation::connect(denied_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        let marker = format!("hub-multi-prefix-udp-allow-{index}");
        allowed_udp_association.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            marker.as_bytes(),
        );
    }
    let allowed_udp_bytes_before_denials = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        allowed_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-prefix-udp-port-denial-{index}").as_bytes(),
        );
        denied_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-prefix-udp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            allowed_udp_bytes_before_denials[index],
            "unauthorized Hub UDP requests must not reach target {index}"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "Hub must deny an unlisted UDP port before Edge dispatch for target {index}"
        );
    }

    let tls_udp_before = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let allowed_tls_udp_association =
        XraySocksUdpAssociation::connect(allowed_tls_socks_addr);
    let denied_tls_udp_association =
        XraySocksUdpAssociation::connect(denied_tls_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        allowed_tls_udp_association.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-tls-static-udp",
        );
        allowed_tls_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-tls-udp-port-denial-{index}").as_bytes(),
        );
        denied_tls_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-tls-udp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            tls_udp_before[index] + b"hub-tls-static-udp".len(),
            "TLS-authorized UDP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "TLS Hub must deny an unlisted UDP port before Edge dispatch for target {index}"
        );
    }

    let ws_udp_before = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let allowed_ws_udp_association =
        XraySocksUdpAssociation::connect(allowed_ws_socks_addr);
    let denied_ws_udp_association =
        XraySocksUdpAssociation::connect(denied_ws_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        allowed_ws_udp_association.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-ws-static-udp",
        );
        allowed_ws_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-ws-udp-port-denial-{index}").as_bytes(),
        );
        denied_ws_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-ws-udp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            ws_udp_before[index] + b"hub-ws-static-udp".len(),
            "WebSocket/TLS-authorized UDP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "WebSocket/TLS Hub must deny an unlisted UDP port before Edge dispatch for target {index}"
        );
    }

    let reality_tcp_before = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_echo_with_retry(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-reality-static-tcp",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_target_denied(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-reality-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-reality-tcp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            reality_tcp_before[index] + b"hub-reality-static-tcp".len(),
            "REALITY-authorized TCP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "REALITY Hub must deny an unlisted TCP port before Edge dispatch for target {index}"
        );
    }

    let reality_udp_before = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let allowed_reality_udp_association =
        XraySocksUdpAssociation::connect(allowed_reality_socks_addr);
    let denied_reality_udp_association =
        XraySocksUdpAssociation::connect(denied_reality_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        allowed_reality_udp_association.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-reality-static-udp",
        );
        allowed_reality_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-reality-udp-port-denial-{index}").as_bytes(),
        );
        denied_reality_udp_association.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-reality-udp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            reality_udp_before[index] + b"hub-reality-static-udp".len(),
            "REALITY-authorized UDP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "REALITY Hub must deny an unlisted UDP port before Edge dispatch for target {index}"
        );
    }

    let xhttp_tcp_before = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_echo_with_retry(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-static-tcp",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_target_denied(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-xhttp-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-xhttp-tcp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            xhttp_tcp_before[index] + b"hub-xhttp-static-tcp".len(),
            "XHTTP-authorized TCP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "XHTTP Hub must deny an unlisted TCP port before Edge dispatch for target {index}"
        );
    }
    let xhttp_udp_before = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let allowed_xhttp_udp =
        XraySocksUdpAssociation::connect(allowed_xhttp_socks_addr);
    let denied_xhttp_udp = XraySocksUdpAssociation::connect(denied_xhttp_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        allowed_xhttp_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-static-udp",
        );
        allowed_xhttp_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-xhttp-udp-port-denial-{index}").as_bytes(),
        );
        denied_xhttp_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-xhttp-udp-identity-denial-{index}").as_bytes(),
        );
    }
    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            xhttp_udp_before[index] + b"hub-xhttp-static-udp".len(),
            "XHTTP-authorized UDP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "XHTTP Hub must deny an unlisted UDP port before Edge dispatch for target {index}"
        );
    }
    assert_hub_xhttp_profile_static_policy(
        "stream-up",
        allowed_xhttp_stream_up_socks_addr,
        denied_xhttp_stream_up_socks_addr,
        &targets,
    );
    assert_hub_xhttp_profile_static_policy(
        "auto",
        allowed_xhttp_auto_socks_addr,
        denied_xhttp_auto_socks_addr,
        &targets,
    );
    assert_hub_xhttp_profile_static_policy(
        "h3-packet-up",
        allowed_xhttp_h3_socks_addr,
        denied_xhttp_h3_socks_addr,
        &targets,
    );
    assert_hub_xhttp_profile_static_policy(
        "h3-stream-up",
        allowed_xhttp_h3_stream_up_socks_addr,
        denied_xhttp_h3_stream_up_socks_addr,
        &targets,
    );
    assert_hub_xhttp_profile_static_policy(
        "h3-auto",
        allowed_xhttp_h3_auto_socks_addr,
        denied_xhttp_h3_auto_socks_addr,
        &targets,
    );
    let h3_auth_target = &targets[0];
    let h3_tcp_bytes_before_bad_auth =
        h3_auth_target.tcp_allowed_bytes.load(Ordering::SeqCst);
    let h3_udp_bytes_before_bad_auth =
        h3_auth_target.udp_allowed_bytes.load(Ordering::SeqCst);
    assert_socks5_target_denied(
        unauthenticated_xhttp_h3_socks_addr,
        h3_auth_target.overlay_target(h3_auth_target.tcp_allowed.port()),
        b"hub-xhttp-h3-unregistered-uuid-tcp",
    );
    let unauthenticated_h3_udp =
        XraySocksUdpAssociation::connect(unauthenticated_xhttp_h3_socks_addr);
    unauthenticated_h3_udp.send_and_expect_no_response(
        h3_auth_target.overlay_target(h3_auth_target.udp_allowed.port()),
        b"hub-xhttp-h3-unregistered-uuid-udp",
    );
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        h3_auth_target.tcp_allowed_bytes.load(Ordering::SeqCst),
        h3_tcp_bytes_before_bad_auth,
        "unregistered H3 VLESS UUID must not reach the TCP target"
    );
    assert_eq!(
        h3_auth_target.udp_allowed_bytes.load(Ordering::SeqCst),
        h3_udp_bytes_before_bad_auth,
        "unregistered H3 VLESS UUID must not reach the UDP target"
    );
    for (profile, socks_addr) in [
        ("stream-up", unauthenticated_xhttp_h3_stream_up_socks_addr),
        ("auto", unauthenticated_xhttp_h3_auto_socks_addr),
    ] {
        let tcp_bytes_before =
            h3_auth_target.tcp_allowed_bytes.load(Ordering::SeqCst);
        let udp_bytes_before =
            h3_auth_target.udp_allowed_bytes.load(Ordering::SeqCst);
        assert_socks5_target_denied(
            socks_addr,
            h3_auth_target.overlay_target(h3_auth_target.tcp_allowed.port()),
            format!("hub-xhttp-h3-{profile}-unregistered-uuid-tcp").as_bytes(),
        );
        let association = XraySocksUdpAssociation::connect(socks_addr);
        association.send_and_expect_no_response(
            h3_auth_target.overlay_target(h3_auth_target.udp_allowed.port()),
            format!("hub-xhttp-h3-{profile}-unregistered-uuid-udp").as_bytes(),
        );
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            h3_auth_target.tcp_allowed_bytes.load(Ordering::SeqCst),
            tcp_bytes_before,
            "unregistered H3 {profile} VLESS UUID must not reach the TCP target"
        );
        assert_eq!(
            h3_auth_target.udp_allowed_bytes.load(Ordering::SeqCst),
            udp_bytes_before,
            "unregistered H3 {profile} VLESS UUID must not reach the UDP target"
        );
    }

    let target_two_tcp_before_dynamic =
        targets[2].tcp_allowed_bytes.load(Ordering::SeqCst);
    let target_two_udp_before_dynamic =
        targets[2].udp_allowed_bytes.load(Ordering::SeqCst);

    replace_dynamic_hub_policy(&grpc_runtime, &grpc_channel, &["10.200.1.0/24"]);
    let listed_rules = grpc_runtime
        .block_on(
            grpc_unary::<DynamicListRuleRequest, DynamicListRuleResponse>(
                grpc_channel.clone(),
                ROUTING_LIST_RULE_PATH,
                DynamicListRuleRequest {},
            ),
        )
        .expect("list runtime Hub authorization rules");
    assert!(listed_rules.rules.iter().any(|rule| {
        rule.rule_tag == "hub-site-allow-prefix-0" && rule.tag == "site-edge"
    }));

    for target in &targets[..2] {
        let marker = b"hub-dynamic-prefix-allow";
        assert_socks5_echo_with_retry(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            marker,
            &target.tcp_allowed_bytes,
        );
    }
    for target in &targets[..2] {
        assert_socks5_echo_with_retry(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-tls-dynamic-prefix-allow",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_echo_with_retry(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-ws-dynamic-prefix-allow",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_echo_with_retry(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-dynamic-prefix-allow",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_echo_with_retry(
            allowed_xhttp_h3_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-h3-dynamic-prefix-allow",
            &target.tcp_allowed_bytes,
        );
        assert_socks5_echo_with_retry(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-reality-dynamic-prefix-allow",
            &target.tcp_allowed_bytes,
        );
    }
    for (profile, socks_addr) in [
        ("stream-up", allowed_xhttp_stream_up_socks_addr),
        ("auto", allowed_xhttp_auto_socks_addr),
        ("h3-stream-up", allowed_xhttp_h3_stream_up_socks_addr),
        ("h3-auto", allowed_xhttp_h3_auto_socks_addr),
    ] {
        let marker = format!("hub-xhttp-{profile}-dynamic-prefix-allow");
        for target in &targets[..2] {
            assert_socks5_echo_with_retry(
                socks_addr,
                target.overlay_target(target.tcp_allowed.port()),
                marker.as_bytes(),
                &target.tcp_allowed_bytes,
            );
        }
        assert_socks5_target_denied(
            socks_addr,
            targets[2].overlay_target(targets[2].tcp_allowed.port()),
            format!("hub-xhttp-{profile}-dynamic-prefix-deny").as_bytes(),
        );
        let association = XraySocksUdpAssociation::connect(socks_addr);
        let udp_marker = format!("hub-xhttp-{profile}-dynamic-prefix-udp-allow");
        for target in &targets[..2] {
            association.send_and_expect_echo(
                target.overlay_target(target.udp_allowed.port()),
                udp_marker.as_bytes(),
            );
        }
        association.send_and_expect_no_response(
            targets[2].overlay_target(targets[2].udp_allowed.port()),
            format!("hub-xhttp-{profile}-dynamic-prefix-udp-deny").as_bytes(),
        );
    }
    assert_socks5_target_denied(
        allowed_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        allowed_tls_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-tls-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        allowed_ws_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-ws-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        allowed_xhttp_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-xhttp-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        allowed_xhttp_h3_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-xhttp-h3-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        allowed_reality_socks_addr,
        targets[2].overlay_target(targets[2].tcp_allowed.port()),
        b"hub-reality-dynamic-prefix-deny",
    );
    assert_socks5_target_denied(
        denied_socks_addr,
        targets[0].overlay_target(targets[0].tcp_allowed.port()),
        b"hub-dynamic-identity-deny",
    );

    let dynamic_udp = XraySocksUdpAssociation::connect(allowed_socks_addr);
    let dynamic_tls_udp = XraySocksUdpAssociation::connect(allowed_tls_socks_addr);
    let dynamic_ws_udp = XraySocksUdpAssociation::connect(allowed_ws_socks_addr);
    let dynamic_xhttp_udp =
        XraySocksUdpAssociation::connect(allowed_xhttp_socks_addr);
    let dynamic_xhttp_h3_udp =
        XraySocksUdpAssociation::connect(allowed_xhttp_h3_socks_addr);
    let dynamic_reality_udp =
        XraySocksUdpAssociation::connect(allowed_reality_socks_addr);
    for target in &targets[..2] {
        dynamic_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-dynamic-prefix-udp-allow",
        );
        dynamic_tls_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-tls-dynamic-prefix-udp-allow",
        );
        dynamic_ws_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-ws-dynamic-prefix-udp-allow",
        );
        dynamic_xhttp_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-dynamic-prefix-udp-allow",
        );
        dynamic_xhttp_h3_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-h3-dynamic-prefix-udp-allow",
        );
        dynamic_reality_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-reality-dynamic-prefix-udp-allow",
        );
    }
    dynamic_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-dynamic-prefix-udp-deny",
    );
    dynamic_tls_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-tls-dynamic-prefix-udp-deny",
    );
    dynamic_ws_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-ws-dynamic-prefix-udp-deny",
    );
    dynamic_xhttp_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-xhttp-dynamic-prefix-udp-deny",
    );
    dynamic_xhttp_h3_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-xhttp-h3-dynamic-prefix-udp-deny",
    );
    dynamic_reality_udp.send_and_expect_no_response(
        targets[2].overlay_target(targets[2].udp_allowed.port()),
        b"hub-reality-dynamic-prefix-udp-deny",
    );
    let denied_identity_udp = XraySocksUdpAssociation::connect(denied_socks_addr);
    denied_identity_udp.send_and_expect_no_response(
        targets[0].overlay_target(targets[0].udp_allowed.port()),
        b"hub-dynamic-identity-udp-deny",
    );
    if let Some(target) = targets.get(3) {
        assert_socks5_target_denied(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-dynamic-ipv6-deny",
        );
        dynamic_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-dynamic-ipv6-udp-deny",
        );
        assert_socks5_target_denied(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-tls-dynamic-ipv6-deny",
        );
        dynamic_tls_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-tls-dynamic-ipv6-udp-deny",
        );
        assert_socks5_target_denied(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-ws-dynamic-ipv6-deny",
        );
        dynamic_ws_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-ws-dynamic-ipv6-udp-deny",
        );
        assert_socks5_target_denied(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-deny",
        );
        assert_socks5_target_denied(
            allowed_xhttp_h3_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-deny",
        );
        dynamic_xhttp_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-udp-deny",
        );
        dynamic_xhttp_h3_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-udp-deny",
        );
        for (profile, socks_addr) in [
            ("stream-up", allowed_xhttp_stream_up_socks_addr),
            ("auto", allowed_xhttp_auto_socks_addr),
            ("h3-stream-up", allowed_xhttp_h3_stream_up_socks_addr),
            ("h3-auto", allowed_xhttp_h3_auto_socks_addr),
        ] {
            assert_socks5_target_denied(
                socks_addr,
                target.overlay_target(target.tcp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-deny").as_bytes(),
            );
            let association = XraySocksUdpAssociation::connect(socks_addr);
            association.send_and_expect_no_response(
                target.overlay_target(target.udp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-udp-deny").as_bytes(),
            );
        }
        assert_socks5_target_denied(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-reality-dynamic-ipv6-deny",
        );
        dynamic_reality_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-reality-dynamic-ipv6-udp-deny",
        );
    }

    replace_dynamic_hub_policy(
        &grpc_runtime,
        &grpc_channel,
        &["10.200.1.0/24", "2001:db8:30::/64"],
    );
    if let Some(target) = targets.get(3) {
        assert_socks5_echo_with_retry(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let ipv6_udp = XraySocksUdpAssociation::connect(allowed_socks_addr);
        ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-dynamic-ipv6-udp-allow",
        );
        assert_socks5_echo_with_retry(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-tls-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let tls_ipv6_udp = XraySocksUdpAssociation::connect(allowed_tls_socks_addr);
        tls_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-tls-dynamic-ipv6-udp-allow",
        );
        assert_socks5_echo_with_retry(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-ws-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let ws_ipv6_udp = XraySocksUdpAssociation::connect(allowed_ws_socks_addr);
        ws_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-ws-dynamic-ipv6-udp-allow",
        );
        assert_socks5_echo_with_retry(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let xhttp_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_socks_addr);
        xhttp_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-udp-allow",
        );
        assert_socks5_echo_with_retry(
            allowed_xhttp_h3_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let h3_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_h3_socks_addr);
        h3_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-udp-allow",
        );
        let mut xhttp_stream_up_ipv6_tcp = connect_socks5_target_for_vless(
            allowed_xhttp_stream_up_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
        )
        .expect("establish XHTTP stream-up IPv6 TCP before rule removal");
        let mut xhttp_auto_ipv6_tcp = connect_socks5_target_for_vless(
            allowed_xhttp_auto_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
        )
        .expect("establish XHTTP auto IPv6 TCP before rule removal");
        for (stream, profile) in [
            (&mut xhttp_stream_up_ipv6_tcp, "stream-up"),
            (&mut xhttp_auto_ipv6_tcp, "auto"),
        ] {
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("set XHTTP IPv6 TCP read timeout");
            stream
                .set_write_timeout(Some(IO_TIMEOUT))
                .expect("set XHTTP IPv6 TCP write timeout");
            let marker = format!("hub-xhttp-{profile}-dynamic-ipv6-allow");
            stream
                .write_all(marker.as_bytes())
                .expect("write XHTTP IPv6 TCP");
            let mut response = vec![0; marker.len()];
            stream
                .read_exact(&mut response)
                .expect("read XHTTP IPv6 TCP echo");
            assert_eq!(response, marker.as_bytes());
        }
        let xhttp_stream_up_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_stream_up_socks_addr);
        xhttp_stream_up_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-stream-up-dynamic-ipv6-udp-allow",
        );
        let xhttp_auto_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_auto_socks_addr);
        xhttp_auto_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-auto-dynamic-ipv6-udp-allow",
        );
        let mut h3_mode_ipv6_udp = Vec::new();
        for (profile, socks_addr) in [
            ("h3-stream-up", allowed_xhttp_h3_stream_up_socks_addr),
            ("h3-auto", allowed_xhttp_h3_auto_socks_addr),
        ] {
            assert_socks5_echo_with_retry(
                socks_addr,
                target.overlay_target(target.tcp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-allow").as_bytes(),
                &target.tcp_allowed_bytes,
            );
            let association = XraySocksUdpAssociation::connect(socks_addr);
            association.send_and_expect_echo(
                target.overlay_target(target.udp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-udp-allow").as_bytes(),
            );
            h3_mode_ipv6_udp.push((profile, association));
        }
        assert_socks5_echo_with_retry(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-reality-dynamic-ipv6-allow",
            &target.tcp_allowed_bytes,
        );
        let reality_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_reality_socks_addr);
        reality_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-reality-dynamic-ipv6-udp-allow",
        );
        let mut established_ipv6_tcp = connect_socks5_target_for_vless(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
        )
        .expect("establish IPv6 TCP flow before rule removal");
        established_ipv6_tcp
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set established IPv6 TCP read timeout");
        established_ipv6_tcp
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("set established IPv6 TCP write timeout");
        let before_update_marker = b"established flow before route update";
        established_ipv6_tcp
            .write_all(before_update_marker)
            .expect("write on established flow before rule removal");
        let mut before_update_echo = vec![0; before_update_marker.len()];
        established_ipv6_tcp
            .read_exact(&mut before_update_echo)
            .expect("read established flow before rule removal");
        assert_eq!(before_update_echo, before_update_marker);
        let ipv6_tcp_before_removal =
            target.tcp_allowed_bytes.load(Ordering::SeqCst);
        let ipv6_udp_before_removal =
            target.udp_allowed_bytes.load(Ordering::SeqCst);

        remove_dynamic_hub_rule(
            &grpc_runtime,
            &grpc_channel,
            "hub-site-allow-prefix-1",
        );
        // Xray routing selects an outbound when it dispatches the UDP session.
        // Removing the rule blocks new sessions but must not silently tear down
        // packets already attached to the selected Reverse target.
        let active_raw_udp = b"established raw UDP survives route removal";
        let active_tls_udp = b"established TLS UDP survives route removal";
        let active_ws_udp = b"established WebSocket UDP survives route removal";
        let active_xhttp_udp = b"established XHTTP UDP survives route removal";
        let active_xhttp_h3_udp = b"established XHTTP H3 UDP survives route removal";
        let active_xhttp_stream_up_udp =
            b"established XHTTP stream-up UDP survives route removal";
        let active_xhttp_auto_udp =
            b"established XHTTP auto UDP survives route removal";
        let mut active_h3_mode_udp_bytes = 0;
        for (profile, association) in &h3_mode_ipv6_udp {
            let marker = format!("established {profile} UDP survives route removal");
            association.send_and_expect_echo(
                target.overlay_target(target.udp_allowed.port()),
                marker.as_bytes(),
            );
            active_h3_mode_udp_bytes += marker.len();
        }
        let active_reality_udp = b"established REALITY UDP survives route removal";
        ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_raw_udp,
        );
        tls_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_tls_udp,
        );
        ws_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_ws_udp,
        );
        xhttp_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_xhttp_udp,
        );
        h3_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_xhttp_h3_udp,
        );
        xhttp_stream_up_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_xhttp_stream_up_udp,
        );
        xhttp_auto_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_xhttp_auto_udp,
        );
        reality_ipv6_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            active_reality_udp,
        );
        let ipv6_udp_after_active_echo =
            target.udp_allowed_bytes.load(Ordering::SeqCst);
        assert_eq!(
            ipv6_udp_after_active_echo,
            ipv6_udp_before_removal
                + active_raw_udp.len()
                + active_tls_udp.len()
                + active_ws_udp.len()
                + active_xhttp_udp.len()
                + active_xhttp_h3_udp.len()
                + active_xhttp_stream_up_udp.len()
                + active_xhttp_auto_udp.len()
                + active_h3_mode_udp_bytes
                + active_reality_udp.len(),
            "existing RAW/TLS/WebSocket/all XHTTP/REALITY UDP sessions continue after rule removal"
        );
        let active_marker = b"established flow survives route update";
        established_ipv6_tcp
            .write_all(active_marker)
            .expect("write on established flow after rule removal");
        let mut active_echo = vec![0; active_marker.len()];
        established_ipv6_tcp
            .read_exact(&mut active_echo)
            .expect("read established flow response after rule removal");
        assert_eq!(active_echo, active_marker);
        let ipv6_tcp_after_active_echo =
            target.tcp_allowed_bytes.load(Ordering::SeqCst);

        assert_socks5_target_denied(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-dynamic-ipv6-removed",
        );
        assert_socks5_target_denied(
            allowed_tls_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-tls-dynamic-ipv6-removed",
        );
        assert_socks5_target_denied(
            allowed_ws_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-ws-dynamic-ipv6-removed",
        );
        assert_socks5_target_denied(
            allowed_xhttp_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-removed",
        );
        assert_socks5_target_denied(
            allowed_xhttp_h3_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-removed",
        );
        for (profile, socks_addr) in [
            ("stream-up", allowed_xhttp_stream_up_socks_addr),
            ("auto", allowed_xhttp_auto_socks_addr),
            ("h3-stream-up", allowed_xhttp_h3_stream_up_socks_addr),
            ("h3-auto", allowed_xhttp_h3_auto_socks_addr),
        ] {
            assert_socks5_target_denied(
                socks_addr,
                target.overlay_target(target.tcp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-removed").as_bytes(),
            );
            let removed_udp = XraySocksUdpAssociation::connect(socks_addr);
            removed_udp.send_and_expect_no_response(
                target.overlay_target(target.udp_allowed.port()),
                format!("hub-xhttp-{profile}-dynamic-ipv6-udp-removed").as_bytes(),
            );
        }
        let removed_ipv6_udp = XraySocksUdpAssociation::connect(allowed_socks_addr);
        removed_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-dynamic-ipv6-udp-removed",
        );
        let removed_tls_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_tls_socks_addr);
        removed_tls_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-tls-dynamic-ipv6-udp-removed",
        );
        let removed_ws_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_ws_socks_addr);
        removed_ws_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-ws-dynamic-ipv6-udp-removed",
        );
        let removed_xhttp_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_socks_addr);
        removed_xhttp_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-dynamic-ipv6-udp-removed",
        );
        let removed_xhttp_h3_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_xhttp_h3_socks_addr);
        removed_xhttp_h3_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-xhttp-h3-dynamic-ipv6-udp-removed",
        );
        assert_socks5_target_denied(
            allowed_reality_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            b"hub-reality-dynamic-ipv6-removed",
        );
        let removed_reality_ipv6_udp =
            XraySocksUdpAssociation::connect(allowed_reality_socks_addr);
        removed_reality_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            b"hub-reality-dynamic-ipv6-udp-removed",
        );
        ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established UDP association is denied after rule removal",
        );
        tls_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established TLS UDP association is denied after rule removal",
        );
        ws_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established WebSocket UDP association is denied after rule removal",
        );
        xhttp_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established XHTTP UDP association is denied after rule removal",
        );
        h3_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established XHTTP H3 UDP association is denied after rule removal",
        );
        xhttp_stream_up_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established XHTTP stream-up UDP association is denied after rule removal",
        );
        xhttp_auto_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established XHTTP auto UDP association is denied after rule removal",
        );
        for (profile, association) in &h3_mode_ipv6_udp {
            association.send_and_expect_no_response(
                target.overlay_target(target.udp_denied.port()),
                format!(
                    "new target on established XHTTP {profile} UDP association is denied after rule removal"
                )
                .as_bytes(),
            );
        }
        reality_ipv6_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            b"new target on established REALITY UDP association is denied after rule removal",
        );
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            ipv6_tcp_after_active_echo,
            "new TCP requests after rule removal must not reach Edge"
        );
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            ipv6_udp_after_active_echo,
            "new UDP sessions after rule removal must not reach Edge"
        );
        assert!(
            ipv6_tcp_after_active_echo > ipv6_tcp_before_removal,
            "the established TCP session must continue after route removal"
        );
    }
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        targets[2].tcp_allowed_bytes.load(Ordering::SeqCst),
        target_two_tcp_before_dynamic,
        "dynamically denied IPv4 prefix must not reach Edge"
    );
    assert_eq!(
        targets[2].udp_allowed_bytes.load(Ordering::SeqCst),
        target_two_udp_before_dynamic,
        "dynamically denied IPv4 UDP prefix must not reach Edge"
    );
    hub.assert_running();
    edge.assert_running();
    allowed_client.assert_running();
    denied_client.assert_running();
    allowed_tls_client.assert_running();
    denied_tls_client.assert_running();
    allowed_ws_client.assert_running();
    denied_ws_client.assert_running();
    allowed_xhttp_client.assert_running();
    denied_xhttp_client.assert_running();
    allowed_xhttp_stream_up_client.assert_running();
    denied_xhttp_stream_up_client.assert_running();
    allowed_xhttp_auto_client.assert_running();
    denied_xhttp_auto_client.assert_running();
    allowed_xhttp_h3_client.assert_running();
    denied_xhttp_h3_client.assert_running();
    unauthenticated_xhttp_h3_stream_up_client.assert_running();
    unauthenticated_xhttp_h3_auto_client.assert_running();
    allowed_xhttp_h3_stream_up_client.assert_running();
    denied_xhttp_h3_stream_up_client.assert_running();
    allowed_xhttp_h3_auto_client.assert_running();
    denied_xhttp_h3_auto_client.assert_running();
    unauthenticated_xhttp_h3_client.assert_running();
    allowed_reality_client.assert_running();
    denied_reality_client.assert_running();

    verify_reference_xray_udp_route_persistence(&workspace, &work_dir);
}

fn verify_reference_xray_udp_route_persistence(workspace: &Path, parent_dir: &Path) {
    let server_dir = parent_dir.join("reference-xray-server");
    let client_dir = parent_dir.join("reference-xray-client");
    fs::create_dir_all(&server_dir).expect("create reference Xray server directory");
    fs::create_dir_all(&client_dir).expect("create reference Xray client directory");

    let server_port = free_localhost_port();
    let api_port = free_localhost_port();
    let socks_port = free_localhost_port();
    let server_config = server_dir.join("server.json");
    let client_config = client_dir.join("client.json");
    let (echo_addr, echo_bytes) = start_observed_udp_echo_server();
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb7291";
    let user_email = "reference-udp@example.test";

    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind reference UDP echo fixture probe");
    probe
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set reference UDP echo fixture probe timeout");
    probe
        .send_to(b"reference UDP echo fixture probe", echo_addr)
        .expect("send reference UDP echo fixture probe");
    let mut probe_response = [0u8; 128];
    let (probe_length, _) = probe
        .recv_from(&mut probe_response)
        .expect("read reference UDP echo fixture probe");
    assert_eq!(
        &probe_response[..probe_length],
        b"reference UDP echo fixture probe"
    );

    write_json(
        &server_config,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "tag": "reference-vless-in",
                "settings": {
                    "clients": [{"id": user_id, "email": user_email}],
                    "decryption": "none"
                },
                "streamSettings": {"network": "tcp", "security": "none"}
            }],
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [loopback_allow_rule("udp", echo_addr)]
                    }
                },
                {"tag": "block", "protocol": "blackhole"}
            ],
            "api": {
                "tag": "reference-api",
                "listen": format!("127.0.0.1:{api_port}"),
                "services": ["RoutingService"]
            },
            "routing": {"rules": [{
                "type": "field",
                "inboundTag": ["reference-vless-in"],
                "ip": ["127.0.0.1/32"],
                "outboundTag": "block"
            }]}
        }),
    );
    write_json(
        &client_config,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": true}
            }],
            "outbounds": [{
                "tag": "to-reference-xray",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{"id": user_id, "encryption": "none"}]
                    }]
                },
                "streamSettings": {"network": "tcp", "security": "none"}
            }]
        }),
    );

    let mut server = start_xray(workspace, &server_dir, &server_config);
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));
    let api_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, api_port));
    wait_for_tcp(server_addr);
    wait_for_tcp(api_addr);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create reference Xray API runtime");
    let channel = runtime.block_on(connect_grpc_channel(api_addr));

    let cidr = format!("{}/32", echo_addr.ip());
    let cidr_rule = dynamic_cidr_rule(&cidr);
    let rules = vec![
        DynamicRoutingRule {
            target_tag: Some(dynamic_routing_rule::TargetTag::Tag(
                "direct".to_string(),
            )),
            rule_tag: "reference-udp-allow".to_string(),
            ip: vec![cidr_rule.clone()],
            networks: vec![3], // Xray common.net.Network: UDP.
            user_email: vec![user_email.to_string()],
            inbound_tag: vec!["reference-vless-in".to_string()],
        },
        DynamicRoutingRule {
            target_tag: Some(dynamic_routing_rule::TargetTag::Tag(
                "block".to_string(),
            )),
            rule_tag: "reference-udp-default-deny".to_string(),
            ip: vec![cidr_rule],
            networks: Vec::new(),
            user_email: Vec::new(),
            inbound_tag: Vec::new(),
        },
    ];
    let typed_config = DynamicTypedMessage {
        r#type: "xray.app.router.Config".to_string(),
        value: DynamicRouterConfig {
            domain_strategy: 0,
            rule: rules,
        }
        .encode_to_vec(),
    };
    runtime
        .block_on(grpc_unary::<DynamicAddRuleRequest, DynamicAddRuleResponse>(
            channel.clone(),
            ROUTING_ADD_RULE_PATH,
            DynamicAddRuleRequest {
                config: Some(typed_config),
                should_append: false,
            },
        ))
        .expect("install Xray reference UDP session routing rules");

    let mut client = start_xray(workspace, &client_dir, &client_config);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    wait_for_tcp(socks_addr);
    let association = XraySocksUdpAssociation::connect(socks_addr);
    let first_marker = b"reference UDP route before RemoveRule";
    association
        .udp
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set reference Xray UDP response timeout");
    association.send(echo_addr, first_marker);
    if let Err(error) = association.receive_response(echo_addr, first_marker) {
        panic!(
            "reference Xray failed before rule removal: {error}; echo target received {} bytes",
            echo_bytes.load(Ordering::SeqCst)
        );
    }
    remove_dynamic_hub_rule(&runtime, &channel, "reference-udp-allow");
    association
        .send_and_expect_echo(echo_addr, b"reference UDP route survives RemoveRule");
    let new_association = XraySocksUdpAssociation::connect(socks_addr);
    new_association.send_and_expect_no_response(
        echo_addr,
        b"new reference UDP session denied after RemoveRule",
    );
    server.assert_running();
    client.assert_running();
}

fn assert_hub_xhttp_profile_static_policy(
    profile: &str,
    allowed_socks_addr: SocketAddr,
    denied_socks_addr: SocketAddr,
    targets: &[HubOverlayEchoTarget],
) {
    let tcp_before = targets
        .iter()
        .map(|target| target.tcp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let tcp_marker = format!("hub-xhttp-{profile}-static-tcp");
    for (index, target) in targets.iter().enumerate() {
        assert_socks5_echo_with_retry(
            allowed_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            tcp_marker.as_bytes(),
            &target.tcp_allowed_bytes,
        );
        assert_socks5_target_denied(
            allowed_socks_addr,
            target.overlay_target(target.tcp_denied.port()),
            format!("hub-xhttp-{profile}-tcp-port-denial-{index}").as_bytes(),
        );
        assert_socks5_target_denied(
            denied_socks_addr,
            target.overlay_target(target.tcp_allowed.port()),
            format!("hub-xhttp-{profile}-tcp-identity-denial-{index}").as_bytes(),
        );
    }

    let udp_before = targets
        .iter()
        .map(|target| target.udp_allowed_bytes.load(Ordering::SeqCst))
        .collect::<Vec<_>>();
    let udp_marker = format!("hub-xhttp-{profile}-static-udp");
    let allowed_udp = XraySocksUdpAssociation::connect(allowed_socks_addr);
    let denied_udp = XraySocksUdpAssociation::connect(denied_socks_addr);
    for (index, target) in targets.iter().enumerate() {
        allowed_udp.send_and_expect_echo(
            target.overlay_target(target.udp_allowed.port()),
            udp_marker.as_bytes(),
        );
        allowed_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_denied.port()),
            format!("hub-xhttp-{profile}-udp-port-denial-{index}").as_bytes(),
        );
        denied_udp.send_and_expect_no_response(
            target.overlay_target(target.udp_allowed.port()),
            format!("hub-xhttp-{profile}-udp-identity-denial-{index}").as_bytes(),
        );
    }

    thread::sleep(Duration::from_millis(150));
    for (index, target) in targets.iter().enumerate() {
        assert_eq!(
            target.tcp_allowed_bytes.load(Ordering::SeqCst),
            tcp_before[index] + tcp_marker.len(),
            "XHTTP {profile}-authorized TCP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.udp_allowed_bytes.load(Ordering::SeqCst),
            udp_before[index] + udp_marker.len(),
            "XHTTP {profile}-authorized UDP reaches target {index}; denied identities do not"
        );
        assert_eq!(
            target.tcp_denied_bytes.load(Ordering::SeqCst),
            0,
            "XHTTP {profile} Hub must deny an unlisted TCP port before Edge dispatch"
        );
        assert_eq!(
            target.udp_denied_bytes.load(Ordering::SeqCst),
            0,
            "XHTTP {profile} Hub must deny an unlisted UDP port before Edge dispatch"
        );
    }
}

fn assert_socks5_echo_with_retry(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
    echoed_bytes: &AtomicUsize,
) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match connect_socks5_target_for_vless(socks_addr, target_addr) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let mut echoed = vec![0; payload.len()];
                if let Err(error) = stream
                    .write_all(payload)
                    .and_then(|()| stream.read_exact(&mut echoed))
                {
                    last_error = Some(error);
                } else if echoed == payload {
                    return;
                } else {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Overlay echo payload mismatch",
                    ));
                }
            }
            Err(error) => last_error = Some(error),
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!(
        "authorized Overlay route did not become usable; Edge received {} bytes: {}",
        echoed_bytes.load(Ordering::SeqCst),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no connection attempt completed".to_string())
    );
}

fn connect_socks5_target_for_vless(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS greeting failed: {greeting:02x?}"
        )));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target_addr.ip() {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    stream.write_all(&request)?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response)?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect failed: header={response:02x?}"
        )));
    }
    let tail_length = match response[3] {
        0x01 => 6,
        0x03 => {
            let mut domain_length = [0u8; 1];
            stream.read_exact(&mut domain_length)?;
            usize::from(domain_length[0]) + 2
        }
        0x04 => 18,
        address_type => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {address_type:#x}"),
            ));
        }
    };
    let mut tail = vec![0; tail_length];
    stream.read_exact(&mut tail)?;
    Ok(stream)
}

fn assert_socks5_target_denied(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    match connect_socks5_target_for_vless(socks_addr, target_addr) {
        Err(_) => {}
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set denied target read timeout");
            stream
                .set_write_timeout(Some(Duration::from_millis(500)))
                .expect("set denied target write timeout");
            if stream.write_all(payload).is_ok() {
                let mut response = vec![0; payload.len()];
                if stream.read_exact(&mut response).is_ok() {
                    assert_ne!(
                        response, payload,
                        "denied Overlay request unexpectedly reached its echo target"
                    );
                }
            }
        }
    }
}

fn dynamic_cidr_rule(prefix: &str) -> DynamicIpRule {
    let (address, prefix_length) =
        prefix.split_once('/').expect("CIDR prefix has slash");
    let address = address.parse::<IpAddr>().expect("parse CIDR address");
    let prefix_length = prefix_length
        .parse::<u32>()
        .expect("parse CIDR prefix length");
    let (ip, maximum_prefix) = match address {
        IpAddr::V4(ip) => (ip.octets().to_vec(), 32),
        IpAddr::V6(ip) => (ip.octets().to_vec(), 128),
    };
    assert!(prefix_length <= maximum_prefix, "CIDR prefix is in range");
    DynamicIpRule {
        custom: Some(DynamicCidrRule {
            cidr: Some(DynamicCidr {
                ip,
                prefix: prefix_length,
            }),
            reverse_match: false,
        }),
    }
}

fn replace_dynamic_hub_policy(
    runtime: &tokio::runtime::Runtime,
    channel: &Channel,
    allowed_prefixes: &[&str],
) {
    let mut rules = allowed_prefixes
        .iter()
        .enumerate()
        .map(|(index, prefix)| DynamicRoutingRule {
            target_tag: Some(dynamic_routing_rule::TargetTag::Tag(
                "site-edge".to_string(),
            )),
            rule_tag: format!("hub-site-allow-prefix-{index}"),
            ip: vec![dynamic_cidr_rule(prefix)],
            networks: vec![2, 3], // Xray common.net.Network: TCP and UDP.
            user_email: vec!["office-allowed@example.test".to_string()],
            inbound_tag: vec![
                "hub-vless-in".to_string(),
                "hub-vless-tls-in".to_string(),
                "hub-vless-ws-in".to_string(),
                "hub-vless-xhttp-in".to_string(),
                "hub-vless-xhttp-stream-up-in".to_string(),
                "hub-vless-xhttp-auto-in".to_string(),
                "hub-vless-xhttp-h3-in".to_string(),
                "hub-vless-xhttp-h3-stream-up-in".to_string(),
                "hub-vless-xhttp-h3-auto-in".to_string(),
                "hub-vless-reality-in".to_string(),
            ],
        })
        .collect::<Vec<_>>();
    rules.extend(HUB_OVERLAY_PROTECTED_PREFIXES.iter().enumerate().map(
        |(index, prefix)| DynamicRoutingRule {
            target_tag: Some(dynamic_routing_rule::TargetTag::Tag(
                "overlay-default-deny".to_string(),
            )),
            rule_tag: format!("hub-site-deny-prefix-{index}"),
            ip: vec![dynamic_cidr_rule(prefix)],
            networks: Vec::new(),
            user_email: Vec::new(),
            inbound_tag: Vec::new(),
        },
    ));
    let typed_config = DynamicTypedMessage {
        r#type: "xray.app.router.Config".to_string(),
        value: DynamicRouterConfig {
            domain_strategy: 0,
            rule: rules,
        }
        .encode_to_vec(),
    };
    runtime
        .block_on(grpc_unary::<DynamicAddRuleRequest, DynamicAddRuleResponse>(
            channel.clone(),
            ROUTING_ADD_RULE_PATH,
            DynamicAddRuleRequest {
                config: Some(typed_config),
                should_append: false,
            },
        ))
        .expect("replace Hub rules through Xray RoutingService.AddRule");
}

fn remove_dynamic_hub_rule(
    runtime: &tokio::runtime::Runtime,
    channel: &Channel,
    rule_tag: &str,
) {
    runtime
        .block_on(grpc_unary::<
            DynamicRemoveRuleRequest,
            DynamicRemoveRuleResponse,
        >(
            channel.clone(),
            ROUTING_REMOVE_RULE_PATH,
            DynamicRemoveRuleRequest {
                rule_tag: rule_tag.to_string(),
            },
        ))
        .expect("remove Hub rule through Xray RoutingService.RemoveRule");
}

async fn connect_grpc_channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("valid Hub gRPC endpoint")
        .connect_timeout(IO_TIMEOUT)
        .timeout(IO_TIMEOUT)
        .connect()
        .await
        .expect("connect to Hub gRPC API")
}

async fn grpc_unary<RequestMessage, ResponseMessage>(
    channel: Channel,
    path: &'static str,
    request: RequestMessage,
) -> Result<ResponseMessage, Status>
where
    RequestMessage: Message + Default + Send + Sync + 'static,
    ResponseMessage: Message + Default + Send + Sync + 'static,
{
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|error| {
        Status::unknown(format!("Hub gRPC service is not ready: {error}"))
    })?;
    grpc.unary(
        Request::new(request),
        PathAndQuery::from_static(path),
        tonic_prost::ProstCodec::default(),
    )
    .await
    .map(|response| response.into_inner())
}

fn run_chimera_bridge_sniffing_interop(
    name: &str,
    original_target: &str,
    sniffing: serde_json::Value,
    payload: &[u8],
) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse sniffing Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir =
        create_test_dir(&format!("vless-reverse-chimera-bridge-sniff-http-{name}"));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-sniff@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-http",
                    "settings": {
                        "address": original_target,
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-http"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {
                            "tag": "bridge-in",
                            "sniffing": sniffing
                        }
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [loopback_allow_rule("tcp", echo_addr)]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    assert_reverse_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        payload,
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_udp_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse UDP Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-chimera-bridge-udp-raw");
    let (echo_addr, echoed_bytes) = start_observed_udp_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_udp_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-udp@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-udp",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "udp",
                        "followRedirect": false
                    }
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-udp"],
                    "network": "udp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [loopback_allow_rule("udp", echo_addr)]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "udp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    // Exercise the same supervised retry path as the TCP fixture.
    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    xray.assert_running();

    assert_reverse_udp_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        b"chimera bridge through xray reverse portal udp",
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_reverse_udp_interop(reattach_after_disconnect: bool) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse UDP Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir(if reattach_after_disconnect {
        "vless-reverse-xray-global-id-reattach"
    } else {
        "vless-reverse-xray-bridge-udp-raw"
    });
    let (echo_addr, echoed_bytes) = start_observed_udp_echo_server();
    let (second_echo_addr, second_echo_bytes) = start_observed_udp_echo_server();
    let reverse_port = free_localhost_port();
    let vless_udp_port = free_localhost_port();
    let public_port = free_localhost_udp_port();
    let xray_socks_port = free_localhost_port();
    let vless_proxy = reattach_after_disconnect.then(|| {
        ResettableTcpProxy::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            vless_udp_port,
        )))
    });
    let xray_vless_port = vless_proxy
        .as_ref()
        .map_or(vless_udp_port, |proxy| proxy.addr.port());
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "xray-bridge-udp@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-udp",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "udp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "udp"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": vless_udp_port,
                    "protocol": "vless",
                    "tag": "vless-udp-in",
                    "settings": {
                        "clients": [{"id": TEST_UUID, "email": "udp-gateway@example.test"}],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["public-udp"],
                        "network": "udp",
                        "outboundTag": "reverse-out"
                    },
                    {
                        "type": "field",
                        "inboundTag": ["vless-udp-in"],
                        "network": "udp",
                        "outboundTag": "reverse-out"
                    }
                ]
            }
        }),
    );

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "tag": "xray-socks",
                "settings": {"auth": "noauth", "udp": true}
            }],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "to-chimera-vless-udp",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": xray_vless_port,
                            "users": [{"id": TEST_UUID, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [{
                            "action": "allow",
                            "network": "udp",
                            "ip": ["127.0.0.0/8"]
                        }]
                    }
                }
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["bridge-in"],
                        "network": "udp",
                        "outboundTag": "direct"
                    },
                    {
                        "type": "field",
                        "inboundTag": ["xray-socks"],
                        "network": "udp",
                        "outboundTag": "to-chimera-vless-udp"
                    }
                ]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray.assert_running();

    assert_reverse_udp_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        b"xray bridge through chimera reverse portal udp",
        &echoed_bytes,
    );
    let echoed_before_socks = echoed_bytes.load(Ordering::SeqCst);
    let association = XraySocksUdpAssociation::connect(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        xray_socks_port,
    )));
    association.send_and_expect_echo(
        echo_addr,
        b"Xray VLESS UDP through Chimera Reverse Portal",
    );
    if let Some(proxy) = vless_proxy.as_ref() {
        proxy.wait_for_connections(1);
        proxy.reset_active_connections();
        association.send_until_echo(
            echo_addr,
            b"same GlobalID after VLESS TCP reconnect",
            Duration::from_secs(8),
        );
        proxy.wait_for_connections(2);
        association.send_and_expect_echo(
            second_echo_addr,
            b"second target after GlobalID reattachment",
        );
    } else {
        association.send_and_expect_echo(
            second_echo_addr,
            b"same XUDP session, second target",
        );
    }
    assert!(
        echoed_bytes.load(Ordering::SeqCst) > echoed_before_socks,
        "the first Xray VLESS UDP target did not reach its echo server"
    );
    assert!(
        second_echo_bytes.load(Ordering::SeqCst) > 0,
        "the second Xray VLESS UDP target did not reach its echo server"
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_xray_socks_udp_without_worker_recovery() {
    let workspace = workspace_root();
    let xray_binary = xray_binary(&workspace);
    if !xray_binary.is_file() {
        eprintln!(
            "skipping VLESS Reverse UDP Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray_binary.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-xray-socks-udp-no-worker");
    let bridge_dir = work_dir.join("bridge");
    let client_dir = work_dir.join("client");
    fs::create_dir_all(&bridge_dir).expect("create Xray Bridge work directory");
    fs::create_dir_all(&client_dir).expect("create Xray client work directory");

    let (echo_addr, echoed_bytes) = start_observed_udp_echo_server();
    let reverse_port = free_localhost_port();
    let vless_udp_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let bridge_config = bridge_dir.join("xray.json");
    let client_config = client_dir.join("xray.json");

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "xray-socks-no-worker-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": vless_udp_port,
                    "protocol": "vless",
                    "tag": "vless-udp-in",
                    "settings": {
                        "clients": [{"id": TEST_UUID, "email": "xray-socks-udp@example.test"}],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                }
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["vless-udp-in"],
                    "network": "udp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &bridge_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {"finalRules": [loopback_allow_rule("udp", echo_addr)]}
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "udp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    write_json(
        &client_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "tag": "xray-socks",
                "settings": {"auth": "noauth", "udp": true}
            }],
            "outbounds": [{
                "tag": "to-chimera-vless-udp",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": vless_udp_port,
                        "users": [{"id": TEST_UUID, "encryption": "none"}]
                    }]
                },
                "streamSettings": {"network": "tcp", "security": "none"}
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["xray-socks"],
                    "network": "udp",
                    "outboundTag": "to-chimera-vless-udp"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, vless_udp_port)));
    chimera.assert_running();

    let mut xray_client = start_xray(&workspace, &client_dir, &client_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray_client.assert_running();
    let association = XraySocksUdpAssociation::connect(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        xray_socks_port,
    )));
    let source_port = association
        .udp
        .local_addr()
        .expect("read Xray SOCKS UDP source tuple")
        .port();

    association
        .send_and_expect_no_response(echo_addr, b"xray-socks-no-reverse-worker");
    assert_eq!(
        echoed_bytes.load(Ordering::SeqCst),
        0,
        "UDP must not reach its target while the Reverse Portal has no Bridge worker"
    );
    chimera.assert_running();
    xray_client.assert_running();

    let mut xray_bridge = start_xray(&workspace, &bridge_dir, &bridge_config);
    association.send_until_echo(
        echo_addr,
        b"xray-socks-recovered-after-reverse-worker-attach",
        Duration::from_secs(12),
    );
    assert_eq!(
        association
            .udp
            .local_addr()
            .expect("read recovered Xray SOCKS UDP source tuple")
            .port(),
        source_port,
        "recovery must use the original SOCKS UDP client socket"
    );
    association.send_and_expect_echo(
        echo_addr,
        b"xray-socks-stable-after-reverse-worker-attach",
    );
    let idle_baseline = echoed_bytes.load(Ordering::SeqCst);

    // The production UDP worker idle timeout is 60 seconds. Keep the same
    // Xray SOCKS association silent beyond it before sending again.
    thread::sleep(Duration::from_secs(65));
    assert_eq!(
        echoed_bytes.load(Ordering::SeqCst),
        idle_baseline,
        "the echo target must receive no UDP traffic during the idle interval"
    );
    association.send_until_echo(
        echo_addr,
        b"xray-socks-recovered-after-udp-idle-expiry",
        Duration::from_secs(12),
    );
    assert_eq!(
        association
            .udp
            .local_addr()
            .expect("read post-idle Xray SOCKS UDP source tuple")
            .port(),
        source_port,
        "post-idle recovery must use the original SOCKS UDP client socket"
    );
    assert!(
        echoed_bytes.load(Ordering::SeqCst) > idle_baseline,
        "UDP echo must recover after the production idle timeout"
    );

    chimera.assert_running();
    xray_client.assert_running();
    xray_bridge.assert_running();
}

struct XraySocksUdpAssociation {
    _control: TcpStream,
    udp: UdpSocket,
    relay_addr: SocketAddr,
}

impl XraySocksUdpAssociation {
    fn connect(socks_addr: SocketAddr) -> Self {
        let mut control =
            TcpStream::connect(socks_addr).expect("connect Xray SOCKS UDP control");
        control
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set SOCKS control read timeout");
        control
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("set SOCKS control write timeout");
        control
            .write_all(&[0x05, 0x01, 0x00])
            .expect("send Xray SOCKS hello");
        let mut hello = [0u8; 2];
        control
            .read_exact(&mut hello)
            .expect("read Xray SOCKS hello response");
        assert_eq!(hello, [0x05, 0x00]);

        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("send Xray SOCKS UDP ASSOCIATE");
        let mut response_header = [0u8; 4];
        control
            .read_exact(&mut response_header)
            .expect("read Xray SOCKS UDP ASSOCIATE response");
        assert_eq!(response_header[1], 0, "Xray SOCKS UDP ASSOCIATE failed");
        let relay_ip = match response_header[3] {
            0x01 => {
                let mut bytes = [0u8; 4];
                control
                    .read_exact(&mut bytes)
                    .expect("read SOCKS relay IPv4");
                std::net::IpAddr::V4(Ipv4Addr::from(bytes))
            }
            other => panic!("unexpected Xray SOCKS UDP relay address type {other}"),
        };
        let mut port_bytes = [0u8; 2];
        control
            .read_exact(&mut port_bytes)
            .expect("read SOCKS relay port");
        let mut relay_addr =
            SocketAddr::new(relay_ip, u16::from_be_bytes(port_bytes));
        if relay_addr.ip().is_unspecified() {
            relay_addr.set_ip(socks_addr.ip());
        }

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind SOCKS UDP client");
        Self {
            _control: control,
            udp,
            relay_addr,
        }
    }

    fn send_and_expect_echo(&self, target_addr: SocketAddr, payload: &[u8]) {
        self.udp
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set SOCKS UDP response timeout");
        self.send(target_addr, payload);
        self.expect_response(target_addr, payload);
    }

    fn send_and_expect_no_response(&self, target_addr: SocketAddr, payload: &[u8]) {
        self.udp
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set denied SOCKS UDP response timeout");
        self.send(target_addr, payload);
        let mut response = [0u8; 2048];
        match self.udp.recv_from(&mut response) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("read denied SOCKS UDP response: {error}"),
            Ok((length, _)) => panic!(
                "denied Overlay UDP request unexpectedly received a response: {length} bytes"
            ),
        }
    }

    fn send_until_echo(
        &self,
        target_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        self.udp
            .set_read_timeout(Some(Duration::from_millis(150)))
            .expect("set retrying SOCKS UDP response timeout");
        loop {
            self.send(target_addr, payload);
            match self.receive_response(target_addr, payload) {
                Ok(()) => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && Instant::now() < deadline => {}
                Err(error) => panic!(
                    "Xray SOCKS UDP did not recover after the VLESS TCP disconnect: {error}"
                ),
            }
            assert!(
                Instant::now() < deadline,
                "Xray SOCKS UDP reattachment timed out"
            );
        }
    }

    fn send(&self, target_addr: SocketAddr, payload: &[u8]) {
        let mut request = vec![0, 0, 0];
        match target_addr.ip() {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        request.extend_from_slice(payload);
        self.udp
            .send_to(&request, self.relay_addr)
            .expect("send Xray SOCKS UDP request");
    }

    fn expect_response(&self, target_addr: SocketAddr, payload: &[u8]) {
        self.receive_response(target_addr, payload)
            .expect("receive Xray SOCKS UDP response");
    }

    fn receive_response(
        &self,
        target_addr: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut response = vec![0u8; payload.len() + 64];
        let (length, _) = self.udp.recv_from(&mut response)?;
        assert!(length >= 4, "SOCKS UDP response header was truncated");
        assert_eq!(&response[..2], &[0, 0]);
        assert_eq!(response[2], 0, "fragmented SOCKS UDP response");
        let (source_ip, address_length) = match response[3] {
            0x01 if length >= 10 => (
                IpAddr::V4(Ipv4Addr::new(
                    response[4],
                    response[5],
                    response[6],
                    response[7],
                )),
                4,
            ),
            0x04 if length >= 22 => (
                IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&response[4..20])
                        .expect("IPv6 SOCKS UDP source length"),
                )),
                16,
            ),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "truncated or unsupported SOCKS UDP address type {other:#x}"
                    ),
                ));
            }
        };
        let port_start = 4 + address_length;
        assert_eq!(
            source_ip,
            target_addr.ip(),
            "SOCKS UDP response source IP while waiting for {target_addr}"
        );
        let response_port =
            u16::from_be_bytes([response[port_start], response[port_start + 1]]);
        assert_eq!(
            response_port,
            target_addr.port(),
            "SOCKS UDP response source while waiting for {target_addr}, payload={:?}",
            &response[port_start + 2..length]
        );
        assert_eq!(&response[port_start + 2..length], payload);
        Ok(())
    }
}

struct ResettableTcpProxy {
    addr: SocketAddr,
    active_clients: Arc<Mutex<Vec<TcpStream>>>,
    accepted_connections: Arc<AtomicUsize>,
    running: Arc<AtomicBool>,
    listener_task: Option<thread::JoinHandle<()>>,
}

impl ResettableTcpProxy {
    fn new(target: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind resettable VLESS TCP proxy");
        listener
            .set_nonblocking(true)
            .expect("set resettable proxy listener nonblocking");
        let addr = listener.local_addr().expect("read resettable proxy addr");
        let active_clients = Arc::new(Mutex::new(Vec::new()));
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let task_active_clients = active_clients.clone();
        let task_accepted_connections = accepted_connections.clone();
        let task_running = running.clone();
        let listener_task = thread::spawn(move || {
            while task_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let upstream = match TcpStream::connect(target) {
                            Ok(upstream) => upstream,
                            Err(_) => continue,
                        };
                        let Ok(control_client) = client.try_clone() else {
                            continue;
                        };
                        task_active_clients
                            .lock()
                            .expect("resettable proxy client mutex")
                            .push(control_client);
                        task_accepted_connections.fetch_add(1, Ordering::SeqCst);
                        let mut client_reader =
                            client.try_clone().expect("clone proxy client");
                        let mut upstream_writer =
                            upstream.try_clone().expect("clone proxy upstream");
                        thread::spawn(move || {
                            let _ =
                                io::copy(&mut client_reader, &mut upstream_writer);
                            let _ = upstream_writer.shutdown(Shutdown::Write);
                        });

                        let mut upstream_reader =
                            upstream.try_clone().expect("clone proxy upstream");
                        let mut client_writer =
                            client.try_clone().expect("clone proxy client");
                        thread::spawn(move || {
                            let _ =
                                io::copy(&mut upstream_reader, &mut client_writer);
                            let _ = client_writer.shutdown(Shutdown::Write);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            active_clients,
            accepted_connections,
            running,
            listener_task: Some(listener_task),
        }
    }

    fn wait_for_connections(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.accepted_connections.load(Ordering::SeqCst) < expected
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            self.accepted_connections.load(Ordering::SeqCst) >= expected,
            "Xray VLESS transport did not reconnect through the resettable proxy"
        );
    }

    fn reset_active_connections(&self) {
        assert!(
            self.close_active_connections() > 0,
            "no VLESS TCP connection to reset"
        );
    }

    fn close_active_connections(&self) -> usize {
        let clients = std::mem::take(
            &mut *self
                .active_clients
                .lock()
                .expect("resettable proxy client mutex"),
        );
        let count = clients.len();
        for client in clients {
            let _ = client.shutdown(Shutdown::Both);
        }
        count
    }
}

impl Drop for ResettableTcpProxy {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.close_active_connections();
        if let Some(listener_task) = self.listener_task.take() {
            let _ = listener_task.join();
        }
    }
}

fn run_chimera_bridge_proxy_protocol_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse PROXY protocol Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-chimera-bridge-proxy-protocol");
    let (echo_addr, captured_source) = start_proxy_protocol_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-proxy@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-proxy",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-proxy"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "proxyProtocol": 1,
                        "finalRules": [loopback_allow_rule("tcp", echo_addr)]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    let payload = b"reverse proxy protocol source";
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let successful_source = loop {
        match reverse_echo_once_with_source(public_addr, payload) {
            Ok(source) => break source,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                panic!(
                    "VLESS Reverse PROXY protocol worker did not become usable at {public_addr}: {error}"
                );
            }
        }
    };

    assert_eq!(
        *captured_source
            .lock()
            .expect("PROXY protocol capture lock poisoned"),
        Some(successful_source),
        "Chimera freedom proxyProtocol must preserve the Xray Portal public source"
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_xhttp_forwarded_source_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse XHTTP forwarded-source interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir =
        create_test_dir("vless-reverse-chimera-bridge-xhttp-forwarded-source");
    let (echo_addr, captured_source) = start_proxy_protocol_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");
    let (cert_path, key_path) = generate_test_certificate(&work_dir);
    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-xhttp-forwarded@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "certificates": [{
                                "certificateFile": cert_path,
                                "keyFile": key_path
                            }]
                        },
                        "xhttpSettings": {
                            "host": "cdn.reverse.test",
                            "path": "/reverse-xhttp-forwarded/",
                            "mode": "stream-up",
                            "xPaddingBytes": 1
                        },
                        "sockopt": {
                            "trustedXForwardedFor": ["X-Trusted-CDN"]
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-proxy",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-proxy"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "localhost",
                            "disableSystemRoot": true,
                            "certificates": [{
                                "certificateFile": cert_path,
                                "usage": "verify"
                            }]
                        },
                        "xhttpSettings": {
                            "host": "cdn.reverse.test",
                            "path": "/reverse-xhttp-forwarded/",
                            "mode": "stream-up",
                            "xPaddingBytes": 1,
                            "headers": {
                                "X-Forwarded-For": "198.51.100.77",
                                "X-Trusted-CDN": "edge-a"
                            }
                        }
                    }
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "proxyProtocol": 1,
                        "finalRules": [loopback_allow_rule("tcp", echo_addr)]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    let payload = b"reverse xhttp trusted forwarded source";
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let successful_source = loop {
        match reverse_echo_once_with_source(public_addr, payload) {
            Ok(source) => break source,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                panic!(
                    "VLESS Reverse XHTTP forwarded-source worker did not become usable at {public_addr}: {error}"
                );
            }
        }
    };

    assert_eq!(
        *captured_source
            .lock()
            .expect("PROXY protocol capture lock poisoned"),
        Some(successful_source),
        "transport-level trusted XHTTP forwarded source must not replace the public Reverse logical-session source"
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_interop(
    security: ReverseSecurity,
    routing_user: Option<&str>,
) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let case_suffix = if routing_user.is_some() {
        "-routing-user"
    } else {
        ""
    };
    let work_dir = create_test_dir(&format!(
        "vless-reverse-chimera-bridge-{}{}",
        security.name(),
        case_suffix
    ));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let chimera_bad_auth_config = work_dir.join("chimera-bad-auth.json");
    let xray_config = work_dir.join("xray.json");

    let (xray_stream, chimera_stream) = match security {
        ReverseSecurity::Raw => (
            json!({"network": "tcp", "security": "none"}),
            json!({"network": "tcp", "security": "none"}),
        ),
        ReverseSecurity::Tls => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            (
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }),
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "disableSystemRoot": true,
                        "certificates": [{
                            "certificateFile": cert_path,
                            "usage": "verify"
                        }]
                    }
                }),
            )
        }
        #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
        ReverseSecurity::Reality => (
            json!({
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.apple.com:443",
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "minClientVer": "26.2.6"
                }
            }),
            json!({
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.apple.com",
                    "fingerprint": "chrome",
                    "publicKey": "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg",
                    "shortId": "4ac97aaf8b9b0356"
                }
            }),
        ),
        ReverseSecurity::Websocket => (
            json!({
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/reverse"}
            }),
            json!({
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/reverse"}
            }),
        ),
        ReverseSecurity::XhttpTls
        | ReverseSecurity::XhttpTlsAuto
        | ReverseSecurity::XhttpTlsPacketUp => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            let mode = security.xhttp_mode();
            (
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": ["h2"],
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp/?edge=portal",
                        "mode": mode,
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "seqPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "seqKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Sequence" } else { "" },
                        "uplinkDataPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "uplinkDataKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Payload" } else { "" },
                        "uplinkChunkSize": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { json!("64") } else { serde_json::Value::Null },
                        "xPaddingBytes": 1
                    }
                }),
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": ["h2"],
                        "disableSystemRoot": true,
                        "certificates": [{
                            "certificateFile": cert_path,
                            "usage": "verify"
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp/?edge=bridge",
                        "mode": mode,
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "seqPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "seqKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Sequence" } else { "" },
                        "uplinkDataPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "uplinkDataKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Payload" } else { "" },
                        "uplinkChunkSize": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { json!("64") } else { serde_json::Value::Null },
                        "headers": {
                            "User-Agent": "chimera-reverse-xhttp",
                            "X-Reverse-Edge": "chimera-bridge"
                        },
                        "xPaddingBytes": 1
                    }
                }),
            )
        }
        ReverseSecurity::XhttpTlsObfs => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            (
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp-obfs/?edge=portal",
                        "mode": "stream-up",
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "xPaddingBytes": 64,
                        "xPaddingObfsMode": true,
                        "xPaddingPlacement": "queryInHeader",
                        "xPaddingHeader": "X-Reverse-Padding",
                        "xPaddingKey": "x_reverse_pad",
                        "xPaddingMethod": "tokenish"
                    }
                }),
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "disableSystemRoot": true,
                        "certificates": [{
                            "certificateFile": cert_path,
                            "usage": "verify"
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp-obfs/?edge=bridge",
                        "mode": "stream-up",
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "xPaddingBytes": 64,
                        "xPaddingObfsMode": true,
                        "xPaddingPlacement": "queryInHeader",
                        "xPaddingHeader": "X-Reverse-Padding",
                        "xPaddingKey": "x_reverse_pad",
                        "xPaddingMethod": "tokenish",
                        "headers": {
                            "User-Agent": "chimera-reverse-xhttp-obfs",
                            "X-Reverse-Edge": "chimera-bridge-obfs"
                        }
                    }
                }),
            )
        }
        ReverseSecurity::XhttpTlsH3PacketUp
        | ReverseSecurity::XhttpTlsH3StreamUp
        | ReverseSecurity::XhttpTlsH3Auto => {
            unreachable!("Chimera Bridge -> Xray Portal Reverse H3 is fail-closed")
        }
    };

    let reverse_bridge_outbound = json!({
        "tag": "reverse-bridge",
        "protocol": "vless",
        "settings": {
            "address": "127.0.0.1",
            "port": reverse_port,
            "id": TEST_UUID,
            "email": routing_user.unwrap_or(""),
            "encryption": "none",
            "reverse": {"tag": "bridge-in"}
        },
        "streamSettings": chimera_stream
    });
    let direct_outbound = json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {
            "finalRules": [loopback_allow_rule("tcp", echo_addr)]
        }
    });
    let (mut chimera_outbounds, chimera_routing_rules) =
        if let Some(routing_user) = routing_user {
            (
                vec![
                    json!({"tag": "default-block", "protocol": "blackhole"}),
                    direct_outbound.clone(),
                ],
                vec![json!({
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "user": [routing_user],
                    "network": "tcp",
                    "outboundTag": "direct"
                })],
            )
        } else {
            (
                vec![direct_outbound],
                vec![json!({
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                })],
            )
        };
    chimera_outbounds.insert(0, reverse_bridge_outbound);

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": xray_stream
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-echo",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-echo"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    let chimera_config_value = json!({
        "log": {"loglevel": "debug"},
        "inbounds": [],
        "outbounds": chimera_outbounds,
        "routing": {
            "rules": chimera_routing_rules
        }
    });
    write_json(&chimera_config, chimera_config_value.clone());
    if security.is_reality() {
        let mut bad_auth = chimera_config_value;
        bad_auth["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] =
            json!("0000000000000000");
        write_json(&chimera_bad_auth_config, bad_auth);
    }

    let bridge_config = if security.is_reality() {
        &chimera_bad_auth_config
    } else {
        &chimera_config
    };
    let mut chimera = start_chimera(&workspace, &work_dir, bridge_config);
    chimera.assert_running();

    // Xray waits two seconds before its first Reverse monitor tick. Start
    // Chimera first and let that first TCP dial fail so the successful path
    // also proves periodic retry rather than startup ordering.
    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    if security.is_reality() {
        std::thread::sleep(Duration::from_millis(2300));
        assert_reverse_echo_unavailable(public_addr);
        assert_eq!(
            echoed_bytes.load(Ordering::SeqCst),
            0,
            "invalid REALITY shortId must not create a Reverse worker or reach the target"
        );
        drop(chimera);
        chimera = start_chimera(&workspace, &work_dir, &chimera_config);
        chimera.assert_running();
    }

    let first_payload = format!(
        "chimera bridge through xray reverse portal ({})",
        security.name()
    );
    assert_reverse_echo_with_retry(
        public_addr,
        first_payload.as_bytes(),
        &echoed_bytes,
    );

    // Kill the Portal side and bring it back on the same ports. The physical
    // Reverse worker must observe EOF and the monitor must create a new worker.
    drop(xray);
    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(public_addr);
    xray.assert_running();

    let reconnect_payload = format!(
        "chimera bridge reconnect through xray reverse portal ({})",
        security.name()
    );
    assert_reverse_echo_with_retry(
        public_addr,
        reconnect_payload.as_bytes(),
        &echoed_bytes,
    );
    if matches!(security, ReverseSecurity::Raw) {
        assert_reverse_tcp_acceptance(public_addr, &echoed_bytes);
    }

    chimera.assert_running();
    xray.assert_running();
}

fn run_multiple_xray_bridge_failover() {
    let workspace = workspace_root();
    let xray_binary = xray_binary(&workspace);
    if !xray_binary.is_file() {
        eprintln!(
            "skipping multi-Bridge Reverse failover test because {} is unavailable; set XRAY_BIN to enable it",
            xray_binary.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-multi-bridge-failover");
    let bridge_a_dir = work_dir.join("bridge-a");
    let bridge_b_dir = work_dir.join("bridge-b");
    fs::create_dir_all(&bridge_a_dir).expect("create first Xray Bridge directory");
    fs::create_dir_all(&bridge_b_dir).expect("create second Xray Bridge directory");

    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let bridge_a_config = bridge_a_dir.join("xray.json");
    let bridge_b_config = bridge_b_dir.join("xray.json");

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "multi-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-echo",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-echo"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );
    let bridge_config = xray_bridge_config(reverse_port);
    write_json(&bridge_a_config, bridge_config.clone());
    write_json(&bridge_b_config, bridge_config);

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    let reverse_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port));
    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    wait_for_tcp(reverse_addr);
    wait_for_tcp(public_addr);
    chimera.assert_running();

    let bytes_before_offline_probe = echoed_bytes.load(Ordering::SeqCst);
    wait_for_reverse_route_unavailable(public_addr);
    assert_eq!(
        echoed_bytes.load(Ordering::SeqCst),
        bytes_before_offline_probe,
        "a Reverse Portal without Bridge workers must not fall back to the direct target"
    );
    wait_for_tcp(reverse_addr);
    chimera.assert_running();

    let mut bridge_a = start_xray(&workspace, &bridge_a_dir, &bridge_a_config);
    let mut bridge_b = start_xray(&workspace, &bridge_b_dir, &bridge_b_config);
    bridge_a.assert_running();
    bridge_b.assert_running();
    wait_for_xray_reverse_control_session(
        &bridge_a_dir.join("xray.stdout.log"),
        "first Bridge",
    );
    wait_for_xray_reverse_control_session(
        &bridge_b_dir.join("xray.stdout.log"),
        "second Bridge",
    );
    assert_reverse_echo_with_retry(
        public_addr,
        b"traffic before a Bridge exits",
        &echoed_bytes,
    );
    chimera.assert_running();
    bridge_a.assert_running();
    bridge_b.assert_running();

    // Killing either physical Bridge must remove only its worker. The other
    // Bridge must continue serving new TCP sessions on the same Portal tag.
    drop(bridge_a);
    bridge_b.assert_running();

    for payload in [
        b"traffic after first Bridge exit".as_slice(),
        b"second recovery request".as_slice(),
        b"steady traffic on surviving Bridge".as_slice(),
    ] {
        assert_reverse_echo_with_retry(public_addr, payload, &echoed_bytes);
    }
    chimera.assert_running();
    bridge_b.assert_running();

    drop(bridge_b);
    wait_for_reverse_route_unavailable(public_addr);
    let bytes_before_second_offline_probe = echoed_bytes.load(Ordering::SeqCst);
    assert_reverse_echo_unavailable(public_addr);
    assert_eq!(
        echoed_bytes.load(Ordering::SeqCst),
        bytes_before_second_offline_probe,
        "when all Bridge workers exit, the Portal must not send the request to the direct target"
    );
    wait_for_tcp(reverse_addr);
    chimera.assert_running();

    let mut recovered_bridge =
        start_xray(&workspace, &bridge_b_dir, &bridge_b_config);
    wait_for_xray_reverse_control_session(
        &bridge_b_dir.join("xray.stdout.log"),
        "reconnected Bridge",
    );
    assert_reverse_echo_with_retry(
        public_addr,
        b"traffic after all Bridges reconnect",
        &echoed_bytes,
    );
    chimera.assert_running();
    recovered_bridge.assert_running();
}

fn xray_bridge_config(reverse_port: u16) -> serde_json::Value {
    json!({
        "log": {"loglevel": "debug"},
        "outbounds": [
            {
                "tag": "reverse-bridge",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": reverse_port,
                    "id": TEST_UUID,
                    "encryption": "none",
                    "reverse": {"tag": "bridge-in"}
                },
                "streamSettings": {"network": "tcp", "security": "none"}
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "finalRules": [{
                        "action": "allow",
                        "network": "tcp",
                        "ip": ["127.0.0.0/8"]
                    }]
                }
            }
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["bridge-in"],
                "network": "tcp",
                "outboundTag": "direct"
            }]
        }
    })
}

fn wait_for_xray_reverse_control_session(log_path: &Path, bridge_name: &str) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    loop {
        let log = fs::read_to_string(log_path).unwrap_or_default();
        if log.contains("received request for udp:reverse:0") {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {bridge_name} to receive the Reverse control session; log={log}"
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_reverse_interop(security: ReverseSecurity) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir(&format!("vless-reverse-{}", security.name()));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = if security.is_xhttp_h3() {
        free_localhost_udp_port()
    } else {
        free_localhost_port()
    };
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");
    let xray_bad_auth_config = work_dir.join("xray-bad-auth.json");

    let (chimera_stream, xray_stream) = match security {
        ReverseSecurity::Raw => (
            json!({
                "network": "tcp",
                "security": "none"
            }),
            json!({
                "network": "tcp",
                "security": "none"
            }),
        ),
        ReverseSecurity::Tls => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);
            (
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }),
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256
                    }
                }),
            )
        }
        #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
        ReverseSecurity::Reality => (
            json!({
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.apple.com:443",
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "minClientVer": "26.2.6"
                }
            }),
            json!({
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.apple.com",
                    "fingerprint": "chrome",
                    "publicKey": "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg",
                    "shortId": "4ac97aaf8b9b0356"
                }
            }),
        ),
        ReverseSecurity::Websocket => {
            unreachable!("Portal-side WebSocket is not exercised here")
        }
        ReverseSecurity::XhttpTls
        | ReverseSecurity::XhttpTlsAuto
        | ReverseSecurity::XhttpTlsPacketUp
        | ReverseSecurity::XhttpTlsH3PacketUp
        | ReverseSecurity::XhttpTlsH3StreamUp
        | ReverseSecurity::XhttpTlsH3Auto => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);
            let mode = security.xhttp_mode();
            let alpn = if security.is_xhttp_h3() { "h3" } else { "h2" };
            (
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": [alpn],
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp/?edge=portal",
                        "mode": mode,
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "seqPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "seqKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Sequence" } else { "" },
                        "uplinkDataPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "uplinkDataKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Payload" } else { "" },
                        "uplinkChunkSize": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { json!("64") } else { serde_json::Value::Null },
                        "xPaddingBytes": 1
                    }
                }),
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": [alpn],
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp/?edge=bridge",
                        "mode": mode,
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "seqPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "seqKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Sequence" } else { "" },
                        "uplinkDataPlacement": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "header" } else { "" },
                        "uplinkDataKey": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { "X-Reverse-Payload" } else { "" },
                        "uplinkChunkSize": if matches!(security, ReverseSecurity::XhttpTlsPacketUp) { json!("64") } else { serde_json::Value::Null },
                        "headers": {
                            "User-Agent": "xray-reverse-xhttp",
                            "X-Reverse-Edge": "xray-bridge"
                        },
                        "xPaddingBytes": 1
                    }
                }),
            )
        }
        ReverseSecurity::XhttpTlsObfs => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);
            (
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp-obfs/?edge=portal",
                        "mode": "stream-up",
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "xPaddingBytes": 64,
                        "xPaddingObfsMode": true,
                        "xPaddingPlacement": "queryInHeader",
                        "xPaddingHeader": "X-Reverse-Padding",
                        "xPaddingKey": "x_reverse_pad",
                        "xPaddingMethod": "tokenish"
                    }
                }),
                json!({
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256
                    },
                    "xhttpSettings": {
                        "host": "cdn.reverse.test",
                        "path": "/reverse-xhttp-obfs/?edge=bridge",
                        "mode": "stream-up",
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Reverse-Session",
                        "xPaddingBytes": 64,
                        "xPaddingObfsMode": true,
                        "xPaddingPlacement": "queryInHeader",
                        "xPaddingHeader": "X-Reverse-Padding",
                        "xPaddingKey": "x_reverse_pad",
                        "xPaddingMethod": "tokenish",
                        "headers": {
                            "User-Agent": "xray-reverse-xhttp-obfs",
                            "X-Reverse-Edge": "xray-bridge-obfs"
                        }
                    }
                }),
            )
        }
    };

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "reverse-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": chimera_stream
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-echo",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-echo"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    let xray_config_value = json!({
        "log": {"loglevel": "debug"},
        "outbounds": [
            {
                "tag": "reverse-bridge",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": reverse_port,
                    "id": TEST_UUID,
                    "encryption": "none",
                    "reverse": {"tag": "bridge-in"}
                },
                "streamSettings": xray_stream
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    // Current Xray applies a default private-IP block to
                    // traffic originating from a VLESS inbound. The echo
                    // target is intentionally loopback, so allow it
                    // explicitly for this interoperability fixture.
                    "finalRules": [{
                        "action": "allow",
                        "network": "tcp",
                        "ip": ["127.0.0.0/8"]
                    }]
                }
            }
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["bridge-in"],
                "network": "tcp",
                "outboundTag": "direct"
            }]
        }
    });
    write_json(&xray_config, xray_config_value.clone());
    if security.has_negative_auth_case() {
        let mut bad_auth = xray_config_value.clone();
        match security {
            ReverseSecurity::Raw => {
                bad_auth["outbounds"][0]["settings"]["id"] = json!(WRONG_TEST_UUID);
            }
            #[cfg(any(feature = "full", feature = "vless-reverse-reality"))]
            ReverseSecurity::Reality => {
                bad_auth["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] =
                    json!("0000000000000000");
            }
            _ => unreachable!("this transport has no negative-auth case"),
        }
        write_json(&xray_bad_auth_config, bad_auth);
    }

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    if !security.is_xhttp_h3() {
        wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    }
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    chimera.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    if security.has_negative_auth_case() {
        let before = echoed_bytes.load(Ordering::SeqCst);
        let mut bad_xray = start_xray(&workspace, &work_dir, &xray_bad_auth_config);
        std::thread::sleep(Duration::from_millis(2300));
        bad_xray.assert_running();
        assert_reverse_echo_unavailable(public_addr);
        assert_eq!(
            echoed_bytes.load(Ordering::SeqCst),
            before,
            "invalid Reverse authentication must not dial the target"
        );
        chimera.assert_running();
        drop(bad_xray);
    }

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    xray.assert_running();
    assert_reverse_echo_with_retry(
        public_addr,
        format!(
            "xray bridge through chimera reverse portal ({})",
            security.name()
        )
        .as_bytes(),
        &echoed_bytes,
    );
    if matches!(security, ReverseSecurity::Raw) {
        assert_reverse_tcp_acceptance(public_addr, &echoed_bytes);
    }

    chimera.assert_running();
    xray.assert_running();
}

fn tls_client_hello_payload(server_name: &str) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default TLS protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_string())
            .expect("valid TLS sniffing server name");
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("create TLS sniffing client");
    let mut payload = Vec::new();
    connection
        .write_tls(&mut payload)
        .expect("serialize TLS ClientHello");
    assert!(!payload.is_empty(), "TLS ClientHello must not be empty");
    payload
}

fn free_localhost_udp_port() -> u16 {
    let socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind temporary UDP port");
    socket
        .local_addr()
        .expect("temporary UDP local address")
        .port()
}

fn assert_reverse_udp_echo_with_retry(
    public_addr: SocketAddr,
    payload: &[u8],
    echoed_bytes: &AtomicUsize,
) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let mut last_error = None;

    while Instant::now() < deadline {
        match reverse_udp_echo_once(public_addr, payload) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    panic!(
        "VLESS Reverse UDP worker did not become usable at {public_addr}; target received {} bytes: {}",
        echoed_bytes.load(Ordering::SeqCst),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no UDP exchange completed".to_string())
    );
}

fn start_observed_udp_echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    start_observed_udp_echo_server_on(Ipv4Addr::LOCALHOST.into())
}

fn start_observed_udp_echo_server_on(
    bind_ip: IpAddr,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .expect("bind observed Reverse UDP echo server");
    socket
        .set_read_timeout(Some(UDP_ECHO_IDLE_TIMEOUT))
        .expect("set Reverse UDP echo timeout");
    let address = socket
        .local_addr()
        .expect("observed Reverse UDP echo address");
    let received = Arc::new(AtomicUsize::new(0));
    let received_worker = received.clone();

    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        for _ in 0..32 {
            let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                break;
            };
            received_worker.fetch_add(length, Ordering::SeqCst);
            let _ = socket.send_to(&buffer[..length], peer);
        }
    });

    (address, received)
}

fn reverse_udp_echo_once(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.send_to(payload, public_addr)?;

    let mut response = vec![0u8; payload.len().max(1)];
    let (length, source) = socket.recv_from(&mut response)?;
    if source != public_addr {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Reverse UDP reply came from unexpected source {source}"),
        ));
    }
    response.truncate(length);
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse UDP echo payload mismatch",
        ));
    }

    Ok(())
}

fn assert_reverse_echo_with_retry(
    public_addr: SocketAddr,
    payload: &[u8],
    echoed_bytes: &AtomicUsize,
) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let mut last_error = None;

    while Instant::now() < deadline {
        match reverse_echo_once(public_addr, payload) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    panic!(
        "VLESS Reverse worker did not become usable at {public_addr}; target received {} bytes: {}",
        echoed_bytes.load(Ordering::SeqCst),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no connection attempt completed".to_string())
    );
}

fn assert_reverse_echo_unavailable(public_addr: SocketAddr) {
    let error = reverse_echo_once(public_addr, b"reverse-invalid-auth").expect_err(
        "invalid Reverse authentication must leave the route unavailable",
    );
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
        ),
        "unexpected unavailable-route error: {error}"
    );
}

fn wait_for_reverse_route_unavailable(public_addr: SocketAddr) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    while Instant::now() < deadline {
        match reverse_echo_once(public_addr, b"reverse-offline-probe") {
            Ok(()) => thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) {
                    return;
                }
                panic!("unexpected Reverse offline-probe error: {error}");
            }
        }
    }

    panic!(
        "Reverse route at {public_addr} remained usable without a Bridge worker; the target kept echoing offline probes"
    );
}

fn assert_reverse_tcp_acceptance(
    public_addr: SocketAddr,
    echoed_bytes: &AtomicUsize,
) {
    let large_payload = (0..256 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    reverse_echo_once(public_addr, &large_payload)
        .expect("Reverse RAW path must round-trip a 256 KiB payload");

    let concurrent_payload_len = 32 * 1024;
    let mut workers = Vec::new();
    for worker_id in 0..4u8 {
        workers.push(std::thread::spawn(move || {
            let payload = vec![
                worker_id.wrapping_mul(53).wrapping_add(17);
                concurrent_payload_len
            ];
            reverse_echo_once(public_addr, &payload)
        }));
    }
    for worker in workers {
        worker
            .join()
            .expect("Reverse concurrent echo worker panicked")
            .expect("Reverse RAW path must carry concurrent TCP sessions");
    }

    reverse_echo_then_shutdown(public_addr)
        .expect("Reverse Mux END must close the complete logical TCP session");

    let minimum_echoed = large_payload.len() + 4 * concurrent_payload_len;
    assert!(
        echoed_bytes.load(Ordering::SeqCst) >= minimum_echoed,
        "Reverse target must observe the large and concurrent payloads"
    );
}

fn reverse_echo_then_shutdown(public_addr: SocketAddr) -> std::io::Result<()> {
    let payload = b"reverse-mux-end";
    let mut stream = TcpStream::connect_timeout(&public_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(payload)?;

    let mut response = [0u8; 15];
    stream.read_exact(&mut response)?;
    if response != *payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse shutdown echo payload mismatch",
        ));
    }

    stream.shutdown(Shutdown::Write)?;
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse Mux END left the logical session readable",
        )),
        Err(error) => Err(error),
    }
}

fn start_proxy_protocol_echo_server() -> (SocketAddr, Arc<Mutex<Option<SocketAddr>>>)
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind Reverse PROXY protocol echo server");
    let address = listener
        .local_addr()
        .expect("Reverse PROXY protocol echo address");
    let captured_source = Arc::new(Mutex::new(None));
    let captured_worker = Arc::clone(&captured_source);

    std::thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let captured_source = Arc::clone(&captured_worker);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

                let mut header = Vec::with_capacity(108);
                let mut byte = [0u8; 1];
                while header.len() < 108 {
                    if stream.read_exact(&mut byte).is_err() {
                        return;
                    }
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n") {
                        break;
                    }
                }
                let Ok(header) = std::str::from_utf8(&header) else {
                    return;
                };
                let fields = header.split_whitespace().collect::<Vec<_>>();
                if fields.len() != 6 || fields[0] != "PROXY" || fields[1] != "TCP4" {
                    return;
                }
                let Ok(source_ip) = fields[2].parse::<std::net::IpAddr>() else {
                    return;
                };
                let Ok(source_port) = fields[4].parse::<u16>() else {
                    return;
                };
                *captured_source
                    .lock()
                    .expect("PROXY protocol capture lock poisoned") =
                    Some(SocketAddr::new(source_ip, source_port));

                let mut payload = [0u8; 4096];
                if let Ok(length) = stream.read(&mut payload)
                    && length != 0
                {
                    let _ = stream.write_all(&payload[..length]);
                }
            });
        }
    });

    (address, captured_source)
}

fn reverse_echo_once_with_source(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<SocketAddr> {
    let mut stream = TcpStream::connect_timeout(&public_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let source = stream.local_addr()?;
    stream.write_all(payload)?;

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response)?;
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse PROXY protocol echo payload mismatch",
        ));
    }
    Ok(source)
}

// Reverse-originated Freedom traffic defaults to block-all; keep e2e access
// limited to the fixture's loopback echo address family and ephemeral port.
fn loopback_allow_rule(network: &str, echo_addr: SocketAddr) -> serde_json::Value {
    json!({
        "action": "allow",
        "network": network,
        "port": echo_addr.port(),
        "ip": ["127.0.0.0/8", "::1/128"]
    })
}

fn start_observed_echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    start_observed_echo_server_on(Ipv4Addr::LOCALHOST.into())
}

fn start_observed_echo_server_on(bind_ip: IpAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))
        .expect("bind observed Reverse echo server");
    let address = listener
        .local_addr()
        .expect("observed Reverse echo address");
    let received = Arc::new(AtomicUsize::new(0));
    let received_worker = received.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let received = received_worker.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut buffer = [0u8; 4096];
                while let Ok(length) = stream.read(&mut buffer) {
                    if length == 0 {
                        break;
                    }
                    received.fetch_add(length, Ordering::SeqCst);
                    if stream.write_all(&buffer[..length]).is_err() {
                        break;
                    }
                }
            });
        }
    });

    (address, received)
}

fn reverse_echo_once(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&public_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(payload)?;

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response)?;
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse echo payload mismatch",
        ));
    }
    Ok(())
}

fn generate_test_certificate(work_dir: &Path) -> (PathBuf, PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate VLESS Reverse interoperability RSA key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build VLESS Reverse certificate params")
        .self_signed(&signing_key)
        .expect("generate VLESS Reverse test certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    fs::write(&cert_path, cert.pem())
        .expect("write VLESS Reverse interoperability certificate");
    fs::write(&key_path, signing_key.serialize_pem())
        .expect("write VLESS Reverse interoperability private key");
    (cert_path, key_path)
}

fn first_cert_sha256_hex(cert_path: &Path) -> String {
    let cert_file =
        File::open(cert_path).expect("open VLESS Reverse pinned certificate");
    let first_cert = certs(&mut BufReader::new(cert_file))
        .next()
        .expect("VLESS Reverse certificate present")
        .expect("parse VLESS Reverse certificate");
    let bytes = digest(&SHA256, first_cert.as_ref());
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
