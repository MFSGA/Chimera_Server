use std::{
    io::IoSliceMut,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
use crate::{
    address::{Address, NetLocation},
    config::server_config::DokodemoDoorConfig,
    handler::dokodemo::DokodemoDoorTcpHandler,
};

use crate::{
    handler::tcp::tcp_handler::{TcpServerSetupOutcome, TcpServerSetupResult},
    traffic::TrafficContext,
};

use super::*;

#[derive(Debug)]
struct AlwaysWritableUdpPoller;

impl UdpPoller for AlwaysWritableUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct FailingQuicUdpSocket {
    local_addr: SocketAddr,
}

impl AsyncUdpSocket for FailingQuicUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritableUdpPoller)
    }

    fn try_send(&self, _transmit: &Transmit) -> std::io::Result<()> {
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context<'_>,
        _bufs: &mut [IoSliceMut<'_>],
        _meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::other(
            "simulated QUIC UDP receive failure",
        )))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

#[tokio::test]
async fn quic_endpoint_driver_loss_reaches_inbound_health() {
    let config = ServerConfig {
        tag: "quic-driver-loss".to_string(),
        bind_location: BindLocation::Address(NetLocation::from_ip_addr(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            10002,
        )),
        protocol: ServerProxyConfig::Socks {
            accounts: crate::config::server_config::SocksUserStore::new(Vec::new()),
            udp_enabled: false,
            udp_response_ip: None,
            user_level: 0,
        },
        transport: Transport::Quic,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![config], Vec::new());
    assert!(runtime.mark_running());

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(FailingQuicUdpSocket {
            local_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 10002)),
        }),
        Arc::new(quinn::TokioRuntime),
    )
    .expect("construct endpoint with controlled failing socket");
    let task = tokio::spawn(async move {
        let error = accept_quic_with_health(&endpoint, "test-quic")
            .await
            .expect_err("driver loss must end QUIC accept");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    });
    runtime.register_inbound_tasks("quic-driver-loss", vec![task]);

    let failure = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.wait_for_inbound_failure(),
    )
    .await
    .expect("QUIC listener failure should reach runtime health");
    assert_eq!(failure.tag, "quic-driver-loss");
    assert!(!runtime.is_ready());
}

#[test]
fn tcp_accept_health_fails_only_after_sustained_listener_errors() {
    let mut health = TcpAcceptHealth::default();
    let error = std::io::Error::other("simulated listener resource failure");
    let started = Instant::now();

    for attempt in 0..(ACCEPT_ERROR_MIN_FAILURES - 1) {
        let disposition = health.classify_error_at(
            &error,
            started + Duration::from_millis(u64::from(attempt) * 100),
        );
        assert!(matches!(disposition, AcceptErrorDisposition::Retry(_)));
    }
    assert_eq!(
        health.classify_error_at(
            &error,
            started + ACCEPT_ERROR_UNHEALTHY_AFTER - Duration::from_millis(1),
        ),
        AcceptErrorDisposition::Retry(ACCEPT_ERROR_MAX_BACKOFF)
    );
    assert_eq!(
        health.classify_error_at(&error, started + ACCEPT_ERROR_UNHEALTHY_AFTER,),
        AcceptErrorDisposition::Fatal
    );
}

#[test]
fn tcp_accept_health_resets_on_success_or_connection_scoped_error() {
    let mut health = TcpAcceptHealth::default();
    let listener_error =
        std::io::Error::other("simulated listener resource failure");
    let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
    let started = Instant::now();

    assert_eq!(
        health.classify_error_at(&listener_error, started),
        AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
    );
    assert_eq!(
        health.classify_error_at(&aborted, started + Duration::from_secs(4)),
        AcceptErrorDisposition::Retry(Duration::ZERO)
    );
    assert_eq!(
        health.classify_error_at(&listener_error, started + Duration::from_secs(10)),
        AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
    );

    health.record_success();
    assert_eq!(
        health.classify_error_at(&listener_error, started + Duration::from_secs(20)),
        AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
    );
}

#[test]
fn tcp_accept_health_bounds_backoff_and_fails_terminal_states_immediately() {
    let mut health = TcpAcceptHealth::default();
    let error = std::io::Error::other("simulated listener resource failure");
    let started = Instant::now();
    let mut last_retry = Duration::ZERO;
    for attempt in 0..6 {
        let disposition = health.classify_error_at(
            &error,
            started + Duration::from_millis(attempt * 100),
        );
        let AcceptErrorDisposition::Retry(backoff) = disposition else {
            panic!("short error streak should remain retryable");
        };
        last_retry = backoff;
    }
    assert_eq!(last_retry, ACCEPT_ERROR_MAX_BACKOFF);

    let would_block = std::io::Error::from(std::io::ErrorKind::WouldBlock);
    assert_eq!(
        health.classify_error_at(&would_block, started + Duration::from_secs(1)),
        AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
    );

    let terminal = std::io::Error::from(std::io::ErrorKind::NotConnected);
    assert_eq!(
        health.classify_error_at(&terminal, started + Duration::from_secs(1)),
        AcceptErrorDisposition::Fatal
    );
}

#[tokio::test]
async fn bound_inbound_tasks_drop_releases_ready_listener() {
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port");
    let address = probe.local_addr().expect("read ephemeral address");
    drop(probe);

    let config = ServerConfig {
        tag: "bound-ready".to_string(),
        bind_location: BindLocation::Address(NetLocation::from_ip_addr(
            address.ip(),
            address.port(),
        )),
        protocol: ServerProxyConfig::Socks {
            accounts: crate::config::server_config::SocksUserStore::new(Vec::new()),
            udp_enabled: false,
            udp_response_ip: None,
            user_level: 0,
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
    let bound = start_bound_servers(config, runtime)
        .await
        .expect("bind inbound before returning readiness token");

    assert!(
        tokio::net::TcpListener::bind(address).await.is_err(),
        "bound result must represent an already-owned listener"
    );
    drop(bound);

    for _ in 0..50 {
        if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
            drop(listener);
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("dropping an unadopted bound result must release its listener");
}

#[test]
fn configured_identity_registration_respects_user_stats_policy() {
    let disabled_identity = "stats-policy-disabled-identity";
    let disabled_runtime = RuntimeState::new(Vec::new(), Vec::new());
    register_stats_identity(&disabled_runtime, 7, disabled_identity.to_string());
    assert!(
        !crate::traffic::snapshot()
            .known_identities
            .contains(disabled_identity)
    );

    let enabled_identity = "stats-policy-enabled-identity";
    let enabled_runtime = RuntimeState::new(Vec::new(), Vec::new());
    let mut levels = std::collections::HashMap::new();
    levels.insert(
        7,
        Some(crate::config::def::PolicyLevelConfig {
            stats_user_uplink: true,
            ..crate::config::def::PolicyLevelConfig::default()
        }),
    );
    enabled_runtime.replace_policy(Some(&crate::config::def::PolicyConfig {
        levels,
        ..crate::config::def::PolicyConfig::default()
    }));
    register_stats_identity(&enabled_runtime, 7, enabled_identity.to_string());
    assert!(
        crate::traffic::snapshot()
            .known_identities
            .contains(enabled_identity)
    );
}

#[test]
fn sniffed_http_metadata_drives_xray_override_and_exclusions() {
    let SniffInspection::Complete(metadata) = inspect_sniffed_routing_metadata(
        b"GET /private?q=1 HTTP/1.1\r\nHost: Api.Example.COM:443\r\nX-Test: ok\r\n\r\n",
    ) else {
        panic!("HTTP request should be sniffed");
    };
    assert_eq!(metadata.protocol.as_deref(), Some("http1"));
    assert_eq!(metadata.domain.as_deref(), Some("api.example.com"));
    assert_eq!(
        metadata.attributes.get(":method").map(String::as_str),
        Some("GET")
    );
    assert_eq!(
        metadata.attributes.get(":path").map(String::as_str),
        Some("/private?q=1")
    );
    assert_eq!(
        metadata.attributes.get("x-test").map(String::as_str),
        Some("ok")
    );

    let original =
        NetLocation::new(Address::Ipv4("192.0.2.7".parse().unwrap()), 8443);
    let replace = InboundSniffingConfig {
        enabled: true,
        dest_override_http: true,
        ..InboundSniffingConfig::default()
    };
    assert_eq!(
        sniffed_outbound_target(Some(&replace), &metadata, &original),
        NetLocation::new(Address::Hostname("api.example.com".into()), 8443)
    );

    let route_only = InboundSniffingConfig {
        route_only: true,
        ..replace.clone()
    };
    assert_eq!(
        sniffed_outbound_target(Some(&route_only), &metadata, &original),
        original
    );
    assert_eq!(
        route_only_sniffed_domain(Some(&route_only), &metadata, &original)
            .as_deref(),
        Some("api.example.com")
    );
    let local_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let plan = build_sniffed_route_plan(
        Some(&route_only),
        metadata.clone(),
        &original,
        Some(local_addr),
    );
    assert_eq!(plan.outbound_target, original);
    assert_eq!(plan.routing_metadata.local_addr, Some(local_addr));
    assert_eq!(
        plan.routing_metadata.sniffed_protocol.as_deref(),
        Some("http1")
    );
    assert_eq!(
        plan.routing_metadata.route_target_domain.as_deref(),
        Some("api.example.com")
    );

    let exclusions = crate::routing_state::SniffExclusionMatcher::compile(
        vec!["domain:example.com".into()],
        vec!["192.0.2.0/24".into()],
    )
    .expect("sniff exclusions should compile");
    let excluded = InboundSniffingConfig {
        exclusions: Arc::new(exclusions),
        ..replace
    };
    assert_eq!(
        sniffed_outbound_target(Some(&excluded), &metadata, &original),
        original
    );
    assert_eq!(
        route_only_sniffed_domain(Some(&excluded), &metadata, &original),
        None
    );
}

#[tokio::test]
async fn sniff_stream_replays_consumed_bytes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().unwrap();
    let connect = tokio::net::TcpStream::connect(addr);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let mut client = client.expect("connect loopback client");
    let (server, _) = accepted.expect("accept loopback client");

    let payload = b"GET / HTTP/1.1\r\nHost: replay.example\r\n\r\nbody";
    client.write_all(payload).await.unwrap();
    let config = InboundSniffingConfig {
        enabled: true,
        dest_override_http: true,
        ..InboundSniffingConfig::default()
    };
    let (mut stream, metadata) =
        sniff_stream_protocol(Box::new(server), Some(&config))
            .await
            .expect("sniff stream");
    assert_eq!(metadata.domain.as_deref(), Some("replay.example"));
    let mut replayed = vec![0; payload.len()];
    stream.read_exact(&mut replayed).await.unwrap();
    assert_eq!(replayed, payload);
}

#[test]
fn logical_stream_context_preserves_local_addr() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let local_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let context = stream_connection_context(&runtime.data_plane(), Some(local_addr));

    assert_eq!(context.local_addr, Some(local_addr));
    assert!(context.runtime.is_some());
}

#[test]
fn routing_identity_projects_only_routing_fields() {
    assert_eq!(routing_identity(None), ("", ""));

    let context = TrafficContext::new("test")
        .with_inbound_tag("inbound-a")
        .with_identity("user-a");
    assert_eq!(routing_identity(Some(&context)), ("inbound-a", "user-a"));
}

#[test]
fn setup_result_normalization_uses_innermost_peer_override() {
    let original: SocketAddr = "192.0.2.1:1000".parse().unwrap();
    let outer: SocketAddr = "192.0.2.2:2000".parse().unwrap();
    let inner: SocketAddr = "192.0.2.3:3000".parse().unwrap();
    let result = TcpServerSetupResult::PeerAddrOverride {
        peer_addr: outer,
        inner: Box::new(TcpServerSetupResult::PeerAddrOverride {
            peer_addr: inner,
            inner: Box::new(TcpServerSetupResult::AlreadyHandled),
        }),
    };

    let (peer_addr, normalized) =
        normalize_setup_result(result, original, None).unwrap();
    assert_eq!(peer_addr, inner);
    assert!(matches!(normalized, TcpServerSetupOutcome::AlreadyHandled));
}

#[test]
fn setup_result_normalization_reapplies_followup_peer_override() {
    let original: SocketAddr = "192.0.2.1:1000".parse().unwrap();
    let first: SocketAddr = "192.0.2.2:2000".parse().unwrap();
    let followup: SocketAddr = "192.0.2.3:3000".parse().unwrap();

    let first_result = TcpServerSetupResult::PeerAddrOverride {
        peer_addr: first,
        inner: Box::new(TcpServerSetupResult::AlreadyHandled),
    };
    let (peer_addr, _) =
        normalize_setup_result(first_result, original, None).unwrap();
    assert_eq!(peer_addr, first);

    let followup_result = TcpServerSetupResult::PeerAddrOverride {
        peer_addr: followup,
        inner: Box::new(TcpServerSetupResult::AlreadyHandled),
    };
    let (peer_addr, normalized) =
        normalize_setup_result(followup_result, peer_addr, None).unwrap();
    assert_eq!(peer_addr, followup);
    assert!(matches!(normalized, TcpServerSetupOutcome::AlreadyHandled));
}

#[test]
fn proxy_protocol_v1_encodes_ipv4_addresses_and_ports() {
    let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let header = build_proxy_protocol_header(1, source, Some(destination))
        .expect("build PROXY v1 header");
    assert_eq!(header, b"PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n");
}

#[test]
fn proxy_protocol_v2_encodes_ipv4_addresses_and_ports() {
    let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let header = build_proxy_protocol_header(2, source, Some(destination))
        .expect("build PROXY v2 header");
    let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    expected.extend_from_slice(&[192, 0, 2, 10]);
    expected.extend_from_slice(&[198, 51, 100, 20]);
    expected.extend_from_slice(&12345u16.to_be_bytes());
    expected.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(header, expected);
}

#[test]
fn proxy_protocol_uses_unknown_or_local_for_mixed_families() {
    let source = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
    let destination = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
    assert_eq!(
        build_proxy_protocol_header(1, source, Some(destination)).unwrap(),
        b"PROXY UNKNOWN\r\n"
    );
    let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    expected.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    assert_eq!(
        build_proxy_protocol_header(2, source, Some(destination)).unwrap(),
        expected
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_destination_matches_tcp_listener() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind original-destination listener");
    let listener_addr = listener.local_addr().expect("listener address");
    let connect_task = tokio::spawn(async move {
        TcpStream::connect(listener_addr)
            .await
            .expect("connect original-destination listener")
    });
    let (server_stream, _) = listener
        .accept()
        .await
        .expect("accept original-destination connection");
    let _client_stream = connect_task.await.expect("connect task finished");
    let handler = DokodemoDoorTcpHandler::new(
        DokodemoDoorConfig {
            target: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 1),
            follow_redirect: true,
            user_level: 0,
        },
        "dokodemo-original-destination",
    );

    let context = tcp_server_connection_context(&server_stream, &handler)
        .expect("read SO_ORIGINAL_DST from accepted TCP connection");
    assert_eq!(
        context.original_destination,
        Some(NetLocation::from_ip_addr(
            listener_addr.ip(),
            listener_addr.port(),
        ))
    );
}
