use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

#[cfg(feature = "traffic")]
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
#[cfg(feature = "traffic")]
use tokio::{net::UdpSocket, time::timeout};

use super::*;
use crate::runtime::RuntimeState;
#[cfg(all(feature = "trojan", feature = "traffic"))]
use crate::{
    address::NetLocation,
    config::{
        def::OutboundItem,
        rule::{NetworkListConfig, RoutingConfig, RuleConfig},
    },
    handler::trojan_udp::TrojanUdpStream,
    outbound::compile_static_outbound,
    routing_state::RoutingState,
};
#[cfg(feature = "traffic")]
use crate::{
    resolver::{NativeResolver, Resolver},
    runtime::OutboundSummary,
    traffic::{active_connections, snapshot},
};

#[cfg(all(feature = "trojan", feature = "traffic"))]
async fn start_fake_trojan_udp_proxy(
    expected_target: NetLocation,
) -> (OutboundSummary, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut password_hash = [0u8; 56];
        stream.read_exact(&mut password_hash).await.unwrap();
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected_hash = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(password_hash.as_slice(), expected_hash.as_slice());
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.unwrap(), 0x03);
        assert_eq!(stream.read_u8().await.unwrap(), ADDR_TYPE_DOMAIN);
        let domain_len = stream.read_u8().await.unwrap() as usize;
        let mut domain = vec![0u8; domain_len];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&domain).unwrap(),
            expected_target.address().hostname().unwrap()
        );
        assert_eq!(stream.read_u16().await.unwrap(), expected_target.port());
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(crlf, *b"\r\n");

        let mut udp = TrojanUdpStream::new(Box::new(stream));
        let mut buffer = [0u8; 8192];
        while let Ok((target, length)) = udp.recv_from(&mut buffer).await {
            assert_eq!(target, expected_target);
            if udp.send_to(&target, &buffer[..length]).await.is_err() {
                break;
            }
        }
    });
    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": proxy_addr.ip().to_string(),
            "port": proxy_addr.port(),
            "password": "secret"
        }
    }))
    .unwrap();
    (compile_static_outbound(&item).unwrap(), task)
}

#[cfg(all(feature = "trojan", feature = "traffic"))]
fn runtime_routing_udp_to(outbound: OutboundSummary) -> RuntimeState {
    let runtime = RuntimeState::new(Vec::new(), vec![outbound]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .unwrap(),
    );
    runtime
}

#[cfg(all(feature = "trojan", feature = "traffic"))]
fn socks_udp_request(target: &NetLocation, payload: &[u8]) -> Vec<u8> {
    let mut request = vec![0, 0, 0, ADDR_TYPE_DOMAIN];
    let domain = target.address().hostname().unwrap().as_bytes();
    request.push(domain.len() as u8);
    request.extend_from_slice(domain);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(payload);
    request
}

#[cfg(all(feature = "trojan", feature = "traffic"))]
fn parse_socks_udp_response(data: &[u8]) -> (NetLocation, &[u8]) {
    assert!(data.len() >= 4);
    assert_eq!(&data[..3], &[0, 0, 0]);
    let (target, payload_offset) = parse_udp_address(data, 3).unwrap();
    (target, &data[payload_offset..])
}

#[tokio::test]
async fn socks_handshake_policy_starts_after_protocol_discriminator_like_xray() {
    use crate::config::def::{PolicyConfig, PolicyLevelConfig};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, peer_addr) = listener.accept().await.unwrap();
    let local_addr = server.local_addr().unwrap();

    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            handshake: Some(0),
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks",
        false,
        None,
    )
    .with_user_level(7);
    let context = TcpServerConnectionContext {
        peer_addr: Some(peer_addr),
        local_addr: Some(local_addr),
        listener_addr: Some(listener_addr),
        runtime: Some(runtime.data_plane()),
        ..TcpServerConnectionContext::default()
    };
    let mut task = tokio::spawn(async move {
        handler
            .setup_server_stream_with_context(Box::new(server), context)
            .await
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut task)
            .await
            .is_err(),
        "Xray does not start the SOCKS handshake deadline before the first byte"
    );

    client.write_all(&[SOCKS_VERSION]).await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), &mut task)
        .await
        .expect("zero-second policy must terminate the SOCKS handshake")
        .expect("handler task must not panic");
    let error = match result {
        Ok(_) => panic!("incomplete SOCKS handshake must time out"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn udp_activity_window_matches_xray_v26_2_6_downlink_only_refresh() {
    let mut activity = XrayUdpActivityWindow::new();

    assert!(activity.keep_alive_on_check());
    assert!(!activity.keep_alive_on_check());

    activity.record_downstream();
    assert!(activity.keep_alive_on_check());
    assert!(!activity.keep_alive_on_check());
}

#[tokio::test]
async fn closed_udp_sessions_are_pruned_like_xray_dispatcher_rays() {
    let (closed_sender, closed_receiver) = mpsc::channel(1);
    drop(closed_receiver);
    let closed_task = tokio::spawn(std::future::pending::<()>());

    let (open_sender, _open_receiver) = mpsc::channel(1);
    let open_task = tokio::spawn(std::future::pending::<()>());

    let closed_key = ("127.0.0.1:10001".parse().unwrap(), false);
    let open_key = ("127.0.0.1:10002".parse().unwrap(), false);
    let mut sessions = HashMap::from([
        (
            closed_key,
            SocksUdpClientSession {
                sender: closed_sender,
                task: Some(closed_task),
            },
        ),
        (
            open_key,
            SocksUdpClientSession {
                sender: open_sender,
                task: Some(open_task),
            },
        ),
    ]);

    prune_closed_udp_sessions(&mut sessions);

    assert!(!sessions.contains_key(&closed_key));
    assert!(sessions.contains_key(&open_key));
}

async fn socks4_setup(
    handler: &SocksTcpServerHandler,
    request: &[u8],
) -> (TcpServerSetupResult, [u8; 8]) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client.write_all(request).await.unwrap();

    let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
    let mut response = [0u8; 8];
    client.read_exact(&mut response).await.unwrap();
    (result, response)
}

#[test]
fn socks5_domain_validation_matches_xray() {
    for domain in ["example.com", "srv_name-1.local", "127.0.0.1"] {
        validate_socks5_domain(domain).unwrap();
    }
    for domain in ["", "bad/name", "bad name", "bad:name", "café.test"] {
        assert!(validate_socks5_domain(domain).is_err(), "{domain}");
    }

    assert_eq!(
        parse_xray_socks_domain_address("[::1]").unwrap(),
        Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("[127.0.0.1]").unwrap(),
        Address::Ipv4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("[::ffff:127.0.0.1]").unwrap(),
        Address::Ipv4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("[ 127.0.0.1 ]").unwrap(),
        Address::Ipv4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("[ ::1 ]").unwrap(),
        Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("127.0.0.1 ").unwrap(),
        Address::Ipv4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        parse_xray_socks_domain_address("2001:db8::1 ").unwrap(),
        Address::Ipv6("2001:db8::1".parse().unwrap())
    );
    assert!(parse_xray_socks_domain_address("[ example.com ]").is_err());
    assert!(parse_xray_socks_domain_address(" 127.0.0.1").is_err());
    assert!(parse_xray_socks_domain_address("1.example.com ").is_err());
    assert!(parse_xray_socks_domain_address("::1").is_err());

    let domain = b"bad/name";
    let mut packet = vec![ADDR_TYPE_DOMAIN, domain.len() as u8];
    packet.extend_from_slice(domain);
    packet.extend_from_slice(&53u16.to_be_bytes());
    assert!(parse_udp_address(&packet, 0).is_err());
}

#[test]
fn socks5_udp_domain_atyp_accepts_bracketed_ip_literals_like_xray() {
    for (domain, expected) in [
        ("[::1]", Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
        ("[127.0.0.1]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        ("[::ffff:127.0.0.1]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        ("[ 127.0.0.1 ]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        ("[ ::1 ]", Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
        ("127.0.0.1 ", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        (
            "2001:db8::1 ",
            Address::Ipv6("2001:db8::1".parse().unwrap()),
        ),
    ] {
        let domain = domain.as_bytes();
        let mut packet = vec![ADDR_TYPE_DOMAIN, domain.len() as u8];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&53u16.to_be_bytes());
        let (location, used) = parse_udp_address(&packet, 0).unwrap();
        assert_eq!(location.address(), &expected);
        assert_eq!(location.port(), 53);
        assert_eq!(used, packet.len());
    }
}

#[tokio::test]
async fn socks5_tcp_domain_parser_rejects_xray_invalid_names() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let domain = b"bad/name";
    client
        .write_all(&[ADDR_TYPE_DOMAIN, domain.len() as u8])
        .await
        .unwrap();
    client.write_all(domain).await.unwrap();
    client.write_all(&53u16.to_be_bytes()).await.unwrap();

    let mut server: Box<dyn AsyncStream> = Box::new(server);
    assert!(read_address_from_stream(&mut server).await.is_err());
}

#[test]
fn socks5_udp_ipv4_mapped_ipv6_is_canonicalized_like_xray() {
    let mapped = std::net::Ipv6Addr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
    ]);
    let mut packet = vec![ADDR_TYPE_IPV6];
    packet.extend_from_slice(&mapped.octets());
    packet.extend_from_slice(&53u16.to_be_bytes());

    let (location, used) = parse_udp_address(&packet, 0).unwrap();
    assert_eq!(location.address(), &Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(location.port(), 53);
    assert_eq!(used, packet.len());
}

#[tokio::test]
async fn socks5_tcp_ipv4_mapped_ipv6_is_canonicalized_like_xray() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mapped = std::net::Ipv6Addr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
    ]);
    client.write_all(&[ADDR_TYPE_IPV6]).await.unwrap();
    client.write_all(&mapped.octets()).await.unwrap();
    client.write_all(&443u16.to_be_bytes()).await.unwrap();

    let mut server: Box<dyn AsyncStream> = Box::new(server);
    let location = read_address_from_stream(&mut server).await.unwrap();
    assert_eq!(location.address(), &Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(location.port(), 443);
}

#[test]
fn udp_response_packet_matches_xray_8kib_limit() {
    let src_addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let max_payload =
        XRAY_SOCKS_UDP_PACKET_SIZE - build_udp_response_header(src_addr).len();

    let at_limit = build_udp_response_packet(src_addr, &vec![0x5a; max_payload]);
    assert_eq!(at_limit.len(), XRAY_SOCKS_UDP_PACKET_SIZE);
    assert_eq!(&at_limit[10..], vec![0x5a; max_payload]);

    let oversized =
        build_udp_response_packet(src_addr, &vec![0x5a; max_payload + 1]);
    assert!(oversized.is_empty());
}

#[tokio::test]
async fn socks5_password_auth_version_is_ignored_like_xray() {
    for auth_version in [0x00, 0x02, 0x05] {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(
                vec![SocksUser {
                    username: "user".into(),
                    password: "pass".into(),
                }],
                true,
            ),
            "socks5-auth-version",
            false,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_USERNAME_PASSWORD,
                auth_version,
                4,
                b'u',
                b's',
                b'e',
                b'r',
                4,
                b'p',
                b'a',
                b's',
                b's',
                SOCKS_VERSION,
                CMD_CONNECT,
                0,
                ADDR_TYPE_IPV4,
                203,
                0,
                113,
                7,
                0x01,
                0xbb,
            ])
            .await
            .unwrap();

        let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
        let mut responses = [0u8; 4];
        client.read_exact(&mut responses).await.unwrap();
        assert_eq!(
            responses,
            [SOCKS_VERSION, METHOD_USERNAME_PASSWORD, AUTH_VERSION, 0x00]
        );

        let TcpServerSetupResult::TcpForward {
            remote_location,
            traffic_context,
            ..
        } = result
        else {
            panic!("expected SOCKS5 TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "203.0.113.7:443");
        assert_eq!(
            traffic_context.and_then(|context| context.identity),
            Some("user".to_string())
        );
    }
}

#[tokio::test]
async fn socks5_password_auth_failure_uses_xray_status_ff() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(
            vec![SocksUser {
                username: "user".into(),
                password: "pass".into(),
            }],
            true,
        ),
        "socks5-auth-failure-status",
        false,
        None,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    client
        .write_all(&[
            SOCKS_VERSION,
            1,
            METHOD_USERNAME_PASSWORD,
            AUTH_VERSION,
            4,
            b'u',
            b's',
            b'e',
            b'r',
            5,
            b'w',
            b'r',
            b'o',
            b'n',
            b'g',
        ])
        .await
        .unwrap();

    let error = match handler.setup_server_stream(Box::new(server)).await {
        Ok(_) => panic!("invalid SOCKS5 credentials must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

    let mut responses = [0u8; 4];
    client.read_exact(&mut responses).await.unwrap();
    assert_eq!(
        responses,
        [SOCKS_VERSION, METHOD_USERNAME_PASSWORD, AUTH_VERSION, 0xff]
    );
}

#[tokio::test]
async fn socks5_non_utf8_credentials_fail_auth_like_xray() {
    for (username, password) in [
        (vec![0xff], b"pass".to_vec()),
        (b"user".to_vec(), vec![0xff]),
    ] {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(
                vec![SocksUser {
                    username: "user".into(),
                    password: "pass".into(),
                }],
                true,
            ),
            "socks5-non-utf8-auth",
            false,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let mut request =
            vec![SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD, AUTH_VERSION];
        request.push(username.len() as u8);
        request.extend_from_slice(&username);
        request.push(password.len() as u8);
        request.extend_from_slice(&password);
        client.write_all(&request).await.unwrap();

        let error = match handler.setup_server_stream(Box::new(server)).await {
            Ok(_) => {
                panic!("non-UTF-8 SOCKS5 credentials must fail authentication")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut responses = [0u8; 4];
        client.read_exact(&mut responses).await.unwrap();
        assert_eq!(
            responses,
            [SOCKS_VERSION, METHOD_USERNAME_PASSWORD, AUTH_VERSION, 0xff]
        );
    }
}

#[tokio::test]
async fn socks5_command_version_and_reserved_are_ignored_like_xray() {
    for (request_version, reserved) in
        [(0x04, 0x00), (0x06, 0x00), (0x05, 0x07), (0x04, 0x07)]
    {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks5-request-header",
            false,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_NO_AUTH,
                request_version,
                CMD_CONNECT,
                reserved,
                ADDR_TYPE_IPV4,
                203,
                0,
                113,
                7,
                0x01,
                0xbb,
            ])
            .await
            .unwrap();

        let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
        let mut responses = [0u8; 12];
        client.read_exact(&mut responses).await.unwrap();
        assert_eq!(&responses[..2], &[SOCKS_VERSION, METHOD_NO_AUTH]);
        assert_eq!(&responses[2..], SUCCESS_RESPONSE.as_slice());

        let TcpServerSetupResult::TcpForward {
            remote_location,
            connection_success_response,
            ..
        } = result
        else {
            panic!("expected SOCKS5 TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "203.0.113.7:443");
        assert!(connection_success_response.is_none());
    }
}

#[tokio::test]
async fn socks5_unsupported_command_waits_for_reserved_byte_like_xray() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks5-command-header-timing",
        false,
        None,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    client
        .write_all(&[
            SOCKS_VERSION,
            1,
            METHOD_NO_AUTH,
            SOCKS_VERSION,
            0x02, // BIND is unsupported by Xray and Chimera.
        ])
        .await
        .unwrap();

    let task =
        tokio::spawn(
            async move { handler.setup_server_stream(Box::new(server)).await },
        );

    let mut method_response = [0u8; 2];
    client.read_exact(&mut method_response).await.unwrap();
    assert_eq!(method_response, [SOCKS_VERSION, METHOD_NO_AUTH]);

    let early_reply = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        client.read_u8(),
    )
    .await;
    assert!(
        early_reply.is_err(),
        "Xray waits for the request RSV byte before rejecting BIND"
    );

    client.write_all(&[0x7f]).await.unwrap();
    let mut command_response = [0u8; 10];
    client.read_exact(&mut command_response).await.unwrap();
    assert_eq!(
        command_response,
        build_socks5_response(REP_COMMAND_NOT_SUPPORTED, None).as_slice()
    );

    let error = match task.await.unwrap() {
        Ok(_) => panic!("unsupported SOCKS5 BIND command must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn socks5_connect_response_uses_listener_gateway_like_xray() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks5-bound-address",
        false,
        None,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let gateway_addr =
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), listener_addr.port());
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client
        .write_all(&[
            SOCKS_VERSION,
            1,
            METHOD_NO_AUTH,
            SOCKS_VERSION,
            CMD_CONNECT,
            0,
            ADDR_TYPE_IPV4,
            203,
            0,
            113,
            7,
            0x01,
            0xbb,
        ])
        .await
        .unwrap();

    let result = handler
        .setup_server_stream_with_context(
            Box::new(server),
            TcpServerConnectionContext {
                local_addr: Some(listener_addr),
                listener_addr: Some(gateway_addr),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut responses = [0u8; 12];
    client.read_exact(&mut responses).await.unwrap();
    assert_eq!(&responses[..2], &[SOCKS_VERSION, METHOD_NO_AUTH]);
    assert_eq!(
        &responses[2..],
        build_socks5_response(REP_SUCCEEDED, Some(gateway_addr)).as_slice()
    );

    let TcpServerSetupResult::TcpForward {
        connection_success_response,
        ..
    } = result
    else {
        panic!("expected SOCKS5 TCP forward result");
    };
    assert!(connection_success_response.is_none());
}

#[tokio::test]
async fn socks5_tor_resolve_commands_are_tcp_connect_like_xray() {
    for command in [CMD_TOR_RESOLVE, CMD_TOR_RESOLVE_PTR] {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks5-tor-command",
            false,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_NO_AUTH,
                SOCKS_VERSION,
                command,
                0,
                ADDR_TYPE_IPV4,
                203,
                0,
                113,
                7,
                0x01,
                0xbb,
            ])
            .await
            .unwrap();

        let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
        let mut responses = [0u8; 12];
        client.read_exact(&mut responses).await.unwrap();
        assert_eq!(&responses[..2], &[SOCKS_VERSION, METHOD_NO_AUTH]);
        assert_eq!(&responses[2..], SUCCESS_RESPONSE.as_slice());

        let TcpServerSetupResult::TcpForward {
            remote_location,
            connection_success_response,
            ..
        } = result
        else {
            panic!("expected SOCKS5 TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "203.0.113.7:443");
        assert!(connection_success_response.is_none());
    }
}

#[tokio::test]
async fn socks4_connect_matches_xray_handshake() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks4",
        false,
        None,
    );
    let request = [
        SOCKS4_VERSION,
        CMD_CONNECT,
        0x01,
        0xbb,
        203,
        0,
        113,
        7,
        b'u',
        b's',
        b'e',
        b'r',
        0,
    ];
    let (result, response) = socks4_setup(&handler, &request).await;

    assert_eq!(response, [0x00, SOCKS4_REQUEST_GRANTED, 0, 0, 0, 0, 0, 0]);
    let TcpServerSetupResult::TcpForward {
        remote_location,
        connection_success_response,
        traffic_context,
        ..
    } = result
    else {
        panic!("expected SOCKS4 TCP forward result");
    };
    assert_eq!(remote_location.to_string(), "203.0.113.7:443");
    assert!(connection_success_response.is_none());
    assert!(traffic_context.is_some());
}

#[tokio::test]
async fn socks4_null_terminated_fields_match_xray_buffer_limit() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks4-null-limit",
        false,
        None,
    );
    let mut accepted = vec![SOCKS4_VERSION, CMD_CONNECT, 0x01, 0xbb, 203, 0, 113, 7];
    accepted.extend(std::iter::repeat_n(b'u', XRAY_SOCKS4_NULL_FIELD_SIZE - 1));
    accepted.push(0);
    let (result, response) = socks4_setup(&handler, &accepted).await;
    assert_eq!(response[1], SOCKS4_REQUEST_GRANTED);
    assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mut rejected = vec![SOCKS4_VERSION, CMD_CONNECT, 0x01, 0xbb, 203, 0, 113, 7];
    rejected.extend(std::iter::repeat_n(b'u', XRAY_SOCKS4_NULL_FIELD_SIZE));
    rejected.push(0);
    client.write_all(&rejected).await.unwrap();
    let error = match handler.setup_server_stream(Box::new(server)).await {
        Ok(_) => {
            panic!("Xray rejects an 8192-byte SOCKS4 null-terminated field")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn socks4a_zero_prefix_uses_domain_like_xray() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks4a",
        false,
        None,
    );
    let mut request = vec![SOCKS4_VERSION, CMD_CONNECT, 0x00, 0x50, 0, 9, 8, 7, 0];
    request.extend_from_slice(b"example.com\0");
    let (result, response) = socks4_setup(&handler, &request).await;

    assert_eq!(response[1], SOCKS4_REQUEST_GRANTED);
    let TcpServerSetupResult::TcpForward {
        remote_location, ..
    } = result
    else {
        panic!("expected SOCKS4a TCP forward result");
    };
    assert_eq!(remote_location.to_string(), "example.com:80");
}

#[tokio::test]
async fn socks4a_domains_use_xray_parse_address_semantics() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks4a-domain-semantics",
        false,
        None,
    );
    for (domain, expected) in [
        (b"bad/name".as_slice(), "bad/name:80"),
        (b" bad.com ".as_slice(), "bad.com:80"),
        (b"bad name".as_slice(), "bad name:80"),
        (b"".as_slice(), ":80"),
    ] {
        let mut request =
            vec![SOCKS4_VERSION, CMD_CONNECT, 0x00, 0x50, 0, 0, 0, 1, 0];
        request.extend_from_slice(domain);
        request.push(0);
        let (result, response) = socks4_setup(&handler, &request).await;

        assert_eq!(response[1], SOCKS4_REQUEST_GRANTED, "domain={domain:?}");
        let TcpServerSetupResult::TcpForward {
            remote_location, ..
        } = result
        else {
            panic!("expected SOCKS4a TCP forward result for {domain:?}");
        };
        assert_eq!(remote_location.to_string(), expected, "domain={domain:?}");
    }
}

#[tokio::test]
async fn socks4a_bracketed_ip_domain_matches_xray() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks4a-bracketed-ip",
        false,
        None,
    );
    let mut request = vec![SOCKS4_VERSION, CMD_CONNECT, 0x01, 0xbb, 0, 0, 0, 1, 0];
    request.extend_from_slice(b"[127.0.0.1]\0");
    let (result, response) = socks4_setup(&handler, &request).await;

    assert_eq!(response[1], SOCKS4_REQUEST_GRANTED);
    let TcpServerSetupResult::TcpForward {
        remote_location, ..
    } = result
    else {
        panic!("expected SOCKS4a TCP forward result");
    };
    assert_eq!(remote_location.to_string(), "127.0.0.1:443");
}

#[tokio::test]
async fn socks4_is_rejected_when_password_auth_is_required() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(
            vec![SocksUser {
                username: "user".into(),
                password: "pass".into(),
            }],
            true,
        ),
        "socks4-auth",
        false,
        None,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client
        .write_all(&[SOCKS4_VERSION, CMD_CONNECT])
        .await
        .unwrap();

    let error = match handler.setup_server_stream(Box::new(server)).await {
        Ok(_) => {
            panic!("SOCKS4 must be rejected when password auth is required")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    let mut response = [0u8; 8];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x00, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]);
}

async fn http_fallback_setup(
    handler: &SocksTcpServerHandler,
    request: &[u8],
) -> TcpServerSetupResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client.write_all(request).await.unwrap();
    handler.setup_server_stream(Box::new(server)).await.unwrap()
}

#[tokio::test]
async fn non_socks_first_byte_falls_back_to_http_proxy() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks-http",
        false,
        None,
    );
    let result = http_fallback_setup(
        &handler,
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    )
    .await;

    let TcpServerSetupResult::TcpForward {
        remote_location,
        connection_success_response,
        traffic_context,
        ..
    } = result
    else {
        panic!("expected HTTP fallback TCP forward result");
    };
    assert_eq!(remote_location.to_string(), "example.com:443");
    assert_eq!(
        connection_success_response.as_deref(),
        Some(b"HTTP/1.1 200 Connection established\r\n\r\n".as_slice())
    );
    let traffic_context = traffic_context.expect("HTTP traffic context");
    assert_eq!(traffic_context.protocol, "http");
    assert_eq!(traffic_context.inbound_tag.as_deref(), Some("socks-http"));
}

#[tokio::test]
async fn http_fallback_auth_follows_xray_auth_type() {
    let account = SocksUser {
        username: "alice".into(),
        password: "secret".into(),
    };
    let authenticated = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(vec![account.clone()], true),
        "socks-http-auth",
        false,
        None,
    );
    let result = http_fallback_setup(
            &authenticated,
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
        )
        .await;
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = result
    else {
        panic!("expected authenticated HTTP fallback TCP forward result");
    };
    assert_eq!(
        traffic_context
            .expect("HTTP traffic context")
            .identity
            .as_deref(),
        Some("alice")
    );

    let no_auth = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(vec![account], false),
        "socks-http-noauth",
        false,
        None,
    );
    let result =
        http_fallback_setup(&no_auth, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await;
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = result
    else {
        panic!("expected no-auth HTTP fallback TCP forward result");
    };
    assert!(
        traffic_context
            .expect("HTTP traffic context")
            .identity
            .is_none(),
        "configured accounts must not force HTTP auth when Xray authType is NO_AUTH"
    );
}

#[tokio::test]
async fn udp_associate_advertises_tcp_local_ip_by_default() {
    let handler = SocksTcpServerHandler::new(
        SocksUserStore::with_auth_required(Vec::new(), false),
        "socks-local",
        true,
        None,
    )
    .with_user_level(7);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client
        .write_all(&[
            SOCKS_VERSION,
            1,
            METHOD_NO_AUTH,
            SOCKS_VERSION,
            CMD_UDP_ASSOCIATE,
            0,
            ADDR_TYPE_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
        .unwrap();

    let result = handler
        .setup_server_stream_with_context(
            Box::new(server),
            TcpServerConnectionContext {
                local_addr: Some(listener_addr),
                ..TcpServerConnectionContext::default()
            },
        )
        .await
        .expect("SOCKS UDP ASSOCIATE should succeed");
    let TcpServerSetupResult::UdpAssociate { user_level, .. } = result else {
        panic!("expected UDP associate result");
    };
    assert_eq!(user_level, 7);
    let mut response = [0u8; 12];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..2], &[SOCKS_VERSION, METHOD_NO_AUTH]);
    assert_eq!(&response[6..10], &Ipv4Addr::LOCALHOST.octets());
}

#[tokio::test]
async fn udp_associate_uses_explicit_client_hint_like_current_xray() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    client
        .write_all(&[ADDR_TYPE_IPV4, 127, 0, 0, 2, 0x12, 0x34])
        .await
        .unwrap();

    let result =
        handle_udp_associate(Box::new(server), None, None, None, None, None, 0)
            .await
            .unwrap();
    let TcpServerSetupResult::UdpAssociate {
        expected_client, ..
    } = result
    else {
        panic!("expected UDP associate result");
    };
    assert_eq!(expected_client, "127.0.0.2:4660".parse().unwrap());
}

#[tokio::test]
async fn udp_associate_unspecified_hint_uses_tcp_peer_like_current_xray() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, peer_addr) = listener.accept().await.unwrap();

    client
        .write_all(&[ADDR_TYPE_IPV4, 0, 0, 0, 0, 0x12, 0x34])
        .await
        .unwrap();

    let result = handle_udp_associate(
        Box::new(server),
        None,
        Some(peer_addr),
        None,
        None,
        None,
        0,
    )
    .await
    .unwrap();
    let TcpServerSetupResult::UdpAssociate {
        expected_client, ..
    } = result
    else {
        panic!("expected UDP associate result");
    };
    assert_eq!(expected_client.ip(), peer_addr.ip());
    assert_eq!(expected_client.port(), 0);
}

#[tokio::test]
async fn udp_associate_binds_and_advertises_configured_response_ip() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    client
        .write_all(&[ADDR_TYPE_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let advertised_ip = Ipv4Addr::LOCALHOST;
    let result = handle_udp_associate(
        Box::new(server),
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        None,
        Some(advertised_ip.to_string()),
        0,
    )
    .await
    .unwrap();

    let TcpServerSetupResult::UdpAssociate { udp_socket, .. } = result else {
        panic!("expected UDP associate result");
    };
    assert_eq!(
        udp_socket.local_addr().unwrap().ip(),
        IpAddr::V4(advertised_ip)
    );

    let mut response = [0u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], SOCKS_VERSION);
    assert_eq!(response[1], REP_SUCCEEDED);
    assert_eq!(response[3], ADDR_TYPE_IPV4);
    assert_eq!(&response[4..8], &advertised_ip.octets());
    assert_eq!(
        u16::from_be_bytes([response[8], response[9]]),
        udp_socket.local_addr().unwrap().port()
    );
}

#[test]
fn udp_associate_response_matches_xray_domain_length_limit() {
    let max_domain = Address::Hostname("a".repeat(256));
    let response = build_udp_associate_response(&max_domain, 1080).unwrap();
    assert_eq!(response[3], ADDR_TYPE_DOMAIN);
    assert_eq!(response[4], 0);
    assert_eq!(response.len(), 3 + 1 + 1 + 256 + 2);

    let oversized_domain = Address::Hostname("a".repeat(257));
    let error = build_udp_associate_response(&oversized_domain, 1080).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn udp_associate_advertises_configured_domain_like_xray() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    client
        .write_all(&[ADDR_TYPE_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let result = handle_udp_associate(
        Box::new(server),
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(listener_addr),
        Some("localhost".to_string()),
        0,
    )
    .await
    .unwrap();
    let TcpServerSetupResult::UdpAssociate { udp_socket, .. } = result else {
        panic!("expected UDP associate result");
    };

    let mut response = vec![0u8; 3 + 1 + 1 + "localhost".len() + 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], SOCKS_VERSION);
    assert_eq!(response[1], REP_SUCCEEDED);
    assert_eq!(response[3], ADDR_TYPE_DOMAIN);
    assert_eq!(response[4] as usize, "localhost".len());
    assert_eq!(&response[5..14], b"localhost");
    assert_eq!(
        u16::from_be_bytes([response[14], response[15]]),
        udp_socket.local_addr().unwrap().port()
    );
}

#[cfg(all(feature = "trojan", feature = "traffic"))]
#[tokio::test]
async fn shared_udp_listener_routes_through_trojan_outbound() {
    let target = NetLocation::from_str("origin.example:53", None).unwrap();
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy);
    let relay = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let relay_task = tokio::spawn(run_shared_udp_relay(
        relay,
        Arc::new(NativeResolver::new()),
        runtime.data_plane(),
        SocksUserStore::with_auth_required(Vec::new(), false),
        None,
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client
        .send_to(
            &socks_udp_request(&target, b"shared-via-trojan"),
            relay_addr,
        )
        .await
        .unwrap();
    let mut response = [0u8; 256];
    let (length, _) =
        timeout(Duration::from_secs(5), client.recv_from(&mut response))
            .await
            .expect("SOCKS shared Trojan UDP response timeout")
            .unwrap();
    let (source, payload) = parse_socks_udp_response(&response[..length]);
    assert_eq!(source, target);
    assert_eq!(payload, b"shared-via-trojan");

    relay_task.abort();
    proxy_task.abort();
}

#[cfg(all(feature = "trojan", feature = "traffic"))]
#[tokio::test]
async fn udp_associate_routes_through_trojan_outbound() {
    let target = NetLocation::from_str("origin.example:53", None).unwrap();
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy);
    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();

    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        Arc::new(NativeResolver::new()),
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client
        .send_to(
            &socks_udp_request(&target, b"associate-via-trojan"),
            relay_addr,
        )
        .await
        .unwrap();
    let mut response = [0u8; 256];
    let (length, _) =
        timeout(Duration::from_secs(5), client.recv_from(&mut response))
            .await
            .expect("SOCKS UDP_ASSOCIATE Trojan response timeout")
            .unwrap();
    let (source, payload) = parse_socks_udp_response(&response[..length]);
    assert_eq!(source, target);
    assert_eq!(payload, b"associate-via-trojan");

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("SOCKS UDP_ASSOCIATE relay shutdown timeout")
        .unwrap()
        .unwrap();
    proxy_task.abort();
}

#[cfg(feature = "traffic")]
async fn udp_source_from_alternate_loopback_is_forwarded(
    restrict_client_ip_to_tcp_peer: bool,
) -> bool {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        restrict_client_ip_to_tcp_peer,
        None,
    ));

    let alternate_source = Ipv4Addr::new(127, 0, 0, 2);
    let client_socket = UdpSocket::bind((alternate_source, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!("test origin socket must use IPv4");
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    request.extend_from_slice(b"source-check");
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut received = [0u8; 64];
    let forwarded = timeout(
        Duration::from_millis(300),
        origin_socket.recv_from(&mut received),
    )
    .await
    .is_ok();

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    forwarded
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn shared_udp_listener_matches_xray_noauth_and_password_filtering() {
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        for _ in 0..2 {
            let (len, peer) = origin.recv_from(&mut buf).await.unwrap();
            origin.send_to(&buf[..len], peer).await.unwrap();
        }
    });

    for auth_required in [false, true] {
        let relay =
            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let accounts = SocksUserStore::with_auth_required(Vec::new(), auth_required);
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let task = tokio::spawn(run_shared_udp_relay(
            relay,
            Arc::new(NativeResolver::new()),
            runtime.data_plane(),
            accounts.clone(),
            None,
        ));
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(origin_ip) = origin_addr.ip() else {
            unreachable!()
        };
        request.extend_from_slice(&origin_ip.octets());
        request.extend_from_slice(&origin_addr.port().to_be_bytes());
        request.extend_from_slice(b"shared");

        if auth_required {
            client.send_to(&request, relay_addr).await.unwrap();
            let mut dropped = [0u8; 64];
            assert!(
                timeout(Duration::from_millis(150), client.recv_from(&mut dropped))
                    .await
                    .is_err()
            );
            accounts.authorize_udp_ip(client.local_addr().unwrap().ip());
        }

        client.send_to(&request, relay_addr).await.unwrap();
        let mut response = [0u8; 64];
        let (len, _) =
            timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&response[len - b"shared".len()..len], b"shared");
        task.abort();
    }
    origin_task.await.unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn password_udp_authorization_does_not_survive_control_close_like_current_xray()
 {
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (len, peer) = origin.recv_from(&mut buf).await.unwrap();
        origin.send_to(&buf[..len], peer).await.unwrap();
    });

    let relay = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let accounts = SocksUserStore::with_auth_required(
        vec![SocksUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        true,
    );
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let relay_task = tokio::spawn(run_shared_udp_relay(
        relay,
        Arc::new(NativeResolver::new()),
        runtime.data_plane(),
        accounts.clone(),
        None,
    ));

    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let mut control_client = TcpStream::connect(control_addr).await.unwrap();
    let (control_server, peer_addr) = control_listener.accept().await.unwrap();
    let handler = SocksTcpServerHandler::new(accounts, "socks", true, None);
    control_client
        .write_all(&[
            0x05,
            0x01,
            0x02, // username/password method
            0x01,
            0x05,
            b'a',
            b'l',
            b'i',
            b'c',
            b'e',
            0x06,
            b's',
            b'e',
            b'c',
            b'r',
            b'e',
            b't', // RFC1929 credentials
            0x05,
            CMD_UDP_ASSOCIATE,
            0x00,
            ADDR_TYPE_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
        .unwrap();
    let result = handler
        .setup_server_stream_with_context(
            Box::new(control_server),
            TcpServerConnectionContext {
                peer_addr: Some(peer_addr),
                local_addr: Some(control_addr),
                listener_addr: Some(control_addr),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(result, TcpServerSetupResult::UdpAssociate { .. }));

    let mut handshake_response = [0u8; 14];
    control_client
        .read_exact(&mut handshake_response)
        .await
        .unwrap();
    assert_eq!(&handshake_response[..4], &[0x05, 0x02, 0x01, 0x00]);
    drop(result);
    drop(control_client);

    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!()
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    request.extend_from_slice(b"after-close");
    udp_client.send_to(&request, relay_addr).await.unwrap();

    let mut response = [0u8; 64];
    assert!(
        timeout(
            Duration::from_millis(200),
            udp_client.recv_from(&mut response)
        )
        .await
        .is_err(),
        "current Xray scopes UDP authorization to the live association"
    );

    relay_task.abort();
    origin_task.abort();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_noauth_accepts_non_tcp_peer_source_like_xray_v26_2_6() {
    assert!(udp_source_from_alternate_loopback_is_forwarded(false).await);
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_password_auth_filters_non_tcp_peer_source_like_xray_v26_2_6() {
    assert!(!udp_source_from_alternate_loopback_is_forwarded(true).await);
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_locks_first_source_port_like_current_xray() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (len, peer) = origin_socket.recv_from(&mut buf).await.unwrap();
        origin_socket.send_to(&buf[..len], peer).await.unwrap();
    });

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        true,
        None,
    ));

    let first_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let second_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    assert_ne!(
        first_client.local_addr().unwrap().port(),
        second_client.local_addr().unwrap().port()
    );

    let make_request = |payload: &[u8]| {
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(origin_ip) = origin_addr.ip() else {
            unreachable!("test origin socket must use IPv4");
        };
        request.extend_from_slice(&origin_ip.octets());
        request.extend_from_slice(&origin_addr.port().to_be_bytes());
        request.extend_from_slice(payload);
        request
    };

    first_client
        .send_to(&make_request(b"first"), relay_addr)
        .await
        .unwrap();
    let mut response = [0u8; 128];
    let (len, _) = timeout(
        Duration::from_secs(2),
        first_client.recv_from(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response[10..len], b"first");

    second_client
        .send_to(&make_request(b"second"), relay_addr)
        .await
        .unwrap();
    assert!(
        timeout(
            Duration::from_millis(200),
            second_client.recv_from(&mut response)
        )
        .await
        .is_err(),
        "current Xray locks a zero-port UDP hint to the first observed source port"
    );

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    origin_task.await.unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_reuses_outbound_source_port_across_targets_like_xray_v26_2_6() {
    let first_origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let first_origin_addr = first_origin.local_addr().unwrap();
    let second_origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let second_origin_addr = second_origin.local_addr().unwrap();

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let make_request = |target: SocketAddr, payload: &[u8]| {
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(target_ip) = target.ip() else {
            unreachable!("test origin socket must use IPv4");
        };
        request.extend_from_slice(&target_ip.octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        request.extend_from_slice(payload);
        request
    };

    client_socket
        .send_to(&make_request(first_origin_addr, b"one"), relay_addr)
        .await
        .unwrap();
    client_socket
        .send_to(&make_request(second_origin_addr, b"two"), relay_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (first_len, first_peer) =
        timeout(Duration::from_secs(2), first_origin.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buf[..first_len], b"one");
    let (second_len, second_peer) =
        timeout(Duration::from_secs(2), second_origin.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buf[..second_len], b"two");
    assert_eq!(first_peer.port(), second_peer.port());

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_tcp_close_waits_for_target_session_cleanup() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();
    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!("test origin socket must use IPv4");
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    request.extend_from_slice(b"cleanup");
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut buffer = [0u8; 64];
    let (length, worker_peer) =
        timeout(Duration::from_secs(2), origin_socket.recv_from(&mut buffer))
            .await
            .expect("SOCKS UDP target request timeout")
            .expect("receive SOCKS UDP target request");
    assert_eq!(&buffer[..length], b"cleanup");
    assert!(
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, worker_peer.port()))
            .await
            .is_err(),
        "SOCKS UDP target socket must still be owned before association teardown"
    );

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("SOCKS UDP association teardown timeout")
        .expect("SOCKS UDP association task must not panic")
        .expect("SOCKS UDP association teardown must succeed");

    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, worker_peer.port()))
        .await
        .expect(
            "association teardown must release target UDP socket before returning",
        );
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_target_session_retries_payload_after_idle_task_closed() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();
    let client_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let client_endpoint = client_socket.local_addr().unwrap();

    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let closed_task = tokio::spawn(async {});
    closed_task.await.unwrap();
    let closed_task = tokio::spawn(async {});
    let mut sessions = HashMap::from([(
        (client_endpoint, origin_addr.is_ipv6()),
        SocksUdpClientSession {
            sender,
            task: Some(closed_task),
        },
    )]);

    send_udp_target_payload(
        &mut sessions,
        origin_addr,
        client_endpoint,
        client_socket,
        None,
        b"after-idle".to_vec(),
        None,
    )
    .await
    .unwrap();

    let mut buf = [0u8; 64];
    let (len, _) =
        timeout(Duration::from_secs(2), origin_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buf[..len], b"after-idle");
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_connection_idle_uses_xray_user_level_policy() {
    use crate::config::def::{PolicyConfig, PolicyLevelConfig};

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime.replace_policy(Some(&PolicyConfig {
        levels: HashMap::from([(
            7,
            Some(PolicyLevelConfig {
                connection_idle: Some(1),
                ..PolicyLevelConfig::default()
            }),
        )]),
        ..PolicyConfig::default()
    }));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut relay_task = tokio::spawn(run_udp_relay_with_expected_client(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        None,
        7,
        None,
    ));

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        !relay_task.is_finished(),
        "Xray's initial activity token keeps the association through the first idle check"
    );

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client_socket.send_to(&[0], relay_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !relay_task.is_finished(),
        "valid-source UDP activity should keep the next Xray idle check alive"
    );

    timeout(Duration::from_millis(1_200), &mut relay_task)
        .await
        .expect("association should close on the following inactive check")
        .unwrap()
        .unwrap();
    drop(client_control);
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_forwards_multiple_responses_from_one_target_like_xray() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (len, peer) = origin_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
        origin_socket.send_to(b"one", peer).await.unwrap();
        origin_socket.send_to(b"two", peer).await.unwrap();
    });

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!("test origin socket must use IPv4");
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    request.extend_from_slice(b"ping");
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut payloads = Vec::new();
    for _ in 0..2 {
        let mut response = [0u8; 128];
        let (response_len, _) = timeout(
            Duration::from_secs(2),
            client_socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        payloads.push(response[10..response_len].to_vec());
    }
    assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    origin_task.await.unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_drops_empty_payloads_like_xray() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!("test origin socket must use IPv4");
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut received = [0u8; 1];
    assert!(
        timeout(
            Duration::from_millis(200),
            origin_socket.recv_from(&mut received)
        )
        .await
        .is_err()
    );

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_truncates_oversized_requests_like_xray() {
    let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_addr = origin_socket.local_addr().unwrap();

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        None,
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(origin_ip) = origin_addr.ip() else {
        unreachable!("test origin socket must use IPv4");
    };
    request.extend_from_slice(&origin_ip.octets());
    request.extend_from_slice(&origin_addr.port().to_be_bytes());
    request.extend(std::iter::repeat_n(0x5a, XRAY_SOCKS_UDP_PACKET_SIZE));
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut received = vec![0u8; XRAY_SOCKS_UDP_PACKET_SIZE * 2];
    let (len, _) = timeout(
        Duration::from_secs(2),
        origin_socket.recv_from(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(len, XRAY_SOCKS_UDP_PACKET_SIZE - 10);
    assert!(received[..len].iter().all(|byte| *byte == 0x5a));

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(feature = "traffic")]
#[tokio::test]
async fn udp_relay_routes_and_records_live_user_traffic() {
    let inbound_tag = "socks-udp-e2e-in";
    let outbound_tag = "socks-udp-e2e-out";
    let identity = "socks-udp-e2e-user";
    let payload = b"socks-udp-e2e";
    let before = snapshot();

    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo_socket.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let (len, peer) = echo_socket.recv_from(&mut buf).await.unwrap();
        echo_socket.send_to(&buf[..len], peer).await.unwrap();
    });

    let relay_socket =
        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let relay_addr = relay_socket.local_addr().unwrap();
    let control_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let control_addr = control_listener.local_addr().unwrap();
    let client_control = TcpStream::connect(control_addr).await.unwrap();
    let (server_control, _) = control_listener.accept().await.unwrap();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: outbound_tag.into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let client_ip: IpAddr = "203.0.113.19".parse().unwrap();
    let traffic_context = TrafficContext::new("socks")
        .with_identity(identity)
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_ip);
    let relay_task = tokio::spawn(run_udp_relay(
        relay_socket,
        Box::new(server_control),
        resolver,
        runtime.data_plane(),
        client_control.local_addr().unwrap(),
        false,
        Some(traffic_context),
    ));

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        unreachable!("test echo socket must use IPv4");
    };
    request.extend_from_slice(&echo_ip.octets());
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    request.extend_from_slice(payload);
    client_socket.send_to(&request, relay_addr).await.unwrap();

    let mut response = [0u8; 128];
    let (response_len, _) = timeout(
        Duration::from_secs(2),
        client_socket.recv_from(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response[10..response_len], payload);
    assert!(active_connections().iter().any(|entry| {
        entry.inbound_tag.as_deref() == Some(inbound_tag)
            && entry.identity.as_deref() == Some(identity)
            && entry.client_ip == Some(client_ip)
    }));

    let after = snapshot();
    let before_inbound = before
        .per_inbound
        .get(inbound_tag)
        .cloned()
        .unwrap_or_default();
    let after_inbound = after.per_inbound.get(inbound_tag).unwrap();
    assert_eq!(
        after_inbound.upload_bytes - before_inbound.upload_bytes,
        payload.len() as u64
    );
    assert_eq!(
        after_inbound.download_bytes - before_inbound.download_bytes,
        payload.len() as u64
    );
    let outbound = after.per_outbound.get(outbound_tag).unwrap();
    let before_outbound = before
        .per_outbound
        .get(outbound_tag)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        outbound.upload_bytes - before_outbound.upload_bytes,
        payload.len() as u64
    );
    assert_eq!(
        outbound.download_bytes - before_outbound.download_bytes,
        payload.len() as u64
    );
    let user = after
        .per_inbound_user
        .get(&(inbound_tag.into(), identity.into()))
        .unwrap();
    assert_eq!(user.upload_bytes, payload.len() as u64);
    assert_eq!(user.download_bytes, payload.len() as u64);

    drop(client_control);
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    echo_task.await.unwrap();
}
