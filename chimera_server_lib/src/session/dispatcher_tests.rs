use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::UdpSocket,
    time::timeout,
};

use crate::{
    address::{Address, NetLocation},
    config::{
        rule::{NetworkListConfig, RoutingConfig, RuleConfig},
        server_config::DokodemoDoorConfig,
    },
    handler::{
        dokodemo::DokodemoDoorTcpHandler,
        tcp::tcp_handler::TcpServerHandler,
        vless_reverse::{
            mux_frame::{FrameMetadata, FrameOption, SessionStatus},
            mux_io::{MuxFrame, encode_frame, read_frame_with_source_and_local},
            session_stream::ReverseSessionStream,
        },
    },
    routing_state::RoutingState,
    runtime::{OutboundSummary, RuntimeState},
    session::{
        dispatcher::process_stream_with_sniffing_and_local_addr,
        udp::run_bidirectional_udp,
    },
    traffic::TrafficContext,
};

#[tokio::test]
async fn bidirectional_udp_route_round_trips_through_reverse_portal_worker() {
    let runtime_state = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "reverse-out".into(),
            protocol: "vless-reverse".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    runtime_state.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["vless-udp".into()],
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("reverse-out".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile VLESS UDP to Reverse route"),
    );
    let runtime = runtime_state.data_plane();

    let (physical, mut bridge_peer) = duplex(16 * 1024);
    let _lease = runtime
        .attach_reverse_portal(
            "reverse-out",
            Box::new(ReverseSessionStream::new(physical)),
        )
        .await
        .expect("attach Reverse UDP worker");
    let _control = read_frame_with_source_and_local(&mut bridge_peer, true)
        .await
        .expect("read Reverse worker control frame");

    let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 5353);
    let relay_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind VLESS UDP relay socket");
    let relay_addr = relay_socket.local_addr().expect("VLESS UDP relay address");
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind VLESS UDP client socket");
    let client_addr = client_socket
        .local_addr()
        .expect("VLESS UDP client address");
    relay_socket
        .connect(client_addr)
        .await
        .expect("connect relay socket");
    client_socket
        .connect(relay_addr)
        .await
        .expect("connect client socket");

    let dispatch = tokio::spawn(run_bidirectional_udp(
        Box::new(relay_socket),
        target.clone(),
        runtime.resolver(),
        runtime.clone(),
        client_addr,
        Some(relay_addr),
        Some(
            TrafficContext::new("vless")
                .with_identity("udp-user")
                .with_inbound_tag("vless-udp"),
        ),
    ));
    client_socket
        .send(b"query")
        .await
        .expect("send request through fixed-target UDP stream");

    let request = timeout(
        Duration::from_secs(1),
        read_frame_with_source_and_local(&mut bridge_peer, true),
    )
    .await
    .expect("Reverse UDP request timeout")
    .expect("read Reverse UDP request");
    assert_eq!(request.metadata.status, SessionStatus::New);
    assert_eq!(request.metadata.target.as_ref().unwrap().location, target);
    assert_eq!(request.payload.as_ref(), b"query");
    let session_id = request.metadata.session_id;

    bridge_peer
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id,
                    status: SessionStatus::Keep,
                    option: FrameOption::default().with_data(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"reply"),
            })
            .expect("encode Reverse UDP response"),
        )
        .await
        .expect("write Reverse UDP response");

    let mut response = [0u8; 16];
    let length = timeout(Duration::from_secs(1), client_socket.recv(&mut response))
        .await
        .expect("fixed-target UDP response timeout")
        .expect("read fixed-target UDP response");
    assert_eq!(&response[..length], b"reply");

    dispatch.abort();
}

#[tokio::test]
async fn dokodemo_route_round_trips_through_reverse_portal_worker() {
    let runtime_state = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: "reverse-out".into(),
            protocol: "vless-reverse".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    runtime_state.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["public-8080".into()],
                outbound_tag: Some("reverse-out".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile DokodemoDoor -> Reverse route"),
    );
    let runtime = runtime_state.data_plane();

    let (physical, mut bridge_peer) = duplex(16 * 1024);
    let _lease = runtime
        .attach_reverse_portal(
            "reverse-out",
            Box::new(ReverseSessionStream::new(physical)),
        )
        .await
        .expect("attach ACTIVE Reverse worker");

    let control = read_frame_with_source_and_local(&mut bridge_peer, true)
        .await
        .expect("read initial Reverse control frame");
    assert_eq!(control.metadata.status, SessionStatus::New);

    let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 3000);
    let handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(Box::new(DokodemoDoorTcpHandler::new(
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
                user_level: 0,
            },
            "public-8080",
        )));

    let public_peer: SocketAddr =
        "198.51.100.20:55000".parse().expect("public peer address");
    let public_local: SocketAddr = "203.0.113.10:8080"
        .parse()
        .expect("public listener address");
    let (mut public_client, public_server) = duplex(16 * 1024);
    let resolver = runtime.resolver();
    let dispatch_runtime = runtime.clone();
    let dispatch = tokio::spawn(async move {
        process_stream_with_sniffing_and_local_addr(
            ReverseSessionStream::new(public_server),
            handler,
            resolver,
            public_peer,
            Some(public_local),
            dispatch_runtime,
            None,
        )
        .await
    });

    public_client
        .write_all(b"ping")
        .await
        .expect("write public TCP payload");

    let request = timeout(
        Duration::from_secs(1),
        read_frame_with_source_and_local(&mut bridge_peer, true),
    )
    .await
    .expect("Reverse NEW frame timeout")
    .expect("read Reverse NEW frame");
    assert_eq!(request.metadata.status, SessionStatus::New);
    assert_eq!(
        request
            .metadata
            .target
            .as_ref()
            .expect("Reverse target")
            .location,
        target
    );
    assert_eq!(
        request
            .metadata
            .source
            .as_ref()
            .expect("Reverse source")
            .location,
        NetLocation::from_ip_addr(public_peer.ip(), public_peer.port())
    );
    assert_eq!(
        request
            .metadata
            .local
            .as_ref()
            .expect("Reverse local")
            .location,
        NetLocation::from_ip_addr(public_local.ip(), public_local.port())
    );
    assert_eq!(request.payload.as_ref(), b"ping");
    let session_id = request.metadata.session_id;

    let response = encode_frame(&MuxFrame {
        metadata: FrameMetadata {
            session_id,
            status: SessionStatus::Keep,
            option: FrameOption::default().with_data(),
            target: None,
            source: None,
            local: None,
            global_id: None,
        },
        payload: Bytes::from_static(b"pong"),
    })
    .expect("encode Bridge response");
    bridge_peer
        .write_all(&response)
        .await
        .expect("write Bridge response");

    let mut reply = [0u8; 4];
    timeout(Duration::from_secs(1), public_client.read_exact(&mut reply))
        .await
        .expect("public response timeout")
        .expect("read public response");
    assert_eq!(&reply, b"pong");

    public_client.shutdown().await.expect("close public upload");
    let end = timeout(
        Duration::from_secs(1),
        read_frame_with_source_and_local(&mut bridge_peer, true),
    )
    .await
    .expect("Reverse END timeout")
    .expect("read Reverse END");
    assert_eq!(end.metadata.session_id, session_id);
    assert_eq!(end.metadata.status, SessionStatus::End);

    drop(bridge_peer);
    drop(public_client);
    timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("dispatcher shutdown timeout")
        .expect("dispatcher task join")
        .expect("DokodemoDoor Reverse path completes");
}
