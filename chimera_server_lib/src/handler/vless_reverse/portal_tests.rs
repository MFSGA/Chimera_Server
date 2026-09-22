use tokio::io::duplex;

use super::*;
use crate::handler::vless_reverse::{
    control::ControlState, mux_io::read_frame_with_source_and_local,
    session_stream::ReverseSessionStream,
};

#[tokio::test]
async fn attach_sends_xray_control_new_before_worker_becomes_routable() {
    let registry = ReversePortalRegistry::new(["reverse-out".to_string()]);
    let (physical, mut peer) = duplex(4096);
    let lease = registry
        .attach_physical(
            "reverse-out",
            Box::new(ReverseSessionStream::new(physical)),
        )
        .await
        .expect("attach Reverse physical connection");

    let frame = read_frame_with_source_and_local(&mut peer, true)
        .await
        .expect("read initial control Mux frame");
    assert_eq!(frame.metadata.status, SessionStatus::New);
    assert_eq!(frame.metadata.target, Some(xray_reverse_control_target()));
    let control = ReverseControl::decode(&frame.payload)
        .expect("decode initial ACTIVE control");
    assert_eq!(control.state, ControlState::Active);
    assert!(
        registry
            .open_tcp(
                "reverse-out",
                NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 80),
                "192.0.2.10:50000".parse().unwrap(),
                Some("203.0.113.5:8080".parse().unwrap()),
            )
            .is_ok()
    );
    drop(lease);
}

#[tokio::test]
async fn unknown_or_offline_portal_fails_without_freedom_fallback() {
    let registry = ReversePortalRegistry::new(["reverse-out".to_string()]);
    let target = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 80);
    let source = "192.0.2.10:50000".parse().unwrap();

    let unknown = registry
        .open_tcp("missing", target.clone(), source, None)
        .expect_err("unknown Reverse portal must fail");
    assert_eq!(unknown.kind(), std::io::ErrorKind::NotFound);

    let offline = registry
        .open_tcp("reverse-out", target, source, None)
        .expect_err("configured portal without ACTIVE worker must fail");
    assert_eq!(offline.kind(), std::io::ErrorKind::NotConnected);
}

#[tokio::test]
async fn public_tcp_open_emits_reverse_source_and_local_metadata() {
    let registry = ReversePortalRegistry::new(["reverse-out".to_string()]);
    let (physical, mut peer) = duplex(4096);
    let _lease = registry
        .attach_physical(
            "reverse-out",
            Box::new(ReverseSessionStream::new(physical)),
        )
        .await
        .expect("attach Reverse physical connection");
    let _control = read_frame_with_source_and_local(&mut peer, true)
        .await
        .expect("consume control frame");

    let mut session = registry
        .open_tcp(
            "reverse-out",
            NetLocation::new(Address::Hostname("service.internal".into()), 443),
            "192.0.2.10:50000".parse().unwrap(),
            Some("203.0.113.5:8443".parse().unwrap()),
        )
        .expect("open Reverse routed TCP session");
    tokio::io::AsyncWriteExt::write_all(&mut session, b"x")
        .await
        .expect("write public payload");

    let frame = read_frame_with_source_and_local(&mut peer, true)
        .await
        .expect("read Reverse public NEW frame");
    assert_eq!(frame.metadata.status, SessionStatus::New);
    assert_eq!(
        frame.metadata.source,
        Some(socket_destination("192.0.2.10:50000".parse().unwrap()))
    );
    assert_eq!(
        frame.metadata.local,
        Some(socket_destination("203.0.113.5:8443".parse().unwrap()))
    );
    assert_eq!(frame.payload.as_ref(), b"x");
}
