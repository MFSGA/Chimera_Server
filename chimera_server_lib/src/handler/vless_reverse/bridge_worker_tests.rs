use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::mpsc,
    time::timeout,
};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    handler::vless_reverse::{
        mux_frame::{
            Destination, FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
        },
        mux_io::{MuxFrame, encode_frame, read_frame},
        session_stream::ReverseSessionStream,
        site_policy::{
            SitePrefixMapConfig, SiteTargetAllowConfig, SiteToSiteConfig,
            SiteToSitePolicy,
        },
    },
    runtime::RuntimeState,
    session::tcp_relay::copy_bidirectional,
};

use super::super::{session_core::SessionLimits, worker::MuxClientWorker};
use super::{
    BridgeDispatchContext, BridgeTcpDispatcher, BridgeUdpResponse, BridgeUdpSession,
    MuxServerWorker, idle_snapshot_is_unchanged,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchCall {
    reverse_tag: String,
    target: NetLocation,
    source: Option<SocketAddr>,
    local: Option<SocketAddr>,
    routing_user: String,
    policy_identity: String,
    user_level: u32,
}

struct FakeDispatcher {
    stream: Mutex<Option<DuplexStream>>,
    calls: Mutex<Vec<DispatchCall>>,
}

impl FakeDispatcher {
    fn new(stream: DuplexStream) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<DispatchCall> {
        self.calls
            .lock()
            .expect("fake dispatch calls lock poisoned")
            .clone()
    }
}

#[async_trait]
impl BridgeTcpDispatcher for FakeDispatcher {
    async fn open_tcp(
        &self,
        reverse_tag: &str,
        target: NetLocation,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
        context: BridgeDispatchContext,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        self.calls
            .lock()
            .expect("fake dispatch calls lock poisoned")
            .push(DispatchCall {
                reverse_tag: reverse_tag.to_string(),
                target,
                source,
                local,
                routing_user: context.routing_user,
                policy_identity: context.policy_identity,
                user_level: context.user_level,
            });
        let stream = self
            .stream
            .lock()
            .expect("fake dispatch stream lock poisoned")
            .take()
            .ok_or_else(|| std::io::Error::other("fake stream already consumed"))?;
        Ok(Box::new(ReverseSessionStream::new(stream)))
    }

    async fn open_udp(
        &self,
        _reverse_tag: &str,
        _source: Option<SocketAddr>,
        _local: Option<SocketAddr>,
        _context: BridgeDispatchContext,
    ) -> std::io::Result<BridgeUdpSession> {
        let (requests, mut request_rx) =
            tokio::sync::mpsc::channel::<super::BridgeUdpRequest>(16);
        let (response_tx, responses) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(request) = request_rx.recv().await {
                let Some(source) = request.target.to_socket_addr_nonblocking()
                else {
                    continue;
                };
                if response_tx
                    .send(BridgeUdpResponse {
                        payload: request.payload,
                        source,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(BridgeUdpSession {
            requests,
            responses,
        })
    }
}

fn tcp_destination(address: Ipv4Addr, port: u16) -> Destination {
    Destination {
        network: TargetNetwork::Tcp,
        location: NetLocation::new(Address::Ipv4(address), port),
    }
}

fn site_to_site_policy() -> SiteToSitePolicy {
    SiteToSitePolicy::compile(&SiteToSiteConfig {
        prefix_maps: vec![SitePrefixMapConfig {
            from: "10.200.1.0/24".to_string(),
            to: "192.168.50.0/24".to_string(),
        }],
        allow: vec![SiteTargetAllowConfig {
            network: vec!["tcp".to_string(), "udp".to_string()],
            ip: vec!["192.168.50.0/24".to_string()],
            ports: vec!["22".to_string(), "53".to_string(), "80-443".to_string()],
        }],
    })
    .expect("compile site-to-site policy")
}

#[tokio::test]
async fn mux_server_routes_tcp_with_reverse_context_and_round_trips_frames() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, mut local_peer) = duplex(16 * 1024);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new_with_context(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher.clone(),
        BridgeDispatchContext {
            sniffing: None,
            routing_user: "bridge@example.test".to_string(),
            policy_identity: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
            user_level: 7,
            site_to_site: None,
        },
    );

    assert!(worker.is_active(), "Xray Bridge workers start ACTIVE");

    let target = tcp_destination(Ipv4Addr::LOCALHOST, 8080);
    let source: SocketAddr = "192.0.2.10:51000".parse().unwrap();
    let local_addr: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let request = MuxFrame {
        metadata: FrameMetadata {
            session_id: 7,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(target.clone()),
            source: Some(tcp_destination(
                match source.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                },
                source.port(),
            )),
            local: Some(tcp_destination(
                match local_addr.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                },
                local_addr.port(),
            )),
            global_id: None,
        },
        payload: Bytes::from_static(b"hello"),
    };
    portal
        .write_all(&encode_frame(&request).expect("encode Reverse NEW"))
        .await
        .expect("write Reverse NEW");

    let mut received = [0u8; 5];
    timeout(Duration::from_secs(1), local_peer.read_exact(&mut received))
        .await
        .expect("Bridge dispatched the logical TCP session")
        .expect("read initial Reverse payload");
    assert_eq!(&received, b"hello");

    assert_eq!(
        dispatcher.calls(),
        vec![DispatchCall {
            reverse_tag: "bridge-in".to_string(),
            target: target.location,
            source: Some(source),
            local: Some(local_addr),
            routing_user: "bridge@example.test".to_string(),
            policy_identity: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
            user_level: 7,
        }]
    );

    local_peer
        .write_all(b"world")
        .await
        .expect("write logical response");
    let response = timeout(Duration::from_secs(1), read_frame(&mut portal))
        .await
        .expect("Bridge emitted response frame")
        .expect("read response frame");
    assert_eq!(response.metadata.session_id, 7);
    assert_eq!(response.metadata.status, SessionStatus::Keep);
    assert_eq!(response.payload, Bytes::from_static(b"world"));

    local_peer.shutdown().await.expect("close logical response");
    let end = timeout(Duration::from_secs(1), read_frame(&mut portal))
        .await
        .expect("Bridge emitted END")
        .expect("read END");
    assert_eq!(end.metadata.session_id, 7);
    assert_eq!(end.metadata.status, SessionStatus::End);
    assert!(end.metadata.option.has_half_close());

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 7,
                    status: SessionStatus::End,
                    option: FrameOption::default().with_half_close(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode Portal half-close"),
        )
        .await
        .expect("write Portal half-close");

    timeout(Duration::from_secs(1), async {
        while worker.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("logical session is removed after END");
}

#[tokio::test]
async fn mux_server_preserves_tcp_response_after_half_close() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, mut local_peer) = duplex(16 * 1024);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher,
    );
    let session_id = 91;
    let target = tcp_destination(Ipv4Addr::LOCALHOST, 8080);
    let request = MuxFrame {
        metadata: FrameMetadata {
            session_id,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(target),
            source: None,
            local: None,
            global_id: None,
        },
        payload: Bytes::from_static(b"request"),
    };
    portal
        .write_all(&encode_frame(&request).expect("encode Reverse NEW"))
        .await
        .expect("write Reverse NEW");

    let mut received = [0u8; 7];
    timeout(Duration::from_secs(1), local_peer.read_exact(&mut received))
        .await
        .expect("Bridge dispatched the logical TCP session")
        .expect("read initial payload");
    assert_eq!(&received, b"request");

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id,
                    status: SessionStatus::End,
                    option: FrameOption::default().with_half_close(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode directional END"),
        )
        .await
        .expect("write directional END");

    let mut eof_probe = [0u8; 1];
    let read = timeout(Duration::from_secs(1), local_peer.read(&mut eof_probe))
        .await
        .expect("Bridge propagated the TCP write-side half-close")
        .expect("read EOF after half-close");
    assert_eq!(read, 0);

    local_peer
        .write_all(b"final-response")
        .await
        .expect("remote TCP peer can still return data after client FIN");
    local_peer
        .shutdown()
        .await
        .expect("close remote TCP peer response side");

    let response = timeout(Duration::from_secs(1), read_frame(&mut portal))
        .await
        .expect("Bridge forwards final response after half-close")
        .expect("read final response frame");
    assert_eq!(response.metadata.status, SessionStatus::Keep);
    assert_eq!(response.payload, Bytes::from_static(b"final-response"));

    let end = timeout(Duration::from_secs(1), read_frame(&mut portal))
        .await
        .expect("Bridge reports the remote write-side half-close")
        .expect("read remote half-close frame");
    assert_eq!(end.metadata.session_id, session_id);
    assert_eq!(end.metadata.status, SessionStatus::End);
    assert!(end.metadata.option.has_half_close());

    timeout(Duration::from_secs(1), async {
        while worker.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("logical session is removed after both TCP halves close");
}

struct FinalResponseDispatcher {
    accepted_targets: mpsc::UnboundedSender<DuplexStream>,
}

#[async_trait]
impl BridgeTcpDispatcher for FinalResponseDispatcher {
    async fn open_tcp(
        &self,
        _reverse_tag: &str,
        _target: NetLocation,
        _source: Option<SocketAddr>,
        _local: Option<SocketAddr>,
        _context: BridgeDispatchContext,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let (bridge_side, target_side) = duplex(64 * 1024);
        self.accepted_targets
            .send(target_side)
            .map_err(|_| std::io::Error::other("test target receiver closed"))?;
        Ok(Box::new(ReverseSessionStream::new(bridge_side)))
    }

    async fn open_udp(
        &self,
        _reverse_tag: &str,
        _source: Option<SocketAddr>,
        _local: Option<SocketAddr>,
        _context: BridgeDispatchContext,
    ) -> std::io::Result<BridgeUdpSession> {
        Err(std::io::Error::other("UDP is not used by this TCP test"))
    }
}

#[tokio::test]
async fn mux_server_keeps_physical_worker_alive_for_closed_logical_routes() {
    let (portal_wire, bridge_wire) = duplex(64 * 1024);
    let (accepted_targets, mut target_rx) = mpsc::unbounded_channel();
    let dispatcher = Arc::new(FinalResponseDispatcher { accepted_targets });
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(bridge_wire)),
        "bridge-in".to_string(),
        dispatcher,
    );
    let mut portal = ReverseSessionStream::new(portal_wire);

    for session_id in [80, 81] {
        let (closed_route, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        worker
            .sessions
            .lock()
            .expect("Reverse Bridge routes lock poisoned")
            .insert(session_id, closed_route);
        let (status, option, payload) = match session_id {
            80 => (
                SessionStatus::End,
                FrameOption::default().with_half_close(),
                Bytes::new(),
            ),
            _ => (
                SessionStatus::Keep,
                FrameOption::default().with_data(),
                Bytes::from_static(b"late-data"),
            ),
        };
        portal
            .write_all(
                &encode_frame(&MuxFrame {
                    metadata: FrameMetadata {
                        session_id,
                        status,
                        option,
                        target: None,
                        source: None,
                        local: None,
                        global_id: None,
                    },
                    payload,
                })
                .expect("encode frame for a closed logical route"),
            )
            .await
            .expect("write frame for a closed logical route");
    }

    for session_id in [80, 81] {
        let end = timeout(Duration::from_secs(1), read_frame(&mut portal))
            .await
            .expect("Bridge closes the stale logical session")
            .expect("read stale-session END");
        assert_eq!(end.metadata.status, SessionStatus::End);
        assert_eq!(end.metadata.session_id, session_id);
    }

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 82,
                    status: SessionStatus::New,
                    option: FrameOption::default().with_data(),
                    target: Some(tcp_destination(Ipv4Addr::LOCALHOST, 5201)),
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"live"),
            })
            .expect("encode valid session after stale frames"),
        )
        .await
        .expect("write valid session after stale frames");
    let mut target = timeout(Duration::from_secs(1), target_rx.recv())
        .await
        .expect("Bridge continues reading frames after stale routes")
        .expect("dispatcher receives the valid target");
    let mut received = [0u8; 4];
    timeout(Duration::from_secs(1), target.read_exact(&mut received))
        .await
        .expect("valid session receives its initial payload")
        .expect("read initial payload");
    assert_eq!(&received, b"live");
    assert!(worker.is_active());

    worker.close();
    worker.wait_closed().await;
}

#[tokio::test]
async fn mux_tcp_relay_repeatedly_returns_final_data_after_client_half_close() {
    const ITERATIONS: usize = 16;

    let (portal_wire, bridge_wire) = duplex(64 * 1024);
    let (accepted_targets, mut target_rx) = mpsc::unbounded_channel();
    let dispatcher = Arc::new(FinalResponseDispatcher { accepted_targets });
    let bridge = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(bridge_wire)),
        "bridge-in".to_string(),
        dispatcher,
    );
    let portal = MuxClientWorker::new(
        92,
        Box::new(ReverseSessionStream::new(portal_wire)),
        SessionLimits::default(),
    );
    portal
        .control_session_became_active()
        .expect("activate Portal worker");

    for iteration in 0..ITERATIONS {
        let request = format!("iperf-control-request-{iteration}");
        let response =
            format!("iperf-final-result-{iteration}-{}", "x".repeat(4096));
        let target = portal
            .open_tcp_session(tcp_destination(Ipv4Addr::LOCALHOST, 5201), None, None)
            .expect("open Portal TCP session");
        let (application_side, relay_side) = duplex(64 * 1024);
        let mut application_side = ReverseSessionStream::new(application_side);
        let mut relay_side = ReverseSessionStream::new(relay_side);

        let relay_task = tokio::spawn(async move {
            let mut target = target;
            copy_bidirectional(&mut relay_side, &mut target).await
        });

        application_side
            .write_all(request.as_bytes())
            .await
            .expect("write application request");
        application_side
            .shutdown()
            .await
            .expect("half-close application request");

        let mut target_side = timeout(Duration::from_secs(1), target_rx.recv())
            .await
            .expect("Bridge dispatched the TCP target")
            .expect("target receiver remains open");
        let mut received_request = Vec::new();
        timeout(
            Duration::from_secs(1),
            target_side.read_to_end(&mut received_request),
        )
        .await
        .expect("target observes the propagated client FIN")
        .expect("read request until EOF");
        assert_eq!(received_request, request.as_bytes());

        target_side
            .write_all(response.as_bytes())
            .await
            .expect("write final target response after client FIN");
        target_side
            .shutdown()
            .await
            .expect("half-close target response");

        let mut received_response = Vec::new();
        timeout(
            Duration::from_secs(1),
            application_side.read_to_end(&mut received_response),
        )
        .await
        .expect("application receives final response and EOF")
        .expect("read final result until EOF");
        assert_eq!(received_response, response.as_bytes());

        let relay_result = timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("bidirectional relay completes after both FINs")
            .expect("relay task joins")
            .expect("relay succeeds");
        assert_eq!(relay_result.left_to_right, request.len() as u64);
        assert_eq!(relay_result.right_to_left, response.len() as u64);

        timeout(Duration::from_secs(1), async {
            while portal.active_connections() != 0
                || bridge.active_connections() != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both workers release the completed Mux session");
    }

    portal.close();
    bridge.close();
    portal.wait_closed().await;
    bridge.wait_closed().await;
}

#[tokio::test]
async fn mux_server_routes_udp_packets_and_target_overrides() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, _local_peer) = duplex(4096);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher,
    );

    for (status, target, payload) in [
        (SessionStatus::New, 5300, b"one".as_slice()),
        (SessionStatus::Keep, 5301, b"two".as_slice()),
    ] {
        portal
            .write_all(
                &encode_frame(&MuxFrame {
                    metadata: FrameMetadata {
                        session_id: 8,
                        status,
                        option: FrameOption::default().with_data(),
                        target: Some(Destination {
                            network: TargetNetwork::Udp,
                            location: NetLocation::new(
                                Address::Ipv4(Ipv4Addr::LOCALHOST),
                                target,
                            ),
                        }),
                        source: None,
                        local: None,
                        global_id: None,
                    },
                    payload: Bytes::copy_from_slice(payload),
                })
                .expect("encode UDP Reverse packet"),
            )
            .await
            .expect("write UDP Reverse packet");

        let response = timeout(Duration::from_secs(1), read_frame(&mut portal))
            .await
            .expect("Bridge emitted UDP response")
            .expect("read UDP response");
        assert_eq!(response.metadata.session_id, 8);
        assert_eq!(response.metadata.status, SessionStatus::Keep);
        assert_eq!(response.payload.as_ref(), payload);
        assert_eq!(
            response
                .metadata
                .target
                .expect("UDP response source target")
                .location,
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target)
        );
    }

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 8,
                    status: SessionStatus::End,
                    option: FrameOption::default(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode UDP Reverse END"),
        )
        .await
        .expect("write UDP Reverse END");

    timeout(Duration::from_secs(1), async {
        while worker.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("UDP logical session is removed after END");
}

#[tokio::test]
async fn mux_server_maps_udp_targets_and_response_sources() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, _local_peer) = duplex(4096);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new_with_context(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher,
        BridgeDispatchContext {
            site_to_site: Some(site_to_site_policy()),
            ..BridgeDispatchContext::default()
        },
    );

    for (status, address, payload) in [
        (
            SessionStatus::New,
            Ipv4Addr::new(10, 200, 1, 20),
            b"one".as_slice(),
        ),
        (
            SessionStatus::Keep,
            Ipv4Addr::new(10, 200, 1, 21),
            b"two".as_slice(),
        ),
    ] {
        portal
            .write_all(
                &encode_frame(&MuxFrame {
                    metadata: FrameMetadata {
                        session_id: 18,
                        status,
                        option: FrameOption::default().with_data(),
                        target: Some(Destination {
                            network: TargetNetwork::Udp,
                            location: NetLocation::from_ip_addr(address.into(), 80),
                        }),
                        source: None,
                        local: None,
                        global_id: None,
                    },
                    payload: Bytes::copy_from_slice(payload),
                })
                .expect("encode overlay UDP frame"),
            )
            .await
            .expect("write overlay UDP frame");

        let response = timeout(Duration::from_secs(1), read_frame(&mut portal))
            .await
            .expect("Bridge emitted mapped UDP response")
            .expect("read mapped UDP response");
        assert_eq!(response.metadata.status, SessionStatus::Keep);
        assert_eq!(response.payload.as_ref(), payload);
        assert_eq!(
            response
                .metadata
                .target
                .expect("overlay response source")
                .location,
            NetLocation::from_ip_addr(address.into(), 80)
        );
    }

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 18,
                    status: SessionStatus::End,
                    option: FrameOption::default(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode mapped UDP END"),
        )
        .await
        .expect("write mapped UDP END");
    timeout(Duration::from_secs(1), async {
        while worker.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mapped UDP session closes after END");
}

fn loopback_site_to_site_policy(port: u16) -> SiteToSitePolicy {
    SiteToSitePolicy::compile(&SiteToSiteConfig {
        prefix_maps: vec![SitePrefixMapConfig {
            from: "10.200.1.20/32".to_string(),
            to: "127.0.0.1/32".to_string(),
        }],
        allow: vec![SiteTargetAllowConfig {
            network: vec!["tcp".to_string(), "udp".to_string()],
            ip: vec!["127.0.0.1/32".to_string()],
            ports: vec![port.to_string()],
        }],
    })
    .expect("compile loopback site-to-site policy")
}

fn direct_data_plane_runtime() -> crate::runtime::DataPlaneRuntime {
    let outbound = crate::outbound::freedom_outbound_allow_loopback("direct");
    RuntimeState::new(Vec::new(), vec![outbound]).data_plane()
}

#[tokio::test]
async fn mux_server_maps_tcp_overlay_target_before_real_outbound_dial() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local TCP echo target");
    let lan_target = listener.local_addr().expect("read TCP echo address");
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept mapped TCP");
        let peer = stream.peer_addr().expect("read mapped TCP peer");
        let mut request = [0; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("read TCP payload");
        stream.write_all(b"pong").await.expect("write TCP response");
        (peer, request)
    });

    let (physical, mut portal) = duplex(16 * 1024);
    let worker = MuxServerWorker::new_with_context(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        Arc::new(direct_data_plane_runtime()),
        BridgeDispatchContext {
            site_to_site: Some(loopback_site_to_site_policy(lan_target.port())),
            ..BridgeDispatchContext::default()
        },
    );
    let overlay_target = NetLocation::from_ip_addr(
        Ipv4Addr::new(10, 200, 1, 20).into(),
        lan_target.port(),
    );
    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 81,
                    status: SessionStatus::New,
                    option: FrameOption::default().with_data(),
                    target: Some(Destination {
                        network: TargetNetwork::Tcp,
                        location: overlay_target,
                    }),
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"ping"),
            })
            .expect("encode TCP Reverse NEW"),
        )
        .await
        .expect("send TCP Reverse NEW");

    let response = timeout(Duration::from_secs(2), read_frame(&mut portal))
        .await
        .expect("mapped TCP response arrives")
        .expect("read mapped TCP response");
    assert_eq!(response.metadata.status, SessionStatus::Keep);
    assert_eq!(response.payload, Bytes::from_static(b"pong"));
    let (peer, request) = timeout(Duration::from_secs(2), echo)
        .await
        .expect("TCP echo completed")
        .expect("TCP echo task completed");
    assert_eq!(peer.ip(), lan_target.ip());
    assert_eq!(&request, b"ping");

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 81,
                    status: SessionStatus::End,
                    option: FrameOption::default(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode TCP Reverse END"),
        )
        .await
        .expect("send TCP Reverse END");
    worker.close();
}

#[tokio::test]
async fn mux_server_maps_udp_overlay_target_and_restores_response_source() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind local UDP echo target");
    let lan_target = echo.local_addr().expect("read UDP echo address");
    let echo = tokio::spawn(async move {
        let mut buffer = [0; 32];
        let (size, peer) = echo
            .recv_from(&mut buffer)
            .await
            .expect("receive mapped UDP");
        echo.send_to(&buffer[..size], peer)
            .await
            .expect("send UDP response");
        (peer, buffer[..size].to_vec())
    });

    let (physical, mut portal) = duplex(16 * 1024);
    let worker = MuxServerWorker::new_with_context(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        Arc::new(direct_data_plane_runtime()),
        BridgeDispatchContext {
            site_to_site: Some(loopback_site_to_site_policy(lan_target.port())),
            ..BridgeDispatchContext::default()
        },
    );
    let overlay_ip = Ipv4Addr::new(10, 200, 1, 20);
    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 82,
                    status: SessionStatus::New,
                    option: FrameOption::default().with_data(),
                    target: Some(Destination {
                        network: TargetNetwork::Udp,
                        location: NetLocation::from_ip_addr(
                            overlay_ip.into(),
                            lan_target.port(),
                        ),
                    }),
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"udp-ping"),
            })
            .expect("encode UDP Reverse NEW"),
        )
        .await
        .expect("send UDP Reverse NEW");

    let response = timeout(Duration::from_secs(2), read_frame(&mut portal))
        .await
        .expect("mapped UDP response arrives")
        .expect("read mapped UDP response");
    assert_eq!(response.metadata.status, SessionStatus::Keep);
    assert_eq!(response.payload, Bytes::from_static(b"udp-ping"));
    assert_eq!(
        response
            .metadata
            .target
            .expect("UDP response source target")
            .location,
        NetLocation::from_ip_addr(overlay_ip.into(), lan_target.port())
    );
    let (peer, request) = timeout(Duration::from_secs(2), echo)
        .await
        .expect("UDP echo completed")
        .expect("UDP echo task completed");
    assert_eq!(peer.ip(), lan_target.ip());
    assert_eq!(request, b"udp-ping");

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 82,
                    status: SessionStatus::End,
                    option: FrameOption::default(),
                    target: None,
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::new(),
            })
            .expect("encode UDP Reverse END"),
        )
        .await
        .expect("send UDP Reverse END");
    worker.close();
}

#[tokio::test]
async fn mux_server_denies_tcp_outside_edge_policy_without_closing_bridge() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, mut local_peer) = duplex(4096);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new_with_context(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher.clone(),
        BridgeDispatchContext {
            site_to_site: Some(site_to_site_policy()),
            ..BridgeDispatchContext::default()
        },
    );

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 19,
                    status: SessionStatus::New,
                    option: FrameOption::default().with_data(),
                    target: Some(tcp_destination(
                        Ipv4Addr::new(10, 200, 1, 20),
                        3389,
                    )),
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"blocked"),
            })
            .expect("encode blocked TCP frame"),
        )
        .await
        .expect("write blocked TCP frame");
    let denied = timeout(Duration::from_secs(1), read_frame(&mut portal))
        .await
        .expect("Bridge returned a per-session denial")
        .expect("read denial frame");
    assert_eq!(denied.metadata.status, SessionStatus::End);
    assert_eq!(denied.metadata.option, FrameOption::default().with_error());
    assert!(
        worker.is_active(),
        "a denied target must not close the Bridge"
    );

    portal
        .write_all(
            &encode_frame(&MuxFrame {
                metadata: FrameMetadata {
                    session_id: 20,
                    status: SessionStatus::New,
                    option: FrameOption::default().with_data(),
                    target: Some(tcp_destination(
                        Ipv4Addr::new(10, 200, 1, 20),
                        443,
                    )),
                    source: None,
                    local: None,
                    global_id: None,
                },
                payload: Bytes::from_static(b"allowed"),
            })
            .expect("encode allowed TCP frame"),
        )
        .await
        .expect("write allowed TCP frame");
    let mut initial = [0u8; 7];
    timeout(Duration::from_secs(1), local_peer.read_exact(&mut initial))
        .await
        .expect("Edge dialed the mapped target")
        .expect("read initial data");
    assert_eq!(&initial, b"allowed");
    assert_eq!(
        dispatcher.calls()[0].target,
        NetLocation::from_str("192.168.50.20:443", None).unwrap()
    );
}

#[tokio::test]
async fn mux_server_rejects_non_reverse_global_id_wire_as_invalid_metadata() {
    let (physical, mut portal) = duplex(4096);
    let (local, _local_peer) = duplex(4096);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher,
    );

    let request = MuxFrame {
        metadata: FrameMetadata {
            session_id: 9,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(Destination {
                network: TargetNetwork::Udp,
                location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53),
            }),
            source: None,
            local: None,
            global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        },
        payload: Bytes::from_static(b"dns"),
    };
    portal
        .write_all(&encode_frame(&request).expect("encode XUDP Reverse NEW"))
        .await
        .expect("write XUDP Reverse NEW");

    timeout(Duration::from_secs(1), worker.wait_closed())
        .await
        .expect("non-Reverse GlobalID metadata closes the Reverse worker");
    assert!(worker.closed());
}

#[test]
fn mux_server_idle_check_matches_xray_two_snapshot_rule() {
    assert!(idle_snapshot_is_unchanged(0, 7, 0, 7));
    assert!(!idle_snapshot_is_unchanged(1, 7, 0, 7));
    assert!(!idle_snapshot_is_unchanged(0, 7, 1, 8));
    assert!(!idle_snapshot_is_unchanged(0, 7, 0, 8));
}

#[tokio::test]
async fn dropping_mux_server_worker_closes_physical_stream() {
    let (physical, mut portal) = duplex(4096);
    let (local, _local_peer) = duplex(4096);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher,
    );

    drop(worker);

    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(1), portal.read(&mut byte))
        .await
        .expect("dropping the worker must close its physical stream")
        .expect("physical stream closes cleanly");
    assert_eq!(read, 0);
}
