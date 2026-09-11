#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(any(feature = "vless", feature = "vmess"))]
use bytes::{BufMut, BytesMut};
#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    duplex,
};
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{
        rule::{
            BalancerConfig, NetworkListConfig, PortListConfig, PortRangeConfig,
            RoutingConfig, RuleConfig,
        },
        server_config::{DokodemoDoorConfig, TcpSocketPolicy},
    },
    resolver::NativeResolver,
    routing_state::RoutingState,
    runtime::{OutboundSummary, RuntimeState},
};

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
use crate::async_stream::{AsyncPing, AsyncStream};
#[cfg(any(feature = "vless", feature = "vmess"))]
use crate::handler::xudp::{
    frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork},
    message_stream::XudpMessageStream,
};
#[cfg(target_os = "linux")]
use crate::util::socket::{enable_udp_original_destination, new_socket2_udp_socket};
#[cfg(feature = "shadowsocks")]
use crate::{
    config::server_config::ShadowsocksUser,
    handler::shadowsocks::ShadowsocksUdpCodec,
};

#[cfg(feature = "trojan")]
use crate::{
    config::def::OutboundItem, handler::trojan_udp::TrojanUdpStream,
    outbound::compile_static_outbound,
};

use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_listener_applies_reuse_port() {
    let socket =
        create_udp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None, false)
            .expect("create UDP listener");
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: `value` and `length` are valid writable getsockopt buffers.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(value, 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_listener_applies_original_destination_option() {
    let policy = TcpSocketPolicy {
        receive_original_destination: true,
        ..TcpSocketPolicy::default()
    };
    let socket = create_udp_listener(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Some(&policy),
        false,
    )
    .expect("create original-destination UDP listener");
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: `value` and `length` are valid writable getsockopt buffers.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(value, 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_listener_applies_ipv6_only() {
    let policy = TcpSocketPolicy {
        ipv6_only: true,
        ..TcpSocketPolicy::default()
    };
    let socket = create_udp_listener(
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        Some(&policy),
        false,
    )
    .expect("create IPv6-only UDP listener");
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: `value` and `length` are valid writable getsockopt buffers.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(value, 1);
}

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
struct TestStream(DuplexStream);

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
impl AsyncRead for TestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
impl AsyncWrite for TestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
impl AsyncPing for TestStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
impl AsyncStream for TestStream {}

#[cfg(any(feature = "vless", feature = "vmess"))]
struct FailingSessionResponseStream {
    request: Option<(SessionMessage, Vec<u8>)>,
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl crate::async_stream::AsyncReadSessionMessage for FailingSessionResponseStream {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>> {
        let Some((message, payload)) = self.request.take() else {
            return Poll::Pending;
        };
        buffer.put_slice(&payload);
        Poll::Ready(Ok(message))
    }
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl crate::async_stream::AsyncWriteSessionMessage for FailingSessionResponseStream {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _session_id: u16,
        _buffer: &[u8],
        _target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "test session response write failure",
        )))
    }

    fn poll_write_session_end(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _session_id: u16,
        _has_error: bool,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl crate::async_stream::AsyncFlushMessage for FailingSessionResponseStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl crate::async_stream::AsyncShutdownMessage for FailingSessionResponseStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl AsyncPing for FailingSessionResponseStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

#[cfg(any(feature = "vless", feature = "vmess"))]
impl AsyncSessionMessageStream for FailingSessionResponseStream {}

fn runtime_with_outbounds(outbounds: Vec<OutboundSummary>) -> RuntimeState {
    RuntimeState::new(Vec::new(), outbounds)
}

fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
    OutboundSummary {
        tag: tag.into(),
        protocol: protocol.into(),
        proxy_settings_type: None,
        proxy_settings_value: None,
        sender_settings_type: None,
        sender_settings_value: None,
    }
}

#[cfg(feature = "trojan")]
fn runtime_routing_udp_to(
    outbound: OutboundSummary,
    inbound_tag: &str,
) -> DataPlaneRuntime {
    let outbound_tag = outbound.tag.clone();
    let runtime = RuntimeState::new(Vec::new(), vec![outbound]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec![inbound_tag.to_string()],
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some(outbound_tag),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan UDP routing rule"),
    );
    runtime.data_plane()
}

#[cfg(feature = "trojan")]
async fn start_fake_trojan_udp_proxy(
    expected_initial_target: NetLocation,
) -> (OutboundSummary, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan UDP proxy");
    let proxy_addr = listener
        .local_addr()
        .expect("fake Trojan UDP proxy address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept fake Trojan UDP client");
        let mut password_hash = [0u8; 56];
        stream
            .read_exact(&mut password_hash)
            .await
            .expect("read Trojan UDP password hash");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected_hash = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(password_hash.as_slice(), expected_hash.as_slice());
        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read Trojan UDP auth CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(
            stream.read_u8().await.expect("read Trojan UDP command"),
            0x03
        );
        let address = match stream
            .read_u8()
            .await
            .expect("read Trojan UDP target address type")
        {
            0x01 => {
                let mut octets = [0u8; 4];
                stream
                    .read_exact(&mut octets)
                    .await
                    .expect("read Trojan UDP IPv4 target");
                Address::Ipv4(octets.into())
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream
                    .read_exact(&mut octets)
                    .await
                    .expect("read Trojan UDP IPv6 target");
                Address::Ipv6(octets.into())
            }
            0x03 => {
                let length = stream
                    .read_u8()
                    .await
                    .expect("read Trojan UDP domain length")
                    as usize;
                let mut domain = vec![0u8; length];
                stream
                    .read_exact(&mut domain)
                    .await
                    .expect("read Trojan UDP domain target");
                Address::from(
                    std::str::from_utf8(&domain)
                        .expect("Trojan UDP target domain is UTF-8"),
                )
                .expect("parse Trojan UDP target domain")
            }
            other => panic!("unexpected Trojan UDP address type {other}"),
        };
        let port = stream
            .read_u16()
            .await
            .expect("read Trojan UDP target port");
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read Trojan UDP request CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(NetLocation::new(address, port), expected_initial_target);

        let mut udp = TrojanUdpStream::new(Box::new(stream));
        let mut payload = [0u8; 8192];
        while let Ok((target, length)) = udp.recv_from(&mut payload).await {
            if udp.send_to(&target, &payload[..length]).await.is_err() {
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
    .expect("parse fake Trojan UDP outbound");
    (
        compile_static_outbound(&item).expect("compile fake Trojan UDP outbound"),
        server,
    )
}

#[test]
fn global_udp_response_delivery_routes_to_current_attachment() {
    let (response_sender, _response_receiver) = mpsc::channel(1);
    let pending = PendingGlobalUdpResponse {
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        payload: b"response".to_vec(),
    };
    let delivery = match plan_global_udp_response_delivery(
        Some(GlobalUdpAttachment {
            token: 9,
            session_id: 17,
            generation: 23,
            response_sender,
            traffic_context: None,
        }),
        pending,
    ) {
        Ok(delivery) => delivery,
        Err(_) => panic!("attached GlobalID should produce a delivery plan"),
    };

    assert_eq!(delivery.attachment_token, 9);
    assert_eq!(delivery.response.session_id, 17);
    assert_eq!(delivery.response.generation, 23);
    assert_eq!(delivery.response.source.port(), 53);
    assert_eq!(delivery.response.payload, b"response");
}

#[test]
fn global_udp_response_delivery_preserves_payload_while_detached() {
    let pending = PendingGlobalUdpResponse {
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        payload: b"pending".to_vec(),
    };
    let pending = match plan_global_udp_response_delivery(None, pending) {
        Ok(_) => panic!("detached GlobalID must keep the response pending"),
        Err(pending) => pending,
    };

    assert_eq!(pending.source.port(), 53);
    assert_eq!(pending.payload, b"pending");
}

#[test]
fn global_udp_payload_plan_distinguishes_detached_stale_and_current() {
    let (response_sender, _response_receiver) = mpsc::channel(1);
    let attachment = GlobalUdpAttachment {
        token: 17,
        session_id: 3,
        generation: 5,
        response_sender,
        traffic_context: None,
    };

    assert!(matches!(
        plan_global_udp_payload(None, 17),
        GlobalUdpPayloadPlan::RejectDetached,
    ));
    assert!(matches!(
        plan_global_udp_payload(Some(attachment.clone()), 16),
        GlobalUdpPayloadPlan::RejectStale { current_token: 17 },
    ));
    match plan_global_udp_payload(Some(attachment), 17) {
        GlobalUdpPayloadPlan::Send(current) => {
            assert_eq!(current.token, 17);
            assert_eq!(current.session_id, 3);
            assert_eq!(current.generation, 5);
        }
        _ => panic!("current attachment token should be accepted"),
    }
}

#[test]
fn global_udp_receive_pauses_only_for_full_detached_buffer() {
    assert!(!should_pause_global_udp_receive(true, 64, 64));
    assert!(!should_pause_global_udp_receive(false, 63, 64));
    assert!(should_pause_global_udp_receive(false, 64, 64));
    assert!(should_pause_global_udp_receive(false, 65, 64));
}

#[test]
fn global_udp_worker_plan_reuses_only_matching_live_open_worker() {
    assert_eq!(plan_global_udp_worker(None), GlobalUdpWorkerPlan::Replace);
    assert_eq!(
        plan_global_udp_worker(Some(GlobalUdpWorkerSnapshot {
            key_matches: true,
            task_finished: false,
            sender_closed: false,
        })),
        GlobalUdpWorkerPlan::Reuse,
    );
    for snapshot in [
        GlobalUdpWorkerSnapshot {
            key_matches: false,
            task_finished: false,
            sender_closed: false,
        },
        GlobalUdpWorkerSnapshot {
            key_matches: true,
            task_finished: true,
            sender_closed: false,
        },
        GlobalUdpWorkerSnapshot {
            key_matches: true,
            task_finished: false,
            sender_closed: true,
        },
    ] {
        assert_eq!(
            plan_global_udp_worker(Some(snapshot)),
            GlobalUdpWorkerPlan::Replace,
        );
    }
}

#[tokio::test]
async fn global_xudp_gates_serialize_same_id_without_blocking_other_ids() {
    let first_id = [201, 202, 203, 204, 205, 206, 207, 208];
    let second_id = [209, 210, 211, 212, 213, 214, 215, 216];
    let first_gate = global_xudp_gate(first_id).await;
    let held = first_gate.lock().await;
    let same_gate = global_xudp_gate(first_id).await;
    let second_gate = global_xudp_gate(second_id).await;

    assert!(Arc::ptr_eq(&first_gate, &same_gate));
    assert!(!Arc::ptr_eq(&first_gate, &second_gate));
    assert!(
        timeout(Duration::from_millis(50), second_gate.lock())
            .await
            .is_ok(),
        "a held GlobalID gate must not block a different GlobalID",
    );
    assert!(
        timeout(Duration::from_millis(20), same_gate.lock())
            .await
            .is_err(),
        "the same GlobalID must remain serialized",
    );

    drop(held);
    assert!(
        timeout(Duration::from_millis(50), same_gate.lock())
            .await
            .is_ok(),
        "the next same-ID operation should proceed after release",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_xudp_replacement_waits_for_previous_worker_cleanup() {
    let global_id = [217, 218, 219, 220, 221, 222, 223, 224];
    let (payload_sender, _payload_receiver) = mpsc::channel(1);
    let (ready_sender, ready_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let old_task = tokio::spawn(async move {
        let _ = ready_sender.send(());
        let _ = release_receiver.recv();
        std::future::pending::<()>().await;
    });
    let old_abort = old_task.abort_handle();
    ready_receiver
        .await
        .expect("previous GlobalID worker must start before replacement");

    let globals = global_xudp_workers();
    {
        let mut guard = globals.lock().await;
        assert!(
            guard
                .workers
                .insert(
                    global_id,
                    GlobalSessionUdpWorker {
                        key: GlobalUdpWorkerKey::Direct {
                            target_is_ipv6: true,
                            outbound_tag: None,
                        },
                        sender: payload_sender,
                        attachment: Arc::new(RwLock::new(None)),
                        attachment_notify: Arc::new(Notify::new()),
                        task: old_task,
                    },
                )
                .is_none(),
            "replacement test GlobalID must be unused",
        );
    }

    let (response_sender, _response_receiver) = mpsc::channel(1);
    let replacement = tokio::spawn(start_session_udp_session(
        604,
        1,
        TargetedUdpSessionKey {
            target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            outbound_tag: None,
        },
        response_sender,
        None,
        Some(global_id),
        Duration::from_secs(5),
    ));

    sleep(Duration::from_millis(20)).await;
    let returned_before_cleanup = replacement.is_finished();
    release_sender
        .send(())
        .expect("release previous GlobalID worker cleanup");
    let worker = timeout(Duration::from_secs(1), replacement)
        .await
        .expect("GlobalID replacement timeout")
        .expect("GlobalID replacement task must not panic")
        .expect("GlobalID replacement must succeed");

    assert!(
        !returned_before_cleanup,
        "GlobalID replacement must not publish a new worker before the previous task exits",
    );
    assert!(old_abort.is_finished());

    let mut sessions = HashMap::from([(604, worker)]);
    terminate_session_udp_worker(&mut sessions, 604).await;
    assert!(sessions.is_empty());
}

#[test]
fn session_generation_exhaustion_is_reported_without_wrapping() {
    let error = plan_session_generation(u64::MAX)
        .expect_err("exhausted session generation counter must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert!(error.to_string().contains("generation counter exhausted"));
}

#[test]
fn session_generation_plan_advances_monotonically() {
    assert_eq!(
        plan_session_generation(41).expect("plan next session generation"),
        (41, 42)
    );
    assert_eq!(
        plan_session_generation(42).expect("plan following session generation"),
        (42, 43)
    );
}

#[cfg(any(feature = "vless", feature = "vmess"))]
#[tokio::test]
async fn session_udp_blackhole_drops_without_contacting_target() {
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind XUDP blackhole observation socket");
    let target_addr = target
        .local_addr()
        .expect("XUDP blackhole observation address");
    let mut frame = BytesMut::new();
    FrameMetadata {
        session_id: 15,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(NetLocation::from_ip_addr(
            target_addr.ip(),
            target_addr.port(),
        )),
        network: Some(TargetNetwork::Udp),
        global_id: None,
    }
    .encode(&mut frame)
    .expect("encode blackholed XUDP request metadata");
    frame.put_u16(4);
    frame.extend_from_slice(b"drop");

    let (mut client, server) = duplex(2048);
    client
        .write_all(&frame)
        .await
        .expect("write blackholed XUDP request");
    let stream = XudpMessageStream::new(
        Box::new(TestStream(server)),
        Arc::new(NativeResolver::new()),
    );
    let relay = tokio::spawn(run_session_based_udp(
        Box::new(stream),
        runtime_with_outbounds(vec![outbound("blocked", "blackhole")]).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43115)),
        None,
        None,
    ));

    let mut buffer = [0u8; 16];
    assert!(
        timeout(Duration::from_millis(50), target.recv_from(&mut buffer))
            .await
            .is_err(),
        "blackholed XUDP packet must not reach its UDP target"
    );

    relay.abort();
}

#[cfg(all(feature = "trojan", any(feature = "vless", feature = "vmess")))]
#[tokio::test]
async fn global_id_xudp_trojan_outbound_fails_closed() {
    let target_addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53));
    let mut frame = BytesMut::new();
    FrameMetadata {
        session_id: 91,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(NetLocation::from_ip_addr(
            target_addr.ip(),
            target_addr.port(),
        )),
        network: Some(TargetNetwork::Udp),
        global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
    }
    .encode(&mut frame)
    .expect("encode GlobalID Trojan XUDP request metadata");
    frame.put_u16(4);
    frame.extend_from_slice(b"fail");

    let (mut client, server) = duplex(2048);
    client
        .write_all(&frame)
        .await
        .expect("write GlobalID Trojan XUDP request");
    let stream = XudpMessageStream::new(
        Box::new(TestStream(server)),
        Arc::new(NativeResolver::new()),
    );
    let relay = tokio::spawn(run_session_based_udp(
        Box::new(stream),
        runtime_with_outbounds(vec![outbound("proxy", "trojan")]).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43191)),
        None,
        None,
    ));

    let error = timeout(Duration::from_secs(1), relay)
        .await
        .expect("GlobalID Trojan XUDP must fail promptly")
        .expect("GlobalID Trojan XUDP relay task must not panic")
        .expect_err("GlobalID Trojan XUDP must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("GlobalID XUDP"));
}

#[cfg(any(feature = "vless", feature = "vmess"))]
#[tokio::test]
async fn session_udp_unsupported_outbound_fails_without_contacting_target() {
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind unsupported-outbound observation socket");
    let target_addr = target
        .local_addr()
        .expect("unsupported-outbound observation address");
    let mut frame = BytesMut::new();
    FrameMetadata {
        session_id: 16,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(NetLocation::from_ip_addr(
            target_addr.ip(),
            target_addr.port(),
        )),
        network: Some(TargetNetwork::Udp),
        global_id: None,
    }
    .encode(&mut frame)
    .expect("encode unsupported-outbound XUDP request metadata");
    frame.put_u16(4);
    frame.extend_from_slice(b"fail");

    let (mut client, server) = duplex(2048);
    client
        .write_all(&frame)
        .await
        .expect("write unsupported-outbound XUDP request");
    let stream = XudpMessageStream::new(
        Box::new(TestStream(server)),
        Arc::new(NativeResolver::new()),
    );
    let relay = tokio::spawn(run_session_based_udp(
        Box::new(stream),
        runtime_with_outbounds(vec![outbound("proxy", "vmess")]).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43116)),
        None,
        None,
    ));

    let error = timeout(Duration::from_secs(1), relay)
        .await
        .expect("unsupported XUDP outbound must fail promptly")
        .expect("unsupported XUDP relay task must not panic")
        .expect_err("unsupported XUDP outbound must return an error");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("unsupported protocol vmess"));

    let mut buffer = [0u8; 16];
    assert!(
        timeout(Duration::from_millis(20), target.recv_from(&mut buffer))
            .await
            .is_err(),
        "unsupported XUDP outbound must not contact its UDP target"
    );
}

#[tokio::test]
async fn session_udp_response_requires_current_generation() {
    let (sender, _receiver) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let join = tokio::spawn(async move {
        task_cancellation.cancelled().await;
    });
    let mut sessions = HashMap::new();
    sessions.insert(
        17,
        SessionUdpWorker {
            key: TargetedUdpSessionKey {
                target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                outbound_tag: None,
            },
            global_id: None,
            generation: 2,
            sender: SessionUdpSender::Local(sender),
            task: Some(LocalSessionUdpTask {
                cancellation,
                join: Some(join),
            }),
        },
    );
    let mut response = SessionUdpResponse {
        session_id: 17,
        generation: 1,
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        payload: b"response".to_vec(),
        traffic_context: None,
    };

    assert!(!is_current_session_udp_response(&sessions, &response));
    assert!(!is_current_session_udp_generation(&sessions, 17, 1));
    response.generation = 2;
    assert!(is_current_session_udp_response(&sessions, &response));
    assert!(is_current_session_udp_generation(&sessions, 17, 2));

    terminate_session_udp_worker(&mut sessions, 17).await;
}

#[tokio::test]
async fn local_xudp_reuses_socket_across_udp_targets() {
    let target_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first local XUDP target");
    let target_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind second local XUDP target");
    let target_a_addr = target_a
        .local_addr()
        .expect("first local XUDP target address");
    let target_b_addr = target_b
        .local_addr()
        .expect("second local XUDP target address");

    let target_a_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = target_a
            .recv_from(&mut buffer)
            .await
            .expect("receive first local XUDP request");
        target_a
            .send_to(&buffer[..length], peer)
            .await
            .expect("echo first local XUDP response");
        (buffer[..length].to_vec(), peer)
    });
    let target_b_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = target_b
            .recv_from(&mut buffer)
            .await
            .expect("receive second local XUDP request");
        target_b
            .send_to(&buffer[..length], peer)
            .await
            .expect("echo second local XUDP response");
        (buffer[..length].to_vec(), peer)
    });

    let key_a = TargetedUdpSessionKey {
        target_addr: target_a_addr,
        outbound_tag: None,
    };
    let key_b = TargetedUdpSessionKey {
        target_addr: target_b_addr,
        outbound_tag: None,
    };
    let (response_sender, mut response_receiver) = mpsc::channel(8);
    let worker = start_session_udp_session(
        90,
        1,
        key_a,
        response_sender,
        None,
        None,
        Duration::from_secs(5),
    )
    .await
    .expect("start multi-target local XUDP worker");
    assert!(session_udp_worker_matches(&worker, &key_b, None));

    worker
        .sender
        .send_to(b"local-a".to_vec(), target_a_addr)
        .await
        .expect("send first local XUDP target payload");
    let first_event = timeout(Duration::from_secs(1), response_receiver.recv())
        .await
        .expect("first local XUDP target response timeout")
        .expect("first local XUDP target response event");
    let SessionUdpEvent::Data(first_response) = first_event else {
        panic!("first local XUDP target response was not data");
    };
    assert_eq!(first_response.payload, b"local-a");
    assert_eq!(first_response.source, target_a_addr);

    worker
        .sender
        .send_to(b"local-b".to_vec(), target_b_addr)
        .await
        .expect("send second local XUDP target payload");
    let second_event = timeout(Duration::from_secs(1), response_receiver.recv())
        .await
        .expect("second local XUDP target response timeout")
        .expect("second local XUDP target response event");
    let SessionUdpEvent::Data(second_response) = second_event else {
        panic!("second local XUDP target response was not data");
    };
    assert_eq!(second_response.payload, b"local-b");
    assert_eq!(second_response.source, target_b_addr);

    let (payload_a, peer_a) =
        target_a_task.await.expect("first local XUDP target task");
    let (payload_b, peer_b) =
        target_b_task.await.expect("second local XUDP target task");
    assert_eq!(payload_a, b"local-a");
    assert_eq!(payload_b, b"local-b");
    assert_eq!(peer_a, peer_b);

    let mut sessions = HashMap::from([(90, worker)]);
    terminate_session_udp_worker(&mut sessions, 90).await;
}

#[tokio::test]
async fn global_xudp_reuses_socket_across_udp_targets() {
    let target_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first GlobalID UDP target");
    let target_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind second GlobalID UDP target");
    let target_a_addr = target_a
        .local_addr()
        .expect("first GlobalID target address");
    let target_b_addr = target_b
        .local_addr()
        .expect("second GlobalID target address");

    let target_a_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = target_a
            .recv_from(&mut buffer)
            .await
            .expect("receive first GlobalID target request");
        target_a
            .send_to(&buffer[..length], peer)
            .await
            .expect("echo first GlobalID target response");
        (buffer[..length].to_vec(), peer)
    });
    let target_b_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = target_b
            .recv_from(&mut buffer)
            .await
            .expect("receive second GlobalID target request");
        target_b
            .send_to(&buffer[..length], peer)
            .await
            .expect("echo second GlobalID target response");
        (buffer[..length].to_vec(), peer)
    });

    let global_id = [81, 82, 83, 84, 85, 86, 87, 88];
    let key_a = TargetedUdpSessionKey {
        target_addr: target_a_addr,
        outbound_tag: None,
    };
    let key_b = TargetedUdpSessionKey {
        target_addr: target_b_addr,
        outbound_tag: None,
    };
    let (response_sender, mut response_receiver) = mpsc::channel(8);
    let worker = start_session_udp_session(
        91,
        1,
        key_a,
        response_sender,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start multi-target GlobalID UDP worker");
    assert!(session_udp_worker_matches(&worker, &key_b, Some(global_id)));

    worker
        .sender
        .send_to(b"target-a".to_vec(), target_a_addr)
        .await
        .expect("send first GlobalID target payload");
    let first_event = timeout(Duration::from_secs(1), response_receiver.recv())
        .await
        .expect("first GlobalID target response timeout")
        .expect("first GlobalID target response event");
    let SessionUdpEvent::Data(first_response) = first_event else {
        panic!("first GlobalID target response was not data");
    };
    assert_eq!(first_response.payload, b"target-a");
    assert_eq!(first_response.source, target_a_addr);

    worker
        .sender
        .send_to(b"target-b".to_vec(), target_b_addr)
        .await
        .expect("send second GlobalID target payload");
    let second_event = timeout(Duration::from_secs(1), response_receiver.recv())
        .await
        .expect("second GlobalID target response timeout")
        .expect("second GlobalID target response event");
    let SessionUdpEvent::Data(second_response) = second_event else {
        panic!("second GlobalID target response was not data");
    };
    assert_eq!(second_response.payload, b"target-b");
    assert_eq!(second_response.source, target_b_addr);

    let (payload_a, peer_a) =
        target_a_task.await.expect("first GlobalID target task");
    let (payload_b, peer_b) =
        target_b_task.await.expect("second GlobalID target task");
    assert_eq!(payload_a, b"target-a");
    assert_eq!(payload_b, b"target-b");
    assert_eq!(peer_a, peer_b);

    let mut sessions = HashMap::from([(91, worker)]);
    terminate_session_udp_worker(&mut sessions, 91).await;
}

#[tokio::test]
async fn global_xudp_takeover_reuses_socket_and_rejects_stale_sender() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind GlobalID UDP echo socket");
    let echo_addr = echo_socket.local_addr().expect("GlobalID UDP echo address");
    let (observation_sender, mut observation_receiver) = mpsc::channel(2);
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        for _ in 0..2 {
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive GlobalID UDP request");
            observation_sender
                .send((buffer[..length].to_vec(), peer))
                .await
                .expect("record GlobalID UDP request");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send GlobalID UDP response");
        }
    });

    let global_id = [91, 92, 93, 94, 95, 96, 97, 98];
    let key = TargetedUdpSessionKey {
        target_addr: echo_addr,
        outbound_tag: None,
    };
    let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
    let worker_a = start_session_udp_session(
        101,
        1,
        key.clone(),
        response_sender_a,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start first GlobalID UDP attachment");
    let stale_sender = worker_a.sender.clone();
    stale_sender
        .send_to(b"first".to_vec(), echo_addr)
        .await
        .expect("send first GlobalID UDP payload");

    let first_response = timeout(Duration::from_secs(1), response_receiver_a.recv())
        .await
        .expect("first GlobalID response timeout")
        .expect("first GlobalID response event");
    let SessionUdpEvent::Data(first_response) = first_response else {
        panic!("first GlobalID response was not data");
    };
    assert_eq!(first_response.session_id, 101);
    assert_eq!(first_response.generation, 1);
    assert_eq!(first_response.payload, b"first");

    let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
    let worker_b = start_session_udp_session(
        202,
        2,
        key,
        response_sender_b,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("take over GlobalID UDP attachment");

    let replaced_event = timeout(Duration::from_secs(1), response_receiver_a.recv())
        .await
        .expect("replaced GlobalID End timeout")
        .expect("replaced GlobalID End event");
    assert!(matches!(
        replaced_event,
        SessionUdpEvent::End {
            session_id: 101,
            generation: 1,
            has_error: false,
        }
    ));

    let stale_payload = stale_sender
        .send_to(b"stale".to_vec(), echo_addr)
        .await
        .expect_err("stale GlobalID sender must reject its payload");
    assert_eq!(stale_payload, b"stale");
    worker_b
        .sender
        .send_to(b"second".to_vec(), echo_addr)
        .await
        .expect("send second GlobalID UDP payload");

    let second_response =
        timeout(Duration::from_secs(1), response_receiver_b.recv())
            .await
            .expect("second GlobalID response timeout")
            .expect("second GlobalID response event");
    let SessionUdpEvent::Data(second_response) = second_response else {
        panic!("second GlobalID response was not data");
    };
    assert_eq!(second_response.session_id, 202);
    assert_eq!(second_response.generation, 2);
    assert_eq!(second_response.payload, b"second");

    let (first_payload, first_peer) = observation_receiver
        .recv()
        .await
        .expect("first GlobalID UDP observation");
    let (second_payload, second_peer) = observation_receiver
        .recv()
        .await
        .expect("second GlobalID UDP observation");
    assert_eq!(first_payload, b"first");
    assert_eq!(second_payload, b"second");
    assert_eq!(first_peer, second_peer);

    let mut sessions = HashMap::from([(101, worker_a), (202, worker_b)]);
    terminate_session_udp_worker(&mut sessions, 101).await;
    assert!(sessions.contains_key(&202));
    terminate_session_udp_worker(&mut sessions, 202).await;
    assert!(sessions.is_empty());
    echo_task.await.expect("GlobalID UDP echo task");
}

#[tokio::test]
async fn detached_global_xudp_sender_returns_original_payload_promptly() {
    let global_id = [141, 142, 143, 144, 145, 146, 147, 148];
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let key = TargetedUdpSessionKey {
        target_addr,
        outbound_tag: None,
    };
    let (response_sender, _response_receiver) = mpsc::channel(1);
    let worker = start_session_udp_session(
        601,
        1,
        key,
        response_sender,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start detachable GlobalID sender test worker");
    let detached_sender = worker.sender.clone();
    let attachment_token = match &detached_sender {
        SessionUdpSender::Global {
            attachment_token, ..
        } => *attachment_token,
        _ => panic!("GlobalID worker returned a non-global sender"),
    };
    detach_session_udp_worker(worker).await;

    let payload = timeout(
        Duration::from_secs(1),
        detached_sender.send_to(b"detached".to_vec(), target_addr),
    )
    .await
    .expect("detached GlobalID sender must not hang")
    .expect_err("detached GlobalID sender must reject its payload");
    assert_eq!(payload, b"detached");

    terminate_global_udp_worker(global_id, attachment_token).await;
}

#[tokio::test]
async fn terminated_global_xudp_sender_returns_original_payload_promptly() {
    let global_id = [149, 150, 151, 152, 153, 154, 155, 156];
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let key = TargetedUdpSessionKey {
        target_addr,
        outbound_tag: None,
    };
    let (response_sender, _response_receiver) = mpsc::channel(1);
    let worker = start_session_udp_session(
        602,
        1,
        key,
        response_sender,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start terminable GlobalID sender test worker");
    let terminated_sender = worker.sender.clone();
    let attachment_token = match &terminated_sender {
        SessionUdpSender::Global {
            attachment_token, ..
        } => *attachment_token,
        _ => panic!("GlobalID worker returned a non-global sender"),
    };

    terminate_global_udp_worker(global_id, attachment_token).await;

    let payload = timeout(
        Duration::from_secs(1),
        terminated_sender.send_to(b"terminated".to_vec(), target_addr),
    )
    .await
    .expect("terminated GlobalID sender must not hang")
    .expect_err("terminated GlobalID sender must reject its payload");
    assert_eq!(payload, b"terminated");
}

#[tokio::test]
async fn terminating_global_xudp_worker_waits_for_task_cleanup() {
    struct CleanupSignal(Option<oneshot::Sender<()>>);

    impl Drop for CleanupSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let global_id = [157, 158, 159, 160, 161, 162, 163, 164];
    let now = Instant::now();
    let (payload_sender, _payload_receiver) = mpsc::channel(1);
    let (cleanup_sender, mut cleanup_receiver) = oneshot::channel();
    let (ready_sender, ready_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _cleanup = CleanupSignal(Some(cleanup_sender));
        let _ = ready_sender.send(());
        std::future::pending::<()>().await;
    });
    ready_receiver
        .await
        .expect("GlobalID cleanup test task must start before termination");
    let globals = global_xudp_workers();
    let attachment_token = {
        let mut guard = globals.lock().await;
        let transition = guard
            .registry
            .attach(global_id, 603, 1, now)
            .expect("attach GlobalID before explicit termination cleanup test");
        guard.workers.insert(
            global_id,
            GlobalSessionUdpWorker {
                key: GlobalUdpWorkerKey::Direct {
                    target_is_ipv6: false,
                    outbound_tag: None,
                },
                sender: payload_sender,
                attachment: Arc::new(RwLock::new(None)),
                attachment_notify: Arc::new(Notify::new()),
                task,
            },
        );
        transition.current.token
    };

    terminate_global_udp_worker(global_id, attachment_token).await;

    cleanup_receiver.try_recv().expect(
        "explicit GlobalID termination must await task cleanup before returning",
    );
    let mut guard = globals.lock().await;
    assert!(guard.registry.current(global_id, Instant::now()).is_none());
    assert!(!guard.workers.contains_key(&global_id));
}

#[tokio::test]
async fn expiring_global_xudp_worker_waits_for_task_cleanup() {
    struct CleanupSignal(Option<oneshot::Sender<()>>);

    impl Drop for CleanupSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let global_id = [165, 166, 167, 168, 169, 170, 171, 172];
    let now = Instant::now();
    let detached_at = now - XUDP_GLOBAL_REATTACH_TTL;
    let (payload_sender, _payload_receiver) = mpsc::channel(1);
    let (cleanup_sender, mut cleanup_receiver) = oneshot::channel();
    let (ready_sender, ready_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _cleanup = CleanupSignal(Some(cleanup_sender));
        let _ = ready_sender.send(());
        std::future::pending::<()>().await;
    });
    ready_receiver
        .await
        .expect("GlobalID expiry cleanup test task must start");

    let globals = global_xudp_workers();
    {
        let mut guard = globals.lock().await;
        let transition = guard
            .registry
            .attach(global_id, 604, 1, detached_at)
            .expect("attach GlobalID before expiry cleanup test");
        assert!(guard.registry.detach(
            global_id,
            transition.current.token,
            detached_at,
        ));
        guard.workers.insert(
            global_id,
            GlobalSessionUdpWorker {
                key: GlobalUdpWorkerKey::Direct {
                    target_is_ipv6: false,
                    outbound_tag: None,
                },
                sender: payload_sender,
                attachment: Arc::new(RwLock::new(None)),
                attachment_notify: Arc::new(Notify::new()),
                task,
            },
        );
    }

    expire_global_udp_worker(global_id, now).await;

    cleanup_receiver
        .try_recv()
        .expect("GlobalID expiry must await worker task cleanup before returning");
    let mut guard = globals.lock().await;
    assert!(guard.registry.current(global_id, now).is_none());
    assert!(!guard.workers.contains_key(&global_id));
}

#[tokio::test]
async fn global_xudp_expiry_timer_is_task_tracked() {
    let maintenance_tasks = TaskTracker::new();
    let global_id = [173, 174, 175, 176, 177, 178, 179, 180];

    schedule_global_udp_worker_expiry(
        maintenance_tasks.clone(),
        CancellationToken::new(),
        global_id,
        Duration::from_millis(10),
    );
    assert_eq!(maintenance_tasks.len(), 1);

    timeout(Duration::from_secs(1), async {
        while !maintenance_tasks.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("GlobalID expiry timer must leave its task owner after completion");
}

#[tokio::test]
async fn global_xudp_expiry_timer_cancels_promptly_on_server_shutdown() {
    let maintenance_tasks = TaskTracker::new();
    let cancellation = CancellationToken::new();
    let global_id = [181, 182, 183, 184, 185, 186, 187, 188];

    schedule_global_udp_worker_expiry(
        maintenance_tasks.clone(),
        cancellation.clone(),
        global_id,
        Duration::from_secs(60),
    );
    assert_eq!(maintenance_tasks.len(), 1);
    maintenance_tasks.close();
    cancellation.cancel();

    timeout(Duration::from_secs(1), maintenance_tasks.wait())
        .await
        .expect("server shutdown must cancel GlobalID expiry timers promptly");
}

#[tokio::test]
async fn ended_global_xudp_attachment_resumes_same_socket() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind detached GlobalID UDP echo socket");
    let echo_addr = echo_socket
        .local_addr()
        .expect("detached GlobalID UDP echo address");
    let (peer_sender, mut peer_receiver) = mpsc::channel(2);
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        for _ in 0..2 {
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive detached GlobalID UDP request");
            peer_sender
                .send(peer)
                .await
                .expect("record detached GlobalID UDP peer");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send detached GlobalID UDP response");
        }
    });

    let global_id = [99, 100, 101, 102, 103, 104, 105, 106];
    let key = TargetedUdpSessionKey {
        target_addr: echo_addr,
        outbound_tag: None,
    };
    let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
    let worker_a = start_session_udp_session(
        301,
        1,
        key.clone(),
        response_sender_a,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start detachable GlobalID UDP attachment");
    worker_a
        .sender
        .send_to(b"before-detach".to_vec(), echo_addr)
        .await
        .expect("send pre-detach GlobalID payload");
    let first_response = timeout(Duration::from_secs(1), response_receiver_a.recv())
        .await
        .expect("pre-detach GlobalID response timeout")
        .expect("pre-detach GlobalID response event");
    assert!(matches!(
        first_response,
        SessionUdpEvent::Data(SessionUdpResponse {
            session_id: 301,
            generation: 1,
            ..
        })
    ));
    let mut ended_sessions = HashMap::from([(301, worker_a)]);
    expire_session_udp_worker(&mut ended_sessions, 301).await;
    assert!(ended_sessions.is_empty());

    let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
    let worker_b = start_session_udp_session(
        302,
        2,
        key,
        response_sender_b,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("resume detached GlobalID UDP attachment");
    worker_b
        .sender
        .send_to(b"after-detach".to_vec(), echo_addr)
        .await
        .expect("send resumed GlobalID payload");
    let second_response =
        timeout(Duration::from_secs(1), response_receiver_b.recv())
            .await
            .expect("resumed GlobalID response timeout")
            .expect("resumed GlobalID response event");
    assert!(matches!(
        second_response,
        SessionUdpEvent::Data(SessionUdpResponse {
            session_id: 302,
            generation: 2,
            ..
        })
    ));

    let first_peer = peer_receiver
        .recv()
        .await
        .expect("pre-detach GlobalID UDP peer");
    let second_peer = peer_receiver
        .recv()
        .await
        .expect("resumed GlobalID UDP peer");
    assert_eq!(first_peer, second_peer);

    let mut sessions = HashMap::from([(302, worker_b)]);
    terminate_session_udp_worker(&mut sessions, 302).await;
    echo_task.await.expect("ended GlobalID UDP echo task");
}

#[tokio::test]
async fn stale_global_xudp_cleanup_does_not_remove_reattachment() {
    let now = Instant::now();
    let global_id = [121, 122, 123, 124, 125, 126, 127, 128];
    let mut globals = GlobalXudpWorkers::default();
    let first = globals
        .registry
        .attach(global_id, 501, 1, now)
        .expect("attach GlobalID before cleanup test");
    assert!(globals.registry.detach(global_id, first.current.token, now));

    let (payload_sender, _payload_receiver) = mpsc::channel(1);
    let (response_sender, _response_receiver) = mpsc::channel(1);
    let attachment = Arc::new(RwLock::new(None));
    let task = tokio::spawn(std::future::pending::<()>());
    globals.workers.insert(
        global_id,
        GlobalSessionUdpWorker {
            key: GlobalUdpWorkerKey::Direct {
                target_is_ipv6: false,
                outbound_tag: None,
            },
            sender: payload_sender,
            attachment: attachment.clone(),
            attachment_notify: Arc::new(Notify::new()),
            task,
        },
    );

    let reattached = globals
        .registry
        .attach(
            global_id,
            502,
            2,
            now + XUDP_GLOBAL_REATTACH_TTL - Duration::from_millis(1),
        )
        .expect("reattach GlobalID before stale cleanup");
    *attachment.write().await = Some(GlobalUdpAttachment {
        token: reattached.current.token,
        session_id: 502,
        generation: 2,
        response_sender,
        traffic_context: None,
    });

    let expired_worker = take_expired_global_udp_worker(
        &mut globals,
        global_id,
        now + XUDP_GLOBAL_REATTACH_TTL + Duration::from_secs(1),
    );
    assert!(
        expired_worker.is_none(),
        "stale expiry cleanup must not remove a reattached worker",
    );

    assert_eq!(
        globals.registry.current(
            global_id,
            now + XUDP_GLOBAL_REATTACH_TTL + Duration::from_secs(1),
        ),
        Some(reattached.current)
    );
    assert!(globals.workers.contains_key(&global_id));
    let worker = globals
        .workers
        .remove(&global_id)
        .expect("GlobalID worker survives stale cleanup");
    stop_global_udp_worker(worker).await;
}

#[tokio::test]
async fn detached_global_xudp_buffers_downlink_until_reattach() {
    let remote_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind buffered GlobalID UDP socket");
    let remote_addr = remote_socket
        .local_addr()
        .expect("buffered GlobalID UDP address");
    let (request_sender, mut request_receiver) = mpsc::channel(1);
    let (release_sender, mut release_receiver) = mpsc::channel(1);
    let remote_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = remote_socket
            .recv_from(&mut buffer)
            .await
            .expect("receive buffered GlobalID request");
        request_sender
            .send((buffer[..length].to_vec(), peer))
            .await
            .expect("report buffered GlobalID request");
        release_receiver
            .recv()
            .await
            .expect("release buffered GlobalID response");
        remote_socket
            .send_to(b"delayed-response", peer)
            .await
            .expect("send buffered GlobalID response");
    });

    let global_id = [107, 108, 109, 110, 111, 112, 113, 114];
    let key = TargetedUdpSessionKey {
        target_addr: remote_addr,
        outbound_tag: None,
    };
    let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
    let worker_a = start_session_udp_session(
        401,
        1,
        key.clone(),
        response_sender_a,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start buffered GlobalID attachment");
    worker_a
        .sender
        .send_to(b"request-before-detach".to_vec(), remote_addr)
        .await
        .expect("send buffered GlobalID request");
    let (request, _) = timeout(Duration::from_secs(1), request_receiver.recv())
        .await
        .expect("buffered GlobalID request timeout")
        .expect("buffered GlobalID request observation");
    assert_eq!(request, b"request-before-detach");

    detach_session_udp_worker(worker_a).await;
    release_sender
        .send(())
        .await
        .expect("release detached GlobalID response");
    remote_task.await.expect("buffered GlobalID remote task");
    sleep(Duration::from_millis(20)).await;
    match timeout(Duration::from_millis(20), response_receiver_a.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(_)) => panic!(
            "detached GlobalID response must not be sent to the old attachment"
        ),
    }

    let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
    let worker_b = start_session_udp_session(
        402,
        2,
        key,
        response_sender_b,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("reattach buffered GlobalID session");
    let buffered_event = timeout(Duration::from_secs(1), response_receiver_b.recv())
        .await
        .expect("buffered GlobalID downlink timeout")
        .expect("buffered GlobalID downlink event");
    let SessionUdpEvent::Data(buffered_response) = buffered_event else {
        panic!("buffered GlobalID downlink was not data");
    };
    assert_eq!(buffered_response.session_id, 402);
    assert_eq!(buffered_response.generation, 2);
    assert_eq!(buffered_response.payload, b"delayed-response");

    let mut sessions = HashMap::from([(402, worker_b)]);
    terminate_session_udp_worker(&mut sessions, 402).await;
}

#[tokio::test]
async fn session_udp_worker_emits_end_on_idle_timeout() {
    let (event_sender, mut event_receiver) = mpsc::channel(4);
    let worker = start_session_udp_session(
        19,
        7,
        TargetedUdpSessionKey {
            target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            outbound_tag: None,
        },
        event_sender,
        None,
        None,
        Duration::from_millis(10),
    )
    .await
    .expect("start short-lived session UDP worker");

    let event = timeout(Duration::from_secs(1), event_receiver.recv())
        .await
        .expect("session UDP idle End timeout")
        .expect("session UDP idle End event");
    assert!(matches!(
        event,
        SessionUdpEvent::End {
            session_id: 19,
            generation: 7,
            has_error: false,
        }
    ));

    let mut task = worker.task.expect("local session UDP worker task");
    task.join
        .take()
        .expect("local session UDP worker join handle")
        .await
        .expect("idle session UDP worker should finish cleanly");
}

#[tokio::test]
async fn global_session_udp_worker_emits_end_on_idle_timeout() {
    let global_id = [151, 152, 153, 154, 155, 156, 157, 158];
    let (event_sender, mut event_receiver) = mpsc::channel(4);
    let worker = start_session_udp_session(
        20,
        8,
        TargetedUdpSessionKey {
            target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            outbound_tag: None,
        },
        event_sender,
        None,
        Some(global_id),
        Duration::from_millis(10),
    )
    .await
    .expect("start short-lived GlobalID session UDP worker");
    let mut sessions = HashMap::from([(20, worker)]);

    let event = timeout(Duration::from_secs(1), event_receiver.recv())
        .await
        .expect("GlobalID session UDP idle End timeout")
        .expect("GlobalID session UDP idle End event");
    assert!(matches!(
        event,
        SessionUdpEvent::End {
            session_id: 20,
            generation: 8,
            has_error: false,
        }
    ));

    terminate_session_udp_worker(&mut sessions, 20).await;
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn global_session_udp_worker_emits_error_end_on_write_failure() {
    let global_id = [161, 162, 163, 164, 165, 166, 167, 168];
    let (event_sender, mut event_receiver) = mpsc::channel(4);
    let worker = start_session_udp_session(
        21,
        9,
        TargetedUdpSessionKey {
            target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            outbound_tag: None,
        },
        event_sender,
        None,
        Some(global_id),
        Duration::from_secs(5),
    )
    .await
    .expect("start GlobalID write-failure UDP worker");
    let sender = worker.sender.clone();
    let mut sessions = HashMap::from([(21, worker)]);
    let invalid_target = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 9));

    let payload = timeout(
        Duration::from_secs(1),
        sender.send_to(b"write-failure".to_vec(), invalid_target),
    )
    .await
    .expect("GlobalID write failure must not hang")
    .expect_err("IPv4 GlobalID worker must reject an IPv6 target");
    assert_eq!(payload, b"write-failure");

    let event = timeout(Duration::from_secs(1), event_receiver.recv())
        .await
        .expect("GlobalID write-failure End timeout")
        .expect("GlobalID write-failure End event");
    assert!(matches!(
        event,
        SessionUdpEvent::End {
            session_id: 21,
            generation: 9,
            has_error: true,
        }
    ));

    terminate_session_udp_worker(&mut sessions, 21).await;
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn removing_session_udp_worker_waits_for_cancelled_task() {
    let (sender, _receiver) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let (stopped_sender, stopped_receiver) = oneshot::channel();
    let join = tokio::spawn(async move {
        task_cancellation.cancelled().await;
        let _ = stopped_sender.send(());
    });
    let mut sessions = HashMap::new();
    sessions.insert(
        23,
        SessionUdpWorker {
            key: TargetedUdpSessionKey {
                target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                outbound_tag: None,
            },
            global_id: None,
            generation: 1,
            sender: SessionUdpSender::Local(sender),
            task: Some(LocalSessionUdpTask {
                cancellation,
                join: Some(join),
            }),
        },
    );

    terminate_session_udp_worker(&mut sessions, 23).await;

    timeout(Duration::from_secs(1), stopped_receiver)
        .await
        .expect("local session UDP cancellation timeout")
        .expect("local session UDP task must observe cancellation");
    assert!(!sessions.contains_key(&23));
}

#[cfg(any(feature = "vless", feature = "vmess"))]
#[tokio::test]
async fn session_udp_write_error_waits_for_local_worker_cleanup() {
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind session UDP cleanup target");
    let target_addr = target
        .local_addr()
        .expect("session UDP cleanup target address");
    let (peer_sender, peer_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (length, peer) = target
            .recv_from(&mut buffer)
            .await
            .expect("receive session UDP cleanup request");
        peer_sender
            .send(peer)
            .expect("report session UDP worker address");
        release_receiver
            .await
            .expect("release session UDP cleanup response");
        target
            .send_to(&buffer[..length], peer)
            .await
            .expect("send session UDP cleanup response");
    });

    let stream = FailingSessionResponseStream {
        request: Some((
            SessionMessage::Data {
                session_id: 24,
                target: target_addr,
                global_id: None,
                is_new: true,
            },
            b"cleanup".to_vec(),
        )),
    };
    let relay = tokio::spawn(run_session_based_udp(
        Box::new(stream),
        runtime_with_outbounds(vec![outbound("direct", "freedom")]).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43124)),
        None,
        None,
    ));

    let worker_addr = timeout(Duration::from_secs(1), peer_receiver)
        .await
        .expect("session UDP worker address timeout")
        .expect("session UDP worker address channel");
    assert!(
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, worker_addr.port()))
            .await
            .is_err(),
        "local session UDP socket must still be owned before relay teardown"
    );

    release_sender
        .send(())
        .expect("release session UDP cleanup target response");
    target_task
        .await
        .expect("session UDP cleanup target task must not panic");
    let error = timeout(Duration::from_secs(1), relay)
        .await
        .expect("session UDP write failure must finish promptly")
        .expect("session UDP relay task must not panic")
        .expect_err("session UDP response write must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);

    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, worker_addr.port()))
        .await
        .expect("relay error teardown must release local session UDP socket before returning");
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn multi_directional_udp_relays_trojan_packets() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Trojan UDP echo socket");
    let echo_addr = echo_socket.local_addr().expect("Trojan UDP echo address");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        let (length, peer) = echo_socket
            .recv_from(&mut buffer)
            .await
            .expect("receive Trojan UDP echo request");
        echo_socket
            .send_to(&buffer[..length], peer)
            .await
            .expect("send Trojan UDP echo response");
    });

    let (mut client, server) = duplex(4096);
    let session_tasks = TaskTracker::new();
    let observed_session_tasks = session_tasks.clone();
    let relay_task = tokio::spawn(run_multi_directional_udp_with_tasks(
        Box::new(TrojanUdpStream::new(Box::new(TestStream(server)))),
        Arc::new(NativeResolver::new()),
        runtime_with_outbounds(vec![outbound("direct", "freedom")]).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 32000)),
        None,
        Some(
            TrafficContext::new("trojan")
                .with_identity("udp-user")
                .with_inbound_tag("trojan-udp"),
        ),
        session_tasks,
    ));

    let mut request = vec![1];
    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        unreachable!("test echo address must be IPv4");
    };
    request.extend_from_slice(&echo_ip.octets());
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    request.extend_from_slice(&4u16.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(b"ping");
    client
        .write_all(&request)
        .await
        .expect("write Trojan UDP packet");

    let mut header = [0u8; 9];
    timeout(Duration::from_secs(5), client.read_exact(&mut header))
        .await
        .expect("Trojan UDP response header timeout")
        .expect("read Trojan UDP response header");
    assert_eq!(header[0], 1);
    assert_eq!(&header[1..5], &echo_ip.octets());
    assert_eq!(u16::from_be_bytes([header[5], header[6]]), echo_addr.port());
    assert_eq!(u16::from_be_bytes([header[7], header[8]]), 4);

    let mut suffix_and_payload = [0u8; 6];
    client
        .read_exact(&mut suffix_and_payload)
        .await
        .expect("read Trojan UDP response payload");
    assert_eq!(&suffix_and_payload[..2], b"\r\n");
    assert_eq!(&suffix_and_payload[2..], b"ping");

    echo_task.await.expect("Trojan UDP echo task finished");
    drop(client);
    let relay_result = timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("multi-directional UDP relay teardown timeout")
        .expect("multi-directional UDP relay task panicked");
    assert!(relay_result.is_ok());
    assert_eq!(observed_session_tasks.len(), 0);
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn bidirectional_udp_routes_through_trojan_outbound() {
    let target = NetLocation::from_str("origin.example:53", None)
        .expect("Trojan UDP bidirectional target");
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy, "vmess-udp");

    let relay_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Trojan UDP bidirectional relay socket");
    let relay_addr = relay_socket
        .local_addr()
        .expect("Trojan UDP bidirectional relay address");
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Trojan UDP bidirectional client socket");
    let client_addr = client_socket
        .local_addr()
        .expect("Trojan UDP bidirectional client address");
    relay_socket
        .connect(client_addr)
        .await
        .expect("connect Trojan UDP relay socket");
    client_socket
        .connect(relay_addr)
        .await
        .expect("connect Trojan UDP client socket");

    let relay_task = tokio::spawn(run_bidirectional_udp(
        Box::new(relay_socket),
        target,
        Arc::new(NativeResolver::new()),
        runtime,
        client_addr,
        None,
        Some(
            TrafficContext::new("vmess")
                .with_identity("udp-user")
                .with_inbound_tag("vmess-udp"),
        ),
    ));

    client_socket
        .send(b"via-trojan")
        .await
        .expect("send Trojan-routed UDP message");
    let mut response = [0u8; 64];
    tokio::pin!(relay_task);
    let length = tokio::select! {
        result = client_socket.recv(&mut response) => {
            result.expect("receive Trojan-routed bidirectional response")
        }
        result = &mut relay_task => {
            panic!("Trojan-routed bidirectional relay ended early: {result:?}");
        }
        _ = sleep(Duration::from_secs(5)) => {
            panic!("Trojan-routed bidirectional response timeout");
        }
    };
    assert_eq!(&response[..length], b"via-trojan");

    relay_task.abort();
    proxy_task.abort();
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn multi_directional_udp_routes_through_trojan_outbound() {
    let target_addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53));
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy, "trojan-udp");
    let (client, server) = duplex(4096);
    let mut client_stream = TrojanUdpStream::new(Box::new(TestStream(client)));
    let relay_task = tokio::spawn(run_multi_directional_udp(
        Box::new(TrojanUdpStream::new(Box::new(TestStream(server)))),
        Arc::new(NativeResolver::new()),
        runtime,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 32001)),
        None,
        Some(
            TrafficContext::new("trojan")
                .with_identity("udp-user")
                .with_inbound_tag("trojan-udp"),
        ),
    ));

    client_stream
        .send_to(&target, b"targeted-via-trojan")
        .await
        .expect("send targeted Trojan-routed UDP packet");
    let mut response = [0u8; 128];
    let (source, length) = timeout(
        Duration::from_secs(5),
        client_stream.recv_from(&mut response),
    )
    .await
    .expect("targeted Trojan-routed response timeout")
    .expect("receive targeted Trojan-routed response");
    assert_eq!(source.port(), target.port());
    assert_eq!(&response[..length], b"targeted-via-trojan");

    relay_task.abort();
    proxy_task.abort();
}

#[cfg(all(feature = "trojan", any(feature = "vless", feature = "vmess")))]
#[tokio::test]
async fn session_udp_routes_through_trojan_outbound() {
    let target_addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53));
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy, "xudp-in");

    let mut frame = BytesMut::new();
    FrameMetadata {
        session_id: 77,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(target),
        network: Some(TargetNetwork::Udp),
        global_id: None,
    }
    .encode(&mut frame)
    .expect("encode Trojan-routed XUDP request metadata");
    let request_payload = b"xudp-via-trojan";
    frame.put_u16(request_payload.len() as u16);
    frame.extend_from_slice(request_payload);

    let (mut client, server) = duplex(4096);
    client
        .write_all(&frame)
        .await
        .expect("write Trojan-routed XUDP request");
    let relay_stream = XudpMessageStream::new(
        Box::new(TestStream(server)),
        Arc::new(NativeResolver::new()),
    );
    let relay_task = tokio::spawn(run_session_based_udp(
        Box::new(relay_stream),
        runtime,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43177)),
        None,
        Some(
            TrafficContext::new("vless")
                .with_identity("udp-user")
                .with_inbound_tag("xudp-in"),
        ),
    ));

    let mut metadata_length = [0u8; 2];
    timeout(
        Duration::from_secs(5),
        client.read_exact(&mut metadata_length),
    )
    .await
    .expect("Trojan-routed XUDP response metadata timeout")
    .expect("read Trojan-routed XUDP response metadata length");
    let metadata_length = u16::from_be_bytes(metadata_length) as usize;
    let mut metadata_body = vec![0u8; metadata_length];
    client
        .read_exact(&mut metadata_body)
        .await
        .expect("read Trojan-routed XUDP response metadata");
    let mut metadata_frame = BytesMut::with_capacity(metadata_length + 2);
    metadata_frame.put_u16(metadata_length as u16);
    metadata_frame.extend_from_slice(&metadata_body);
    let metadata = FrameMetadata::decode(&mut metadata_frame)
        .expect("decode Trojan-routed XUDP response metadata")
        .expect("complete Trojan-routed XUDP response metadata");
    assert_eq!(metadata.session_id, 77);
    assert_eq!(metadata.status, SessionStatus::Keep);
    assert_eq!(
        metadata.target,
        Some(NetLocation::from_ip_addr(
            target_addr.ip(),
            target_addr.port(),
        ))
    );

    let payload_length = client
        .read_u16()
        .await
        .expect("read Trojan-routed XUDP response payload length")
        as usize;
    let mut response = vec![0u8; payload_length];
    client
        .read_exact(&mut response)
        .await
        .expect("read Trojan-routed XUDP response payload");
    assert_eq!(response, b"xudp-via-trojan");

    let mut end_frame = BytesMut::new();
    FrameMetadata {
        session_id: 77,
        status: SessionStatus::End,
        option: FrameOption::default(),
        target: None,
        network: None,
        global_id: None,
    }
    .encode(&mut end_frame)
    .expect("encode Trojan-routed XUDP End metadata");
    client
        .write_all(&end_frame)
        .await
        .expect("write Trojan-routed XUDP End");

    timeout(Duration::from_secs(1), proxy_task)
        .await
        .expect("Trojan session UDP cleanup must close proxy promptly")
        .expect("fake Trojan UDP proxy task must not panic");

    drop(client);
    timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("Trojan-routed XUDP relay teardown timeout")
        .expect("Trojan-routed XUDP relay task must not panic")
        .expect("Trojan-routed XUDP relay teardown must succeed");
}

#[tokio::test]
async fn bidirectional_udp_relay_preserves_message_boundaries() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP echo socket");
    let echo_addr = echo_socket.local_addr().expect("UDP echo address");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        let (len, peer) = echo_socket
            .recv_from(&mut buffer)
            .await
            .expect("receive UDP echo request");
        echo_socket
            .send_to(&buffer[..len], peer)
            .await
            .expect("send UDP echo response");
    });

    let relay_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind message relay socket");
    let relay_addr = relay_socket.local_addr().expect("message relay address");
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind message client socket");
    let client_addr = client_socket.local_addr().expect("message client address");
    relay_socket
        .connect(client_addr)
        .await
        .expect("connect relay message socket");
    client_socket
        .connect(relay_addr)
        .await
        .expect("connect client message socket");

    let relay_task = tokio::spawn(run_bidirectional_udp(
        Box::new(relay_socket),
        NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port()),
        Arc::new(NativeResolver::new()),
        runtime_with_outbounds(Vec::new()).data_plane(),
        client_addr,
        None,
        Some(
            TrafficContext::new("vmess")
                .with_identity("udp-user")
                .with_inbound_tag("vmess-udp"),
        ),
    ));

    client_socket
        .send(b"vmess-udp-message")
        .await
        .expect("send message to relay");
    let mut response = [0u8; 128];
    let len = timeout(Duration::from_secs(5), client_socket.recv(&mut response))
        .await
        .expect("bidirectional UDP response timeout")
        .expect("receive bidirectional UDP response");

    assert_eq!(&response[..len], b"vmess-udp-message");
    echo_task.await.expect("UDP echo task finished");
    relay_task.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dokodemo_udp_follow_redirect_routes_by_original_destination() {
    let observation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fixed-target observation socket");
    let observation_addr = observation
        .local_addr()
        .expect("fixed-target observation address");

    let socket = new_socket2_udp_socket(
        false,
        None,
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        false,
    )
    .expect("bind followRedirect UDP socket");
    enable_udp_original_destination(&socket, false)
        .expect("enable UDP original destination");
    let server_addr = socket
        .local_addr()
        .expect("followRedirect UDP listener address")
        .as_socket()
        .expect("followRedirect listener must use IP address");
    let socket: std::net::UdpSocket = socket.into();
    let server_socket = Arc::new(
        UdpSocket::from_std(socket).expect("convert followRedirect UDP listener"),
    );

    let runtime = runtime_with_outbounds(vec![
        outbound("direct", "freedom"),
        outbound("blocked", "blackhole"),
    ]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                network: NetworkListConfig(vec!["udp".into()]),
                port: PortListConfig(vec![PortRangeConfig {
                    from: server_addr.port(),
                    to: server_addr.port(),
                }]),
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("build original-destination routing rule"),
    );

    let server_task = tokio::spawn(run_dokodemo_udp_server(
        server_socket,
        DokodemoDoorConfig {
            target: NetLocation::from_ip_addr(
                observation_addr.ip(),
                observation_addr.port(),
            ),
            follow_redirect: true,
            user_level: 0,
        },
        None::<SocketAddr>,
        "dokodemo-follow-redirect".into(),
        runtime.data_plane(),
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind followRedirect UDP client");
    client
        .send_to(b"must-use-original-destination", server_addr)
        .await
        .expect("send followRedirect UDP datagram");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !server_task.is_finished(),
        "followRedirect receive loop must remain active"
    );
    let mut buffer = [0u8; 64];
    assert!(
        timeout(
            Duration::from_millis(100),
            observation.recv_from(&mut buffer)
        )
        .await
        .is_err(),
        "fixed config target must not receive a followRedirect datagram"
    );

    server_task.abort();
}

#[cfg(feature = "shadowsocks")]
#[tokio::test]
async fn shadowsocks_udp_packet_stays_owned_after_listener_stop() {
    let target_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Shadowsocks UDP target socket");
    let target_addr = target_socket
        .local_addr()
        .expect("Shadowsocks UDP target address");
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());
    let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
    let user = ShadowsocksUser {
        method: "xchacha20-poly1305".to_string(),
        password: "password".to_string(),
        email: "ss-owner@example.com".to_string(),
        user_level: 0,
    };
    let server_codec = Arc::new(
        ShadowsocksUdpCodec::new(vec![user.clone()], None)
            .expect("create Shadowsocks UDP server codec"),
    );
    let client_codec = ShadowsocksUdpCodec::new(vec![user], None)
        .expect("create Shadowsocks UDP client codec");
    let request = client_codec
        .encrypt_test_request(&target, b"before-listener-stop")
        .expect("encrypt Shadowsocks UDP request");

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Shadowsocks UDP server socket"),
    );
    let server_addr = server_socket
        .local_addr()
        .expect("Shadowsocks UDP server address");
    let server_task = tokio::spawn(run_shadowsocks_udp_server(
        server_socket,
        server_codec,
        "ss-owner".to_string(),
        runtime.data_plane(),
    ));
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Shadowsocks UDP client socket");
    client_socket
        .send_to(&request, server_addr)
        .await
        .expect("send Shadowsocks UDP request");

    let mut target_request = [0u8; 128];
    let (request_len, outbound_peer) = timeout(
        Duration::from_secs(1),
        target_socket.recv_from(&mut target_request),
    )
    .await
    .expect("Shadowsocks UDP target request timeout")
    .expect("receive Shadowsocks UDP target request");
    assert_eq!(&target_request[..request_len], b"before-listener-stop");
    assert_eq!(runtime.tracked_inbound_connection_count(), 1);

    server_task.abort();
    let _ = server_task.await;
    assert_eq!(
        runtime.tracked_inbound_connection_count(),
        1,
        "stopping the Shadowsocks UDP listener must not orphan or cancel an active packet task",
    );

    target_socket
        .send_to(b"after-listener-stop", outbound_peer)
        .await
        .expect("send Shadowsocks UDP target response");
    let mut encrypted_response = vec![0u8; 4096];
    let (response_len, source) = timeout(
        Duration::from_secs(1),
        client_socket.recv_from(&mut encrypted_response),
    )
    .await
    .expect("Shadowsocks UDP response after listener stop timeout")
    .expect("receive Shadowsocks UDP response after listener stop");
    assert_eq!(source, server_addr);
    let response = client_codec
        .decrypt_packet(&encrypted_response[..response_len])
        .expect("decrypt Shadowsocks UDP response after listener stop");
    assert_eq!(response.target_location, target);
    assert_eq!(response.payload, b"after-listener-stop");

    timeout(Duration::from_secs(1), async {
        while runtime.tracked_inbound_connection_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed Shadowsocks UDP packet task must leave the server owner");
}

#[cfg(all(feature = "shadowsocks", feature = "trojan"))]
#[tokio::test]
async fn shadowsocks_udp_routes_through_trojan_outbound() {
    let target = NetLocation::from_str("origin.example:53", None)
        .expect("Shadowsocks Trojan UDP target");
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy, "ss-trojan");
    let user = ShadowsocksUser {
        method: "xchacha20-poly1305".to_string(),
        password: "password".to_string(),
        email: "ss-user@example.com".to_string(),
        user_level: 0,
    };
    let server_codec = Arc::new(
        ShadowsocksUdpCodec::new(vec![user.clone()], None)
            .expect("create Shadowsocks UDP server codec"),
    );
    let client_codec = ShadowsocksUdpCodec::new(vec![user], None)
        .expect("create Shadowsocks UDP client codec");
    let request = client_codec
        .encrypt_test_request(&target, b"ss-via-trojan")
        .expect("encrypt Shadowsocks UDP request");

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Shadowsocks UDP server socket"),
    );
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Shadowsocks UDP client socket");
    let client_addr = client_socket
        .local_addr()
        .expect("Shadowsocks UDP client address");

    let relay = tokio::spawn(relay_shadowsocks_udp_packet(
        server_socket,
        server_codec,
        Arc::new(NativeResolver::new()),
        runtime,
        "ss-trojan".to_string(),
        client_addr,
        request,
    ));

    let mut encrypted_response = vec![0u8; 4096];
    let (response_len, _) = timeout(
        Duration::from_secs(5),
        client_socket.recv_from(&mut encrypted_response),
    )
    .await
    .expect("Shadowsocks Trojan UDP response timeout")
    .expect("receive Shadowsocks Trojan UDP response");
    let response = client_codec
        .decrypt_packet(&encrypted_response[..response_len])
        .expect("decrypt Shadowsocks Trojan UDP response");
    assert_eq!(response.target_location, target);
    assert_eq!(response.payload, b"ss-via-trojan");

    relay
        .await
        .expect("Shadowsocks Trojan UDP relay task")
        .expect("Shadowsocks Trojan UDP relay succeeds");
    proxy_task
        .await
        .expect("fake Shadowsocks Trojan UDP proxy task");
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn dokodemo_udp_routes_through_reused_trojan_session() {
    let target = NetLocation::from_str("origin.example:53", None)
        .expect("Dokodemo Trojan UDP target");
    let (proxy, proxy_task) = start_fake_trojan_udp_proxy(target.clone()).await;
    let runtime = runtime_routing_udp_to(proxy, "dokodemo-trojan");

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Dokodemo Trojan UDP socket"),
    );
    let server_addr = server_socket
        .local_addr()
        .expect("Dokodemo Trojan UDP address");
    let target_addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53));
    let server_task = tokio::spawn(run_dokodemo_udp_server(
        server_socket,
        DokodemoDoorConfig {
            target: target.clone(),
            follow_redirect: false,
            user_level: 0,
        },
        Some(target_addr),
        "dokodemo-trojan".to_string(),
        runtime.clone(),
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Dokodemo Trojan UDP client");
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        client
            .send_to(payload, server_addr)
            .await
            .expect("send Dokodemo Trojan UDP request");
        let mut response = [0u8; 64];
        let (length, source) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("Dokodemo Trojan UDP response timeout")
                .expect("receive Dokodemo Trojan UDP response");
        assert_eq!(source, server_addr);
        assert_eq!(&response[..length], payload);
    }

    timeout(Duration::from_secs(1), async {
        loop {
            if runtime.tracked_inbound_connection_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Dokodemo Trojan UDP session must enter the server task owner");

    server_task.abort();
    let _ = server_task.await;
    assert_eq!(
        runtime.tracked_inbound_connection_count(),
        1,
        "stopping the UDP listener must not cancel the active Trojan UDP session",
    );
    proxy_task.abort();
}

#[tokio::test]
async fn dokodemo_udp_relay_forwards_datagrams() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo socket");
    let echo_addr = echo_socket.local_addr().expect("echo addr");
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (len, peer) = echo_socket.recv_from(&mut buf).await.expect("echo recv");
        echo_socket
            .send_to(&buf[..len], peer)
            .await
            .expect("echo send");
    });

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind dokodemo socket"),
    );
    let server_addr = server_socket.local_addr().expect("dokodemo addr");
    let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
    let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
    let server_task = tokio::spawn(run_dokodemo_udp_server(
        server_socket,
        DokodemoDoorConfig {
            target: target.clone(),
            follow_redirect: false,
            user_level: 0,
        },
        echo_addr,
        "dokodemo-udp-test".into(),
        runtime.data_plane(),
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind client socket");
    client
        .send_to(b"ping", server_addr)
        .await
        .expect("client send");

    let mut response = [0u8; 32];
    let (len, _peer) =
        timeout(Duration::from_secs(5), client.recv_from(&mut response))
            .await
            .expect("relay response timeout")
            .expect("client receive");
    assert_eq!(&response[..len], b"ping");

    timeout(Duration::from_secs(1), async {
        loop {
            if runtime.tracked_inbound_connection_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Dokodemo UDP logical session must enter the server task owner");

    echo_task.await.expect("echo task finished");
    server_task.abort();
    let _ = server_task.await;
    assert_eq!(
        runtime.tracked_inbound_connection_count(),
        1,
        "stopping the UDP listener must not orphan or cancel the active logical session",
    );
}

#[tokio::test]
async fn dokodemo_udp_reuses_session_for_same_flow() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo socket");
    let echo_addr = echo_socket.local_addr().expect("echo addr");
    let (peer_tx, mut peer_rx) = mpsc::channel(2);
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        for _ in 0..2 {
            let (len, peer) =
                echo_socket.recv_from(&mut buf).await.expect("echo recv");
            peer_tx.send(peer).await.expect("record peer");
            echo_socket
                .send_to(&buf[..len], peer)
                .await
                .expect("echo send");
        }
    });

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind dokodemo socket"),
    );
    let server_addr = server_socket.local_addr().expect("dokodemo addr");
    let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
    let server_task = tokio::spawn(run_dokodemo_udp_server(
        server_socket,
        DokodemoDoorConfig {
            target: target.clone(),
            follow_redirect: false,
            user_level: 0,
        },
        echo_addr,
        "dokodemo-udp-test".into(),
        runtime_with_outbounds(vec![outbound("direct", "freedom")]).data_plane(),
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind client socket");
    let mut response = [0u8; 32];

    client
        .send_to(b"one", server_addr)
        .await
        .expect("client send one");
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("relay response one timeout")
        .expect("client receive one");
    assert_eq!(&response[..len], b"one");

    client
        .send_to(b"two", server_addr)
        .await
        .expect("client send two");
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("relay response two timeout")
        .expect("client receive two");
    assert_eq!(&response[..len], b"two");

    let first_peer = peer_rx.recv().await.expect("first outbound peer");
    let second_peer = peer_rx.recv().await.expect("second outbound peer");
    assert_eq!(first_peer, second_peer);

    echo_task.await.expect("echo task finished");
    server_task.abort();
}

#[tokio::test]
async fn dokodemo_udp_session_forwards_multiple_responses() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo socket");
    let echo_addr = echo_socket.local_addr().expect("echo addr");
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (_len, peer) = echo_socket.recv_from(&mut buf).await.expect("echo recv");
        echo_socket
            .send_to(b"first", peer)
            .await
            .expect("send first");
        echo_socket
            .send_to(b"second", peer)
            .await
            .expect("send second");
    });

    let server_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind dokodemo socket"),
    );
    let server_addr = server_socket.local_addr().expect("dokodemo addr");
    let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
    let server_task = tokio::spawn(run_dokodemo_udp_server(
        server_socket,
        DokodemoDoorConfig {
            target: target.clone(),
            follow_redirect: false,
            user_level: 0,
        },
        echo_addr,
        "dokodemo-udp-test".into(),
        runtime_with_outbounds(vec![outbound("direct", "freedom")]).data_plane(),
    ));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind client socket");
    client
        .send_to(b"request", server_addr)
        .await
        .expect("client send");

    let mut response = [0u8; 32];
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("first relay response timeout")
        .expect("client receive first");
    assert_eq!(&response[..len], b"first");
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("second relay response timeout")
        .expect("client receive second");
    assert_eq!(&response[..len], b"second");

    echo_task.await.expect("echo task finished");
    server_task.abort();
}

#[tokio::test]
async fn udp_routing_selects_blackhole_outbound() {
    let runtime = runtime_with_outbounds(vec![
        outbound("direct", "freedom"),
        outbound("blocked", "blackhole"),
    ]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["dokodemo-udp".into()],
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("routing should build"),
    );

    let action = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect("outbound selection should succeed");

    assert_eq!(
        action,
        UdpOutboundAction::Blackhole {
            tag: "blocked".into()
        }
    );
}

#[tokio::test]
async fn udp_routing_matches_local_ip_and_port() {
    let runtime = runtime_with_outbounds(vec![
        outbound("direct", "freedom"),
        outbound("blocked", "blackhole"),
    ]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                local_ip: vec!["127.0.0.1/32".into()],
                local_port: PortListConfig(vec![PortRangeConfig {
                    from: 5353,
                    to: 5353,
                }]),
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("UDP local metadata routing should build"),
    );

    let action = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 5353))),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect("UDP local metadata routing should succeed");

    assert_eq!(
        action,
        UdpOutboundAction::Blackhole {
            tag: "blocked".into()
        }
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_routing_selects_outbound_by_local_process() {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind process routing UDP client");
    let client_addr = client.local_addr().expect("UDP client address");
    let process_name = std::env::current_exe()
        .expect("current executable")
        .file_name()
        .expect("current executable name")
        .to_string_lossy()
        .into_owned();
    let runtime = runtime_with_outbounds(vec![
        outbound("direct", "freedom"),
        outbound("blocked", "blackhole"),
    ]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                process: vec![process_name],
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("UDP process routing should build"),
    );

    let action = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        client_addr,
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect("UDP process routing should succeed");

    assert_eq!(
        action,
        UdpOutboundAction::Blackhole {
            tag: "blocked".into()
        }
    );
}

#[tokio::test]
async fn udp_routing_defaults_to_first_outbound() {
    let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);

    let action = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect("outbound selection should succeed");

    assert_eq!(
        action,
        UdpOutboundAction::Freedom {
            tag: Some("direct".into())
        }
    );
}

#[tokio::test]
async fn udp_routing_rejects_missing_routed_outbound() {
    let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["dokodemo-udp".into()],
                network: NetworkListConfig(vec!["udp".into()]),
                outbound_tag: Some("missing".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("missing UDP outbound routing rule should compile"),
    );

    let error = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect_err("missing routed UDP outbound must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("missing outbound missing"));
}

#[tokio::test]
async fn udp_routing_rejects_empty_balancer_without_falling_back() {
    let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["dokodemo-udp".into()],
                network: NetworkListConfig(vec!["udp".into()]),
                balancer_tag: Some("empty".into()),
                ..RuleConfig::default()
            }],
            balancers: vec![BalancerConfig {
                tag: "empty".into(),
                outbound_selector: vec!["missing-prefix".into()],
                strategy: Default::default(),
                fallback_tag: None,
            }],
            ..RoutingConfig::default()
        }))
        .expect("empty UDP balancer routing rule should compile"),
    );

    let error = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect_err("empty routed UDP balancer must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("balancer empty has no available outbound")
    );
}

#[tokio::test]
async fn udp_routing_rejects_unsupported_outbound_protocol() {
    let runtime = runtime_with_outbounds(vec![outbound("proxy", "vmess")]);

    let err = select_udp_outbound(
        &runtime.data_plane(),
        "dokodemo-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
        None,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
    )
    .await
    .expect_err("unsupported udp outbound protocol should fail");

    assert!(
        err.to_string()
            .contains("udp outbound proxy uses unsupported protocol vmess")
    );
}

#[test]
fn udp_bind_location_converts_ip_address() {
    let bind_location = BindLocation::Address(NetLocation::new(
        Address::Ipv4(Ipv4Addr::LOCALHOST),
        1080,
    ));

    let socket_addr = bind_location_to_socket_addr(&bind_location)
        .expect("ip bind should convert to socket address");
    assert_eq!(socket_addr.port(), 1080);
}
