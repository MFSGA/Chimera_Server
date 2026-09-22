use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    time::timeout,
};

use crate::{
    address::{Address, NetLocation},
    handler::vless_reverse::{
        mux_frame::{
            Destination, FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
        },
        mux_io::{
            MuxFrame, encode_frame, read_frame, read_frame_with_source_and_local,
        },
        session_core::{SessionLimits, WorkerPhase},
        session_stream::ReverseSessionStream,
    },
};

use super::{MuxClientPicker, MuxClientWorker};

fn target(port: u16) -> Destination {
    Destination {
        network: TargetNetwork::Tcp,
        location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port),
    }
}

fn udp_target(address: Ipv4Addr, port: u16) -> Destination {
    Destination {
        network: TargetNetwork::Udp,
        location: NetLocation::new(Address::Ipv4(address), port),
    }
}

fn worker_with_peer(
    id: u64,
    physical_capacity: usize,
    limits: SessionLimits,
) -> (MuxClientWorker, DuplexStream) {
    let (physical, peer) = duplex(physical_capacity);
    (
        MuxClientWorker::new(
            id,
            Box::new(ReverseSessionStream::new(physical)),
            limits,
        ),
        peer,
    )
}

async fn write_remote_frame(peer: &mut DuplexStream, frame: MuxFrame) {
    let encoded = encode_frame(&frame).expect("encode remote Mux frame");
    peer.write_all(&encoded)
        .await
        .expect("write remote Mux frame");
}

#[tokio::test]
async fn worker_requires_active_control_and_drain_stops_new_sessions() {
    let (worker, _peer) = worker_with_peer(1, 4096, SessionLimits::default());

    let error = worker
        .open_tcp_session(target(80), None, None)
        .expect_err("pending worker must reject public sessions");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

    worker
        .control_session_became_active()
        .expect("control session activates worker");
    let _session = worker
        .open_tcp_session(target(80), None, None)
        .expect("ACTIVE worker accepts a session");
    assert_eq!(worker.active_connections(), 1);

    worker.begin_drain().expect("begin worker drain");
    assert_eq!(worker.phase(), WorkerPhase::Draining);
    let error = worker
        .open_tcp_session(target(81), None, None)
        .expect_err("DRAIN worker must reject new sessions");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

#[tokio::test]
async fn tcp_session_round_trips_payload_and_xray_end_closes_both_halves() {
    let (worker, mut peer) = worker_with_peer(2, 4096, SessionLimits::default());
    worker
        .control_session_became_active()
        .expect("activate worker");

    let source = Destination {
        network: TargetNetwork::Tcp,
        location: NetLocation::new(
            Address::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            50_000,
        ),
    };
    let local = Destination {
        network: TargetNetwork::Tcp,
        location: NetLocation::new(
            Address::Ipv4(Ipv4Addr::new(203, 0, 113, 5)),
            8443,
        ),
    };

    let mut session = worker
        .open_tcp_session(target(8080), Some(source.clone()), Some(local.clone()))
        .expect("open public Reverse session");
    session
        .write_all(b"hello")
        .await
        .expect("write session uplink");

    let first = read_frame_with_source_and_local(&mut peer, true)
        .await
        .expect("read first Reverse Mux frame");
    assert_eq!(first.metadata.status, SessionStatus::New);
    assert_eq!(first.metadata.source, Some(source));
    assert_eq!(first.metadata.local, Some(local));
    assert_eq!(first.payload.as_ref(), b"hello");
    let session_id = first.metadata.session_id;

    write_remote_frame(
        &mut peer,
        MuxFrame {
            metadata: FrameMetadata {
                session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"world"),
        },
    )
    .await;

    let mut response = [0u8; 5];
    session
        .read_exact(&mut response)
        .await
        .expect("read session downlink");
    assert_eq!(&response, b"world");

    session
        .shutdown()
        .await
        .expect("shutdown session write side");

    let end = read_frame(&mut peer).await.expect("read Mux END");
    assert_eq!(end.metadata.session_id, session_id);
    assert_eq!(end.metadata.status, SessionStatus::End);
    assert!(end.payload.is_empty());

    let mut one = [0u8; 1];
    let read = timeout(Duration::from_secs(1), session.read(&mut one))
        .await
        .expect("logical session close must propagate")
        .expect("read logical EOF");
    assert_eq!(read, 0, "Xray Mux END closes the logical session");
}

#[tokio::test]
async fn udp_packet_session_matches_xray_reverse_mux_packet_frames() {
    let (worker, mut peer) = worker_with_peer(6, 4096, SessionLimits::default());
    worker
        .control_session_became_active()
        .expect("activate worker");
    let original = udp_target(Ipv4Addr::new(192, 0, 2, 53), 53);
    let source = udp_target(Ipv4Addr::new(198, 51, 100, 7), 40_000);
    let local = udp_target(Ipv4Addr::new(203, 0, 113, 8), 5353);
    let mut session = worker
        .open_packet_session(
            original.clone(),
            Some(source.clone()),
            Some(local.clone()),
        )
        .expect("open Reverse UDP packet session");

    session
        .send(Bytes::from_static(b"query"), None)
        .await
        .expect("send first UDP packet");
    let first = read_frame_with_source_and_local(&mut peer, true)
        .await
        .expect("read UDP NEW frame");
    assert_eq!(first.metadata.status, SessionStatus::New);
    assert_eq!(first.metadata.target, Some(original));
    assert_eq!(first.metadata.source, Some(source));
    assert_eq!(first.metadata.local, Some(local));
    assert_eq!(first.metadata.global_id, None);
    assert_eq!(first.payload.as_ref(), b"query");
    let session_id = first.metadata.session_id;

    let override_target = udp_target(Ipv4Addr::new(192, 0, 2, 54), 5353);
    session
        .send(
            Bytes::from_static(b"query-2"),
            Some(override_target.clone()),
        )
        .await
        .expect("send UDP packet with target override");
    let keep = read_frame(&mut peer).await.expect("read UDP KEEP frame");
    assert_eq!(keep.metadata.status, SessionStatus::Keep);
    assert_eq!(keep.metadata.target, Some(override_target));
    assert_eq!(keep.payload.as_ref(), b"query-2");

    let response_target = udp_target(Ipv4Addr::new(192, 0, 2, 99), 53);
    write_remote_frame(
        &mut peer,
        MuxFrame {
            metadata: FrameMetadata {
                session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: Some(response_target.clone()),
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"answer"),
        },
    )
    .await;
    let (payload, target) = session
        .recv()
        .await
        .expect("receive UDP response")
        .expect("UDP response event");
    assert_eq!(payload.as_ref(), b"answer");
    assert_eq!(target, Some(response_target));

    session.close().await.expect("close UDP packet session");
    let end = read_frame(&mut peer).await.expect("read UDP END frame");
    assert_eq!(end.metadata.session_id, session_id);
    assert_eq!(end.metadata.status, SessionStatus::End);
    assert!(end.payload.is_empty());
}

#[tokio::test]
async fn orphan_keep_gets_end_reply_like_xray_client_worker() {
    let (worker, mut peer) = worker_with_peer(3, 4096, SessionLimits::default());
    worker
        .control_session_became_active()
        .expect("activate worker");

    write_remote_frame(
        &mut peer,
        MuxFrame {
            metadata: FrameMetadata {
                session_id: 77,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"orphan"),
        },
    )
    .await;

    let reply = read_frame(&mut peer).await.expect("read orphan END reply");
    assert_eq!(reply.metadata.session_id, 77);
    assert_eq!(reply.metadata.status, SessionStatus::End);
    assert!(reply.payload.is_empty());
}

#[tokio::test]
async fn physical_close_propagates_to_worker_and_logical_sessions() {
    let (worker, peer) = worker_with_peer(4, 4096, SessionLimits::default());
    worker
        .control_session_became_active()
        .expect("activate worker");
    let mut session = worker
        .open_tcp_session(target(8081), None, None)
        .expect("open logical session");

    drop(peer);

    timeout(Duration::from_secs(1), worker.wait_closed())
        .await
        .expect("physical EOF must close worker");
    assert_eq!(worker.phase(), WorkerPhase::Closed);

    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(1), session.read(&mut byte))
        .await
        .expect("worker close must wake logical reader")
        .expect("logical reader closes cleanly");
    assert_eq!(read, 0);
}

#[tokio::test]
async fn bounded_mux_queues_backpressure_application_writes() {
    let (worker, _peer) = worker_with_peer(5, 1, SessionLimits::default());
    worker
        .control_session_became_active()
        .expect("activate worker");
    let mut session = worker
        .open_tcp_session(target(8082), None, None)
        .expect("open logical session");

    let payload = vec![0x5a; 512 * 1024];
    let write =
        timeout(Duration::from_millis(200), session.write_all(&payload)).await;
    assert!(
        write.is_err(),
        "bounded physical/session queues must apply backpressure"
    );

    worker.close();
}

#[tokio::test]
async fn runtime_picker_uses_least_loaded_active_worker_only() {
    let (first, _first_peer) = worker_with_peer(10, 4096, SessionLimits::default());
    let (second, _second_peer) =
        worker_with_peer(11, 4096, SessionLimits::default());
    first
        .control_session_became_active()
        .expect("activate first");
    second
        .control_session_became_active()
        .expect("activate second");

    let first = Arc::new(first);
    let second = Arc::new(second);
    let picker = MuxClientPicker::default();
    picker.add(first.clone());
    picker.add(second.clone());

    let _busy_session = first
        .open_tcp_session(target(9000), None, None)
        .expect("make first worker busier");

    assert_eq!(
        picker.pick_available().expect("pick idle worker").id(),
        second.id()
    );

    second.begin_drain().expect("drain second worker");
    assert_eq!(
        picker
            .pick_available()
            .expect("pick remaining ACTIVE worker")
            .id(),
        first.id()
    );

    first.close();
    let error = picker
        .pick_available()
        .expect_err("DRAIN/CLOSED workers must not be selected");
    assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
}
