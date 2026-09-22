use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
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
    },
};

use super::{BridgeTcpDispatcher, MuxServerWorker};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchCall {
    reverse_tag: String,
    target: NetLocation,
    source: Option<SocketAddr>,
    local: Option<SocketAddr>,
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
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        self.calls
            .lock()
            .expect("fake dispatch calls lock poisoned")
            .push(DispatchCall {
                reverse_tag: reverse_tag.to_string(),
                target,
                source,
                local,
            });
        let stream = self
            .stream
            .lock()
            .expect("fake dispatch stream lock poisoned")
            .take()
            .ok_or_else(|| std::io::Error::other("fake stream already consumed"))?;
        Ok(Box::new(ReverseSessionStream::new(stream)))
    }
}

fn tcp_destination(address: Ipv4Addr, port: u16) -> Destination {
    Destination {
        network: TargetNetwork::Tcp,
        location: NetLocation::new(Address::Ipv4(address), port),
    }
}

#[tokio::test]
async fn mux_server_routes_tcp_with_reverse_context_and_round_trips_frames() {
    let (physical, mut portal) = duplex(16 * 1024);
    let (local, mut local_peer) = duplex(16 * 1024);
    let dispatcher = Arc::new(FakeDispatcher::new(local));
    let worker = MuxServerWorker::new(
        Box::new(ReverseSessionStream::new(physical)),
        "bridge-in".to_string(),
        dispatcher.clone(),
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

    timeout(Duration::from_secs(1), async {
        while worker.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("logical session is removed after END");
}

#[tokio::test]
async fn mux_server_rejects_udp_until_xudp_batch() {
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
            session_id: 8,
            status: SessionStatus::New,
            option: FrameOption::default(),
            target: Some(Destination {
                network: TargetNetwork::Udp,
                location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53),
            }),
            source: None,
            local: None,
            global_id: None,
        },
        payload: Bytes::new(),
    };
    portal
        .write_all(&encode_frame(&request).expect("encode UDP Reverse NEW"))
        .await
        .expect("write UDP Reverse NEW");

    timeout(Duration::from_secs(1), worker.wait_closed())
        .await
        .expect("unsupported UDP frame closes the physical worker");
    assert!(worker.closed());
}
