use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error};

#[cfg(test)]
use std::net::IpAddr;
#[cfg(test)]
use tokio::net::UdpSocket;

use crate::{
    address::{Address, NetLocation},
    config::server_config::TuicServerConfig,
    outbound::connect_tcp_outbound,
    resolver::{NativeResolver, Resolver},
    runtime::DataPlaneRuntime,
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, register_connection,
    },
    util::{allocate_vec, socket::new_socket2_udp_socket_with_buffer_size},
};

const TUIC_VERSION: u8 = 5;
const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
const MAX_HEADER_LEN: usize = 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

const MAX_QUIC_ENDPOINTS: usize = 1;

#[derive(Clone)]
struct TuicConnectionContext {
    identity: Arc<String>,
    inbound_tag: Arc<String>,
    runtime: DataPlaneRuntime,
}

#[derive(Clone)]
struct TuicFlowContext {
    connection: TuicConnectionContext,
    peer_addr: SocketAddr,
}

impl TuicFlowContext {
    fn traffic_context(&self) -> TrafficContext {
        let mut context = TrafficContext::new("tuic")
            .with_identity((*self.connection.identity).clone())
            .with_inbound_tag((*self.connection.inbound_tag).clone())
            .with_client_ip(self.peer_addr.ip());
        self.connection
            .runtime
            .apply_traffic_stats_policy(&mut context);
        context
    }
}

fn spawn_tuic_connection<F>(runtime: &DataPlaneRuntime, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    runtime.spawn_inbound_connection(future);
}

struct TuicConnectionTaskOwnerInner {
    runtime: DataPlaneRuntime,
    tracker: TaskTracker,
    cancellation: CancellationToken,
}

impl Drop for TuicConnectionTaskOwnerInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tracker.close();
    }
}

#[derive(Clone)]
struct TuicConnectionTaskOwner {
    inner: Arc<TuicConnectionTaskOwnerInner>,
}

impl TuicConnectionTaskOwner {
    fn new(runtime: DataPlaneRuntime) -> Self {
        Self {
            inner: Arc::new(TuicConnectionTaskOwnerInner {
                runtime,
                tracker: TaskTracker::new(),
                cancellation: CancellationToken::new(),
            }),
        }
    }

    fn spawn<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancellation = self.inner.cancellation.clone();
        let future = self.inner.tracker.track_future(async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = future => {}
            }
        });
        self.inner.runtime.spawn_inbound_connection(future)
    }

    async fn shutdown(&self) {
        self.inner.tracker.close();
        self.inner.cancellation.cancel();
        self.inner.tracker.wait().await;
    }
}

/// Run a TUIC v5 server bound to the provided address with the given TLS config.
pub async fn run_tuic_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: TuicServerConfig,
    inbound_tag: String,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(std::io::Error::other)?;
    let quic_server_config = Arc::new(quic_server_config);

    let identity = Arc::new(config.uuid.clone());
    let uuid = uuid::Uuid::parse_str(&config.uuid)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?
        .into_bytes();
    let uuid = Arc::new(uuid);
    let password: Arc<str> = Arc::from(config.password);
    let zero_rtt_handshake = config.zero_rtt_handshake;
    let connection_context = TuicConnectionContext {
        identity,
        inbound_tag: Arc::new(inbound_tag),
        runtime,
    };

    let mut endpoint_tasks = tokio::task::JoinSet::new();

    for _ in 0..MAX_QUIC_ENDPOINTS {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let uuid = uuid.clone();
        let password = password.clone();
        let connection_context = connection_context.clone();

        endpoint_tasks.spawn(async move {
            let mut server_config =
                quinn::ServerConfig::with_crypto(quic_server_config);
            let transport =
                Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
                    std::io::Error::other("tuic transport config already shared")
                })?;
            let idle_timeout =
                Duration::from_secs(60).try_into().map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
                })?;

            transport
                .max_concurrent_bidi_streams(4096_u32.into())
                .max_concurrent_uni_streams(4096_u32.into())
                .max_idle_timeout(Some(idle_timeout))
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .send_window(16 * 1024 * 1024)
                .receive_window((20u32 * 1024 * 1024).into())
                .stream_receive_window((8u32 * 1024 * 1024).into())
                // MTU settings per official TUIC reference
                .initial_mtu(1200)
                .min_mtu(1200)
                // Enable MTU discovery for larger packets on capable networks
                .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
                // Enable GSO (Generic Segmentation Offload) for better throughput
                .enable_segmentation_offload(true)
                // Lower initial RTT estimate for faster initial window growth
                .initial_rtt(Duration::from_millis(100));

            // Use 7.5MB socket buffers for high-throughput QUIC (8.625MB on BSD for 15% overhead)
            let socket2_socket = new_socket2_udp_socket_with_buffer_size(
                bind_address.is_ipv6(),
                None,
                Some(bind_address),
                false,
                Some(8_625_000),
            )
            .map_err(std::io::Error::other)?;

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket2_socket.into(),
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(std::io::Error::other)?;

            loop {
                let conn = match crate::beginning::accept_quic_with_health(
                    &endpoint, "tuic",
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(error) => break Err(error),
                };
                let resolver = resolver.clone();
                let uuid = uuid.clone();
                let password = password.clone();
                let connection_context = connection_context.clone();
                let connection_runtime = connection_context.runtime.clone();
                spawn_tuic_connection(&connection_runtime, async move {
                    if let Err(e) = process_connection(
                        resolver,
                        uuid,
                        password,
                        conn,
                        zero_rtt_handshake,
                        connection_context,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        });
    }

    match endpoint_tasks.join_next().await {
        Some(Ok(Ok(()))) => Err(std::io::Error::other(
            "TUIC QUIC endpoint task ended unexpectedly",
        )),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(std::io::Error::other(error)),
        None => Err(std::io::Error::other(
            "TUIC listener started without QUIC endpoint tasks",
        )),
    }
}

async fn process_connection(
    resolver: Arc<dyn Resolver>,
    uuid: Arc<[u8; 16]>,
    password: Arc<str>,
    conn: quinn::Incoming,
    zero_rtt_handshake: bool,
    context: TuicConnectionContext,
) -> std::io::Result<()> {
    let connection = if zero_rtt_handshake {
        let connecting = conn.accept().map_err(std::io::Error::other)?;
        let (connection, _zero_rtt_accepted) = connecting
            .into_0rtt()
            .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
        connection
    } else {
        conn.await.map_err(std::io::Error::other)?
    };

    match timeout(
        AUTH_TIMEOUT,
        auth_connection(&connection, uuid.as_ref(), password.as_ref()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            connection.close(0u32.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(0u32.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    }

    let context = TuicFlowContext {
        connection: context,
        peer_addr: connection.remote_address(),
    };
    let cancel_token = CancellationToken::new();
    let udp_session_map = Arc::new(DashMap::new());
    let child_tasks =
        TuicConnectionTaskOwner::new(context.connection.runtime.clone());

    let heartbeat_loop =
        run_heartbeat_loop(connection.clone(), cancel_token.clone());
    let bi_loop = run_bidirectional_loop(
        connection.clone(),
        resolver.clone(),
        context.clone(),
        child_tasks.clone(),
    );
    let uni_loop = run_unidirectional_loop(
        connection.clone(),
        resolver.clone(),
        udp_session_map.clone(),
        cancel_token.clone(),
        context.clone(),
        child_tasks.clone(),
    );
    let datagram_loop = run_datagram_loop(
        connection.clone(),
        resolver.clone(),
        udp_session_map.clone(),
        cancel_token.clone(),
        context.clone(),
        child_tasks.clone(),
    );

    let result = tokio::try_join!(heartbeat_loop, bi_loop, uni_loop, datagram_loop);

    cancel_token.cancel();

    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(0u32.into(), b"");
    }

    child_tasks.shutdown().await;
    result.map(|_| ())
}

async fn run_heartbeat_loop(
    connection: quinn::Connection,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            _ = interval.tick() => {
                let heartbeat = bytes::Bytes::from_static(&[TUIC_VERSION, COMMAND_TYPE_HEARTBEAT]);
                if let Err(e) = connection.send_datagram(heartbeat) {
                    return Err(std::io::Error::other(format!("heartbeat failed: {e}")));
                }
            }
        }
    }
}

async fn auth_connection(
    connection: &quinn::Connection,
    uuid: &[u8],
    password: &str,
) -> std::io::Result<()> {
    let mut expected_token_bytes = [0u8; 32];
    connection
        .export_keying_material(&mut expected_token_bytes, uuid, password.as_bytes())
        .map_err(|e| {
            std::io::Error::other(format!("Failed to export keying material: {e:?}"))
        })?;

    loop {
        let mut recv_stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(err) => {
                return Err(std::io::Error::other(err));
            }
        };
        let tuic_version = recv_stream.read_u8().await?;
        if tuic_version != TUIC_VERSION {
            return Err(std::io::Error::other(format!(
                "invalid tuic version: {tuic_version}"
            )));
        }
        let command_type = recv_stream.read_u8().await?;

        if command_type != COMMAND_TYPE_AUTHENTICATE {
            debug!(
                "Received command type {command_type} before auth, waiting for auth command"
            );
            continue;
        }

        let mut specified_uuid = [0u8; 16];
        recv_stream
            .read_exact(&mut specified_uuid)
            .await
            .map_err(std::io::Error::other)?;
        if specified_uuid.as_slice() != uuid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("incorrect uuid: {specified_uuid:?}"),
            ));
        }

        let mut token_bytes = [0u8; 32];
        recv_stream
            .read_exact(&mut token_bytes)
            .await
            .map_err(std::io::Error::other)?;
        if token_bytes != expected_token_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "incorrect token",
            ));
        }

        return Ok(());
    }
}

async fn run_bidirectional_loop(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    context: TuicFlowContext,
    child_tasks: TuicConnectionTaskOwner,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let conn = connection.clone();
        let resolver = resolver.clone();
        let context = context.clone();
        if !child_tasks.spawn(async move {
            match process_tcp_stream(resolver, send_stream, recv_stream, context)
                .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    error!(
                        "Error parsing TCP stream header, closing connection: {e}"
                    );
                    conn.close(0u32.into(), b"");
                }
                Err(e) => {
                    error!("Error processing TCP stream: {e}");
                }
            }
        }) {
            return Ok(());
        }
    }
    Ok(())
}

async fn process_tcp_stream(
    resolver: Arc<dyn Resolver>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    context: TuicFlowContext,
) -> std::io::Result<()> {
    let tuic_version = recv.read_u8().await?;
    if tuic_version != TUIC_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tuic version: {tuic_version}"),
        ));
    }
    let command_type = recv.read_u8().await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid command type: {command_type}"),
        ));
    }

    let remote_location = read_address(&mut recv).await?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address")
    })?;

    let connect_future = timeout(
        Duration::from_secs(60),
        connect_tcp_outbound(
            &resolver,
            &remote_location,
            &context.connection.runtime,
            context.connection.inbound_tag.as_str(),
            context.connection.identity.as_str(),
            context.peer_addr,
        ),
    );

    let connection = match connect_future.await {
        Ok(Ok(Some(connection))) => connection,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to connect to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    let mut context = context.traffic_context();
    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }
    let _connection_guard = register_connection(Some(&context));

    let mut server_stream = MeteredStream::new(
        QuicStream::from((send, recv)),
        Some(context.clone()),
        TrafficDirection::Upload,
    );
    let mut client_stream = MeteredStream::new(
        connection.stream,
        Some(context),
        TrafficDirection::Download,
    );
    let copy_result =
        tokio::io::copy_bidirectional(&mut server_stream, &mut client_stream).await;

    let _ = server_stream.shutdown().await;
    let _ = client_stream.shutdown().await;

    match copy_result {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

async fn read_address(
    recv: &mut quinn::RecvStream,
) -> std::io::Result<Option<NetLocation>> {
    let address_type = recv.read_u8().await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = recv.read_u8().await? as usize;
            let mut address_bytes = allocate_vec(address_len);
            recv.read_exact(&mut address_bytes)
                .await
                .map_err(std::io::Error::other)?;
            let address_str = std::str::from_utf8(&address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            Address::from(address_str).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        }
        0x01 => {
            let mut ipv4_bytes = [0u8; 4];
            recv.read_exact(&mut ipv4_bytes)
                .await
                .map_err(std::io::Error::other)?;
            Address::Ipv4(Ipv4Addr::new(
                ipv4_bytes[0],
                ipv4_bytes[1],
                ipv4_bytes[2],
                ipv4_bytes[3],
            ))
        }
        0x02 => {
            let mut ipv6_bytes = [0u8; 16];
            recv.read_exact(&mut ipv6_bytes)
                .await
                .map_err(std::io::Error::other)?;
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {address_type}"),
            ));
        }
    };

    let mut port_bytes = [0u8; 2];
    recv.read_exact(&mut port_bytes)
        .await
        .map_err(std::io::Error::other)?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(Some(NetLocation::new(address, port)))
}

fn serialize_address(location: &NetLocation) -> Vec<u8> {
    let mut address_bytes = match location.address() {
        Address::Hostname(hostname) => {
            let mut res = Vec::with_capacity(1 + 1 + hostname.len() + 2);
            res.push(0x00);
            let hostname_bytes = hostname.as_bytes();
            res.push(hostname_bytes.len() as u8);
            res.extend_from_slice(hostname_bytes);
            res
        }
        Address::Ipv4(ipv4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01);
            res.extend_from_slice(&ipv4.octets());
            res
        }
        Address::Ipv6(ipv6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02);
            res.extend_from_slice(&ipv6.octets());
            res
        }
    };

    address_bytes.extend_from_slice(&location.port().to_be_bytes());

    address_bytes
}

mod udp;
use dashmap::DashMap;
#[cfg(test)]
use udp::{UdpSession, forward_udp_payload, serialize_socket_addr};
use udp::{run_datagram_loop, run_unidirectional_loop};

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl From<(quinn::SendStream, quinn::RecvStream)> for QuicStream {
    fn from((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod e2e_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    use crate::{
        runtime::{OutboundSummary, RuntimeState},
        traffic::{register_connection, snapshot},
    };

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    async fn wait_for_no_tracked_connection_tasks(runtime: &RuntimeState) {
        timeout(Duration::from_secs(1), async {
            while runtime.tracked_inbound_connection_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("TUIC child task should leave the server owner");
    }

    #[tokio::test]
    async fn tuic_connection_task_uses_server_owner() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        spawn_tuic_connection(&runtime.data_plane(), async move {
            let _ = release_rx.await;
        });
        for _ in 0..50 {
            if runtime.tracked_inbound_connection_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.tracked_inbound_connection_count(), 1);

        release_tx
            .send(())
            .expect("release tracked TUIC connection");
        for _ in 0..50 {
            if runtime.tracked_inbound_connection_count() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("completed TUIC connection should leave server owner");
    }

    #[tokio::test]
    async fn tuic_child_task_shutdown_cancels_and_waits() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let child_tasks = TuicConnectionTaskOwner::new(runtime.data_plane());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();

        assert!(child_tasks.spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        started_rx.await.expect("TUIC child task should start");
        assert_eq!(runtime.tracked_inbound_connection_count(), 1);

        child_tasks.shutdown().await;
        timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("TUIC child task should be cancelled")
            .expect("TUIC child task drop signal should be sent");
        wait_for_no_tracked_connection_tasks(&runtime).await;
    }

    #[tokio::test]
    async fn dropping_tuic_child_owner_cancels_server_owned_task() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let child_tasks = TuicConnectionTaskOwner::new(runtime.data_plane());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();

        assert!(child_tasks.spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        started_rx.await.expect("TUIC child task should start");
        assert_eq!(runtime.tracked_inbound_connection_count(), 1);

        drop(child_tasks);
        timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("dropping TUIC child owner should cancel the task")
            .expect("TUIC child task drop signal should be sent");
        wait_for_no_tracked_connection_tasks(&runtime).await;
    }

    #[test]
    fn traffic_context_applies_level_zero_and_system_stats_policy() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let mut levels = std::collections::HashMap::new();
        levels.insert(
            0,
            Some(crate::config::def::PolicyLevelConfig {
                stats_user_uplink: false,
                stats_user_downlink: true,
                stats_user_online: false,
                ..crate::config::def::PolicyLevelConfig::default()
            }),
        );
        runtime.replace_policy(Some(&crate::config::def::PolicyConfig {
            levels,
            system: Some(crate::config::def::SystemPolicyConfig {
                stats_inbound_uplink: true,
                stats_inbound_downlink: false,
                stats_outbound_uplink: false,
                stats_outbound_downlink: true,
            }),
        }));
        let context = TuicFlowContext {
            connection: TuicConnectionContext {
                identity: Arc::new("tuic-policy-user".into()),
                inbound_tag: Arc::new("tuic-policy-in".into()),
                runtime: runtime.data_plane(),
            },
            peer_addr: "127.0.0.1:12345".parse().unwrap(),
        }
        .traffic_context();

        assert_eq!(context.user_level, 0);
        assert_eq!(context.stats_user_uplink, Some(false));
        assert_eq!(context.stats_user_downlink, Some(true));
        assert_eq!(context.stats_user_online, Some(false));
        assert_eq!(context.stats_inbound_uplink, Some(true));
        assert_eq!(context.stats_inbound_downlink, Some(false));
        assert_eq!(context.stats_outbound_uplink, Some(false));
        assert_eq!(context.stats_outbound_downlink, Some(true));
    }

    #[test]
    fn serialize_address_hostname() {
        let location = NetLocation::new(Address::from("example.com").unwrap(), 443);
        let bytes = serialize_address(&location);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1] as usize, "example.com".len());
        assert_eq!(&bytes[2..2 + "example.com".len()], "example.com".as_bytes());
        let port_offset = 2 + "example.com".len();
        assert_eq!(&bytes[port_offset..port_offset + 2], &443u16.to_be_bytes());
    }

    #[test]
    fn serialize_address_ipv4() {
        let location =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let bytes = serialize_address(&location);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], &[1, 2, 3, 4]);
        assert_eq!(&bytes[5..7], &8080u16.to_be_bytes());
    }

    #[tokio::test]
    async fn udp_forward_uses_selected_outbound_and_records_upload() {
        let outbound_tag = "tuic-udp-test-direct";
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
        runtime.replace_policy(Some(&crate::config::def::PolicyConfig {
            levels: std::collections::HashMap::from([(
                0,
                Some(crate::config::def::PolicyLevelConfig {
                    stats_user_uplink: true,
                    stats_user_downlink: true,
                    stats_user_online: true,
                    ..crate::config::def::PolicyLevelConfig::default()
                }),
            )]),
            system: Some(crate::config::def::SystemPolicyConfig {
                stats_inbound_uplink: true,
                stats_inbound_downlink: true,
                stats_outbound_uplink: true,
                stats_outbound_downlink: true,
            }),
        }));
        let context = TuicFlowContext {
            connection: TuicConnectionContext {
                identity: Arc::new("tuic-test-user".into()),
                inbound_tag: Arc::new("tuic-test-in".into()),
                runtime: runtime.data_plane(),
            },
            peer_addr: "127.0.0.1:12345".parse().unwrap(),
        };
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let location = NetLocation::from_ip_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            target_addr.port(),
        );
        let base_context = context.traffic_context();
        let connection_guard = register_connection(Some(&base_context));
        let session = UdpSession {
            send_socket: Arc::new(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
            ),
            last_location: location.clone(),
            last_socket_addr: target_addr,
            last_activity: std::time::Instant::now(),
            cancel_token: CancellationToken::new(),
            base_context,
            response_contexts: Arc::new(DashMap::new()),
            _connection_guard: connection_guard,
        };
        let before = snapshot()
            .per_outbound
            .get(outbound_tag)
            .map(|totals| totals.upload_bytes)
            .unwrap_or_default();
        let payload = b"tuic UDP accounting";

        assert!(
            forward_udp_payload(
                &session,
                &context,
                7,
                &location,
                target_addr,
                payload,
            )
            .await
            .unwrap()
        );

        let mut received = [0u8; 64];
        let (len, _) =
            timeout(Duration::from_secs(1), target.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..len], payload);
        let response_context = session.response_contexts.get(&target_addr).unwrap();
        assert_eq!(response_context.outbound_tag.as_deref(), Some(outbound_tag));
        let after = snapshot().per_outbound[outbound_tag].upload_bytes;
        assert_eq!(after - before, payload.len() as u64);
    }
}
