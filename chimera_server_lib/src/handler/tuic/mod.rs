#![cfg(feature = "tuic")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use lru::LruCache;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::{
    address::{Address, NetLocation},
    config::server_config::TuicServerConfig,
    resolver::{resolve_single_address, NativeResolver, Resolver},
    traffic::{record_transfer, register_connection, TrafficContext},
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

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

const MAX_QUIC_ENDPOINTS: usize = 1;

type UdpSessionMap = Arc<DashMap<u16, UdpSession>>;

fn fragment_cache_size() -> NonZeroUsize {
    // MAX_FRAGMENT_CACHE_SIZE is a positive constant; fall back to 1 if changed.
    NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE)
        .unwrap_or_else(|| NonZeroUsize::new(1).expect("non-zero"))
}

/// Run a TUIC v5 server bound to the provided address with the given TLS config.
pub async fn run_tuic_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: TuicServerConfig,
    inbound_tag: String,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let quic_server_config = Arc::new(quic_server_config);

    let identity = Arc::new(config.uuid.clone());
    let uuid = uuid::Uuid::parse_str(&config.uuid)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?
        .into_bytes();
    let uuid = Arc::new(uuid);
    let password: Arc<str> = Arc::from(config.password);
    let zero_rtt_handshake = config.zero_rtt_handshake;
    let inbound_tag = Arc::new(inbound_tag);

    let mut join_handles = Vec::with_capacity(MAX_QUIC_ENDPOINTS);

    for _ in 0..MAX_QUIC_ENDPOINTS {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let uuid = uuid.clone();
        let identity = identity.clone();
        let password = password.clone();
        let inbound_tag = inbound_tag.clone();

        let join_handle = tokio::spawn(async move {
            let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);
            let transport = Arc::get_mut(&mut server_config.transport)
                .ok_or_else(|| std::io::Error::other("tuic transport config already shared"))?;
            let idle_timeout = Duration::from_secs(60)
                .try_into()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

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

            while let Some(conn) = endpoint.accept().await {
                let resolver = resolver.clone();
                let uuid = uuid.clone();
                let identity = identity.clone();
                let password = password.clone();
                let inbound_tag = inbound_tag.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        resolver,
                        uuid,
                        password,
                        conn,
                        zero_rtt_handshake,
                        identity,
                        inbound_tag,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }

            Ok::<(), std::io::Error>(())
        });

        join_handles.push(join_handle);
    }

    for join_handle in join_handles {
        join_handle
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))??;
    }

    Ok(())
}

async fn process_connection(
    resolver: Arc<dyn Resolver>,
    uuid: Arc<[u8; 16]>,
    password: Arc<str>,
    conn: quinn::Incoming,
    zero_rtt_handshake: bool,
    identity: Arc<String>,
    inbound_tag: Arc<String>,
) -> std::io::Result<()> {
    let connection = if zero_rtt_handshake {
        let connecting = conn.accept().map_err(std::io::Error::other)?;
        let (connection, _zero_rtt_accepted) = connecting
            .into_0rtt()
            .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
        connection
    } else {
        conn.await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
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

    let cancel_token = CancellationToken::new();
    let udp_session_map = Arc::new(DashMap::new());

    let heartbeat_loop = run_heartbeat_loop(connection.clone(), cancel_token.clone());
    let bi_loop = run_bidirectional_loop(
        connection.clone(),
        resolver.clone(),
        identity.clone(),
        inbound_tag.clone(),
    );
    let uni_loop = run_unidirectional_loop(
        connection.clone(),
        resolver.clone(),
        udp_session_map.clone(),
        cancel_token.clone(),
    );
    let datagram_loop = run_datagram_loop(
        connection.clone(),
        resolver.clone(),
        udp_session_map.clone(),
        cancel_token.clone(),
    );

    let result = tokio::try_join!(heartbeat_loop, bi_loop, uni_loop, datagram_loop);

    cancel_token.cancel();

    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(0u32.into(), b"");
    }

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
        .map_err(|e| std::io::Error::other(format!("Failed to export keying material: {e:?}")))?;

    loop {
        let mut recv_stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(err) => {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
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
            debug!("Received command type {command_type} before auth, waiting for auth command");
            continue;
        }

        let mut specified_uuid = [0u8; 16];
        recv_stream
            .read_exact(&mut specified_uuid)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
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
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
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
    identity: Arc<String>,
    inbound_tag: Arc<String>,
) -> std::io::Result<()> {
    let peer_ip = connection.remote_address().ip();
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
        let identity = identity.clone();
        let inbound_tag = inbound_tag.clone();
        tokio::spawn(async move {
            match process_tcp_stream(
                resolver,
                send_stream,
                recv_stream,
                identity,
                inbound_tag,
                peer_ip,
            )
            .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    error!("Error parsing TCP stream header, closing connection: {e}");
                    conn.close(0u32.into(), b"");
                }
                Err(e) => {
                    error!("Error processing TCP stream: {e}");
                }
            }
        });
    }
    Ok(())
}

async fn process_tcp_stream(
    resolver: Arc<dyn Resolver>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    identity: Arc<String>,
    inbound_tag: Arc<String>,
    peer_ip: std::net::IpAddr,
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

    let remote_location = read_address(&mut recv)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address"))?;

    let connect_future = timeout(
        Duration::from_secs(60),
        connect_tcp_remote(resolver.clone(), remote_location.clone()),
    );

    let mut client_stream = match connect_future.await {
        Ok(Ok(s)) => s,
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

    let context = TrafficContext::new("tuic")
        .with_identity((*identity).clone())
        .with_inbound_tag((*inbound_tag).clone())
        .with_client_ip(peer_ip);
    let _connection_guard = register_connection(Some(&context));

    let mut server_stream = QuicStream::from((send, recv));
    let copy_result = tokio::io::copy_bidirectional(&mut server_stream, &mut client_stream).await;

    let _ = server_stream.shutdown().await;
    let _ = client_stream.shutdown().await;

    match copy_result {
        Ok((client_to_server, server_to_client)) => {
            record_transfer(Some(context), client_to_server, server_to_client);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn connect_tcp_remote(
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<tokio::net::TcpStream> {
    let target_addr = resolve_single_address(&resolver, &remote_location).await?;
    let tcp_socket = crate::util::socket::new_tcp_socket(None, target_addr.is_ipv6())?;
    let client_stream = tcp_socket.connect(target_addr).await?;
    if let Err(e) = client_stream.set_nodelay(true) {
        warn!("Failed to set TCP no-delay on client socket: {}", e);
    }
    Ok(client_stream)
}

async fn read_address(recv: &mut quinn::RecvStream) -> std::io::Result<Option<NetLocation>> {
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
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            let address_str = std::str::from_utf8(&address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            Address::from(address_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        }
        0x01 => {
            let mut ipv4_bytes = [0u8; 4];
            recv.read_exact(&mut ipv4_bytes)
                .await
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
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
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
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
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
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

fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut res = match addr {
        SocketAddr::V4(addr_v4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01);
            res.extend_from_slice(&addr_v4.ip().octets());
            res
        }
        SocketAddr::V6(addr_v6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02);
            res.extend_from_slice(&addr_v6.ip().octets());
            res
        }
    };

    res.extend_from_slice(&addr.port().to_be_bytes());

    res
}

struct UdpSession {
    send_socket: Arc<UdpSocket>,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
}

impl UdpSession {
    fn start_with_send_stream(
        assoc_id: u16,
        send_stream: quinn::SendStream,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_stream_loop(
                assoc_id,
                send_stream,
                client_socket,
                session_cancel_token,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }

    fn start_with_datagram(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_datagram_loop(
                assoc_id,
                connection,
                client_socket,
                session_cancel_token,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }

    async fn resolve_address(
        &self,
        location: &NetLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(SocketAddr, bool)> {
        if location == &self.last_location {
            Ok((self.last_socket_addr, false))
        } else {
            let updated_address = resolve_single_address(resolver, location).await?;
            Ok((updated_address, true))
        }
    }

    fn update_last_location(&mut self, location: NetLocation, socket_addr: SocketAddr) {
        self.last_location = location;
        self.last_socket_addr = socket_addr;
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    mut send_stream: quinn::SendStream,
    socket: Arc<UdpSocket>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(MAX_HEADER_LEN + 65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf[MAX_HEADER_LEN..]) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let address_bytes = serialize_socket_addr(&src_addr);
        let address_bytes_len = address_bytes.len();

        // assoc_id(2) + packet_id(2) + fragment total(1) + fragment id(1) + payload size (2)
        // + address bytes
        let header_len = 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        let start_offset = MAX_HEADER_LEN - header_len;
        let end_offset = MAX_HEADER_LEN + payload_len;

        buf[start_offset] = (assoc_id >> 8) as u8;
        buf[start_offset + 1] = assoc_id as u8;
        buf[start_offset + 2] = (packet_id >> 8) as u8;
        buf[start_offset + 3] = packet_id as u8;
        buf[start_offset + 4] = 1;
        buf[start_offset + 5] = 0;
        buf[start_offset + 6] = (payload_len >> 8) as u8;
        buf[start_offset + 7] = payload_len as u8;
        buf[start_offset + 8..start_offset + 8 + address_bytes_len].copy_from_slice(&address_bytes);

        let mut i = start_offset;
        while i < end_offset {
            let count = send_stream
                .write(&buf[i..end_offset])
                .await
                .map_err(std::io::Error::other)?;
            i += count;
        }
    }
}

async fn run_udp_remote_to_local_datagram_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    client_socket: Arc<UdpSocket>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match client_socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = client_socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let address_bytes = serialize_socket_addr(&src_addr);
        let address_bytes_len = address_bytes.len();

        // tuic_version (1) + command (1) + assoc_id (2) + packet_id (2)
        // + frag_total (1) + frag_id (1) + payload_size (2) + address bytes
        let header_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.put_u8(TUIC_VERSION);
            datagram.put_u8(COMMAND_TYPE_PACKET);
            datagram.extend_from_slice(&assoc_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.put_u8(1);
            datagram.put_u8(0);
            datagram.extend_from_slice(&(payload_len as u16).to_be_bytes());
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            let first_overhead = header_overhead;
            let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1;
            let first_capacity = max_datagram_size - first_overhead;
            let other_capacity = max_datagram_size - other_overhead;

            let remaining = payload_len.saturating_sub(first_capacity);
            let additional_fragments = remaining.div_ceil(other_capacity);
            let fragment_count = 1 + additional_fragments;

            let mut offset = 0;
            for fragment_id in 0..fragment_count {
                let (fragment_payload_len, header_size) = if fragment_id == 0 {
                    let len = std::cmp::min(first_capacity, payload_len);
                    (len, first_overhead)
                } else {
                    let len = std::cmp::min(other_capacity, payload_len - offset);
                    (len, other_overhead)
                };

                let mut datagram = BytesMut::with_capacity(header_size + fragment_payload_len);
                datagram.extend_from_slice(&[TUIC_VERSION, COMMAND_TYPE_PACKET]);
                datagram.extend_from_slice(&assoc_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_count as u8, fragment_id as u8]);
                datagram.extend_from_slice(&(fragment_payload_len as u16).to_be_bytes());
                if fragment_id == 0 {
                    datagram.extend_from_slice(&address_bytes);
                } else {
                    datagram.put_u8(0xff);
                }
                datagram.extend_from_slice(&buf[offset..offset + fragment_payload_len]);
                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
                offset += fragment_payload_len;
            }
        }
    }
}

async fn run_unidirectional_loop(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let cleanup_session_map = udp_session_map.clone();
    let cleanup_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    cleanup_session_map.retain(|assoc_id, session| {
                        if session.last_activity.elapsed() > IDLE_TIMEOUT {
                            session.cancel_token.cancel();
                            debug!("Removing inactive UDP session {assoc_id}");
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
    });

    loop {
        let recv_stream = match connection.accept_uni().await {
            Ok(recv_stream) => recv_stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept unidirectional stream: {e}"
                )));
            }
        };

        let connection = connection.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        let cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            match process_uni_stream(
                &connection,
                resolver,
                recv_stream,
                udp_session_map,
                cancel_token,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!("Error processing uni stream, closing connection: {e}");
                    connection.close(0u32.into(), b"");
                }
            }
        });
    }
    Ok(())
}

async fn process_uni_stream(
    connection: &quinn::Connection,
    resolver: Arc<dyn Resolver>,
    mut recv_stream: quinn::RecvStream,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let tuic_version = recv_stream.read_u8().await?;
    if tuic_version != TUIC_VERSION {
        return Err(std::io::Error::other(format!(
            "invalid tuic version: {tuic_version}"
        )));
    }
    let command_type = recv_stream.read_u8().await?;

    if command_type == COMMAND_TYPE_DISSOCIATE {
        let assoc_id = recv_stream.read_u16().await?;
        if let Some((_, session)) = udp_session_map.remove(&assoc_id) {
            session.cancel_token.cancel();
        }
        return Ok(());
    }

    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "invalid uni stream command type: {command_type}"
        )));
    }

    let assoc_id = recv_stream.read_u16().await?;
    let packet_id = recv_stream.read_u16().await?;
    let frag_total = recv_stream.read_u8().await?;
    let frag_id = recv_stream.read_u8().await?;
    let payload_size = recv_stream.read_u16().await? as usize;
    let remote_location = read_address(&mut recv_stream).await?;

    let mut payload_fragment = allocate_vec(payload_size);
    recv_stream
        .read_exact(&mut payload_fragment)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let mut fragments: LruCache<u16, FragmentedPacket> = LruCache::new(fragment_cache_size());

    process_udp_packet(
        connection,
        &resolver,
        &udp_session_map,
        &mut fragments,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        &payload_fragment,
        true,
        &cancel_token,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn process_udp_packet(
    connection: &quinn::Connection,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    fragments: &mut LruCache<u16, FragmentedPacket>,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    if frag_total == 0 {
        return Err(std::io::Error::other(
            "ignoring packet with empty fragment total",
        ));
    }

    if frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "invalid fragment id {frag_id} >= total {frag_total}"
        )));
    }

    let session = match udp_session_map.get(&assoc_id) {
        Some(s) => s,
        None => {
            if remote_location.is_none() {
                return Err(std::io::Error::other(
                    "ignoring packet with unknown session and empty address",
                ));
            }

            let remote_location = remote_location
                .clone()
                .ok_or_else(|| std::io::Error::other("missing initial address"))?;
            let resolved_address = resolve_single_address(resolver, &remote_location).await?;

            let bind_addr: SocketAddr = if resolved_address.is_ipv6() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            let socket = new_udp_socket(bind_addr, None)?;

            let session = if is_uni_stream {
                let send_stream = connection
                    .open_uni()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                UdpSession::start_with_send_stream(
                    assoc_id,
                    send_stream,
                    Arc::new(socket),
                    remote_location,
                    resolved_address,
                    cancel_token,
                )
            } else {
                UdpSession::start_with_datagram(
                    assoc_id,
                    connection.clone(),
                    Arc::new(socket),
                    remote_location,
                    resolved_address,
                    cancel_token,
                )
            };

            udp_session_map.insert(assoc_id, session);
            udp_session_map
                .get(&assoc_id)
                .expect("udp session should exist")
        }
    };

    if frag_total == 1 {
        let remote_location = remote_location.as_ref().ok_or_else(|| {
            std::io::Error::other("ignoring packet with single fragment and no address")
        })?;

        let (socket_addr, is_updated) = session.resolve_address(remote_location, resolver).await?;

        if let Err(e) = session
            .send_socket
            .send_to(payload_fragment, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {assoc_id}: {e}");
            drop(session);
            udp_session_map.remove(&assoc_id);
            return Ok(());
        }

        drop(session);
        if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
            session.last_activity = std::time::Instant::now();
            if is_updated {
                session.update_last_location(remote_location.clone(), socket_addr);
            }
        }
    } else {
        let is_new = !fragments.contains(&packet_id);

        if is_new {
            fragments.put(
                packet_id,
                FragmentedPacket {
                    fragment_count: frag_total,
                    fragment_received: 0,
                    packet_len: 0,
                    received: vec![None; frag_total as usize],
                    remote_location: remote_location.clone(),
                },
            );
        }

        let packet = match fragments.get_mut(&packet_id) {
            Some(p) => p,
            None => {
                return Err(std::io::Error::other("fragment cache error"));
            }
        };

        if is_new && frag_id == 0 && packet.remote_location.is_none() {
            if remote_location.is_none() {
                fragments.pop(&packet_id);
                return Err(std::io::Error::other(format!(
                    "ignoring packet with empty first fragment address for session {assoc_id}"
                )));
            }
            packet.remote_location = remote_location.clone();
        }

        if packet.fragment_count != frag_total {
            fragments.pop(&packet_id);
            return Err(std::io::Error::other(format!(
                "mismatched fragment count for session {assoc_id} packet {packet_id}"
            )));
        }
        if packet.received[frag_id as usize].is_some() {
            fragments.pop(&packet_id);
            return Err(std::io::Error::other(format!(
                "duplicate fragment for session {assoc_id} packet {packet_id}"
            )));
        }

        packet.fragment_received += 1;
        packet.packet_len += payload_fragment.len();
        packet.received[frag_id as usize] = Some(payload_fragment.to_vec().into());

        if packet.fragment_received != packet.fragment_count {
            return Ok(());
        }

        let FragmentedPacket {
            remote_location,
            received,
            packet_len,
            ..
        } = fragments
            .pop(&packet_id)
            .ok_or_else(|| std::io::Error::other("fragment cache missing"))?;

        let remote_location =
            remote_location.ok_or_else(|| std::io::Error::other("missing fragment address"))?;

        let (socket_addr, is_updated) = session.resolve_address(&remote_location, resolver).await?;

        let mut complete_payload = Vec::with_capacity(packet_len);
        for frag in received.iter() {
            match frag.as_ref() {
                Some(bytes) => complete_payload.extend_from_slice(bytes),
                None => {
                    return Err(std::io::Error::other(
                        "missing fragment while assembling payload",
                    ));
                }
            }
        }

        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {assoc_id}: {e}");
            drop(session);
            udp_session_map.remove(&assoc_id);
            return Ok(());
        }

        drop(session);
        if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
            session.last_activity = std::time::Instant::now();
            if is_updated {
                session.update_last_location(remote_location.clone(), socket_addr);
            }
        }
    }

    Ok(())
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut fragments: LruCache<u16, FragmentedPacket> = LruCache::new(fragment_cache_size());
    let mut last_cleanup = std::time::Instant::now();

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            udp_session_map.retain(|assoc_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {assoc_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        if data.len() < 2 {
            return Err(std::io::Error::other("invalid message: too short"));
        }

        let tuic_version = data[0];
        if tuic_version != TUIC_VERSION {
            return Err(std::io::Error::other(format!(
                "unknown version: {tuic_version}"
            )));
        }

        let command_type = data[1];
        if command_type == COMMAND_TYPE_HEARTBEAT {
            continue;
        } else if command_type != COMMAND_TYPE_PACKET {
            return Err(std::io::Error::other(format!(
                "unknown command: {command_type}"
            )));
        }

        let data_len = data.len();
        if data_len < 11 {
            return Err(std::io::Error::other("decode UDP message: too short"));
        }

        let assoc_id = u16::from_be_bytes([data[2], data[3]]);
        let packet_id = u16::from_be_bytes([data[4], data[5]]);
        let frag_total = data[6];
        let frag_id = data[7];
        let payload_size = u16::from_be_bytes([data[8], data[9]]) as usize;

        let address_type = data[10];

        let (remote_location, offset) = match address_type {
            0xff => (None, 11),
            0x00 => {
                if data_len < 14 {
                    return Err(std::io::Error::other(
                        "decode UDP message: hostname too short",
                    ));
                }
                let address_len = data[11] as usize;
                if data_len < 12 + address_len + 2 + payload_size {
                    return Err(std::io::Error::other(
                        "decode UDP message: truncated hostname",
                    ));
                }
                let address_bytes = &data[12..12 + address_len];
                let address_str = std::str::from_utf8(address_bytes).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid UTF-8: {e}"))
                })?;
                let address = Address::from(address_str).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid address: {e}"))
                })?;
                let port = u16::from_be_bytes([data[12 + address_len], data[12 + address_len + 1]]);
                (Some(NetLocation::new(address, port)), 12 + address_len + 2)
            }
            0x01 => {
                if data_len < 17 + payload_size {
                    return Err(std::io::Error::other("decode UDP message: IPv4 too short"));
                }
                let ipv4_addr = Ipv4Addr::new(data[11], data[12], data[13], data[14]);
                let port = u16::from_be_bytes([data[15], data[16]]);
                (Some(NetLocation::new(Address::Ipv4(ipv4_addr), port)), 17)
            }
            0x02 => {
                if data_len < 29 + payload_size {
                    return Err(std::io::Error::other("decode UDP message: IPv6 too short"));
                }
                let ipv6_bytes: [u8; 16] = data[11..27]
                    .try_into()
                    .map_err(|_| std::io::Error::other("decode UDP message: invalid IPv6 bytes"))?;
                let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([data[27], data[28]]);
                (Some(NetLocation::new(Address::Ipv6(ipv6_addr), port)), 29)
            }
            _ => {
                return Err(std::io::Error::other(format!(
                    "decode UDP message: invalid address type: {address_type}"
                )));
            }
        };

        if data_len < offset + payload_size {
            return Err(std::io::Error::other(
                "decode UDP message: truncated payload",
            ));
        }
        let payload_fragment = &data[offset..offset + payload_size];

        if let Err(e) = process_udp_packet(
            &connection,
            &resolver,
            &udp_session_map,
            &mut fragments,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
            false,
            &cancel_token,
        )
        .await
        {
            error!("Failed to process datagram UDP packet: {e}");
        }
    }
}

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
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_flush(cx)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_shutdown(cx)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
    }
}

fn new_udp_socket(
    bind_address: SocketAddr,
    buffer_size: Option<usize>,
) -> std::io::Result<UdpSocket> {
    let socket2_socket = new_socket2_udp_socket_with_buffer_size(
        bind_address.is_ipv6(),
        None,
        Some(bind_address),
        false,
        buffer_size,
    )?;
    let std_socket: std::net::UdpSocket = socket2_socket.into();
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let bytes = serialize_address(&location);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], &[1, 2, 3, 4]);
        assert_eq!(&bytes[5..7], &8080u16.to_be_bytes());
    }
}
