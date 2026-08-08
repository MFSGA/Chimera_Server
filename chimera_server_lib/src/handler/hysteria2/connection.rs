use std::{
    collections::{HashMap, hash_map::Entry},
    convert::TryFrom,
    io::{Error, ErrorKind},
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use h3_quinn::BidiStream;
use http::{Request, Response, StatusCode};
use lru::LruCache;
use rand::{
    RngExt,
    // distributions::{Alphanumeric, DistString},
    distr::{Alphanumeric, SampleString},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

#[cfg(feature = "user_domain_access")]
use crate::user_domain_access::hysteria2_password_identity;
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::server_config::{
        Hysteria2Client, Hysteria2MasqueradeConfig, Hysteria2ServerConfig,
    },
    outbound::{
        DirectOutboundAction, UdpProxyAssociationRegistry, connect_tcp_outbound,
        connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{
        AccessTransport, ConnectionGuard, MeteredStream, TrafficContext,
        TrafficDirection, record_transfer, register_connection,
    },
};

const AUTH_PATH: &str = "/auth";
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const CLOSE_ERR_CODE_OK: u32 = 0x100;
const AUTH_HEADER: &str = "Hysteria-Auth";
const CLIENT_CC_RX_HEADER: &str = "Hysteria-CC-RX";
const UDP_SUPPORT_HEADER: &str = "Hysteria-UDP";
const PADDING_HEADER: &str = "Hysteria-Padding";
const SUCCESS_STATUS: u16 = 233;
const TCP_REQUEST_ID: u64 = 0x401;
const MAX_ADDRESS_LEN: usize = 2048;
const PADDING_SCRATCH_LEN: usize = 1024;
const TCP_SUCCESS_STATUS: u8 = 0x00;
const DEFAULT_UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
const TCP_ERROR_STATUS: u8 = 0x01;

fn hysteria2_routing_identity(client: &Hysteria2Client) -> String {
    client
        .email
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            #[cfg(feature = "user_domain_access")]
            {
                hysteria2_password_identity(&client.password)
            }
            #[cfg(not(feature = "user_domain_access"))]
            {
                client.password.clone()
            }
        })
}

fn hysteria2_traffic_context(
    client: &Hysteria2Client,
    inbound_tag: &str,
    peer_addr: SocketAddr,
) -> TrafficContext {
    #[allow(unused_mut)]
    let mut context = TrafficContext::new("hysteria2")
        .with_identity(hysteria2_routing_identity(client))
        .with_user_level(client.user_level)
        .with_inbound_tag(inbound_tag.to_string())
        .with_client_ip(peer_addr.ip());
    #[cfg(feature = "user_domain_access")]
    {
        context = context
            .with_protocol_identity(hysteria2_password_identity(&client.password));
    }
    context
}

fn apply_hysteria2_policy(
    mut context: TrafficContext,
    runtime: &RuntimeState,
) -> TrafficContext {
    let user_stats = runtime.policy_user_stats(context.user_level);
    let system_stats = runtime.policy_system_stats();
    context.set_user_stats_policy(
        user_stats.uplink,
        user_stats.downlink,
        user_stats.online,
    );
    context.set_system_stats_policy(
        system_stats.inbound_uplink,
        system_stats.inbound_downlink,
        system_stats.outbound_uplink,
        system_stats.outbound_downlink,
    );
    context
}

#[derive(Clone)]
struct AuthContext {
    client: Hysteria2Client,
    udp_enabled: bool,
}

struct AuthInfo {
    client: Hysteria2Client,
    client_rx_limit: Option<u64>,
    udp_enabled: bool,
}

pub async fn process_hysteria2_connection(
    resolver: Arc<dyn Resolver>,
    config: Arc<Hysteria2ServerConfig>,
    tx_bps: Arc<AtomicU64>,
    connection: quinn::Connection,
    inbound_tag: Arc<String>,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn = h3::server::Connection::new(h3_quinn_connection)
        .await
        .map_err(|err| {
            Error::other(format!("hysteria2 H3 driver creation failed: {err}"))
        })?;
    debug!("hysteria2 QUIC established");
    debug!("hysteria2 H3 driver created");

    let udp_idle_timeout = if config.udp_idle_timeout == 0 {
        DEFAULT_UDP_SESSION_IDLE_TIMEOUT
    } else {
        Duration::from_secs(config.udp_idle_timeout)
    };

    let auth_ctx = match tokio::time::timeout(
        AUTH_TIMEOUT,
        auth_hysteria2_connection(&mut h3_conn, config.as_ref(), tx_bps.clone()),
    )
    .await
    {
        Ok(Ok(auth_ctx)) => auth_ctx,
        Ok(Err(err)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(Error::new(
                err.kind(),
                format!("hysteria2 authentication failed: {err}"),
            ));
        }
        Err(_) => {
            warn!("hysteria2 authentication timed out");
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(Error::new(
                ErrorKind::TimedOut,
                "hysteria2 authentication timeout",
            ));
        }
    };

    // Keep the H3 driver alive because dropping it closes the underlying QUIC
    // connection. Do not poll it after authentication: Hysteria2 TCP requests
    // are raw QUIC bidi streams and would otherwise race with h3_conn.accept().
    let _h3_conn = h3_conn;

    let result = if auth_ctx.udp_enabled {
        tokio::try_join!(
            drive_tcp_streams(
                connection.clone(),
                resolver.clone(),
                &auth_ctx,
                inbound_tag.clone(),
                runtime.clone(),
            ),
            drive_udp_datagrams(
                connection.clone(),
                resolver.clone(),
                &auth_ctx,
                inbound_tag,
                udp_idle_timeout,
                runtime,
            ),
            drain_unidirectional_streams(connection.clone()),
        )
        .map(|_| ())
    } else {
        tokio::try_join!(
            drive_tcp_streams(
                connection.clone(),
                resolver.clone(),
                &auth_ctx,
                inbound_tag.clone(),
                runtime,
            ),
            drain_unidirectional_streams(connection.clone()),
        )
        .map(|_| ())
    };

    if result.is_err() {
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }
    result
}

async fn auth_hysteria2_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    config: &Hysteria2ServerConfig,
    tx_bps: Arc<AtomicU64>,
) -> std::io::Result<AuthContext> {
    loop {
        match h3_conn.accept().await.map_err(map_h3_error)? {
            Some(resolver) => {
                let (req, mut stream) =
                    resolver.resolve_request().await.map_err(|err| {
                        Error::other(format!(
                            "hysteria2 auth resolve_request failed: {err}"
                        ))
                    })?;
                debug!(method = %req.method(), uri = %req.uri(), "hysteria2 auth request received");
                match validate_auth_request(req, config) {
                    Ok(auth_info) => {
                        let (actual_tx, response_rx, response_rx_auto) =
                            resolve_bandwidth_settings(
                                config,
                                auth_info.client_rx_limit,
                            );
                        tx_bps.store(actual_tx, Ordering::Relaxed);
                        debug!(status = SUCCESS_STATUS, "hysteria2 auth accepted");
                        send_auth_success(
                            &mut stream,
                            auth_info.udp_enabled,
                            response_rx,
                            response_rx_auto,
                        )
                        .await
                        .map_err(|err| {
                            Error::other(format!(
                                "hysteria2 auth response failed: {err}"
                            ))
                        })?;
                        debug!("hysteria2 auth response finished");
                        return Ok(AuthContext {
                            client: auth_info.client,
                            udp_enabled: auth_info.udp_enabled,
                        });
                    }
                    Err(reject) => {
                        match &reject {
                            AuthReject::NotAuthRequest => {}
                            AuthReject::Unauthorized(msg) => {
                                warn!("hysteria2 auth rejected: {}", msg);
                            }
                            AuthReject::BadRequest(msg) => {
                                warn!("hysteria2 auth request invalid: {}", msg);
                            }
                        }
                        send_masquerade_response(&mut stream, &config.masquerade)
                            .await?;
                    }
                }
            }
            None => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "h3 connection closed before authentication",
                ));
            }
        }
    }
}

async fn drain_unidirectional_streams(
    connection: quinn::Connection,
) -> std::io::Result<()> {
    loop {
        match connection.accept_uni().await {
            Ok(mut stream) => {
                let _ = stream.stop(0_u32.into());
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(err) => {
                return Err(Error::other(format!(
                    "hysteria2 unidirectional stream loop failed: {err}"
                )));
            }
        }
    }
}

async fn drive_tcp_streams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let peer_addr = connection.remote_address();
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let resolver = resolver.clone();
                let client = auth_ctx.client.clone();
                let inbound_tag = inbound_tag.clone();
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_stream(
                        send,
                        recv,
                        resolver,
                        client,
                        inbound_tag,
                        peer_addr,
                        runtime,
                    )
                    .await
                    {
                        debug!("hysteria2 tcp stream ended with error: {}", err);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(err) => {
                return Err(Error::other(err));
            }
        }
    }
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    resolver: Arc<dyn Resolver>,
    client: Hysteria2Client,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let request = TcpRequest::read(&mut recv).await?;
    let mut context = apply_hysteria2_policy(
        hysteria2_traffic_context(&client, inbound_tag.as_str(), peer_addr),
        &runtime,
    )
    .with_access_target(
        request.target.address().to_string(),
        request.target.port(),
        AccessTransport::Quic,
    );
    #[cfg(feature = "user_domain_access")]
    match crate::beginning::enforce_user_domain_access(
        &runtime,
        Some(&context),
        &request.target,
    ) {
        Ok(Some(user_uuid)) => {
            context.set_user_uuid(user_uuid.to_string());
        }
        Ok(None) => {}
        Err(error) => {
            let _ = send_tcp_response(&mut send, TCP_ERROR_STATUS, "access denied")
                .await;
            let _ = send.finish();
            return Err(error);
        }
    }

    let connection = match connect_tcp_outbound(
        &resolver,
        &request.target,
        &runtime,
        inbound_tag.as_str(),
        context.routing_identity().unwrap_or_default(),
        peer_addr,
    )
    .await
    {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            let _ = send.finish();
            return Ok(());
        }
        Err(err) => {
            warn!("failed to connect to {}: {}", request.target, err);
            let _ = send_tcp_response(&mut send, TCP_ERROR_STATUS, "connect failed")
                .await;
            let _ = send.finish();
            return Err(err);
        }
    };

    send_tcp_response(&mut send, TCP_SUCCESS_STATUS, "").await?;

    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }

    proxy_tcp(send, recv, connection.stream, context).await
}

struct TcpRequest {
    target: NetLocation,
}

impl TcpRequest {
    async fn read(stream: &mut quinn::RecvStream) -> std::io::Result<Self> {
        let request_id = read_varint(stream).await?;
        if request_id != TCP_REQUEST_ID {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unexpected hysteria2 request type: {:#x}", request_id),
            ));
        }

        let address_len = read_varint(stream).await?;
        if address_len > MAX_ADDRESS_LEN as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "request address too long",
            ));
        }
        let address_len = address_len as usize;
        let mut address_bytes = vec![0; address_len];
        stream
            .read_exact(&mut address_bytes)
            .await
            .map_err(Error::other)?;
        let address = String::from_utf8(address_bytes)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        let target = NetLocation::from_str(&address, None)?;

        let padding_len = read_varint(stream).await?;
        let padding_len = usize::try_from(padding_len).map_err(|_| {
            Error::new(ErrorKind::InvalidData, "padding length too large")
        })?;
        skip_padding(stream, padding_len).await?;

        Ok(Self { target })
    }
}

async fn proxy_tcp(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    tcp_stream: Box<dyn AsyncStream>,
    context: TrafficContext,
) -> std::io::Result<()> {
    let _connection_guard = register_connection(Some(&context));
    let mut quic_stream = MeteredStream::new(
        QuicStream { send, recv },
        Some(context.clone()),
        TrafficDirection::Upload,
    );
    let mut tcp_stream =
        MeteredStream::new(tcp_stream, Some(context), TrafficDirection::Download);
    match tokio::io::copy_bidirectional(&mut quic_stream, &mut tcp_stream).await {
        Ok((client_to_server, server_to_client)) => {
            debug!(
                "hysteria2 tcp stream forwarded {} bytes client->server and {} bytes server->client",
                client_to_server, server_to_client
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
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
            .map_err(Error::other)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_flush(cx)
            .map_err(Error::other)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_shutdown(cx)
            .map_err(Error::other)
    }
}

#[derive(Debug)]
enum AuthReject {
    NotAuthRequest,
    Unauthorized(&'static str),
    BadRequest(&'static str),
}

fn resolve_bandwidth_settings(
    config: &Hysteria2ServerConfig,
    client_rx_limit: Option<u64>,
) -> (u64, u64, bool) {
    if config.quic_params.from_finalmask {
        let client_rx_limit = client_rx_limit.unwrap_or(0);
        let actual_tx = match config.quic_params.congestion.as_str() {
            "reno" | "bbr" => 0,
            "force-brutal" => config.quic_params.brutal_up,
            "" | "brutal" => {
                if config.quic_params.brutal_up == 0 || client_rx_limit == 0 {
                    0
                } else {
                    config.quic_params.brutal_up.min(client_rx_limit)
                }
            }
            _ => {
                unreachable!("hysteria2 congestion mode validated by config builder")
            }
        };
        return (actual_tx, config.quic_params.brutal_down, false);
    }

    if config.ignore_client_bandwidth {
        return (0, config.bandwidth.max_rx, true);
    }

    let mut actual_tx = client_rx_limit.unwrap_or(0);
    if actual_tx > 0
        && config.bandwidth.max_tx > 0
        && actual_tx > config.bandwidth.max_tx
    {
        actual_tx = config.bandwidth.max_tx;
    }

    (actual_tx, config.bandwidth.max_rx, false)
}

fn validate_auth_request(
    req: Request<()>,
    config: &Hysteria2ServerConfig,
) -> Result<AuthInfo, AuthReject> {
    if req.method() != http::Method::POST || req.uri().path() != AUTH_PATH {
        return Err(AuthReject::NotAuthRequest);
    }

    let headers = req.headers();
    let provided = headers
        .get(AUTH_HEADER)
        .ok_or(AuthReject::Unauthorized("missing auth header"))?;
    let provided = provided
        .to_str()
        .map_err(|_| AuthReject::Unauthorized("invalid auth header"))?;

    let provided = provided.trim();

    let (client, udp_enabled) = if config.clients.is_empty() {
        let fallback_auth = config
            .fallback_auth
            .as_deref()
            .ok_or(AuthReject::Unauthorized("password mismatch"))?;
        if fallback_auth != provided {
            return Err(AuthReject::Unauthorized("password mismatch"));
        }
        (
            Hysteria2Client {
                password: fallback_auth.to_string(),
                email: None,
                user_level: 0,
            },
            false,
        )
    } else {
        let client = config
            .clients
            .iter()
            .find(|client| client.password == provided)
            .cloned()
            .ok_or(AuthReject::Unauthorized("password mismatch"))?;
        (client, true)
    };

    let client_rx_limit =
        match headers.get(CLIENT_CC_RX_HEADER) {
            Some(value) if !value.is_empty() => match value.to_str() {
                Ok(val) => {
                    if val.eq_ignore_ascii_case("auto") {
                        None
                    } else {
                        Some(val.parse::<u64>().map_err(|_| {
                            AuthReject::BadRequest("invalid cc header")
                        })?)
                    }
                }
                Err(_) => return Err(AuthReject::BadRequest("invalid cc header")),
            },
            _ => None,
        };

    Ok(AuthInfo {
        client,
        client_rx_limit,
        udp_enabled,
    })
}

async fn send_auth_success(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
) -> std::io::Result<()> {
    let padding = random_padding();
    let cc_rx_value = if rx_auto {
        "auto".to_string()
    } else {
        server_rx_limit.to_string()
    };
    let response = Response::builder()
        .status(
            StatusCode::from_u16(SUCCESS_STATUS).expect("valid hysteria2 status"),
        )
        .header(
            UDP_SUPPORT_HEADER,
            if udp_enabled { "true" } else { "false" },
        )
        .header(CLIENT_CC_RX_HEADER, cc_rx_value.as_str())
        .header(PADDING_HEADER, &padding)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(Error::other)?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

fn build_masquerade_response(
    masquerade: &Hysteria2MasqueradeConfig,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    match masquerade.mode.as_str() {
        "" | "404" => {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(http::header::CONTENT_LENGTH, "0")
                .body(())
                .map_err(Error::other)?;
            Ok((response, None))
        }
        "string" => {
            let status = if masquerade.status_code == 0 {
                StatusCode::OK
            } else {
                StatusCode::from_u16(masquerade.status_code).map_err(Error::other)?
            };
            let mut builder = Response::builder().status(status);
            for (name, value) in &masquerade.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let response = builder.body(()).map_err(Error::other)?;
            Ok((response, Some(Bytes::from(masquerade.content.clone()))))
        }
        _ => unreachable!("hysteria2 masquerade mode validated by config builder"),
    }
}

async fn send_masquerade_response(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    masquerade: &Hysteria2MasqueradeConfig,
) -> std::io::Result<()> {
    let (response, body) = build_masquerade_response(masquerade)?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    if let Some(body) = body
        && !body.is_empty()
    {
        stream.send_data(body).await.map_err(map_h3_error)?;
    }
    stream.finish().await.map_err(map_h3_error)
}

fn random_padding() -> String {
    let mut rng = rand::rng();
    let len = rng.random_range(16..=64);
    Alphanumeric.sample_string(&mut rng, len)
}

fn map_h3_error<E>(err: E) -> std::io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::other(err)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(Error::other)?;
    let prefix = first[0] >> 6;
    let mut value = (first[0] & 0x3f) as u64;
    if prefix > 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 varint prefix: {prefix}"),
        ));
    }
    let remaining: usize = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };

    if remaining > 0 {
        let mut buf = [0u8; 8];
        stream
            .read_exact(&mut buf[..remaining])
            .await
            .map_err(Error::other)?;
        for &byte in &buf[..remaining] {
            value = (value << 8) | u64::from(byte);
        }
    }

    Ok(value)
}

async fn skip_padding(
    stream: &mut quinn::RecvStream,
    mut len: usize,
) -> std::io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut scratch = [0u8; PADDING_SCRATCH_LEN];
    while len > 0 {
        let take = scratch.len().min(len);
        stream
            .read_exact(&mut scratch[..take])
            .await
            .map_err(Error::other)?;
        len -= take;
    }
    Ok(())
}

async fn send_tcp_response(
    stream: &mut quinn::SendStream,
    status: u8,
    message: &str,
) -> std::io::Result<()> {
    let message_bytes = message.as_bytes();
    let mut buf = Vec::with_capacity(1 + message_bytes.len() + 16);
    buf.push(status);
    push_varint(&mut buf, message_bytes.len() as u64)?;
    buf.extend_from_slice(message_bytes);
    push_varint(&mut buf, 0)?;
    stream.write_all(&buf).await.map_err(Error::other)?;
    stream.flush().await.map_err(Error::other)
}

async fn drive_udp_datagrams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    udp_idle_timeout: Duration,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let mut sessions: HashMap<u32, UdpSession> = HashMap::new();
    let mut cleanup = tokio::time::interval(UDP_SESSION_CLEANUP_INTERVAL);
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    cleanup.tick().await;
    let peer_addr = connection.remote_address();
    let base_context = apply_hysteria2_policy(
        hysteria2_traffic_context(&auth_ctx.client, inbound_tag.as_str(), peer_addr),
        &runtime,
    );

    loop {
        let data = tokio::select! {
            _ = cleanup.tick() => {
                sessions.retain(|session_id, session| {
                    if session.idle_for() > udp_idle_timeout {
                        debug!("Removing inactive hysteria2 UDP session {session_id}");
                        false
                    } else {
                        true
                    }
                });
                continue;
            }
            result = connection.read_datagram() => match result {
                Ok(data) => data,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::ConnectionClosed { .. }) => return Ok(()),
                Err(err) => return Err(Error::other(err)),
            },
        };

        if data.len() < 9 {
            warn!("Ignoring short hysteria2 UDP datagram (len={})", data.len());
            continue;
        }

        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, varint_len) = match decode_varint_from_slice(&data[8..]) {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    "Ignoring hysteria2 UDP packet with invalid address length: {err}"
                );
                continue;
            }
        };
        if address_len == 0 || address_len > MAX_ADDRESS_LEN {
            warn!(
                "Ignoring hysteria2 UDP packet {} with invalid address length {}",
                session_id, address_len
            );
            continue;
        }

        let address_start = 8 + varint_len;
        let payload_start = address_start + address_len;
        if data.len() < payload_start {
            warn!(
                "Ignoring truncated hysteria2 UDP packet for session {}",
                session_id
            );
            continue;
        }

        let address_bytes = data.slice(address_start..payload_start);
        let payload_fragment = data.slice(payload_start..);

        let address_str = match std::str::from_utf8(&address_bytes) {
            Ok(addr) => addr,
            Err(err) => {
                warn!("Ignoring hysteria2 UDP packet with invalid UTF-8: {}", err);
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(address_str, None) {
            Ok(loc) => loc,
            Err(err) => {
                warn!(
                    "Failed to parse hysteria2 UDP address {}: {}",
                    address_str, err
                );
                continue;
            }
        };

        #[allow(unused_mut)]
        let mut packet_context = base_context.clone().with_access_target(
            remote_location.address().to_string(),
            remote_location.port(),
            AccessTransport::Quic,
        );
        #[cfg(feature = "user_domain_access")]
        match crate::beginning::enforce_user_domain_access(
            &runtime,
            Some(&packet_context),
            &remote_location,
        ) {
            Ok(Some(user_uuid)) => {
                packet_context.set_user_uuid(user_uuid.to_string());
            }
            Ok(None) => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                debug!(
                    "Hysteria2 UDP target {} rejected by user-domain access policy",
                    remote_location
                );
                continue;
            }
            Err(error) => return Err(error),
        }

        let session = match sessions.entry(session_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let session = create_udp_session(
                    session_id,
                    remote_location.clone(),
                    resolver.clone(),
                    connection.clone(),
                    packet_context.clone(),
                    udp_idle_timeout,
                )
                .await?;
                entry.insert(session)
            }
        };
        session.touch();

        if remote_location != session.last_location {
            let updated_addr =
                resolve_single_address(&resolver, &remote_location).await?;
            session.last_location = remote_location.clone();
            session.last_socket_addr = updated_addr;
        }

        let complete_payload = if fragment_count == 0 {
            warn!(
                "Ignoring hysteria2 UDP packet {} with zero fragments",
                session_id
            );
            continue;
        } else if fragment_count == 1 {
            payload_fragment
        } else {
            if fragment_id as usize >= fragment_count as usize {
                warn!(
                    "Ignoring hysteria2 UDP packet {} with invalid fragment id {}",
                    session_id, fragment_id
                );
                continue;
            }

            if !session.fragments.contains(&packet_id) {
                session.fragments.put(
                    packet_id,
                    FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }
            let Some(entry) = session.fragments.get_mut(&packet_id) else {
                warn!(
                    "Failed to track hysteria2 UDP fragments for session {} packet {}",
                    session_id, packet_id
                );
                continue;
            };

            if entry.fragment_count != fragment_count {
                warn!(
                    "Mismatched fragment count for hysteria2 UDP packet {}",
                    session_id
                );
                session.fragments.pop(&packet_id);
                continue;
            }

            if entry.received[fragment_id as usize].is_some() {
                warn!(
                    "Duplicate fragment {} for hysteria2 UDP packet {}",
                    fragment_id, session_id
                );
                session.fragments.pop(&packet_id);
                continue;
            }

            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location: remembered_location,
                received,
                packet_len,
                ..
            } = session.fragments.pop(&packet_id).unwrap();

            let mut assembled = BytesMut::with_capacity(packet_len);
            for bytes in received.into_iter().flatten() {
                assembled.extend_from_slice(&bytes);
            }

            if remembered_location != session.last_location {
                let updated_addr =
                    resolve_single_address(&resolver, &remembered_location).await?;
                session.last_location = remembered_location;
                session.last_socket_addr = updated_addr;
            }

            assembled.freeze()
        };

        let route_input = connection_routing_input(
            inbound_tag.as_str(),
            packet_context.routing_identity().unwrap_or_default(),
            3,
            peer_addr,
            session.last_socket_addr,
            &session.last_location,
        );
        let action = select_direct_outbound(&runtime, &route_input, "udp")?;
        let mut traffic_context = packet_context;

        match action {
            DirectOutboundAction::Blackhole { tag } => {
                traffic_context = traffic_context.with_outbound_tag(tag.clone());
                record_transfer(
                    Some(traffic_context),
                    complete_payload.len() as u64,
                    0,
                );
                debug!(
                    "hysteria2 UDP payload for session {} dropped by blackhole outbound {}",
                    session_id, tag
                );
                continue;
            }
            DirectOutboundAction::Freedom { tag: Some(tag) } => {
                traffic_context = traffic_context.with_outbound_tag(tag);
            }
            DirectOutboundAction::Freedom { tag: None } => {}
            proxy_action => {
                let tag = proxy_action.required_outbound_tag()?.to_string();
                traffic_context = traffic_context.with_outbound_tag(tag);
                let response = session
                    .proxy_associations
                    .exchange(
                        &resolver,
                        &runtime,
                        &proxy_action,
                        &session.last_location,
                        complete_payload.as_ref(),
                    )
                    .await?;
                send_hysteria_udp_payload(
                    &connection,
                    session_id,
                    packet_id,
                    &response.source,
                    &response.payload,
                )?;
                record_transfer(
                    Some(traffic_context),
                    complete_payload.len() as u64,
                    response.payload.len() as u64,
                );
                continue;
            }
        }

        session
            .response_contexts
            .write()
            .expect("hysteria2 UDP contexts lock poisoned")
            .insert(session.last_socket_addr, traffic_context.clone());

        match session
            .socket
            .send_to(complete_payload.as_ref(), session.last_socket_addr)
            .await
        {
            Ok(sent) => {
                record_transfer(Some(traffic_context), sent as u64, 0);
            }
            Err(err) => {
                warn!(
                    "Failed to forward hysteria2 UDP payload for session {}: {}",
                    session_id, err
                );
            }
        }
    }
}

fn new_fragment_cache() -> LruCache<u16, FragmentedPacket> {
    LruCache::new(
        NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE)
            .expect("fragment cache size must be non-zero"),
    )
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    fragments: LruCache<u16, FragmentedPacket>,
    last_activity: Arc<RwLock<Instant>>,
    cancel_token: CancellationToken,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    base_context: TrafficContext,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, TrafficContext>>>,
    proxy_associations: UdpProxyAssociationRegistry,
    _connection_guard: ConnectionGuard,
}

impl UdpSession {
    fn touch(&self) {
        *self
            .last_activity
            .write()
            .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_activity
            .read()
            .expect("hysteria2 UDP activity lock poisoned")
            .elapsed()
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

async fn create_udp_session(
    session_id: u32,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    connection: quinn::Connection,
    base_context: TrafficContext,
    udp_idle_timeout: Duration,
) -> std::io::Result<UdpSession> {
    let remote_addr = resolve_single_address(&resolver, &remote_location).await?;
    let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let socket_for_task = socket.clone();
    let connection_for_task = connection.clone();
    let response_contexts = Arc::new(RwLock::new(HashMap::new()));
    let contexts_for_task = response_contexts.clone();
    let fallback_context = base_context.clone();
    let last_activity = Arc::new(RwLock::new(Instant::now()));
    let activity_for_task = last_activity.clone();
    let cancel_token = CancellationToken::new();
    let cancel_for_task = cancel_token.clone();
    let connection_guard = register_connection(Some(&base_context));

    tokio::spawn(async move {
        if let Err(err) = run_udp_remote_to_local_loop(
            session_id,
            connection_for_task,
            socket_for_task,
            contexts_for_task,
            fallback_context,
            activity_for_task,
            cancel_for_task,
        )
        .await
        {
            debug!(
                "hysteria2 UDP remote-to-local loop for session {} ended: {}",
                session_id, err
            );
        }
    });

    Ok(UdpSession {
        socket,
        fragments: new_fragment_cache(),
        last_activity,
        cancel_token,
        last_location: remote_location,
        last_socket_addr: remote_addr,
        base_context,
        response_contexts,
        proxy_associations: UdpProxyAssociationRegistry::new(udp_idle_timeout),
        _connection_guard: connection_guard,
    })
}

fn send_hysteria_udp_payload(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    source: &NetLocation,
    payload: &[u8],
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| Error::other("peer does not support datagrams"))?;
    let address_bytes = Bytes::from(source.to_string().into_bytes());
    let mut address_len_buf = Vec::with_capacity(8);
    push_varint(&mut address_len_buf, address_bytes.len() as u64)?;
    let address_len_bytes = Bytes::from(address_len_buf);
    let header_overhead =
        4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
    if header_overhead >= max_datagram_size {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "hysteria2 UDP response header exceeds max datagram size",
        ));
    }
    let available_payload = max_datagram_size - header_overhead;
    if payload.len() <= available_payload {
        let mut datagram = BytesMut::with_capacity(header_overhead + payload.len());
        datagram.extend_from_slice(&session_id.to_be_bytes());
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.extend_from_slice(&[0, 1]);
        datagram.extend_from_slice(&address_len_bytes);
        datagram.extend_from_slice(&address_bytes);
        datagram.extend_from_slice(payload);
        connection
            .send_datagram(datagram.freeze())
            .map_err(Error::other)?;
        return Ok(());
    }

    let fragment_count = payload.len().div_ceil(available_payload);
    if fragment_count > u8::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "hysteria2 UDP response requires too many fragments",
        ));
    }
    for fragment_id in 0..fragment_count {
        let start = fragment_id * available_payload;
        let end = std::cmp::min(start + available_payload, payload.len());
        let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
        datagram.extend_from_slice(&session_id.to_be_bytes());
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.extend_from_slice(&[fragment_id as u8, fragment_count as u8]);
        datagram.extend_from_slice(&address_len_bytes);
        datagram.extend_from_slice(&address_bytes);
        datagram.extend_from_slice(&payload[start..end]);
        connection
            .send_datagram(datagram.freeze())
            .map_err(Error::other)?;
    }
    Ok(())
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, TrafficContext>>>,
    fallback_context: TrafficContext,
    last_activity: Arc<RwLock<Instant>>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| Error::other("peer does not support datagrams"))?;

    let mut next_packet_id: u16 = 0;
    let mut buf = vec![0u8; 65535];

    loop {
        let recv_result = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            result = socket.recv_from(&mut buf) => result,
        };
        let (payload_len, src_addr) = recv_result.map_err(|err| {
            Error::other(format!("failed to receive hysteria2 UDP payload: {}", err))
        })?;
        *last_activity
            .write()
            .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
        let traffic_context = response_contexts
            .read()
            .expect("hysteria2 UDP contexts lock poisoned")
            .get(&src_addr)
            .cloned()
            .unwrap_or_else(|| fallback_context.clone());

        let address_bytes = Bytes::from(src_addr.to_string().into_bytes());
        let mut address_len_buf = Vec::with_capacity(8);
        push_varint(&mut address_len_buf, address_bytes.len() as u64)?;
        let address_len_bytes = Bytes::from(address_len_buf);

        let header_overhead =
            4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
        if header_overhead >= max_datagram_size {
            warn!(
                "hysteria2 UDP datagram header larger than max datagram size ({} >= {})",
                header_overhead, max_datagram_size
            );
            continue;
        }

        let available_payload = max_datagram_size - header_overhead;
        if available_payload == 0 {
            warn!("hysteria2 UDP available payload is zero, skipping packet");
            continue;
        }

        if payload_len <= available_payload {
            let mut datagram =
                BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&next_packet_id.to_be_bytes());
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(Error::other)?;
        } else {
            let fragment_count = payload_len.div_ceil(available_payload);
            if fragment_count > u8::MAX as usize {
                warn!(
                    "hysteria2 UDP packet too large to fragment ({} fragments)",
                    fragment_count
                );
                continue;
            }

            for fragment_id in 0..fragment_count {
                let start = fragment_id * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);

                let mut datagram =
                    BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&next_packet_id.to_be_bytes());
                datagram
                    .extend_from_slice(&[fragment_id as u8, fragment_count as u8]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                connection
                    .send_datagram(datagram.freeze())
                    .map_err(Error::other)?;
            }
        }

        record_transfer(Some(traffic_context), 0, payload_len as u64);
        next_packet_id = next_packet_id.wrapping_add(1);
    }
}

fn decode_varint_from_slice(data: &[u8]) -> std::io::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "varint truncated in hysteria2 datagram",
        ));
    }

    let first = data[0];
    let prefix = first >> 6;
    if prefix > 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 varint prefix in datagram: {prefix}"),
        ));
    }
    let bytes = match prefix {
        0 => 1usize,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if data.len() < bytes {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "varint truncated in hysteria2 datagram",
        ));
    }

    let mut value = (first & 0x3f) as u64;
    for &byte in &data[1..bytes] {
        value = (value << 8) | u64::from(byte);
    }

    let numeric = usize::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "varint too large in hysteria2 datagram",
        )
    })?;

    Ok((numeric, bytes))
}

fn push_varint(buf: &mut Vec<u8>, value: u64) -> std::io::Result<()> {
    if value <= 0x3f {
        buf.push(value as u8);
    } else if value <= 0x3fff {
        buf.push(0x40 | ((value >> 8) as u8 & 0x3f));
        buf.push((value & 0xff) as u8);
    } else if value <= 0x3fff_ffff {
        buf.push(0x80 | ((value >> 24) as u8 & 0x3f));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else if value <= 0x3fff_ffff_ffff_ffff {
        buf.push(0xc0 | ((value >> 56) as u8 & 0x3f));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "varint value too large",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{
        def::{PolicyConfig, PolicyLevelConfig, PolicySystemConfig},
        server_config::{
            Hysteria2BandwidthConfig, Hysteria2MasqueradeConfig, Hysteria2QuicParams,
        },
    };

    fn auth_request(auth: &str) -> Request<()> {
        Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header(AUTH_HEADER, auth)
            .body(())
            .expect("valid hysteria auth request")
    }

    #[test]
    fn transport_auth_disables_udp_and_users_take_precedence() {
        let mut config = Hysteria2ServerConfig {
            clients: Vec::new(),
            fallback_auth: Some("fallback-auth".into()),
            bandwidth: Hysteria2BandwidthConfig::default(),
            ignore_client_bandwidth: false,
            udp_idle_timeout: 60,
            quic_params: Hysteria2QuicParams::default(),
            masquerade: Default::default(),
        };

        let auth = validate_auth_request(auth_request("fallback-auth"), &config)
            .expect("fallback auth should authenticate");
        assert!(!auth.udp_enabled);
        assert_eq!(auth.client.password, "fallback-auth");

        config.clients.push(Hysteria2Client {
            password: "user-auth".into(),
            email: Some("user@example.com".into()),
            user_level: 7,
        });
        assert!(
            validate_auth_request(auth_request("fallback-auth"), &config).is_err()
        );
        let auth = validate_auth_request(auth_request("user-auth"), &config)
            .expect("configured users should take precedence");
        assert!(auth.udp_enabled);
        assert_eq!(auth.client.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn masquerade_response_matches_xray_404_and_string_modes() {
        let (response, body) =
            build_masquerade_response(&Hysteria2MasqueradeConfig::default())
                .expect("default masquerade response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body.is_none());

        let (response, body) =
            build_masquerade_response(&Hysteria2MasqueradeConfig {
                mode: "string".into(),
                content: "hello from hysteria".into(),
                headers: std::collections::HashMap::from([(
                    "x-hysteria-test".into(),
                    "yes".into(),
                )]),
                status_code: 201,
            })
            .expect("string masquerade response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-hysteria-test"], "yes");
        assert_eq!(body.as_deref(), Some(&b"hello from hysteria"[..]));
    }

    #[test]
    fn finalmask_brutal_bandwidth_matches_xray_negotiation() {
        let mut config = Hysteria2ServerConfig {
            clients: Vec::new(),
            fallback_auth: None,
            bandwidth: Hysteria2BandwidthConfig {
                max_tx: 9_000_000,
                max_rx: 8_000_000,
            },
            ignore_client_bandwidth: true,
            udp_idle_timeout: 60,
            masquerade: Default::default(),
            quic_params: Hysteria2QuicParams {
                brutal_up: 1_000_000,
                brutal_down: 2_000_000,
                from_finalmask: true,
                ..Hysteria2QuicParams::default()
            },
        };

        assert_eq!(
            resolve_bandwidth_settings(&config, Some(1_500_000)),
            (1_000_000, 2_000_000, false)
        );
        assert_eq!(
            resolve_bandwidth_settings(&config, Some(500_000)),
            (500_000, 2_000_000, false)
        );
        assert_eq!(
            resolve_bandwidth_settings(&config, None),
            (0, 2_000_000, false)
        );

        config.quic_params.brutal_up = 0;
        assert_eq!(
            resolve_bandwidth_settings(&config, Some(500_000)),
            (0, 2_000_000, false)
        );

        config.quic_params.brutal_up = 1_000_000;
        config.quic_params.congestion = "bbr".into();
        assert_eq!(
            resolve_bandwidth_settings(&config, Some(500_000)),
            (0, 2_000_000, false)
        );

        config.quic_params.congestion = "reno".into();
        assert_eq!(
            resolve_bandwidth_settings(&config, Some(500_000)),
            (0, 2_000_000, false)
        );

        config.quic_params.congestion = "force-brutal".into();
        assert_eq!(
            resolve_bandwidth_settings(&config, None),
            (1_000_000, 2_000_000, false)
        );
    }

    #[test]
    fn fragment_cache_evicts_oldest_packet_at_capacity() {
        let mut cache = new_fragment_cache();
        for packet_id in 0..=MAX_FRAGMENT_CACHE_SIZE as u16 {
            cache.put(
                packet_id,
                FragmentedPacket {
                    fragment_count: 2,
                    fragment_received: 1,
                    packet_len: 1,
                    received: vec![Some(Bytes::from_static(b"x")), None],
                    remote_location: NetLocation::from_str("127.0.0.1:53", None)
                        .unwrap(),
                },
            );
        }

        assert_eq!(cache.len(), MAX_FRAGMENT_CACHE_SIZE);
        assert!(!cache.contains(&0));
        assert!(cache.contains(&(MAX_FRAGMENT_CACHE_SIZE as u16)));
    }

    #[test]
    fn password_only_context_does_not_expose_plaintext() {
        let client = Hysteria2Client {
            password: "super-secret".into(),
            email: None,
            user_level: 3,
        };
        let context = hysteria2_traffic_context(
            &client,
            "hysteria-test",
            "127.0.0.1:12345".parse().unwrap(),
        );
        let expected = hysteria2_password_identity(&client.password);
        assert_eq!(context.identity.as_deref(), Some(expected.as_str()));
        assert_eq!(context.protocol_identity(), Some(expected.as_str()));
        assert!(!expected.contains(&client.password));
        assert_eq!(context.inbound_tag.as_deref(), Some("hysteria-test"));
        assert_eq!(context.user_level, 3);
    }

    #[test]
    fn traffic_context_applies_user_and_system_stats_policy() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime
            .configure_policy(Some(&PolicyConfig {
                levels: std::collections::HashMap::from([(
                    "7".into(),
                    PolicyLevelConfig {
                        stats_user_uplink: Some(false),
                        stats_user_downlink: Some(true),
                        stats_user_online: Some(false),
                        ..PolicyLevelConfig::default()
                    },
                )]),
                system: Some(PolicySystemConfig {
                    stats_inbound_uplink: Some(true),
                    stats_inbound_downlink: Some(false),
                    stats_outbound_uplink: Some(false),
                    stats_outbound_downlink: Some(true),
                }),
            }))
            .unwrap();
        let client = Hysteria2Client {
            password: "policy-secret".into(),
            email: Some("policy@example.com".into()),
            user_level: 7,
        };
        let context = apply_hysteria2_policy(
            hysteria2_traffic_context(
                &client,
                "hysteria-policy",
                "127.0.0.1:12345".parse().unwrap(),
            ),
            &runtime,
        );

        assert_eq!(context.stats_user_uplink, Some(false));
        assert_eq!(context.stats_user_downlink, Some(true));
        assert_eq!(context.stats_user_online, Some(false));
        assert_eq!(context.stats_inbound_uplink, Some(true));
        assert_eq!(context.stats_inbound_downlink, Some(false));
        assert_eq!(context.stats_outbound_uplink, Some(false));
        assert_eq!(context.stats_outbound_downlink, Some(true));
    }

    #[test]
    fn email_is_display_identity_but_password_hash_is_policy_identity() {
        let client = Hysteria2Client {
            password: "super-secret".into(),
            email: Some("user@example.com".into()),
            user_level: 7,
        };
        let context = hysteria2_traffic_context(
            &client,
            "hysteria-test",
            "127.0.0.1:12345".parse().unwrap(),
        );
        let expected = hysteria2_password_identity(&client.password);
        assert_eq!(context.identity.as_deref(), Some("user@example.com"));
        assert_eq!(context.protocol_identity(), Some(expected.as_str()));
        assert_eq!(context.user_level, 7);
    }
}
