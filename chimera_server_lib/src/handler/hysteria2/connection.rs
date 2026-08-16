use std::{
    collections::{HashMap, hash_map::Entry},
    convert::TryFrom,
    future::Future,
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
use tracing::{debug, warn};

use crate::{
    address::NetLocation,
    config::server_config::{Hysteria2Client, Hysteria2ServerConfig},
    outbound::{
        DirectOutboundAction, connect_tcp_outbound_with_vless_route,
        connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{
        ConnectionGuard, MeteredStream, TrafficContext, TrafficDirection,
        record_transfer, register_connection,
    },
    util::socket::new_socket2_udp_socket,
};

const AUTH_URI: &str = "https://hysteria/auth";
const AUTH_HEADER: &str = "Hysteria-Auth";
const CLIENT_CC_RX_HEADER: &str = "Hysteria-CC-RX";
const UDP_SUPPORT_HEADER: &str = "Hysteria-UDP";
const PADDING_HEADER: &str = "Hysteria-Padding";
const SUCCESS_STATUS: u16 = 233;
const TCP_REQUEST_ID: u64 = 0x401;
const MAX_ADDRESS_LEN: usize = 2048;
const MAX_TCP_REQUEST_PADDING_LEN: u64 = 4096;
const PADDING_SCRATCH_LEN: usize = 1024;
const TCP_SUCCESS_STATUS: u8 = 0x00;
const TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_IDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
// Match Shoes/sing-box: unauthenticated Hysteria2 QUIC connections only get a
// short window to complete the HTTP/3 authentication exchange.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const CLOSE_ERR_CODE_OK: u32 = 0x100;

#[derive(Clone)]
struct AuthContext {
    client: Hysteria2Client,
    udp_enabled: bool,
    vless_route: u32,
    xray_compat: bool,
}

struct AuthInfo {
    client: Hysteria2Client,
    client_rx_limit: Option<u64>,
    vless_route: u32,
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

    let auth_ctx = match await_authentication(
        auth_hysteria2_connection(&mut h3_conn, config.as_ref(), tx_bps.clone()),
        config.xray_compat,
    )
    .await
    {
        Ok(auth_ctx) => auth_ctx,
        Err(err) => {
            let kind = err.kind();
            let reason: &[u8] = if kind == ErrorKind::TimedOut {
                b"auth timeout"
            } else {
                b"auth failed"
            };
            connection.close(CLOSE_ERR_CODE_OK.into(), reason);
            return Err(Error::new(
                kind,
                format!("hysteria2 authentication failed: {err}"),
            ));
        }
    };

    // Keep the H3 driver alive because dropping it closes the underlying QUIC
    // connection. Do not poll it after authentication: Hysteria2 TCP requests
    // are raw QUIC bidi streams and would otherwise race with h3_conn.accept().
    let _h3_conn = h3_conn;
    let udp_idle_timeout = config
        .xray_udp_idle_timeout_secs
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);

    if auth_ctx.udp_enabled {
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
                runtime,
                udp_idle_timeout,
            ),
            drain_unidirectional_streams(connection),
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
            drain_unidirectional_streams(connection),
        )
        .map(|_| ())
    }
}

fn configured_auth_timeout(xray_compat: bool) -> Option<Duration> {
    (!xray_compat).then_some(AUTH_TIMEOUT)
}

async fn await_authentication<F, T>(
    future: F,
    xray_compat: bool,
) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    match configured_auth_timeout(xray_compat) {
        Some(timeout) => {
            tokio::time::timeout(timeout, future).await.map_err(|_| {
                Error::new(ErrorKind::TimedOut, "authentication timeout")
            })?
        }
        None => future.await,
    }
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
                match validate_auth_request(
                    req,
                    config.clients.as_ref(),
                    config.xray_compat,
                ) {
                    Ok(auth_info) => {
                        let (actual_tx, response_rx, response_rx_auto) =
                            resolve_bandwidth_settings(
                                config,
                                auth_info.client_rx_limit,
                            );
                        let congestion_tx = resolve_congestion_tx_bps(
                            config,
                            auth_info.client_rx_limit,
                            actual_tx,
                        );
                        tx_bps.store(congestion_tx, Ordering::Relaxed);
                        debug!(status = SUCCESS_STATUS, "hysteria2 auth accepted");
                        send_auth_success(
                            &mut stream,
                            config.udp_enabled,
                            response_rx,
                            response_rx_auto,
                            config.xray_compat,
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
                            udp_enabled: config.udp_enabled,
                            vless_route: auth_info.vless_route,
                            xray_compat: config.xray_compat,
                        });
                    }
                    Err(reject) => {
                        match &reject {
                            AuthReject::NotAuthRequest => {}
                            AuthReject::Unauthorized(msg) => {
                                warn!("hysteria2 auth rejected: {}", msg);
                            }
                        }
                        send_simple_response(
                            &mut stream,
                            auth_reject_status(&reject),
                        )
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
                let auth_ctx = auth_ctx.clone();
                let inbound_tag = inbound_tag.clone();
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_stream(
                        send,
                        recv,
                        resolver,
                        auth_ctx,
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
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
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
    auth_ctx: AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let request = match read_tcp_request(&mut recv, auth_ctx.xray_compat).await {
        Ok(request) => request,
        Err(err) => {
            let _ = send.finish();
            return Err(err);
        }
    };
    send_tcp_response(&mut send, TCP_SUCCESS_STATUS, "", auth_ctx.xray_compat)
        .await?;

    let context_identity = auth_ctx
        .client
        .email
        .clone()
        .unwrap_or(auth_ctx.client.password.clone());
    let connection = match tokio::time::timeout(
        TCP_CONNECT_TIMEOUT,
        connect_tcp_outbound_with_vless_route(
            &resolver,
            &request.target,
            &runtime,
            inbound_tag.as_str(),
            &context_identity,
            peer_addr,
            auth_ctx.vless_route,
        ),
    )
    .await
    {
        Ok(Ok(Some(connection))) => connection,
        Ok(Ok(None)) => {
            let _ = send.finish();
            return Ok(());
        }
        Ok(Err(err)) => {
            warn!("failed to connect to {}: {}", request.target, err);
            let _ = send.finish();
            return Err(err);
        }
        Err(_) => {
            let _ = send.finish();
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("client setup to {} timed out", request.target),
            ));
        }
    };

    let mut context = TrafficContext::new("hysteria2")
        .with_identity(context_identity)
        .with_inbound_tag((*inbound_tag).clone())
        .with_client_ip(peer_addr.ip());
    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }

    proxy_tcp(send, recv, connection.stream, context).await
}

struct TcpRequest {
    target: NetLocation,
}

fn configured_tcp_request_timeout(xray_compat: bool) -> Option<Duration> {
    xray_compat.then_some(TCP_REQUEST_TIMEOUT)
}

async fn read_tcp_request(
    stream: &mut quinn::RecvStream,
    xray_compat: bool,
) -> std::io::Result<TcpRequest> {
    match configured_tcp_request_timeout(xray_compat) {
        Some(timeout) => tokio::time::timeout(timeout, TcpRequest::read(stream))
            .await
            .map_err(|_| {
                Error::new(
                    ErrorKind::TimedOut,
                    "hysteria2 TCP request header timed out",
                )
            })?,
        None => TcpRequest::read(stream).await,
    }
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

        let padding_len =
            validate_tcp_request_padding_len(read_varint(stream).await?)?;
        skip_padding(stream, padding_len).await?;

        Ok(Self { target })
    }
}

async fn proxy_tcp(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    tcp_stream: tokio::net::TcpStream,
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
    match tokio::io::copy_bidirectional_with_sizes(
        &mut quic_stream,
        &mut tcp_stream,
        32 * 1024,
        32 * 1024,
    )
    .await
    {
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
}

fn auth_reject_status(_reject: &AuthReject) -> StatusCode {
    StatusCode::NOT_FOUND
}

fn resolve_congestion_tx_bps(
    config: &Hysteria2ServerConfig,
    client_rx_limit: Option<u64>,
    shoes_tx_bps: u64,
) -> u64 {
    match config.xray_congestion.as_deref() {
        None if config.xray_compat => 0,
        None => shoes_tx_bps,
        Some("reno") | Some("bbr") => 0,
        Some("") | Some("brutal") => {
            let up = config.xray_brutal_up.unwrap_or(0);
            let down = client_rx_limit.unwrap_or(0);
            if up == 0 || down == 0 {
                0
            } else {
                up.min(down)
            }
        }
        Some("force-brutal") => config.xray_brutal_up.unwrap_or(0),
        Some(_) => unreachable!("validated Xray congestion mode"),
    }
}

fn resolve_bandwidth_settings(
    config: &Hysteria2ServerConfig,
    client_rx_limit: Option<u64>,
) -> (u64, u64, bool) {
    if config.xray_compat || config.xray_congestion.is_some() {
        return (
            client_rx_limit.unwrap_or(0),
            config.xray_brutal_down.unwrap_or(0),
            false,
        );
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
    clients: &[Hysteria2Client],
    xray_compat: bool,
) -> Result<AuthInfo, AuthReject> {
    let is_auth_request = if xray_compat {
        req.method() == http::Method::POST
            && req.uri().host() == Some("hysteria")
            && req.uri().path() == "/auth"
    } else {
        req.method() == http::Method::POST && req.uri() == AUTH_URI
    };
    if !is_auth_request {
        return Err(AuthReject::NotAuthRequest);
    }

    let headers = req.headers();
    let provided = headers
        .get(AUTH_HEADER)
        .ok_or(AuthReject::Unauthorized("missing auth header"))?;
    let provided = provided
        .to_str()
        .map_err(|_| AuthReject::Unauthorized("invalid auth header"))?;

    let (client, vless_route) = match_hysteria_auth(provided, clients)
        .ok_or(AuthReject::Unauthorized("password mismatch"))?;

    // Xray ignores Hysteria-CC-RX parse errors, while shoes does not consume
    // this header at all. Treat malformed values as an unspecified/zero limit
    // instead of rejecting an otherwise valid authentication request.
    let client_rx_limit = headers
        .get(CLIENT_CC_RX_HEADER)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            (!value.eq_ignore_ascii_case("auto"))
                .then(|| value.parse::<u64>().ok())
                .flatten()
        });

    Ok(AuthInfo {
        client,
        client_rx_limit,
        vless_route,
    })
}

fn match_hysteria_auth(
    provided: &str,
    clients: &[Hysteria2Client],
) -> Option<(Hysteria2Client, u32)> {
    // Chimera's shoes/native `id` credentials and Xray's transport auth
    // fallback remain exact even when they happen to look like UUIDs.
    if let Some(client) = clients
        .iter()
        .rev()
        .find(|client| !client.xray_uuid_route && client.password == provided)
        .cloned()
    {
        return Some((client, 0));
    }

    if let Some((provided_key, vless_route)) = xray_uuid_auth_key(provided) {
        // Xray's UUID validator stores the masked ID in a map, so later users
        // replace earlier users that share the same bytes outside 6..=7.
        if let Some(client) = clients.iter().rev().find_map(|client| {
            if !client.xray_uuid_route {
                return None;
            }
            let (configured_key, _) = xray_uuid_auth_key(&client.password)?;
            (configured_key == provided_key).then(|| client.clone())
        }) {
            return Some((client, vless_route));
        }
    }

    // Non-UUID Xray auth follows the same last-write-wins user-map behavior.
    clients
        .iter()
        .rev()
        .find(|client| client.xray_uuid_route && client.password == provided)
        .cloned()
        .map(|client| (client, 0))
}

fn xray_uuid_auth_key(auth: &str) -> Option<([u8; 16], u32)> {
    let uuid = uuid::Uuid::parse_str(auth).ok()?;
    let mut key = *uuid.as_bytes();
    let vless_route = u16::from_be_bytes([key[6], key[7]]) as u32;
    key[6] = 0;
    key[7] = 0;
    Some((key, vless_route))
}

async fn send_auth_success(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
    xray_compat: bool,
) -> std::io::Result<()> {
    let padding = random_auth_padding(xray_compat);
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

async fn send_simple_response(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> std::io::Result<()> {
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(Error::other)?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

fn random_auth_padding(xray_compat: bool) -> String {
    let mut rng = rand::rng();
    let len = if xray_compat {
        rng.random_range(256..2048)
    } else {
        rng.random_range(1..80)
    };
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

fn validate_tcp_request_padding_len(padding_len: u64) -> std::io::Result<usize> {
    if padding_len > MAX_TCP_REQUEST_PADDING_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "padding length too large",
        ));
    }
    usize::try_from(padding_len)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "padding length too large"))
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

fn build_tcp_response(
    status: u8,
    message: &str,
    xray_compat: bool,
) -> std::io::Result<Vec<u8>> {
    let message_bytes = message.as_bytes();
    let mut rng = rand::rng();
    let padding_len = if xray_compat {
        rng.random_range(128..1024usize)
    } else {
        rng.random_range(0..=63usize)
    };
    let mut buf = Vec::with_capacity(1 + message_bytes.len() + padding_len + 16);
    buf.push(status);
    push_varint(&mut buf, message_bytes.len() as u64)?;
    buf.extend_from_slice(message_bytes);
    push_varint(&mut buf, padding_len as u64)?;
    let padding_start = buf.len();
    if xray_compat {
        buf.extend_from_slice(
            Alphanumeric.sample_string(&mut rng, padding_len).as_bytes(),
        );
    } else if padding_len > 0 {
        buf.resize(padding_start + padding_len, 0);
        rng.fill(&mut buf[padding_start..]);
    }
    Ok(buf)
}

async fn send_tcp_response(
    stream: &mut quinn::SendStream,
    status: u8,
    message: &str,
    xray_compat: bool,
) -> std::io::Result<()> {
    let buf = build_tcp_response(status, message, xray_compat)?;
    stream.write_all(&buf).await.map_err(Error::other)?;
    stream.flush().await.map_err(Error::other)
}

async fn drive_udp_datagrams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    runtime: RuntimeState,
    udp_idle_timeout: Option<Duration>,
) -> std::io::Result<()> {
    let mut sessions: HashMap<u32, UdpSession> = HashMap::new();
    let mut cleanup_interval = udp_idle_timeout.map(|_| {
        let start = tokio::time::Instant::now() + UDP_IDLE_CLEANUP_INTERVAL;
        let mut interval =
            tokio::time::interval_at(start, UDP_IDLE_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval
    });
    let peer_addr = connection.remote_address();
    let identity = auth_ctx
        .client
        .email
        .clone()
        .unwrap_or(auth_ctx.client.password.clone());
    let base_context = TrafficContext::new("hysteria2")
        .with_identity(identity.clone())
        .with_inbound_tag((*inbound_tag).clone())
        .with_client_ip(peer_addr.ip());

    loop {
        let data_result = loop {
            if let (Some(interval), Some(timeout)) =
                (cleanup_interval.as_mut(), udp_idle_timeout)
            {
                tokio::select! {
                    result = connection.read_datagram() => break result,
                    _ = interval.tick() => {
                        prune_idle_udp_sessions(
                            &mut sessions,
                            Instant::now(),
                            timeout,
                        );
                    }
                }
            } else {
                break connection.read_datagram().await;
            }
        };

        let data = match data_result {
            Ok(data) => data,
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed { .. }) => return Ok(()),
            Err(err) => return Err(Error::other(err)),
        };

        let (address_start, payload_start) =
            match udp_datagram_address_bounds(&data, auth_ctx.xray_compat) {
                Ok(bounds) => bounds,
                Err(err) => {
                    debug!("Ignoring malformed hysteria2 UDP datagram: {}", err);
                    continue;
                }
            };

        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

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

        let session = match sessions.entry(session_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let remote_addr = match resolve_single_address(
                    &resolver,
                    &remote_location,
                )
                .await
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(
                            "Failed to resolve hysteria2 UDP destination {}: {}",
                            remote_location, err
                        );
                        continue;
                    }
                };
                let session = create_udp_session(
                    session_id,
                    remote_location.clone(),
                    remote_addr,
                    connection.clone(),
                    base_context.clone(),
                )
                .await?;
                entry.insert(session)
            }
        };
        if remote_location != session.last_location {
            let updated_addr = match resolve_single_address(
                &resolver,
                &remote_location,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(
                        "Failed to resolve updated hysteria2 UDP destination {}: {}",
                        remote_location, err
                    );
                    continue;
                }
            };
            session.last_location = remote_location.clone();
            session.last_socket_addr = updated_addr;
        }

        let complete_payload = if fragment_count <= 1 {
            // Xray's Defragger treats FragCount 0 and 1 as complete datagrams.
            // Keep accepting the legacy zero value in Xray compatibility mode,
            // while shoes/native mode retains shoes' stricter zero-fragment rejection.
            if !accept_unfragmented_udp_datagram(
                fragment_count,
                auth_ctx.xray_compat,
            ) {
                warn!(
                    "Ignoring hysteria2 UDP packet {} with zero fragments",
                    session_id
                );
                continue;
            }
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

            let entry = session
                .fragments
                .get_mut(&packet_id)
                .expect("inserted hysteria2 fragment must be cached");

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
                let updated_addr = match resolve_single_address(
                    &resolver,
                    &remembered_location,
                )
                .await
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(
                            "Failed to resolve fragmented hysteria2 UDP destination {}: {}",
                            remembered_location, err
                        );
                        continue;
                    }
                };
                session.last_location = remembered_location;
                session.last_socket_addr = updated_addr;
            }

            assembled.freeze()
        };

        session.mark_active();

        let mut route_input = connection_routing_input(
            inbound_tag.as_str(),
            &identity,
            3,
            peer_addr,
            session.last_socket_addr,
            &session.last_location,
        );
        route_input.vless_route = auth_ctx.vless_route;
        let action = match select_direct_outbound(&runtime, &route_input, "udp") {
            Ok(action) => action,
            Err(err) => {
                warn!(
                    "Failed to route hysteria2 UDP payload for session {}: {}",
                    session_id, err
                );
                continue;
            }
        };
        let mut traffic_context = session.base_context.clone();

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
        }

        session
            .response_contexts
            .write()
            .expect("hysteria2 UDP contexts lock poisoned")
            .insert(
                session.last_socket_addr,
                UdpResponseContext {
                    traffic_context: traffic_context.clone(),
                    client_location: session.last_location.clone(),
                },
            );

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
                sessions.remove(&session_id);
            }
        }
    }
}

fn prune_idle_udp_sessions(
    sessions: &mut HashMap<u32, UdpSession>,
    now: Instant,
    timeout: Duration,
) {
    sessions.retain(|session_id, session| {
        let active = !udp_session_is_idle(session.last_active(), now, timeout);
        if !active {
            debug!(
                "hysteria2 UDP session {} expired after {:?} of inactivity",
                session_id, timeout
            );
        }
        active
    });
}

fn udp_session_is_idle(
    last_active: Instant,
    now: Instant,
    timeout: Duration,
) -> bool {
    now.saturating_duration_since(last_active) > timeout
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    fragments: LruCache<u16, FragmentedPacket>,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    last_active: Arc<RwLock<Instant>>,
    base_context: TrafficContext,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, UdpResponseContext>>>,
    remote_task: tokio::task::JoinHandle<()>,
    _connection_guard: ConnectionGuard,
}

impl UdpSession {
    fn mark_active(&self) {
        *self
            .last_active
            .write()
            .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
    }

    fn last_active(&self) -> Instant {
        *self
            .last_active
            .read()
            .expect("hysteria2 UDP activity lock poisoned")
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.remote_task.abort();
    }
}

#[derive(Clone)]
struct UdpResponseContext {
    traffic_context: TrafficContext,
    client_location: NetLocation,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

fn hysteria2_fragment_cache() -> LruCache<u16, FragmentedPacket> {
    LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap())
}

fn new_hysteria2_socket2_udp_socket() -> std::io::Result<socket2::Socket> {
    let socket = new_socket2_udp_socket(true, None, None, false)?;
    socket.set_only_v6(false)?;
    let bind_addr: SocketAddr =
        "[::]:0".parse().expect("valid IPv6 wildcard address");
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    Ok(socket)
}

fn new_hysteria2_udp_socket() -> std::io::Result<UdpSocket> {
    let std_socket: std::net::UdpSocket = new_hysteria2_socket2_udp_socket()?.into();
    UdpSocket::from_std(std_socket)
}

fn normalize_hysteria2_udp_peer_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::from((ip, addr.port())))
            .unwrap_or(SocketAddr::V6(addr)),
        SocketAddr::V4(_) => addr,
    }
}

async fn create_udp_session(
    session_id: u32,
    remote_location: NetLocation,
    remote_addr: SocketAddr,
    connection: quinn::Connection,
    base_context: TrafficContext,
) -> std::io::Result<UdpSession> {
    // Match shoes: one Hysteria UDP session can change destination address
    // families, so keep a dual-stack socket instead of binding to the family
    // of the first destination.
    let socket = Arc::new(new_hysteria2_udp_socket()?);
    let socket_for_task = socket.clone();
    let connection_for_task = connection.clone();
    let response_contexts = Arc::new(RwLock::new(HashMap::new()));
    let contexts_for_task = response_contexts.clone();
    let last_active = Arc::new(RwLock::new(Instant::now()));
    let activity_for_task = last_active.clone();
    let fallback_context = base_context.clone();
    let connection_guard = register_connection(Some(&base_context));

    let remote_task = tokio::spawn(async move {
        if let Err(err) = run_udp_remote_to_local_loop(
            session_id,
            connection_for_task,
            socket_for_task,
            contexts_for_task,
            activity_for_task,
            fallback_context,
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
        fragments: hysteria2_fragment_cache(),
        last_location: remote_location,
        last_socket_addr: remote_addr,
        last_active,
        base_context,
        response_contexts,
        remote_task,
        _connection_guard: connection_guard,
    })
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, UdpResponseContext>>>,
    last_active: Arc<RwLock<Instant>>,
    fallback_context: TrafficContext,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| Error::other("peer does not support datagrams"))?;

    let mut next_packet_id: u16 = 0;
    let mut buf = vec![0u8; 65535];
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) =
            socket.recv_from(&mut buf).await.map_err(|err| {
                Error::other(format!(
                    "failed to receive hysteria2 UDP payload: {}",
                    err
                ))
            })?;
        let src_addr = normalize_hysteria2_udp_peer_addr(src_addr);
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }
        let response_context = response_contexts
            .read()
            .expect("hysteria2 UDP contexts lock poisoned")
            .get(&src_addr)
            .cloned();
        let (traffic_context, client_address) = match response_context {
            Some(context) => {
                (context.traffic_context, context.client_location.to_string())
            }
            None => (fallback_context.clone(), src_addr.to_string()),
        };

        let address_bytes = Bytes::from(client_address.into_bytes());
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

        *last_active
            .write()
            .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
        record_transfer(Some(traffic_context), 0, payload_len as u64);
        next_packet_id = next_packet_id.wrapping_add(1);
    }
}

fn accept_unfragmented_udp_datagram(fragment_count: u8, xray_compat: bool) -> bool {
    fragment_count == 1 || (fragment_count == 0 && xray_compat)
}

fn udp_datagram_address_bounds(
    data: &[u8],
    xray_compat: bool,
) -> std::io::Result<(usize, usize)> {
    if data.len() < 9 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "hysteria2 datagram too short",
        ));
    }

    let (address_len, varint_len) = decode_varint_from_slice(&data[8..])?;
    if address_len == 0 || address_len > MAX_ADDRESS_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 UDP address length: {address_len}"),
        ));
    }

    let address_start = 8 + varint_len;
    let payload_start = address_start.checked_add(address_len).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "hysteria2 UDP address length overflow",
        )
    })?;
    if data.len() < payload_start {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "hysteria2 datagram truncated before payload",
        ));
    }
    if xray_compat && data.len() == payload_start {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "xray hysteria2 UDP datagram requires a non-empty payload",
        ));
    }

    Ok((address_start, payload_start))
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
    use std::{future::pending, io::ErrorKind, time::Instant};

    use super::*;
    use crate::config::server_config::Hysteria2Client;

    fn hysteria2_config(
        congestion: Option<&str>,
        brutal_up: Option<u64>,
        brutal_down: Option<u64>,
    ) -> Hysteria2ServerConfig {
        serde_json::from_value(serde_json::json!({
            "clients": [{"password": "secret"}],
            "xrayCongestion": congestion,
            "xrayBrutalUp": brutal_up,
            "xrayBrutalDown": brutal_down
        }))
        .expect("valid Hysteria2 test config")
    }

    fn auth_request(auth: &str, uri: &str) -> Request<()> {
        Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(AUTH_HEADER, auth)
            .body(())
            .expect("valid Hysteria2 auth request")
    }

    #[test]
    fn auth_timeout_matches_xray_and_shoes() {
        assert_eq!(configured_auth_timeout(false), Some(AUTH_TIMEOUT));
        assert_eq!(configured_auth_timeout(true), None);
    }

    #[tokio::test]
    async fn authentication_times_out_after_shoes_window() {
        let started = Instant::now();
        let err = await_authentication(pending::<std::io::Result<()>>(), false)
            .await
            .expect_err("pending shoes Hysteria2 auth must time out");

        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() >= AUTH_TIMEOUT);
    }

    #[test]
    fn tcp_request_timeout_is_xray_only() {
        assert_eq!(
            configured_tcp_request_timeout(true),
            Some(TCP_REQUEST_TIMEOUT)
        );
        assert_eq!(configured_tcp_request_timeout(false), None);
    }

    #[test]
    fn auth_rejections_use_not_found_like_shoes() {
        assert_eq!(
            auth_reject_status(&AuthReject::NotAuthRequest),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            auth_reject_status(&AuthReject::Unauthorized("bad auth")),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn auth_password_matches_xray_and_shoes_exactly() {
        let clients = vec![Hysteria2Client {
            password: " spaced-secret ".to_string(),
            email: None,
            xray_uuid_route: false,
        }];

        validate_auth_request(
            auth_request(" spaced-secret ", AUTH_URI),
            &clients,
            false,
        )
        .expect("exact Xray Hysteria auth should match");
        assert!(matches!(
            validate_auth_request(
                auth_request("spaced-secret", AUTH_URI),
                &clients,
                false,
            ),
            Err(AuthReject::Unauthorized("password mismatch"))
        ));
    }

    #[test]
    fn xray_uuid_user_auth_masks_route_bytes_but_shoes_id_stays_exact() {
        let xray_clients = vec![
            Hysteria2Client {
                password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
                email: Some("shadowed@example.com".to_string()),
                xray_uuid_route: true,
            },
            Hysteria2Client {
                password: "00112233-4455-1234-8899-aabbccddeeff".to_string(),
                email: Some("route-user@example.com".to_string()),
                xray_uuid_route: true,
            },
        ];
        let routed = validate_auth_request(
            auth_request("00112233-4455-abcd-8899-aabbccddeeff", AUTH_URI),
            &xray_clients,
            true,
        )
        .expect("Xray UUID auth should ignore route bytes during lookup");
        assert_eq!(
            routed.client.email.as_deref(),
            Some("route-user@example.com")
        );
        assert_eq!(routed.vless_route, 0xabcd);

        let shoes_clients = vec![Hysteria2Client {
            password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            email: None,
            xray_uuid_route: false,
        }];
        assert!(matches!(
            validate_auth_request(
                auth_request("00112233-4455-abcd-8899-aabbccddeeff", AUTH_URI),
                &shoes_clients,
                false,
            ),
            Err(AuthReject::Unauthorized("password mismatch"))
        ));
    }

    #[test]
    fn malformed_cc_rx_does_not_reject_authentication() {
        let clients = vec![Hysteria2Client {
            password: "secret".to_string(),
            email: None,
            xray_uuid_route: false,
        }];
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_URI)
            .header(AUTH_HEADER, "secret")
            .header(CLIENT_CC_RX_HEADER, "not-a-number")
            .body(())
            .expect("valid Hysteria2 auth request");

        let auth = validate_auth_request(request, &clients, true)
            .expect("malformed CC-RX should be treated as zero like Xray");
        assert_eq!(auth.client_rx_limit, None);
    }

    #[test]
    fn xray_congestion_tx_matches_hysteria_negotiation() {
        let shoes = hysteria2_config(None, None, None);
        assert_eq!(
            resolve_congestion_tx_bps(&shoes, Some(300_000), 200_000),
            200_000
        );

        for mode in ["reno", "bbr"] {
            let config = hysteria2_config(Some(mode), Some(500_000), None);
            assert_eq!(
                resolve_congestion_tx_bps(&config, Some(300_000), 200_000),
                0
            );
        }

        let brutal = hysteria2_config(Some("brutal"), Some(500_000), None);
        assert_eq!(
            resolve_congestion_tx_bps(&brutal, Some(300_000), 0),
            300_000
        );
        assert_eq!(resolve_congestion_tx_bps(&brutal, None, 0), 0);

        let forced = hysteria2_config(Some("force-brutal"), Some(500_000), None);
        assert_eq!(resolve_congestion_tx_bps(&forced, None, 0), 500_000);
    }

    #[test]
    fn xray_defaults_without_finalmask_ignore_deprecated_bandwidth() {
        let config: Hysteria2ServerConfig =
            serde_json::from_value(serde_json::json!({
                "clients": [{"password": "secret"}],
                "bandwidth": {"up": 500000, "down": 750000},
                "xrayCompat": true
            }))
            .expect("valid Xray-default Hysteria2 config");

        assert_eq!(
            resolve_bandwidth_settings(&config, Some(300_000)),
            (300_000, 0, false)
        );
        assert_eq!(
            resolve_congestion_tx_bps(&config, Some(300_000), 200_000),
            0
        );
    }

    #[test]
    fn xray_brutal_down_replaces_shoes_bandwidth_response() {
        let config = hysteria2_config(Some("brutal"), Some(500_000), Some(750_000));
        assert_eq!(
            resolve_bandwidth_settings(&config, Some(300_000)),
            (300_000, 750_000, false)
        );
    }

    #[test]
    fn xray_udp_idle_timeout_uses_strict_expiry_boundary() {
        let last_active = Instant::now();
        let timeout = Duration::from_secs(2);
        assert!(!udp_session_is_idle(
            last_active,
            last_active + timeout,
            timeout
        ));
        assert!(udp_session_is_idle(
            last_active,
            last_active + timeout + Duration::from_millis(1),
            timeout
        ));
    }

    #[test]
    fn auth_requires_exact_shoes_uri() {
        let clients = vec![Hysteria2Client {
            password: "secret".to_string(),
            email: None,
            xray_uuid_route: false,
        }];
        assert!(
            validate_auth_request(
                auth_request("secret", AUTH_URI),
                &clients,
                false,
            )
            .is_ok()
        );
        for uri in [
            "https://hysteria/auth?extra=1",
            "https://example.com/auth",
            "http://hysteria/auth",
        ] {
            assert!(
                matches!(
                    validate_auth_request(
                        auth_request("secret", uri),
                        &clients,
                        false,
                    ),
                    Err(AuthReject::NotAuthRequest)
                ),
                "unexpected auth URI accepted: {uri}"
            );
        }
    }

    #[test]
    fn xray_auth_uri_ignores_query_while_shoes_stays_exact() {
        let clients = vec![Hysteria2Client {
            password: "secret".to_string(),
            email: None,
            xray_uuid_route: false,
        }];
        let query_uri = "https://hysteria/auth?extra=1";

        validate_auth_request(auth_request("secret", query_uri), &clients, true)
            .expect("Xray matches Hysteria auth by host and path");
        assert!(matches!(
            validate_auth_request(
                auth_request("secret", query_uri),
                &clients,
                false,
            ),
            Err(AuthReject::NotAuthRequest)
        ));
    }

    #[tokio::test]
    async fn udp_session_socket_is_dual_stack_like_shoes() {
        let socket = new_hysteria2_socket2_udp_socket()
            .expect("create dual-stack UDP socket");
        assert!(
            socket
                .local_addr()
                .expect("dual-stack socket address")
                .as_socket()
                .expect("IP socket address")
                .is_ipv6()
        );
        assert!(!socket.only_v6().expect("read IPV6_V6ONLY"));

        let std_socket: std::net::UdpSocket = socket.into();
        let socket =
            UdpSocket::from_std(std_socket).expect("convert dual-stack UDP socket");
        let ipv4 = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind IPv4 UDP receiver");

        socket
            .send_to(b"v4", ipv4.local_addr().expect("IPv4 receiver address"))
            .await
            .expect("dual-stack socket should send to IPv4");

        let mut buf = [0u8; 2];
        let (len, sender) =
            tokio::time::timeout(Duration::from_secs(1), ipv4.recv_from(&mut buf))
                .await
                .expect("IPv4 receive should not time out")
                .expect("receive IPv4 datagram");
        assert_eq!(&buf[..len], b"v4");

        ipv4.send_to(b"ok", sender)
            .await
            .expect("reply to dual-stack socket");
        let (len, source) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
                .await
                .expect("dual-stack reply should not time out")
                .expect("receive IPv4 reply on dual-stack socket");
        assert_eq!(&buf[..len], b"ok");
        assert_eq!(
            normalize_hysteria2_udp_peer_addr(source),
            ipv4.local_addr().expect("IPv4 receiver address")
        );
    }

    #[test]
    fn fragment_cache_matches_shoes_bound() {
        let mut cache = hysteria2_fragment_cache();
        let remote_location = NetLocation::from_str("127.0.0.1:53", None)
            .expect("valid fragment test location");

        for packet_id in 0..=MAX_FRAGMENT_CACHE_SIZE as u16 {
            cache.put(
                packet_id,
                FragmentedPacket {
                    fragment_count: 2,
                    fragment_received: 1,
                    packet_len: 1,
                    received: vec![Some(Bytes::from_static(b"x")), None],
                    remote_location: remote_location.clone(),
                },
            );
        }

        assert_eq!(cache.len(), MAX_FRAGMENT_CACHE_SIZE);
        assert!(
            !cache.contains(&0),
            "oldest incomplete packet should be evicted"
        );
        assert!(cache.contains(&(MAX_FRAGMENT_CACHE_SIZE as u16)));
    }

    #[test]
    fn zero_fragment_udp_datagrams_match_xray_and_shoes_semantics() {
        assert!(accept_unfragmented_udp_datagram(0, true));
        assert!(!accept_unfragmented_udp_datagram(0, false));
        assert!(accept_unfragmented_udp_datagram(1, true));
        assert!(accept_unfragmented_udp_datagram(1, false));
        assert!(!accept_unfragmented_udp_datagram(2, true));
        assert!(!accept_unfragmented_udp_datagram(2, false));
    }

    #[test]
    fn malformed_udp_datagram_bounds_are_rejected_without_panicking() {
        assert!(udp_datagram_address_bounds(&[], false).is_err());
        assert!(udp_datagram_address_bounds(&[0; 8], false).is_err());

        let mut truncated_varint = vec![0; 9];
        truncated_varint[8] = 0x40;
        assert!(udp_datagram_address_bounds(&truncated_varint, false).is_err());

        let mut truncated_address = vec![0; 9];
        truncated_address[8] = 5;
        assert!(udp_datagram_address_bounds(&truncated_address, false).is_err());

        let mut valid = vec![0; 8];
        valid.push(3);
        valid.extend_from_slice(b"dns");
        valid.extend_from_slice(b"payload");
        assert_eq!(
            udp_datagram_address_bounds(&valid, false)
                .expect("valid UDP datagram bounds"),
            (9, 12)
        );
        assert_eq!(
            udp_datagram_address_bounds(&valid, true)
                .expect("valid Xray UDP datagram bounds"),
            (9, 12)
        );
    }

    #[test]
    fn empty_udp_payload_matches_xray_and_shoes_semantics() {
        let mut empty_payload = vec![0; 8];
        empty_payload.push(3);
        empty_payload.extend_from_slice(b"dns");

        assert_eq!(
            udp_datagram_address_bounds(&empty_payload, false)
                .expect("shoes accepts an empty UDP payload"),
            (9, 12)
        );
        assert!(
            udp_datagram_address_bounds(&empty_payload, true).is_err(),
            "Xray rejects UDP datagrams without payload bytes"
        );
    }

    #[test]
    fn shoes_padding_bounds_apply_to_auth_and_tcp_frames() {
        assert_eq!(MAX_ADDRESS_LEN, 2048);

        for _ in 0..64 {
            let padding = random_auth_padding(false);
            assert!((1..80).contains(&padding.len()));
            assert!(padding.is_ascii());
        }

        assert_eq!(
            validate_tcp_request_padding_len(MAX_TCP_REQUEST_PADDING_LEN)
                .expect("maximum Shoes request padding should pass"),
            MAX_TCP_REQUEST_PADDING_LEN as usize
        );
        assert!(
            validate_tcp_request_padding_len(MAX_TCP_REQUEST_PADDING_LEN + 1)
                .is_err()
        );

        for _ in 0..64 {
            let frame = build_tcp_response(TCP_SUCCESS_STATUS, "ok", false)
                .expect("TCP response frame should build");
            assert_eq!(frame[0], TCP_SUCCESS_STATUS);
            let (message_len, message_varint_len) =
                decode_varint_from_slice(&frame[1..])
                    .expect("message length varint");
            assert_eq!(message_len, 2);
            let message_start = 1 + message_varint_len;
            assert_eq!(&frame[message_start..message_start + message_len], b"ok");
            let padding_start = message_start + message_len;
            let (padding_len, padding_varint_len) =
                decode_varint_from_slice(&frame[padding_start..])
                    .expect("padding length varint");
            assert!(padding_len <= 63);
            assert_eq!(
                frame.len(),
                padding_start + padding_varint_len + padding_len
            );
        }
    }

    #[test]
    fn xray_padding_bounds_and_alphabet_match_reference() {
        for _ in 0..64 {
            let padding = random_auth_padding(true);
            assert!((256..2048).contains(&padding.len()));
            assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));

            let frame = build_tcp_response(TCP_SUCCESS_STATUS, "ok", true)
                .expect("Xray TCP response frame should build");
            let (message_len, message_varint_len) =
                decode_varint_from_slice(&frame[1..])
                    .expect("message length varint");
            let padding_start = 1 + message_varint_len + message_len;
            let (padding_len, padding_varint_len) =
                decode_varint_from_slice(&frame[padding_start..])
                    .expect("padding length varint");
            assert!((128..1024).contains(&padding_len));
            let padding_bytes = &frame[padding_start + padding_varint_len
                ..padding_start + padding_varint_len + padding_len];
            assert!(
                padding_bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric())
            );
        }
    }
}
