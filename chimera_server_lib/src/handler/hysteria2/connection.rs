use std::{
    collections::{HashMap, hash_map::Entry},
    convert::TryFrom,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes, BytesMut};
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
    xray_proxy_transport: Option<Arc<XrayProxyTransport>>,
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
        auth_hysteria2_connection(
            &mut h3_conn,
            config.as_ref(),
            tx_bps.clone(),
            xray_proxy_transport.as_deref(),
        ),
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
    xray_proxy_transport: Option<&XrayProxyTransport>,
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
                let request_method = req.method().clone();
                let request_uri = req.uri().clone();
                let request_headers = req.headers().clone();
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
                        send_auth_reject_response(
                            &mut stream,
                            &request_method,
                            &request_uri,
                            &request_headers,
                            config,
                            xray_proxy_transport,
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
    let tcp_request_timeout = configured_tcp_request_timeout(
        auth_ctx.xray_compat,
        auth_ctx.client.level,
        &runtime,
    );
    let request = match read_tcp_request(&mut recv, tcp_request_timeout).await {
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

fn configured_tcp_request_timeout(
    xray_compat: bool,
    level: u32,
    runtime: &RuntimeState,
) -> Option<Duration> {
    xray_compat.then(|| runtime.xray_handshake_timeout_for_level(level))
}

async fn read_tcp_request(
    stream: &mut quinn::RecvStream,
    timeout: Option<Duration>,
) -> std::io::Result<TcpRequest> {
    match timeout {
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
            && req.uri().authority().map(|authority| authority.as_str())
                == Some("hysteria")
            && xray_auth_path_matches(req.uri().path())
    } else {
        req.method() == http::Method::POST && req.uri() == AUTH_URI
    };
    if !is_auth_request {
        return Err(AuthReject::NotAuthRequest);
    }

    let headers = req.headers();
    let provided = match headers.get(AUTH_HEADER) {
        Some(value) => value
            .to_str()
            .map_err(|_| AuthReject::Unauthorized("invalid auth header"))?,
        None if xray_compat => "",
        None => return Err(AuthReject::Unauthorized("missing auth header")),
    };

    let (client, vless_route) = match_hysteria_auth(provided, clients, xray_compat)
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

fn xray_auth_path_matches(path: &str) -> bool {
    const AUTH_PATH: &[u8] = b"/auth";
    let raw = path.as_bytes();
    let mut raw_index = 0usize;
    let mut decoded_index = 0usize;

    while raw_index < raw.len() {
        let byte = if raw[raw_index] == b'%' {
            if raw_index + 2 >= raw.len() {
                return false;
            }
            let Some(high) = hex_nibble(raw[raw_index + 1]) else {
                return false;
            };
            let Some(low) = hex_nibble(raw[raw_index + 2]) else {
                return false;
            };
            raw_index += 3;
            (high << 4) | low
        } else {
            let byte = raw[raw_index];
            raw_index += 1;
            byte
        };

        if AUTH_PATH.get(decoded_index).copied() != Some(byte) {
            return false;
        }
        decoded_index += 1;
    }

    decoded_index == AUTH_PATH.len()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn match_hysteria_auth(
    provided: &str,
    clients: &[Hysteria2Client],
    xray_compat: bool,
) -> Option<(Hysteria2Client, u32)> {
    // Xray consults transport-level `hysteriaSettings.auth` only while its
    // inbound user validator is empty. A dynamic AddUser therefore disables
    // the fallback until the last real user is removed again.
    let xray_has_users = xray_compat
        && clients
            .iter()
            .any(|client| !client.xray_transport_auth_fallback);

    // Chimera's shoes/native `id` credentials and Xray's transport auth
    // fallback remain exact even when they happen to look like UUIDs.
    if let Some(client) = clients
        .iter()
        .rev()
        .find(|client| {
            !client.xray_uuid_route
                && (!xray_has_users || !client.xray_transport_auth_fallback)
                && client.password == provided
        })
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

fn build_auth_success_response(
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
    xray_compat: bool,
) -> std::io::Result<Response<()>> {
    let padding = random_auth_padding(xray_compat);
    let cc_rx_value = if rx_auto {
        "auto".to_string()
    } else {
        server_rx_limit.to_string()
    };
    let mut response = Response::builder()
        .status(
            StatusCode::from_u16(SUCCESS_STATUS).expect("valid hysteria2 status"),
        )
        .header(
            UDP_SUPPORT_HEADER,
            if udp_enabled { "true" } else { "false" },
        )
        .header(CLIENT_CC_RX_HEADER, cc_rx_value.as_str())
        .header(PADDING_HEADER, &padding)
        .body(())
        .map_err(Error::other)?;
    if xray_compat {
        // Xray's quic-go response writer adds Content-Length: 0 when an
        // empty handler response completes. Shoes sends the h3 response as
        // built and therefore leaves Content-Length absent.
        response.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("0"),
        );
        xray_response_add_date(&mut response)?;
    }
    Ok(response)
}

async fn send_auth_success(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
    xray_compat: bool,
) -> std::io::Result<()> {
    let response = build_auth_success_response(
        udp_enabled,
        server_rx_limit,
        rx_auto,
        xray_compat,
    )?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

fn xray_response_add_date(response: &mut Response<()>) -> std::io::Result<()> {
    if !response.headers().contains_key(http::header::DATE) {
        let date = xray_format_http_date(std::time::SystemTime::now());
        response.headers_mut().insert(
            http::header::DATE,
            http::HeaderValue::from_str(&date).map_err(Error::other)?,
        );
    }
    Ok(())
}

fn xray_string_masquerade_response(
    method: &http::Method,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeStringConfig,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::copy_from_slice(masquerade.content.as_bytes());
    let status = if masquerade.status_code == 0 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(masquerade.status_code as u16).map_err(Error::other)?
    };
    let mut response = Response::builder()
        .status(status)
        .body(())
        .map_err(Error::other)?;
    for (name, value) in &masquerade.headers {
        let name =
            http::HeaderName::from_bytes(name.as_bytes()).map_err(Error::other)?;
        let value = http::HeaderValue::from_str(value).map_err(Error::other)?;
        response.headers_mut().insert(name, value);
    }

    xray_response_add_date(&mut response)?;

    let body_allowed = !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED);
    let written_len = if body_allowed { body.len() } else { 0 };
    if !response
        .headers()
        .contains_key(http::header::CONTENT_LENGTH)
    {
        response.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&written_len.to_string())
                .map_err(Error::other)?,
        );
    }
    if method != http::Method::HEAD
        && body_allowed
        && !body.is_empty()
        && !response.headers().contains_key(http::header::CONTENT_TYPE)
        && response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_none_or(|value| value.as_bytes().is_empty())
    {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(xray_detect_content_type(
                &body[..body.len().min(512)],
            )),
        );
    }

    Ok((response, body_allowed.then_some(body)))
}

fn auth_reject_response(
    xray_compat: bool,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if xray_compat {
        let body = Bytes::from_static(b"404 page not found\n");
        let mut response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .header(http::header::CONTENT_LENGTH, body.len().to_string())
            .body(())
            .map_err(Error::other)?;
        xray_response_add_date(&mut response)?;
        Ok((response, Some(body)))
    } else {
        // Shoes sends the h3 response exactly as built, so an empty reject
        // response does not gain an implicit Content-Length header.
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .map_err(Error::other)?;
        Ok((response, None))
    }
}

async fn send_auth_reject_response(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    config: &Hysteria2ServerConfig,
    xray_proxy_transport: Option<&XrayProxyTransport>,
) -> std::io::Result<()> {
    let (mut response, body) = if let Some(masquerade) =
        config.xray_masquerade_file.as_ref()
    {
        xray_file_masquerade_response(method, uri, request_headers, &masquerade.dir)
            .await?
    } else if let Some(masquerade) = config.xray_masquerade_proxy.as_ref() {
        let mut request_body = BytesMut::new();
        while let Some(mut data) = stream.recv_data().await.map_err(map_h3_error)? {
            request_body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        match xray_proxy_transport {
            Some(transport) => {
                xray_proxy_masquerade_response_with_transport(
                    method,
                    uri,
                    request_headers,
                    request_body.freeze(),
                    masquerade,
                    transport,
                )
                .await?
            }
            None => {
                xray_proxy_masquerade_response(
                    method,
                    uri,
                    request_headers,
                    request_body.freeze(),
                    masquerade,
                )
                .await?
            }
        }
    } else if let Some(masquerade) = config.xray_masquerade_string.as_ref() {
        xray_string_masquerade_response(method, masquerade)?
    } else {
        auth_reject_response(config.xray_compat)?
    };
    if config.xray_compat {
        xray_response_add_date(&mut response)?;
    }
    stream.send_response(response).await.map_err(map_h3_error)?;
    if method != http::Method::HEAD
        && let Some(body) = body
    {
        stream.send_data(body).await.map_err(map_h3_error)?;
    }
    stream.finish().await.map_err(map_h3_error)
}

fn xray_proxy_target_url(
    base: &str,
    uri: &http::Uri,
) -> std::io::Result<reqwest::Url> {
    let mut base_url = reqwest::Url::parse(base).map_err(Error::other)?;
    let base_query = base_url.query().map(str::to_owned);
    base_url.set_query(None);
    base_url.set_fragment(None);
    if base_url.has_authority() {
        let _ = base_url.set_username("");
        let _ = base_url.set_password(None);
    }

    let base_path_has_slash = base_url.path().ends_with('/');
    let request_path = uri.path();
    let request_path_has_slash = request_path.starts_with('/');
    let mut raw = base_url.as_str().to_string();
    match (base_path_has_slash, request_path_has_slash) {
        (true, true) => raw.push_str(&request_path[1..]),
        (false, false) => {
            raw.push('/');
            raw.push_str(request_path);
        }
        _ => raw.push_str(request_path),
    }
    let mut target = reqwest::Url::parse(&raw).map_err(Error::other)?;
    let request_query = uri.query().map(xray_proxy_clean_query);
    let query = match (base_query.as_deref(), request_query.as_deref()) {
        (Some(base), Some(request)) if !base.is_empty() && !request.is_empty() => {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_string()),
        _ => None,
    };
    if query.is_none() && uri.query() == Some("") {
        target.set_query(Some(""));
    } else {
        target.set_query(query.as_deref());
    }
    Ok(target)
}

fn xray_proxy_clean_query(value: &str) -> String {
    let parameter_count = value
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b'&')
        .count()
        + 1;
    let needs_cleaning = parameter_count > 10_000
        || value.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b';'
                || (*byte == b'%'
                    && (index + 2 >= value.len()
                        || !value.as_bytes()[index + 1].is_ascii_hexdigit()
                        || !value.as_bytes()[index + 2].is_ascii_hexdigit()))
        });
    if !needs_cleaning {
        return value.to_string();
    }

    let mut pairs = std::collections::BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    for field in value.as_bytes().split(|byte| *byte == b'&') {
        if field.contains(&b';') || field.is_empty() {
            continue;
        }
        let (key, value) = match field.iter().position(|byte| *byte == b'=') {
            Some(index) => (&field[..index], &field[index + 1..]),
            None => (field, &[][..]),
        };
        let (Some(key), Some(value)) = (
            xray_proxy_query_unescape(key),
            xray_proxy_query_unescape(value),
        ) else {
            continue;
        };
        pairs.entry(key).or_default().push(value);
    }

    let mut clean = String::new();
    for (key, values) in pairs {
        for value in values {
            if !clean.is_empty() {
                clean.push('&');
            }
            xray_proxy_query_escape(&mut clean, &key);
            clean.push('=');
            xray_proxy_query_escape(&mut clean, &value);
        }
    }
    clean
}

fn xray_proxy_query_unescape(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = *value.get(index + 1)?;
                let low = *value.get(index + 2)?;
                decoded.push((xray_proxy_hex(high)? << 4) | xray_proxy_hex(low)?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    Some(decoded)
}

fn xray_proxy_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn xray_proxy_query_escape(output: &mut String, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            b' ' => output.push('+'),
            _ => {
                output.push('%');
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
}

fn xray_proxy_hop_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn xray_proxy_forwarding_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto"
    )
}

fn xray_proxy_supports_trailers(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::TE).iter().any(|value| {
        xray_proxy_header_value_contains_token(value.as_bytes(), b"trailers", false)
    })
}

fn xray_proxy_header_value_contains_token(
    value: &[u8],
    token: &[u8],
    trim_ascii_space: bool,
) -> bool {
    value.split(|byte| *byte == b',').any(|part| {
        xray_proxy_trim_header_token(part, trim_ascii_space)
            .eq_ignore_ascii_case(token)
    })
}

fn xray_proxy_trim_header_token(mut value: &[u8], trim_ascii_space: bool) -> &[u8] {
    let is_space = |byte: u8| {
        matches!(byte, b' ' | b'\t')
            || (trim_ascii_space && matches!(byte, b'\n' | b'\r'))
    };
    while value.first().copied().is_some_and(is_space) {
        value = &value[1..];
    }
    while value.last().copied().is_some_and(is_space) {
        value = &value[..value.len() - 1];
    }
    value
}

fn xray_proxy_auto_gzip(method: &http::Method, headers: &http::HeaderMap) -> bool {
    *method != http::Method::HEAD
        && headers
            .get(http::header::ACCEPT_ENCODING)
            .is_none_or(|value| value.as_bytes().is_empty())
        && headers
            .get(http::header::RANGE)
            .is_none_or(|value| value.as_bytes().is_empty())
}

fn xray_proxy_connection_header(
    name: &http::HeaderName,
    headers: &http::HeaderMap,
) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            xray_proxy_header_value_contains_token(
                value.as_bytes(),
                name.as_str().as_bytes(),
                true,
            )
        })
}

pub(crate) struct XrayProxyTransport {
    client: reqwest::Client,
}

impl XrayProxyTransport {
    fn new(insecure: bool) -> std::io::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .tls_danger_accept_invalid_certs(insecure)
            .no_gzip()
            .pool_max_idle_per_host(2)
            .build()
            .map_err(Error::other)?;
        Ok(Self { client })
    }
}

fn xray_proxy_validate_target_url(value: &str) -> std::io::Result<()> {
    if value.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains a control character",
        ));
    }

    let (without_fragment, fragment) = value.split_once('#').unwrap_or((value, ""));
    if !xray_proxy_valid_percent_escapes(fragment) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains an invalid fragment escape",
        ));
    }
    let main = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(main, _)| main);
    let opaque = main.find(':').is_some_and(|colon| {
        xray_proxy_valid_scheme(&main[..colon])
            && !main[colon + 1..].starts_with('/')
    });
    if !opaque && !xray_proxy_valid_percent_escapes(main) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains an invalid escape",
        ));
    }
    Ok(())
}

fn xray_proxy_valid_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
}

fn xray_proxy_valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    true
}

pub(crate) fn build_xray_proxy_transport(
    masquerade: Option<
        &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    >,
) -> std::io::Result<Option<Arc<XrayProxyTransport>>> {
    masquerade
        .map(|masquerade| {
            xray_proxy_validate_target_url(&masquerade.url)?;
            XrayProxyTransport::new(masquerade.insecure).map(Arc::new)
        })
        .transpose()
}

fn xray_proxy_bad_gateway_response() -> std::io::Result<(Response<()>, Option<Bytes>)>
{
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(())
        .map_err(Error::other)?;
    Ok((response, None))
}

async fn xray_proxy_masquerade_response(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    body: Bytes,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let transport = XrayProxyTransport::new(masquerade.insecure)?;
    xray_proxy_masquerade_response_with_transport(
        method,
        uri,
        request_headers,
        body,
        masquerade,
        &transport,
    )
    .await
}

async fn xray_proxy_masquerade_response_with_transport(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    body: Bytes,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    transport: &XrayProxyTransport,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let target = match xray_proxy_target_url(&masquerade.url, uri) {
        Ok(target) => target,
        Err(err) => {
            debug!(error = %err, url = %masquerade.url, "Xray proxy masquerade target cannot be forwarded");
            return xray_proxy_bad_gateway_response();
        }
    };
    let auto_gzip = xray_proxy_auto_gzip(method, request_headers);
    let mut request = transport.client.request(method.clone(), target);
    for (name, value) in request_headers {
        if !xray_proxy_hop_header(name)
            && !xray_proxy_connection_header(name, request_headers)
            && !xray_proxy_forwarding_header(name)
            && name != http::header::HOST
        {
            request = request.header(name, value);
        }
    }
    if auto_gzip {
        request = request.header(http::header::ACCEPT_ENCODING, "gzip");
    }
    if xray_proxy_supports_trailers(request_headers) {
        request = request.header(http::header::TE, "trailers");
    }
    if !masquerade.rewrite_host
        && let Some(authority) = uri.authority()
    {
        request = request.header(http::header::HOST, authority.as_str());
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let upstream = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            debug!(error = %err, url = %masquerade.url, "Xray proxy masquerade upstream request failed");
            return xray_proxy_bad_gateway_response();
        }
    };
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    let mut body = upstream.bytes().await.map_err(Error::other)?;
    if auto_gzip
        && headers
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"))
    {
        let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded)
            .map_err(Error::other)?;
        body = Bytes::from(decoded);
        headers.remove(http::header::CONTENT_ENCODING);
        headers.remove(http::header::CONTENT_LENGTH);
    }
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !xray_proxy_hop_header(name)
            && !xray_proxy_connection_header(name, &headers)
        {
            response = response.header(name, value);
        }
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}

async fn xray_file_masquerade_response(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    root: &str,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let Some(decoded_uri_path) = xray_file_percent_decode_path_bytes(uri.path())
    else {
        return auth_reject_response(true);
    };
    if decoded_uri_path.ends_with(b"/index.html") {
        return xray_file_redirect_response(uri, "./");
    }

    let Some(relative) =
        decode_file_masquerade_decoded_path_bytes(&decoded_uri_path, cfg!(windows))
    else {
        return auth_reject_response(true);
    };
    let mut path = PathBuf::from(root);
    if !relative.as_os_str().is_empty() {
        path.push(relative);
    }

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(err) => return xray_file_server_error_response(&err),
    };

    if metadata.is_dir() {
        let directory_modified = metadata.modified().ok();
        if !decoded_uri_path.ends_with(b"/") {
            let base = xray_file_path_base_bytes(&decoded_uri_path);
            let mut location = Vec::with_capacity(base.len() + 1);
            location.extend_from_slice(base);
            location.push(b'/');
            return xray_file_redirect_response_bytes(uri, &location);
        }
        let index = path.join("index.html");
        match tokio::fs::metadata(&index).await {
            Ok(index_metadata) if index_metadata.is_file() => path = index,
            Ok(index_metadata) if index_metadata.is_dir() => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &index,
                    index_metadata.modified().ok(),
                )
                .await;
            }
            Ok(_) => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &path,
                    directory_modified,
                )
                .await;
            }
            Err(_) => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &path,
                    directory_modified,
                )
                .await;
            }
        }
    } else if metadata.is_file() {
        if decoded_uri_path.ends_with(b"/") {
            let base = xray_file_path_base_bytes(&decoded_uri_path);
            if base.is_empty() || base == b"." {
                return xray_file_non_directory_traversal_response();
            }
            let mut location = Vec::with_capacity(base.len() + 3);
            location.extend_from_slice(b"../");
            location.extend_from_slice(base);
            return xray_file_redirect_response_bytes(uri, &location);
        }
    } else {
        return auth_reject_response(true);
    }

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(err) => return xray_file_server_error_response(&err),
    };
    let modified = metadata.modified().ok();
    let last_modified = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date);
    if let Some(status) =
        xray_file_precondition_status(method, request_headers, modified)
    {
        let mut response = Response::builder().status(status);
        if let Some(last_modified) = last_modified.as_deref() {
            response = response.header(http::header::LAST_MODIFIED, last_modified);
        }
        return Ok((response.body(()).map_err(Error::other)?, None));
    }

    let body = match tokio::fs::read(&path).await {
        Ok(body) => body,
        Err(err) => return xray_file_server_error_response(&err),
    };
    let content_type = if let Some(content_type) =
        xray_file_extension_content_type(&path)
    {
        content_type.to_string()
    } else {
        match mime_guess::from_path(&path).first() {
            Some(guessed_type) if guessed_type.type_() == mime_guess::mime::TEXT => {
                format!("{}; charset=utf-8", guessed_type.essence_str())
            }
            Some(guessed_type) => guessed_type.essence_str().to_string(),
            None => {
                xray_detect_content_type(&body[..body.len().min(512)]).to_string()
            }
        }
    };
    let range_header = request_headers
        .get(http::header::RANGE)
        .filter(|_| xray_if_range_matches(method, request_headers, modified));
    let mut ranges = match range_header {
        Some(value) => match xray_parse_ranges(value.as_bytes(), body.len()) {
            Ok(ranges) => ranges,
            Err(XrayRangeError::NoOverlap) if body.is_empty() => Vec::new(),
            Err(err) => return xray_range_error_response(err, body.len()),
        },
        None => Vec::new(),
    };
    if ranges.iter().map(|range| range.length).sum::<usize>() > body.len() {
        ranges.clear();
    }

    let (status, response_body, content_range, response_content_type) = match ranges
        .as_slice()
    {
        [] => (StatusCode::OK, Bytes::from(body), None, content_type),
        [range] => {
            let end = range.start + range.length;
            (
                StatusCode::PARTIAL_CONTENT,
                Bytes::copy_from_slice(&body[range.start..end]),
                Some(format!("bytes {}-{}/{}", range.start, end - 1, body.len())),
                content_type,
            )
        }
        _ => {
            let (multipart_body, multipart_content_type) =
                xray_multipart_ranges(&ranges, &body, &content_type);
            (
                StatusCode::PARTIAL_CONTENT,
                multipart_body,
                None,
                multipart_content_type,
            )
        }
    };

    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, response_content_type)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(
            http::header::CONTENT_LENGTH,
            response_body.len().to_string(),
        );
    if let Some(content_range) = content_range {
        response = response.header(http::header::CONTENT_RANGE, content_range);
    }
    if let Some(last_modified) = last_modified.as_deref() {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    let response = response.body(()).map_err(Error::other)?;
    Ok((response, Some(response_body)))
}

fn xray_file_non_directory_traversal_response()
-> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::from_static(b"http: attempting to traverse a non-directory\n");
    let response = Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(Error::other)?;
    Ok((response, Some(body)))
}

fn xray_file_directory_error_response(
    modified: Option<std::time::SystemTime>,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::from_static(b"Error reading directory\n");
    let mut response = Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if let Some(last_modified) = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date)
    {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}

fn xray_file_server_error_response(
    err: &std::io::Error,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) {
        return auth_reject_response(true);
    }

    let (status, body) = if err.kind() == ErrorKind::PermissionDenied {
        (
            StatusCode::FORBIDDEN,
            Bytes::from_static(b"403 Forbidden\n"),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from_static(b"500 Internal Server Error\n"),
        )
    };
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(Error::other)?;
    Ok((response, Some(body)))
}

fn xray_file_precondition_status(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    modified: Option<std::time::SystemTime>,
) -> Option<StatusCode> {
    let if_match = request_headers
        .get(http::header::IF_MATCH)
        .filter(|value| !value.as_bytes().is_empty());
    if let Some(if_match) = if_match {
        // Xray's FileServer does not set ETag, so only If-Match: * can match.
        if !xray_etag_list_has_wildcard(if_match.as_bytes()) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let Some(value) = request_headers
        .get(http::header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && !xray_modified_not_after(modified, since)
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }

    let if_none_match = request_headers
        .get(http::header::IF_NONE_MATCH)
        .filter(|value| !value.as_bytes().is_empty());
    if let Some(if_none_match) = if_none_match {
        // With no server ETag, only the wildcard matches the existing file.
        if xray_etag_list_has_wildcard(if_none_match.as_bytes()) {
            return Some(
                if matches!(*method, http::Method::GET | http::Method::HEAD) {
                    StatusCode::NOT_MODIFIED
                } else {
                    StatusCode::PRECONDITION_FAILED
                },
            );
        }
    } else if matches!(*method, http::Method::GET | http::Method::HEAD)
        && let Some(value) = request_headers
            .get(http::header::IF_MODIFIED_SINCE)
            .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && xray_modified_not_after(modified, since)
    {
        return Some(StatusCode::NOT_MODIFIED);
    }

    None
}

fn xray_is_zero_modtime(modified: std::time::SystemTime) -> bool {
    modified == std::time::UNIX_EPOCH
}

fn xray_system_time_seconds(time: std::time::SystemTime) -> i128 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i128,
        Err(err) => {
            let duration = err.duration();
            let seconds = duration.as_secs() as i128;
            if duration.subsec_nanos() == 0 {
                -seconds
            } else {
                -seconds - 1
            }
        }
    }
}

fn xray_modified_not_after(
    modified: std::time::SystemTime,
    validator: std::time::SystemTime,
) -> bool {
    xray_system_time_seconds(modified) <= xray_system_time_seconds(validator)
}

fn xray_etag_list_has_wildcard(mut value: &[u8]) -> bool {
    loop {
        while value
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            value = &value[1..];
        }
        if value.is_empty() {
            return false;
        }
        if value[0] == b',' {
            value = &value[1..];
            continue;
        }
        if value[0] == b'*' {
            return true;
        }

        let quote = if value.starts_with(b"W/\"") {
            2
        } else if value.starts_with(b"\"") {
            0
        } else {
            return false;
        };
        let mut end = None;
        for (index, byte) in value.iter().copied().enumerate().skip(quote + 1) {
            match byte {
                b'!' | b'#'..=b'~' | 0x80..=0xff => {}
                b'"' => {
                    end = Some(index + 1);
                    break;
                }
                _ => return false,
            }
        }
        let Some(end) = end else {
            return false;
        };
        value = &value[end..];
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct XrayByteRange {
    start: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XrayRangeError {
    Invalid,
    NoOverlap,
}

fn xray_if_range_matches(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    modified: Option<std::time::SystemTime>,
) -> bool {
    if !matches!(*method, http::Method::GET | http::Method::HEAD) {
        return true;
    }
    let Some(value) = request_headers.get(http::header::IF_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    // Xray's FileServer does not set an ETag, so an entity-tag If-Range can
    // never match. A date validator must match Last-Modified to the second.
    if value.trim_start().starts_with('"') || value.trim_start().starts_with("W/\"")
    {
        return false;
    }
    let Some(if_range) = xray_parse_http_date(value) else {
        return false;
    };
    modified.is_some_and(|modified| {
        modified
            .duration_since(if_range)
            .is_ok_and(|delta| delta.as_secs() == 0)
    })
}

fn xray_parse_http_date(value: &str) -> Option<std::time::SystemTime> {
    // Go's time.RFC850 maps two-digit years 69..99 to 1969..1999 and 00..68
    // to 2000..2068. httpdate instead maps 69 to 2069, so handle RFC850
    // before its fast path.
    if let Some(parsed) = xray_parse_rfc850_http_date(value) {
        return Some(parsed);
    }
    if let Ok(parsed) = httpdate::parse_http_date(value) {
        return Some(parsed);
    }

    // httpdate rejects years before 1970 and validates weekday/date
    // consistency. Go's http.ParseTime accepts pre-epoch dates and treats the
    // weekday as syntax only, so use time's calendar-date parser as fallback.
    xray_parse_http_date_with_format(
        value,
        "[weekday repr:short], [day padding:zero] [month repr:short] [year repr:full] [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT",
    )
    .or_else(|| {
        xray_parse_http_date_with_format(
            value,
            "[weekday repr:short] [month repr:short] [day padding:space] [hour padding:zero]:[minute padding:zero]:[second padding:zero] [year repr:full]",
        )
    })
}

fn xray_parse_rfc850_http_date(value: &str) -> Option<std::time::SystemTime> {
    let (weekday, rest) = value.split_once(", ")?;
    if !matches!(
        weekday,
        "Monday"
            | "Tuesday"
            | "Wednesday"
            | "Thursday"
            | "Friday"
            | "Saturday"
            | "Sunday"
    ) || rest.len() != 22
        || rest.as_bytes().get(2) != Some(&b'-')
        || rest.as_bytes().get(6) != Some(&b'-')
        || rest.as_bytes().get(9) != Some(&b' ')
    {
        return None;
    }
    let year = rest.get(7..9)?.parse::<u16>().ok()?;
    let year = if year >= 69 { 1900 + year } else { 2000 + year };
    let expanded = format!("{weekday}, {}{year:04}{}", &rest[..7], &rest[9..]);
    xray_parse_http_date_with_format(
        &expanded,
        "[weekday repr:long], [day padding:zero]-[month repr:short]-[year repr:full] [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT",
    )
}

fn xray_parse_http_date_with_format(
    value: &str,
    format: &str,
) -> Option<std::time::SystemTime> {
    let format = time::format_description::parse(format).ok()?;
    let parsed = time::PrimitiveDateTime::parse(value, &format).ok()?;
    let seconds = parsed.assume_utc().unix_timestamp();
    if seconds >= 0 {
        std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(seconds as u64))
    } else {
        std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
    }
}

fn xray_format_http_date(value: std::time::SystemTime) -> String {
    if value.duration_since(std::time::UNIX_EPOCH).is_ok() {
        return httpdate::fmt_http_date(value);
    }

    let value = time::OffsetDateTime::from(value);
    let weekday = match value.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match value.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        value.day(),
        value.year(),
        value.hour(),
        value.minute(),
        value.second(),
    )
}

fn xray_parse_ranges(
    value: &[u8],
    size: usize,
) -> Result<Vec<XrayByteRange>, XrayRangeError> {
    let value = std::str::from_utf8(value).map_err(|_| XrayRangeError::Invalid)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let Some(value) = value.strip_prefix("bytes=") else {
        return Err(XrayRangeError::Invalid);
    };
    let size_i64 = i64::try_from(size).map_err(|_| XrayRangeError::Invalid)?;
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((start, end)) = raw.split_once('-') else {
            return Err(XrayRangeError::Invalid);
        };
        let start = start.trim();
        let end = end.trim();
        let range = if start.is_empty() {
            if end.starts_with('-') {
                return Err(XrayRangeError::Invalid);
            }
            let suffix = end.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
            if suffix < 0 {
                return Err(XrayRangeError::Invalid);
            }
            let length = suffix.min(size_i64);
            let start = size_i64 - length;
            XrayByteRange {
                start: usize::try_from(start)
                    .map_err(|_| XrayRangeError::Invalid)?,
                length: usize::try_from(length)
                    .map_err(|_| XrayRangeError::Invalid)?,
            }
        } else {
            let start = start.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
            if start < 0 {
                return Err(XrayRangeError::Invalid);
            }
            if start >= size_i64 {
                no_overlap = true;
                continue;
            }
            let end = if end.is_empty() {
                size_i64 - 1
            } else {
                let end = end.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
                if start > end {
                    return Err(XrayRangeError::Invalid);
                }
                end.min(size_i64 - 1)
            };
            XrayByteRange {
                start: usize::try_from(start)
                    .map_err(|_| XrayRangeError::Invalid)?,
                length: usize::try_from(end - start + 1)
                    .map_err(|_| XrayRangeError::Invalid)?,
            }
        };
        ranges.push(range);
    }
    if no_overlap && ranges.is_empty() {
        Err(XrayRangeError::NoOverlap)
    } else {
        Ok(ranges)
    }
}

fn xray_range_error_response(
    error: XrayRangeError,
    size: usize,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let text = match error {
        XrayRangeError::Invalid => "invalid range\n",
        XrayRangeError::NoOverlap => "invalid range: failed to overlap\n",
    };
    let body = Bytes::from_static(text.as_bytes());
    let mut response = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if matches!(error, XrayRangeError::NoOverlap) {
        response =
            response.header(http::header::CONTENT_RANGE, format!("bytes */{size}"));
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}

fn xray_multipart_ranges(
    ranges: &[XrayByteRange],
    body: &[u8],
    content_type: &str,
) -> (Bytes, String) {
    let boundary = xray_multipart_boundary();
    let mut multipart = Vec::new();
    for range in ranges {
        let end = range.start + range.length;
        multipart.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        multipart.extend_from_slice(
            format!(
                "Content-Range: bytes {}-{}/{}\r\nContent-Type: {}\r\n\r\n",
                range.start,
                end.saturating_sub(1),
                body.len(),
                content_type
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(&body[range.start..end]);
        multipart.extend_from_slice(b"\r\n");
    }
    multipart.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (
        Bytes::from(multipart),
        format!("multipart/byteranges; boundary={boundary}"),
    )
}

fn xray_multipart_boundary() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let random = rand::random::<[u8; 30]>();
    let mut boundary = String::with_capacity(60);
    for byte in random {
        boundary.push(HEX[(byte >> 4) as usize] as char);
        boundary.push(HEX[(byte & 0x0f) as usize] as char);
    }
    boundary
}

fn xray_file_extension_content_type(path: &Path) -> Option<&'static str> {
    // Keep only the Go builtin MIME entries that differ from mime_guess 2.0.5.
    let extension = path.extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("com") {
        Some("application/octet-stream")
    } else if extension.eq_ignore_ascii_case("docx") {
        Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    } else if extension.eq_ignore_ascii_case("ehtml") {
        Some("text/html; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("ico") {
        Some("image/vnd.microsoft.icon")
    } else if extension.eq_ignore_ascii_case("m4a") {
        Some("audio/mp4")
    } else if extension.eq_ignore_ascii_case("mjs") {
        Some("text/javascript; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("pjp")
        || extension.eq_ignore_ascii_case("pjpeg")
    {
        Some("image/jpeg")
    } else if extension.eq_ignore_ascii_case("pptx") {
        Some(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
    } else if extension.eq_ignore_ascii_case("webm") {
        Some("audio/webm")
    } else if extension.eq_ignore_ascii_case("xbl") {
        Some("text/xml; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("xlsx") {
        Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    } else {
        None
    }
}

fn xray_detect_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(512)];
    let first_non_ws = data
        .iter()
        .position(|byte| !matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' '))
        .unwrap_or(data.len());
    let trimmed = &data[first_non_ws..];

    const HTML_SIGNATURES: &[&[u8]] = &[
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    if HTML_SIGNATURES.iter().any(|signature| {
        trimmed.len() > signature.len()
            && trimmed[..signature.len()].eq_ignore_ascii_case(signature)
            && matches!(trimmed[signature.len()], b' ' | b'>')
    }) {
        return "text/html; charset=utf-8";
    }
    if trimmed.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }

    const EXACT_SIGNATURES: &[(&[u8], &str)] = &[
        (b"%PDF-", "application/pdf"),
        (b"%!PS-Adobe-", "application/postscript"),
        (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"\x00\x00\x02\x00", "image/x-icon"),
        (b"BM", "image/bmp"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"ID3", "audio/mpeg"),
        (b"OggS\x00", "application/ogg"),
        (b"MThd\x00\x00\x00\x06", "audio/midi"),
        (b"\x1a\x45\xdf\xa3", "video/webm"),
        (b"\x00\x01\x00\x00", "font/ttf"),
        (b"OTTO", "font/otf"),
        (b"ttcf", "font/collection"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"\x1f\x8b\x08", "application/x-gzip"),
        (b"PK\x03\x04", "application/zip"),
        (b"Rar!\x1a\x07\x00", "application/x-rar-compressed"),
        (b"Rar!\x1a\x07\x01\x00", "application/x-rar-compressed"),
        (b"\x00asm", "application/wasm"),
    ];
    if let Some((_, content_type)) = EXACT_SIGNATURES
        .iter()
        .find(|(signature, _)| data.starts_with(signature))
    {
        return content_type;
    }

    if data.len() >= 4 && data.starts_with(b"\xfe\xff") {
        return "text/plain; charset=utf-16be";
    }
    if data.len() >= 4 && data.starts_with(b"\xff\xfe") {
        return "text/plain; charset=utf-16le";
    }
    if data.len() >= 4 && data.starts_with(b"\xef\xbb\xbf") {
        return "text/plain; charset=utf-8";
    }
    if data.len() >= 14 && data.starts_with(b"RIFF") && &data[8..14] == b"WEBPVP" {
        return "image/webp";
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") {
        if &data[8..12] == b"AVI " {
            return "video/avi";
        }
        if &data[8..12] == b"WAVE" {
            return "audio/wave";
        }
    }
    if data.len() >= 12 && data.starts_with(b"FORM") && &data[8..12] == b"AIFF" {
        return "audio/aiff";
    }
    if data.len() >= 36 && &data[34..36] == b"LP" {
        return "application/vnd.ms-fontobject";
    }
    if data.len() >= 12 {
        let box_size =
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if box_size >= 12
            && box_size <= data.len()
            && box_size.is_multiple_of(4)
            && &data[4..8] == b"ftyp"
            && (8..box_size)
                .step_by(4)
                .filter(|offset| *offset != 12)
                .any(|offset| data.get(offset..offset + 3) == Some(b"mp4"))
        {
            return "video/mp4";
        }
    }

    if data[first_non_ws..].iter().all(|byte| {
        !matches!(
            *byte,
            0x00..=0x08 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f
        )
    }) {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn xray_file_redirect_response(
    uri: &http::Uri,
    location: &str,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    xray_file_redirect_response_bytes(uri, location.as_bytes())
}

fn xray_file_redirect_response_bytes(
    uri: &http::Uri,
    location: &[u8],
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let mut location_with_query = Vec::with_capacity(
        location.len() + uri.query().map_or(0, |query| query.len() + 1),
    );
    location_with_query.extend_from_slice(location);
    if let Some(query) = uri.query() {
        location_with_query.push(b'?');
        location_with_query.extend_from_slice(query.as_bytes());
    }
    let location = xray_file_hex_escape_non_ascii_bytes(&location_with_query);
    let response = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(http::header::LOCATION, location)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(Error::other)?;
    Ok((response, None))
}

async fn xray_file_directory_response(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    path: &Path,
    modified: Option<std::time::SystemTime>,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if matches!(*method, http::Method::GET | http::Method::HEAD)
        && let Some(value) = request_headers
            .get(http::header::IF_MODIFIED_SINCE)
            .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && xray_modified_not_after(modified, since)
    {
        let response = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(())
            .map_err(Error::other)?;
        return Ok((response, None));
    }

    let mut read_dir = match tokio::fs::read_dir(path).await {
        Ok(read_dir) => read_dir,
        Err(err) => {
            debug!(error = %err, path = %path.display(), "Xray file masquerade directory read failed");
            return xray_file_directory_error_response(modified);
        }
    };
    let mut entries = Vec::new();
    loop {
        let entry = match read_dir.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(err) => {
                debug!(error = %err, path = %path.display(), "Xray file masquerade directory iteration failed");
                return xray_file_directory_error_response(modified);
            }
        };
        let file_type = match entry.file_type().await {
            Ok(file_type) => file_type,
            Err(err) if xray_file_directory_entry_disappeared(&err) => continue,
            Err(err) => {
                debug!(error = %err, path = %path.display(), "Xray file masquerade directory entry stat failed");
                return xray_file_directory_error_response(modified);
            }
        };
        let file_name = entry.file_name();
        let mut name = xray_file_name_bytes(&file_name);
        if file_type.is_dir() {
            name.push(b'/');
        }
        entries.push(name);
    }
    entries.sort_unstable();

    let mut body = Vec::from(
        &b"<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n"[..],
    );
    for name in entries {
        body.extend_from_slice(b"<a href=\"");
        body.extend_from_slice(xray_file_url_escape_bytes(&name).as_bytes());
        body.extend_from_slice(b"\">");
        body.extend_from_slice(&xray_file_html_escape_bytes(&name));
        body.extend_from_slice(b"</a>\n");
    }
    body.extend_from_slice(b"</pre>\n");
    let body = Bytes::from(body);
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if let Some(last_modified) = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date)
    {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    let response = response.body(()).map_err(Error::other)?;
    Ok((response, Some(body)))
}

fn xray_file_directory_entry_disappeared(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::NotFound
}

fn xray_file_name_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }

    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn xray_file_html_escape_bytes(value: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'&' => escaped.extend_from_slice(b"&amp;"),
            b'\'' => escaped.extend_from_slice(b"&#39;"),
            b'<' => escaped.extend_from_slice(b"&lt;"),
            b'>' => escaped.extend_from_slice(b"&gt;"),
            b'"' => escaped.extend_from_slice(b"&#34;"),
            byte => escaped.push(byte),
        }
    }
    escaped
}

fn xray_file_url_escape(value: &str) -> String {
    xray_file_url_escape_bytes(value.as_bytes())
}

fn xray_file_url_escape_bytes(value: &[u8]) -> String {
    let mut escaped = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'/'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            )
        {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

fn decode_file_masquerade_path(uri_path: &str) -> Option<PathBuf> {
    decode_file_masquerade_path_for_platform(uri_path, cfg!(windows))
}

fn decode_file_masquerade_path_for_platform(
    uri_path: &str,
    windows: bool,
) -> Option<PathBuf> {
    let decoded = xray_file_percent_decode_path_bytes(uri_path)?;
    decode_file_masquerade_decoded_path_bytes(&decoded, windows)
}

fn xray_file_percent_decode_path_bytes(uri_path: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(uri_path.len());
    let bytes = uri_path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_nibble(high)? << 4) | hex_nibble(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

fn decode_file_masquerade_decoded_path_bytes(
    decoded: &[u8],
    windows: bool,
) -> Option<PathBuf> {
    if windows {
        let decoded = std::str::from_utf8(decoded).ok()?;
        if decoded
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b':' | b'\\' | 0))
        {
            return None;
        }
        if decoded.split('/').any(xray_windows_reserved_path_component) {
            return None;
        }
        return xray_file_normalize_utf8_path(decoded);
    }

    #[cfg(unix)]
    {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        if decoded.contains(&0) {
            return None;
        }
        let mut normalized = PathBuf::new();
        for component in decoded.split(|byte| *byte == b'/') {
            match component {
                b"" | b"." => {}
                b".." => {
                    normalized.pop();
                }
                component => normalized.push(OsStr::from_bytes(component)),
            }
        }
        Some(normalized)
    }

    #[cfg(not(unix))]
    {
        let decoded = std::str::from_utf8(decoded).ok()?;
        xray_file_normalize_utf8_path(decoded)
    }
}

fn xray_file_normalize_utf8_path(decoded: &str) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in Path::new(decoded.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn xray_file_hex_escape_non_ascii(value: &str) -> String {
    xray_file_hex_escape_non_ascii_bytes(value.as_bytes())
}

fn xray_file_hex_escape_non_ascii_bytes(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii() {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

fn xray_file_path_base_bytes(path: &[u8]) -> &[u8] {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.rsplit(|byte| *byte == b'/').next().unwrap_or_default()
}

fn xray_windows_reserved_path_component(component: &str) -> bool {
    let upper = component.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }

    let Some(suffix) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    matches!(
        suffix,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
    )
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
                    auth_ctx.xray_compat,
                )
                .await?;
                entry.insert(session)
            }
        };
        if refresh_udp_activity_on_datagram(auth_ctx.xray_compat) {
            // Xray refreshes InterConn activity as soon as a session datagram is
            // read, before UDP parsing/defragmentation completes. In particular,
            // a stream of partial fragments must keep an active session alive.
            session.mark_active();
        }
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

            prepare_fragment_cache(
                &mut session.fragments,
                packet_id,
                fragment_count,
                auth_ctx.xray_compat,
            );

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
                handle_duplicate_fragment(
                    &mut session.fragments,
                    packet_id,
                    auth_ctx.xray_compat,
                );
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
            } = completed_fragment_packet(
                &mut session.fragments,
                packet_id,
                auth_ctx.xray_compat,
            )
            .expect("completed hysteria2 fragment packet must be cached");
            let completed_location = fragment_completion_location(
                remembered_location,
                remote_location,
                auth_ctx.xray_compat,
            );

            let mut assembled = BytesMut::with_capacity(packet_len);
            for bytes in received.into_iter().flatten() {
                assembled.extend_from_slice(&bytes);
            }

            if completed_location != session.last_location {
                let updated_addr = match resolve_single_address(
                    &resolver,
                    &completed_location,
                )
                .await
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(
                            "Failed to resolve fragmented hysteria2 UDP destination {}: {}",
                            completed_location, err
                        );
                        continue;
                    }
                };
                session.last_location = completed_location;
                session.last_socket_addr = updated_addr;
            }

            assembled.freeze()
        };

        if refresh_udp_activity_on_completed_payload(auth_ctx.xray_compat) {
            // Preserve the existing shoes/native activity point at completed
            // payload delivery; Xray has already refreshed on datagram receipt.
            session.mark_active();
        }

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
            .send_to(
                complete_payload.as_ref(),
                hysteria2_udp_send_addr(session.last_socket_addr),
            )
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

fn refresh_udp_activity_on_datagram(xray_compat: bool) -> bool {
    xray_compat
}

fn refresh_udp_activity_on_completed_payload(xray_compat: bool) -> bool {
    !xray_compat
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

#[derive(Clone)]
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

fn fragment_completion_location(
    remembered_location: NetLocation,
    current_location: NetLocation,
    xray_compat: bool,
) -> NetLocation {
    // Xray's Defragger returns the fragment that completes the packet after
    // replacing only its Data field, so the completed message keeps that
    // fragment's address. Shoes explicitly retains the first fragment's address.
    if xray_compat {
        current_location
    } else {
        remembered_location
    }
}

fn completed_fragment_packet(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    xray_compat: bool,
) -> Option<FragmentedPacket> {
    // Xray's Defragger keeps completed state until a different packet ID or
    // fragment count replaces it. Shoes removes completed packets immediately.
    if xray_compat {
        fragments.peek(&packet_id).cloned()
    } else {
        fragments.pop(&packet_id)
    }
}

fn handle_duplicate_fragment(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    xray_compat: bool,
) {
    // Xray's Defragger ignores a duplicate fragment and retains the partial
    // packet. Shoes discards the entire partial packet on a duplicate.
    if !xray_compat {
        fragments.pop(&packet_id);
    }
}

fn prepare_fragment_cache(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    fragment_count: u8,
    xray_compat: bool,
) {
    if !xray_compat {
        return;
    }

    let current_matches = fragments
        .peek(&packet_id)
        .is_some_and(|packet| packet.fragment_count == fragment_count);
    if !current_matches {
        // Xray's Defragger tracks only one in-flight packet per UDP session.
        // A new packet ID or fragment count replaces any partial assembly.
        fragments.clear();
    }
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

fn hysteria2_udp_send_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(addr) => {
            SocketAddr::from((addr.ip().to_ipv6_mapped(), addr.port()))
        }
        SocketAddr::V6(_) => addr,
    }
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
    xray_compat: bool,
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
            xray_compat,
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
    xray_compat: bool,
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
            let packet_id =
                udp_response_packet_id(&mut next_packet_id, false, xray_compat);
            let mut datagram =
                BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
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

            let packet_id =
                udp_response_packet_id(&mut next_packet_id, true, xray_compat);
            for fragment_id in 0..fragment_count {
                let start = fragment_id * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);

                let mut datagram =
                    BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
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
    }
}

fn udp_response_packet_id(
    next_packet_id: &mut u16,
    fragmented: bool,
    xray_compat: bool,
) -> u16 {
    if xray_compat {
        if fragmented {
            rand::rng().random_range(1..=u16::MAX)
        } else {
            0
        }
    } else {
        let packet_id = *next_packet_id;
        *next_packet_id = next_packet_id.wrapping_add(1);
        packet_id
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
    use std::{
        future::pending,
        io::ErrorKind,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::server_config::{
        Hysteria2Client, Hysteria2MasqueradeProxyConfig,
    };

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
    fn tcp_request_timeout_uses_xray_user_level_policy_only() {
        use crate::config::def::{PolicyConfig, PolicyLevelConfig};
        use std::collections::HashMap;

        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        assert_eq!(
            configured_tcp_request_timeout(true, 7, &runtime),
            Some(Duration::from_secs(60))
        );
        assert_eq!(configured_tcp_request_timeout(false, 7, &runtime), None);

        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                handshake: Some(2),
                ..PolicyLevelConfig::default()
            }),
        );
        runtime.replace_policy(Some(&PolicyConfig {
            levels,
            ..PolicyConfig::default()
        }));
        assert_eq!(
            configured_tcp_request_timeout(true, 7, &runtime),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            configured_tcp_request_timeout(true, 8, &runtime),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn auth_success_content_length_matches_xray_and_shoes_writers() {
        let shoes = build_auth_success_response(true, 0, false, false)
            .expect("valid shoes auth response");
        assert_eq!(shoes.status().as_u16(), SUCCESS_STATUS);
        assert!(shoes.headers().get(http::header::CONTENT_LENGTH).is_none());
        assert!(shoes.headers().get(http::header::DATE).is_none());

        let xray = build_auth_success_response(true, 0, false, true)
            .expect("valid Xray auth response");
        assert_eq!(xray.status().as_u16(), SUCCESS_STATUS);
        assert_eq!(
            xray.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("0"))
        );
        assert!(xray.headers().get(http::header::DATE).is_some());
    }

    #[test]
    fn auth_rejections_match_xray_and_shoes_default_masquerade() {
        let (shoes_response, shoes_body) =
            auth_reject_response(false).expect("valid shoes reject response");
        assert_eq!(shoes_response.status(), StatusCode::NOT_FOUND);
        assert!(
            shoes_response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .is_none()
        );
        assert!(shoes_response.headers().get(http::header::DATE).is_none());
        assert!(shoes_body.is_none());

        let (xray_response, xray_body) =
            auth_reject_response(true).expect("valid Xray reject response");
        assert_eq!(xray_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            xray_response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(
            xray_response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            xray_response.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("19"))
        );
        assert!(xray_response.headers().get(http::header::DATE).is_some());
        assert_eq!(xray_body.as_deref(), Some(&b"404 page not found\n"[..]));
    }

    #[test]
    fn auth_rejections_match_xray_string_masquerade() {
        let masquerade =
            crate::config::server_config::Hysteria2MasqueradeStringConfig {
                content: "hello from xray".to_string(),
                headers: [("x-test-header".to_string(), "present".to_string())]
                    .into_iter()
                    .collect(),
                status_code: 418,
            };
        let (response, body) =
            xray_string_masquerade_response(&http::Method::GET, &masquerade)
                .expect("valid Xray string masquerade response");
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(
            response.headers().get("x-test-header"),
            Some(&http::HeaderValue::from_static("present"))
        );
        assert!(response.headers().get(http::header::DATE).is_some());
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("15"))
        );
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(body.as_deref(), Some(&b"hello from xray"[..]));

        let mut explicit_date = masquerade.clone();
        explicit_date.headers.insert(
            "date".to_string(),
            "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
        );
        let (explicit_date_response, _) =
            xray_string_masquerade_response(&http::Method::GET, &explicit_date)
                .expect("preserve explicit Xray string Date header");
        assert_eq!(
            explicit_date_response.headers().get(http::header::DATE),
            Some(&http::HeaderValue::from_static(
                "Sun, 06 Nov 1994 08:49:37 GMT"
            ))
        );

        let (head_response, head_body) =
            xray_string_masquerade_response(&http::Method::HEAD, &masquerade)
                .expect("valid Xray HEAD string masquerade response");
        assert_eq!(
            head_response.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("15"))
        );
        assert!(
            head_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .is_none()
        );
        assert_eq!(head_body.as_deref(), Some(&b"hello from xray"[..]));

        let no_content =
            crate::config::server_config::Hysteria2MasqueradeStringConfig {
                content: "ignored body".to_string(),
                headers: HashMap::new(),
                status_code: 204,
            };
        let (no_content_response, no_content_body) =
            xray_string_masquerade_response(&http::Method::GET, &no_content)
                .expect("valid Xray no-content string masquerade response");
        assert_eq!(no_content_response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            no_content_response
                .headers()
                .get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("0"))
        );
        assert!(
            no_content_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .is_none()
        );
        assert!(no_content_body.is_none());
    }

    #[test]
    fn xray_proxy_query_cleaning_matches_go_reverse_proxy_rewrite() {
        assert_eq!(xray_proxy_clean_query("a=1&a=2;b=3"), "a=1");
        assert_eq!(xray_proxy_clean_query("a=1&a=%zz&b=3"), "a=1&b=3");
        assert_eq!(xray_proxy_clean_query("a=%zz"), "");
        assert_eq!(xray_proxy_clean_query("a=%zz&&b=2"), "b=2");
        assert_eq!(xray_proxy_clean_query("&&a=%zz"), "");
        assert_eq!(xray_proxy_clean_query("=&&a=%zz"), "=");
        assert_eq!(
            xray_proxy_clean_query("b=2&a=first&a=second%20value"),
            "b=2&a=first&a=second%20value"
        );
        assert_eq!(
            xray_proxy_clean_query("b=2;a=ignored&a=first&a=second+value"),
            "a=first&a=second+value"
        );
        let at_limit = "b=2&".repeat(9_999) + "a=1";
        assert_eq!(xray_proxy_clean_query(&at_limit), at_limit);

        let over_limit_same_key = "a=1&".repeat(10_000) + "a=1";
        assert_eq!(
            xray_proxy_clean_query(&over_limit_same_key),
            over_limit_same_key
        );
        let over_limit_sorted = "b=2&".repeat(10_000) + "a=1";
        let cleaned = xray_proxy_clean_query(&over_limit_sorted);
        assert!(cleaned.starts_with("a=1&b=2&b=2"));
        assert_eq!(cleaned.matches("b=2").count(), 10_000);

        let uri: http::Uri = "https://original.test/path?a=1&a=%25zz&b=3"
            .parse()
            .expect("valid encoded proxy URI");
        let target =
            xray_proxy_target_url("https://upstream.test/base?fixed=1", &uri)
                .expect("build cleaned proxy target");
        assert_eq!(
            target.as_str(),
            "https://upstream.test/base/path?fixed=1&a=1&a=%25zz&b=3"
        );

        let escaped_uri: http::Uri = "https://original.test/c%2Fd?q=2"
            .parse()
            .expect("valid escaped proxy URI");
        let escaped_target = xray_proxy_target_url(
            "https://user:pass@upstream.test/base//?fixed=1",
            &escaped_uri,
        )
        .expect("build Xray-compatible proxy target");
        assert_eq!(
            escaped_target.as_str(),
            "https://upstream.test/base//c%2Fd?fixed=1&q=2"
        );

        let malformed_uri: http::Uri = "https://original.test/path?a=1&a=2;b=3&b=3"
            .parse()
            .expect("valid proxy URI with semicolon query");
        let target = xray_proxy_target_url(
            "https://upstream.test/base?fixed=1",
            &malformed_uri,
        )
        .expect("build sanitized proxy target");
        assert_eq!(
            target.as_str(),
            "https://upstream.test/base/path?fixed=1&a=1&b=3"
        );

        let force_query_uri: http::Uri = "https://original.test/path?"
            .parse()
            .expect("valid explicit-empty-query proxy URI");
        let force_query_target =
            xray_proxy_target_url("https://upstream.test/base", &force_query_uri)
                .expect("preserve Xray incoming ForceQuery");
        assert_eq!(
            force_query_target.as_str(),
            "https://upstream.test/base/path?"
        );
        let plain_uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid queryless proxy URI");
        let target_force_query =
            xray_proxy_target_url("https://upstream.test/base?", &plain_uri)
                .expect("drop target-only ForceQuery like Xray");
        assert_eq!(
            target_force_query.as_str(),
            "https://upstream.test/base/path"
        );
    }

    #[test]
    fn xray_proxy_target_validation_matches_go_url_parse_escape_failures() {
        assert!(
            xray_proxy_validate_target_url("https://upstream.test/a%2Fb?q=%zz")
                .is_ok()
        );
        assert!(xray_proxy_validate_target_url("mailto:%zz?q=%zz").is_ok());

        for invalid in [
            "https://upstream.test/a%zz?q=ok",
            "https://upstream.test/a#frag%zz",
            "https://upstream.test/a\u{7f}",
        ] {
            assert!(
                xray_proxy_validate_target_url(invalid).is_err(),
                "Xray net/url.Parse should reject {invalid:?}"
            );
            let config = Hysteria2MasqueradeProxyConfig {
                url: invalid.to_string(),
                rewrite_host: false,
                insecure: false,
            };
            assert!(
                build_xray_proxy_transport(Some(&config)).is_err(),
                "invalid Xray proxy URL should fail transport setup"
            );
        }
    }

    #[test]
    fn xray_proxy_header_tokens_tolerate_obs_text_like_go() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_bytes(b"X-Hop,\x80")
                .expect("obs-text connection value"),
        );
        let x_hop = http::HeaderName::from_static("x-hop");
        assert!(xray_proxy_connection_header(&x_hop, &headers));

        headers.insert(
            http::header::TE,
            http::HeaderValue::from_bytes(b"trailers,\x80")
                .expect("obs-text TE value"),
        );
        assert!(xray_proxy_supports_trailers(&headers));

        headers.insert(
            http::header::TE,
            http::HeaderValue::from_bytes(b"x-trailers,\x80")
                .expect("obs-text non-token TE value"),
        );
        assert!(!xray_proxy_supports_trailers(&headers));
    }

    #[test]
    fn xray_proxy_auto_gzip_matches_go_transport_conditions() {
        let mut headers = http::HeaderMap::new();
        assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));
        assert!(!xray_proxy_auto_gzip(&http::Method::HEAD, &headers));

        headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-1"),
        );
        assert!(!xray_proxy_auto_gzip(&http::Method::GET, &headers));
        headers.insert(http::header::RANGE, http::HeaderValue::from_static(""));
        assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));

        headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("br"),
        );
        assert!(!xray_proxy_auto_gzip(&http::Method::GET, &headers));
        headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static(""),
        );
        assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_forwards_request_and_upstream_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy masquerade upstream");
        let upstream_addr = listener
            .local_addr()
            .expect("read proxy masquerade upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept proxy request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read =
                    stream.read(&mut buffer).await.expect("read proxy request");
                assert_ne!(read, 0, "proxy request closed before headers");
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) =
                    request.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while request.len() < header_end + content_length {
                        let read = stream
                            .read(&mut buffer)
                            .await
                            .expect("read proxy request body");
                        assert_ne!(read, 0, "proxy request closed before body");
                        request.extend_from_slice(&buffer[..read]);
                    }
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nX-Upstream: yes\r\nConnection: close, X-Upstream-Hop\r\nX-Upstream-Hop: hidden\r\n\r\nhello",
                )
                .await
                .expect("write proxy response");
            String::from_utf8(request).expect("proxy request should be utf8")
        });

        let uri: http::Uri = "https://original.test/path?q=2"
            .parse()
            .expect("valid proxy request URI");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("forwarded"));
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static(""),
        );
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("br"),
        );
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive, X-Client-Hop"),
        );
        headers.insert("x-client-hop", http::HeaderValue::from_static("hidden"));
        headers.insert(
            http::header::TE,
            http::HeaderValue::from_static("gzip, trailers"),
        );
        headers.insert("forwarded", http::HeaderValue::from_static("for=spoofed"));
        headers.insert(
            "x-forwarded-for",
            http::HeaderValue::from_static("203.0.113.7"),
        );
        headers.insert(
            "x-forwarded-host",
            http::HeaderValue::from_static("spoofed.example"),
        );
        headers.insert("x-forwarded-proto", http::HeaderValue::from_static("http"));
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("http://url-user:url-pass@{upstream_addr}/base?fixed=1"),
            rewrite_host: false,
            insecure: false,
        };
        let (response, body) = xray_proxy_masquerade_response(
            &http::Method::POST,
            &uri,
            &headers,
            Bytes::from_static(b"payload"),
            &config,
        )
        .await
        .expect("proxy Xray masquerade request");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("x-upstream"),
            Some(&http::HeaderValue::from_static("yes"))
        );
        assert!(response.headers().get(http::header::CONNECTION).is_none());
        assert!(response.headers().get("x-upstream-hop").is_none());
        assert_eq!(body.as_deref(), Some(&b"hello"[..]));

        let request = upstream.await.expect("join proxy upstream");
        assert!(request.starts_with("POST /base/path?fixed=1&q=2 HTTP/1.1\r\n"));
        assert!(
            request.contains("host: original.test\r\n")
                || request.contains("Host: original.test\r\n")
        );
        assert!(
            request.contains("x-test: forwarded\r\n")
                || request.contains("X-Test: forwarded\r\n")
        );
        let request_lower = request.to_ascii_lowercase();
        assert!(!request_lower.contains("\r\nx-client-hop:"));
        assert!(!request_lower.contains("\r\nconnection:"));
        assert!(request_lower.contains("\r\nte: trailers\r\n"));
        assert!(!request_lower.contains("te: gzip"));
        assert!(request_lower.contains("\r\naccept-encoding: \r\n"));
        assert!(request_lower.contains("\r\naccept-encoding: br\r\n"));
        assert!(request_lower.contains("\r\naccept-encoding: gzip\r\n"));
        assert!(!request_lower.contains("\r\nforwarded:"));
        assert!(!request_lower.contains("\r\nx-forwarded-for:"));
        assert!(!request_lower.contains("\r\nx-forwarded-host:"));
        assert!(!request_lower.contains("\r\nx-forwarded-proto:"));
        assert!(!request_lower.contains("\r\nauthorization:"));
        assert!(request.ends_with("\r\npayload"));
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_auto_decompresses_transport_gzip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gzip proxy upstream");
        let upstream_addr =
            listener.local_addr().expect("read gzip upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept gzip request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read =
                    stream.read(&mut buffer).await.expect("read gzip request");
                assert_ne!(read, 0, "gzip request closed before headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request =
                String::from_utf8(request).expect("gzip request should be utf8");
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("\r\naccept-encoding: gzip\r\n")
            );

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 25\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write gzip response headers");
            stream
                .write_all(&[
                    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff,
                    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10,
                    0x36, 0x05, 0x00, 0x00, 0x00,
                ])
                .await
                .expect("write gzip response body");
        });

        let uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid gzip proxy URI");
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("http://{upstream_addr}/"),
            rewrite_host: true,
            insecure: false,
        };
        let (response, body) = xray_proxy_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            &config,
        )
        .await
        .expect("proxy gzip Xray masquerade request");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .is_none()
        );
        assert!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .is_none()
        );
        assert_eq!(body.as_deref(), Some(&b"hello"[..]));
        upstream.await.expect("join gzip upstream");
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_preserves_caller_requested_gzip() {
        const GZIP_HELLO: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48,
            0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00,
            0x00,
        ];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind explicit-gzip proxy upstream");
        let upstream_addr = listener
            .local_addr()
            .expect("read explicit-gzip upstream address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept explicit-gzip request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .expect("read explicit-gzip request");
                assert_ne!(read, 0, "explicit-gzip request closed before headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request)
                .expect("explicit-gzip request should be utf8");
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("\r\naccept-encoding: gzip\r\n")
            );

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 25\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write explicit-gzip response headers");
            stream
                .write_all(GZIP_HELLO)
                .await
                .expect("write explicit-gzip response body");
        });

        let uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid explicit-gzip proxy URI");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("http://{upstream_addr}/"),
            rewrite_host: true,
            insecure: false,
        };
        let (response, body) = xray_proxy_masquerade_response(
            &http::Method::GET,
            &uri,
            &headers,
            Bytes::new(),
            &config,
        )
        .await
        .expect("proxy explicit-gzip Xray masquerade request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_ENCODING),
            Some(&http::HeaderValue::from_static("gzip"))
        );
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("25"))
        );
        assert_eq!(body.as_deref(), Some(GZIP_HELLO));
        upstream.await.expect("join explicit-gzip upstream");
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_reuses_upstream_transport_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reusable proxy upstream");
        let upstream_addr = listener
            .local_addr()
            .expect("read reusable upstream address");
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepts_for_task = accepts.clone();
        let upstream = tokio::spawn(async move {
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("accept reusable proxy request");
                accepts_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut pending = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    loop {
                        while !pending.windows(4).any(|window| window == b"\r\n\r\n")
                        {
                            let read = stream
                                .read(&mut buffer)
                                .await
                                .expect("read reusable proxy request");
                            if read == 0 {
                                return;
                            }
                            pending.extend_from_slice(&buffer[..read]);
                        }
                        let header_end = pending
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .expect("complete reusable proxy request")
                            + 4;
                        pending.drain(..header_end);
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                            )
                            .await
                            .expect("write reusable proxy response");
                    }
                });
            }
        });

        let uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid reusable proxy URI");
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("http://{upstream_addr}/"),
            rewrite_host: true,
            insecure: false,
        };
        let transport = XrayProxyTransport::new(false)
            .expect("build reusable Xray proxy transport");
        for _ in 0..2 {
            let (response, body) = xray_proxy_masquerade_response_with_transport(
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
                &config,
                &transport,
            )
            .await
            .expect("proxy reusable Xray masquerade request");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body.as_deref(), Some(&b"ok"[..]));
        }

        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Xray DefaultTransport reuses the upstream keep-alive connection",
        );
        upstream.abort();
    }

    #[tokio::test]
    async fn xray_proxy_transport_caps_idle_connections_per_host_like_go() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind pooled proxy upstream");
        let upstream_addr =
            listener.local_addr().expect("read pooled upstream address");
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let progress = std::sync::Arc::new(tokio::sync::Notify::new());
        let accepts_for_task = accepts.clone();
        let requests_for_task = requests.clone();
        let progress_for_task = progress.clone();
        let upstream = tokio::spawn(async move {
            loop {
                let (stream, _) =
                    listener.accept().await.expect("accept pooled request");
                accepts_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let requests = requests_for_task.clone();
                let progress = progress_for_task.clone();
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut pending = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    loop {
                        while !pending.windows(4).any(|window| window == b"\r\n\r\n")
                        {
                            let read = stream
                                .read(&mut buffer)
                                .await
                                .expect("read pooled proxy request");
                            if read == 0 {
                                return;
                            }
                            pending.extend_from_slice(&buffer[..read]);
                        }
                        let header_end = pending
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .expect("complete pooled proxy request")
                            + 4;
                        pending.drain(..header_end);

                        let request_number = requests
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            + 1;
                        progress.notify_waiters();
                        let threshold = if request_number <= 3 { 3 } else { 6 };
                        while requests.load(std::sync::atomic::Ordering::SeqCst)
                            < threshold
                        {
                            progress.notified().await;
                        }
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                            )
                            .await
                            .expect("write pooled proxy response");
                    }
                });
            }
        });

        let uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid pooled proxy URI");
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("http://{upstream_addr}/"),
            rewrite_host: true,
            insecure: false,
        };
        let transport =
            XrayProxyTransport::new(false).expect("build pooled proxy transport");
        let method = http::Method::GET;
        let headers = http::HeaderMap::new();
        let request = || {
            xray_proxy_masquerade_response_with_transport(
                &method,
                &uri,
                &headers,
                Bytes::new(),
                &config,
                &transport,
            )
        };

        let first = tokio::join!(request(), request(), request());
        for result in [first.0, first.1, first.2] {
            let (response, body) = result.expect("proxy first pooled request round");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body.as_deref(), Some(&b"ok"[..]));
        }
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "first concurrent round should establish three upstream connections",
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = tokio::join!(request(), request(), request());
        for result in [second.0, second.1, second.2] {
            let (response, body) =
                result.expect("proxy second pooled request round");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body.as_deref(), Some(&b"ok"[..]));
        }
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "Go DefaultTransport retains only two idle connections per host",
        );
        upstream.abort();
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_supports_https_http2_upstream() {
        let generated_cert =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate h2 upstream certificate");
        let cert_bytes = generated_cert.cert.pem().into_bytes();
        let key_bytes = generated_cert.signing_key.serialize_pem().into_bytes();
        let server_config = crate::util::rustls_util::create_server_config(
            &cert_bytes,
            &key_bytes,
            &["h2".to_string()],
            &[],
        )
        .expect("build h2-only TLS upstream config");
        let acceptor =
            tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind h2-only proxy upstream");
        let upstream_addr = listener.local_addr().expect("read h2 upstream address");
        let upstream = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept h2 proxy request");
            let tls = acceptor
                .accept(stream)
                .await
                .expect("accept h2 upstream TLS");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice()),
                "Xray DefaultTransport negotiates HTTP/2 with an h2-only HTTPS upstream",
            );

            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    assert_eq!(request.version(), http::Version::HTTP_2);
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                        http_body_util::Full::new(Bytes::from_static(
                            b"h2 upstream",
                        )),
                    ))
                },
            );
            hyper::server::conn::http2::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
            .await
            .expect("serve h2-only upstream request");
        });

        let uri: http::Uri = "https://original.test/path"
            .parse()
            .expect("valid h2 proxy URI");
        let config = Hysteria2MasqueradeProxyConfig {
            url: format!("https://localhost:{}/", upstream_addr.port()),
            rewrite_host: true,
            insecure: true,
        };
        let (response, body) = xray_proxy_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            &config,
        )
        .await
        .expect("proxy Xray masquerade request to h2-only upstream");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body.as_deref(), Some(&b"h2 upstream"[..]));
        upstream.await.expect("join h2 upstream");
    }

    #[tokio::test]
    async fn xray_proxy_masquerade_returns_bad_gateway_for_relative_target() {
        let uri: http::Uri = "https://original.test/path?q=2"
            .parse()
            .expect("valid proxy request URI");
        let config = Hysteria2MasqueradeProxyConfig {
            url: "/relative-upstream".to_string(),
            rewrite_host: false,
            insecure: false,
        };

        let (response, body) = xray_proxy_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            &config,
        )
        .await
        .expect("relative Xray proxy target should become a gateway failure");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(body.is_none());
    }

    #[tokio::test]
    async fn xray_file_masquerade_serves_files_indexes_redirects_and_listings() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chimera-hysteria2-file-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(root.join("sub"))
            .await
            .expect("create file masquerade subdir");
        tokio::fs::create_dir_all(root.join("encoded.dir"))
            .await
            .expect("create encoded directory fixture");
        tokio::fs::create_dir_all(root.join("list/dir"))
            .await
            .expect("create file masquerade listing dir");
        tokio::fs::create_dir_all(root.join("indexdir/index.html"))
            .await
            .expect("create file masquerade index directory");
        #[cfg(unix)]
        tokio::fs::create_dir_all(root.join("badindex"))
            .await
            .expect("create file masquerade bad-index directory");
        tokio::fs::write(root.join("hello.txt"), b"hello file")
            .await
            .expect("write file masquerade file");
        tokio::fs::write(root.join("你好.txt"), b"unicode file")
            .await
            .expect("write unicode redirect fixture");
        tokio::fs::write(
            root.join("page.unknown"),
            b"<!doctype html><title>x</title>",
        )
        .await
        .expect("write sniffed html file");
        tokio::fs::write(
            root.join("image.unknown"),
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR",
        )
        .await
        .expect("write sniffed png file");
        tokio::fs::write(
            root.join("plain.unknown"),
            b"plain text without extension",
        )
        .await
        .expect("write sniffed text file");
        tokio::fs::write(root.join("binary.unknown"), b"\x00\x01\x02binary")
            .await
            .expect("write sniffed binary file");
        tokio::fs::write(root.join("module.mjs"), b"plain bytes")
            .await
            .expect("write Xray MIME override file");
        tokio::fs::write(root.join("sub/index.html"), b"sub index")
            .await
            .expect("write file masquerade index");
        tokio::fs::write(root.join("list/z.txt"), b"z")
            .await
            .expect("write listing entry");
        tokio::fs::write(root.join("list/a&b.txt"), b"a")
            .await
            .expect("write escaped listing entry");
        tokio::fs::write(root.join("indexdir/parent.txt"), b"parent")
            .await
            .expect("write parent index-directory entry");
        tokio::fs::write(root.join("indexdir/index.html/inside.txt"), b"inside")
            .await
            .expect("write nested index-directory entry");
        #[cfg(unix)]
        {
            tokio::fs::write(root.join("badindex/visible.txt"), b"visible")
                .await
                .expect("write bad-index parent listing entry");
            std::os::unix::fs::symlink(
                "index.html",
                root.join("badindex/index.html"),
            )
            .expect("create self-referential index symlink");
        }

        let root_str = root.to_string_lossy();
        let get = http::Method::GET;
        let headers = http::HeaderMap::new();
        let file_uri: http::Uri = "https://example.test/hello%2Etxt"
            .parse()
            .expect("valid file URI");
        let (file_response, file_body) =
            xray_file_masquerade_response(&get, &file_uri, &headers, &root_str)
                .await
                .expect("serve Xray file masquerade file");
        assert_eq!(file_response.status(), StatusCode::OK);
        assert_eq!(
            file_response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(file_body.as_deref(), Some(&b"hello file"[..]));

        let encoded_file_redirect_uri: http::Uri =
            "https://example.test/hello%2Etxt/?keep=yes"
                .parse()
                .expect("valid encoded file redirect URI");
        let (encoded_file_redirect_response, encoded_file_redirect_body) =
            xray_file_masquerade_response(
                &get,
                &encoded_file_redirect_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("redirect encoded Xray file basename");
        assert_eq!(
            encoded_file_redirect_response.status(),
            StatusCode::MOVED_PERMANENTLY
        );
        assert_eq!(
            encoded_file_redirect_response
                .headers()
                .get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("../hello.txt?keep=yes"))
        );
        assert!(encoded_file_redirect_body.is_none());

        let unicode_file_redirect_uri: http::Uri =
            "https://example.test/%e4%bd%a0%e5%a5%bd%2Etxt/"
                .parse()
                .expect("valid unicode file redirect URI");
        let (unicode_file_redirect_response, _) = xray_file_masquerade_response(
            &get,
            &unicode_file_redirect_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("redirect unicode Xray file basename");
        assert_eq!(
            unicode_file_redirect_response
                .headers()
                .get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("../%E4%BD%A0%E5%A5%BD.txt"))
        );

        let last_modified = file_response
            .headers()
            .get(http::header::LAST_MODIFIED)
            .cloned()
            .expect("Xray file response should expose Last-Modified");
        let mut conditional_headers = http::HeaderMap::new();
        conditional_headers
            .insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
        let (not_modified_response, not_modified_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &conditional_headers,
                &root_str,
            )
            .await
            .expect("honor Xray If-Modified-Since condition");
        assert_eq!(not_modified_response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            not_modified_response
                .headers()
                .get(http::header::LAST_MODIFIED),
            Some(&last_modified)
        );
        assert!(
            not_modified_response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .is_none()
        );
        assert!(not_modified_body.is_none());

        let mut if_match_headers = http::HeaderMap::new();
        if_match_headers.insert(
            http::header::IF_MATCH,
            http::HeaderValue::from_static("\"missing-etag\""),
        );
        if_match_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-1"),
        );
        let (if_match_response, if_match_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_match_headers,
            &root_str,
        )
        .await
        .expect("reject unmatched Xray If-Match before Range");
        assert_eq!(if_match_response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            if_match_response.headers().get(http::header::LAST_MODIFIED),
            Some(&last_modified)
        );
        assert!(
            if_match_response
                .headers()
                .get(http::header::CONTENT_RANGE)
                .is_none()
        );
        assert!(if_match_body.is_none());

        let mut if_unmodified_headers = http::HeaderMap::new();
        if_unmodified_headers.insert(
            http::header::IF_UNMODIFIED_SINCE,
            http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:01 GMT"),
        );
        let (if_unmodified_response, _) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_unmodified_headers,
            &root_str,
        )
        .await
        .expect("reject stale Xray If-Unmodified-Since");
        assert_eq!(
            if_unmodified_response.status(),
            StatusCode::PRECONDITION_FAILED
        );

        if_unmodified_headers
            .insert(http::header::IF_MATCH, http::HeaderValue::from_static("*"));
        let (if_match_star_response, if_match_star_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &if_unmodified_headers,
                &root_str,
            )
            .await
            .expect("Xray If-Match should take precedence over If-Unmodified-Since");
        assert_eq!(if_match_star_response.status(), StatusCode::OK);
        assert_eq!(if_match_star_body.as_deref(), Some(&b"hello file"[..]));

        let mut if_none_match_headers = http::HeaderMap::new();
        if_none_match_headers.insert(
            http::header::IF_NONE_MATCH,
            http::HeaderValue::from_static("*"),
        );
        let (if_none_match_response, if_none_match_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &if_none_match_headers,
                &root_str,
            )
            .await
            .expect("honor Xray If-None-Match wildcard");
        assert_eq!(if_none_match_response.status(), StatusCode::NOT_MODIFIED);
        assert!(if_none_match_body.is_none());

        let post = http::Method::POST;
        let (post_if_none_match_response, post_if_none_match_body) =
            xray_file_masquerade_response(
                &post,
                &file_uri,
                &if_none_match_headers,
                &root_str,
            )
            .await
            .expect("reject matching Xray If-None-Match on non-GET request");
        assert_eq!(
            post_if_none_match_response.status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert!(post_if_none_match_body.is_none());

        if_none_match_headers.insert(
            http::header::IF_NONE_MATCH,
            http::HeaderValue::from_static("\"missing-etag\""),
        );
        if_none_match_headers
            .insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
        let (nonmatching_if_none_match_response, nonmatching_if_none_match_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &if_none_match_headers,
                &root_str,
            )
            .await
            .expect("Xray If-None-Match presence should suppress If-Modified-Since");
        assert_eq!(nonmatching_if_none_match_response.status(), StatusCode::OK);
        assert_eq!(
            nonmatching_if_none_match_body.as_deref(),
            Some(&b"hello file"[..])
        );

        let mut empty_range_headers = http::HeaderMap::new();
        empty_range_headers
            .insert(http::header::RANGE, http::HeaderValue::from_static(""));
        let (empty_range_response, empty_range_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &empty_range_headers,
                &root_str,
            )
            .await
            .expect("ignore empty Xray Range header");
        assert_eq!(empty_range_response.status(), StatusCode::OK);
        assert_eq!(empty_range_body.as_deref(), Some(&b"hello file"[..]));

        let mut range_headers = http::HeaderMap::new();
        range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=1-4"),
        );
        let (range_response, range_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &range_headers,
            &root_str,
        )
        .await
        .expect("serve Xray byte range");
        assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            range_response.headers().get(http::header::ACCEPT_RANGES),
            Some(&http::HeaderValue::from_static("bytes"))
        );
        assert_eq!(
            range_response.headers().get(http::header::CONTENT_RANGE),
            Some(&http::HeaderValue::from_static("bytes 1-4/10"))
        );
        assert_eq!(range_body.as_deref(), Some(&b"ello"[..]));

        range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=-4"),
        );
        let (_, suffix_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &range_headers,
            &root_str,
        )
        .await
        .expect("serve Xray suffix range");
        assert_eq!(suffix_body.as_deref(), Some(&b"file"[..]));

        range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-1,6-9"),
        );
        let (multi_response, multi_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &range_headers,
            &root_str,
        )
        .await
        .expect("serve Xray multipart ranges");
        assert_eq!(multi_response.status(), StatusCode::PARTIAL_CONTENT);
        let multipart_content_type = multi_response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("multipart Xray range Content-Type");
        let boundary = multipart_content_type
            .strip_prefix("multipart/byteranges; boundary=")
            .expect("multipart Xray range boundary");
        assert_eq!(boundary.len(), 60);
        assert!(
            boundary
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "Xray multipart boundary must be lowercase hex",
        );
        let multi_body = multi_body.expect("multipart range body");
        assert!(multi_body.windows(2).any(|window| window == b"he"));
        assert!(multi_body.windows(4).any(|window| window == b"file"));

        let mut if_range_headers = http::HeaderMap::new();
        if_range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=0-1"),
        );
        if_range_headers.insert(http::header::IF_RANGE, last_modified.clone());
        let (if_range_response, if_range_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_range_headers,
            &root_str,
        )
        .await
        .expect("honor matching Xray If-Range date");
        assert_eq!(if_range_response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(if_range_body.as_deref(), Some(&b"he"[..]));

        if_range_headers.insert(
            http::header::IF_RANGE,
            http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:01 GMT"),
        );
        let (stale_if_range_response, stale_if_range_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &if_range_headers,
                &root_str,
            )
            .await
            .expect("ignore stale Xray If-Range range");
        assert_eq!(stale_if_range_response.status(), StatusCode::OK);
        assert_eq!(stale_if_range_body.as_deref(), Some(&b"hello file"[..]));

        let (post_if_range_response, post_if_range_body) =
            xray_file_masquerade_response(
                &http::Method::POST,
                &file_uri,
                &if_range_headers,
                &root_str,
            )
            .await
            .expect("ignore Xray If-Range outside GET/HEAD");
        assert_eq!(post_if_range_response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(post_if_range_body.as_deref(), Some(&b"he"[..]));

        range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=50-60"),
        );
        let (unsatisfied_response, unsatisfied_body) =
            xray_file_masquerade_response(
                &get,
                &file_uri,
                &range_headers,
                &root_str,
            )
            .await
            .expect("reject unsatisfied Xray range");
        assert_eq!(
            unsatisfied_response.status(),
            StatusCode::RANGE_NOT_SATISFIABLE
        );
        assert_eq!(
            unsatisfied_response
                .headers()
                .get(http::header::CONTENT_RANGE),
            Some(&http::HeaderValue::from_static("bytes */10"))
        );
        assert_eq!(
            unsatisfied_body.as_deref(),
            Some(&b"invalid range: failed to overlap\n"[..])
        );

        for overflow_range in [
            "bytes=9223372036854775808-",
            "bytes=0-9223372036854775808",
            "bytes=-9223372036854775808",
        ] {
            range_headers.insert(
                http::header::RANGE,
                http::HeaderValue::from_static(overflow_range),
            );
            let (overflow_response, overflow_body) = xray_file_masquerade_response(
                &get,
                &file_uri,
                &range_headers,
                &root_str,
            )
            .await
            .expect("reject Xray signed-int64 Range overflow");
            assert_eq!(
                overflow_response.status(),
                StatusCode::RANGE_NOT_SATISFIABLE,
                "Range {overflow_range}",
            );
            assert!(
                overflow_response
                    .headers()
                    .get(http::header::CONTENT_RANGE)
                    .is_none(),
                "overflow is invalid rather than merely non-overlapping for {overflow_range}",
            );
            assert_eq!(
                overflow_body.as_deref(),
                Some(&b"invalid range\n"[..]),
                "Range {overflow_range}",
            );
        }

        let redirect_uri: http::Uri = "https://example.test/sub?keep=yes"
            .parse()
            .expect("valid directory URI");
        let (redirect_response, _) =
            xray_file_masquerade_response(&get, &redirect_uri, &headers, &root_str)
                .await
                .expect("redirect Xray file masquerade directory");
        assert_eq!(redirect_response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect_response.headers().get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("sub/?keep=yes"))
        );

        let encoded_directory_redirect_uri: http::Uri =
            "https://example.test/encoded%2Edir"
                .parse()
                .expect("valid encoded directory redirect URI");
        let (encoded_directory_redirect_response, _) =
            xray_file_masquerade_response(
                &get,
                &encoded_directory_redirect_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("redirect encoded Xray directory basename");
        assert_eq!(
            encoded_directory_redirect_response
                .headers()
                .get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("encoded.dir/"))
        );

        let encoded_directory_slash_uri: http::Uri = "https://example.test/sub%2F"
            .parse()
            .expect("valid encoded directory slash URI");
        let (encoded_directory_slash_response, encoded_directory_slash_body) =
            xray_file_masquerade_response(
                &get,
                &encoded_directory_slash_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("treat decoded slash as Xray directory slash");
        assert_eq!(encoded_directory_slash_response.status(), StatusCode::OK);
        assert_eq!(
            encoded_directory_slash_body.as_deref(),
            Some(&b"sub index"[..])
        );

        let encoded_index_uri: http::Uri =
            "https://example.test/sub/index%2Ehtml?keep=yes"
                .parse()
                .expect("valid encoded index redirect URI");
        let (encoded_index_response, encoded_index_body) =
            xray_file_masquerade_response(
                &get,
                &encoded_index_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("redirect encoded Xray index.html path");
        assert_eq!(
            encoded_index_response.status(),
            StatusCode::MOVED_PERMANENTLY
        );
        assert_eq!(
            encoded_index_response.headers().get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("./?keep=yes"))
        );
        assert!(encoded_index_body.is_none());

        let index_uri: http::Uri = "https://example.test/sub/"
            .parse()
            .expect("valid index URI");
        let (_, index_body) =
            xray_file_masquerade_response(&get, &index_uri, &headers, &root_str)
                .await
                .expect("serve Xray file masquerade index");
        assert_eq!(index_body.as_deref(), Some(&b"sub index"[..]));

        let explicit_index_uri: http::Uri =
            "https://example.test/sub/index.html?q=1"
                .parse()
                .expect("valid explicit index URI");
        let (explicit_index_response, _) = xray_file_masquerade_response(
            &get,
            &explicit_index_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("redirect explicit Xray index path");
        assert_eq!(
            explicit_index_response
                .headers()
                .get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("./?q=1"))
        );

        let list_uri: http::Uri = "https://example.test/list/"
            .parse()
            .expect("valid listing URI");
        let (list_response, list_body) =
            xray_file_masquerade_response(&get, &list_uri, &headers, &root_str)
                .await
                .expect("serve Xray directory listing");
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_last_modified = list_response
            .headers()
            .get(http::header::LAST_MODIFIED)
            .cloned()
            .expect("Xray directory listing should expose Last-Modified");
        let listing =
            std::str::from_utf8(list_body.as_deref().expect("listing body"))
                .expect("utf8 directory listing");
        assert!(listing.contains("href=\"a&b.txt\">a&amp;b.txt</a>"));
        assert!(listing.contains("href=\"dir/\">dir/</a>"));
        assert!(
            listing.find("a&amp;b.txt").unwrap() < listing.find("z.txt").unwrap()
        );

        let mut list_conditional_headers = http::HeaderMap::new();
        list_conditional_headers
            .insert(http::header::IF_MODIFIED_SINCE, list_last_modified);
        let (list_not_modified_response, list_not_modified_body) =
            xray_file_masquerade_response(
                &get,
                &list_uri,
                &list_conditional_headers,
                &root_str,
            )
            .await
            .expect("honor Xray directory If-Modified-Since condition");
        assert_eq!(
            list_not_modified_response.status(),
            StatusCode::NOT_MODIFIED
        );
        assert!(
            list_not_modified_response
                .headers()
                .get(http::header::LAST_MODIFIED)
                .is_none()
        );
        assert!(list_not_modified_body.is_none());

        let index_directory_uri: http::Uri = "https://example.test/indexdir/"
            .parse()
            .expect("valid index-directory URI");
        let (index_directory_response, index_directory_body) =
            xray_file_masquerade_response(
                &get,
                &index_directory_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("serve Xray index.html directory listing");
        assert_eq!(index_directory_response.status(), StatusCode::OK);
        let index_directory_listing = std::str::from_utf8(
            index_directory_body
                .as_deref()
                .expect("index-directory listing body"),
        )
        .expect("utf8 index-directory listing");
        assert!(index_directory_listing.contains("inside.txt"));
        assert!(!index_directory_listing.contains("parent.txt"));
        assert!(!index_directory_listing.contains("index.html/"));

        #[cfg(unix)]
        {
            let bad_index_uri: http::Uri = "https://example.test/badindex/"
                .parse()
                .expect("valid bad-index URI");
            let (bad_index_response, bad_index_body) =
                xray_file_masquerade_response(
                    &get,
                    &bad_index_uri,
                    &headers,
                    &root_str,
                )
                .await
                .expect("ignore Xray index.html stat failure");
            assert_eq!(bad_index_response.status(), StatusCode::OK);
            let bad_index_listing = std::str::from_utf8(
                bad_index_body.as_deref().expect("bad-index listing body"),
            )
            .expect("utf8 bad-index listing");
            assert!(bad_index_listing.contains("visible.txt"));
            assert!(bad_index_listing.contains("index.html"));

            let invalid_uri: http::Uri = "https://example.test/bad%00path"
                .parse()
                .expect("valid encoded-NUL URI");
            let (invalid_response, invalid_body) = xray_file_masquerade_response(
                &get,
                &invalid_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("map invalid filesystem path to Xray HTTP error");
            assert_eq!(invalid_response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                invalid_response.headers().get(http::header::CONTENT_TYPE),
                Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
            );
            assert_eq!(
                invalid_response.headers().get("x-content-type-options"),
                Some(&http::HeaderValue::from_static("nosniff"))
            );
            assert_eq!(invalid_body.as_deref(), Some(&b"404 page not found\n"[..]));
        }

        let cleaned_uri: http::Uri = "https://example.test/../hello.txt"
            .parse()
            .expect("valid cleaned URI");
        let (_, cleaned_body) =
            xray_file_masquerade_response(&get, &cleaned_uri, &headers, &root_str)
                .await
                .expect("clean Xray file path within root");
        assert_eq!(cleaned_body.as_deref(), Some(&b"hello file"[..]));

        for (name, expected_type) in [
            ("page.unknown", "text/html; charset=utf-8"),
            ("image.unknown", "image/png"),
            ("plain.unknown", "text/plain; charset=utf-8"),
            ("binary.unknown", "application/octet-stream"),
            ("module.mjs", "text/javascript; charset=utf-8"),
        ] {
            let uri: http::Uri = format!("https://example.test/{name}")
                .parse()
                .expect("valid sniffed file URI");
            let (response, _) =
                xray_file_masquerade_response(&get, &uri, &headers, &root_str)
                    .await
                    .expect("serve sniffed Xray file masquerade file");
            assert_eq!(
                response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_type),
                "content type for {name}",
            );
        }

        tokio::fs::remove_dir_all(&root)
            .await
            .expect("remove file masquerade tempdir");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn xray_file_unix_names_preserve_non_utf8_bytes() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chimera-hysteria2-nonutf8-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("create non-UTF8 file masquerade root");

        let file_name = OsString::from_vec(b"raw\xFF.bin".to_vec());
        tokio::fs::write(root.join(&file_name), b"\0raw")
            .await
            .expect("write non-UTF8 file fixture");
        let directory_name = OsString::from_vec(b"dir\xFE".to_vec());
        tokio::fs::create_dir(root.join(&directory_name))
            .await
            .expect("create non-UTF8 directory fixture");
        tokio::fs::write(root.join(&directory_name).join("inside.txt"), b"inside")
            .await
            .expect("write non-UTF8 directory child");

        let root_str = root.to_string_lossy();
        let headers = http::HeaderMap::new();
        let file_uri: http::Uri = "https://example.test/raw%FF.bin"
            .parse()
            .expect("valid encoded non-UTF8 file URI");
        let (file_response, file_body) = xray_file_masquerade_response(
            &http::Method::GET,
            &file_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("serve encoded non-UTF8 Xray file");
        assert_eq!(file_response.status(), StatusCode::OK);
        assert_eq!(file_body.as_deref(), Some(&b"\0raw"[..]));

        let directory_uri: http::Uri = "https://example.test/dir%FE"
            .parse()
            .expect("valid encoded non-UTF8 directory URI");
        let (directory_redirect, directory_redirect_body) =
            xray_file_masquerade_response(
                &http::Method::GET,
                &directory_uri,
                &headers,
                &root_str,
            )
            .await
            .expect("redirect encoded non-UTF8 Xray directory");
        assert_eq!(directory_redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            directory_redirect.headers().get(http::header::LOCATION),
            Some(&http::HeaderValue::from_static("dir%FE/"))
        );
        assert!(directory_redirect_body.is_none());

        let list_uri: http::Uri = "https://example.test/"
            .parse()
            .expect("valid non-UTF8 listing URI");
        let (list_response, list_body) = xray_file_masquerade_response(
            &http::Method::GET,
            &list_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("list non-UTF8 Xray file names");
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = list_body.expect("non-UTF8 directory listing body");
        for expected in [
            &b"href=\"raw%FF.bin\">raw\xFF.bin</a>"[..],
            &b"href=\"dir%FE/\">dir\xFE/</a>"[..],
        ] {
            assert!(
                list_body
                    .windows(expected.len())
                    .any(|window| window == expected),
                "directory listing should preserve {:?}",
                expected,
            );
        }

        let nested_uri: http::Uri = "https://example.test/dir%FE/inside.txt"
            .parse()
            .expect("valid nested non-UTF8 directory URI");
        let (nested_response, nested_body) = xray_file_masquerade_response(
            &http::Method::GET,
            &nested_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("serve file below non-UTF8 Xray directory");
        assert_eq!(nested_response.status(), StatusCode::OK);
        assert_eq!(nested_body.as_deref(), Some(&b"inside"[..]));

        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove non-UTF8 file masquerade root");
    }

    #[test]
    fn xray_file_windows_paths_match_localize_rejections() {
        for path in [
            "/a%5Cb",
            "/a:b",
            "/a%00b",
            "/CON",
            "/nested/prn",
            "/AUX",
            "/nul",
            "/COM1",
            "/com9",
            "/LPT1",
            "/lpt9",
            "/COM¹",
            "/com²",
            "/LPT³",
            "/ConIn$",
            "/conout$",
        ] {
            assert!(
                decode_file_masquerade_path_for_platform(path, true).is_none(),
                "Windows should reject Xray file path {path}",
            );
        }
        for path in ["/a/b", "/COM0", "/COM10", "/LPT0", "/console"] {
            assert!(
                decode_file_masquerade_path_for_platform(path, true).is_some(),
                "Windows should keep non-reserved Xray file path {path}",
            );
        }
        assert!(
            decode_file_masquerade_path_for_platform("/a%5Cb", false).is_some(),
            "Unix should preserve backslash as a filename character",
        );
    }

    #[tokio::test]
    async fn xray_file_root_file_with_slash_returns_non_directory_error() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chimera-hysteria2-file-root-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::write(&root, b"root file")
            .await
            .expect("write file masquerade root file");
        let root_str = root.to_string_lossy();

        for uri in [
            "https://example.test/",
            "https://example.test/./",
            "https://example.test/%2E/",
        ] {
            let uri: http::Uri = uri.parse().expect("valid root-file URI");
            let (response, body) = xray_file_masquerade_response(
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                &root_str,
            )
            .await
            .expect("map root file slash to Xray non-directory error");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                response.headers().get(http::header::CONTENT_TYPE),
                Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
            );
            assert_eq!(
                response.headers().get("x-content-type-options"),
                Some(&http::HeaderValue::from_static("nosniff"))
            );
            assert_eq!(
                body.as_deref(),
                Some(&b"http: attempting to traverse a non-directory\n"[..])
            );
        }

        tokio::fs::remove_file(root)
            .await
            .expect("remove file masquerade root file");
    }

    #[test]
    fn xray_file_extension_types_match_go_builtin_mime_differences() {
        for (name, expected) in [
            ("sample.com", "application/octet-stream"),
            (
                "sample.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            ("sample.ehtml", "text/html; charset=utf-8"),
            ("sample.ico", "image/vnd.microsoft.icon"),
            ("sample.m4a", "audio/mp4"),
            ("sample.MJS", "text/javascript; charset=utf-8"),
            ("sample.pjp", "image/jpeg"),
            ("sample.pjpeg", "image/jpeg"),
            (
                "sample.pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            ("sample.webm", "audio/webm"),
            ("sample.xbl", "text/xml; charset=utf-8"),
            (
                "sample.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
        ] {
            assert_eq!(
                xray_file_extension_content_type(Path::new(name)),
                Some(expected),
                "Xray MIME type for {name}",
            );
        }
        assert_eq!(
            xray_file_extension_content_type(Path::new("sample.txt")),
            None
        );
    }

    #[test]
    fn xray_file_url_escape_matches_go_path_encoding() {
        assert_eq!(
            xray_file_url_escape("azAZ09-._~/$&+,:;=@"),
            "azAZ09-._~/$&+,:;=@"
        );
        assert_eq!(
            xray_file_url_escape("space ?#%!'()*[]"),
            "space%20%3F%23%25%21%27%28%29%2A%5B%5D"
        );
        assert_eq!(xray_file_url_escape("你好.txt"), "%E4%BD%A0%E5%A5%BD.txt");
    }

    #[test]
    fn xray_file_directory_entry_errors_match_go_readdir_behavior() {
        assert!(xray_file_directory_entry_disappeared(&Error::new(
            ErrorKind::NotFound,
            "entry vanished",
        )));
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::Other,
        ] {
            assert!(
                !xray_file_directory_entry_disappeared(&Error::new(
                    kind,
                    "entry stat failed"
                )),
                "{kind:?} must fail the directory listing instead of being skipped",
            );
        }
    }

    #[tokio::test]
    async fn xray_file_directory_read_errors_return_http_500() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "chimera-hysteria2-not-directory-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::write(&path, b"not a directory")
            .await
            .expect("write non-directory fixture");
        let modified = tokio::fs::metadata(&path)
            .await
            .expect("stat non-directory fixture")
            .modified()
            .ok();

        let (response, body) = xray_file_directory_response(
            &http::Method::GET,
            &http::HeaderMap::new(),
            &path,
            modified,
        )
        .await
        .expect("map directory read error to HTTP response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        if modified.is_some() {
            assert!(response.headers().contains_key(http::header::LAST_MODIFIED));
        }
        assert_eq!(body.as_deref(), Some(&b"Error reading directory\n"[..]));

        tokio::fs::remove_file(path)
            .await
            .expect("remove non-directory fixture");
    }

    #[test]
    fn xray_file_server_errors_match_go_http_error_responses() {
        for (kind, status, expected_body) in [
            (
                ErrorKind::NotFound,
                StatusCode::NOT_FOUND,
                &b"404 page not found\n"[..],
            ),
            (
                ErrorKind::NotADirectory,
                StatusCode::NOT_FOUND,
                &b"404 page not found\n"[..],
            ),
            (
                ErrorKind::PermissionDenied,
                StatusCode::FORBIDDEN,
                &b"403 Forbidden\n"[..],
            ),
            (
                ErrorKind::InvalidInput,
                StatusCode::INTERNAL_SERVER_ERROR,
                &b"500 Internal Server Error\n"[..],
            ),
        ] {
            let err = Error::new(kind, "sensitive filesystem detail");
            let (response, body) = xray_file_server_error_response(&err)
                .expect("build Xray file-server error response");
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(http::header::CONTENT_TYPE),
                Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
            );
            assert_eq!(
                response.headers().get("x-content-type-options"),
                Some(&http::HeaderValue::from_static("nosniff"))
            );
            assert_eq!(
                response.headers().get(http::header::CONTENT_LENGTH),
                Some(
                    &http::HeaderValue::from_str(&expected_body.len().to_string())
                        .unwrap()
                )
            );
            assert_eq!(body.as_deref(), Some(expected_body));
        }
    }

    #[tokio::test]
    async fn xray_file_non_directory_path_component_maps_to_not_found() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chimera-hysteria2-enotdir-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::create_dir(&root)
            .await
            .expect("create ENOTDIR fixture root");
        tokio::fs::write(root.join("file"), b"leaf")
            .await
            .expect("write ENOTDIR fixture file");
        let root_str = root.to_string_lossy().into_owned();
        let uri: http::Uri = "https://example.test/file/child"
            .parse()
            .expect("valid ENOTDIR fixture URI");

        let (response, body) = xray_file_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            &root_str,
        )
        .await
        .expect("map Xray intermediate non-directory path");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body.as_deref(), Some(&b"404 page not found\n"[..]));

        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove ENOTDIR fixture root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn xray_file_unreadable_file_maps_to_forbidden() {
        use std::os::unix::fs::PermissionsExt;

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chimera-hysteria2-unreadable-{}-{suffix}",
            std::process::id()
        ));
        tokio::fs::create_dir(&root)
            .await
            .expect("create unreadable fixture root");
        let path = root.join("secret.txt");
        tokio::fs::write(&path, b"secret")
            .await
            .expect("write unreadable fixture file");
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .await
            .expect("make fixture unreadable");
        let root_str = root.to_string_lossy().into_owned();
        let uri: http::Uri = "https://example.test/secret.txt"
            .parse()
            .expect("valid unreadable fixture URI");

        let result = xray_file_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            &root_str,
        )
        .await;

        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .expect("restore fixture permissions");
        tokio::fs::remove_dir_all(root)
            .await
            .expect("remove unreadable fixture root");

        let (response, body) =
            result.expect("map unreadable file to Xray HTTP error");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body.as_deref(), Some(&b"403 Forbidden\n"[..]));
    }

    #[test]
    fn xray_file_etag_wildcard_scanner_stops_on_invalid_tags() {
        assert!(xray_etag_list_has_wildcard(b"*"));
        assert!(xray_etag_list_has_wildcard(
            b"\"missing\", W/\"also-missing\", *"
        ));
        assert!(!xray_etag_list_has_wildcard(b"\"missing\""));
        assert!(!xray_etag_list_has_wildcard(b"\"bad tag\", *"));
        assert!(!xray_etag_list_has_wildcard(b"W/\"unterminated, *"));
    }

    #[test]
    fn xray_file_preconditions_ignore_unix_epoch_modtime() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::IF_MODIFIED_SINCE,
            http::HeaderValue::from_static("Thu, 01 Jan 2099 00:00:00 GMT"),
        );

        assert_eq!(
            xray_file_precondition_status(
                &http::Method::GET,
                &headers,
                Some(std::time::UNIX_EPOCH),
            ),
            None
        );
    }

    #[test]
    fn xray_if_range_matches_pre_epoch_modtime() {
        let modified = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("pre-epoch SystemTime");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::IF_RANGE,
            http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:59 GMT"),
        );

        assert!(xray_if_range_matches(
            &http::Method::GET,
            &headers,
            Some(modified),
        ));

        headers.insert(
            http::header::IF_RANGE,
            http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:58 GMT"),
        );
        assert!(!xray_if_range_matches(
            &http::Method::GET,
            &headers,
            Some(modified),
        ));
    }

    #[test]
    fn xray_range_parser_rejects_non_utf8_header_bytes() {
        assert_eq!(xray_parse_ranges(b"\x80", 5), Err(XrayRangeError::Invalid),);
    }

    #[test]
    fn xray_http_dates_support_pre_epoch_file_times() {
        let modified = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("pre-epoch SystemTime");
        let formatted = xray_format_http_date(modified);
        assert_eq!(formatted, "Wed, 31 Dec 1969 23:59:59 GMT");
        assert_eq!(xray_parse_http_date(&formatted), Some(modified));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::IF_MODIFIED_SINCE,
            http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:59 GMT"),
        );
        assert_eq!(
            xray_file_precondition_status(
                &http::Method::GET,
                &headers,
                Some(modified)
            ),
            Some(StatusCode::NOT_MODIFIED),
        );

        headers.clear();
        headers.insert(
            http::header::IF_UNMODIFIED_SINCE,
            http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:58 GMT"),
        );
        assert_eq!(
            xray_file_precondition_status(
                &http::Method::GET,
                &headers,
                Some(modified)
            ),
            Some(StatusCode::PRECONDITION_FAILED),
        );
    }

    #[test]
    fn xray_http_date_parser_accepts_pre_epoch_legacy_formats() {
        let expected = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("pre-epoch SystemTime");
        for value in [
            "Wednesday, 31-Dec-69 23:59:59 GMT",
            "Thursday, 31-Dec-69 23:59:59 GMT",
            "Wed Dec 31 23:59:59 1969",
            "Thu Dec 31 23:59:59 1969",
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Thu, 31 Dec 1969 23:59:59 GMT",
        ] {
            assert_eq!(
                xray_parse_http_date(value),
                Some(expected),
                "Xray/Go should parse HTTP date without validating weekday {value}",
            );
        }
        assert!(xray_parse_http_date("Nope, 31 Dec 1969 23:59:59 GMT").is_none());
    }

    #[test]
    fn auth_password_matches_xray_and_shoes_exactly() {
        let clients = vec![Hysteria2Client {
            password: " spaced-secret ".to_string(),
            email: None,
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: false,
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
    fn xray_empty_user_auth_matches_missing_header_without_relaxing_shoes() {
        let clients = vec![Hysteria2Client {
            password: String::new(),
            email: Some("empty@example.com".to_string()),
            level: 0,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        }];
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_URI)
            .body(())
            .expect("valid Hysteria2 auth request without auth header");

        validate_auth_request(request.clone(), &clients, true)
            .expect("Xray Header.Get maps a missing auth header to an empty key");
        assert!(matches!(
            validate_auth_request(request, &clients, false),
            Err(AuthReject::Unauthorized("missing auth header"))
        ));
    }

    #[test]
    fn xray_transport_auth_fallback_yields_to_validator_users() {
        let fallback = Hysteria2Client {
            password: "transport-fallback".to_string(),
            email: None,
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: true,
        };
        let dynamic_user = Hysteria2Client {
            password: "dynamic-user-auth".to_string(),
            email: Some("dynamic@example.com".to_string()),
            level: 0,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        };

        let mut clients = vec![fallback];
        assert!(
            match_hysteria_auth("transport-fallback", &clients, true).is_some(),
            "Xray transport auth fallback should work while the validator is empty"
        );

        clients.push(dynamic_user);
        assert!(
            match_hysteria_auth("transport-fallback", &clients, true).is_none(),
            "adding an Xray user must disable transport auth fallback"
        );
        assert_eq!(
            match_hysteria_auth("dynamic-user-auth", &clients, true)
                .and_then(|(client, _)| client.email),
            Some("dynamic@example.com".to_string())
        );

        clients
            .retain(|client| client.email.as_deref() != Some("dynamic@example.com"));
        assert!(
            match_hysteria_auth("transport-fallback", &clients, true).is_some(),
            "removing the last Xray user must re-enable transport auth fallback"
        );
    }

    #[test]
    fn xray_uuid_user_auth_masks_route_bytes_but_shoes_id_stays_exact() {
        let xray_clients = vec![
            Hysteria2Client {
                password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
                email: Some("shadowed@example.com".to_string()),
                level: 0,
                xray_uuid_route: true,
                xray_transport_auth_fallback: false,
            },
            Hysteria2Client {
                password: "00112233-4455-1234-8899-aabbccddeeff".to_string(),
                email: Some("route-user@example.com".to_string()),
                level: 0,
                xray_uuid_route: true,
                xray_transport_auth_fallback: false,
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
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: false,
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
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: false,
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
    fn udp_activity_refresh_point_matches_xray_without_changing_shoes() {
        assert!(refresh_udp_activity_on_datagram(true));
        assert!(!refresh_udp_activity_on_completed_payload(true));
        assert!(!refresh_udp_activity_on_datagram(false));
        assert!(refresh_udp_activity_on_completed_payload(false));
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
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: false,
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
    fn xray_auth_uri_matches_decoded_path_exact_authority_and_ignores_query() {
        let clients = vec![Hysteria2Client {
            password: "secret".to_string(),
            email: None,
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: false,
        }];
        let query_uri = "https://hysteria/auth?extra=1";

        for uri in [
            query_uri,
            "https://hysteria/%61uth",
            "https://hysteria/a%75th",
        ] {
            validate_auth_request(auth_request("secret", uri), &clients, true)
                .expect("Xray matches Hysteria auth against Go's decoded URL.Path");
        }
        assert!(matches!(
            validate_auth_request(
                auth_request("secret", query_uri),
                &clients,
                false,
            ),
            Err(AuthReject::NotAuthRequest)
        ));
        assert!(matches!(
            validate_auth_request(
                auth_request("secret", "https://hysteria/%61uth"),
                &clients,
                false,
            ),
            Err(AuthReject::NotAuthRequest)
        ));
        assert!(matches!(
            validate_auth_request(
                auth_request("secret", "https://hysteria:443/auth"),
                &clients,
                true,
            ),
            Err(AuthReject::NotAuthRequest)
        ));
        for path in ["/Auth", "/%2Fauth", "/auth%2F", "/%zzuth", "/aut%"] {
            assert!(
                !xray_auth_path_matches(path),
                "unexpected Xray auth path: {path}"
            );
        }
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

        let ipv4_addr = ipv4.local_addr().expect("IPv4 receiver address");
        socket
            .send_to(b"v4", hysteria2_udp_send_addr(ipv4_addr))
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
        assert_eq!(normalize_hysteria2_udp_peer_addr(source), ipv4_addr);
    }

    #[test]
    fn udp_session_send_address_maps_ipv4_for_dual_stack_sockets() {
        let ipv4 = SocketAddr::from(([192, 0, 2, 1], 443));
        let mapped = hysteria2_udp_send_addr(ipv4);
        assert_eq!(mapped, "[::ffff:192.0.2.1]:443".parse().unwrap());
        assert_eq!(normalize_hysteria2_udp_peer_addr(mapped), ipv4);

        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(hysteria2_udp_send_addr(ipv6), ipv6);
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
    fn fragment_reassembly_matches_xray_single_packet_and_shoes_lru_semantics() {
        let remote_location = NetLocation::from_str("127.0.0.1:53", None)
            .expect("valid fragment test location");
        let packet = |fragment_count| FragmentedPacket {
            fragment_count,
            fragment_received: 1,
            packet_len: 1,
            received: vec![Some(Bytes::from_static(b"x")); fragment_count as usize],
            remote_location: remote_location.clone(),
        };

        let mut xray_cache = hysteria2_fragment_cache();
        xray_cache.put(10, packet(2));
        prepare_fragment_cache(&mut xray_cache, 11, 2, true);
        assert!(
            xray_cache.is_empty(),
            "new Xray packet should replace partial state"
        );

        xray_cache.put(11, packet(2));
        prepare_fragment_cache(&mut xray_cache, 11, 3, true);
        assert!(
            xray_cache.is_empty(),
            "changed Xray fragment count should replace partial state"
        );

        xray_cache.put(11, packet(3));
        prepare_fragment_cache(&mut xray_cache, 11, 3, true);
        assert_eq!(
            xray_cache.len(),
            1,
            "matching Xray fragments should retain state"
        );

        let mut shoes_cache = hysteria2_fragment_cache();
        shoes_cache.put(10, packet(2));
        prepare_fragment_cache(&mut shoes_cache, 11, 2, false);
        assert!(
            shoes_cache.contains(&10),
            "shoes should retain older partial packets"
        );
    }

    #[test]
    fn completed_fragment_state_matches_xray_and_shoes_semantics() {
        let completed_packet = FragmentedPacket {
            fragment_count: 2,
            fragment_received: 2,
            packet_len: 2,
            received: vec![
                Some(Bytes::from_static(b"a")),
                Some(Bytes::from_static(b"b")),
            ],
            remote_location: NetLocation::from_str("127.0.0.1:53", None)
                .expect("valid fragment location"),
        };

        let mut xray_cache = hysteria2_fragment_cache();
        xray_cache.put(7, completed_packet.clone());
        let xray_completed = completed_fragment_packet(&mut xray_cache, 7, true)
            .expect("Xray completed packet should be readable");
        assert_eq!(xray_completed.packet_len, 2);
        assert!(
            xray_cache.contains(&7),
            "Xray retains completed defragmentation state until another packet resets it"
        );

        let mut shoes_cache = hysteria2_fragment_cache();
        shoes_cache.put(7, completed_packet);
        let shoes_completed = completed_fragment_packet(&mut shoes_cache, 7, false)
            .expect("shoes completed packet should be readable");
        assert_eq!(shoes_completed.packet_len, 2);
        assert!(
            !shoes_cache.contains(&7),
            "shoes removes a packet from its fragment cache after reassembly"
        );
    }

    #[test]
    fn duplicate_fragments_match_xray_and_shoes_semantics() {
        let remote_location = NetLocation::from_str("127.0.0.1:53", None)
            .expect("valid fragment test location");
        let packet = FragmentedPacket {
            fragment_count: 2,
            fragment_received: 1,
            packet_len: 1,
            received: vec![Some(Bytes::from_static(b"x")), None],
            remote_location,
        };

        let mut xray_cache = hysteria2_fragment_cache();
        xray_cache.put(7, packet);
        handle_duplicate_fragment(&mut xray_cache, 7, true);
        assert!(
            xray_cache.contains(&7),
            "Xray should ignore a duplicate fragment and retain partial state"
        );

        let mut shoes_cache = hysteria2_fragment_cache();
        shoes_cache.put(
            7,
            FragmentedPacket {
                fragment_count: 2,
                fragment_received: 1,
                packet_len: 1,
                received: vec![Some(Bytes::from_static(b"x")), None],
                remote_location: NetLocation::from_str("127.0.0.1:53", None)
                    .expect("valid fragment test location"),
            },
        );
        handle_duplicate_fragment(&mut shoes_cache, 7, false);
        assert!(
            !shoes_cache.contains(&7),
            "shoes should discard partial state after a duplicate fragment"
        );
    }

    #[test]
    fn fragment_completion_address_matches_xray_and_shoes_semantics() {
        let first = NetLocation::from_str("127.0.0.1:53", None)
            .expect("valid first fragment location");
        let completing = NetLocation::from_str("127.0.0.1:5353", None)
            .expect("valid completing fragment location");

        assert_eq!(
            fragment_completion_location(first.clone(), completing.clone(), true),
            completing,
            "Xray keeps the address of the fragment that completes reassembly"
        );
        assert_eq!(
            fragment_completion_location(first.clone(), completing, false),
            first,
            "shoes keeps the first fragment address for the reassembled packet"
        );
    }

    #[test]
    fn response_packet_ids_match_xray_and_shoes_semantics() {
        let mut xray_next = 41;
        assert_eq!(udp_response_packet_id(&mut xray_next, false, true), 0);
        assert_eq!(
            xray_next, 41,
            "Xray unfragmented packets do not consume IDs"
        );
        let fragmented_id = udp_response_packet_id(&mut xray_next, true, true);
        assert_ne!(fragmented_id, 0, "Xray fragmented packets use non-zero IDs");
        assert_eq!(
            xray_next, 41,
            "Xray fragmented IDs are random, not sequential"
        );

        let mut shoes_next = u16::MAX;
        assert_eq!(
            udp_response_packet_id(&mut shoes_next, false, false),
            u16::MAX
        );
        assert_eq!(shoes_next, 0, "shoes increments IDs for every datagram");
        assert_eq!(udp_response_packet_id(&mut shoes_next, true, false), 0);
        assert_eq!(shoes_next, 1);
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
