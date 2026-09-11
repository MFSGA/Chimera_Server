use std::{
    collections::HashMap,
    convert::TryFrom,
    future::{Future, poll_fn},
    io::{Error, ErrorKind},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{
    RecvStream as H3RecvStream, SendStream as H3SendStream, SendStreamUnframed,
};
use h3_quinn::BidiStream;
use http::{Request, Response, StatusCode};
use rand::{
    RngExt,
    // distributions::{Alphanumeric, DistString},
    distr::{Alphanumeric, SampleString},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinSet,
};
use tracing::{debug, warn};

use crate::{
    address::NetLocation,
    config::server_config::{Hysteria2Client, Hysteria2ServerConfig},
    outbound::connect_tcp_outbound_with_vless_route,
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, register_connection,
    },
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

#[derive(Debug)]
struct HysteriaUserState {
    clients: Vec<Hysteria2Client>,
    masked_ids: HashMap<[u8; 16], String>,
}

#[derive(Debug)]
pub(crate) struct HysteriaUserStore {
    state: RwLock<HysteriaUserState>,
}

impl HysteriaUserStore {
    pub(crate) fn new(clients: Vec<Hysteria2Client>) -> Self {
        let mut state = HysteriaUserState {
            clients: Vec::with_capacity(clients.len()),
            masked_ids: HashMap::new(),
        };
        for client in clients {
            if client.xray_uuid_route {
                upsert_xray_hysteria_user(&mut state, client);
            } else {
                state.clients.push(client);
            }
        }
        Self {
            state: RwLock::new(state),
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<Hysteria2Client> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clients
            .clone()
    }

    pub(crate) fn add_user(&self, client: Hysteria2Client) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        upsert_xray_hysteria_user(&mut state, client);
    }

    pub(crate) fn remove_user_by_email(&self, email: &str) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = state.clients.iter().position(|client| {
            client.xray_uuid_route && client.email.as_deref().unwrap_or("") == email
        }) else {
            return;
        };
        let client = state.clients.remove(index);
        if let Some((masked_id, _)) = xray_uuid_auth_key(&client.password) {
            // Xray deletes the secondary UUID index directly. It does not
            // restore an older user that shared the same masked ID.
            state.masked_ids.remove(&masked_id);
        }
    }

    fn match_auth(
        &self,
        provided: &str,
        xray_compat: bool,
    ) -> Option<(Hysteria2Client, u32)> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let xray_has_users =
            xray_compat && state.clients.iter().any(|client| client.xray_uuid_route);

        if let Some(client) = state
            .clients
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

        if let Some((masked_id, vless_route)) = xray_uuid_auth_key(provided) {
            let auth = state.masked_ids.get(&masked_id)?;
            let client = state
                .clients
                .iter()
                .rev()
                .find(|client| client.xray_uuid_route && client.password == *auth)?
                .clone();
            return Some((client, vless_route));
        }

        state
            .clients
            .iter()
            .rev()
            .find(|client| client.xray_uuid_route && client.password == provided)
            .cloned()
            .map(|client| (client, 0))
    }
}

fn upsert_xray_hysteria_user(
    state: &mut HysteriaUserState,
    client: Hysteria2Client,
) {
    state.clients.retain(|existing| {
        !existing.xray_uuid_route || existing.password != client.password
    });
    if let Some((masked_id, _)) = xray_uuid_auth_key(&client.password) {
        state.masked_ids.insert(masked_id, client.password.clone());
    }
    state.clients.push(client);
}

fn hysteria2_traffic_context(
    client: &Hysteria2Client,
    inbound_tag: &str,
    peer_addr: SocketAddr,
    runtime: &DataPlaneRuntime,
) -> TrafficContext {
    let identity = client
        .email
        .clone()
        .unwrap_or_else(|| client.password.clone());
    let mut context = TrafficContext::new("hysteria2")
        .with_identity(identity)
        .with_inbound_tag(inbound_tag.to_string())
        .with_client_ip(peer_addr.ip())
        .with_user_level(client.level);
    runtime.apply_traffic_stats_policy(&mut context);
    context
}

pub async fn process_hysteria2_connection(
    resolver: Arc<dyn Resolver>,
    config: Arc<Hysteria2ServerConfig>,
    tx_bps: Arc<AtomicU64>,
    connection: quinn::Connection,
    inbound_tag: Arc<String>,
    runtime: DataPlaneRuntime,
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

    let user_store = runtime.hysteria_user_store(inbound_tag.as_str());
    let auth_ctx = match await_authentication(
        auth_hysteria2_connection(
            &mut h3_conn,
            config.as_ref(),
            user_store.as_deref(),
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

    // Keep post-authentication custom Hysteria2 streams under the same H3
    // connection owner that handled authentication. Modern Xray dispatches its
    // 0x401 TCP streams through the HTTP/3 stream queue; a second raw Quinn
    // accept loop can race that queue and lose streams.
    let udp_idle_timeout = config
        .xray_udp_idle_timeout_secs
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let peer_addr = connection.remote_address();

    if auth_ctx.udp_enabled {
        tokio::try_join!(
            drive_tcp_streams(
                &mut h3_conn,
                resolver.clone(),
                &auth_ctx,
                inbound_tag.clone(),
                peer_addr,
                runtime.clone(),
            ),
            drive_udp_datagrams(
                connection,
                resolver,
                &auth_ctx,
                inbound_tag,
                runtime,
                udp_idle_timeout,
            ),
        )
        .map(|_| ())
    } else {
        drive_tcp_streams(
            &mut h3_conn,
            resolver,
            &auth_ctx,
            inbound_tag,
            peer_addr,
            runtime,
        )
        .await
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
    user_store: Option<&HysteriaUserStore>,
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
                let auth_result = match user_store {
                    Some(store) => validate_auth_request_with_store(
                        req,
                        store,
                        config.xray_compat,
                    ),
                    None => validate_auth_request(
                        req,
                        config.clients.as_ref(),
                        config.xray_compat,
                    ),
                };
                match auth_result {
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

async fn drive_tcp_streams(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let mut stream_tasks = JoinSet::new();
    let result = loop {
        let stream = tokio::select! {
            accepted = next_hysteria_stream(h3_conn) => {
                match accepted {
                    Ok(stream) => stream,
                    Err(err) if err.is_h3_no_error() => break Ok(()),
                    Err(err) => break Err(map_h3_error(err)),
                }
            }
            completed = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                if let Some(Err(err)) = completed {
                    warn!("hysteria2 tcp stream task ended unexpectedly: {err}");
                }
                continue;
            }
        };
        let resolver = resolver.clone();
        let auth_ctx = auth_ctx.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        stream_tasks.spawn(async move {
            if let Err(err) = handle_tcp_stream(
                H3RawStream::new(stream),
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
    };

    abort_and_drain_hysteria_stream_tasks(&mut stream_tasks).await;
    result
}

async fn abort_and_drain_hysteria_stream_tasks(stream_tasks: &mut JoinSet<()>) {
    stream_tasks.abort_all();
    while let Some(result) = stream_tasks.join_next().await {
        if let Err(err) = result
            && !err.is_cancelled()
        {
            warn!("hysteria2 tcp stream task failed during cleanup: {err}");
        }
    }
}

async fn next_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
) -> Result<BidiStream<Bytes>, h3::error::ConnectionError> {
    poll_fn(|cx| poll_hysteria_stream(h3_conn, cx)).await
}

fn poll_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    cx: &mut Context<'_>,
) -> Poll<Result<BidiStream<Bytes>, h3::error::ConnectionError>> {
    loop {
        match h3_conn.inner.poll_control(cx) {
            Poll::Ready(Ok(_)) => continue,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => break,
        }
    }
    h3_conn.inner.poll_accept_bi(cx)
}

async fn handle_tcp_stream(
    mut stream: H3RawStream,
    resolver: Arc<dyn Resolver>,
    auth_ctx: AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let tcp_request_timeout = configured_tcp_request_timeout(
        auth_ctx.xray_compat,
        auth_ctx.client.level,
        &runtime,
    );
    let request = match read_tcp_request(
        &mut stream,
        tcp_request_timeout,
        auth_ctx.xray_compat,
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };
    send_tcp_response(&mut stream, TCP_SUCCESS_STATUS, "", auth_ctx.xray_compat)
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
            let _ = stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(err)) => {
            warn!("failed to connect to {}: {}", request.target, err);
            let _ = stream.shutdown().await;
            return Err(err);
        }
        Err(_) => {
            let _ = stream.shutdown().await;
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("client setup to {} timed out", request.target),
            ));
        }
    };

    let mut context = hysteria2_traffic_context(
        &auth_ctx.client,
        inbound_tag.as_str(),
        peer_addr,
        &runtime,
    );
    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }

    proxy_tcp(stream, connection.stream, context).await
}

struct TcpRequest {
    target: NetLocation,
}

fn configured_tcp_request_timeout(
    xray_compat: bool,
    level: u32,
    runtime: &DataPlaneRuntime,
) -> Option<Duration> {
    xray_compat.then(|| runtime.xray_handshake_timeout_for_level(level))
}

async fn read_tcp_request<S>(
    stream: &mut S,
    timeout: Option<Duration>,
    xray_compat: bool,
) -> std::io::Result<TcpRequest>
where
    S: AsyncRead + Unpin,
{
    match timeout {
        Some(timeout) => {
            tokio::time::timeout(timeout, TcpRequest::read(stream, xray_compat))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::TimedOut,
                        "hysteria2 TCP request header timed out",
                    )
                })?
        }
        None => TcpRequest::read(stream, xray_compat).await,
    }
}

impl TcpRequest {
    async fn read<S>(stream: &mut S, xray_compat: bool) -> std::io::Result<Self>
    where
        S: AsyncRead + Unpin,
    {
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
        let target = if xray_compat {
            None
        } else {
            Some(parse_tcp_request_target(address_bytes.as_slice())?)
        };

        let padding_len =
            validate_tcp_request_padding_len(read_varint(stream).await?)?;
        skip_padding(stream, padding_len).await?;

        let target = match target {
            Some(target) => target,
            None => parse_tcp_request_target(address_bytes.as_slice())?,
        };
        Ok(Self { target })
    }
}

async fn proxy_tcp<S>(
    quic_stream: S,
    tcp_stream: Box<dyn crate::async_stream::AsyncStream>,
    context: TrafficContext,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _connection_guard = register_connection(Some(&context));
    let mut quic_stream = MeteredStream::new(
        quic_stream,
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

struct H3RawStream {
    stream: BidiStream<Bytes>,
    read_buffer: Bytes,
}

impl H3RawStream {
    fn new(stream: BidiStream<Bytes>) -> Self {
        Self {
            stream,
            read_buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for H3RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !this.read_buffer.is_empty() {
                let len = this.read_buffer.len().min(buf.remaining());
                let chunk = this.read_buffer.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            match H3RecvStream::poll_data(&mut this.stream, cx) {
                Poll::Ready(Ok(Some(data))) => this.read_buffer = data,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(Error::other(err)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H3RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut data = buf;
        match SendStreamUnframed::poll_send(&mut this.stream, cx, &mut data) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match H3SendStream::poll_finish(&mut self.get_mut().stream, cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
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
    validate_auth_request_with_match(req, xray_compat, |provided| {
        match_hysteria_auth(provided, clients, xray_compat)
    })
}

fn validate_auth_request_with_store(
    req: Request<()>,
    store: &HysteriaUserStore,
    xray_compat: bool,
) -> Result<AuthInfo, AuthReject> {
    validate_auth_request_with_match(req, xray_compat, |provided| {
        store.match_auth(provided, xray_compat)
    })
}

fn validate_auth_request_with_match<F>(
    req: Request<()>,
    xray_compat: bool,
    match_auth: F,
) -> Result<AuthInfo, AuthReject>
where
    F: FnOnce(&str) -> Option<(Hysteria2Client, u32)>,
{
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

    let (client, vless_route) =
        match_auth(provided).ok_or(AuthReject::Unauthorized("password mismatch"))?;

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
    let cc_rx_value = if !xray_compat {
        // Shoes always advertises zero receive bandwidth in its auth response,
        // regardless of the local bandwidth settings used by Chimera.
        "0".to_string()
    } else if rx_auto {
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

mod proxy_masquerade;
use proxy_masquerade::*;

pub(crate) fn build_xray_proxy_transport(
    masquerade: Option<
        &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    >,
) -> std::io::Result<Option<Arc<XrayProxyTransport>>> {
    build_xray_proxy_transport_impl(masquerade)
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

fn parse_tcp_request_target(address_bytes: &[u8]) -> std::io::Result<NetLocation> {
    let address = std::str::from_utf8(address_bytes)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    NetLocation::from_str(address, None)
}

async fn read_varint<S>(stream: &mut S) -> std::io::Result<u64>
where
    S: AsyncRead + Unpin,
{
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

async fn skip_padding<S>(stream: &mut S, mut len: usize) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
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

async fn send_tcp_response<S>(
    stream: &mut S,
    status: u8,
    message: &str,
    xray_compat: bool,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let buf = build_tcp_response(status, message, xray_compat)?;
    stream.write_all(&buf).await.map_err(Error::other)?;
    stream.flush().await.map_err(Error::other)
}

mod udp_session;
use udp_session::*;

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
mod tests;
