use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use rand::RngExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::{Mutex, oneshot},
    time::{Duration, sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tracing::{debug, error};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{
        ServerConfig, ServerProxyConfig, XhttpDataPlacement, XhttpMode,
        XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement,
        XhttpServerConfig,
    },
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
};
#[cfg(feature = "reality")]
use crate::{
    config::server_config::RealityTransportConfig,
    handler::reality::accept_reality_stream,
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig, handler::tls::build_server_config,
};

use super::process_stream;

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
const XHTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(4);

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

pub async fn start_xhttp_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        ..
    } = config;

    let listener_config = parse_listener_protocol(protocol)?;

    let bind_addr = match bind_location {
        BindLocation::Address(address) => address.to_socket_addr()?,
    };

    let mut rules_stack = vec![];
    let server_handler = Arc::new(create_tcp_server_handler(
        listener_config.inner,
        &tag,
        &mut rules_stack,
    )?);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let state = Arc::new(AppState::new(
        listener_config.xhttp_config,
        server_handler,
        resolver,
        runtime,
    ));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let security = listener_config.security.clone();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    error!("xhttp accept failed: {}", err);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);

            let state = state.clone();
            let security = security.clone();
            tokio::spawn(async move {
                let stream: Box<dyn AsyncStream> = Box::new(stream);
                let wrapped_stream: std::io::Result<Box<dyn AsyncStream>> =
                    match security {
                        XhttpSecurityLayer::None => Ok(stream),
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::Tls(acceptor) => {
                            accept_xhttp_tls(acceptor, stream).await
                        }
                        #[cfg(feature = "reality")]
                        XhttpSecurityLayer::Reality(config) => {
                            accept_reality_stream(stream, &config).await.map(
                                |stream| Box::new(stream) as Box<dyn AsyncStream>,
                            )
                        }
                    };

                match wrapped_stream {
                    Ok(stream) => {
                        serve_http_connection(stream, state, peer_addr).await
                    }
                    Err(err) => {
                        error!("xhttp accept {} failed: {}", peer_addr, err);
                    }
                }
            });
        }
    });

    Ok(vec![handle])
}

struct XhttpListenerConfig {
    xhttp_config: XhttpServerConfig,
    inner: ServerProxyConfig,
    security: XhttpSecurityLayer,
}

#[derive(Clone)]
enum XhttpSecurityLayer {
    None,
    #[cfg(feature = "tls")]
    Tls(TlsAcceptor),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
}

#[cfg(feature = "tls")]
async fn accept_xhttp_tls(
    acceptor: TlsAcceptor,
    stream: Box<dyn AsyncStream>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    match tokio::time::timeout(XHTTP_HEADER_READ_TIMEOUT, acceptor.accept(stream))
        .await
    {
        Ok(result) => {
            result.map(|tls_stream| Box::new(tls_stream) as Box<dyn AsyncStream>)
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "xhttp tls handshake timeout",
        )),
    }
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> std::io::Result<XhttpListenerConfig> {
    match protocol {
        ServerProxyConfig::Xhttp { config, inner } => Ok(XhttpListenerConfig {
            xhttp_config: config,
            inner: *inner,
            security: XhttpSecurityLayer::None,
        }),
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(TlsServerConfig {
            certificates,
            mut alpn_protocols,
            enable_session_resumption,
            reject_unknown_sni,
            min_version,
            max_version,
            server_name: _,
            inner,
        }) => match *inner {
            ServerProxyConfig::Xhttp { config, inner } => {
                if !alpn_protocols.iter().any(|proto| proto == "h2") {
                    alpn_protocols.push("h2".to_string());
                }

                let tls_config = build_server_config(
                    &certificates,
                    &alpn_protocols,
                    enable_session_resumption,
                    reject_unknown_sni,
                    min_version.as_deref(),
                    max_version.as_deref(),
                )?;

                Ok(XhttpListenerConfig {
                    xhttp_config: config,
                    inner: *inner,
                    security: XhttpSecurityLayer::Tls(TlsAcceptor::from(Arc::new(
                        tls_config,
                    ))),
                })
            }
            _ => Err(std::io::Error::other(
                "invalid tls-wrapped protocol for xhttp server",
            )),
        },
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            match reality_config.inner.as_ref() {
                ServerProxyConfig::Xhttp { config, inner } => {
                    Ok(XhttpListenerConfig {
                        xhttp_config: config.clone(),
                        inner: (**inner).clone(),
                        security: XhttpSecurityLayer::Reality(reality_config),
                    })
                }
                _ => Err(std::io::Error::other(
                    "invalid reality-wrapped protocol for xhttp server",
                )),
            }
        }
        _ => Err(std::io::Error::other("invalid protocol for xhttp server")),
    }
}

fn configure_http_builder(
    builder: &mut auto::Builder<TokioExecutor>,
    server_max_header_bytes: usize,
) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(XHTTP_HEADER_READ_TIMEOUT)
        .max_buf_size(server_max_header_bytes.max(8192));
    builder
        .http2()
        .max_header_list_size(server_max_header_bytes as u32);
}

async fn serve_http_connection<IO>(
    io: IO,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http_builder(&mut builder, state.server_max_header_bytes);
    let service =
        service_fn(move |request| handle_request(request, state.clone(), peer_addr));

    if let Err(err) = builder.serve_connection(io, service).await {
        error!("xhttp connection {} exited: {}", peer_addr, err);
    }
}

#[derive(Clone)]
struct AppState {
    mode: XhttpMode,
    host: Option<String>,
    base_path: String,
    trusted_x_forwarded_for: Vec<String>,
    min_padding: usize,
    max_padding: usize,
    max_each_post_bytes: usize,
    stream_up_server_secs: (usize, usize),
    server_max_header_bytes: usize,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: XhttpPaddingPlacement,
    padding_method: XhttpPaddingMethod,
    no_sse_header: bool,
    uplink_http_method: String,
    session_placement: XhttpPlacement,
    session_key: String,
    seq_placement: XhttpPlacement,
    seq_key: String,
    uplink_data_placement: XhttpDataPlacement,
    uplink_data_key: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    sessions: SessionStore,
}

impl AppState {
    fn new(
        config: XhttpServerConfig,
        server_handler: Arc<Box<dyn TcpServerHandler>>,
        resolver: Arc<dyn Resolver>,
        runtime: RuntimeState,
    ) -> Self {
        Self {
            mode: config.mode,
            host: config.host,
            base_path: normalize_base_path(config.path),
            trusted_x_forwarded_for: config.trusted_x_forwarded_for,
            min_padding: config.min_padding,
            max_padding: config.max_padding,
            max_each_post_bytes: config.max_each_post_bytes,
            stream_up_server_secs: config.stream_up_server_secs,
            server_max_header_bytes: config.server_max_header_bytes,
            padding_obfs_mode: config.padding_obfs_mode,
            padding_key: config.padding_key,
            padding_header: config.padding_header,
            padding_placement: config.padding_placement,
            padding_method: config.padding_method,
            no_sse_header: config.no_sse_header,
            uplink_http_method: config.uplink_http_method,
            session_placement: config.session_placement,
            session_key: config.session_key,
            seq_placement: config.seq_placement,
            seq_key: config.seq_key,
            uplink_data_placement: config.uplink_data_placement,
            uplink_data_key: config.uplink_data_key,
            server_handler,
            resolver,
            runtime,
            sessions: SessionStore::new(
                Duration::from_secs(config.session_ttl_secs),
                config.max_buffered_posts,
            ),
        }
    }

    fn validate_host(&self, header_host: Option<&str>) -> bool {
        match (&self.host, header_host) {
            (None, _) => true,
            (Some(expected), Some(actual)) => {
                let normalized = actual
                    .split(':')
                    .next()
                    .map(|host| host.to_ascii_lowercase())
                    .unwrap_or_default();
                &normalized == expected
            }
            _ => false,
        }
    }

    fn extract_meta(
        &self,
        request: &Request<Incoming>,
    ) -> (Option<String>, Option<String>) {
        let trimmed_base_path = self.base_path.trim_end_matches('/');
        let path_tail = if request.uri().path() == trimmed_base_path {
            ""
        } else {
            request
                .uri()
                .path()
                .strip_prefix(&self.base_path)
                .unwrap_or("")
        };
        let path_segments = path_tail
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let mut path_index = 0usize;
        let mut next_path_value = || {
            let value = path_segments
                .get(path_index)
                .map(|value| (*value).to_string());
            if value.is_some() {
                path_index += 1;
            }
            value
        };

        let session_id = match self.session_placement {
            XhttpPlacement::Path => next_path_value(),
            XhttpPlacement::Query => {
                query_value(request.uri().query(), &self.session_key)
            }
            XhttpPlacement::Header => {
                header_value(request.headers(), &self.session_key)
            }
            XhttpPlacement::Cookie => {
                cookie_value(request.headers(), &self.session_key)
            }
        };
        let seq = match self.seq_placement {
            XhttpPlacement::Path => next_path_value(),
            XhttpPlacement::Query => {
                query_value(request.uri().query(), &self.seq_key)
            }
            XhttpPlacement::Header => header_value(request.headers(), &self.seq_key),
            XhttpPlacement::Cookie => cookie_value(request.headers(), &self.seq_key),
        };
        (session_id, seq)
    }

    fn validate_padding(
        &self,
        path_query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> bool {
        let padding = if self.padding_obfs_mode {
            cookie_value(headers, &self.padding_key)
                .or_else(|| {
                    header_value(headers, &self.padding_header).and_then(|value| {
                        match self.padding_placement {
                            XhttpPaddingPlacement::Header => Some(value),
                            _ => query_value_from_url(&value, &self.padding_key),
                        }
                    })
                })
                .or_else(|| query_value(path_query, &self.padding_key))
        } else if let Some(referer) = header_value(headers, "referer") {
            query_value_from_url(&referer, "x_padding")
        } else {
            query_value(path_query, "x_padding")
        };

        let Some(padding) = padding else {
            return false;
        };

        is_padding_valid(
            &padding,
            self.min_padding,
            self.max_padding,
            self.padding_method,
        )
    }

    fn response_uses_credentials(&self) -> bool {
        self.session_placement == XhttpPlacement::Cookie
            || self.seq_placement == XhttpPlacement::Cookie
            || self.padding_placement == XhttpPaddingPlacement::Cookie
            || self.uplink_data_placement == XhttpDataPlacement::Cookie
    }

    fn decorate_response(
        &self,
        response: &mut Response<ResponseBody>,
        request_method: &Method,
        request_headers: &hyper::HeaderMap,
    ) {
        let origin = request_headers
            .get(header::ORIGIN)
            .cloned()
            .unwrap_or_else(|| hyper::header::HeaderValue::from_static("*"));
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);

        if self.response_uses_credentials() {
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                hyper::header::HeaderValue::from_static("true"),
            );
        }

        if request_method == Method::OPTIONS {
            let allow_method = request_headers
                .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                .cloned()
                .unwrap_or_else(|| hyper::header::HeaderValue::from_static("*"));
            response
                .headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_METHODS, allow_method);
            let allow_headers = request_headers
                .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                .cloned()
                .unwrap_or_else(|| hyper::header::HeaderValue::from_static("*"));
            response
                .headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers);
        }

        apply_response_padding(response.headers_mut(), self);
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    let request_method = request.method().clone();
    let request_headers = request.headers().clone();

    if request_header_bytes(request.headers()) > state.server_max_header_bytes {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            limit = state.server_max_header_bytes,
            "xhttp request rejected by header size limit"
        );
        return Ok(simple_response(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));
    }

    let host_header = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let authority_host = request.uri().authority().map(|value| value.as_str());
    let request_host = host_header.or(authority_host);

    if !state.validate_host(request_host) {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            host = ?request_host,
            "xhttp request rejected by host validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    let path = request.uri().path().to_string();
    if !matches_base_path(&path, &state.base_path) {
        debug!(
            method = %request.method(),
            path = %path,
            base_path = %state.base_path,
            "xhttp request rejected by path validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    if request_method == Method::OPTIONS {
        let mut response = simple_response(StatusCode::OK);
        state.decorate_response(&mut response, &request_method, &request_headers);
        return Ok(response);
    }

    if !state.validate_padding(request.uri().query(), request.headers()) {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            query = ?request.uri().query(),
            "xhttp request rejected by padding validation"
        );
        let mut response = simple_response(StatusCode::BAD_REQUEST);
        state.decorate_response(&mut response, &request_method, &request_headers);
        return Ok(response);
    }

    let logical_peer_addr =
        trusted_forwarded_peer(&request_headers, &state.trusted_x_forwarded_for)
            .unwrap_or(peer_addr);
    let stream_up_padding = state.padding_obfs_mode
        || header_value(&request_headers, "referer").is_some();
    let (session_id, seq) = state.extract_meta(&request);

    let is_downlink_method = request.method() == Method::GET;
    let is_uplink_method =
        request.method().as_str() == state.uplink_http_method.as_str();
    let mut response = match (is_downlink_method, is_uplink_method, session_id, seq)
    {
        (true, _, Some(session_id), None)
            if matches!(
                state.mode,
                XhttpMode::Auto | XhttpMode::PacketUp | XhttpMode::StreamUp
            ) =>
        {
            handle_stream_down(state.clone(), session_id, logical_peer_addr).await
        }
        (_, true, None, None)
            if matches!(
                state.mode,
                XhttpMode::Auto | XhttpMode::StreamOne | XhttpMode::StreamUp
            ) =>
        {
            handle_stream_one(request, state.clone(), logical_peer_addr).await
        }
        (_, true, Some(session_id), None)
            if matches!(state.mode, XhttpMode::Auto | XhttpMode::StreamUp) =>
        {
            handle_stream_up(
                request,
                state.clone(),
                session_id,
                logical_peer_addr,
                stream_up_padding,
            )
            .await
        }
        (_, true, Some(session_id), Some(seq))
            if matches!(state.mode, XhttpMode::Auto | XhttpMode::PacketUp) =>
        {
            handle_packet_up(
                request,
                state.clone(),
                session_id,
                seq,
                logical_peer_addr,
            )
            .await
        }
        _ => simple_response(StatusCode::METHOD_NOT_ALLOWED),
    };

    state.decorate_response(&mut response, &request_method, &request_headers);
    Ok(response)
}

async fn handle_stream_one(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
    let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
    let logical_stream = XhttpLogicalStream::new(server_read, server_write);

    spawn_handler_stream(logical_stream, state.clone(), peer_addr);

    let mut upload_writer = client_upload;
    let mut body = request.into_body();
    tokio::spawn(async move {
        while let Some(frame_result) = body.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Some(chunk) = frame.data_ref()
                        && upload_writer.write_all(chunk).await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = upload_writer.shutdown().await;
    });

    reader_response(StatusCode::OK, client_download, state.no_sse_header)
}

async fn handle_stream_up(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let sessions = state.sessions.clone();
    let upload_session_id = session_id.clone();
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut body = request.into_body();
        let mut upload_state = session.upload.lock().await;
        while let Some(frame_result) = body.frame().await {
            let frame = match frame_result {
                Ok(frame) => frame,
                Err(error) => {
                    error!("xhttp stream-up body failed: {}", error);
                    sessions.remove(&upload_session_id);
                    let _ = done_tx.send(());
                    return;
                }
            };
            if let Some(chunk) = frame.data_ref()
                && let Err(error) = upload_state.writer.write_all(chunk).await
            {
                error!("xhttp stream-up write failed: {}", error);
                sessions.remove(&upload_session_id);
                let _ = done_tx.send(());
                return;
            }
        }
        let _ = done_tx.send(());
    });

    stream_up_response(done_rx, &state, padding_enabled)
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let Some(reader) = session.take_downlink_reader().await else {
        return simple_response(StatusCode::CONFLICT);
    };

    let cleanup = SessionCleanupGuard {
        sessions: state.sessions.clone(),
        session_id,
    };
    let body_stream = futures::stream::unfold(
        (ReaderStream::new(reader), cleanup),
        |(mut reader, cleanup)| async move {
            match reader.next().await {
                Some(Ok(bytes)) => Some((Ok(Frame::data(bytes)), (reader, cleanup))),
                Some(Err(err)) => {
                    error!("xhttp stream-down read failed: {}", err);
                    None
                }
                None => None,
            }
        },
    );

    stream_response(StatusCode::OK, body_stream.boxed(), state.no_sse_header)
}

async fn handle_packet_up(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session_id: String,
    seq: String,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let Ok(seq) = seq.parse::<u64>() else {
        return simple_response(StatusCode::BAD_REQUEST);
    };

    let (parts, body) = request.into_parts();
    let header_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header
    ) {
        match decode_chunked_header_payload(&parts.headers, &state.uplink_data_key) {
            Ok(payload) => payload,
            Err(_) => return simple_response(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let cookie_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Cookie
    ) {
        match decode_chunked_cookie_payload(&parts.headers, &state.uplink_data_key) {
            Ok(payload) => payload,
            Err(_) => return simple_response(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let body_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        match collect_body_limited(body, state.max_each_post_bytes).await {
            Ok(payload) => payload,
            Err(status) => return simple_response(status),
        }
    } else {
        Vec::new()
    };

    let payload = match state.uplink_data_placement {
        XhttpDataPlacement::Auto => {
            let mut payload = Vec::with_capacity(
                header_payload.len() + cookie_payload.len() + body_payload.len(),
            );
            payload.extend_from_slice(&header_payload);
            payload.extend_from_slice(&cookie_payload);
            payload.extend_from_slice(&body_payload);
            payload
        }
        XhttpDataPlacement::Body => body_payload,
        XhttpDataPlacement::Header => header_payload,
        XhttpDataPlacement::Cookie => cookie_payload,
    };
    if payload.len() > state.max_each_post_bytes {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let collected = Bytes::from(payload);

    let session = state.sessions.get_or_create(&session_id);
    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let mut upload_state = session.upload.lock().await;
    match upload_state.packet_queue.push_packet(seq, collected) {
        Ok(()) => {}
        Err(QueueError::TooManyBuffered) => {
            return simple_response(StatusCode::CONFLICT);
        }
    }

    while let Some(chunk) = upload_state.packet_queue.pop_ready() {
        if let Err(err) = upload_state.writer.write_all(&chunk).await {
            error!("xhttp packet-up write failed: {}", err);
            state.sessions.remove(&session_id);
            return simple_response(StatusCode::BAD_GATEWAY);
        }
    }

    simple_response(StatusCode::OK)
}

fn stream_up_response(
    done_rx: oneshot::Receiver<()>,
    state: &AppState,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let (min_secs, max_secs) = state.stream_up_server_secs;
    let min_padding = state.min_padding;
    let max_padding = state.max_padding;
    let body_stream =
        futures::stream::unfold(done_rx, move |mut done_rx| async move {
            if !padding_enabled || max_secs == 0 {
                let _ = (&mut done_rx).await;
                return None;
            }

            let delay_secs = random_inclusive(min_secs, max_secs);
            tokio::select! {
                _ = &mut done_rx => None,
                _ = sleep(Duration::from_secs(delay_secs as u64)) => {
                    let padding_len = random_inclusive(min_padding, max_padding);
                    Some((
                        Ok(Frame::data(Bytes::from(vec![b'X'; padding_len]))),
                        done_rx,
                    ))
                }
            }
        });

    stream_response(StatusCode::OK, body_stream, true)
}

fn spawn_handler_stream(
    stream: XhttpLogicalStream,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) {
    tokio::spawn(async move {
        if let Err(err) = process_stream(
            stream,
            state.server_handler.clone(),
            state.resolver.clone(),
            peer_addr,
            state.runtime.clone(),
        )
        .await
        {
            error!("xhttp logical stream {} failed: {}", peer_addr, err);
        }
    });
}

fn reader_response(
    status: StatusCode,
    reader: DuplexStream,
    no_sse_header: bool,
) -> Response<ResponseBody> {
    let body_stream = ReaderStream::new(reader).filter_map(|result| async move {
        match result {
            Ok(bytes) => Some(Ok(Frame::data(bytes))),
            Err(err) => {
                error!("xhttp response read failed: {}", err);
                None
            }
        }
    });
    stream_response(status, body_stream.boxed(), no_sse_header)
}

fn stream_response<S>(
    status: StatusCode,
    body_stream: S,
    no_sse_header: bool,
) -> Response<ResponseBody>
where
    S: futures::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static,
{
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-accel-buffering", "no");
    if !no_sse_header {
        response = response.header(header::CONTENT_TYPE, "text/event-stream");
    }
    response
        .body(BodyExt::boxed_unsync(StreamBody::new(body_stream)))
        .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn simple_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

#[derive(Clone)]
struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Arc<XhttpSession>>>>,
    ttl: Duration,
    max_buffered_posts: usize,
}

impl SessionStore {
    fn new(ttl: Duration, max_buffered_posts: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_buffered_posts,
        }
    }

    fn get_or_create(&self, session_id: &str) -> Arc<XhttpSession> {
        if let Some(existing) = self.inner.read().unwrap().get(session_id) {
            return existing.clone();
        }

        let session = Arc::new(XhttpSession::new(self.max_buffered_posts));
        let inserted = self
            .inner
            .write()
            .unwrap()
            .entry(session_id.to_string())
            .or_insert_with(|| session.clone())
            .clone();
        self.spawn_ttl_cleanup(session_id.to_string());
        inserted
    }

    fn remove(&self, session_id: &str) {
        self.inner.write().unwrap().remove(session_id);
    }

    fn spawn_ttl_cleanup(&self, session_id: String) {
        let ttl = self.ttl;
        let store = self.clone();
        tokio::spawn(async move {
            sleep(ttl).await;

            let session = { store.inner.read().unwrap().get(&session_id).cloned() };

            if let Some(session) = session
                && !session.fully_connected.load(Ordering::Acquire)
            {
                store.remove(&session_id);
            }
        });
    }
}

struct SessionCleanupGuard {
    sessions: SessionStore,
    session_id: String,
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        self.sessions.remove(&self.session_id);
    }
}

struct XhttpSession {
    upload: Mutex<UploadState>,
    downlink_reader: Mutex<Option<DuplexStream>>,
    handler_stream: Mutex<Option<XhttpLogicalStream>>,
    fully_connected: AtomicBool,
}

impl XhttpSession {
    fn new(max_buffered_posts: usize) -> Self {
        let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
        let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);

        Self {
            upload: Mutex::new(UploadState {
                writer: client_upload,
                packet_queue: PacketQueue::new(max_buffered_posts),
            }),
            downlink_reader: Mutex::new(Some(client_download)),
            handler_stream: Mutex::new(Some(XhttpLogicalStream::new(
                server_read,
                server_write,
            ))),
            fully_connected: AtomicBool::new(false),
        }
    }

    async fn take_handler_stream(&self) -> Option<XhttpLogicalStream> {
        self.handler_stream.lock().await.take()
    }

    async fn take_downlink_reader(&self) -> Option<DuplexStream> {
        self.downlink_reader.lock().await.take()
    }
}

struct UploadState {
    writer: DuplexStream,
    packet_queue: PacketQueue,
}

struct XhttpLogicalStream {
    reader: DuplexStream,
    writer: DuplexStream,
}

impl XhttpLogicalStream {
    fn new(reader: DuplexStream, writer: DuplexStream) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpLogicalStream {
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

impl AsyncStream for XhttpLogicalStream {}

struct PacketQueue {
    next_seq: u64,
    buffered: BTreeMap<u64, Bytes>,
    ready: Vec<Bytes>,
    max_buffered_posts: usize,
}

impl PacketQueue {
    fn new(max_buffered_posts: usize) -> Self {
        Self {
            next_seq: 0,
            buffered: BTreeMap::new(),
            ready: Vec::new(),
            max_buffered_posts,
        }
    }

    fn push_packet(&mut self, seq: u64, data: Bytes) -> Result<(), QueueError> {
        if seq < self.next_seq {
            return Ok(());
        }
        if self.buffered.len() >= self.max_buffered_posts
            && !self.buffered.contains_key(&seq)
        {
            return Err(QueueError::TooManyBuffered);
        }

        self.buffered.insert(seq, data);
        while let Some(chunk) = self.buffered.remove(&self.next_seq) {
            self.ready.push(chunk);
            self.next_seq += 1;
        }

        Ok(())
    }

    fn pop_ready(&mut self) -> Option<Bytes> {
        if self.ready.is_empty() {
            return None;
        }
        Some(self.ready.remove(0))
    }
}

enum QueueError {
    TooManyBuffered,
}

fn normalize_base_path(mut path: String) -> String {
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn header_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn trusted_forwarded_peer(
    headers: &hyper::HeaderMap,
    trusted_x_forwarded_for: &[String],
) -> Option<std::net::SocketAddr> {
    if !trusted_x_forwarded_for.is_empty()
        && !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(header.trim()))
    {
        return None;
    }

    let first = headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()?;
    let mut candidate = first;
    if candidate.starts_with('[') && candidate.ends_with(']') {
        candidate = &candidate[1..candidate.len() - 1];
    }
    if candidate
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || candidate
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        candidate = candidate.trim();
    }

    let ip = candidate.parse::<std::net::IpAddr>().ok()?;
    let ip = match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ipv6), std::net::IpAddr::V4),
        ip => ip,
    };
    Some(std::net::SocketAddr::new(ip, 0))
}

fn cookie_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().find_map(|value| {
        let value = value.to_str().ok()?;
        value.split(';').find_map(|cookie| {
            let (name, value) = cookie.trim().split_once('=')?;
            (name == key && !value.is_empty()).then(|| value.to_string())
        })
    })
}

fn decode_chunked_header_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let header_name = format!("{key}-{index}");
        let Some(chunk) = header_value(headers, &header_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

fn decode_chunked_cookie_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let cookie_name = format!("{key}_{index}");
        let Some(chunk) = cookie_value(headers, &cookie_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

async fn collect_body_limited<B>(
    mut body: B,
    max_bytes: usize,
) -> Result<Vec<u8>, StatusCode>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut payload = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(chunk) = frame.data_ref() {
            let next_len = payload.len().saturating_add(chunk.len());
            if next_len > max_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            payload.extend_from_slice(chunk);
        }
    }
    Ok(payload)
}

fn decode_xhttp_payload(encoded: &str) -> std::io::Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid XHTTP uplink payload encoding: {error}"),
        )
    })
}

fn matches_base_path(request_path: &str, base_path: &str) -> bool {
    let trimmed_base_path = base_path.trim_end_matches('/');
    request_path == trimmed_base_path || request_path.starts_with(base_path)
}

fn query_value_from_url(raw_url: &str, key: &str) -> Option<String> {
    let query = raw_url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    query_value(Some(query), key)
}

fn request_header_bytes(headers: &hyper::HeaderMap) -> usize {
    headers.iter().fold(2usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(2)
            .saturating_add(value.as_bytes().len())
            .saturating_add(2)
    })
}

fn random_inclusive(from: usize, to: usize) -> usize {
    let low = from.min(to);
    let high = from.max(to);
    if low == high {
        low
    } else {
        rand::rng().random_range(low..=high)
    }
}

fn is_padding_valid(
    padding: &str,
    min_padding: usize,
    max_padding: usize,
    method: XhttpPaddingMethod,
) -> bool {
    if padding.is_empty() {
        return false;
    }

    match method {
        XhttpPaddingMethod::RepeatX => {
            padding.len() >= min_padding && padding.len() <= max_padding
        }
        XhttpPaddingMethod::Tokenish => {
            let encoded_len = hpack_huffman_encoded_len(padding);
            encoded_len >= min_padding.saturating_sub(2)
                && encoded_len <= max_padding.saturating_add(2)
        }
    }
}

fn generate_padding(method: XhttpPaddingMethod, target_len: usize) -> String {
    match method {
        XhttpPaddingMethod::RepeatX => "X".repeat(target_len),
        XhttpPaddingMethod::Tokenish => generate_tokenish_padding(target_len),
    }
}

fn generate_tokenish_padding(target_len: usize) -> String {
    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if target_len == 0 {
        return String::new();
    }

    let initial_len = target_len.saturating_mul(5).div_ceil(4).max(1);
    let mut rng = rand::rng();
    let mut padding = String::with_capacity(initial_len + 4);
    for _ in 0..initial_len {
        let index = rng.random_range(0..BASE62.len());
        padding.push(BASE62[index] as char);
    }
    drop(rng);

    let mut adjust_char = 'X';
    for _ in 0..150 {
        let current_len = hpack_huffman_encoded_len(&padding);
        if current_len.abs_diff(target_len) <= 2 {
            return padding;
        }
        if current_len < target_len {
            padding.push(adjust_char);
            adjust_char = if adjust_char == 'X' { 'Z' } else { 'X' };
        } else if padding.pop().is_none() {
            break;
        }
    }
    padding
}

fn hpack_huffman_encoded_len(value: &str) -> usize {
    let bits = value.bytes().fold(0usize, |total, byte| {
        total.saturating_add(hpack_huffman_bit_len(byte))
    });
    bits.div_ceil(8)
}

fn hpack_huffman_bit_len(byte: u8) -> usize {
    match byte {
        b'0' | b'1' | b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'B'..=b'W' | b'Y' | b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
        b'X' | b'Z' => 8,
        _ => 8,
    }
}

fn apply_response_padding(headers: &mut hyper::HeaderMap, state: &AppState) {
    let padding_len = random_inclusive(state.min_padding, state.max_padding);

    if !state.padding_obfs_mode {
        if let Ok(value) =
            hyper::header::HeaderValue::from_str(&"X".repeat(padding_len))
        {
            headers.insert("x-padding", value);
        }
        return;
    }

    let padding = generate_padding(state.padding_method, padding_len);
    match state.padding_placement {
        XhttpPaddingPlacement::Cookie => {
            let cookie = format!("{}={}; Path=/", state.padding_key, padding);
            if let Ok(value) = hyper::header::HeaderValue::from_str(&cookie) {
                headers.append(header::SET_COOKIE, value);
            }
        }
        XhttpPaddingPlacement::Header => {
            if let Ok(name) = hyper::header::HeaderName::from_bytes(
                state.padding_header.as_bytes(),
            ) && let Ok(value) = hyper::header::HeaderValue::from_str(&padding)
            {
                headers.insert(name, value);
            }
        }
        XhttpPaddingPlacement::Query => {}
        XhttpPaddingPlacement::QueryInHeader => {
            let value = format!("?{}={}", state.padding_key, padding);
            if let Ok(name) = hyper::header::HeaderName::from_bytes(
                state.padding_header.as_bytes(),
            ) && let Ok(value) = hyper::header::HeaderValue::from_str(&value)
            {
                headers.insert(name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhttp_trusted_forwarded_peer_matches_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            hyper::header::HeaderValue::from_static("203.0.113.77, 198.51.100.2"),
        );

        assert_eq!(
            trusted_forwarded_peer(&headers, &[]),
            Some("203.0.113.77:0".parse().expect("forwarded peer"))
        );
        assert_eq!(
            trusted_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
            None
        );

        headers.insert(
            "x-trusted-cdn",
            hyper::header::HeaderValue::from_static("yes"),
        );
        assert_eq!(
            trusted_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
            Some("203.0.113.77:0".parse().expect("trusted forwarded peer"))
        );
    }

    #[tokio::test]
    async fn xhttp_times_out_incomplete_headers_like_xray_v26_2_6() {
        let (mut client, server) = tokio::io::duplex(4096);
        let io = TokioIo::new(server);
        let mut builder = auto::Builder::new(TokioExecutor::new());
        configure_http_builder(&mut builder, 8192);
        let service = service_fn(|_request| async {
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        });
        let mut server_task =
            tokio::spawn(async move { builder.serve_connection(io, service).await });

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example\r\n")
            .await
            .expect("write incomplete XHTTP request");
        assert!(
            tokio::time::timeout(Duration::from_millis(3500), &mut server_task)
                .await
                .is_err(),
            "XHTTP header timeout must not fire before Xray's four-second window"
        );

        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("XHTTP header timeout should fire near four seconds")
            .expect("server task should not panic");
        let error = result.expect_err("incomplete XHTTP headers must time out");
        assert!(
            error
                .to_string()
                .contains("read header from client timeout"),
            "expected Hyper header timeout, got {error}"
        );
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn tls_xhttp_times_out_handshake_like_xray_v26_2_6() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate test certificate");
        let tls_config = build_server_config(
            &[crate::config::server_config::TlsCertificateConfig {
                certificate_path: None,
                certificate_pem: generated.cert.pem().into_bytes(),
                key_path: None,
                key_pem: Some(generated.signing_key.serialize_pem().into_bytes()),
                usage:
                    crate::config::server_config::TlsCertificateUsage::Encipherment,
            }],
            &["h2".to_string()],
            true,
            false,
            None,
            None,
        )
        .expect("build TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect test client");
        let (server, _) = listener.accept().await.expect("accept test client");
        let mut server_task = tokio::spawn(async move {
            accept_xhttp_tls(acceptor, Box::new(server) as Box<dyn AsyncStream>)
                .await
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(3500), &mut server_task)
                .await
                .is_err(),
            "XHTTP TLS timeout must not fire before Xray's four-second window"
        );

        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("XHTTP TLS timeout should fire near four seconds")
            .expect("server task should not panic");
        let error = match result {
            Ok(_) => panic!("idle TLS handshake must time out"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(client);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn tls_xhttp_honors_xray_tls_version_settings() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate test certificate");
        let xhttp_config = XhttpServerConfig {
            mode: XhttpMode::Auto,
            host: None,
            path: "/xhttp".to_string(),
            trusted_x_forwarded_for: Vec::new(),
            min_padding: 100,
            max_padding: 1000,
            max_each_post_bytes: 1_000_000,
            max_buffered_posts: 30,
            session_ttl_secs: 300,
            stream_up_server_secs: (20, 80),
            server_max_header_bytes: 8192,
            padding_obfs_mode: false,
            padding_key: "x_padding".to_string(),
            padding_header: "X-Padding".to_string(),
            padding_placement: XhttpPaddingPlacement::QueryInHeader,
            padding_method: XhttpPaddingMethod::RepeatX,
            no_grpc_header: false,
            no_sse_header: false,
            uplink_http_method: "POST".to_string(),
            min_posts_interval_ms: (30, 30),
            session_placement: XhttpPlacement::Path,
            session_key: String::new(),
            seq_placement: XhttpPlacement::Path,
            seq_key: String::new(),
            uplink_data_placement: XhttpDataPlacement::Auto,
            uplink_data_key: "x_data".to_string(),
        };
        let protocol = ServerProxyConfig::Tls(TlsServerConfig {
            certificates: vec![crate::config::server_config::TlsCertificateConfig {
                certificate_path: None,
                certificate_pem: generated.cert.pem().into_bytes(),
                key_path: None,
                key_pem: Some(generated.signing_key.serialize_pem().into_bytes()),
                usage:
                    crate::config::server_config::TlsCertificateUsage::Encipherment,
            }],
            alpn_protocols: vec![],
            enable_session_resumption: true,
            reject_unknown_sni: false,
            min_version: Some("1.3".to_string()),
            max_version: None,
            server_name: None,
            inner: Box::new(ServerProxyConfig::Xhttp {
                config: xhttp_config,
                inner: Box::new(ServerProxyConfig::Socks {
                    accounts: crate::config::server_config::SocksUserStore::new(
                        vec![],
                    ),
                    udp_enabled: false,
                    udp_response_ip: None,
                    user_level: 0,
                }),
            }),
        });

        let parsed = parse_listener_protocol(protocol).expect("valid TLS XHTTP");
        let XhttpSecurityLayer::Tls(acceptor) = parsed.security else {
            panic!("expected TLS XHTTP security");
        };

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                generated.cert.der().to_vec(),
            ))
            .expect("trust test certificate");
        let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS12,
        ])
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move { acceptor.accept(server_io).await });
        let client = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost")
                    .expect("valid server name"),
                client_io,
            )
            .await;

        assert!(
            client.is_err(),
            "TLS 1.2 must be rejected by minVersion=1.3"
        );
        assert!(
            server.await.expect("server task").is_err(),
            "server must reject a TLS 1.2 client"
        );
    }

    #[test]
    fn tokenish_padding_tracks_hpack_target() {
        for target in [1usize, 100, 1000] {
            let padding = generate_tokenish_padding(target);
            let encoded_len = hpack_huffman_encoded_len(&padding);
            assert!(encoded_len.abs_diff(target) <= 2);
        }
    }

    #[test]
    fn padding_validation_matches_repeat_and_tokenish_rules() {
        assert!(is_padding_valid(
            &"X".repeat(100),
            100,
            1000,
            XhttpPaddingMethod::RepeatX,
        ));
        assert!(!is_padding_valid(
            &"X".repeat(99),
            100,
            1000,
            XhttpPaddingMethod::RepeatX,
        ));

        let tokenish = generate_tokenish_padding(100);
        assert!(is_padding_valid(
            &tokenish,
            100,
            100,
            XhttpPaddingMethod::Tokenish,
        ));
    }

    #[test]
    fn query_value_from_header_url_extracts_padding() {
        assert_eq!(
            query_value_from_url(
                "https://example.com/path?pad=XXXX#fragment",
                "pad"
            )
            .as_deref(),
            Some("XXXX"),
        );
    }

    #[tokio::test]
    async fn collect_body_limited_rejects_oversized_streaming_payload() {
        let frames = futures::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"1234"))),
            Ok(Frame::data(Bytes::from_static(b"5678"))),
        ]);
        let body = StreamBody::new(frames);

        let result = collect_body_limited(body, 7).await;

        assert_eq!(result, Err(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn stream_down_cleanup_guard_removes_connected_session() {
        let store = SessionStore::new(Duration::from_secs(30), 30);
        let session = store.get_or_create("session");
        session.fully_connected.store(true, Ordering::Release);
        assert!(store.inner.read().unwrap().contains_key("session"));

        drop(SessionCleanupGuard {
            sessions: store.clone(),
            session_id: "session".to_string(),
        });

        assert!(!store.inner.read().unwrap().contains_key("session"));
    }
}
