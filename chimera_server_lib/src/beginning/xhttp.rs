use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, RwLock,
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
    sync::{Mutex, mpsc, oneshot},
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

const XHTTP_HTTP1_HEADER_SLOP_BYTES: usize = 4096;
const XHTTP_HTTP2_HEADER_LIST_OVERHEAD_BYTES: usize = 320;
const XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS: u32 = 250;
const XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE: u32 = 1_048_576;

fn xray_http1_header_read_limit(server_max_header_bytes: usize) -> usize {
    server_max_header_bytes
        .saturating_add(XHTTP_HTTP1_HEADER_SLOP_BYTES)
        .max(8192)
}

fn xray_http2_header_list_limit(server_max_header_bytes: usize) -> u32 {
    server_max_header_bytes
        .saturating_add(XHTTP_HTTP2_HEADER_LIST_OVERHEAD_BYTES)
        .min(u32::MAX as usize) as u32
}

fn xray_valid_http_host(request: &str, config: &str) -> bool {
    let request = request.to_ascii_lowercase();
    let config = config.to_ascii_lowercase();
    if !request.contains(':') {
        return request == config;
    }

    let host = if let Some(rest) = request.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !suffix.starts_with(':') || suffix[1..].contains(':') {
            return false;
        }
        host
    } else {
        let Some((host, _port)) = request.rsplit_once(':') else {
            return false;
        };
        if host.contains(':') {
            return false;
        }
        host
    };

    host == config
}

fn configure_http_builder(
    builder: &mut auto::Builder<TokioExecutor>,
    server_max_header_bytes: usize,
) {
    // Go net/http reads MaxHeaderBytes plus 4 KiB of bufio slop before it
    // decides an HTTP/1 request header is too large. Xray wires the normalized
    // XHTTP serverMaxHeaderBytes directly into http.Server.MaxHeaderBytes.
    let http1_read_limit = xray_http1_header_read_limit(server_max_header_bytes);
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(XHTTP_HEADER_READ_TIMEOUT)
        .max_buf_size(http1_read_limit);
    // Go's bundled HTTP/2 server adjusts MaxHeaderBytes before advertising
    // SETTINGS_MAX_HEADER_LIST_SIZE. Xray v26.2.6 advertises 8512 for its
    // 8192-byte XHTTP MaxHeaderBytes value (8192 + 320 bytes of HTTP/2 field
    // accounting overhead), rather than the raw MaxHeaderBytes value.
    builder
        .http2()
        .max_header_list_size(xray_http2_header_list_limit(server_max_header_bytes))
        .max_concurrent_streams(XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS)
        .max_frame_size(XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE);
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
    max_each_post_bytes: i64,
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
            (Some(expected), Some(actual)) => xray_valid_http_host(actual, expected),
            _ => false,
        }
    }

    fn extract_meta(
        &self,
        request: &Request<Incoming>,
        decoded_path: &str,
    ) -> (Option<String>, Option<String>) {
        let trimmed_base_path = self.base_path.trim_end_matches('/');
        let path_tail = if decoded_path == trimmed_base_path {
            ""
        } else {
            decoded_path.strip_prefix(&self.base_path).unwrap_or("")
        };

        // Xray v26.2.6 only reads path metadata when both session and sequence
        // placements are path. A path sequence paired with a non-path session
        // is a valid configuration, but the server leaves seq empty.
        if let Some(path_meta) = xray_path_metadata_pair(
            path_tail,
            self.session_placement,
            self.seq_placement,
        ) {
            return path_meta;
        }

        let session_id = match self.session_placement {
            XhttpPlacement::Path => None,
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
            XhttpPlacement::Path => None,
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
        let padding = extract_xray_request_padding(
            self.padding_obfs_mode,
            &self.padding_key,
            &self.padding_header,
            self.padding_placement,
            path_query,
            headers,
        );

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

    fn decorate_response(&self, response: &mut Response<ResponseBody>) {
        apply_xray_cors_headers(response.headers_mut());
        apply_response_padding(response.headers_mut(), self);
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    let request_headers = request.headers().clone();

    let http1_header_limit =
        xray_http1_header_read_limit(state.server_max_header_bytes);
    if request.version() != hyper::Version::HTTP_2
        && request_head_bytes(&request) > http1_header_limit
    {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            limit = http1_header_limit,
            "xhttp request rejected by HTTP/1 header size limit"
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

    let path = match decode_xray_url_path(request.uri().path()) {
        Ok(path) => path,
        Err(()) => {
            debug!(
                method = %request.method(),
                path = %request.uri().path(),
                "xhttp request rejected by malformed URL path escape"
            );
            return Ok(simple_response(StatusCode::BAD_REQUEST));
        }
    };
    if !matches_base_path(&path, &state.base_path) {
        debug!(
            method = %request.method(),
            path = %path,
            base_path = %state.base_path,
            "xhttp request rejected by path validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    if !state.validate_padding(request.uri().query(), request.headers()) {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            query = ?request.uri().query(),
            "xhttp request rejected by padding validation"
        );
        let mut response = simple_response(StatusCode::BAD_REQUEST);
        state.decorate_response(&mut response);
        return Ok(response);
    }

    let logical_peer_addr =
        trusted_forwarded_peer(&request_headers, &state.trusted_x_forwarded_for)
            .unwrap_or(peer_addr);
    // Xray v26.2.6 only starts stream-up server padding when the client sends
    // Referer. xPaddingObfsMode changes where padding is encoded, but does not
    // itself enable the periodic stream-up padding writer.
    let stream_up_padding = header_value(&request_headers, "referer").is_some();
    let (session_id, seq) = state.extract_meta(&request, &path);
    let is_downlink_method = request.method() == Method::GET;
    // Xray v26.2.6 deliberately excludes GET from the plain method match.
    // A GET becomes an uplink only through the header/cookie upstream marker;
    // otherwise it remains the stream-down request even when configured as the
    // uplink HTTP method.
    let is_uplink_method = is_xray_uplink_request(
        request.method(),
        &state.uplink_http_method,
        &request_headers,
        state.uplink_data_placement,
        &state.uplink_data_key,
    );
    let dispatch = classify_request(
        state.mode,
        is_downlink_method,
        is_uplink_method,
        session_id.is_some(),
        seq.is_some(),
    );
    let mut response = match dispatch {
        Ok(XhttpRequestDispatch::StreamDown) => {
            handle_stream_down(
                state.clone(),
                session_id.expect("stream-down requires a session id"),
                logical_peer_addr,
            )
            .await
        }
        Ok(XhttpRequestDispatch::StreamOne) => {
            handle_stream_one(request, state.clone(), logical_peer_addr).await
        }
        Ok(XhttpRequestDispatch::StreamUp) => {
            handle_stream_up(
                request,
                state.clone(),
                session_id.expect("stream-up requires a session id"),
                stream_up_padding,
            )
            .await
        }
        Ok(XhttpRequestDispatch::PacketUp) => {
            handle_packet_up(
                request,
                state.clone(),
                session_id.expect("packet-up requires a session id"),
                seq.expect("packet-up requires a sequence"),
            )
            .await
        }
        Err(status) => simple_response(status),
    };

    state.decorate_response(&mut response);
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

fn stream_up_can_flush_while_uploading(version: hyper::Version) -> bool {
    version == hyper::Version::HTTP_2
}

async fn handle_stream_up(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session_id: String,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let response_can_flush_while_uploading =
        stream_up_can_flush_while_uploading(request.version());
    let session = state.sessions.get_or_create(&session_id);
    let (done_tx, done_rx) = oneshot::channel();
    let reader = IncomingBodyReader::new(request.into_body(), done_tx);
    if session
        .upload_queue
        .push_reader(Box::pin(reader))
        .await
        .is_err()
    {
        return simple_response(StatusCode::CONFLICT);
    }

    stream_up_response(
        done_rx,
        &state,
        padding_enabled && response_can_flush_while_uploading,
    )
    .await
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    let (stream, reader) = session.new_downlink_connection();
    spawn_handler_stream(stream, state.clone(), peer_addr);

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
) -> Response<ResponseBody> {
    let Ok(seq) = seq.parse::<u64>() else {
        return simple_response(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let (parts, body) = request.into_parts();
    let header_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header
    ) {
        match decode_chunked_header_payload(&parts.headers, &state.uplink_data_key) {
            Ok(payload) => payload,
            Err(_) => return simple_response(StatusCode::INTERNAL_SERVER_ERROR),
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
            Err(_) => return simple_response(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        Vec::new()
    };
    let body_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        match collect_body_limited(body, state.max_each_post_bytes.max(0) as usize)
            .await
        {
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
    if payload_exceeds_post_limit(payload.len(), state.max_each_post_bytes) {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let collected = Bytes::from(payload);

    let session = state.sessions.get_or_create(&session_id);
    match session.upload_queue.push_payload(seq, collected).await {
        Ok(()) => simple_response(StatusCode::OK),
        Err(_) => simple_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn wait_for_stream_up_response_start(
    mut done_rx: oneshot::Receiver<()>,
    padding_delay: Option<Duration>,
    min_padding: usize,
    max_padding: usize,
) -> Option<(oneshot::Receiver<()>, Bytes)> {
    let Some(padding_delay) = padding_delay else {
        let _ = done_rx.await;
        return None;
    };

    tokio::select! {
        _ = &mut done_rx => None,
        _ = sleep(padding_delay) => {
            let padding_len = random_inclusive(min_padding, max_padding);
            Some((done_rx, Bytes::from(vec![b'X'; padding_len])))
        }
    }
}

async fn stream_up_response(
    done_rx: oneshot::Receiver<()>,
    state: &AppState,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let (min_secs, max_secs) = state.stream_up_server_secs;
    let padding_delay = (padding_enabled && max_secs > 0)
        .then(|| Duration::from_secs(random_inclusive(min_secs, max_secs) as u64));

    let Some((done_rx, first_padding)) = wait_for_stream_up_response_start(
        done_rx,
        padding_delay,
        state.min_padding,
        state.max_padding,
    )
    .await
    else {
        return stream_response(
            StatusCode::OK,
            futures::stream::empty::<Result<Frame<Bytes>, Infallible>>(),
            true,
        );
    };

    let min_padding = state.min_padding;
    let max_padding = state.max_padding;
    let body_stream = futures::stream::unfold(
        (done_rx, Some(first_padding)),
        move |(mut done_rx, first_padding)| async move {
            if let Some(first_padding) = first_padding {
                return Some((Ok(Frame::data(first_padding)), (done_rx, None)));
            }

            let delay_secs = random_inclusive(min_secs, max_secs);
            tokio::select! {
                _ = &mut done_rx => None,
                _ = sleep(Duration::from_secs(delay_secs as u64)) => {
                    let padding_len = random_inclusive(min_padding, max_padding);
                    Some((
                        Ok(Frame::data(Bytes::from(vec![b'X'; padding_len]))),
                        (done_rx, None),
                    ))
                }
            }
        },
    );

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
        let mut sessions = self.inner.write().unwrap();
        if let Some(existing) = sessions.get(session_id) {
            return existing.clone();
        }
        sessions.insert(session_id.to_string(), session.clone());
        drop(sessions);
        self.spawn_ttl_cleanup(session_id.to_string(), session.clone());
        session
    }

    fn remove(&self, session_id: &str) {
        self.inner.write().unwrap().remove(session_id);
    }

    fn spawn_ttl_cleanup(&self, session_id: String, session: Arc<XhttpSession>) {
        let ttl = self.ttl;
        let store = self.clone();
        tokio::spawn(async move {
            sleep(ttl).await;

            let should_remove =
                store.inner.read().unwrap().get(&session_id).is_some_and(
                    |current| {
                        Arc::ptr_eq(current, &session)
                            && !session.fully_connected.load(Ordering::Acquire)
                    },
                );
            if should_remove {
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

struct IncomingBodyReader {
    body: Incoming,
    current: Bytes,
    done_tx: Option<oneshot::Sender<()>>,
}

impl IncomingBodyReader {
    fn new(body: Incoming, done_tx: oneshot::Sender<()>) -> Self {
        Self {
            body,
            current: Bytes::new(),
            done_tx: Some(done_tx),
        }
    }

    fn finish(&mut self) {
        if let Some(done_tx) = self.done_tx.take() {
            let _ = done_tx.send(());
        }
    }
}

impl AsyncRead for IncomingBodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.current.is_empty() {
                let len = self.current.len().min(buf.remaining());
                buf.put_slice(&self.current.split_to(len));
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.current = data;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finish();
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => {
                    self.finish();
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

type BoxedUploadReader = Pin<Box<dyn AsyncRead + Send>>;

enum UploadPacket {
    Reader(BoxedUploadReader),
    Payload { seq: u64, data: Bytes },
}

struct UploadPushState {
    sender: mpsc::Sender<UploadPacket>,
    reader_claimed: bool,
}

struct UploadQueueSender {
    state: Mutex<UploadPushState>,
}

impl UploadQueueSender {
    async fn push_reader(&self, reader: BoxedUploadReader) -> std::io::Result<()> {
        let mut state = self.state.lock().await;
        if state.reader_claimed {
            return Err(std::io::Error::other("h.reader already exists"));
        }
        state.reader_claimed = true;
        state
            .sender
            .send(UploadPacket::Reader(reader))
            .await
            .map_err(|_| std::io::Error::other("packet queue closed"))
    }

    async fn push_payload(&self, seq: u64, data: Bytes) -> std::io::Result<()> {
        let state = self.state.lock().await;
        if state.reader_claimed {
            return Err(std::io::Error::other("h.reader already exists"));
        }
        state
            .sender
            .send(UploadPacket::Payload { seq, data })
            .await
            .map_err(|_| std::io::Error::other("packet queue closed"))
    }
}

struct XhttpUploadReader {
    receiver: mpsc::Receiver<UploadPacket>,
    reader: Option<BoxedUploadReader>,
    current_payload: Option<Bytes>,
    buffered: BTreeMap<u64, Bytes>,
    next_seq: u64,
    max_buffered_posts: usize,
}

impl XhttpUploadReader {
    fn new(max_buffered_posts: usize) -> (UploadQueueSender, Self) {
        let (sender, receiver) = mpsc::channel(max_buffered_posts);
        (
            UploadQueueSender {
                state: Mutex::new(UploadPushState {
                    sender,
                    reader_claimed: false,
                }),
            },
            Self {
                receiver,
                reader: None,
                current_payload: None,
                buffered: BTreeMap::new(),
                next_seq: 0,
                max_buffered_posts,
            },
        )
    }
}

impl AsyncRead for XhttpUploadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(reader) = self.reader.as_mut() {
                return reader.as_mut().poll_read(cx, buf);
            }

            if let Some(mut payload) = self.current_payload.take() {
                let len = payload.len().min(buf.remaining());
                buf.put_slice(&payload.split_to(len));
                if payload.is_empty() {
                    self.next_seq += 1;
                } else {
                    self.current_payload = Some(payload);
                }
                return Poll::Ready(Ok(()));
            }

            let next_seq = self.next_seq;
            if let Some(payload) = self.buffered.remove(&next_seq) {
                self.current_payload = Some(payload);
                continue;
            }

            if self.buffered.len() > self.max_buffered_posts + 1 {
                return Poll::Ready(Err(std::io::Error::other(
                    "packet queue is too large",
                )));
            }

            match Pin::new(&mut self.receiver).poll_recv(cx) {
                Poll::Ready(Some(UploadPacket::Reader(reader))) => {
                    self.reader = Some(reader);
                }
                Poll::Ready(Some(UploadPacket::Payload { seq, data })) => {
                    if seq >= self.next_seq {
                        self.buffered.entry(seq).or_insert(data);
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct SharedUploadReader {
    inner: Arc<StdMutex<XhttpUploadReader>>,
}

impl AsyncRead for SharedUploadReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut reader = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *reader).poll_read(cx, buf)
    }
}

struct XhttpSession {
    upload_queue: UploadQueueSender,
    upload_reader: Arc<StdMutex<XhttpUploadReader>>,
    fully_connected: AtomicBool,
}

impl XhttpSession {
    fn new(max_buffered_posts: usize) -> Self {
        let (upload_queue, upload_reader) =
            XhttpUploadReader::new(max_buffered_posts);

        Self {
            upload_queue,
            upload_reader: Arc::new(StdMutex::new(upload_reader)),
            fully_connected: AtomicBool::new(false),
        }
    }

    fn new_downlink_connection(&self) -> (XhttpLogicalStream, DuplexStream) {
        // Xray v26.2.6 creates a fresh logical inbound connection for every
        // stream-down GET while all of them compete on the same uploadQueue.
        let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
        let reader = SharedUploadReader {
            inner: self.upload_reader.clone(),
        };
        (
            XhttpLogicalStream::new(reader, server_write),
            client_download,
        )
    }
}

struct XhttpLogicalStream {
    reader: BoxedUploadReader,
    writer: DuplexStream,
}

impl XhttpLogicalStream {
    fn new<R>(reader: R, writer: DuplexStream) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        Self {
            reader: Box::pin(reader),
            writer,
        }
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
    for pair in query?.split('&') {
        // Go's url.ParseQuery rejects a value containing an unescaped semicolon
        // and URL.Query silently discards that malformed pair. Percent-encoded
        // semicolons remain valid data because the rejection happens first.
        if pair.contains(';') {
            continue;
        }
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(name) = decode_query_component(raw_name) else {
            continue;
        };
        if name != key {
            continue;
        }
        let Some(value) = decode_query_component(raw_value) else {
            continue;
        };
        return (!value.is_empty()).then_some(value);
    }
    None
}

fn decode_query_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(header_value) = header_value.to_str() else {
            continue;
        };
        for cookie in header_value.split(';') {
            let Some((name, raw_value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name != key {
                continue;
            }
            let Some(value) = parse_cookie_value_like_go(raw_value) else {
                continue;
            };
            // Go's Request.Cookie returns the first successfully parsed cookie
            // with this name. An empty first value therefore means "missing"
            // to XHTTP and must not fall through to a later duplicate.
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

fn parse_cookie_value_like_go(raw: &str) -> Option<String> {
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    if value.bytes().all(|byte| {
        (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b';' && byte != b'\\'
    }) {
        Some(value.to_string())
    } else {
        None
    }
}

fn has_uplink_marker(
    headers: &hyper::HeaderMap,
    placement: XhttpDataPlacement,
    key: &str,
) -> bool {
    match placement {
        XhttpDataPlacement::Header => {
            header_value(headers, &format!("{key}-Upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Cookie => {
            cookie_value(headers, &format!("{key}_upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body => false,
    }
}

fn decode_chunked_header_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let declared_len = header_value(headers, &format!("{key}-Length"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing uplink data length",
            )
        })?
        .parse::<usize>()
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid uplink data length",
            )
        })?;

    let mut encoded = String::new();
    for index in 0usize.. {
        let header_name = format!("{key}-{index}");
        let Some(chunk) = header_value(headers, &header_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    if encoded.is_empty() || encoded.len() != declared_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "uplink data length mismatch",
        ));
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
    if encoded.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing uplink cookie payload",
        ));
    }
    decode_xhttp_payload(&encoded)
}

fn payload_exceeds_post_limit(payload_len: usize, max_bytes: i64) -> bool {
    i64::try_from(payload_len).unwrap_or(i64::MAX) > max_bytes
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
    request_path.starts_with(base_path)
}

fn xray_path_metadata_pair(
    path_tail: &str,
    session_placement: XhttpPlacement,
    seq_placement: XhttpPlacement,
) -> Option<(Option<String>, Option<String>)> {
    (session_placement == XhttpPlacement::Path
        && seq_placement == XhttpPlacement::Path)
        .then(|| {
            (
                xray_path_metadata_value(path_tail, 0),
                xray_path_metadata_value(path_tail, 1),
            )
        })
}

fn xray_path_metadata_value(path_tail: &str, index: usize) -> Option<String> {
    path_tail
        .split('/')
        .nth(index)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn decode_xray_url_path(raw_path: &str) -> Result<String, ()> {
    if !raw_path.as_bytes().contains(&b'%') {
        return Ok(raw_path.to_string());
    }

    let bytes = raw_path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = hex_value(bytes[index + 1]).ok_or(())?;
        let low = hex_value(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }

    String::from_utf8(decoded).or_else(|_| Ok(raw_path.to_string()))
}

fn extract_xray_request_padding(
    obfs_mode: bool,
    padding_key: &str,
    padding_header: &str,
    padding_placement: XhttpPaddingPlacement,
    path_query: Option<&str>,
    headers: &hyper::HeaderMap,
) -> Option<String> {
    if !obfs_mode {
        if let Some(referer) = header_value(headers, "referer") {
            // Xray v26.2.6 returns immediately when url.Parse succeeds, even
            // if Referer does not contain x_padding. Only a parse failure falls
            // through to the configurable cookie/header/query extraction below.
            if xray_url_parse_succeeds(&referer) {
                return query_value_from_url(&referer, "x_padding");
            }
        } else {
            return query_value(path_query, "x_padding");
        }
    }

    cookie_value(headers, padding_key)
        .or_else(|| {
            header_value(headers, padding_header).and_then(|value| {
                match padding_placement {
                    XhttpPaddingPlacement::Header => Some(value),
                    _ => query_value_from_url(&value, padding_key),
                }
            })
        })
        .or_else(|| query_value(path_query, padding_key))
}

fn xray_url_parse_succeeds(raw_url: &str) -> bool {
    let bytes = raw_url.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] < b' ' || bytes[index] == 0x7f {
            return false;
        }
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || hex_value(bytes[index + 1]).is_none()
            || hex_value(bytes[index + 2]).is_none()
        {
            return false;
        }
        index += 3;
    }
    true
}

fn query_value_from_url(raw_url: &str, key: &str) -> Option<String> {
    if !xray_url_parse_succeeds(raw_url) {
        return None;
    }
    let query = raw_url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    query_value(Some(query), key)
}

fn request_head_bytes<B>(request: &Request<B>) -> usize {
    // XHTTP's HTTP/1 paths use HTTP/1.0 or HTTP/1.1; both protocol tokens are
    // eight bytes long and count against Go net/http's MaxHeaderBytes budget.
    let request_line_bytes = request
        .method()
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(request.uri().to_string().len())
        .saturating_add(1)
        .saturating_add(8)
        .saturating_add(2);

    request.headers().iter().fold(
        request_line_bytes.saturating_add(2),
        |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(2)
                .saturating_add(value.as_bytes().len())
                .saturating_add(2)
        },
    )
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpRequestDispatch {
    StreamDown,
    StreamOne,
    StreamUp,
    PacketUp,
}

fn is_xray_uplink_request(
    method: &Method,
    uplink_http_method: &str,
    headers: &hyper::HeaderMap,
    uplink_data_placement: XhttpDataPlacement,
    uplink_data_key: &str,
) -> bool {
    (uplink_http_method != "GET" && method.as_str() == uplink_http_method)
        || has_uplink_marker(headers, uplink_data_placement, uplink_data_key)
}

fn classify_request(
    mode: XhttpMode,
    is_get: bool,
    is_uplink_method: bool,
    has_session_id: bool,
    has_seq: bool,
) -> Result<XhttpRequestDispatch, StatusCode> {
    if !has_session_id && mode == XhttpMode::PacketUp {
        return Err(StatusCode::BAD_REQUEST);
    }

    if is_uplink_method && has_session_id {
        if !has_seq {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::StreamUp) {
                return Err(StatusCode::BAD_REQUEST);
            }
            return Ok(XhttpRequestDispatch::StreamUp);
        }

        if !matches!(mode, XhttpMode::Auto | XhttpMode::PacketUp) {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(XhttpRequestDispatch::PacketUp);
    }

    if is_get || !has_session_id {
        return Ok(if has_session_id {
            XhttpRequestDispatch::StreamDown
        } else {
            XhttpRequestDispatch::StreamOne
        });
    }

    Err(StatusCode::METHOD_NOT_ALLOWED)
}

fn apply_xray_cors_headers(headers: &mut hyper::HeaderMap) {
    // Xray v26.2.6 writes these two CORS headers unconditionally for XHTTP
    // requests after host/path validation. It does not echo Origin, advertise
    // requested headers, or enable credentials.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        hyper::header::HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        hyper::header::HeaderValue::from_static("*"),
    );
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
    fn http1_header_read_limit_includes_xray_bufio_slop() {
        assert_eq!(xray_http1_header_read_limit(8192), 12_288);
        assert_eq!(xray_http1_header_read_limit(16_384), 20_480);

        let request = Request::builder()
            .uri("/x/")
            .header("x-test", "a".repeat(12_000))
            .body(())
            .unwrap();
        assert!(request_head_bytes(&request) <= xray_http1_header_read_limit(8192));
        let request = Request::builder()
            .uri("/x/")
            .header("x-test", "a".repeat(13_000))
            .body(())
            .unwrap();
        assert!(request_head_bytes(&request) > xray_http1_header_read_limit(8192));

        let request = Request::builder()
            .uri(format!("/x/?q={}", "a".repeat(12_000)))
            .header("host", "localhost")
            .body(())
            .unwrap();
        assert!(request_head_bytes(&request) <= xray_http1_header_read_limit(8192));
        let request = Request::builder()
            .uri(format!("/x/?q={}", "a".repeat(13_000)))
            .header("host", "localhost")
            .body(())
            .unwrap();
        assert!(request_head_bytes(&request) > xray_http1_header_read_limit(8192));
    }

    #[test]
    fn http2_settings_match_xray_v26_2_6() {
        assert_eq!(xray_http2_header_list_limit(8192), 8512);
        assert_eq!(xray_http2_header_list_limit(16_384), 16_704);
        assert_eq!(XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS, 250);
        assert_eq!(XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE, 1_048_576);
    }

    #[test]
    fn http_host_validation_matches_xray_v26_2_6() {
        assert!(xray_valid_http_host("example.com", "example.com"));
        assert!(xray_valid_http_host("EXAMPLE.COM:443", "example.com"));
        assert!(xray_valid_http_host("[::1]:443", "::1"));
        assert!(!xray_valid_http_host("::1", "::1"));
        assert!(!xray_valid_http_host("[::1]", "::1"));
        assert!(!xray_valid_http_host("[::2]:443", "::1"));
    }

    #[test]
    fn request_dispatch_matches_xray_v26_2_6() {
        assert_eq!(
            classify_request(XhttpMode::Auto, false, false, false, false),
            Ok(XhttpRequestDispatch::StreamOne),
            "a non-uplink method without a session is still stream-one"
        );
        assert_eq!(
            classify_request(XhttpMode::Auto, true, false, false, false),
            Ok(XhttpRequestDispatch::StreamOne),
            "GET without a session is stream-one"
        );
        assert_eq!(
            classify_request(XhttpMode::StreamOne, true, false, true, true),
            Ok(XhttpRequestDispatch::StreamDown),
            "GET with a session wins the stream-down fallback even in stream-one mode"
        );
        assert_eq!(
            classify_request(XhttpMode::Auto, true, false, true, false),
            Ok(XhttpRequestDispatch::StreamDown),
            "plain GET with a session remains stream-down"
        );
        assert_eq!(
            classify_request(XhttpMode::PacketUp, false, true, false, false),
            Err(StatusCode::BAD_REQUEST),
            "explicit packet-up requires a session id"
        );
        assert_eq!(
            classify_request(XhttpMode::PacketUp, false, true, true, false),
            Err(StatusCode::BAD_REQUEST),
            "stream-up shaped request is invalid in packet-up mode"
        );
        assert_eq!(
            classify_request(XhttpMode::StreamUp, false, true, true, true),
            Err(StatusCode::BAD_REQUEST),
            "packet-up shaped request is invalid in stream-up mode"
        );
        assert_eq!(
            classify_request(XhttpMode::Auto, false, false, true, false),
            Err(StatusCode::METHOD_NOT_ALLOWED),
            "non-uplink non-GET request with a session remains unsupported"
        );
    }

    #[test]
    fn uplink_markers_match_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        assert!(!is_xray_uplink_request(
            &Method::GET,
            "GET",
            &headers,
            XhttpDataPlacement::Body,
            ""
        ));
        assert!(is_xray_uplink_request(
            &Method::POST,
            "POST",
            &headers,
            XhttpDataPlacement::Body,
            ""
        ));
        headers.insert(
            "x-data-upstream",
            hyper::header::HeaderValue::from_static("1"),
        );
        assert!(has_uplink_marker(
            &headers,
            XhttpDataPlacement::Header,
            "X-Data"
        ));
        assert!(!has_uplink_marker(
            &headers,
            XhttpDataPlacement::Body,
            "X-Data"
        ));

        headers.insert(
            "x-data-upstream",
            hyper::header::HeaderValue::from_static("2"),
        );
        assert!(!has_uplink_marker(
            &headers,
            XhttpDataPlacement::Header,
            "X-Data"
        ));

        let mut cookie_headers = hyper::HeaderMap::new();
        cookie_headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static("other=0; x_data_upstream=1"),
        );
        assert!(has_uplink_marker(
            &cookie_headers,
            XhttpDataPlacement::Cookie,
            "x_data"
        ));

        cookie_headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static("x_data_upstream=0"),
        );
        assert!(!has_uplink_marker(
            &cookie_headers,
            XhttpDataPlacement::Cookie,
            "x_data"
        ));
    }

    #[test]
    fn cookie_uplink_payload_errors_match_xray_v26_2_6() {
        let headers = hyper::HeaderMap::new();
        assert!(decode_chunked_cookie_payload(&headers, "x_data").is_err());

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static("x_data_0=!!!"),
        );
        assert!(decode_chunked_cookie_payload(&headers, "x_data").is_err());

        headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static("x_data_0=cGluZw"),
        );
        assert_eq!(
            decode_chunked_cookie_payload(&headers, "x_data")
                .expect("valid cookie payload"),
            b"ping"
        );
    }

    #[test]
    fn header_uplink_length_matches_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-data-0",
            hyper::header::HeaderValue::from_static("cGluZw"),
        );

        assert!(decode_chunked_header_payload(&headers, "X-Data").is_err());

        headers.insert(
            "x-data-length",
            hyper::header::HeaderValue::from_static("5"),
        );
        assert!(decode_chunked_header_payload(&headers, "X-Data").is_err());

        headers.insert(
            "x-data-length",
            hyper::header::HeaderValue::from_static("nope"),
        );
        assert!(decode_chunked_header_payload(&headers, "X-Data").is_err());

        headers.insert(
            "x-data-length",
            hyper::header::HeaderValue::from_static("6"),
        );
        assert_eq!(
            decode_chunked_header_payload(&headers, "X-Data")
                .expect("valid header payload"),
            b"ping"
        );
    }

    #[test]
    fn xhttp_cors_headers_match_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        apply_xray_cors_headers(&mut headers);

        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&hyper::header::HeaderValue::from_static("*"))
        );
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_METHODS),
            Some(&hyper::header::HeaderValue::from_static("*"))
        );
        assert!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "Xray v26.2.6 does not advertise credentialed CORS"
        );
        assert!(
            headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_none(),
            "Xray v26.2.6 does not echo requested CORS headers"
        );
    }

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
    fn cookie_value_matches_xray_quoted_cookie_parsing() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static(
                "x_session=\"abc\"; x_seq=\"0\"; invalid=\"a\\\\b\"",
            ),
        );

        assert_eq!(cookie_value(&headers, "x_session").as_deref(), Some("abc"));
        assert_eq!(cookie_value(&headers, "x_seq").as_deref(), Some("0"));
        assert_eq!(cookie_value(&headers, "invalid"), None);

        headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static(
                "x_session=; x_session=abc; x_seq=; x_seq=0",
            ),
        );
        assert_eq!(cookie_value(&headers, "x_session"), None);
        assert_eq!(cookie_value(&headers, "x_seq"), None);

        headers.insert(
            header::COOKIE,
            hyper::header::HeaderValue::from_static(
                "x_session=abc; x_session=; x_seq=0; x_seq=",
            ),
        );
        assert_eq!(cookie_value(&headers, "x_session").as_deref(), Some("abc"));
        assert_eq!(cookie_value(&headers, "x_seq").as_deref(), Some("0"));
    }

    #[test]
    fn url_path_decoding_matches_xray_v26_2_6() {
        assert_eq!(decode_xray_url_path("/x/abc/0").as_deref(), Ok("/x/abc/0"));
        assert_eq!(
            decode_xray_url_path("/x/abc%2Fdef/0").as_deref(),
            Ok("/x/abc/def/0"),
        );
        assert_eq!(
            decode_xray_url_path("/x%2Fabc/0").as_deref(),
            Ok("/x/abc/0"),
        );
        assert_eq!(
            decode_xray_url_path("/x/abc%252Fdef/0").as_deref(),
            Ok("/x/abc%2Fdef/0"),
        );
        assert!(decode_xray_url_path("/x/abc%ZZ/0").is_err());
    }

    #[test]
    fn path_metadata_preserves_empty_segments_like_xray_v26_2_6() {
        assert_eq!(xray_path_metadata_value("abc/0", 0).as_deref(), Some("abc"));
        assert_eq!(xray_path_metadata_value("abc/0", 1).as_deref(), Some("0"));
        assert_eq!(
            xray_path_metadata_value("abc//0", 0).as_deref(),
            Some("abc")
        );
        assert_eq!(xray_path_metadata_value("abc//0", 1), None);
        assert_eq!(xray_path_metadata_value("abc//0", 2).as_deref(), Some("0"));
        assert_eq!(xray_path_metadata_value("/0", 0), None);
        assert_eq!(xray_path_metadata_value("/0", 1).as_deref(), Some("0"));
    }

    #[test]
    fn path_sequence_requires_path_session_like_xray_v26_2_6() {
        assert_eq!(
            xray_path_metadata_pair(
                "abc/0",
                XhttpPlacement::Path,
                XhttpPlacement::Path
            ),
            Some((Some("abc".to_string()), Some("0".to_string())))
        );
        assert_eq!(
            xray_path_metadata_pair(
                "0",
                XhttpPlacement::Query,
                XhttpPlacement::Path
            ),
            None,
            "Xray accepts query-session/path-seq config but does not extract the path seq"
        );
    }

    #[test]
    fn query_value_matches_xray_url_query_decoding() {
        assert_eq!(
            query_value(Some("x_session=abc%2Fdef"), "x_session").as_deref(),
            Some("abc/def"),
        );
        assert_eq!(
            query_value(Some("x%5Fsession=hello+world"), "x_session").as_deref(),
            Some("hello world"),
        );
        assert_eq!(query_value(Some("x_session=bad%ZZ"), "x_session"), None);
        assert_eq!(
            query_value(Some("x_session=bad%ZZ&x_session=ok"), "x_session")
                .as_deref(),
            Some("ok"),
        );
        assert_eq!(
            query_value(Some("other=bad%ZZ&x_session=ok"), "x_session").as_deref(),
            Some("ok"),
        );
        assert_eq!(
            query_value(Some("x_session=&x_session=ok"), "x_session"),
            None,
        );
        assert_eq!(
            query_value(Some("x_session=first&x_session="), "x_session").as_deref(),
            Some("first"),
        );
        assert_eq!(
            query_value(Some("x_session=bad;raw&x_session=ok"), "x_session")
                .as_deref(),
            Some("ok"),
        );
        assert_eq!(
            query_value(Some("x_session=abc%3Bdef"), "x_session").as_deref(),
            Some("abc;def"),
        );
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

    #[test]
    fn malformed_padding_urls_fall_back_like_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("referer", hyper::header::HeaderValue::from_static("%"));

        assert_eq!(
            extract_xray_request_padding(
                false,
                "x_padding",
                "X-Padding",
                XhttpPaddingPlacement::Header,
                Some("x_padding=XXXX"),
                &headers,
            )
            .as_deref(),
            Some("XXXX"),
        );

        headers.insert(
            "referer",
            hyper::header::HeaderValue::from_static("https://example.com/"),
        );
        assert_eq!(
            extract_xray_request_padding(
                false,
                "x_padding",
                "X-Padding",
                XhttpPaddingPlacement::Header,
                Some("x_padding=XXXX"),
                &headers,
            ),
            None,
            "a successfully parsed Referer must suppress query fallback even without x_padding",
        );

        headers.remove("referer");
        headers.insert(
            "x-padding",
            hyper::header::HeaderValue::from_static("%ZZ?x_padding=BAD"),
        );
        assert_eq!(
            extract_xray_request_padding(
                true,
                "x_padding",
                "X-Padding",
                XhttpPaddingPlacement::QueryInHeader,
                Some("x_padding=X"),
                &headers,
            )
            .as_deref(),
            Some("X"),
            "a malformed query-in-header URL must be ignored before falling back to request query",
        );
    }

    #[test]
    fn negative_post_limit_rejects_every_payload_like_xray_v26_2_6() {
        assert!(payload_exceeds_post_limit(0, -1));
        assert!(payload_exceeds_post_limit(1, -1));
        assert!(!payload_exceeds_post_limit(0, 0));
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

    #[test]
    fn stream_up_padding_requires_referer_like_xray_v26_2_6() {
        let mut headers = hyper::HeaderMap::new();
        assert!(header_value(&headers, "referer").is_none());

        headers.insert(
            "referer",
            hyper::header::HeaderValue::from_static("https://example.com/"),
        );
        assert!(header_value(&headers, "referer").is_some());
    }

    #[test]
    fn stream_up_padding_flush_scope_matches_xray_v26_2_6() {
        assert!(!stream_up_can_flush_while_uploading(
            hyper::Version::HTTP_10
        ));
        assert!(!stream_up_can_flush_while_uploading(
            hyper::Version::HTTP_11
        ));
        assert!(stream_up_can_flush_while_uploading(hyper::Version::HTTP_2));
    }

    #[tokio::test]
    async fn stream_up_response_waits_for_body_without_padding_like_xray_v26_2_6() {
        let (done_tx, done_rx) = oneshot::channel();
        let mut wait =
            Box::pin(wait_for_stream_up_response_start(done_rx, None, 100, 100));

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err(),
            "stream-up response must stay pending while the request body is still open"
        );

        done_tx.send(()).expect("finish stream-up body");
        assert!(
            wait.await.is_none(),
            "completed stream-up without padding should return headers only after body EOF"
        );
    }

    #[tokio::test]
    async fn stream_up_padding_can_flush_response_before_body_eof_like_xray_v26_2_6()
    {
        let (_done_tx, done_rx) = oneshot::channel();
        let started = wait_for_stream_up_response_start(
            done_rx,
            Some(Duration::from_millis(10)),
            7,
            7,
        )
        .await
        .expect("padding should start the response while upload remains open");

        assert_eq!(started.1, Bytes::from_static(b"XXXXXXX"));
    }

    #[tokio::test]
    async fn split_session_creates_each_logical_connection_on_downlink() {
        use tokio::io::AsyncReadExt;

        let session = XhttpSession::new(4);
        session
            .upload_queue
            .push_payload(0, Bytes::from_static(b"ping"))
            .await
            .expect("queue first packet-up payload");

        let (mut first_stream, _first_downlink) = session.new_downlink_connection();
        let (mut second_stream, _second_downlink) =
            session.new_downlink_connection();

        let mut first_payload = [0u8; 4];
        first_stream.read_exact(&mut first_payload).await.unwrap();
        assert_eq!(&first_payload, b"ping");

        session
            .upload_queue
            .push_payload(1, Bytes::from_static(b"pong"))
            .await
            .expect("queue second packet-up payload");
        let mut second_payload = [0u8; 4];
        second_stream.read_exact(&mut second_payload).await.unwrap();
        assert_eq!(&second_payload, b"pong");
    }

    #[tokio::test]
    async fn duplicate_packet_sequence_keeps_first_payload_like_xray_v26_2_6() {
        use tokio::io::AsyncReadExt;

        let (queue, mut reader) = XhttpUploadReader::new(4);
        queue
            .push_payload(1, Bytes::from_static(b"first"))
            .await
            .unwrap();
        queue
            .push_payload(1, Bytes::from_static(b"second"))
            .await
            .unwrap();
        queue
            .push_payload(0, Bytes::from_static(b"zero"))
            .await
            .unwrap();

        let mut output = [0u8; 9];
        reader.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"zerofirst");
    }

    #[tokio::test]
    async fn stream_up_claim_is_single_use_like_xray_v26_2_6() {
        let (queue, _reader) = XhttpUploadReader::new(4);

        queue
            .push_reader(Box::pin(tokio::io::empty()))
            .await
            .expect("first stream-up reader");
        assert!(
            queue
                .push_reader(Box::pin(tokio::io::empty()))
                .await
                .is_err(),
            "a second stream-up reader must conflict"
        );
        assert!(
            queue
                .push_payload(0, Bytes::from_static(b"packet"))
                .await
                .is_err(),
            "packet-up must fail after stream-up claims the upload queue"
        );
    }

    #[tokio::test]
    async fn buffered_packet_posts_backpressure_until_reader_consumes_like_xray_v26_2_6()
     {
        use tokio::io::AsyncReadExt;

        let (queue, mut reader) = XhttpUploadReader::new(1);
        let queue = Arc::new(queue);
        queue
            .push_payload(1, Bytes::from_static(b"1"))
            .await
            .expect("first buffered post fills Xray channel");

        let second = tokio::spawn({
            let queue = queue.clone();
            async move { queue.push_payload(2, Bytes::from_static(b"2")).await }
        });
        sleep(Duration::from_millis(20)).await;
        assert!(
            !second.is_finished(),
            "a full scMaxBufferedPosts channel must backpressure the HTTP request"
        );

        let read = tokio::spawn(async move {
            let mut output = [0u8; 3];
            reader.read_exact(&mut output).await.unwrap();
            output
        });
        second
            .await
            .expect("second packet task")
            .expect("reader consumption should release one channel slot");
        queue
            .push_payload(0, Bytes::from_static(b"0"))
            .await
            .expect("missing packet completes reorder sequence");

        assert_eq!(read.await.expect("ordered read task"), *b"012");
    }

    #[tokio::test]
    async fn expired_session_timer_does_not_reap_reused_session_id() {
        let store = SessionStore::new(Duration::from_millis(60), 30);
        let old = store.get_or_create("session");
        old.fully_connected.store(true, Ordering::Release);
        store.remove("session");

        sleep(Duration::from_millis(20)).await;
        let reused = store.get_or_create("session");
        sleep(Duration::from_millis(50)).await;

        let current = store
            .inner
            .read()
            .unwrap()
            .get("session")
            .cloned()
            .expect("old timer must not reap reused session id");
        assert!(Arc::ptr_eq(&current, &reused));

        sleep(Duration::from_millis(30)).await;
        assert!(
            !store.inner.read().unwrap().contains_key("session"),
            "reused session must still expire on its own TTL"
        );
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
