use std::{
    convert::Infallible,
    sync::{Arc, atomic::Ordering},
};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Frame},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, duplex},
    time::{Duration, sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

#[cfg(feature = "reality")]
use crate::handler::reality::accept_reality_stream;
use crate::{
    address::BindLocation,
    async_stream::AsyncStream,
    config::server_config::{
        InboundSniffingConfig, ServerConfig, ServerProxyConfig, XhttpDataPlacement,
        XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement,
        XhttpServerConfig,
    },
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::{DataPlaneRuntime, RuntimeState},
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TcpSocketPolicy, handler::tls::build_server_config,
};

use super::{
    process_stream_with_sniffing_and_local_addr,
    transport_plan::{ListenerSecurityPlan, XhttpListenerPlan},
};

#[cfg(feature = "tls")]
mod h3_transport;
mod request;
mod response;
mod session;

#[cfg(feature = "tls")]
use h3_transport::*;

use request::*;
use response::*;
use session::{
    IncomingBodyReader, SessionCleanupGuard, SessionStore, XhttpLogicalStream,
};
#[cfg(test)]
use session::{
    SessionTtlPlan, SessionTtlSnapshot, SharedUploadReader, UploadPayloadPlan,
    UploadReassemblyPlan, UploadReassemblySnapshot, XhttpSession, XhttpUploadReader,
    plan_session_ttl, plan_upload_payload, plan_upload_reassembly,
};

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
const XHTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(4);

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

pub async fn start_xhttp_server(
    config: ServerConfig,
    runtime: RuntimeState,
    plan: XhttpListenerPlan,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol: _,
        sniffing,
        tcp_socket_policy,
        ..
    } = config;

    let listener_config = prepare_xhttp_listener(plan)?;

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
    let shutdown = CancellationToken::new();
    #[cfg(feature = "tls")]
    let h3_transport_config =
        build_xhttp_h3_transport_config(&listener_config.xhttp_config)?;
    let state = Arc::new(AppState::new(
        listener_config.xhttp_config,
        server_handler,
        resolver,
        runtime.data_plane(),
        sniffing,
        shutdown.clone(),
    ));
    #[cfg(feature = "tls")]
    if let XhttpSecurityLayer::H3Tls(server_config) = listener_config.security {
        if tcp_socket_policy
            .as_ref()
            .is_some_and(TcpSocketPolicy::has_tcp_only_options)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TCP-only sockopt fields are not applicable to XHTTP HTTP/3",
            ));
        }
        return start_xhttp_h3_server(
            bind_addr,
            server_config,
            h3_transport_config,
            state,
            tcp_socket_policy,
        )
        .await;
    }

    let listener =
        super::create_tcp_listener(bind_addr, tcp_socket_policy.as_ref()).await?;
    let security = listener_config.security.clone();

    let handle = tokio::spawn(async move {
        let mut accept_health = super::TcpAcceptHealth::default();
        loop {
            let (stream, peer_addr) = match super::accept_tcp_with_health(
                &listener,
                &mut accept_health,
                "xhttp_tcp",
            )
            .await
            {
                Ok(pair) => pair,
                Err(err) => {
                    error!("xhttp TCP listener stopped: {err}");
                    return;
                }
            };
            let _ = stream.set_nodelay(true);
            if let Some(policy) = tcp_socket_policy.as_ref()
                && let Err(err) = super::apply_tcp_socket_policy(
                    &stream, bind_addr, peer_addr, policy,
                )
            {
                error!("xhttp TCP socket policy for {} failed: {}", peer_addr, err);
                continue;
            }
            let local_addr = match stream.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    error!("xhttp local address for {} failed: {}", peer_addr, err);
                    continue;
                }
            };

            let state = state.clone();
            let security = security.clone();
            let connection_runtime = state.runtime.clone();
            connection_runtime.spawn_inbound_connection(async move {
                let stream: Box<dyn AsyncStream> = Box::new(stream);
                let wrapped_stream: std::io::Result<Box<dyn AsyncStream>> =
                    match security {
                        XhttpSecurityLayer::None => Ok(stream),
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::Tls(acceptor) => {
                            accept_xhttp_tls(acceptor, stream).await
                        }
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::H3Tls(_) => unreachable!(
                            "HTTP/3 XHTTP listener is dispatched before TCP accept"
                        ),
                        #[cfg(feature = "reality")]
                        XhttpSecurityLayer::Reality(config) => {
                            accept_reality_stream(stream, &config).await.map(
                                |stream| Box::new(stream) as Box<dyn AsyncStream>,
                            )
                        }
                    };

                match wrapped_stream {
                    Ok(stream) => {
                        serve_http_connection(stream, state, peer_addr, local_addr)
                            .await
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
    #[cfg(feature = "tls")]
    H3Tls(Arc<rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(crate::config::server_config::RealityTransportConfig),
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

fn prepare_xhttp_listener(
    plan: XhttpListenerPlan,
) -> std::io::Result<XhttpListenerConfig> {
    let XhttpListenerPlan {
        config: xhttp_config,
        protocol: inner,
        security,
    } = plan;
    let security = match security {
        ListenerSecurityPlan::None => XhttpSecurityLayer::None,
        #[cfg(feature = "tls")]
        ListenerSecurityPlan::Tls(tls_config) => {
            let crate::config::server_config::TlsServerConfig {
                certificates,
                mut alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                ..
            } = tls_config;
            let is_h3 = alpn_protocols.as_slice() == ["h3"];
            if !is_h3 && !alpn_protocols.iter().any(|proto| proto == "h2") {
                alpn_protocols.push("h2".to_string());
            }
            let tls_config = Arc::new(build_server_config(
                &certificates,
                &alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version.as_deref(),
                max_version.as_deref(),
            )?);
            if is_h3 {
                XhttpSecurityLayer::H3Tls(tls_config)
            } else {
                XhttpSecurityLayer::Tls(TlsAcceptor::from(tls_config))
            }
        }
        #[cfg(feature = "reality")]
        ListenerSecurityPlan::Reality(reality_config) => {
            XhttpSecurityLayer::Reality(reality_config)
        }
    };
    Ok(XhttpListenerConfig {
        xhttp_config,
        inner,
        security,
    })
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

fn uses_http1_header_read_limit(version: hyper::Version) -> bool {
    matches!(version, hyper::Version::HTTP_10 | hyper::Version::HTTP_11)
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
    local_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http_builder(&mut builder, state.server_max_header_bytes);
    let service = service_fn(move |request| {
        handle_request(request, state.clone(), peer_addr, local_addr)
    });

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
    runtime: DataPlaneRuntime,
    sniffing: Option<InboundSniffingConfig>,
    shutdown: CancellationToken,
    sessions: SessionStore,
}

impl AppState {
    fn new(
        config: XhttpServerConfig,
        server_handler: Arc<Box<dyn TcpServerHandler>>,
        resolver: Arc<dyn Resolver>,
        runtime: DataPlaneRuntime,
        sniffing: Option<InboundSniffingConfig>,
        shutdown: CancellationToken,
    ) -> Self {
        let sessions = SessionStore::new(
            Duration::from_secs(config.session_ttl_secs),
            config.max_buffered_posts,
            shutdown.clone(),
            runtime.clone(),
        );
        Self {
            mode: config.mode,
            host: config.host,
            base_path: normalize_base_path(
                config.path,
                config.session_placement,
                config.seq_placement,
            ),
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
            sniffing,
            shutdown,
            sessions,
        }
    }

    fn validate_host(&self, header_host: Option<&str>) -> bool {
        match (&self.host, header_host) {
            (None, _) => true,
            (Some(expected), Some(actual)) => xray_valid_http_host(actual, expected),
            _ => false,
        }
    }

    fn extract_meta<B>(
        &self,
        request: &Request<B>,
        decoded_path: &str,
    ) -> (Option<String>, Option<String>) {
        let trimmed_base_path = self.base_path.trim_end_matches('/');
        let path_tail = if decoded_path == trimmed_base_path {
            ""
        } else {
            decoded_path.strip_prefix(&self.base_path).unwrap_or("")
        };

        // Current Xray consumes path metadata in placement order. Each path
        // placement advances the path segment index independently, so mixed
        // path/query/header/cookie configurations remain valid.
        let mut path_part = 0usize;
        let session_id = match self.session_placement {
            XhttpPlacement::Path => xray_path_metadata_value_for_placement(
                path_tail,
                &mut path_part,
                self.session_placement,
            ),
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
            XhttpPlacement::Path => xray_path_metadata_value_for_placement(
                path_tail,
                &mut path_part,
                self.seq_placement,
            ),
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
    ) -> Option<bool> {
        let padding = extract_xray_request_padding(
            self.padding_obfs_mode,
            &self.padding_key,
            &self.padding_header,
            self.padding_placement,
            path_query,
            headers,
        )?;

        is_padding_valid(
            &padding,
            self.min_padding,
            self.max_padding,
            self.padding_method,
        )
        .then_some(self.padding_obfs_mode && !padding.is_empty())
    }

    fn decorate_response(
        &self,
        response: &mut Response<ResponseBody>,
        request_method: &Method,
        request_headers: &hyper::HeaderMap,
    ) {
        apply_xray_cors_headers(
            response.headers_mut(),
            request_method,
            request_headers,
            self.uses_cookie_request_metadata(),
        );
        apply_response_padding(response.headers_mut(), self);
    }

    fn uses_cookie_request_metadata(&self) -> bool {
        self.session_placement == XhttpPlacement::Cookie
            || self.seq_placement == XhttpPlacement::Cookie
            || self.padding_placement == XhttpPaddingPlacement::Cookie
            || self.uplink_data_placement == XhttpDataPlacement::Cookie
    }
}

async fn handle_request<B>(
    request: Request<B>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let request_headers = request.headers().clone();

    let http1_header_limit =
        xray_http1_header_read_limit(state.server_max_header_bytes);
    if uses_http1_header_read_limit(request.version())
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

    if request.method() == Method::OPTIONS {
        let mut response = simple_response(StatusCode::OK);
        state.decorate_response(&mut response, request.method(), request.headers());
        return Ok(response);
    }

    let Some(obfs_padding_accepted) =
        state.validate_padding(request.uri().query(), request.headers())
    else {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            query = ?request.uri().query(),
            "xhttp request rejected by padding validation"
        );
        let mut response = simple_response(StatusCode::BAD_REQUEST);
        state.decorate_response(&mut response, request.method(), request.headers());
        return Ok(response);
    };

    let request_method = request.method().clone();
    let logical_peer_addr =
        trusted_forwarded_peer(&request_headers, &state.trusted_x_forwarded_for)
            .unwrap_or(peer_addr);
    // Current Xray keeps the legacy Referer compatibility marker, and also
    // enables stream-up padding when xPaddingObfsMode accepted non-empty padding.
    let stream_up_padding =
        stream_up_padding_enabled(&request_headers, obfs_padding_accepted);
    let (session_id, seq) = state.extract_meta(&request, &path);
    let is_downlink_method = request.method() == Method::GET;
    // Current Xray treats every non-GET request as uplink. GET is uplink only
    // when sequence metadata is present, which lets packet-up use GET without
    // relying on the configured client method or legacy upstream markers.
    let is_uplink_method = is_xray_uplink_request(request.method(), seq.is_some());
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
                local_addr,
            )
            .await
        }
        Ok(XhttpRequestDispatch::StreamOne) => {
            handle_stream_one(
                request.into_body(),
                state.clone(),
                logical_peer_addr,
                local_addr,
            )
            .await
        }
        Ok(XhttpRequestDispatch::StreamUp) => {
            let request_version = request.version();
            handle_stream_up(
                request.into_body(),
                request_version,
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

    state.decorate_response(&mut response, &request_method, &request_headers);
    Ok(response)
}

async fn handle_stream_one<B>(
    mut body: B,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Send + 'static,
{
    let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
    let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
    let logical_stream = XhttpLogicalStream::new(server_read, server_write);

    spawn_handler_stream(logical_stream, state.clone(), peer_addr, local_addr);

    let mut upload_writer = client_upload;
    let shutdown = state.shutdown.clone();
    let runtime = state.runtime.clone();
    let _ = runtime.spawn_inbound_connection(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = async {
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
            } => {}
        }
        let _ = upload_writer.shutdown().await;
    });

    reader_response(StatusCode::OK, client_download, state.no_sse_header)
}

fn stream_up_padding_enabled(
    headers: &hyper::HeaderMap,
    obfs_padding_accepted: bool,
) -> bool {
    header_value(headers, "referer").is_some() || obfs_padding_accepted
}

fn stream_up_can_flush_while_uploading(version: hyper::Version) -> bool {
    matches!(version, hyper::Version::HTTP_2 | hyper::Version::HTTP_3)
}

async fn handle_stream_up<B>(
    body: B,
    request_version: hyper::Version,
    state: Arc<AppState>,
    session_id: String,
    padding_enabled: bool,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let response_can_flush_while_uploading =
        stream_up_can_flush_while_uploading(request_version);
    let session = state.sessions.get_or_create(&session_id);
    let reader = IncomingBodyReader::new(body);
    if session
        .upload_queue
        .push_reader(Box::pin(reader))
        .await
        .is_err()
    {
        return simple_response(StatusCode::CONFLICT);
    }

    stream_up_response(
        session.closed.clone(),
        &state,
        padding_enabled && response_can_flush_while_uploading,
    )
    .await
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    let (stream, reader) = session.new_downlink_connection();
    spawn_handler_stream(stream, state.clone(), peer_addr, local_addr);

    let cleanup = SessionCleanupGuard {
        sessions: state.sessions.clone(),
        session_id,
        session,
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

async fn handle_packet_up<B>(
    request: Request<B>,
    state: Arc<AppState>,
    session_id: String,
    seq: String,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Ok(seq) = seq.parse::<u64>() else {
        return simple_response(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let (parts, body) = request.into_parts();
    if declared_body_length_exceeds_post_limit(
        state.uplink_data_placement,
        &parts.headers,
        state.max_each_post_bytes,
    ) {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
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
        match collect_body_limited(body, state.max_each_post_bytes.max(0) as usize)
            .await
        {
            Ok(payload) => payload,
            Err(status) => return simple_response(status),
        }
    } else {
        Vec::new()
    };

    let body_payload_is_empty = body_payload.is_empty();
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
        Ok(()) => packet_up_success_response(body_payload_is_empty),
        Err(_) => simple_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn spawn_handler_stream(
    stream: XhttpLogicalStream,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) {
    let shutdown = state.shutdown.clone();
    let runtime = state.runtime.clone();
    let _ = runtime.spawn_inbound_connection(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            result = process_stream_with_sniffing_and_local_addr(
                stream,
                state.server_handler.clone(),
                state.resolver.clone(),
                peer_addr,
                Some(local_addr),
                state.runtime.clone(),
                state.sniffing.clone(),
            ) => {
                if let Err(err) = result {
                    error!("xhttp logical stream {} failed: {}", peer_addr, err);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
