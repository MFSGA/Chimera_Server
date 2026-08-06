#[cfg(feature = "tls")]
use std::fs;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use futures::{Stream, StreamExt};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use rand::RngExt as _;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::Mutex,
    time::{Duration, sleep, timeout},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use tracing::{debug, error};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{
        ServerConfig, ServerProxyConfig, XhttpDataPlacement, XhttpMode,
        XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement,
        XhttpServerConfig,
    },
    handler::{
        proxy_protocol::read_proxy_header,
        tcp::{
            tcp_handler::TcpServerHandler,
            tcp_handler_util::create_tcp_server_handler,
        },
    },
    resolver::Resolver,
    runtime::RuntimeState,
};
#[cfg(feature = "reality")]
use crate::{
    config::server_config::RealityTransportConfig,
    handler::reality::accept_reality_stream,
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig,
    util::{
        rustls_util::create_server_config,
        socket::new_socket2_udp_socket_with_buffer_size,
    },
};

use super::process_stream;

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
const UPLOAD_MODE_NONE: u8 = 0;
const UPLOAD_MODE_PACKET: u8 = 1;
const UPLOAD_MODE_STREAM: u8 = 2;

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;
type XhttpResponseStream =
    Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send + 'static>>;

struct XhttpRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Box<dyn XhttpRequestBody>,
}

impl XhttpRequest {
    fn from_hyper(request: Request<Incoming>) -> Self {
        let (parts, body) = request.into_parts();
        Self {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: Box::new(HyperRequestBody { inner: body }),
        }
    }
}

#[async_trait]
trait XhttpRequestBody: Send {
    async fn next_data(&mut self) -> std::io::Result<Option<Bytes>>;
}

struct HyperRequestBody {
    inner: Incoming,
}

#[async_trait]
impl XhttpRequestBody for HyperRequestBody {
    async fn next_data(&mut self) -> std::io::Result<Option<Bytes>> {
        loop {
            let Some(frame) = self.inner.frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(std::io::Error::other)?;
            if let Ok(data) = frame.into_data() {
                return Ok(Some(data));
            }
        }
    }
}

struct H3RequestBody<S> {
    inner: h3::server::RequestStream<S, Bytes>,
}

#[async_trait]
impl<S> XhttpRequestBody for H3RequestBody<S>
where
    S: h3::quic::RecvStream + Send + Unpin + 'static,
{
    async fn next_data(&mut self) -> std::io::Result<Option<Bytes>> {
        let Some(mut data) = self
            .inner
            .recv_data()
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
        else {
            return Ok(None);
        };
        let remaining = data.remaining();
        Ok(Some(data.copy_to_bytes(remaining)))
    }
}

struct XhttpResponsePlan {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<XhttpResponseStream>,
}

impl XhttpResponsePlan {
    fn empty(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: None,
        }
    }
}

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
    let resolver = runtime.resolver();
    let state = Arc::new(AppState::new(
        listener_config.xhttp_config,
        server_handler,
        resolver,
        runtime,
    ));
    #[cfg(feature = "tls")]
    if let XhttpSecurityLayer::Http3(tls_config) = &listener_config.security {
        return start_xhttp3_server(bind_addr, tls_config.clone(), state).await;
    }

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let security = listener_config.security.clone();
    let accept_proxy_protocol = listener_config.accept_proxy_protocol;

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
                #[cfg(feature = "reality")]
                let reality_resolver = state.resolver.clone();
                let mut stream = stream;
                let peer_addr = match resolve_xhttp_peer_addr(
                    &mut stream,
                    peer_addr,
                    accept_proxy_protocol,
                    state.runtime.policy_handshake_timeout(0),
                )
                .await
                {
                    Ok(peer_addr) => peer_addr,
                    Err(err) => {
                        debug!("xhttp PROXY protocol handshake failed: {err}");
                        return;
                    }
                };
                let stream: Box<dyn AsyncStream> = Box::new(stream);
                let wrapped_stream: std::io::Result<Box<dyn AsyncStream>> =
                    match security {
                        XhttpSecurityLayer::None => Ok(stream),
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::Tls(acceptor) => {
                            acceptor.accept(stream).await.map(|tls_stream| {
                                Box::new(tls_stream) as Box<dyn AsyncStream>
                            })
                        }
                        #[cfg(feature = "reality")]
                        XhttpSecurityLayer::Reality(config) => {
                            accept_reality_stream(stream, &config, reality_resolver)
                                .await
                                .map(|stream| {
                                    Box::new(stream) as Box<dyn AsyncStream>
                                })
                        }
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::Http3(_) => unreachable!(
                            "HTTP/3 security is handled by the UDP listener"
                        ),
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

#[cfg(feature = "tls")]
async fn start_xhttp3_server(
    bind_addr: std::net::SocketAddr,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    state: Arc<AppState>,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let quic_crypto: quinn::crypto::rustls::QuicServerConfig =
        tls_config.try_into().map_err(std::io::Error::other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
        std::io::Error::other("xhttp HTTP/3 transport config already shared")
    })?;
    let idle_timeout = Duration::from_secs(300).try_into().map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
    })?;
    transport
        .max_concurrent_bidi_streams(4096_u32.into())
        .max_concurrent_uni_streams(4096_u32.into())
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .send_window(16 * 1024 * 1024)
        .receive_window((20u32 * 1024 * 1024).into())
        .stream_receive_window((8u32 * 1024 * 1024).into());

    let socket = new_socket2_udp_socket_with_buffer_size(
        bind_addr.is_ipv6(),
        None,
        Some(bind_addr),
        false,
        Some(8_625_000),
    )
    .map_err(std::io::Error::other)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.into(),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(std::io::Error::other)?;

    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        if let Err(error) =
                            serve_xhttp3_connection(connection, state).await
                        {
                            error!("xhttp HTTP/3 connection failed: {error}");
                        }
                    }
                    Err(error) => {
                        debug!("xhttp HTTP/3 handshake failed: {error}");
                    }
                }
            });
        }
    });

    Ok(vec![handle])
}

#[cfg(feature = "tls")]
async fn serve_xhttp3_connection(
    connection: quinn::Connection,
    state: Arc<AppState>,
) -> std::io::Result<()> {
    let peer_addr = connection.remote_address();
    let h3_transport = h3_quinn::Connection::new(connection);
    let mut h3_builder = h3::server::builder();
    h3_builder.max_field_section_size(
        state.server_max_header_bytes.min(u64::MAX as usize) as u64,
    );
    let mut h3_connection = h3_builder
        .build(h3_transport)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    loop {
        let Some(resolver) = h3_connection
            .accept()
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
        else {
            return Ok(());
        };
        let state = state.clone();
        tokio::spawn(async move {
            let result = async move {
                let (request, stream) = resolver
                    .resolve_request()
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let (send_stream, recv_stream) = stream.split();
                let (parts, ()) = request.into_parts();
                let request = XhttpRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body: Box::new(H3RequestBody { inner: recv_stream }),
                };
                let plan = handle_xhttp_request(request, state, peer_addr).await;
                write_xhttp3_response(send_stream, plan).await
            }
            .await;
            if let Err(error) = result {
                debug!("xhttp HTTP/3 request failed: {error}");
            }
        });
    }
}

#[cfg(feature = "tls")]
async fn write_xhttp3_response<S>(
    mut stream: h3::server::RequestStream<S, Bytes>,
    mut plan: XhttpResponsePlan,
) -> std::io::Result<()>
where
    S: h3::quic::SendStream<Bytes> + Send + Unpin,
{
    let mut response = Response::new(());
    *response.status_mut() = plan.status;
    *response.headers_mut() = plan.headers;
    stream
        .send_response(response)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;

    if let Some(mut body) = plan.body.take() {
        while let Some(chunk) = body.next().await {
            stream
                .send_data(chunk?)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
    }
    stream
        .finish()
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))
}

struct XhttpListenerConfig {
    xhttp_config: XhttpServerConfig,
    inner: ServerProxyConfig,
    security: XhttpSecurityLayer,
    accept_proxy_protocol: bool,
}

#[derive(Clone)]
enum XhttpSecurityLayer {
    None,
    #[cfg(feature = "tls")]
    Tls(TlsAcceptor),
    #[cfg(feature = "tls")]
    Http3(Arc<tokio_rustls::rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
}

async fn resolve_xhttp_peer_addr<S>(
    stream: &mut S,
    socket_peer_addr: std::net::SocketAddr,
    accept_proxy_protocol: bool,
    handshake_timeout: Duration,
) -> std::io::Result<std::net::SocketAddr>
where
    S: AsyncRead + Unpin,
{
    if !accept_proxy_protocol {
        return Ok(socket_peer_addr);
    }
    match timeout(handshake_timeout, read_proxy_header(stream)).await {
        Ok(result) => Ok(result?.unwrap_or(socket_peer_addr)),
        Err(error) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("PROXY protocol handshake timed out: {error}"),
        )),
    }
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> std::io::Result<XhttpListenerConfig> {
    match protocol {
        ServerProxyConfig::ProxyProtocol { inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            #[cfg(feature = "tls")]
            if matches!(&config.security, XhttpSecurityLayer::Http3(_)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "XHTTP HTTP/3 does not support TCP PROXY protocol",
                ));
            }
            config.accept_proxy_protocol = true;
            Ok(config)
        }
        ServerProxyConfig::Xhttp { config, inner } => Ok(XhttpListenerConfig {
            xhttp_config: config,
            inner: *inner,
            security: XhttpSecurityLayer::None,
            accept_proxy_protocol: false,
        }),
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(TlsServerConfig {
            certificates,
            mut alpn_protocols,
            enable_session_resumption: _,
            reject_unknown_sni: _,
            min_version: _,
            max_version: _,
            server_name: _,
            inner,
        }) => match *inner {
            ServerProxyConfig::Xhttp { config, inner } => {
                let is_h3 = alpn_protocols.len() == 1
                    && alpn_protocols[0].eq_ignore_ascii_case("h3");
                if !is_h3 && alpn_protocols.is_empty() {
                    alpn_protocols = vec!["h2".to_string(), "http/1.1".to_string()];
                }

                let certificate = certificates
                    .into_iter()
                    .find(|certificate| {
                        certificate.key_path.is_some()
                            || certificate.key_pem.is_some()
                    })
                    .ok_or_else(|| {
                        std::io::Error::other(
                            "missing tls key material for xhttp server",
                        )
                    })?;
                let cert_bytes = match certificate.certificate_path {
                    Some(path) => fs::read(path)?,
                    None => certificate.certificate_pem,
                };
                let key_bytes = match (certificate.key_path, certificate.key_pem) {
                    (Some(path), _) => fs::read(path)?,
                    (None, Some(key)) => key,
                    (None, None) => {
                        return Err(std::io::Error::other(
                            "missing tls private key for xhttp server",
                        ));
                    }
                };
                let tls_config = create_server_config(
                    &cert_bytes,
                    &key_bytes,
                    &alpn_protocols,
                    &[],
                )?;

                let security = if is_h3 {
                    XhttpSecurityLayer::Http3(Arc::new(tls_config))
                } else {
                    XhttpSecurityLayer::Tls(TlsAcceptor::from(Arc::new(tls_config)))
                };
                Ok(XhttpListenerConfig {
                    xhttp_config: config,
                    inner: *inner,
                    security,
                    accept_proxy_protocol: false,
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
                        accept_proxy_protocol: false,
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

async fn serve_http_connection<IO>(
    io: IO,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let max_header_bytes = state.server_max_header_bytes.max(8192);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .max_buf_size(max_header_bytes)
        .max_headers((max_header_bytes / 16).max(100))
        .header_read_timeout(Duration::from_secs(4))
        .timer(TokioTimer::new());
    builder.http2().max_header_list_size(
        state.server_max_header_bytes.min(u32::MAX as usize) as u32,
    );
    builder
        .http2()
        .max_header_list_size(max_header_bytes.min(u32::MAX as usize) as u32);
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
            base_path: config.path,
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
                xray_http_host_matches(actual, expected)
            }
            _ => false,
        }
    }

    fn extract_meta(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
        decoded_path: &str,
    ) -> (Option<String>, Option<String>) {
        let path_tail = decoded_path.strip_prefix(&self.base_path).unwrap_or("");
        let path_segments = path_tail.split('/').collect::<Vec<_>>();
        let mut path_index = 0usize;
        let mut next_path_value = || {
            let value = path_segments.get(path_index).copied();
            if value.is_some() {
                path_index += 1;
            }
            value
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        };

        let session_id = match self.session_placement {
            XhttpPlacement::Path => next_path_value(),
            XhttpPlacement::Query => query_value(uri.query(), &self.session_key),
            XhttpPlacement::Header => header_value(headers, &self.session_key),
            XhttpPlacement::Cookie => cookie_value(headers, &self.session_key),
        };
        let seq = match self.seq_placement {
            XhttpPlacement::Path => next_path_value(),
            XhttpPlacement::Query => query_value(uri.query(), &self.seq_key),
            XhttpPlacement::Header => header_value(headers, &self.seq_key),
            XhttpPlacement::Cookie => cookie_value(headers, &self.seq_key),
        };
        (session_id, seq)
    }

    fn stream_up_keepalive_delay(&self) -> Option<Duration> {
        let (from, to) = self.stream_up_server_secs;
        if to == 0 {
            return None;
        }
        let seconds = if from >= to {
            to
        } else {
            rand::rng().random_range(from..=to)
        };
        Some(Duration::from_secs(seconds as u64))
    }

    fn random_padding_length(&self) -> usize {
        if self.min_padding >= self.max_padding {
            self.max_padding
        } else {
            rand::rng().random_range(self.min_padding..=self.max_padding)
        }
    }

    fn stream_up_padding(&self) -> Vec<u8> {
        vec![b'X'; self.random_padding_length()]
    }

    fn response_padding_value(&self) -> String {
        generate_padding(self.padding_method, self.random_padding_length())
    }

    fn uses_cookie_transport(&self) -> bool {
        self.session_placement == XhttpPlacement::Cookie
            || self.seq_placement == XhttpPlacement::Cookie
            || self.uplink_data_placement == XhttpDataPlacement::Cookie
            || self.padding_placement == XhttpPaddingPlacement::Cookie
    }

    fn extract_padding_value(
        &self,
        path_query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> Option<String> {
        if !self.padding_obfs_mode {
            if let Some(referer) = headers
                .get(header::REFERER)
                .and_then(|value| value.to_str().ok())
            {
                return query_value_from_url(referer, "x_padding");
            }
            return query_value(path_query, "x_padding");
        }

        if let Some(value) = cookie_value(headers, &self.padding_key) {
            return Some(value);
        }
        if let Some(header_value) = header_value(headers, &self.padding_header) {
            if self.padding_placement == XhttpPaddingPlacement::Header {
                return Some(header_value);
            }
            if self.padding_placement == XhttpPaddingPlacement::QueryInHeader {
                return query_value_from_url(&header_value, &self.padding_key);
            }
        }
        query_value(path_query, &self.padding_key)
    }

    fn validate_padding(
        &self,
        path_query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> bool {
        let Some(padding) = self.extract_padding_value(path_query, headers) else {
            return false;
        };
        let length = match self.padding_method {
            XhttpPaddingMethod::RepeatX => padding.len(),
            XhttpPaddingMethod::Tokenish => hpack_huffman_encoded_len(&padding),
        };
        let tolerance = if self.padding_method == XhttpPaddingMethod::Tokenish {
            2
        } else {
            0
        };
        length.saturating_add(tolerance) >= self.min_padding
            && length <= self.max_padding.saturating_add(tolerance)
    }
}

#[derive(Debug, Default)]
struct CorsRequest {
    origin: Option<String>,
    requested_method: Option<String>,
    requested_headers: Option<String>,
    is_options: bool,
}

impl CorsRequest {
    fn from_request(request: &XhttpRequest) -> Self {
        Self {
            origin: request
                .headers
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            requested_method: request
                .headers
                .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            requested_headers: request
                .headers
                .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            is_options: request.method == Method::OPTIONS,
        }
    }
}

fn apply_cors_headers(
    response: &mut XhttpResponsePlan,
    request: &CorsRequest,
    allow_credentials: bool,
) {
    let origin = request.origin.as_deref().unwrap_or("*");
    if let Ok(origin) = hyper::header::HeaderValue::from_str(origin) {
        response
            .headers
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    if allow_credentials {
        response.headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            hyper::header::HeaderValue::from_static("true"),
        );
    }
    if request.is_options {
        let allowed_method = request.requested_method.as_deref().unwrap_or("*");
        if let Ok(value) = hyper::header::HeaderValue::from_str(allowed_method) {
            response
                .headers
                .insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
        }
        let allowed_headers = request.requested_headers.as_deref().unwrap_or("*");
        if let Ok(value) = hyper::header::HeaderValue::from_str(allowed_headers) {
            response
                .headers
                .insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
        }
    }
}

fn apply_xhttp_response_headers(
    response: &mut XhttpResponsePlan,
    request: &CorsRequest,
    state: &AppState,
) {
    apply_cors_headers(response, request, state.uses_cookie_transport());
    let padding = state.response_padding_value();
    if !state.padding_obfs_mode {
        if let Ok(value) = hyper::header::HeaderValue::from_str(&padding) {
            response.headers.insert("x-padding", value);
        }
        return;
    }

    match state.padding_placement {
        XhttpPaddingPlacement::Header => {
            if let (Ok(name), Ok(value)) = (
                hyper::header::HeaderName::from_bytes(
                    state.padding_header.as_bytes(),
                ),
                hyper::header::HeaderValue::from_str(&padding),
            ) {
                response.headers.insert(name, value);
            }
        }
        XhttpPaddingPlacement::QueryInHeader => {
            if let (Ok(name), Ok(value)) = (
                hyper::header::HeaderName::from_bytes(
                    state.padding_header.as_bytes(),
                ),
                hyper::header::HeaderValue::from_str(&format!(
                    "?{}={padding}",
                    state.padding_key
                )),
            ) {
                response.headers.insert(name, value);
            }
        }
        XhttpPaddingPlacement::Cookie => {
            if let Ok(value) = hyper::header::HeaderValue::from_str(&format!(
                "{}={padding}; Path=/",
                state.padding_key
            )) {
                response.headers.append(header::SET_COOKIE, value);
            }
        }
        XhttpPaddingPlacement::Query => {}
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    let plan =
        handle_xhttp_request(XhttpRequest::from_hyper(request), state, peer_addr)
            .await;
    Ok(into_hyper_response(plan))
}

fn into_hyper_response(plan: XhttpResponsePlan) -> Response<ResponseBody> {
    let body = match plan.body {
        Some(stream) => {
            let stream = stream.filter_map(|result| async move {
                match result {
                    Ok(bytes) => Some(Ok(Frame::data(bytes))),
                    Err(error) => {
                        error!("xhttp response stream failed: {error}");
                        None
                    }
                }
            });
            BodyExt::boxed_unsync(StreamBody::new(stream))
        }
        None => BodyExt::boxed_unsync(Empty::<Bytes>::new()),
    };
    let mut response = Response::new(body);
    *response.status_mut() = plan.status;
    *response.headers_mut() = plan.headers;
    response
}

async fn handle_xhttp_request(
    request: XhttpRequest,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> XhttpResponsePlan {
    let host_header = request
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let authority_host = request.uri.authority().map(|value| value.as_str());
    let request_host = host_header.or(authority_host);

    if !state.validate_host(request_host) {
        debug!(
            method = %request.method,
            path = %request.uri.path(),
            host = ?request_host,
            "xhttp request rejected by host validation"
        );
        return XhttpResponsePlan::empty(StatusCode::NOT_FOUND);
    }

    let Some(path) = decode_uri_path(request.uri.path()) else {
        return XhttpResponsePlan::empty(StatusCode::NOT_FOUND);
    };
    if !matches_base_path(&path, &state.base_path) {
        debug!(
            method = %request.method,
            path = %path,
            base_path = %state.base_path,
            "xhttp request rejected by path validation"
        );
        return XhttpResponsePlan::empty(StatusCode::NOT_FOUND);
    }
    let cors = CorsRequest::from_request(&request);
    if !state.validate_padding(request.uri.query(), &request.headers) {
        debug!(
            method = %request.method,
            path = %request.uri.path(),
            query = ?request.uri.query(),
            "xhttp request rejected by padding validation"
        );
        let mut response = XhttpResponsePlan::empty(StatusCode::BAD_REQUEST);
        apply_xhttp_response_headers(&mut response, &cors, &state);
        return response;
    }

    if request.method == Method::OPTIONS {
        let mut response = XhttpResponsePlan::empty(StatusCode::OK);
        apply_xhttp_response_headers(&mut response, &cors, &state);
        return response;
    }

    let (session_id, seq) =
        state.extract_meta(&request.uri, &request.headers, &path);
    let is_uplink_request = request.method != Method::GET || seq.is_some();

    let mut response = if session_id.is_none()
        && !matches!(
            state.mode,
            XhttpMode::Auto | XhttpMode::StreamOne | XhttpMode::StreamUp
        ) {
        XhttpResponsePlan::empty(StatusCode::BAD_REQUEST)
    } else if is_uplink_request {
        match (session_id, seq) {
            (Some(session_id), None)
                if matches!(state.mode, XhttpMode::Auto | XhttpMode::StreamUp) =>
            {
                let keepalive_enabled = state.padding_obfs_mode
                    || request.headers.contains_key(header::REFERER);
                handle_stream_up(
                    request,
                    state.clone(),
                    session_id,
                    keepalive_enabled,
                )
                .await
            }
            (Some(_), None) => XhttpResponsePlan::empty(StatusCode::BAD_REQUEST),
            (Some(session_id), Some(seq))
                if matches!(state.mode, XhttpMode::Auto | XhttpMode::PacketUp) =>
            {
                handle_packet_up(request, state.clone(), session_id, seq).await
            }
            (Some(_), Some(_)) => XhttpResponsePlan::empty(StatusCode::BAD_REQUEST),
            (None, _) => handle_stream_one(request, state.clone(), peer_addr).await,
        }
    } else if let Some(session_id) = session_id {
        handle_stream_down(state.clone(), session_id, peer_addr).await
    } else {
        handle_stream_one(request, state.clone(), peer_addr).await
    };

    apply_xhttp_response_headers(&mut response, &cors, &state);
    response
}

async fn handle_stream_one(
    request: XhttpRequest,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> XhttpResponsePlan {
    let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
    let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
    let logical_stream = XhttpLogicalStream::new(server_read, server_write);

    spawn_handler_stream(logical_stream, state.clone(), peer_addr);

    let mut upload_writer = client_upload;
    let mut body = request.body;
    tokio::spawn(async move {
        while let Ok(Some(chunk)) = body.next_data().await {
            if upload_writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = upload_writer.shutdown().await;
    });

    reader_response(StatusCode::OK, client_download, state.no_sse_header)
}

async fn handle_stream_up(
    request: XhttpRequest,
    state: Arc<AppState>,
    session_id: String,
    keepalive_enabled: bool,
) -> XhttpResponsePlan {
    let session = state.sessions.get_or_create(&session_id);
    if !session.claim_stream_upload() {
        return XhttpResponsePlan::empty(StatusCode::CONFLICT);
    }
    let (mut response_writer, response_reader) = duplex(XHTTP_PIPE_CAPACITY);
    let sessions = state.sessions.clone();
    let task_state = state.clone();
    let task_session = session.clone();
    let cancel_token = session.cancel_token.clone();
    tokio::spawn(async move {
        let mut body = request.body;
        let mut upload_state = task_session.upload.lock().await;
        let mut keepalive_enabled = keepalive_enabled;
        let mut failed = false;
        if keepalive_enabled
            && task_state.stream_up_server_secs.1 > 0
            && response_writer
                .write_all(&task_state.stream_up_padding())
                .await
                .is_err()
        {
            keepalive_enabled = false;
        }

        loop {
            let next_chunk = if keepalive_enabled {
                if let Some(delay) = task_state.stream_up_keepalive_delay() {
                    tokio::select! {
                        _ = cancel_token.cancelled() => break,
                        chunk = body.next_data() => chunk,
                        _ = sleep(delay) => {
                            if response_writer
                                .write_all(&task_state.stream_up_padding())
                                .await
                                .is_err()
                            {
                                keepalive_enabled = false;
                            }
                            continue;
                        }
                    }
                } else {
                    tokio::select! {
                        _ = cancel_token.cancelled() => break,
                        chunk = body.next_data() => chunk,
                    }
                }
            } else {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    chunk = body.next_data() => chunk,
                }
            };

            let chunk = match next_chunk {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) => {
                    error!("xhttp stream-up body read failed: {}", error);
                    failed = true;
                    break;
                }
            };
            if let Err(error) = upload_state.writer.write_all(&chunk).await {
                error!("xhttp stream-up write failed: {}", error);
                failed = true;
                break;
            }
        }

        if !failed && let Err(error) = upload_state.writer.shutdown().await {
            error!("xhttp stream-up shutdown failed: {}", error);
            failed = true;
        }
        drop(upload_state);
        if failed {
            sessions.remove(&session_id).await;
        }
    });

    reader_response(StatusCode::OK, response_reader, true)
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
) -> XhttpResponsePlan {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let Some(reader) = session.take_downlink_reader().await else {
        return XhttpResponsePlan::empty(StatusCode::CONFLICT);
    };

    let body_stream =
        SessionBodyStream::new(reader, state.sessions.clone(), session_id);

    stream_response(StatusCode::OK, body_stream, state.no_sse_header)
}

async fn handle_packet_up(
    mut request: XhttpRequest,
    state: Arc<AppState>,
    session_id: String,
    seq: String,
) -> XhttpResponsePlan {
    let Ok(seq) = seq.parse::<u64>() else {
        return XhttpResponsePlan::empty(StatusCode::INTERNAL_SERVER_ERROR);
    };

    if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) && request
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > state.max_each_post_bytes as u64)
    {
        return XhttpResponsePlan::empty(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let header_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header
    ) {
        match decode_chunked_header_payload(&request.headers, &state.uplink_data_key)
        {
            Ok(payload) => payload,
            Err(_) => return XhttpResponsePlan::empty(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let cookie_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Cookie
    ) {
        match decode_chunked_cookie_payload(&request.headers, &state.uplink_data_key)
        {
            Ok(payload) => payload,
            Err(_) => return XhttpResponsePlan::empty(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let body_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        match collect_request_body(request.body.as_mut(), state.max_each_post_bytes)
            .await
        {
            Ok(payload) => payload,
            Err(CollectBodyError::TooLarge) => {
                return XhttpResponsePlan::empty(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Err(CollectBodyError::Read) => {
                return XhttpResponsePlan::empty(StatusCode::BAD_REQUEST);
            }
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
    if payload.len() > state.max_each_post_bytes {
        return XhttpResponsePlan::empty(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let collected = Bytes::from(payload);

    let session = state.sessions.get_or_create(&session_id);
    if !session.claim_packet_upload() {
        return XhttpResponsePlan::empty(StatusCode::CONFLICT);
    }
    let mut upload_state = session.upload.lock().await;
    match upload_state.packet_queue.push_packet(seq, collected) {
        Ok(()) => {}
        Err(QueueError::TooManyBuffered) => {
            return XhttpResponsePlan::empty(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    while let Some(chunk) = upload_state.packet_queue.pop_ready() {
        if let Err(err) = upload_state.writer.write_all(&chunk).await {
            error!("xhttp packet-up write failed: {}", err);
            state.sessions.remove(&session_id).await;
            return XhttpResponsePlan::empty(StatusCode::BAD_GATEWAY);
        }
    }

    let mut response = XhttpResponsePlan::empty(StatusCode::OK);
    if body_payload_is_empty {
        response.headers.insert(
            header::CACHE_CONTROL,
            hyper::header::HeaderValue::from_static("no-store"),
        );
    }
    response
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CollectBodyError {
    TooLarge,
    Read,
}

async fn collect_request_body(
    body: &mut dyn XhttpRequestBody,
    limit: usize,
) -> Result<Vec<u8>, CollectBodyError> {
    let mut payload = Vec::new();
    loop {
        let chunk = body.next_data().await.map_err(|_| CollectBodyError::Read)?;
        let Some(chunk) = chunk else {
            return Ok(payload);
        };
        let next_len = payload
            .len()
            .checked_add(chunk.len())
            .ok_or(CollectBodyError::TooLarge)?;
        if next_len > limit {
            return Err(CollectBodyError::TooLarge);
        }
        payload.extend_from_slice(&chunk);
    }
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

struct SessionBodyStream {
    inner: ReaderStream<DuplexStream>,
    sessions: SessionStore,
    session_id: Option<String>,
}

impl SessionBodyStream {
    fn new(
        reader: DuplexStream,
        sessions: SessionStore,
        session_id: String,
    ) -> Self {
        Self {
            inner: ReaderStream::new(reader),
            sessions,
            session_id: Some(session_id),
        }
    }

    fn start_cleanup(&mut self) {
        let Some(session_id) = self.session_id.take() else {
            return;
        };
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            sessions.remove(&session_id).await;
        });
    }
}

impl futures::Stream for SessionBodyStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(Some(Err(err))) => {
                error!("xhttp stream-down read failed: {}", err);
                self.start_cleanup();
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                self.start_cleanup();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SessionBodyStream {
    fn drop(&mut self) {
        self.start_cleanup();
    }
}

fn reader_response(
    status: StatusCode,
    reader: DuplexStream,
    no_sse_header: bool,
) -> XhttpResponsePlan {
    stream_response(status, ReaderStream::new(reader), no_sse_header)
}

fn stream_response<S>(
    status: StatusCode,
    body_stream: S,
    no_sse_header: bool,
) -> XhttpResponsePlan
where
    S: Stream<Item = std::io::Result<Bytes>> + Send + 'static,
{
    let mut response = XhttpResponsePlan {
        status,
        headers: HeaderMap::new(),
        body: Some(Box::pin(body_stream)),
    };
    response.headers.insert(
        header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response.headers.insert(
        "x-accel-buffering",
        hyper::header::HeaderValue::from_static("no"),
    );
    if !no_sse_header {
        response.headers.insert(
            header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/event-stream"),
        );
    }
    response
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

    async fn remove(&self, session_id: &str) {
        let session = self.inner.write().unwrap().remove(session_id);
        if let Some(session) = session {
            session.close().await;
        }
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
                store.remove(&session_id).await;
            }
        });
    }
}

struct XhttpSession {
    upload: Mutex<UploadState>,
    downlink_reader: Mutex<Option<DuplexStream>>,
    handler_stream: Mutex<Option<XhttpLogicalStream>>,
    fully_connected: AtomicBool,
    upload_mode: AtomicU8,
    cancel_token: CancellationToken,
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
            upload_mode: AtomicU8::new(UPLOAD_MODE_NONE),
            cancel_token: CancellationToken::new(),
        }
    }

    fn claim_stream_upload(&self) -> bool {
        self.upload_mode
            .compare_exchange(
                UPLOAD_MODE_NONE,
                UPLOAD_MODE_STREAM,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn claim_packet_upload(&self) -> bool {
        loop {
            match self.upload_mode.load(Ordering::Acquire) {
                UPLOAD_MODE_PACKET => return true,
                UPLOAD_MODE_STREAM => return false,
                UPLOAD_MODE_NONE => {
                    if self
                        .upload_mode
                        .compare_exchange(
                            UPLOAD_MODE_NONE,
                            UPLOAD_MODE_PACKET,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }

    async fn take_handler_stream(&self) -> Option<XhttpLogicalStream> {
        self.handler_stream.lock().await.take()
    }

    async fn take_downlink_reader(&self) -> Option<DuplexStream> {
        self.downlink_reader.lock().await.take()
    }

    async fn close(&self) {
        self.cancel_token.cancel();
        drop(self.handler_stream.lock().await.take());
        drop(self.downlink_reader.lock().await.take());
        let mut upload = self.upload.lock().await;
        let _ = upload.writer.shutdown().await;
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
    ready: VecDeque<Bytes>,
    max_buffered_posts: usize,
}

impl PacketQueue {
    fn new(max_buffered_posts: usize) -> Self {
        Self {
            next_seq: 0,
            buffered: BTreeMap::new(),
            ready: VecDeque::new(),
            max_buffered_posts,
        }
    }

    fn push_packet(&mut self, seq: u64, data: Bytes) -> Result<(), QueueError> {
        if seq < self.next_seq || self.buffered.contains_key(&seq) {
            return Ok(());
        }
        if self.buffered.len() >= self.max_buffered_posts {
            return Err(QueueError::TooManyBuffered);
        }

        self.buffered.insert(seq, data);
        while let Some(chunk) = self.buffered.remove(&self.next_seq) {
            self.ready.push_back(chunk);
            self.next_seq += 1;
        }

        Ok(())
    }

    fn pop_ready(&mut self) -> Option<Bytes> {
        self.ready.pop_front()
    }
}

#[derive(Debug)]
enum QueueError {
    TooManyBuffered,
}

fn xray_http_host_matches(request: &str, configured: &str) -> bool {
    let request = request.to_ascii_lowercase();
    let configured = configured.to_ascii_lowercase();
    let request_host = if request.contains(':') {
        split_http_host_port(&request).unwrap_or("")
    } else {
        request.as_str()
    };
    request_host == configured
}

fn split_http_host_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']')?;
        let host = &rest[..closing];
        let port = rest.get(closing + 1..)?.strip_prefix(':')?;
        return (!port.is_empty()).then_some(host);
    }

    let (host, port) = authority.rsplit_once(':')?;
    (!host.contains(':') && !port.is_empty()).then_some(host)
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode_query_component(name)?;
        if name != key {
            return None;
        }
        let value = decode_query_component(value)?;
        (!value.is_empty()).then_some(value)
    })
}

fn decode_query_component(value: &str) -> Option<String> {
    decode_percent_component(value, true)
}

fn decode_uri_path(value: &str) -> Option<String> {
    decode_percent_component(value, false)
}

fn decode_percent_component(value: &str, plus_as_space: bool) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' if plus_as_space => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                decoded.push((hex_value(high)? << 4) | hex_value(low)?);
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

fn query_value_from_url(raw_url: &str, key: &str) -> Option<String> {
    let query = raw_url.split_once('?')?.1.split('#').next();
    query_value(query, key)
}

fn header_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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

const HPACK_ASCII_CODE_LENGTHS: [u8; 128] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10,
    10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13,
    19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5,
    6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
];

fn hpack_huffman_encoded_len(value: &str) -> usize {
    let bits = value.bytes().fold(0usize, |sum, byte| {
        sum + HPACK_ASCII_CODE_LENGTHS
            .get(byte as usize)
            .copied()
            .unwrap_or(30) as usize
    });
    bits.div_ceil(8)
}

fn generate_padding(method: XhttpPaddingMethod, target_length: usize) -> String {
    if target_length == 0 {
        return String::new();
    }
    if method == XhttpPaddingMethod::RepeatX {
        return "X".repeat(target_length);
    }

    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let initial_length = (target_length * 5).div_ceil(4).max(1);
    let mut value = String::with_capacity(initial_length + 8);
    let mut rng = rand::rng();
    for _ in 0..initial_length {
        value.push(BASE62[rng.random_range(0..BASE62.len())] as char);
    }

    let mut adjust = 'X';
    for _ in 0..150 {
        let encoded_length = hpack_huffman_encoded_len(&value);
        if encoded_length.abs_diff(target_length) <= 2 {
            return value;
        }
        if encoded_length < target_length {
            value.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else if value.len() > 1 {
            value.pop();
        } else {
            break;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn proxy_protocol_replaces_xhttp_peer_before_http() {
        let (mut client, mut server) = duplex(1024);
        let request = b"GET /xhttp/ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        client
            .write_all(
                b"PROXY TCP4 203.0.113.8 192.0.2.1 5678 443\r\nGET /xhttp/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
            )
            .await
            .unwrap();
        let peer_addr = resolve_xhttp_peer_addr(
            &mut server,
            "127.0.0.1:12345".parse().unwrap(),
            true,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(peer_addr, "203.0.113.8:5678".parse().unwrap());
        let mut remaining = vec![0u8; request.len()];
        server.read_exact(&mut remaining).await.unwrap();
        assert_eq!(remaining, request);
    }

    #[test]
    fn hpack_huffman_length_matches_known_ascii_codes() {
        assert_eq!(hpack_huffman_encoded_len("0"), 1);
        assert_eq!(hpack_huffman_encoded_len("X"), 1);
        assert_eq!(hpack_huffman_encoded_len("XX"), 2);
        assert_eq!(hpack_huffman_encoded_len("abc"), 2);
    }

    #[test]
    fn tokenish_padding_tracks_target_huffman_length() {
        for target in [1, 64, 100, 128, 1000] {
            let padding = generate_padding(XhttpPaddingMethod::Tokenish, target);
            assert!(!padding.is_empty());
            assert!(
                padding.bytes().all(|byte| byte.is_ascii_alphanumeric()),
                "tokenish padding must stay base62"
            );
            assert!(
                hpack_huffman_encoded_len(&padding).abs_diff(target) <= 2,
                "target={target}, actual={}, raw_len={}",
                hpack_huffman_encoded_len(&padding),
                padding.len()
            );
        }
    }

    #[test]
    fn query_value_from_url_ignores_fragments() {
        assert_eq!(
            query_value_from_url("https://example.test/p?pad=XXX#fragment", "pad"),
            Some("XXX".into())
        );
        assert_eq!(query_value_from_url("/p?other=1", "pad"), None);
    }

    #[test]
    fn query_values_follow_go_url_decoding_rules() {
        assert_eq!(
            query_value(Some("x_session=a%2Fb+c"), "x_session"),
            Some("a/b c".into())
        );
        assert_eq!(
            query_value(Some("x%5Fsession=value"), "x_session"),
            Some("value".into())
        );
        assert_eq!(query_value(Some("x_session=%ZZ"), "x_session"), None);
    }

    #[test]
    fn host_validation_matches_xray_split_host_port_rules() {
        assert!(xray_http_host_matches("Example.COM", "example.com"));
        assert!(xray_http_host_matches("example.com:443", "example.com"));
        assert!(xray_http_host_matches("[::1]:443", "::1"));
        assert!(xray_http_host_matches(
            "[fe80::1%25eth0]:8443",
            "fe80::1%25eth0"
        ));
        assert!(!xray_http_host_matches("example.net:443", "example.com"));
        assert!(!xray_http_host_matches("::1", "::1"));
        assert!(!xray_http_host_matches("[::1]", "::1"));
    }

    #[test]
    fn paths_follow_xray_decoding_and_prefix_rules() {
        assert_eq!(
            decode_uri_path("/xhttp/a%2Fb+c"),
            Some("/xhttp/a/b+c".into())
        );
        assert!(matches_base_path("/xhttp/session", "/xhttp/"));
        assert!(!matches_base_path("/xhttp", "/xhttp/"));
        assert!(matches_base_path("/xhttp-other", "/xhttp"));
    }

    #[test]
    fn session_uplink_mode_is_permanently_locked() {
        let packet_session = XhttpSession::new(30);
        assert!(packet_session.claim_packet_upload());
        assert!(packet_session.claim_packet_upload());
        assert!(!packet_session.claim_stream_upload());

        let stream_session = XhttpSession::new(30);
        assert!(stream_session.claim_stream_upload());
        assert!(!stream_session.claim_stream_upload());
        assert!(!stream_session.claim_packet_upload());
    }

    #[test]
    fn packet_queue_reorders_and_keeps_first_duplicate() {
        let mut queue = PacketQueue::new(4);
        queue
            .push_packet(1, Bytes::from_static(b"one-first"))
            .unwrap();
        queue
            .push_packet(1, Bytes::from_static(b"one-retry"))
            .unwrap();
        assert!(queue.pop_ready().is_none());

        queue.push_packet(0, Bytes::from_static(b"zero")).unwrap();
        assert_eq!(queue.pop_ready().unwrap(), Bytes::from_static(b"zero"));
        assert_eq!(queue.pop_ready().unwrap(), Bytes::from_static(b"one-first"));
        assert!(queue.pop_ready().is_none());
    }

    #[test]
    fn packet_queue_bounds_missing_sequence_buffer() {
        let mut queue = PacketQueue::new(1);
        queue.push_packet(2, Bytes::from_static(b"two")).unwrap();
        assert!(matches!(
            queue.push_packet(3, Bytes::from_static(b"three")),
            Err(QueueError::TooManyBuffered)
        ));
    }

    #[tokio::test]
    async fn incomplete_session_ttl_cancels_and_closes_pipes() {
        let store = SessionStore::new(Duration::from_millis(10), 30);
        let session = store.get_or_create("ttl-session");
        let cancellation = session.cancel_token.clone();

        tokio::time::sleep(Duration::from_millis(30)).await;

        assert!(cancellation.is_cancelled());
        assert!(!store.inner.read().unwrap().contains_key("ttl-session"));
        assert!(session.handler_stream.lock().await.is_none());
        assert!(session.downlink_reader.lock().await.is_none());
    }

    #[tokio::test]
    async fn fully_connected_session_survives_initial_ttl() {
        let store = SessionStore::new(Duration::from_millis(10), 30);
        let session = store.get_or_create("connected-session");
        session.fully_connected.store(true, Ordering::Release);

        tokio::time::sleep(Duration::from_millis(30)).await;

        assert!(
            store
                .inner
                .read()
                .unwrap()
                .contains_key("connected-session")
        );
        assert!(!session.cancel_token.is_cancelled());
        store.remove("connected-session").await;
        assert!(session.cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn dropping_stream_down_body_removes_session() {
        let store = SessionStore::new(Duration::from_secs(30), 30);
        let session = store.get_or_create("drop-session");
        let reader = session
            .take_downlink_reader()
            .await
            .expect("session downlink reader");
        let stream =
            SessionBodyStream::new(reader, store.clone(), "drop-session".into());

        drop(stream);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !store.inner.read().unwrap().contains_key("drop-session"),
            "dropping the HTTP response body must reap the XHTTP session"
        );
    }

    #[tokio::test]
    async fn normal_stream_down_eof_removes_session() {
        let store = SessionStore::new(Duration::from_secs(30), 30);
        let session = store.get_or_create("eof-session");
        let reader = session
            .take_downlink_reader()
            .await
            .expect("session downlink reader");
        let mut stream =
            SessionBodyStream::new(reader, store.clone(), "eof-session".into());
        drop(session.take_handler_stream().await);

        assert!(futures::StreamExt::next(&mut stream).await.is_none());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !store.inner.read().unwrap().contains_key("eof-session"),
            "normal response EOF must reap the XHTTP session"
        );
    }
}
