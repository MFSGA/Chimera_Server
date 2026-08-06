#[cfg(feature = "tls")]
use std::fs;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    client::conn::http2,
    header,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    task::JoinHandle,
    time::timeout,
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::{
        def::OutboundGrpcSettings,
        server_config::{GrpcServerConfig, ServerConfig, ServerProxyConfig},
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
    config::server_config::TlsServerConfig, util::rustls_util::create_server_config,
};

use super::process_stream;

const GRPC_PIPE_CAPACITY: usize = 64 * 1024;
const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;
type ClientRequestBody = UnsyncBoxBody<Bytes, io::Error>;

#[derive(Debug, Clone)]
pub(crate) struct GrpcClientConfig {
    authority: String,
    service_path: String,
    user_agent: Option<header::HeaderValue>,
}

impl GrpcClientConfig {
    pub(crate) fn compile(
        settings: Option<&OutboundGrpcSettings>,
        fallback_authority: &str,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        let settings = settings.cloned().unwrap_or_default();
        if settings.multi_mode {
            return Err(format!(
                "outbound {outbound_tag} gRPC multiMode is not supported yet"
            ));
        }
        if settings.idle_timeout != 0
            || settings.health_check_timeout != 0
            || settings.permit_without_stream
        {
            return Err(format!(
                "outbound {outbound_tag} gRPC keepalive settings are not supported yet"
            ));
        }
        if settings.initial_windows_size != 0 {
            return Err(format!(
                "outbound {outbound_tag} gRPC initialWindowsSize is not supported yet"
            ));
        }

        let service_name = settings
            .service_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("GunService");
        if service_name.starts_with('/') {
            return Err(format!(
                "outbound {outbound_tag} gRPC custom method paths are not supported yet"
            ));
        }
        let service_name = percent_encode_path_segment(service_name);
        let service_path = format!("/{service_name}/Tun");

        let authority = settings
            .authority
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback_authority)
            .to_string();
        authority
            .parse::<http::uri::Authority>()
            .map_err(|error| {
                format!(
                    "outbound {outbound_tag} has invalid gRPC authority {authority}: {error}"
                )
            })?;

        let user_agent = settings
            .user_agent
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(header::HeaderValue::from_str)
            .transpose()
            .map_err(|error| {
                format!(
                    "outbound {outbound_tag} has invalid gRPC userAgent: {error}"
                )
            })?;

        Ok(Self {
            authority,
            service_path,
            user_agent,
        })
    }

    pub(crate) async fn connect(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let (logical_stream, transport_stream) = duplex(GRPC_PIPE_CAPACITY);
        let (upload_reader, download_writer) = tokio::io::split(transport_stream);
        let upload_stream =
            ReaderStream::new(upload_reader).filter_map(|result| async move {
                match result {
                    Ok(data) if !data.is_empty() => {
                        Some(Ok(Frame::data(encode_grpc_hunk(&data))))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                }
            });
        let body: ClientRequestBody =
            BodyExt::boxed_unsync(StreamBody::new(upload_stream));

        let (mut sender, connection) = http2::handshake::<_, _, ClientRequestBody>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("outbound gRPC HTTP/2 handshake failed: {error}"),
            )
        })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                debug!("outbound gRPC HTTP/2 connection ended: {error}");
            }
        });

        let uri = format!("http://{}{}", self.authority, self.service_path);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .header("grpc-encoding", "identity")
            .header("grpc-accept-encoding", "identity");
        if let Some(user_agent) = &self.user_agent {
            request = request.header(header::USER_AGENT, user_agent);
        }
        let request = request.body(body).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to build outbound gRPC request: {error}"),
            )
        })?;
        tokio::spawn(async move {
            let mut download_writer = download_writer;
            let result = async {
                let response =
                    sender.send_request(request).await.map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("outbound gRPC request failed: {error}"),
                        )
                    })?;
                validate_grpc_response(&response)?;
                let mut body = response.into_body();
                decode_response_body(&mut body, &mut download_writer).await
            }
            .await;
            if let Err(error) = result {
                debug!("outbound gRPC response failed: {error}");
                let _ = download_writer.shutdown().await;
            }
        });

        Ok(Box::new(GrpcLogicalStream(logical_stream)))
    }
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn validate_grpc_response(response: &Response<Incoming>) -> io::Result<()> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("outbound gRPC returned HTTP status {}", response.status()),
        ));
    }
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound gRPC response has invalid content-type",
        ));
    }
    validate_grpc_status(response.headers())
}

fn validate_grpc_status(headers: &hyper::HeaderMap) -> io::Result<()> {
    let Some(status) = headers.get("grpc-status") else {
        return Ok(());
    };
    if status.as_bytes() == b"0" {
        return Ok(());
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown gRPC error");
    Err(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!(
            "outbound gRPC status {}: {message}",
            status.to_str().unwrap_or("invalid")
        ),
    ))
}

async fn decode_response_body(
    body: &mut Incoming,
    writer: &mut tokio::io::WriteHalf<DuplexStream>,
) -> io::Result<()> {
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })?;
        if let Some(data) = frame.data_ref() {
            buffered.extend_from_slice(data);
            while let Some(payload) = decode_grpc_hunk(&mut buffered)? {
                writer.write_all(&payload).await?;
            }
        }
        if let Some(trailers) = frame.trailers_ref() {
            validate_grpc_status(trailers)?;
        }
    }
    if !buffered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated outbound gRPC message",
        ));
    }
    writer.shutdown().await
}

#[derive(Debug, Clone)]
enum GrpcSecurity {
    Plain,
    #[cfg(feature = "tls")]
    Tls(Arc<rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
}

struct GrpcListenerConfig {
    grpc: GrpcServerConfig,
    inner: ServerProxyConfig,
    security: GrpcSecurity,
    accept_proxy_protocol: bool,
    tcp_keepalive: Option<(i32, i32)>,
    tcp_user_timeout_ms: Option<i32>,
    tcp_congestion: Option<String>,
    tcp_window_clamp: Option<i32>,
    tcp_max_seg: Option<i32>,
    ipv6_only: bool,
    tcp_fast_open: Option<i32>,
    bind_interface: Option<String>,
    bind_mark: Option<i32>,
}

pub(super) async fn start_grpc_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        ..
    } = config;
    let GrpcListenerConfig {
        grpc: grpc_config,
        inner: inner_protocol,
        security,
        accept_proxy_protocol,
        tcp_keepalive,
        tcp_user_timeout_ms,
        tcp_congestion,
        tcp_window_clamp,
        tcp_max_seg,
        ipv6_only,
        tcp_fast_open,
        bind_interface,
        bind_mark,
    } = parse_listener_protocol(protocol)?;
    let mut rules_stack = Vec::new();
    let server_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(
        create_tcp_server_handler(inner_protocol, &tag, &mut rules_stack)?,
    );
    let resolver = runtime.resolver();
    let listen_addr = match bind_location {
        BindLocation::Address(location) => location.to_socket_addr()?,
    };
    let socket =
        crate::util::socket::new_tcp_socket(bind_interface, listen_addr.is_ipv6())?;
    if let Some(value) = bind_mark {
        crate::util::socket::configure_socket_mark(socket.as_raw_fd(), value)?;
    }
    if let Some(value) = tcp_fast_open {
        crate::handler::tcp_fast_open::configure_listener(&socket, value)?;
    }
    if ipv6_only {
        crate::handler::ipv6_only::configure_listener(&socket)?;
    }
    if let Some(value) = tcp_max_seg {
        crate::handler::tcp_max_seg::configure_listener(&socket, value)?;
    }
    socket.bind(listen_addr)?;
    let listener = socket.listen(1024)?;
    info!(
        service = %grpc_config.service_name,
        address = %listen_addr,
        "Starting gRPC transport server"
    );
    let service_path = format!("/{}/Tun", grpc_config.service_name);

    let handle = tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    error!("gRPC transport accept failed: {error}");
                    continue;
                }
            };
            let service_path = service_path.clone();
            let server_handler = server_handler.clone();
            let resolver = resolver.clone();
            let runtime = runtime.clone();
            let security = security.clone();
            let tcp_congestion = tcp_congestion.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                if let Err(error) =
                    configure_grpc_tcp_congestion(&stream, tcp_congestion.as_deref())
                {
                    debug!("gRPC TCP_CONGESTION setup failed: {error}");
                    return;
                }
                if let Err(error) =
                    configure_grpc_tcp_window_clamp(&stream, tcp_window_clamp)
                {
                    debug!("gRPC TCP_WINDOW_CLAMP setup failed: {error}");
                    return;
                }
                if let Err(error) =
                    configure_grpc_tcp_user_timeout(&stream, tcp_user_timeout_ms)
                {
                    debug!("gRPC TCP_USER_TIMEOUT setup failed: {error}");
                    return;
                }
                if let Err(error) =
                    configure_grpc_tcp_keepalive(&stream, tcp_keepalive)
                {
                    debug!("gRPC TCP keepalive setup failed: {error}");
                    return;
                }
                let peer_addr = match resolve_grpc_peer_addr(
                    &mut stream,
                    peer_addr,
                    accept_proxy_protocol,
                    runtime.policy_handshake_timeout(0),
                )
                .await
                {
                    Ok(peer_addr) => peer_addr,
                    Err(error) => {
                        debug!("gRPC PROXY protocol handshake failed: {error}");
                        return;
                    }
                };
                match security {
                    GrpcSecurity::Plain => {
                        serve_grpc_connection(
                            stream,
                            service_path,
                            server_handler,
                            resolver,
                            runtime,
                            peer_addr,
                        )
                        .await;
                    }
                    #[cfg(feature = "tls")]
                    GrpcSecurity::Tls(server_config) => {
                        let acceptor = TlsAcceptor::from(server_config);
                        match acceptor.accept(stream).await {
                            Ok(stream) => {
                                serve_grpc_connection(
                                    stream,
                                    service_path,
                                    server_handler,
                                    resolver,
                                    runtime,
                                    peer_addr,
                                )
                                .await;
                            }
                            Err(error) => {
                                debug!("gRPC TLS handshake failed: {error}");
                            }
                        }
                    }
                    #[cfg(feature = "reality")]
                    GrpcSecurity::Reality(reality_config) => {
                        match accept_reality_stream(
                            Box::new(stream),
                            &reality_config,
                            resolver.clone(),
                        )
                        .await
                        {
                            Ok(stream) => {
                                serve_grpc_connection(
                                    stream,
                                    service_path,
                                    server_handler,
                                    resolver,
                                    runtime,
                                    peer_addr,
                                )
                                .await;
                            }
                            Err(error) => {
                                debug!("gRPC REALITY handshake failed: {error}");
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(vec![handle])
}

fn configure_grpc_tcp_congestion(
    stream: &tokio::net::TcpStream,
    algorithm: Option<&str>,
) -> io::Result<()> {
    let Some(algorithm) = algorithm else {
        return Ok(());
    };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_tcp_congestion(stream.as_raw_fd(), algorithm)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (stream, algorithm);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcpCongestion is currently supported only on Linux and Android",
        ))
    }
}

fn configure_grpc_tcp_window_clamp(
    stream: &tokio::net::TcpStream,
    value: Option<i32>,
) -> io::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_tcp_window_clamp(stream.as_raw_fd(), value)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (stream, value);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcpWindowClamp is currently supported only on Linux and Android",
        ))
    }
}

fn configure_grpc_tcp_user_timeout(
    stream: &tokio::net::TcpStream,
    timeout_ms: Option<i32>,
) -> io::Result<()> {
    let Some(timeout_ms) = timeout_ms else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        crate::util::socket::configure_tcp_user_timeout(
            stream.as_raw_fd(),
            timeout_ms,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, timeout_ms);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcpUserTimeout is currently supported only on Linux",
        ))
    }
}

fn configure_grpc_tcp_keepalive(
    stream: &tokio::net::TcpStream,
    keepalive: Option<(i32, i32)>,
) -> io::Result<()> {
    let Some((idle_secs, interval_secs)) = keepalive else {
        return Ok(());
    };
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_tcp_keepalive(
            stream.as_raw_fd(),
            idle_secs,
            interval_secs,
        )
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (stream, idle_secs, interval_secs);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP keepalive sockopt is currently supported only on Linux and Android",
        ))
    }
}

async fn resolve_grpc_peer_addr<S>(
    stream: &mut S,
    socket_peer_addr: std::net::SocketAddr,
    accept_proxy_protocol: bool,
    handshake_timeout: std::time::Duration,
) -> io::Result<std::net::SocketAddr>
where
    S: AsyncRead + Unpin,
{
    if !accept_proxy_protocol {
        return Ok(socket_peer_addr);
    }
    match timeout(handshake_timeout, read_proxy_header(stream)).await {
        Ok(result) => Ok(result?.unwrap_or(socket_peer_addr)),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("PROXY protocol handshake timed out: {error}"),
        )),
    }
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> io::Result<GrpcListenerConfig> {
    match protocol {
        ServerProxyConfig::BindMark { value, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.bind_mark = Some(value);
            Ok(config)
        }
        ServerProxyConfig::BindInterface { name, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.bind_interface = Some(name);
            Ok(config)
        }
        ServerProxyConfig::TcpFastOpen { value, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_fast_open = Some(value);
            Ok(config)
        }
        ServerProxyConfig::Ipv6Only { inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.ipv6_only = true;
            Ok(config)
        }
        ServerProxyConfig::TcpMaxSeg { value, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_max_seg = Some(value);
            Ok(config)
        }
        ServerProxyConfig::TcpCongestion { algorithm, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_congestion = Some(algorithm);
            Ok(config)
        }
        ServerProxyConfig::TcpWindowClamp { value, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_window_clamp = Some(value);
            Ok(config)
        }
        ServerProxyConfig::TcpUserTimeout { timeout_ms, inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_user_timeout_ms = Some(timeout_ms);
            Ok(config)
        }
        ServerProxyConfig::TcpKeepAlive {
            idle_secs,
            interval_secs,
            inner,
        } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.tcp_keepalive = Some((idle_secs, interval_secs));
            Ok(config)
        }
        ServerProxyConfig::ProxyProtocol { inner } => {
            let mut config = parse_listener_protocol(*inner)?;
            config.accept_proxy_protocol = true;
            Ok(config)
        }
        ServerProxyConfig::Grpc(config) => {
            let inner = (*config.inner).clone();
            Ok(GrpcListenerConfig {
                grpc: config,
                inner,
                security: GrpcSecurity::Plain,
                accept_proxy_protocol: false,
                tcp_keepalive: None,
                tcp_user_timeout_ms: None,
                tcp_congestion: None,
                tcp_window_clamp: None,
                tcp_max_seg: None,
                ipv6_only: false,
                tcp_fast_open: None,
                bind_interface: None,
                bind_mark: None,
            })
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            let TlsServerConfig {
                certificates,
                mut alpn_protocols,
                enable_session_resumption: _,
                reject_unknown_sni: _,
                min_version: _,
                max_version: _,
                server_name: _,
                inner,
            } = tls_config;
            let ServerProxyConfig::Grpc(config) = *inner else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS gRPC listener requires Grpc as the inner protocol",
                ));
            };
            if !alpn_protocols.iter().any(|value| value == "h2") {
                alpn_protocols.push("h2".to_string());
            }
            let certificate = certificates
                .into_iter()
                .find(|certificate| {
                    certificate.key_path.is_some() || certificate.key_pem.is_some()
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "gRPC TLS certificate and private key are required",
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "gRPC TLS private key is required",
                    ));
                }
            };
            let server_config =
                create_server_config(&cert_bytes, &key_bytes, &alpn_protocols, &[])?;
            let inner = (*config.inner).clone();
            Ok(GrpcListenerConfig {
                grpc: config,
                inner,
                security: GrpcSecurity::Tls(Arc::new(server_config)),
                accept_proxy_protocol: false,
                tcp_keepalive: None,
                tcp_user_timeout_ms: None,
                tcp_congestion: None,
                tcp_window_clamp: None,
                tcp_max_seg: None,
                ipv6_only: false,
                tcp_fast_open: None,
                bind_interface: None,
                bind_mark: None,
            })
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            let ServerProxyConfig::Grpc(config) = reality_config.inner.as_ref()
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY gRPC listener requires Grpc as the inner protocol",
                ));
            };
            let config = config.clone();
            let inner = (*config.inner).clone();
            Ok(GrpcListenerConfig {
                grpc: config,
                inner,
                security: GrpcSecurity::Reality(reality_config),
                accept_proxy_protocol: false,
                tcp_keepalive: None,
                tcp_user_timeout_ms: None,
                tcp_congestion: None,
                tcp_window_clamp: None,
                tcp_max_seg: None,
                ipv6_only: false,
                tcp_fast_open: None,
                bind_interface: None,
                bind_mark: None,
            })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid protocol for gRPC transport server: {other}"),
        )),
    }
}

async fn serve_grpc_connection<IO>(
    io: IO,
    service_path: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = auto::Builder::new(TokioExecutor::new());
    let service = service_fn(move |request| {
        handle_request(
            request,
            service_path.clone(),
            server_handler.clone(),
            resolver.clone(),
            runtime.clone(),
            peer_addr,
        )
    });
    if let Err(error) = builder.serve_connection(TokioIo::new(io), service).await {
        debug!("gRPC transport connection {peer_addr} ended: {error}");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    service_path: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    if request.method() != Method::POST
        || request.uri().path() != service_path
        || !request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc"))
    {
        return Ok(grpc_status_response(12, "unimplemented gRPC method"));
    }

    let (handler_stream, transport_stream) = duplex(GRPC_PIPE_CAPACITY);
    let (transport_read, transport_write) = tokio::io::split(transport_stream);
    let mut body = request.into_body();
    tokio::spawn(async move {
        if let Err(error) = decode_request_body(&mut body, transport_write).await {
            debug!("gRPC upload decode failed: {error}");
        }
    });
    tokio::spawn(async move {
        if let Err(error) = process_stream(
            GrpcLogicalStream(handler_stream),
            server_handler,
            resolver,
            peer_addr,
            runtime,
        )
        .await
        {
            debug!("gRPC logical stream {peer_addr} ended: {error}");
        }
    });

    Ok(grpc_stream_response(transport_read))
}

async fn decode_request_body(
    body: &mut Incoming,
    mut writer: tokio::io::WriteHalf<DuplexStream>,
) -> io::Result<()> {
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })?;
        if let Some(data) = frame.data_ref() {
            buffered.extend_from_slice(data);
            while let Some(payload) = decode_grpc_hunk(&mut buffered)? {
                writer.write_all(&payload).await?;
            }
        }
    }
    if !buffered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated gRPC message",
        ));
    }
    writer.shutdown().await
}

fn grpc_stream_response(
    reader: tokio::io::ReadHalf<DuplexStream>,
) -> Response<ResponseBody> {
    let data_stream = ReaderStream::new(reader).filter_map(|result| async move {
        match result {
            Ok(data) if !data.is_empty() => {
                Some(Ok(Frame::data(encode_grpc_hunk(&data))))
            }
            Ok(_) => None,
            Err(error) => {
                debug!("gRPC response read failed: {error}");
                None
            }
        }
    });
    let trailers = futures::stream::once(async {
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("grpc-status", header::HeaderValue::from_static("0"));
        Ok(Frame::trailers(trailers))
    });
    let body = StreamBody::new(data_stream.chain(trailers));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-encoding", "identity")
        .header("grpc-accept-encoding", "identity")
        .body(BodyExt::boxed_unsync(body))
        .unwrap_or_else(|_| grpc_status_response(13, "internal response error"))
}

fn grpc_status_response(status: u8, message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", status.to_string())
        .header("grpc-message", message)
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

fn decode_grpc_hunk(buffer: &mut BytesMut) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC Hunk messages are not supported",
        ));
    }
    let message_len =
        u32::from_be_bytes(buffer[1..5].try_into().expect("gRPC length")) as usize;
    if message_len > MAX_GRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC Hunk message exceeds 4 MiB",
        ));
    }
    if buffer.len() < 5 + message_len {
        return Ok(None);
    }
    buffer.advance(5);
    let message = buffer.split_to(message_len);
    decode_hunk_protobuf(&message).map(Some)
}

fn decode_hunk_protobuf(message: &[u8]) -> io::Result<Vec<u8>> {
    if message.is_empty() {
        return Ok(Vec::new());
    }
    if message[0] != 0x0a {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC Hunk protobuf is missing field 1",
        ));
    }
    let (length, varint_len) = decode_varint(&message[1..])?;
    let start = 1 + varint_len;
    let end = start.checked_add(length).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Hunk length overflow")
    })?;
    if end > message.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated Hunk protobuf payload",
        ));
    }
    Ok(message[start..end].to_vec())
}

fn encode_grpc_hunk(data: &[u8]) -> Bytes {
    let mut protobuf = Vec::with_capacity(data.len() + 6);
    protobuf.push(0x0a);
    encode_varint(data.len(), &mut protobuf);
    protobuf.extend_from_slice(data);
    let mut frame = Vec::with_capacity(protobuf.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    Bytes::from(frame)
}

fn decode_varint(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in data.iter().copied().enumerate().take(10) {
        value |= ((byte & 0x7f) as usize) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid protobuf varint",
    ))
}

fn encode_varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

struct GrpcLogicalStream(DuplexStream);

impl AsyncRead for GrpcLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for GrpcLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncPing for GrpcLogicalStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for GrpcLogicalStream {}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hyper::server::conn::http2;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn client_config_uses_xray_defaults_and_rejects_unsupported_modes() {
        let config = GrpcClientConfig::compile(None, "proxy.example", "proxy")
            .expect("default gRPC settings should compile");
        assert_eq!(config.authority, "proxy.example");
        assert_eq!(config.service_path, "/GunService/Tun");

        let settings = OutboundGrpcSettings {
            multi_mode: true,
            ..OutboundGrpcSettings::default()
        };
        assert!(
            GrpcClientConfig::compile(Some(&settings), "proxy.example", "proxy")
                .unwrap_err()
                .contains("multiMode")
        );

        let settings = OutboundGrpcSettings {
            service_name: Some("/custom/Tun".into()),
            ..OutboundGrpcSettings::default()
        };
        assert!(
            GrpcClientConfig::compile(Some(&settings), "proxy.example", "proxy")
                .unwrap_err()
                .contains("custom method paths")
        );
    }

    #[tokio::test]
    async fn client_logical_stream_round_trips_through_http2_hunks() {
        let (client_io, server_io) = duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let service = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), "/echo-service/Tun");
                assert_eq!(
                    request
                        .headers()
                        .get(header::USER_AGENT)
                        .and_then(|value| value.to_str().ok()),
                    Some("chimera-test")
                );
                let (response_stream, echo_stream) = duplex(GRPC_PIPE_CAPACITY);
                let (reader, _) = tokio::io::split(response_stream);
                let (_, writer) = tokio::io::split(echo_stream);
                let mut body = request.into_body();
                tokio::spawn(async move {
                    decode_request_body(&mut body, writer).await.unwrap();
                });
                Ok::<_, Infallible>(grpc_stream_response(reader))
            });
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service)
                .await
                .unwrap();
        });

        let settings = OutboundGrpcSettings {
            service_name: Some("echo-service".into()),
            user_agent: Some("chimera-test".into()),
            ..OutboundGrpcSettings::default()
        };
        let config =
            GrpcClientConfig::compile(Some(&settings), "proxy.example", "proxy")
                .unwrap();
        let mut stream = config
            .connect(Box::new(GrpcLogicalStream(client_io)))
            .await
            .expect("gRPC client should connect");
        let payload = b"gRPC logical payload";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = vec![0u8; payload.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_protocol_replaces_grpc_peer_before_http2() {
        let (mut client, mut server) = duplex(1024);
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        client
            .write_all(
                b"PROXY TCP4 203.0.113.7 192.0.2.1 4567 443\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            )
            .await
            .unwrap();
        let socket_peer = "127.0.0.1:12345".parse().unwrap();
        let peer_addr = resolve_grpc_peer_addr(
            &mut server,
            socket_peer,
            true,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(peer_addr, "203.0.113.7:4567".parse().unwrap());
        let mut remaining = vec![0u8; preface.len()];
        server.read_exact(&mut remaining).await.unwrap();
        assert_eq!(remaining, preface);
    }

    #[test]
    fn hunk_round_trip_handles_large_payload() {
        let payload = (0..70_000).map(|value| value as u8).collect::<Vec<_>>();
        let encoded = encode_grpc_hunk(&payload);
        let mut buffer = BytesMut::from(encoded.as_ref());
        let decoded = decode_grpc_hunk(&mut buffer)
            .expect("decode Hunk")
            .expect("complete Hunk");
        assert_eq!(decoded, payload);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_decoder_waits_for_complete_frame() {
        let encoded = encode_grpc_hunk(b"hello");
        let mut buffer = BytesMut::from(&encoded[..4]);
        assert!(decode_grpc_hunk(&mut buffer).unwrap().is_none());
    }
}
