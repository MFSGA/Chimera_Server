use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    task::JoinHandle,
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{GrpcServerConfig, ServerConfig, ServerProxyConfig},
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

const GRPC_PIPE_CAPACITY: usize = 64 * 1024;
const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Debug, Clone, Copy)]
struct GrpcKeepalive {
    idle_timeout: u32,
    health_check_timeout: u32,
}

#[derive(Debug)]
enum GrpcSecurity {
    Plain,
    #[cfg(feature = "tls")]
    Tls(Arc<rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
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
    let (grpc_config, inner_protocol, security) = parse_listener_protocol(protocol)?;
    let mut rules_stack = Vec::new();
    let server_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(
        create_tcp_server_handler(inner_protocol, &tag, &mut rules_stack)?,
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let listen_addr = match bind_location {
        BindLocation::Address(location) => location.to_socket_addr()?,
    };
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(
        service = %grpc_config.service_name,
        multi_mode = grpc_config.multi_mode,
        address = %listen_addr,
        "Starting gRPC transport server"
    );
    let (tun_service_path, tun_multi_service_path) =
        grpc_service_paths(&grpc_config.service_name);

    let handle = tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    error!("gRPC transport accept failed: {error}");
                    continue;
                }
            };
            let tun_service_path = tun_service_path.clone();
            let tun_multi_service_path = tun_multi_service_path.clone();
            let keepalive = GrpcKeepalive {
                idle_timeout: grpc_config.idle_timeout,
                health_check_timeout: grpc_config.health_check_timeout,
            };
            let server_handler = server_handler.clone();
            let resolver = resolver.clone();
            let runtime = runtime.clone();
            match &security {
                GrpcSecurity::Plain => {
                    tokio::spawn(serve_grpc_connection(
                        stream,
                        (tun_service_path, tun_multi_service_path),
                        keepalive,
                        server_handler,
                        resolver,
                        runtime,
                        peer_addr,
                    ));
                }
                #[cfg(feature = "tls")]
                GrpcSecurity::Tls(server_config) => {
                    let acceptor = TlsAcceptor::from(server_config.clone());
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(stream) => {
                                serve_grpc_connection(
                                    stream,
                                    (tun_service_path, tun_multi_service_path),
                                    keepalive,
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
                    });
                }
                #[cfg(feature = "reality")]
                GrpcSecurity::Reality(reality_config) => {
                    let reality_config = reality_config.clone();
                    tokio::spawn(async move {
                        match accept_reality_stream(
                            Box::new(stream),
                            &reality_config,
                        )
                        .await
                        {
                            Ok(stream) => {
                                serve_grpc_connection(
                                    stream,
                                    (tun_service_path, tun_multi_service_path),
                                    keepalive,
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
                    });
                }
            }
        }
    });
    Ok(vec![handle])
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> io::Result<(GrpcServerConfig, ServerProxyConfig, GrpcSecurity)> {
    match protocol {
        ServerProxyConfig::Grpc(config) => {
            let inner = (*config.inner).clone();
            Ok((config, inner, GrpcSecurity::Plain))
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            let TlsServerConfig {
                certificates,
                mut alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
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
            let server_config = build_server_config(
                &certificates,
                &alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version.as_deref(),
                max_version.as_deref(),
            )?;
            let inner = (*config.inner).clone();
            Ok((config, inner, GrpcSecurity::Tls(Arc::new(server_config))))
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
            Ok((config, inner, GrpcSecurity::Reality(reality_config)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid protocol for gRPC transport server: {other}"),
        )),
    }
}

fn grpc_service_paths(service_name: &str) -> (String, String) {
    let (service, tun, tun_multi) = grpc_service_parts(service_name);
    (
        format!("/{service}/{tun}"),
        format!("/{service}/{tun_multi}"),
    )
}

fn grpc_service_parts(service_name: &str) -> (String, String, String) {
    if !service_name.starts_with('/') {
        return (
            grpc_path_escape(service_name),
            "Tun".to_string(),
            "TunMulti".to_string(),
        );
    }

    let last_slash = service_name.rfind('/').unwrap_or(0);
    let service = if last_slash <= 1 {
        String::new()
    } else {
        service_name[1..last_slash]
            .split('/')
            .map(grpc_path_escape)
            .collect::<Vec<_>>()
            .join("/")
    };
    let ending = &service_name[last_slash + 1..];
    let mut stream_names = ending.split('|');
    let tun = grpc_path_escape(stream_names.next().unwrap_or_default());
    let tun_multi = grpc_path_escape(stream_names.next().unwrap_or(ending));
    (service, tun, tun_multi)
}

fn grpc_path_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            write!(&mut escaped, "%{byte:02X}")
                .expect("writing to String cannot fail");
        }
    }
    escaped
}

async fn serve_grpc_connection<IO>(
    io: IO,
    service_paths: (String, String),
    keepalive: GrpcKeepalive,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    if keepalive.idle_timeout > 0 || keepalive.health_check_timeout > 0 {
        let mut http2 = builder.http2();
        http2.timer(TokioTimer::new());
        http2.keep_alive_interval(Duration::from_secs(
            if keepalive.idle_timeout > 0 {
                u64::from(keepalive.idle_timeout)
            } else {
                2 * 60 * 60
            },
        ));
        http2.keep_alive_timeout(Duration::from_secs(
            if keepalive.health_check_timeout > 0 {
                u64::from(keepalive.health_check_timeout)
            } else {
                20
            },
        ));
    }
    let (tun_service_path, tun_multi_service_path) = service_paths;
    let service = service_fn(move |request| {
        handle_request(
            request,
            tun_service_path.clone(),
            tun_multi_service_path.clone(),
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
    tun_service_path: String,
    tun_multi_service_path: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    let logical_peer_addr = grpc_logical_peer_addr(request.headers(), peer_addr);
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !grpc_content_type_is_valid(content_type) {
        return Ok(grpc_invalid_content_type_response(content_type));
    }
    if request.method() != Method::POST {
        return Ok(grpc_method_not_allowed_response(request.method()));
    }
    let multi_mode = match request.uri().path() {
        path if path == tun_service_path => false,
        path if path == tun_multi_service_path => true,
        _ => return Ok(grpc_status_response(12, "unimplemented gRPC method")),
    };
    if let Some(encoding) = grpc_unsupported_encoding(request.headers()) {
        return Ok(grpc_status_response(
            12,
            &format!(
                "grpc: Decompressor is not installed for grpc-encoding \"{encoding}\""
            ),
        ));
    }

    let (handler_stream, transport_stream) = duplex(GRPC_PIPE_CAPACITY);
    let (transport_read, transport_write) = tokio::io::split(transport_stream);
    let mut body = request.into_body();
    tokio::spawn(async move {
        if let Err(error) =
            decode_request_body(&mut body, transport_write, multi_mode).await
        {
            debug!("gRPC upload decode failed: {error}");
        }
    });
    tokio::spawn(async move {
        if let Err(error) = process_stream(
            GrpcLogicalStream(handler_stream),
            server_handler,
            resolver,
            logical_peer_addr,
            runtime,
        )
        .await
        {
            debug!("gRPC logical stream {logical_peer_addr} ended: {error}");
        }
    });

    Ok(grpc_stream_response(transport_read, multi_mode))
}

fn grpc_content_type_is_valid(content_type: &str) -> bool {
    const BASE: &str = "application/grpc";
    content_type == BASE
        || content_type
            .strip_prefix(BASE)
            .is_some_and(|suffix| suffix.starts_with('+') || suffix.starts_with(';'))
}

fn grpc_invalid_content_type_response(content_type: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "3")
        .header(
            "grpc-message",
            format!("invalid gRPC request content-type \"{content_type}\""),
        )
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

fn grpc_method_not_allowed_response(method: &Method) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header(
            "grpc-message",
            format!(
                "Received a HEADERS frame with :method \"{method}\" which should be POST"
            ),
        )
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

fn grpc_unsupported_encoding(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get("grpc-encoding")
        .and_then(|value| value.to_str().ok())
        .filter(|encoding| !encoding.is_empty() && *encoding != "identity")
}

fn grpc_logical_peer_addr(
    headers: &hyper::HeaderMap,
    peer_addr: std::net::SocketAddr,
) -> std::net::SocketAddr {
    let Some(value) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    else {
        return peer_addr;
    };
    let value = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let value = if value
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || value
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        value.trim()
    } else {
        value
    };
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| match ip {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(ip)),
            ip => ip,
        })
        .map(|ip| std::net::SocketAddr::new(ip, 0))
        .unwrap_or(peer_addr)
}

async fn decode_request_body(
    body: &mut Incoming,
    mut writer: tokio::io::WriteHalf<DuplexStream>,
    multi_mode: bool,
) -> io::Result<()> {
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })?;
        if let Some(data) = frame.data_ref() {
            buffered.extend_from_slice(data);
            while let Some(payloads) =
                decode_grpc_message(&mut buffered, multi_mode)?
            {
                for payload in payloads {
                    writer.write_all(&payload).await?;
                }
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
    multi_mode: bool,
) -> Response<ResponseBody> {
    let data_stream =
        ReaderStream::new(reader).filter_map(move |result| async move {
            match result {
                Ok(data) if !data.is_empty() => {
                    Some(Ok(Frame::data(encode_grpc_message(&data, multi_mode))))
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

fn decode_grpc_message(
    buffer: &mut BytesMut,
    multi_mode: bool,
) -> io::Result<Option<Vec<Vec<u8>>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC messages are not supported",
        ));
    }
    let message_len =
        u32::from_be_bytes(buffer[1..5].try_into().expect("gRPC length")) as usize;
    if message_len > MAX_GRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC message exceeds 4 MiB",
        ));
    }
    if buffer.len() < 5 + message_len {
        return Ok(None);
    }
    buffer.advance(5);
    let message = buffer.split_to(message_len);
    decode_data_fields(&message, multi_mode).map(Some)
}

fn decode_data_fields(message: &[u8], multi_mode: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut offset = 0;
    let mut payloads = Vec::new();
    while offset < message.len() {
        let (key, key_len) = decode_varint(&message[offset..])?;
        offset += key_len;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protobuf field number cannot be zero",
            ));
        }

        if field_number == 1 {
            if wire_type != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC data field has invalid protobuf wire type",
                ));
            }
            let (length, varint_len) = decode_varint(&message[offset..])?;
            offset += varint_len;
            let end = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC payload length overflow",
                )
            })?;
            if end > message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated gRPC protobuf payload",
                ));
            }
            let payload = message[offset..end].to_vec();
            offset = end;
            if multi_mode {
                payloads.push(payload);
            } else if let Some(existing) = payloads.first_mut() {
                *existing = payload;
            } else {
                payloads.push(payload);
            }
            continue;
        }

        offset = skip_protobuf_field(message, offset, wire_type)?;
    }

    if payloads.is_empty() {
        payloads.push(Vec::new());
    }
    Ok(payloads)
}

fn skip_protobuf_field(
    message: &[u8],
    mut offset: usize,
    wire_type: usize,
) -> io::Result<usize> {
    match wire_type {
        0 => {
            let (_, len) = decode_varint(&message[offset..])?;
            offset += len;
        }
        1 => {
            offset = offset.checked_add(8).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        2 => {
            let (length, len) = decode_varint(&message[offset..])?;
            offset += len;
            offset = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        5 => {
            offset = offset.checked_add(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported protobuf wire type",
            ));
        }
    }
    if offset > message.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated protobuf field",
        ));
    }
    Ok(offset)
}

fn encode_grpc_message(data: &[u8], _multi_mode: bool) -> Bytes {
    // Hunk and MultiHunk both encode their data using protobuf field 1. A single
    // field is a valid repeated-field encoding, so replies can use the same wire form.
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
    use hyper::HeaderMap;

    use super::{
        decode_grpc_message, encode_grpc_message, grpc_content_type_is_valid,
        grpc_invalid_content_type_response, grpc_logical_peer_addr,
        grpc_method_not_allowed_response, grpc_service_paths,
        grpc_unsupported_encoding,
    };

    #[test]
    fn grpc_server_exposes_tun_and_tun_multi_like_xray_v26_2_6() {
        let (tun, tun_multi) = grpc_service_paths("GunService");
        assert_eq!(tun, "/GunService/Tun");
        assert_eq!(tun_multi, "/GunService/TunMulti");
    }

    #[test]
    fn grpc_custom_service_paths_match_xray_v26_2_6() {
        let (tun, tun_multi) = grpc_service_paths("");
        assert_eq!(tun, "//Tun");
        assert_eq!(tun_multi, "//TunMulti");

        let (tun, tun_multi) =
            grpc_service_paths("/my/sample path/tun service|multi service");
        assert_eq!(tun, "/my/sample%20path/tun%20service");
        assert_eq!(tun_multi, "/my/sample%20path/multi%20service");

        let (tun, tun_multi) = grpc_service_paths("hello/world!");
        assert_eq!(tun, "/hello%2Fworld%21/Tun");
        assert_eq!(tun_multi, "/hello%2Fworld%21/TunMulti");
    }

    #[test]
    fn grpc_content_type_validation_matches_xray_v26_2_6() {
        for valid in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+xml",
            "application/grpc; charset=utf-8",
        ] {
            assert!(grpc_content_type_is_valid(valid), "{valid}");
        }
        for invalid in [
            "",
            "application/grpcfoo",
            "application/grpcx+proto",
            "application/grpc ",
            "application/grpc/",
            "APPLICATION/GRPC",
            "text/plain",
        ] {
            assert!(!grpc_content_type_is_valid(invalid), "{invalid}");
        }

        let response = grpc_invalid_content_type_response("application/grpcfoo");
        assert_eq!(response.status(), hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        assert_eq!(response.headers()["grpc-status"], "3");
        assert_eq!(
            response.headers()["grpc-message"],
            "invalid gRPC request content-type \"application/grpcfoo\""
        );
    }

    #[test]
    fn grpc_non_post_response_matches_xray_v26_2_6() {
        for method in [hyper::Method::GET, hyper::Method::PUT] {
            let response = grpc_method_not_allowed_response(&method);
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["content-type"], "application/grpc");
            assert_eq!(response.headers()["grpc-status"], "13");
            assert_eq!(
                response.headers()["grpc-message"],
                format!(
                    "Received a HEADERS frame with :method \"{method}\" which should be POST"
                )
            );
        }
    }

    #[test]
    fn grpc_rejects_non_identity_encoding_like_xray_v26_2_6() {
        let mut headers = HeaderMap::new();
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "identity".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "gzip".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), Some("gzip"));

        headers.insert("grpc-encoding", "deflate".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), Some("deflate"));
    }

    #[test]
    fn grpc_x_real_ip_overrides_logical_peer_like_xray_v26_2_6() {
        let peer_addr = "127.0.0.1:34567".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.9".parse().unwrap());
        assert_eq!(
            grpc_logical_peer_addr(&headers, peer_addr),
            "203.0.113.9:0".parse().unwrap()
        );

        headers.insert("x-real-ip", "[ 2001:db8::7 ]".parse().unwrap());
        assert_eq!(
            grpc_logical_peer_addr(&headers, peer_addr),
            "[2001:db8::7]:0".parse().unwrap()
        );

        headers.insert("x-real-ip", "::ffff:192.0.2.10".parse().unwrap());
        assert_eq!(
            grpc_logical_peer_addr(&headers, peer_addr),
            "192.0.2.10:0".parse().unwrap()
        );

        headers.insert("x-real-ip", "not-an-ip".parse().unwrap());
        assert_eq!(grpc_logical_peer_addr(&headers, peer_addr), peer_addr);
    }

    #[test]
    fn hunk_round_trip_handles_large_payload() {
        let payload = (0..70_000).map(|value| value as u8).collect::<Vec<_>>();
        let encoded = encode_grpc_message(&payload, false);
        let mut buffer = BytesMut::from(encoded.as_ref());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("decode Hunk")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![payload]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn multi_hunk_decodes_repeated_data_fields_in_order() {
        let protobuf = [
            0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', 0x0a, 0x05, b'w', b'o', b'r',
            b'l', b'd',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, true)
            .expect("decode MultiHunk")
            .expect("complete MultiHunk");
        assert_eq!(decoded, vec![b"hello".to_vec(), b"world".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_decoder_matches_protobuf_unknown_and_duplicate_field_semantics() {
        let protobuf = [
            0x10, 0x01, // unknown varint field 2
            0x0a, 0x05, b'f', b'i', b'r', b's', b't', 0x1a, 0x03, b'x', b'y',
            b'z', // unknown bytes field 3
            0x0a, 0x04, b'l', b'a', b's', b't',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("decode Hunk with protobuf-compatible unknown fields")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![b"last".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn multi_hunk_ignores_unknown_fields_and_keeps_all_data_fields() {
        let protobuf = [
            0x0a, 0x03, b'o', b'n', b'e', 0x2d, 0x01, 0x02, 0x03,
            0x04, // unknown fixed32 field 5
            0x0a, 0x03, b't', b'w', b'o',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, true)
            .expect("decode MultiHunk with protobuf-compatible unknown fields")
            .expect("complete MultiHunk");
        assert_eq!(decoded, vec![b"one".to_vec(), b"two".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_decoder_waits_for_complete_frame() {
        let encoded = encode_grpc_message(b"hello", false);
        let mut buffer = BytesMut::from(&encoded[..4]);
        assert!(decode_grpc_message(&mut buffer, false).unwrap().is_none());
    }
}
