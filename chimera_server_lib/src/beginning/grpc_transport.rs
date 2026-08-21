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
            let server_handler = server_handler.clone();
            let resolver = resolver.clone();
            let runtime = runtime.clone();
            match &security {
                GrpcSecurity::Plain => {
                    tokio::spawn(serve_grpc_connection(
                        stream,
                        tun_service_path,
                        tun_multi_service_path,
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
                                    tun_service_path,
                                    tun_multi_service_path,
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
                                    tun_service_path,
                                    tun_multi_service_path,
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
    tun_service_path: String,
    tun_multi_service_path: String,
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
    let multi_mode = match request.uri().path() {
        path if path == tun_service_path => false,
        path if path == tun_multi_service_path => true,
        _ => return Ok(grpc_status_response(12, "unimplemented gRPC method")),
    };
    if request.method() != Method::POST
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
            peer_addr,
            runtime,
        )
        .await
        {
            debug!("gRPC logical stream {peer_addr} ended: {error}");
        }
    });

    Ok(grpc_stream_response(transport_read, multi_mode))
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
    if message.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    let mut offset = 0;
    let mut payloads = Vec::new();
    while offset < message.len() {
        if message[offset] != 0x0a {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC protobuf is missing bytes field 1",
            ));
        }
        offset += 1;
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
        payloads.push(message[offset..end].to_vec());
        offset = end;
        if !multi_mode {
            break;
        }
    }
    Ok(payloads)
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

    use super::{decode_grpc_message, encode_grpc_message, grpc_service_paths};

    #[test]
    fn grpc_server_exposes_tun_and_tun_multi_like_xray_v26_2_6() {
        let (tun, tun_multi) = grpc_service_paths("GunService");
        assert_eq!(tun, "/GunService/Tun");
        assert_eq!(tun_multi, "/GunService/TunMulti");
    }

    #[test]
    fn grpc_custom_service_paths_match_xray_v26_2_6() {
        let (tun, tun_multi) =
            grpc_service_paths("/my/sample path/tun service|multi service");
        assert_eq!(tun, "/my/sample%20path/tun%20service");
        assert_eq!(tun_multi, "/my/sample%20path/multi%20service");

        let (tun, tun_multi) = grpc_service_paths("hello/world!");
        assert_eq!(tun, "/hello%2Fworld%21/Tun");
        assert_eq!(tun_multi, "/hello%2Fworld%21/TunMulti");
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
    fn hunk_decoder_waits_for_complete_frame() {
        let encoded = encode_grpc_message(b"hello", false);
        let mut buffer = BytesMut::from(&encoded[..4]);
        assert!(decode_grpc_message(&mut buffer, false).unwrap().is_none());
    }
}
