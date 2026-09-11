use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use base64::Engine as _;
#[cfg(feature = "grpc_transport")]
use bytes::BytesMut;
#[cfg(feature = "grpc_transport")]
use http_body_util::{BodyExt as _, StreamBody};
#[cfg(feature = "grpc_transport")]
use hyper::{
    Method, Request, Response, body::Frame, header, server::conn::http2,
    service::service_fn,
};
#[cfg(feature = "grpc_transport")]
use hyper_util::rt::{TokioExecutor, TokioIo};
use prost::Message;
#[cfg(feature = "grpc_transport")]
use std::convert::Infallible;
#[cfg(feature = "grpc_transport")]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
#[cfg(feature = "grpc_transport")]
use crate::beginning::grpc_transport::{
    decode_grpc_message_payloads, encode_grpc_message,
};
use crate::{
    config::{
        def::OutboundItem,
        rule::{BalancerConfig, RoutingConfig, RuleConfig},
    },
    handler::ws::WebsocketStream,
    resolver::NativeResolver,
    routing_state::{RoutingInput, RoutingState},
    runtime::{OutboundSummary, RuntimeState},
    util::prefixed_stream::PrefixedStream,
};

fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
    OutboundSummary {
        tag: tag.into(),
        protocol: protocol.into(),
        proxy_settings_type: None,
        proxy_settings_value: None,
        sender_settings_type: None,
        sender_settings_value: None,
    }
}

fn socks_outbound(
    tag: &str,
    server: SocketAddr,
    username: Option<&str>,
    password: Option<&str>,
) -> OutboundSummary {
    let account = username.map(|username| TypedMessagePayload {
        r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
        value: SocksAccountPayload {
            username: username.to_string(),
            password: password.unwrap_or_default().to_string(),
        }
        .encode_to_vec(),
    });
    let payload = SocksClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(IpOrDomainPayload {
                address: Some(match server.ip() {
                    IpAddr::V4(ip) => {
                        ip_or_domain_payload::Address::Ip(ip.octets().to_vec())
                    }
                    IpAddr::V6(ip) => {
                        ip_or_domain_payload::Address::Ip(ip.octets().to_vec())
                    }
                }),
            }),
            port: u32::from(server.port()),
            user: account.map(|account| OutboundUserPayload {
                level: 0,
                email: String::new(),
                account: Some(account),
            }),
        }),
    };
    OutboundSummary {
        tag: tag.into(),
        protocol: "socks".into(),
        proxy_settings_type: Some(TYPE_PROXY_SOCKS_CLIENT_CONFIG.into()),
        proxy_settings_value: Some(payload.encode_to_vec()),
        sender_settings_type: None,
        sender_settings_value: None,
    }
}

#[cfg(feature = "grpc_transport")]
async fn serve_test_grpc_trojan<IO>(
    io: IO,
    expected_authority: &str,
    expected_user_agent: Option<&str>,
    multi_mode: bool,
    expected_command: TrojanCommand,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let expected_authority = expected_authority.to_string();
    let expected_user_agent = expected_user_agent.map(str::to_string);
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let expected_authority = expected_authority.clone();
        let expected_user_agent = expected_user_agent.clone();
        async move {
            assert_eq!(request.method(), Method::POST);
            assert_eq!(
                request.uri().path(),
                if multi_mode {
                    "/GunService/TunMulti"
                } else {
                    "/GunService/Tun"
                }
            );
            assert_eq!(
                request.uri().authority().map(|value| value.as_str()),
                Some(expected_authority.as_str())
            );
            assert_eq!(
                request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/grpc")
            );
            assert_eq!(
                request
                    .headers()
                    .get(header::TE)
                    .and_then(|value| value.to_str().ok()),
                Some("trailers")
            );
            if let Some(expected_user_agent) = expected_user_agent {
                assert_eq!(
                    request
                        .headers()
                        .get(header::USER_AGENT)
                        .and_then(|value| value.to_str().ok()),
                    Some(expected_user_agent.as_str())
                );
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<
                Result<Frame<bytes::Bytes>, Infallible>,
            >(4);
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut encoded = BytesMut::new();
                let target = NetLocation::from_str("origin.example:443", None)
                    .expect("test Trojan target");
                let expected = build_trojan_request(
                    &TrojanOutboundEndpoint {
                        server: NetLocation::UNSPECIFIED,
                        password: "secret".into(),
                    },
                    &target,
                    expected_command,
                )
                .expect("build expected Trojan request");
                let expected_udp_packet = (expected_command == TrojanCommand::Udp)
                    .then(|| {
                        crate::handler::trojan_udp::encode_location_packet(
                            &target, b"ping",
                        )
                        .expect("encode expected Trojan UDP request packet")
                    });
                let expected_len = expected.len()
                    + expected_udp_packet.as_ref().map_or(0, Vec::len);
                let mut decoded = Vec::new();
                while decoded.len() < expected_len {
                    let frame = body
                        .frame()
                        .await
                        .expect("gRPC request body must contain Trojan data")
                        .expect("read gRPC request body frame");
                    if let Some(data) = frame.data_ref() {
                        encoded.extend_from_slice(data);
                        while let Some(payloads) =
                            decode_grpc_message_payloads(&mut encoded, multi_mode)
                                .expect("decode gRPC request Hunk")
                        {
                            for payload in payloads {
                                decoded.extend_from_slice(&payload);
                            }
                        }
                    }
                }
                assert_eq!(&decoded[..expected.len()], expected.as_slice());
                if let Some(expected_udp_packet) = expected_udp_packet {
                    assert_eq!(
                        &decoded[expected.len()..expected_len],
                        expected_udp_packet.as_slice()
                    );
                }
                let reply = if expected_command == TrojanCommand::Udp {
                    let packet = crate::handler::trojan_udp::encode_location_packet(
                        &target, b"pong",
                    )
                    .expect("encode Trojan UDP response packet");
                    encode_grpc_message(&packet, multi_mode)
                } else if multi_mode {
                    let mut frame = vec![0u8; 5];
                    for byte in *b"xy" {
                        frame.extend_from_slice(&[0x0a, 0x01, byte]);
                    }
                    let message_len = frame.len() - 5;
                    frame[1..5].copy_from_slice(&(message_len as u32).to_be_bytes());
                    bytes::Bytes::from(frame)
                } else {
                    encode_grpc_message(b"x", false)
                };
                tx.send(Ok(Frame::data(reply)))
                    .await
                    .expect("send gRPC reply Hunk");
                let mut trailers = hyper::HeaderMap::new();
                trailers.insert(
                    "grpc-status",
                    hyper::header::HeaderValue::from_static("0"),
                );
                tx.send(Ok(Frame::trailers(trailers)))
                    .await
                    .expect("send gRPC success trailers");
            });
            let response_stream = futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|frame| (frame, rx))
            });
            let response = Response::builder()
                .status(hyper::StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/grpc")
                .body(StreamBody::new(response_stream))
                .expect("build fake gRPC response");
            Ok::<_, Infallible>(response)
        }
    });
    http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await
        .expect("serve fake gRPC connection");
}

#[cfg(feature = "ws")]
async fn accept_test_websocket(
    mut stream: Box<dyn AsyncStream>,
    expected_path: &str,
    expected_host: &str,
    expected_header: Option<(&str, &str)>,
) -> WebsocketStream {
    let mut request = Vec::new();
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            request.len() < 64 * 1024,
            "test WebSocket request too large"
        );
        let mut chunk = [0u8; 2048];
        let read = stream
            .read(&mut chunk)
            .await
            .expect("read WebSocket upgrade request");
        assert!(read > 0, "WebSocket client closed during upgrade");
        request.extend_from_slice(&chunk[..read]);
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("upgrade header terminator")
        + 4;
    assert_eq!(
        request.len(),
        header_end,
        "Trojan data must not be sent before WebSocket upgrade completes"
    );
    let request_text = std::str::from_utf8(&request).expect("ASCII upgrade request");
    let mut lines = request_text.split("\r\n");
    assert_eq!(
        lines.next().expect("request line"),
        format!("GET {expected_path} HTTP/1.1")
    );
    let mut headers = HashMap::<String, String>::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("valid request header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
    assert_eq!(
        headers.get("upgrade").map(String::as_str),
        Some("websocket")
    );
    assert!(
        headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("Upgrade"))
    );
    assert_eq!(
        headers.get("sec-websocket-version").map(String::as_str),
        Some("13")
    );
    if let Some((name, value)) = expected_header {
        assert_eq!(
            headers.get(&name.to_ascii_lowercase()).map(String::as_str),
            Some(value)
        );
    }
    let key = headers
        .get("sec-websocket-key")
        .expect("Sec-WebSocket-Key request header");
    let accept = websocket_accept_value(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write WebSocket upgrade response");
    stream
        .flush()
        .await
        .expect("flush WebSocket upgrade response");
    WebsocketStream::new(stream, false, &[])
}

#[cfg(feature = "ws")]
async fn accept_test_websocket_early_data(
    mut stream: Box<dyn AsyncStream>,
    expected_path: &str,
    expected_host: &str,
) -> Box<dyn AsyncStream> {
    let mut request = Vec::new();
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            request.len() < 64 * 1024,
            "test WebSocket early-data request too large"
        );
        let mut chunk = [0u8; 2048];
        let read = stream
            .read(&mut chunk)
            .await
            .expect("read WebSocket early-data upgrade request");
        assert!(
            read > 0,
            "WebSocket early-data client closed during upgrade"
        );
        request.extend_from_slice(&chunk[..read]);
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("early-data upgrade header terminator")
        + 4;
    assert_eq!(
        request.len(),
        header_end,
        "Trojan early data must be carried only in the WebSocket request headers"
    );
    let request_text =
        std::str::from_utf8(&request).expect("ASCII early-data upgrade request");
    let mut lines = request_text.split("\r\n");
    assert_eq!(
        lines.next().expect("request line"),
        format!("GET {expected_path} HTTP/1.1")
    );
    let mut headers = HashMap::<String, String>::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("valid request header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
    let protocol = headers
        .get("sec-websocket-protocol")
        .expect("Xray early data must use Sec-WebSocket-Protocol")
        .clone();
    let early_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protocol.as_bytes())
        .expect("decode Xray WebSocket early data");
    assert!(
        !early_data.is_empty(),
        "Trojan early data must not be empty"
    );
    let key = headers
        .get("sec-websocket-key")
        .expect("Sec-WebSocket-Key request header");
    let accept = websocket_accept_value(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write WebSocket early-data upgrade response");
    stream
        .flush()
        .await
        .expect("flush WebSocket early-data upgrade response");
    let websocket: Box<dyn AsyncStream> =
        Box::new(WebsocketStream::new(stream, false, &[]));
    Box::new(PrefixedStream::new(early_data, websocket))
}

#[cfg(feature = "reality")]
async fn accept_test_reality(
    mut stream: tokio::net::TcpStream,
    config: crate::reality::RealityServerConfig,
) -> crate::reality::RealityTlsStream<
    Box<dyn AsyncStream>,
    crate::reality::RealityServerConnection,
> {
    let mut record_header = [0u8; 5];
    stream
        .read_exact(&mut record_header)
        .await
        .expect("read REALITY ClientHello record header");
    assert_eq!(record_header[0], 0x16, "expected TLS handshake record");
    let record_len =
        u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&record_header);
    client_hello.resize(5 + record_len, 0);
    stream
        .read_exact(&mut client_hello[5..])
        .await
        .expect("read REALITY ClientHello record payload");

    let mut session = crate::reality::RealityServerConnection::new(config)
        .expect("build fake REALITY server session");
    session
        .validate_client_hello(&client_hello)
        .expect("validate REALITY ClientHello");
    session
        .build_server_response(Vec::new())
        .expect("build REALITY server response");
    let mut response = Vec::new();
    while session.wants_write() {
        session
            .write_tls(&mut response)
            .expect("serialize REALITY server handshake");
    }
    stream
        .write_all(&response)
        .await
        .expect("write REALITY server handshake");
    stream
        .flush()
        .await
        .expect("flush REALITY server handshake");

    while session.is_handshaking() {
        let mut buffer = [0u8; 4096];
        let read = stream
            .read(&mut buffer)
            .await
            .expect("read REALITY client Finished");
        assert!(read > 0, "REALITY client closed during handshake");
        session
            .read_tls(&mut std::io::Cursor::new(&buffer[..read]))
            .expect("feed REALITY client handshake data");
        session
            .process_new_packets()
            .expect("process REALITY client handshake data");
        if session.wants_write() {
            let mut pending = Vec::new();
            while session.wants_write() {
                session
                    .write_tls(&mut pending)
                    .expect("serialize pending REALITY server data");
            }
            stream
                .write_all(&pending)
                .await
                .expect("write pending REALITY server data");
            stream
                .flush()
                .await
                .expect("flush pending REALITY server data");
        }
    }

    crate::reality::RealityTlsStream::new(
        Box::new(stream) as Box<dyn AsyncStream>,
        session,
    )
}

#[cfg(feature = "httpupgrade")]
async fn accept_test_httpupgrade(
    mut stream: Box<dyn AsyncStream>,
    expected_path: &str,
    expected_host: &str,
    expected_header: Option<(&str, &str)>,
) -> Box<dyn AsyncStream> {
    let mut request = Vec::new();
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            request.len() < 64 * 1024,
            "test HTTPUpgrade request too large"
        );
        let mut chunk = [0u8; 2048];
        let read = stream
            .read(&mut chunk)
            .await
            .expect("read HTTPUpgrade request");
        assert!(read > 0, "HTTPUpgrade client closed during upgrade");
        request.extend_from_slice(&chunk[..read]);
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTPUpgrade header terminator")
        + 4;
    assert_eq!(
        request.len(),
        header_end,
        "Trojan data must not be sent before HTTPUpgrade completes"
    );
    let request_text =
        std::str::from_utf8(&request).expect("ASCII HTTPUpgrade request");
    let mut lines = request_text.split("\r\n");
    assert_eq!(
        lines.next().expect("request line"),
        format!("GET {expected_path} HTTP/1.1")
    );
    let mut headers = HashMap::<String, String>::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("valid request header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
    assert_eq!(
        headers.get("upgrade").map(String::as_str),
        Some("websocket")
    );
    assert_eq!(
        headers.get("connection").map(String::as_str),
        Some("Upgrade")
    );
    if let Some((name, value)) = expected_header {
        assert_eq!(
            headers.get(&name.to_ascii_lowercase()).map(String::as_str),
            Some(value)
        );
    }
    stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("write HTTPUpgrade response");
    stream.flush().await.expect("flush HTTPUpgrade response");
    stream
}

#[cfg(feature = "httpupgrade")]
async fn accept_test_httpupgrade_early_data(
    mut stream: Box<dyn AsyncStream>,
    expected_path: &str,
    expected_host: &str,
) -> Box<dyn AsyncStream> {
    let mut request = Vec::new();
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            request.len() < 64 * 1024,
            "test HTTPUpgrade early-data request too large"
        );
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .expect("read HTTPUpgrade early-data request");
        assert!(
            read > 0,
            "HTTPUpgrade early-data client closed during upgrade"
        );
        request.push(byte[0]);
    }
    let request_text =
        std::str::from_utf8(&request).expect("ASCII HTTPUpgrade early-data request");
    let mut lines = request_text.split("\r\n");
    assert_eq!(
        lines.next().expect("request line"),
        format!("GET {expected_path} HTTP/1.1")
    );
    let mut headers = HashMap::<String, String>::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("valid request header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
    assert_eq!(
        headers.get("upgrade").map(String::as_str),
        Some("websocket")
    );
    assert_eq!(
        headers.get("connection").map(String::as_str),
        Some("Upgrade")
    );

    assert_trojan_connect(&mut *stream).await;
    stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("write HTTPUpgrade early-data response");
    stream
        .flush()
        .await
        .expect("flush HTTPUpgrade early-data response");
    stream
}

async fn assert_trojan_connect<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let mut password_hash = [0u8; 56];
    stream
        .read_exact(&mut password_hash)
        .await
        .expect("read Trojan password hash");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
    let expected = digest
        .as_ref()
        .iter()
        .flat_map(|byte| format!("{byte:02x}").into_bytes())
        .collect::<Vec<_>>();
    assert_eq!(password_hash.as_slice(), expected.as_slice());
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await.expect("read auth CRLF");
    assert_eq!(crlf, *b"\r\n");
    assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
    assert_eq!(
        stream.read_u8().await.expect("read Trojan address type"),
        0x03
    );
    let domain_len = stream.read_u8().await.expect("read domain length") as usize;
    let mut domain = vec![0u8; domain_len];
    stream
        .read_exact(&mut domain)
        .await
        .expect("read target domain");
    assert_eq!(domain, b"origin.example");
    assert_eq!(stream.read_u16().await.expect("read target port"), 443);
    stream
        .read_exact(&mut crlf)
        .await
        .expect("read request CRLF");
    assert_eq!(crlf, *b"\r\n");
}

async fn assert_trojan_connect_and_reply<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    assert_trojan_connect(stream).await;
    stream.write_all(b"x").await.expect("write relayed byte");
    stream.flush().await.expect("flush relayed byte");
}

#[derive(Clone)]
struct CountingResolver {
    calls: Arc<AtomicUsize>,
    addresses: Vec<SocketAddr>,
}

impl CountingResolver {
    fn new(addresses: Vec<SocketAddr>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            addresses,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Resolver for CountingResolver {
    fn resolve_location(
        &self,
        _location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let addresses = self.addresses.clone();
        Box::pin(async move { Ok(addresses) })
    }
}

#[test]
fn routing_metadata_is_applied_as_value_transformation() {
    let source_addr: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let target_addr: SocketAddr = "198.51.100.20:443".parse().unwrap();
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let base = connection_routing_input(
        "inbound",
        "alice",
        2,
        source_addr,
        target_addr,
        &target,
    );
    let transformed = apply_routing_metadata(
        base,
        InboundRoutingMetadata {
            local_addr: Some("203.0.113.7:8443".parse().unwrap()),
            vless_route: 42,
            sniffed_protocol: Some("tls".into()),
            route_target_domain: Some("sniffed.example".into()),
            attributes: HashMap::from([("x-test".into(), "ok".into())]),
        },
    );

    assert_eq!(transformed.inbound_tag, "inbound");
    assert_eq!(transformed.user, "alice");
    assert_eq!(transformed.source_port, 12345);
    assert_eq!(transformed.target_port, 443);
    assert_eq!(transformed.local_port, 8443);
    assert_eq!(transformed.local_ips, vec![vec![203, 0, 113, 7]]);
    assert_eq!(transformed.vless_route, 42);
    assert_eq!(transformed.protocol, "tls");
    assert_eq!(transformed.target_domain, "sniffed.example");
    assert_eq!(
        transformed.attributes.get("x-test").map(String::as_str),
        Some("ok")
    );
}

#[test]
fn static_socks_outbound_compiles_xray_short_form() {
    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "socks",
        "tag": "proxy",
        "settings": {
            "address": "127.0.0.1",
            "port": 1080,
            "user": "alice",
            "pass": "secret",
            "level": 3,
            "email": "alice@example.test"
        }
    }))
    .expect("parse static SOCKS outbound");

    let outbound = compile_static_outbound(&item).expect("compile SOCKS outbound");
    assert_eq!(outbound.protocol, "socks");
    let endpoint =
        decode_socks_outbound(&outbound).expect("decode compiled SOCKS outbound");
    assert_eq!(endpoint.server.to_string(), "127.0.0.1:1080");
    assert_eq!(endpoint.username.as_deref(), Some("alice"));
    assert_eq!(endpoint.password.as_deref(), Some("secret"));
}

#[cfg(feature = "vless")]
#[test]
fn static_vless_outbound_compiles_xray_short_form_and_rejects_transport_downgrade() {
    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "tag": "proxy",
        "settings": {
            "address": "127.0.0.1",
            "port": 1234,
            "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
            "encryption": "none"
        }
    }))
    .expect("parse static VLESS outbound");
    let outbound = compile_static_outbound(&item).expect("compile VLESS outbound");
    let endpoint = decode_vless_outbound(&outbound).expect("decode VLESS outbound");
    assert_eq!(endpoint.server.to_string(), "127.0.0.1:1234");
    assert_eq!(
        endpoint.user_id,
        parse_xray_uuid("3ac9b383-75a1-431c-8184-106c80eb2273").unwrap()
    );
    assert!(endpoint.flow.is_empty());

    let secure_item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "tag": "secure-proxy",
        "settings": {
            "address": "127.0.0.1",
            "port": 1234,
            "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
            "encryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality"
        }
    }))
    .expect("parse VLESS outbound with stream settings");
    let error = compile_static_outbound(&secure_item)
        .expect_err("unsupported VLESS transport must fail closed");
    assert!(error.contains("refusing to downgrade transport security"));
}

#[cfg(feature = "trojan")]
#[test]
fn static_trojan_outbound_compiles_xray_short_form_and_tls_sender_settings() {
    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": "127.0.0.1",
            "port": 443,
            "password": "secret",
            "email": "trojan@example.test"
        }
    }))
    .expect("parse static Trojan outbound");
    let outbound = compile_static_outbound(&item).expect("compile Trojan outbound");
    let endpoint =
        decode_trojan_outbound(&outbound).expect("decode Trojan outbound");
    assert_eq!(endpoint.server.to_string(), "127.0.0.1:443");
    assert_eq!(endpoint.password, "secret");

    let secure_item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "secure-proxy",
        "settings": {
            "address": "127.0.0.1",
            "port": 443,
            "password": "secret"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls"
        }
    }))
    .expect("parse Trojan outbound with stream settings");
    let secure = compile_static_outbound(&secure_item)
        .expect("Trojan TLS sender settings should compile");
    assert_eq!(
        secure.sender_settings_type.as_deref(),
        Some(TYPE_APP_SENDER_CONFIG)
    );
    let transport = decode_sender_transport(
        secure.sender_settings_type.as_deref(),
        secure.sender_settings_value.as_deref(),
    )
    .expect("decode Trojan TLS sender settings");
    assert!(matches!(transport, OutboundTransport::Tls(_)));
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn routed_tcp_connection_uses_vless_outbound_and_strips_response_header() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake VLESS server");
    let server_addr = listener.local_addr().expect("fake VLESS address");
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let expected_id = parse_xray_uuid(user_id).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept VLESS client");
        let header = crate::handler::vless_handler::protocol::read_request_header(
            &mut stream,
        )
        .await
        .expect("parse VLESS request");
        assert_eq!(header.user_id, expected_id);
        assert_eq!(
            header.command,
            crate::handler::vless_handler::protocol::COMMAND_TCP
        );
        assert_eq!(header.remote_location.to_string(), "origin.example:443");
        assert!(header.flow.is_empty());
        stream
            .write_all(&[0, 0])
            .await
            .expect("write VLESS response header");
        stream.write_all(b"x").await.expect("write relayed byte");
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "vless",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "id": user_id,
            "encryption": "none"
        }
    }))
    .expect("parse VLESS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![compile_static_outbound(&item).expect("compile VLESS outbound")],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile VLESS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("VLESS routed TCP connect")
    .expect("VLESS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
    server.await.expect("fake VLESS server task");
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_outbound_and_preserves_domain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan server");
    let server_addr = listener.local_addr().expect("fake Trojan address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept Trojan client");
        let mut password_hash = [0u8; 56];
        stream
            .read_exact(&mut password_hash)
            .await
            .expect("read Trojan password hash");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(password_hash.as_slice(), expected.as_slice());
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.expect("read first CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
        assert_eq!(
            stream.read_u8().await.expect("read Trojan address type"),
            0x03
        );
        let domain_len =
            stream.read_u8().await.expect("read domain length") as usize;
        let mut domain = vec![0u8; domain_len];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read target domain");
        assert_eq!(domain, b"origin.example");
        assert_eq!(stream.read_u16().await.expect("read target port"), 443);
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read request CRLF");
        assert_eq!(crlf, *b"\r\n");
        stream.write_all(b"x").await.expect("write relayed byte");
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        }
    }))
    .expect("parse Trojan outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![compile_static_outbound(&item).expect("compile Trojan outbound")],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan routed TCP connect")
    .expect("Trojan route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
    server.await.expect("fake Trojan server task");
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn trojan_udp_outbound_roundtrips_raw_transport_and_preserves_domain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan UDP server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan UDP server address");
    let target = NetLocation::from_str("origin.example:443", None)
        .expect("Trojan UDP target");
    let server_target = target.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) =
            listener.accept().await.expect("accept Trojan UDP client");
        let expected = build_trojan_request(
            &TrojanOutboundEndpoint {
                server: NetLocation::UNSPECIFIED,
                password: "secret".into(),
            },
            &server_target,
            TrojanCommand::Udp,
        )
        .expect("build Trojan UDP request header");
        let mut actual = vec![0u8; expected.len()];
        stream
            .read_exact(&mut actual)
            .await
            .expect("read Trojan UDP request header");
        assert_eq!(actual, expected);

        let mut udp =
            crate::handler::trojan_udp::TrojanUdpStream::new(Box::new(stream));
        let mut payload = [0u8; 16];
        let (packet_target, length) = udp
            .recv_from(&mut payload)
            .await
            .expect("read Trojan UDP request packet");
        assert_eq!(packet_target, server_target);
        assert_eq!(&payload[..length], b"ping");
        udp.send_to(&packet_target, b"pong")
            .await
            .expect("write Trojan UDP response packet");
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        }
    }))
    .expect("parse Trojan UDP outbound");
    let outbound =
        compile_static_outbound(&item).expect("compile Trojan UDP outbound");
    let runtime = RuntimeState::new(Vec::new(), vec![outbound.clone()]);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut udp = connect_trojan_udp_via_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        &outbound,
    )
    .await
    .expect("connect Trojan UDP outbound");
    udp.send_to(&target, b"ping")
        .await
        .expect("send Trojan UDP packet");
    let mut payload = [0u8; 16];
    let (source, length) = udp
        .recv_from(&mut payload)
        .await
        .expect("receive Trojan UDP packet");
    assert_eq!(source, target);
    assert_eq!(&payload[..length], b"pong");
    server.await.expect("fake Trojan UDP server task");
}

#[cfg(all(feature = "trojan", feature = "ws"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_websocket_outbound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan WebSocket server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan WebSocket address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan WebSocket client");
        let mut stream = accept_test_websocket(
            Box::new(stream),
            "/trojan?foo=bar",
            "ws.example.test",
            Some(("x-test", "chimera")),
        )
        .await;
        assert_trojan_connect_and_reply(&mut stream).await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {
                "host": "ws.example.test",
                "path": "/trojan?foo=bar",
                "headers": {
                    "X-Test": "chimera"
                }
            }
        }
    }))
    .expect("parse Trojan WebSocket outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan WebSocket outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan WebSocket route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan WebSocket routed TCP connect")
    .expect("Trojan WebSocket route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream.read_u8().await.expect("read WebSocket relayed byte"),
        b'x'
    );
    server.await.expect("fake Trojan WebSocket server task");
}

#[cfg(all(feature = "trojan", feature = "ws"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_websocket_early_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan WebSocket early-data server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan WebSocket early-data address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan WebSocket early-data client");
        let mut stream = accept_test_websocket_early_data(
            Box::new(stream),
            "/trojan",
            "ws.example.test",
        )
        .await;
        assert_trojan_connect_and_reply(&mut *stream).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                .await
                .is_err(),
            "Trojan header must not be repeated as a WebSocket frame after early data"
        );
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {
                "host": "ws.example.test",
                "path": "/trojan?ed=256"
            }
        }
    }))
    .expect("parse Trojan WebSocket early-data outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan WebSocket early-data outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan WebSocket early-data route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan WebSocket early-data routed TCP connect")
    .expect("Trojan WebSocket early-data route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read WebSocket early-data relayed byte"),
        b'x'
    );
    server
        .await
        .expect("fake Trojan WebSocket early-data server task");
}

#[cfg(all(feature = "trojan", feature = "tls", feature = "ws"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_websocket_tls_outbound() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan WSS certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan WSS server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan WSS server");
    let server_addr = listener.local_addr().expect("fake Trojan WSS address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept Trojan WSS client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan WSS TLS");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut stream = accept_test_websocket(
            Box::new(tls_stream),
            "/secure",
            "localhost",
            None,
        )
        .await;
        assert_trojan_connect_and_reply(&mut stream).await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "wsSettings": {
                "path": "/secure"
            }
        }
    }))
    .expect("parse Trojan WSS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![compile_static_outbound(&item).expect("compile Trojan WSS outbound")],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan WSS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan WSS routed TCP connect")
    .expect("Trojan WSS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(stream.read_u8().await.expect("read WSS relayed byte"), b'x');
    server.await.expect("fake Trojan WSS server task");
}

#[cfg(all(feature = "trojan", feature = "tls", feature = "ws"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_websocket_tls_early_data() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan WSS early-data certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan WSS early-data server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan WSS early-data server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan WSS early-data address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan WSS early-data client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan WSS early-data TLS");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut stream = accept_test_websocket_early_data(
            Box::new(tls_stream),
            "/secure",
            "localhost",
        )
        .await;
        assert_trojan_connect_and_reply(&mut *stream).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                .await
                .is_err(),
            "Trojan header must not be repeated after WSS early data"
        );
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "wsSettings": {
                "path": "/secure?ed=256"
            }
        }
    }))
    .expect("parse Trojan WSS early-data outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan WSS early-data outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan WSS early-data route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan WSS early-data routed TCP connect")
    .expect("Trojan WSS early-data route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read WSS early-data relayed byte"),
        b'x'
    );
    server
        .await
        .expect("fake Trojan WSS early-data server task");
}

#[cfg(all(feature = "trojan", feature = "httpupgrade"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_httpupgrade_outbound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan HTTPUpgrade server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan HTTPUpgrade address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan HTTPUpgrade client");
        let mut stream = accept_test_httpupgrade(
            Box::new(stream),
            "/trojan?foo=bar",
            "upgrade.example.test",
            Some(("x-test", "chimera")),
        )
        .await;
        assert_trojan_connect_and_reply(&mut *stream).await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "security": "none",
            "httpUpgradeSettings": {
                "host": "upgrade.example.test",
                "path": "/trojan?foo=bar",
                "headers": {
                    "X-Test": "chimera"
                }
            }
        }
    }))
    .expect("parse Trojan HTTPUpgrade outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan HTTPUpgrade outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan HTTPUpgrade route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan HTTPUpgrade routed TCP connect")
    .expect("Trojan HTTPUpgrade route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read HTTPUpgrade relayed byte"),
        b'x'
    );
    server.await.expect("fake Trojan HTTPUpgrade server task");
}

#[cfg(all(feature = "trojan", feature = "httpupgrade"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_httpupgrade_early_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan HTTPUpgrade early-data server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan HTTPUpgrade early-data address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan HTTPUpgrade early-data client");
        let mut stream = accept_test_httpupgrade_early_data(
            Box::new(stream),
            "/trojan",
            "upgrade.example.test",
        )
        .await;
        stream
            .write_all(b"x")
            .await
            .expect("write early-data relayed byte");
        stream.flush().await.expect("flush early-data relayed byte");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                .await
                .is_err(),
            "Trojan header must not be repeated after HTTPUpgrade early data"
        );
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "security": "none",
            "httpUpgradeSettings": {
                "host": "upgrade.example.test",
                "path": "/trojan?ed=1"
            }
        }
    }))
    .expect("parse Trojan HTTPUpgrade early-data outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan HTTPUpgrade early-data outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan HTTPUpgrade early-data route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan HTTPUpgrade early-data routed TCP connect")
    .expect("Trojan HTTPUpgrade early-data route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read HTTPUpgrade early-data relayed byte"),
        b'x'
    );
    server
        .await
        .expect("fake Trojan HTTPUpgrade early-data server task");
}

#[cfg(all(feature = "trojan", feature = "tls", feature = "httpupgrade"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_httpupgrade_tls_outbound() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan HTTPUpgrade TLS certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan HTTPUpgrade TLS server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan HTTPUpgrade TLS server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan HTTPUpgrade TLS address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan HTTPUpgrade TLS client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan HTTPUpgrade TLS");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut stream = accept_test_httpupgrade(
            Box::new(tls_stream),
            "/secure",
            "localhost",
            None,
        )
        .await;
        assert_trojan_connect_and_reply(&mut *stream).await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "httpUpgradeSettings": {
                "path": "/secure"
            }
        }
    }))
    .expect("parse Trojan HTTPUpgrade TLS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan HTTPUpgrade TLS outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan HTTPUpgrade TLS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan HTTPUpgrade TLS routed TCP connect")
    .expect("Trojan HTTPUpgrade TLS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read HTTPUpgrade TLS relayed byte"),
        b'x'
    );
    server
        .await
        .expect("fake Trojan HTTPUpgrade TLS server task");
}

#[cfg(all(feature = "trojan", feature = "tls", feature = "httpupgrade"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_httpupgrade_tls_early_data() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan HTTPUpgrade TLS early-data certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan HTTPUpgrade TLS early-data server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan HTTPUpgrade TLS early-data server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan HTTPUpgrade TLS early-data address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan HTTPUpgrade TLS early-data client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan HTTPUpgrade TLS early-data");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let mut stream = accept_test_httpupgrade_early_data(
            Box::new(tls_stream),
            "/secure",
            "localhost",
        )
        .await;
        stream
            .write_all(b"x")
            .await
            .expect("write TLS early-data relayed byte");
        stream
            .flush()
            .await
            .expect("flush TLS early-data relayed byte");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                .await
                .is_err(),
            "Trojan header must not be repeated after TLS HTTPUpgrade early data"
        );
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "httpUpgradeSettings": {
                "path": "/secure?ed=1"
            }
        }
    }))
    .expect("parse Trojan HTTPUpgrade TLS early-data outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan HTTPUpgrade TLS early-data outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan HTTPUpgrade TLS early-data route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan HTTPUpgrade TLS early-data routed TCP connect")
    .expect("Trojan HTTPUpgrade TLS early-data route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read HTTPUpgrade TLS early-data relayed byte"),
        b'x'
    );
    server
        .await
        .expect("fake Trojan HTTPUpgrade TLS early-data server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_grpc_outbound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan gRPC server");
    let server_addr = listener.local_addr().expect("fake Trojan gRPC address");
    let server = tokio::spawn(async move {
        let (stream, _) =
            listener.accept().await.expect("accept Trojan gRPC client");
        serve_test_grpc_trojan(
            stream,
            "grpc.example.test",
            Some("chimera-grpc-test"),
            false,
            TrojanCommand::Tcp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "authority": "grpc.example.test",
                "serviceName": "GunService",
                "user_agent": "chimera-grpc-test"
            }
        }
    }))
    .expect("parse Trojan gRPC outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![compile_static_outbound(&item).expect("compile Trojan gRPC outbound")],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan gRPC route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan gRPC routed TCP connect")
    .expect("Trojan gRPC route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream.read_u8().await.expect("read gRPC relayed byte"),
        b'x'
    );
    let mut tail = Vec::new();
    stream
        .read_to_end(&mut tail)
        .await
        .expect("gRPC success trailers should end with clean EOF");
    assert!(tail.is_empty());
    drop(stream);
    server.await.expect("fake Trojan gRPC server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport"))]
#[tokio::test]
async fn trojan_udp_outbound_roundtrips_grpc_transport() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan UDP gRPC server");
    let server_addr = listener.local_addr().expect("fake Trojan UDP gRPC address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan UDP gRPC client");
        serve_test_grpc_trojan(
            stream,
            "grpc.example.test",
            Some("chimera-grpc-udp-test"),
            false,
            TrojanCommand::Udp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "authority": "grpc.example.test",
                "serviceName": "GunService",
                "user_agent": "chimera-grpc-udp-test"
            }
        }
    }))
    .expect("parse Trojan UDP gRPC outbound");
    let outbound =
        compile_static_outbound(&item).expect("compile Trojan UDP gRPC outbound");
    let runtime = RuntimeState::new(Vec::new(), vec![outbound.clone()]);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None)
        .expect("Trojan UDP gRPC target");
    let mut udp = connect_trojan_udp_via_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        &outbound,
    )
    .await
    .expect("connect Trojan UDP gRPC outbound");
    udp.send_to(&target, b"ping")
        .await
        .expect("send Trojan UDP gRPC packet");
    let mut payload = [0u8; 16];
    let (source, length) = udp
        .recv_from(&mut payload)
        .await
        .expect("receive Trojan UDP gRPC packet");
    assert_eq!(source, target);
    assert_eq!(&payload[..length], b"pong");
    drop(udp);
    server.await.expect("fake Trojan UDP gRPC server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_grpc_multi_outbound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan gRPC TunMulti server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan gRPC TunMulti address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan gRPC TunMulti client");
        serve_test_grpc_trojan(
            stream,
            "grpc.example.test",
            Some("chimera-grpc-multi-test"),
            true,
            TrojanCommand::Tcp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "authority": "grpc.example.test",
                "serviceName": "GunService",
                "multiMode": true,
                "user_agent": "chimera-grpc-multi-test"
            }
        }
    }))
    .expect("parse Trojan gRPC TunMulti outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan gRPC TunMulti outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan gRPC TunMulti route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan gRPC TunMulti routed TCP connect")
    .expect("Trojan gRPC TunMulti route should not blackhole");
    let mut stream = connection.stream;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read repeated MultiHunk payloads");
    assert_eq!(&reply, b"xy");
    let mut tail = Vec::new();
    stream
        .read_to_end(&mut tail)
        .await
        .expect("TunMulti success trailers should end with clean EOF");
    assert!(tail.is_empty());
    drop(stream);
    server.await.expect("fake Trojan gRPC TunMulti server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "tls"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_grpc_tls_outbound() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan gRPC TLS certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan gRPC TLS server config");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan gRPC TLS server");
    let server_addr = listener.local_addr().expect("fake Trojan gRPC TLS address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan gRPC TLS client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan gRPC TLS");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );
        serve_test_grpc_trojan(
            tls_stream,
            "localhost",
            Some("chimera-grpc-tls-test"),
            false,
            TrojanCommand::Tcp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "grpcSettings": {
                "serviceName": "GunService",
                "user_agent": "chimera-grpc-tls-test"
            }
        }
    }))
    .expect("parse Trojan gRPC TLS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan gRPC TLS outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan gRPC TLS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan gRPC TLS routed TCP connect")
    .expect("Trojan gRPC TLS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream.read_u8().await.expect("read gRPC TLS relayed byte"),
        b'x'
    );
    drop(stream);
    server.await.expect("fake Trojan gRPC TLS server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "tls"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_grpc_tls_multi_outbound() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan gRPC TunMulti TLS certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan gRPC TunMulti TLS server config");
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan gRPC TunMulti TLS server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan gRPC TunMulti TLS address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan gRPC TunMulti TLS client");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .expect("accept Trojan gRPC TunMulti TLS");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );
        serve_test_grpc_trojan(
            tls_stream,
            "localhost",
            Some("chimera-grpc-tls-multi-test"),
            true,
            TrojanCommand::Tcp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            },
            "grpcSettings": {
                "serviceName": "GunService",
                "multiMode": true,
                "user_agent": "chimera-grpc-tls-multi-test"
            }
        }
    }))
    .expect("parse Trojan gRPC TunMulti TLS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan gRPC TunMulti TLS outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan gRPC TunMulti TLS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan gRPC TunMulti TLS routed TCP connect")
    .expect("Trojan gRPC TunMulti TLS route should not blackhole");
    let mut stream = connection.stream;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read TLS TunMulti repeated payloads");
    assert_eq!(&reply, b"xy");
    drop(stream);
    server
        .await
        .expect("fake Trojan gRPC TunMulti TLS server task");
}

#[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "reality"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_grpc_reality_outbound() {
    let (private_key_b64, public_key_b64) =
        crate::reality::generate_keypair().expect("generate gRPC REALITY keypair");
    let private_key = crate::reality::decode_private_key(&private_key_b64)
        .expect("decode gRPC REALITY private key");
    let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan gRPC REALITY server");
    let server_addr = listener
        .local_addr()
        .expect("fake Trojan gRPC REALITY address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan gRPC REALITY client");
        let reality_stream = accept_test_reality(
            stream,
            crate::reality::RealityServerConfig {
                private_key,
                short_ids: vec![short_id],
                dest: NetLocation::new(
                    Address::Hostname("reality.example.test".to_string()),
                    443,
                ),
                server_names: vec!["reality.example.test".to_string()],
                max_time_diff: Some(60_000),
                min_client_version: Some([26, 3, 27]),
                max_client_version: None,
                cipher_suites: Vec::new(),
            },
        )
        .await;
        serve_test_grpc_trojan(
            reality_stream,
            "grpc.example.test",
            Some("chimera-grpc-reality-test"),
            false,
            TrojanCommand::Tcp,
        )
        .await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "reality",
            "realitySettings": {
                "fingerprint": "chrome",
                "serverName": "reality.example.test",
                "publicKey": public_key_b64,
                "shortId": "0011223344556677",
                "spiderX": "/"
            },
            "grpcSettings": {
                "authority": "grpc.example.test",
                "serviceName": "GunService",
                "user_agent": "chimera-grpc-reality-test"
            }
        }
    }))
    .expect("parse Trojan gRPC REALITY outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item)
                .expect("compile Trojan gRPC REALITY outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan gRPC REALITY route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan gRPC REALITY routed TCP connect")
    .expect("Trojan gRPC REALITY route should not blackhole");
    let mut stream = connection.stream;
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read gRPC REALITY relayed byte"),
        b'x'
    );
    drop(stream);
    server.await.expect("fake Trojan gRPC REALITY server task");
}

#[cfg(feature = "grpc_transport")]
#[test]
fn grpc_tuning_matches_xray_grpc_go_defaults() {
    let mut settings = OutboundGrpcClientSettings {
        authority: String::new(),
        service_name: "GunService".into(),
        multi_mode: false,
        idle_timeout: 0,
        health_check_timeout: 0,
        permit_without_stream: false,
        initial_windows_size: 0,
        user_agent: String::new(),
    };
    assert_eq!(grpc_initial_stream_window(&settings), 65_535);
    assert_eq!(grpc_keepalive_params(&settings), None);

    settings.permit_without_stream = true;
    assert_eq!(
        grpc_keepalive_params(&settings),
        Some((Duration::from_secs(10), Duration::from_secs(20), true))
    );

    settings.idle_timeout = 3;
    settings.health_check_timeout = 7;
    settings.permit_without_stream = false;
    assert_eq!(
        grpc_keepalive_params(&settings),
        Some((Duration::from_secs(10), Duration::from_secs(7), false))
    );

    settings.idle_timeout = 30;
    settings.health_check_timeout = 0;
    assert_eq!(
        grpc_keepalive_params(&settings),
        Some((Duration::from_secs(30), Duration::from_secs(20), false))
    );

    settings.initial_windows_size = 32_768;
    assert_eq!(grpc_initial_stream_window(&settings), 65_535);
    settings.initial_windows_size = 1 << 20;
    assert_eq!(grpc_initial_stream_window(&settings), 1 << 20);

    let normalized = encode_static_grpc_config(StaticOutboundGrpcSettings {
        idle_timeout: -1,
        health_check_timeout: -1,
        initial_windows_size: -1,
        ..StaticOutboundGrpcSettings::default()
    })
    .expect("normalize static gRPC tuning");
    assert_eq!(normalized.idle_timeout, 0);
    assert_eq!(normalized.health_check_timeout, 0);
    assert_eq!(normalized.initial_windows_size, 0);
}

#[cfg(feature = "grpc_transport")]
#[tokio::test]
async fn grpc_outbound_write_shutdown_preserves_download_half() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC half-close test server");
    let server_addr = listener
        .local_addr()
        .expect("gRPC half-close server address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept gRPC half-close client");
        let service =
            service_fn(|request: Request<hyper::body::Incoming>| async move {
                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<Frame<bytes::Bytes>, Infallible>,
                >(4);
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut encoded = BytesMut::new();
                    let mut decoded = Vec::new();
                    while let Some(frame) = body.frame().await {
                        let frame =
                            frame.expect("read half-close gRPC request frame");
                        if let Some(data) = frame.data_ref() {
                            encoded.extend_from_slice(data);
                            while let Some(payloads) =
                                decode_grpc_message_payloads(&mut encoded, false)
                                    .expect("decode half-close gRPC Hunk")
                            {
                                for payload in payloads {
                                    decoded.extend_from_slice(&payload);
                                }
                            }
                        }
                    }
                    assert_eq!(decoded, b"hello");
                    tx.send(Ok(Frame::data(encode_grpc_message(b"x", false))))
                        .await
                        .expect("send half-close reply Hunk");
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert(
                        "grpc-status",
                        hyper::header::HeaderValue::from_static("0"),
                    );
                    tx.send(Ok(Frame::trailers(trailers)))
                        .await
                        .expect("send half-close success trailers");
                });
                let response_stream =
                    futures::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|frame| (frame, rx))
                    });
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/grpc")
                        .body(StreamBody::new(response_stream))
                        .expect("build half-close gRPC response"),
                )
            });
        http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve half-close gRPC connection");
    });

    let raw = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("connect gRPC half-close server");
    let server_location =
        NetLocation::from_ip_addr(server_addr.ip(), server_addr.port());
    let mut stream = connect_grpc_transport(
        Box::new(raw),
        &OutboundGrpcClientSettings {
            authority: "grpc.example.test".into(),
            service_name: "GunService".into(),
            multi_mode: false,
            idle_timeout: 0,
            health_check_timeout: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
            user_agent: String::new(),
        },
        &server_location,
        None,
        false,
    )
    .await
    .expect("establish gRPC half-close tunnel");
    stream.write_all(b"hello").await.expect("write gRPC upload");
    stream.shutdown().await.expect("half-close gRPC upload");
    assert_eq!(
        stream
            .read_u8()
            .await
            .expect("read after gRPC write shutdown"),
        b'x'
    );
    let mut tail = Vec::new();
    stream
        .read_to_end(&mut tail)
        .await
        .expect("read clean gRPC half-close EOF");
    assert!(tail.is_empty());
    drop(stream);
    server.await.expect("gRPC half-close server task");
}

#[cfg(feature = "grpc_transport")]
#[tokio::test]
async fn grpc_outbound_surfaces_nonzero_trailer_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC status test server");
    let server_addr = listener.local_addr().expect("gRPC status server address");
    let server = tokio::spawn(async move {
        let (stream, _) =
            listener.accept().await.expect("accept gRPC status client");
        let service =
            service_fn(|request: Request<hyper::body::Incoming>| async move {
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    while body.frame().await.is_some() {}
                });
                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<Frame<bytes::Bytes>, Infallible>,
                >(2);
                tokio::spawn(async move {
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert(
                        "grpc-status",
                        hyper::header::HeaderValue::from_static("13"),
                    );
                    tx.send(Ok(Frame::trailers(trailers)))
                        .await
                        .expect("send nonzero gRPC trailers");
                });
                let response_stream =
                    futures::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|frame| (frame, rx))
                    });
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/grpc")
                        .body(StreamBody::new(response_stream))
                        .expect("build gRPC status response"),
                )
            });
        http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve gRPC status connection");
    });

    let raw = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("connect gRPC status server");
    let server_location =
        NetLocation::from_ip_addr(server_addr.ip(), server_addr.port());
    let mut stream = connect_grpc_transport(
        Box::new(raw),
        &OutboundGrpcClientSettings {
            authority: "grpc.example.test".into(),
            service_name: "GunService".into(),
            multi_mode: false,
            idle_timeout: 0,
            health_check_timeout: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
            user_agent: String::new(),
        },
        &server_location,
        None,
        false,
    )
    .await
    .expect("establish gRPC status tunnel");
    let error = stream
        .read_u8()
        .await
        .expect_err("nonzero grpc-status must surface as I/O error");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert!(error.to_string().contains("grpc-status 13"));
    drop(stream);
    server.await.expect("gRPC status server task");
}

#[cfg(all(feature = "trojan", feature = "reality"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_reality_outbound() {
    let (private_key_b64, public_key_b64) =
        crate::reality::generate_keypair().expect("generate REALITY keypair");
    let private_key = crate::reality::decode_private_key(&private_key_b64)
        .expect("decode REALITY private key");
    let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan REALITY server");
    let server_addr = listener.local_addr().expect("fake Trojan REALITY address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("accept Trojan REALITY client");
        let mut stream = accept_test_reality(
            stream,
            crate::reality::RealityServerConfig {
                private_key,
                short_ids: vec![short_id],
                dest: NetLocation::new(
                    Address::Hostname("reality.example.test".to_string()),
                    443,
                ),
                server_names: vec!["reality.example.test".to_string()],
                max_time_diff: Some(60_000),
                min_client_version: Some([26, 3, 27]),
                max_client_version: None,
                cipher_suites: Vec::new(),
            },
        )
        .await;
        assert_trojan_connect_and_reply(&mut stream).await;
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "fingerprint": "chrome",
                "serverName": "reality.example.test",
                "publicKey": public_key_b64,
                "shortId": "0011223344556677",
                "spiderX": "/"
            }
        }
    }))
    .expect("parse Trojan REALITY outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            compile_static_outbound(&item).expect("compile Trojan REALITY outbound"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan REALITY route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan REALITY routed TCP connect")
    .expect("Trojan REALITY route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(
        stream.read_u8().await.expect("read REALITY relayed byte"),
        b'x'
    );
    server.await.expect("fake Trojan REALITY server task");
}

#[cfg(all(feature = "trojan", feature = "tls"))]
#[tokio::test]
async fn routed_tcp_connection_uses_trojan_tls_with_custom_verify_root() {
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate Trojan TLS certificate");
    let certificate_pem = generated.cert.pem();
    let certificate_der =
        rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ),
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("select TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)
        .expect("build Trojan TLS server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake Trojan TLS server");
    let server_addr = listener.local_addr().expect("fake Trojan TLS address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept Trojan TLS client");
        let mut stream = acceptor.accept(stream).await.expect("accept Trojan TLS");
        let mut password_hash = [0u8; 56];
        stream
            .read_exact(&mut password_hash)
            .await
            .expect("read Trojan TLS password hash");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(password_hash.as_slice(), expected.as_slice());
        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read TLS auth CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
        assert_eq!(
            stream.read_u8().await.expect("read Trojan address type"),
            0x03
        );
        let domain_len =
            stream.read_u8().await.expect("read domain length") as usize;
        let mut domain = vec![0u8; domain_len];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read target domain");
        assert_eq!(domain, b"origin.example");
        assert_eq!(stream.read_u16().await.expect("read target port"), 443);
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read request CRLF");
        assert_eq!(crlf, *b"\r\n");
        stream
            .write_all(b"x")
            .await
            .expect("write TLS relayed byte");
    });

    let item: OutboundItem = serde_json::from_value(serde_json::json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "address": server_addr.ip().to_string(),
            "port": server_addr.port(),
            "password": "secret"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "disableSystemRoot": true,
                "certificates": [{
                    "certificate": [certificate_pem],
                    "usage": "verify"
                }]
            }
        }
    }))
    .expect("parse Trojan TLS outbound");
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![compile_static_outbound(&item).expect("compile Trojan TLS outbound")],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile Trojan TLS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("Trojan TLS routed TCP connect")
    .expect("Trojan TLS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(stream.read_u8().await.expect("read TLS relayed byte"), b'x');
    server.await.expect("fake Trojan TLS server task");
}

#[tokio::test]
async fn routed_tcp_connection_uses_socks_outbound_and_preserves_domain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake SOCKS server");
    let server_addr = listener.local_addr().expect("fake SOCKS address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept SOCKS client");
        let mut greeting = [0u8; 3];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("read greeting");
        assert_eq!(greeting, [0x05, 0x01, 0x02]);
        stream.write_all(&[0x05, 0x02]).await.expect("write method");

        let version = stream.read_u8().await.expect("read auth version");
        let username_len =
            stream.read_u8().await.expect("read username length") as usize;
        let mut username = vec![0u8; username_len];
        stream
            .read_exact(&mut username)
            .await
            .expect("read username");
        let password_len =
            stream.read_u8().await.expect("read password length") as usize;
        let mut password = vec![0u8; password_len];
        stream
            .read_exact(&mut password)
            .await
            .expect("read password");
        assert_eq!(version, 0x01);
        assert_eq!(username, b"alice");
        assert_eq!(password, b"secret");
        stream
            .write_all(&[0x01, 0x00])
            .await
            .expect("write auth result");

        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("read CONNECT header");
        assert_eq!(request, [0x05, 0x01, 0x00, 0x03]);
        let domain_len =
            stream.read_u8().await.expect("read target domain length") as usize;
        let mut domain = vec![0u8; domain_len];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read target domain");
        let port = stream.read_u16().await.expect("read target port");
        assert_eq!(domain, b"origin.example");
        assert_eq!(port, 443);
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .expect("write CONNECT result");
        stream.write_all(b"x").await.expect("write relay byte");
    });

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![socks_outbound(
            "proxy",
            server_addr,
            Some("alice"),
            Some("secret"),
        )],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["edge".into()],
                outbound_tag: Some("proxy".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("compile SOCKS route"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_str("origin.example:443", None).unwrap();
    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "edge",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("SOCKS routed TCP connect")
    .expect("SOCKS route should not blackhole");
    assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
    let mut stream = connection.stream;
    assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
    server.await.expect("fake SOCKS server task");
}

#[test]
fn tcp_connect_observation_is_a_pure_result_projection() {
    let success = tcp_connect_observation(true, 12, 100, String::new());
    assert!(success.alive);
    assert_eq!(success.delay_ms, 12);
    assert_eq!(success.last_seen_time, 100);
    assert_eq!(success.last_try_time, 100);
    assert!(success.last_error_reason.is_empty());

    let failure = tcp_connect_observation(false, 34, 200, "refused".into());
    assert!(!failure.alive);
    assert_eq!(failure.delay_ms, 34);
    assert_eq!(failure.last_seen_time, 0);
    assert_eq!(failure.last_try_time, 200);
    assert_eq!(failure.last_error_reason, "refused");
}

#[test]
fn direct_outbound_defaults_to_implicit_freedom() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());

    assert_eq!(
        select_direct_outbound(
            &runtime.data_plane(),
            &RoutingInput::default(),
            "tcp"
        )
        .unwrap(),
        DirectOutboundAction::Freedom { tag: None }
    );
}

#[test]
fn direct_outbound_rejects_unsupported_protocol() {
    let runtime = RuntimeState::new(Vec::new(), vec![outbound("proxy", "vmess")]);

    let err = select_direct_outbound(
        &runtime.data_plane(),
        &RoutingInput::default(),
        "tcp",
    )
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "tcp outbound proxy uses unsupported protocol vmess"
    );
}

#[test]
fn direct_outbound_rejects_missing_routed_outbound() {
    let runtime = RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("missing".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("missing outbound routing rule should compile"),
    );

    let error = select_direct_outbound(
        &runtime.data_plane(),
        &RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        },
        "tcp",
    )
    .expect_err("missing routed outbound must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("missing outbound missing"));
}

#[test]
fn direct_outbound_rejects_empty_balancer_without_falling_back() {
    let runtime = RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("empty".into()),
                ..RuleConfig::default()
            }],
            balancers: vec![BalancerConfig {
                tag: "empty".into(),
                outbound_selector: vec!["missing-prefix".into()],
                strategy: Default::default(),
                fallback_tag: None,
            }],
            ..RoutingConfig::default()
        }))
        .expect("empty balancer routing rule should compile"),
    );

    let error = select_direct_outbound(
        &runtime.data_plane(),
        &RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        },
        "tcp",
    )
    .expect_err("empty routed balancer must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("balancer empty has no available outbound")
    );
}

#[test]
fn direct_outbound_routes_by_authenticated_user() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                user: vec!["alice".into()],
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .unwrap(),
    );
    let input = connection_routing_input(
        "quic-in",
        "alice",
        2,
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
        &NetLocation::from_str("example.com:443", None).unwrap(),
    );

    assert_eq!(
        select_direct_outbound(&runtime.data_plane(), &input, "tcp").unwrap(),
        DirectOutboundAction::Blackhole {
            tag: "blocked".into()
        }
    );
    assert_eq!(input.source_port, 12345);
    assert_eq!(input.target_domain, "example.com");
}

#[tokio::test]
async fn as_is_domain_match_does_not_resolve_before_routing() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            domain_strategy: Some("AsIs".into()),
            rules: vec![RuleConfig {
                domain: vec!["full:example.test".into()],
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("AsIs routing config"),
    );
    let counting = CountingResolver::new(vec!["203.0.113.1:443".parse().unwrap()]);
    let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
    let target = NetLocation::from_str("example.test:443", None).unwrap();

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "in",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("domain rule should route without DNS");

    assert!(connection.is_none());
    assert_eq!(counting.calls(), 0);
}

#[tokio::test]
async fn ip_if_non_match_resolves_after_domain_miss_and_matches_any_ip() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            domain_strategy: Some("IpIfNonMatch".into()),
            rules: vec![
                RuleConfig {
                    domain: vec!["full:other.test".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    ip: vec!["203.0.113.2/32".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                },
            ],
            ..RoutingConfig::default()
        }))
        .expect("IpIfNonMatch routing config"),
    );
    let counting = CountingResolver::new(vec![
        "198.51.100.1:443".parse().unwrap(),
        "203.0.113.2:443".parse().unwrap(),
    ]);
    let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
    let target = NetLocation::from_str("example.test:443", None).unwrap();

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "in",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("resolved IP rule should route");

    assert!(connection.is_none());
    assert_eq!(counting.calls(), 1);
}

#[tokio::test]
async fn ip_on_demand_skips_resolution_when_earlier_domain_rule_matches() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            domain_strategy: Some("IpOnDemand".into()),
            rules: vec![
                RuleConfig {
                    domain: vec!["full:example.test".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    ip: vec!["203.0.113.2/32".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                },
            ],
            ..RoutingConfig::default()
        }))
        .expect("IpOnDemand routing config"),
    );
    let counting = CountingResolver::new(vec!["203.0.113.2:443".parse().unwrap()]);
    let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
    let target = NetLocation::from_str("example.test:443", None).unwrap();

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "in",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("earlier domain rule should avoid DNS");

    assert!(connection.is_none());
    assert_eq!(counting.calls(), 0);
}

#[tokio::test]
async fn ip_on_demand_resolves_when_reachable_rule_requires_target_ip() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            domain_strategy: Some("IpOnDemand".into()),
            rules: vec![RuleConfig {
                ip: vec!["203.0.113.2/32".into()],
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("IpOnDemand routing config"),
    );
    let counting = CountingResolver::new(vec![
        "198.51.100.1:443".parse().unwrap(),
        "203.0.113.2:443".parse().unwrap(),
    ]);
    let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
    let target = NetLocation::from_str("example.test:443", None).unwrap();

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "in",
        "",
        "192.0.2.10:12345".parse().unwrap(),
    )
    .await
    .expect("on-demand IP rule should route");

    assert!(connection.is_none());
    assert_eq!(counting.calls(), 1);
}

#[tokio::test]
async fn tcp_outbound_records_successful_observation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observed target");
    let target_addr = listener.local_addr().expect("observed target address");
    let runtime = RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "observed-in",
        "",
        "127.0.0.1:12345".parse().unwrap(),
    )
    .await
    .expect("observed connection should succeed");
    assert!(connection.is_some());

    let observations = runtime.outbound_observations();
    let status = observations.get("direct").expect("observation missing");
    assert!(status.alive);
    assert!(status.last_seen_time > 0);
    assert_eq!(status.last_error_reason, "");
}

#[tokio::test]
async fn tcp_outbound_records_failed_observation() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve failed target port");
    let target_addr = listener.local_addr().expect("failed target address");
    drop(listener);
    let runtime = RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

    if connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "observed-in",
        "",
        "127.0.0.1:12345".parse().unwrap(),
    )
    .await
    .is_ok()
    {
        panic!("connection to released port should fail");
    }

    let observations = runtime.outbound_observations();
    let status = observations
        .get("direct")
        .expect("failure observation missing");
    assert!(!status.alive);
    assert!(status.last_try_time > 0);
    assert!(!status.last_error_reason.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tcp_outbound_routes_by_local_process() {
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind process routing inbound listener");
    let client = tokio::net::TcpStream::connect(
        inbound_listener.local_addr().expect("inbound address"),
    );
    let (client, accepted) = tokio::join!(client, inbound_listener.accept());
    let _client = client.expect("connect local process client");
    let (_accepted, source_addr) = accepted.expect("accept local process client");
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind process routing target");
    let target_addr = target_listener.local_addr().expect("target address");
    let process_name = std::env::current_exe()
        .expect("current executable")
        .file_name()
        .expect("current executable name")
        .to_string_lossy()
        .into_owned();

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ],
    );
    runtime.replace_routing(
        RoutingState::from_config(Some(&RoutingConfig {
            rules: vec![RuleConfig {
                process: vec![process_name],
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        }))
        .expect("process routing should build"),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

    let connection = connect_tcp_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        "process-in",
        "",
        source_addr,
    )
    .await
    .expect("process-routed outbound selection should succeed");

    assert!(
        connection.is_none(),
        "process route should select blackhole"
    );
}
