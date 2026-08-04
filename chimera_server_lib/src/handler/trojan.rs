use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use aws_lc_rs::{
    constant_time::verify_slices_are_equal,
    digest::{SHA224, digest},
};
use tokio::io::AsyncReadExt;

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::{TrojanFallback, TrojanUser},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    traffic::{AccessTransport, TrafficContext},
    util::prefixed_stream::PrefixedStream,
};

use super::trojan_udp::TrojanUdpStream;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;
const MAX_PASSWORD_LINE: usize = 128;
const CRLF: [u8; 2] = [0x0d, 0x0a];

type FallbackScore = (u8, usize, u8, u8);
type FallbackSelection<'a> = Option<(&'a TrojanFallback, FallbackScore)>;

#[derive(Debug, Clone)]
struct TrojanCredential {
    password_hash: Box<[u8]>,
    identity: Option<String>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    credentials: Vec<TrojanCredential>,
    fallbacks: Vec<TrojanFallback>,
    inbound_tag: String,
}

impl TrojanTcpHandler {
    pub fn new(
        users: Vec<TrojanUser>,
        fallbacks: Vec<TrojanFallback>,
        inbound_tag: &str,
    ) -> Self {
        let credentials = users
            .into_iter()
            .map(|user| {
                let identity = user.email.filter(|value| !value.is_empty());
                TrojanCredential {
                    password_hash: create_password_hash(&user.password),
                    identity,
                }
            })
            .collect();
        Self {
            credentials,
            fallbacks,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

impl TrojanTcpHandler {
    async fn setup_server_stream_with_metadata(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        server_name: &str,
        alpn: &str,
    ) -> std::io::Result<TcpServerSetupResult> {
        if !self.fallbacks.is_empty() {
            let mut prefix = Vec::with_capacity(512);
            let password_line = match read_line_crlf_with_prefix(
                &mut server_stream,
                MAX_PASSWORD_LINE,
                &mut prefix,
            )
            .await
            {
                Ok(line) => line,
                Err(_) => {
                    let fallback = select_trojan_fallback(
                        &self.fallbacks,
                        server_name,
                        alpn,
                        &prefix,
                    )
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no Trojan fallback matched the unauthenticated request",
                        )
                    })?;
                    return Ok(fallback_forward(fallback, prefix, server_stream));
                }
            };

            if password_line.len() != 56
                || self.credentials.iter().all(|credential| {
                    !credential_matches(credential, &password_line)
                })
            {
                let fallback = select_trojan_fallback(
                    &self.fallbacks,
                    server_name,
                    alpn,
                    &prefix,
                )
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no Trojan fallback matched the unauthenticated request",
                    )
                })?;
                return Ok(fallback_forward(fallback, prefix, server_stream));
            }

            // Authentication looks valid. Replay the complete prefix into the regular
            // Trojan parser so successful requests follow the same parsing path.
            server_stream = Box::new(PrefixedStream::new(prefix, server_stream));
        }

        let password_line =
            read_line_crlf(&mut server_stream, MAX_PASSWORD_LINE).await?;
        if password_line.len() != 56 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid password hash length, expected 56, got {}",
                    password_line.len()
                ),
            ));
        }

        let credential = self
            .credentials
            .iter()
            .find(|credential| credential_matches(credential, &password_line))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "invalid trojan password",
                )
            })?;

        let command = server_stream.read_u8().await?;
        if !matches!(command, CMD_CONNECT | CMD_UDP_ASSOCIATE) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported trojan command: {}", command),
            ));
        }

        let remote_location = read_location(&mut server_stream).await?;

        let mut suffix = [0u8; 2];
        server_stream.read_exact(&mut suffix).await?;
        if suffix != CRLF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid trojan request suffix",
            ));
        }

        let protocol_identity = String::from_utf8(password_line).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trojan password hash is not valid ASCII",
            )
        })?;
        let transport = if command == CMD_UDP_ASSOCIATE {
            AccessTransport::Udp
        } else {
            AccessTransport::Tcp
        };
        let mut traffic_context = TrafficContext::new("trojan")
            .with_protocol_identity(protocol_identity)
            .with_access_target(
                remote_location.address().to_string(),
                remote_location.port(),
                transport,
            )
            .with_inbound_tag(self.inbound_tag.clone());
        if let Some(label) = credential.identity.as_ref() {
            traffic_context = traffic_context.with_identity(label.clone());
        }
        let traffic_context = Some(traffic_context);

        if command == CMD_UDP_ASSOCIATE {
            return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(TrojanUdpStream::new(server_stream)),
                traffic_context,
            });
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_metadata(server_stream, "", "")
            .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_metadata(
            server_stream,
            context.server_name.as_deref().unwrap_or(""),
            context.alpn_protocol.as_deref().unwrap_or(""),
        )
        .await
    }
}

async fn read_line_crlf<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    loop {
        if buf.len() >= max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }

        let byte = stream.read_u8().await?;
        buf.push(byte);
        if byte == b'\n' {
            if buf.len() < 2 || buf[buf.len() - 2] != b'\r' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line is not terminated by CRLF",
                ));
            }
            buf.truncate(buf.len() - 2);
            return Ok(buf);
        }
    }
}

async fn read_line_crlf_with_prefix<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    max_len: usize,
    prefix: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    loop {
        if buf.len() >= max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }

        let byte = stream.read_u8().await?;
        prefix.push(byte);
        buf.push(byte);
        if byte == b'\n' {
            if buf.len() < 2 || buf[buf.len() - 2] != b'\r' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line is not terminated by CRLF",
                ));
            }
            buf.truncate(buf.len() - 2);
            return Ok(buf);
        }
    }
}

async fn read_location(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<NetLocation> {
    let address_type = stream.read_u8().await?;
    match address_type {
        ADDR_TYPE_IPV4 => {
            let mut address_bytes = [0u8; 4];
            stream.read_exact(&mut address_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;

            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );
            let port = u16::from_be_bytes(port_bytes);
            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let mut address_bytes = [0u8; 16];
            stream.read_exact(&mut address_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;

            let v6addr = Ipv6Addr::new(
                u16::from_be_bytes([address_bytes[0], address_bytes[1]]),
                u16::from_be_bytes([address_bytes[2], address_bytes[3]]),
                u16::from_be_bytes([address_bytes[4], address_bytes[5]]),
                u16::from_be_bytes([address_bytes[6], address_bytes[7]]),
                u16::from_be_bytes([address_bytes[8], address_bytes[9]]),
                u16::from_be_bytes([address_bytes[10], address_bytes[11]]),
                u16::from_be_bytes([address_bytes[12], address_bytes[13]]),
                u16::from_be_bytes([address_bytes[14], address_bytes[15]]),
            );
            let port = u16::from_be_bytes(port_bytes);
            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let domain_len = stream.read_u8().await? as usize;
            if domain_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid domain name length",
                ));
            }
            let mut domain_bytes = vec![0u8; domain_len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = std::str::from_utf8(&domain_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to decode domain name: {}", e),
                )
            })?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            Ok(NetLocation::new(Address::from(domain)?, port))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown address type: {}", other),
        )),
    }
}

fn select_trojan_fallback<'a>(
    fallbacks: &'a [TrojanFallback],
    server_name: &str,
    alpn: &str,
    prefix: &[u8],
) -> Option<&'a TrojanFallback> {
    let server_name = server_name.trim().to_ascii_lowercase();
    let alpn = alpn.trim().to_ascii_lowercase();
    let path = extract_http_path(prefix).unwrap_or_default();
    let mut selected: FallbackSelection<'_> = None;
    for fallback in fallbacks {
        let name_score = if fallback.name.is_empty() {
            0
        } else if server_name == fallback.name {
            2
        } else if !server_name.is_empty() && server_name.contains(&fallback.name) {
            1
        } else {
            continue;
        };
        if !fallback.alpn.is_empty() && fallback.alpn != alpn {
            continue;
        }
        if !fallback.path.is_empty() && fallback.path != path {
            continue;
        }
        let score = (
            name_score,
            fallback.name.len(),
            u8::from(!fallback.alpn.is_empty()),
            u8::from(!fallback.path.is_empty()),
        );
        if selected
            .as_ref()
            .is_none_or(|(_, selected_score)| score >= *selected_score)
        {
            selected = Some((fallback, score));
        }
    }
    selected.map(|(fallback, _)| fallback)
}

fn extract_http_path(prefix: &[u8]) -> Option<String> {
    let line_end = prefix
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(prefix.len());
    let line = std::str::from_utf8(&prefix[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty()
        || method.len() >= 8
        || !target.starts_with('/')
        || !version.starts_with("HTTP/")
    {
        return None;
    }
    Some(target.split(['?', '#']).next()?.to_string())
}

fn fallback_forward(
    fallback: &TrojanFallback,
    prefix: Vec<u8>,
    stream: Box<dyn AsyncStream>,
) -> TcpServerSetupResult {
    let stream: Box<dyn AsyncStream> = Box::new(PrefixedStream::new(prefix, stream));
    if fallback.xver == 0 {
        TcpServerSetupResult::TcpForward {
            remote_location: fallback.dest.clone(),
            stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context: None,
        }
    } else {
        TcpServerSetupResult::TcpFallback {
            remote_location: fallback.dest.clone(),
            stream,
            proxy_protocol_version: fallback.xver,
            traffic_context: None,
        }
    }
}

fn credential_matches(credential: &TrojanCredential, password_line: &[u8]) -> bool {
    verify_slices_are_equal(credential.password_hash.as_ref(), password_line).is_ok()
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_bytes = Vec::with_capacity(hash_bytes.len() * 2);
    for byte in hash_bytes.iter().copied() {
        hex_bytes.push(HEX[(byte >> 4) as usize]);
        hex_bytes.push(HEX[(byte & 0x0f) as usize]);
    }
    hex_bytes.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::async_stream::AsyncPing;

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
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

    impl AsyncStream for TestStream {}

    fn handler_with_fallbacks(password: &str, ports: &[u16]) -> TrojanTcpHandler {
        TrojanTcpHandler::new(
            vec![TrojanUser {
                password: password.into(),
                email: Some("fallback-user".into()),
            }],
            ports
                .iter()
                .map(|port| TrojanFallback {
                    name: String::new(),
                    alpn: String::new(),
                    path: String::new(),
                    dest: NetLocation::new(
                        Address::Ipv4(Ipv4Addr::LOCALHOST),
                        *port,
                    ),
                    xver: 0,
                })
                .collect(),
            "trojan-fallback",
        )
    }

    async fn run_fallback_request(
        handler: &TrojanTcpHandler,
        request: &[u8],
    ) -> (NetLocation, Vec<u8>) {
        let (mut client, server) = duplex(4096);
        client
            .write_all(request)
            .await
            .expect("write fallback request");
        client.shutdown().await.expect("close fallback request");

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("fallback request should be accepted");
        match result {
            TcpServerSetupResult::TcpForward {
                remote_location,
                mut stream,
                traffic_context,
                ..
            } => {
                assert!(traffic_context.is_none());
                let mut replayed = Vec::new();
                stream
                    .read_to_end(&mut replayed)
                    .await
                    .expect("read replayed fallback bytes");
                (remote_location, replayed)
            }
            _ => panic!("fallback request returned a non-TCP result"),
        }
    }

    fn fallback_rule(
        name: &str,
        alpn: &str,
        path: &str,
        port: u16,
    ) -> TrojanFallback {
        TrojanFallback {
            name: name.into(),
            alpn: alpn.into(),
            path: path.into(),
            dest: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port),
            xver: 0,
        }
    }

    #[test]
    fn fallback_selection_prefers_name_then_alpn_then_path() {
        let fallbacks = vec![
            fallback_rule("", "", "", 8080),
            fallback_rule("example.com", "", "", 8081),
            fallback_rule("example.com", "h2", "", 8082),
            fallback_rule("example.com", "h2", "/api", 8083),
        ];
        let selected = select_trojan_fallback(
            &fallbacks,
            "edge.example.com",
            "h2",
            b"GET /api?q=1 HTTP/1.1\r\n",
        )
        .expect("matching Trojan fallback");
        assert_eq!(selected.dest.port(), 8083);
    }

    fn build_trojan_request(
        password: &str,
        command: u8,
        address_type: u8,
        address_payload: &[u8],
        port: u16,
    ) -> Vec<u8> {
        let mut request = create_password_hash(password).into_vec();
        request.extend_from_slice(&CRLF);
        request.push(command);
        request.push(address_type);
        request.extend_from_slice(address_payload);
        request.extend_from_slice(&port.to_be_bytes());
        request.extend_from_slice(&CRLF);
        request
    }

    #[tokio::test]
    async fn partial_valid_password_line_replays_every_prefix_to_fallback() {
        let password = "trojan-password";
        let handler = handler_with_fallbacks(password, &[8080]);
        let mut password_line = create_password_hash(password).into_vec();
        password_line.extend_from_slice(&CRLF);

        for prefix_length in 0..password_line.len() {
            let (_, replayed) =
                run_fallback_request(&handler, &password_line[..prefix_length])
                    .await;
            assert_eq!(
                replayed,
                password_line[..prefix_length],
                "password prefix length {prefix_length}"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_request_truncations_do_not_fallback_or_panic() {
        let password = "trojan-password";
        let handler = handler_with_fallbacks(password, &[8080]);
        let full_request = build_trojan_request(
            password,
            CMD_CONNECT,
            ADDR_TYPE_IPV6,
            &Ipv6Addr::LOCALHOST.octets(),
            443,
        );
        let authenticated_prefix_length = create_password_hash(password).len() + 2;

        for prefix_length in authenticated_prefix_length..full_request.len() {
            let (mut client, server) = duplex(1024);
            client
                .write_all(&full_request[..prefix_length])
                .await
                .expect("write truncated authenticated Trojan request");
            client
                .shutdown()
                .await
                .expect("close truncated authenticated Trojan request");

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!(
                    "authenticated Trojan prefix {prefix_length} must not fallback"
                ),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::InvalidData
                ),
                "prefix {prefix_length}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn connect_parses_address_matrix_and_multi_user_identity() {
        let password_a = "trojan-password-a";
        let password_b = "trojan-password-b";
        let handler = TrojanTcpHandler::new(
            vec![
                TrojanUser {
                    password: password_a.into(),
                    email: Some("trojan-user-a".into()),
                },
                TrojanUser {
                    password: password_b.into(),
                    email: Some("trojan-user-b".into()),
                },
            ],
            Vec::new(),
            "trojan-connect",
        );
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let cases = [
            (
                password_a,
                "trojan-user-a",
                ADDR_TYPE_IPV4,
                Ipv4Addr::LOCALHOST.octets().to_vec(),
                NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
                80,
            ),
            (
                password_b,
                "trojan-user-b",
                ADDR_TYPE_IPV6,
                ipv6.octets().to_vec(),
                NetLocation::new(Address::Ipv6(ipv6), 443),
                443,
            ),
            (
                password_a,
                "trojan-user-a",
                ADDR_TYPE_DOMAIN_NAME,
                [vec![12], b"example.test".to_vec()].concat(),
                NetLocation::new(Address::from("example.test").unwrap(), 8443),
                8443,
            ),
        ];

        for (
            password,
            expected_identity,
            address_type,
            address_payload,
            expected_target,
            port,
        ) in cases
        {
            let request = build_trojan_request(
                password,
                CMD_CONNECT,
                address_type,
                &address_payload,
                port,
            );
            let (mut client, server) = duplex(1024);
            client
                .write_all(&request)
                .await
                .expect("write Trojan CONNECT request");

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Trojan CONNECT handshake must succeed");
            let TcpServerSetupResult::TcpForward {
                remote_location,
                traffic_context,
                ..
            } = result
            else {
                panic!("Trojan CONNECT returned a non-TCP result");
            };
            assert_eq!(remote_location, expected_target);
            let context =
                traffic_context.expect("Trojan CONNECT context must exist");
            assert_eq!(context.identity.as_deref(), Some(expected_identity));
            let expected_protocol_identity = create_password_hash(password);
            assert_eq!(
                context.protocol_identity(),
                Some(
                    std::str::from_utf8(&expected_protocol_identity)
                        .expect("Trojan hash must be ASCII")
                )
            );
            let access =
                context.access_context().expect("access context must exist");
            let expected_target_host = expected_target.address().to_string();
            assert_eq!(
                access.target_host.as_deref(),
                Some(expected_target_host.as_str())
            );
            assert_eq!(access.target_port, Some(port));
            assert_eq!(access.transport, AccessTransport::Tcp);
            assert_eq!(context.inbound_tag.as_deref(), Some("trojan-connect"));
        }
    }

    #[tokio::test]
    async fn duplicate_default_fallback_uses_last_definition() {
        let handler = handler_with_fallbacks("trojan-password", &[8080, 8081]);
        let request = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\nbody";

        let (destination, replayed) = run_fallback_request(&handler, request).await;

        assert_eq!(
            destination,
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 8081)
        );
        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn invalid_user_replays_hash_and_remaining_payload() {
        let handler = handler_with_fallbacks("trojan-password", &[8080]);
        let mut request = vec![b'a'; 56];
        request.extend_from_slice(&CRLF);
        request.extend_from_slice(b"payload-after-invalid-user");

        let (_, replayed) = run_fallback_request(&handler, &request).await;

        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn overlong_first_line_replays_consumed_and_unread_bytes() {
        let handler = handler_with_fallbacks("trojan-password", &[8080]);
        let mut request = vec![b'x'; MAX_PASSWORD_LINE];
        request.extend_from_slice(b"remaining-body");

        let (_, replayed) = run_fallback_request(&handler, &request).await;

        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn valid_user_with_invalid_command_does_not_fallback() {
        let password = "trojan-password";
        let handler = handler_with_fallbacks(password, &[8080]);
        let mut request = create_password_hash(password).into_vec();
        request.extend_from_slice(&CRLF);
        request.push(0x7f);

        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write Trojan request");
        client.shutdown().await.expect("close Trojan request");
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("valid authentication with invalid command must fail"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("unsupported trojan command"));
    }

    #[tokio::test]
    async fn udp_associate_returns_multi_directional_stream() {
        let password = "trojan-password";
        let handler = TrojanTcpHandler::new(
            vec![TrojanUser {
                password: password.into(),
                email: Some("udp-user".into()),
            }],
            Vec::new(),
            "trojan-udp",
        );
        let mut request = create_password_hash(password).into_vec();
        request.extend_from_slice(&CRLF);
        request.push(CMD_UDP_ASSOCIATE);
        request.push(ADDR_TYPE_IPV4);
        request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        request.extend_from_slice(&53u16.to_be_bytes());
        request.extend_from_slice(&CRLF);

        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write Trojan request");
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Trojan UDP handshake should succeed");

        match result {
            TcpServerSetupResult::MultiDirectionalUdp {
                traffic_context, ..
            } => {
                let context = traffic_context.expect("Trojan context should exist");
                assert_eq!(context.identity.as_deref(), Some("udp-user"));
                let access =
                    context.access_context().expect("access context must exist");
                assert_eq!(access.target_host.as_deref(), Some("127.0.0.1"));
                assert_eq!(access.target_port, Some(53));
                assert_eq!(access.transport, AccessTransport::Udp);
                assert_eq!(context.inbound_tag.as_deref(), Some("trojan-udp"));
            }
            _ => panic!("Trojan UDP handshake returned a non-UDP result"),
        }
    }
}
