use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock, RwLock},
};

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA224, digest};
use tokio::io::AsyncReadExt;

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::{TrojanFallback, TrojanUser},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    traffic::TrafficContext,
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
    identity: Option<String>,
    user_level: u32,
}

#[derive(Debug)]
struct TrojanUserState {
    users: Vec<TrojanUser>,
    credentials: HashMap<Vec<u8>, TrojanCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrojanUserStoreError {
    EmptyEmail,
    DuplicateEmail(String),
    NotFound(String),
}

#[derive(Debug)]
pub(crate) struct TrojanUserStore {
    state: RwLock<TrojanUserState>,
}

impl TrojanUserStore {
    pub(crate) fn new(users: Vec<TrojanUser>) -> Self {
        let mut credentials = HashMap::with_capacity(users.len());
        for user in &users {
            credentials.insert(
                create_password_hash(&user.password).into_vec(),
                credential_from_user(user),
            );
        }
        Self {
            state: RwLock::new(TrojanUserState { users, credentials }),
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<TrojanUser> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .users
            .clone()
    }

    pub(crate) fn add_user(
        &self,
        user: TrojanUser,
    ) -> Result<(), TrojanUserStoreError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(email) = user.email.as_deref().filter(|email| !email.is_empty())
            && state.users.iter().any(|existing| {
                existing
                    .email
                    .as_deref()
                    .is_some_and(|current| current.eq_ignore_ascii_case(email))
            })
        {
            return Err(TrojanUserStoreError::DuplicateEmail(email.to_string()));
        }
        state.credentials.insert(
            create_password_hash(&user.password).into_vec(),
            credential_from_user(&user),
        );
        state.users.push(user);
        Ok(())
    }

    pub(crate) fn remove_user_by_email(
        &self,
        email: &str,
    ) -> Result<(), TrojanUserStoreError> {
        if email.is_empty() {
            return Err(TrojanUserStoreError::EmptyEmail);
        }
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = state.users.iter().position(|user| {
            user.email
                .as_deref()
                .is_some_and(|current| current.eq_ignore_ascii_case(email))
        }) else {
            return Err(TrojanUserStoreError::NotFound(email.to_string()));
        };
        let user = state.users.swap_remove(index);
        state
            .credentials
            .remove(create_password_hash(&user.password).as_ref());
        Ok(())
    }

    fn credential(&self, password_line: &[u8]) -> Option<TrojanCredential> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credentials
            .get(password_line)
            .cloned()
    }

    fn contains_password_hash(&self, password_line: &[u8]) -> bool {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credentials
            .contains_key(password_line)
    }

    #[cfg(test)]
    fn replace_for_test(&self, users: Vec<TrojanUser>) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.credentials.clear();
        for user in &users {
            state.credentials.insert(
                create_password_hash(&user.password).into_vec(),
                credential_from_user(user),
            );
        }
        state.users = users;
    }
}

fn credential_from_user(user: &TrojanUser) -> TrojanCredential {
    let identity = user
        .email
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if user.password.is_empty() {
                None
            } else {
                Some(user.password.clone())
            }
        });
    TrojanCredential {
        identity,
        user_level: user.user_level,
    }
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    credentials: Arc<TrojanUserStore>,
    runtime_credentials: OnceLock<Arc<TrojanUserStore>>,
    fallbacks: Vec<TrojanFallback>,
    inbound_tag: String,
}

impl TrojanTcpHandler {
    pub fn new(
        users: Vec<TrojanUser>,
        fallbacks: Vec<TrojanFallback>,
        inbound_tag: &str,
    ) -> Self {
        Self {
            credentials: Arc::new(TrojanUserStore::new(users)),
            runtime_credentials: OnceLock::new(),
            fallbacks,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

impl TrojanTcpHandler {
    fn selected_credentials(&self) -> &TrojanUserStore {
        self.runtime_credentials
            .get()
            .map(Arc::as_ref)
            .unwrap_or_else(|| self.credentials.as_ref())
    }

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
                || !self
                    .selected_credentials()
                    .contains_password_hash(&password_line)
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
            .selected_credentials()
            .credential(&password_line)
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

        let traffic_context = credential.identity.as_ref().map(|label| {
            TrafficContext::new("trojan")
                .with_identity(label.clone())
                .with_inbound_tag(self.inbound_tag.clone())
                .with_user_level(credential.user_level)
        });

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
        if let Some(store) = context
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.trojan_user_store(&self.inbound_tag))
        {
            let _ = self.runtime_credentials.set(store);
        }
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

    use crate::{
        async_stream::AsyncPing,
        config::{
            Transport,
            server_config::{ServerConfig, ServerProxyConfig},
        },
        runtime::RuntimeState,
    };

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
                user_level: 0,
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
    async fn runtime_user_store_updates_existing_handler_without_rebuild() {
        let inbound_tag = "trojan-runtime-users";
        let first = TrojanUser {
            password: "first-password".into(),
            email: Some("first-user".into()),
            user_level: 3,
        };
        let second = TrojanUser {
            password: "second-password".into(),
            email: Some("second-user".into()),
            user_level: 7,
        };
        let runtime = RuntimeState::new(
            vec![ServerConfig {
                tag: inbound_tag.to_string(),
                bind_location: crate::address::BindLocation::Address(
                    NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 10001),
                ),
                protocol: ServerProxyConfig::Trojan {
                    users: vec![first.clone()],
                    fallbacks: Vec::new(),
                },
                transport: Transport::Tcp,
                quic_settings: None,
                sniffing: None,
                tcp_socket_policy: None,
            }],
            Vec::new(),
        );
        let handler = TrojanTcpHandler::new(vec![first], Vec::new(), inbound_tag);
        let context = TcpServerConnectionContext {
            runtime: Some(runtime.clone()),
            ..TcpServerConnectionContext::default()
        };

        let request = build_trojan_request(
            "first-password",
            CMD_CONNECT,
            ADDR_TYPE_IPV4,
            &Ipv4Addr::LOCALHOST.octets(),
            443,
        );
        let (mut client, server) = duplex(1024);
        client.write_all(&request).await.unwrap();
        handler
            .setup_server_stream_with_context(
                Box::new(TestStream(server)),
                context.clone(),
            )
            .await
            .expect("initial Trojan user should authenticate");

        runtime
            .trojan_user_store(inbound_tag)
            .expect("single Trojan inbound should expose runtime users")
            .replace_for_test(vec![second]);

        let request = build_trojan_request(
            "second-password",
            CMD_CONNECT,
            ADDR_TYPE_IPV4,
            &Ipv4Addr::LOCALHOST.octets(),
            443,
        );
        let (mut client, server) = duplex(1024);
        client.write_all(&request).await.unwrap();
        let result = handler
            .setup_server_stream_with_context(Box::new(TestStream(server)), context)
            .await
            .expect(
                "new Trojan user should authenticate without rebuilding handler",
            );
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("Trojan TCP request should produce a TCP forward");
        };
        let traffic_context = traffic_context.expect("Trojan traffic context");
        assert_eq!(traffic_context.identity.as_deref(), Some("second-user"));
        assert_eq!(traffic_context.user_level, 7);
    }

    #[test]
    fn runtime_store_matches_xray_email_and_password_index_semantics() {
        let shared_password = "shared-password";
        let store = TrojanUserStore::new(vec![TrojanUser {
            password: shared_password.into(),
            email: Some("first@example.com".into()),
            user_level: 3,
        }]);

        store
            .add_user(TrojanUser {
                password: shared_password.into(),
                email: Some("second@example.com".into()),
                user_level: 7,
            })
            .expect("same password with a distinct email is allowed");
        let hash = create_password_hash(shared_password);
        let credential = store
            .credential(hash.as_ref())
            .expect("last writer should own the shared password hash");
        assert_eq!(credential.identity.as_deref(), Some("second@example.com"));
        assert_eq!(credential.user_level, 7);

        let duplicate = store
            .add_user(TrojanUser {
                password: "other-password".into(),
                email: Some("SECOND@EXAMPLE.COM".into()),
                user_level: 9,
            })
            .expect_err("email uniqueness is case insensitive");
        assert_eq!(
            duplicate,
            TrojanUserStoreError::DuplicateEmail("SECOND@EXAMPLE.COM".into())
        );

        store
            .remove_user_by_email("SECOND@EXAMPLE.COM")
            .expect("removal should be case insensitive");
        assert!(
            store.credential(hash.as_ref()).is_none(),
            "deleting the hash owner must not resurrect an older shared-password user"
        );
        assert_eq!(store.snapshot().len(), 1);
        assert_eq!(
            store.snapshot()[0].email.as_deref(),
            Some("first@example.com")
        );

        store
            .add_user(TrojanUser {
                password: "anonymous-password".into(),
                email: None,
                user_level: 11,
            })
            .expect("Xray permits Trojan users without email");
        assert!(
            store
                .credential(create_password_hash("anonymous-password").as_ref())
                .is_some()
        );
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
                    user_level: 3,
                },
                TrojanUser {
                    password: password_b.into(),
                    email: Some("trojan-user-b".into()),
                    user_level: 7,
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
                3,
            ),
            (
                password_b,
                "trojan-user-b",
                ADDR_TYPE_IPV6,
                ipv6.octets().to_vec(),
                NetLocation::new(Address::Ipv6(ipv6), 443),
                443,
                7,
            ),
            (
                password_a,
                "trojan-user-a",
                ADDR_TYPE_DOMAIN_NAME,
                [vec![12], b"example.test".to_vec()].concat(),
                NetLocation::new(Address::from("example.test").unwrap(), 8443),
                8443,
                3,
            ),
        ];

        for (
            password,
            expected_identity,
            address_type,
            address_payload,
            expected_target,
            port,
            expected_level,
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
            assert_eq!(context.inbound_tag.as_deref(), Some("trojan-connect"));
            assert_eq!(context.user_level, expected_level);
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
                user_level: 5,
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
                assert_eq!(context.inbound_tag.as_deref(), Some("trojan-udp"));
            }
            _ => panic!("Trojan UDP handshake returned a non-UDP result"),
        }
    }
}
