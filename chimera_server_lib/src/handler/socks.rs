use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::{HttpUser, SocksUser, SocksUserStore},
    handler::{
        http::HttpTcpServerHandler,
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
    },
    traffic::TrafficContext,
    util::prefixed_stream::PrefixedStream,
};

mod udp_session;

pub(crate) use udp_session::run_udp_relay_with_expected_client;
#[cfg(test)]
use udp_session::{
    SocksUdpClientSession, XrayUdpActivityWindow, prune_closed_udp_sessions,
    run_shared_udp_relay, run_udp_relay, send_udp_target_payload,
};

const SOCKS4_VERSION: u8 = 0x04;
const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_REJECT: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const CMD_TOR_RESOLVE: u8 = 0xf0;
const CMD_TOR_RESOLVE_PTR: u8 = 0xf1;
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS4_REQUEST_GRANTED: u8 = 90;
const SOCKS4_REQUEST_REJECTED: u8 = 91;
const XRAY_SOCKS4_NULL_FIELD_SIZE: usize = 8192;
// Xray v26.2.6 transport/internet/udp uses a one-minute ActivityTimer. The
// timer starts with one activity token and only downstream reads refresh it;
// uplink writes do not. With no later response, a new mapping therefore closes
// on the second one-minute check.
const UDP_TARGET_SESSION_ACTIVITY_CHECK: Duration = Duration::from_secs(60);

const SUCCESS_RESPONSE: [u8; 10] = [
    SOCKS_VERSION,
    REP_SUCCEEDED,
    0x00,
    ADDR_TYPE_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];

const UDP_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const XRAY_SOCKS_UDP_PACKET_SIZE: usize = 8 * 1024;
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    accounts: SocksUserStore,
    inbound_tag: String,
    udp_enabled: bool,
    udp_response_ip: Option<String>,
    user_level: u32,
}

impl SocksTcpServerHandler {
    pub fn new(
        accounts: SocksUserStore,
        inbound_tag: &str,
        udp_enabled: bool,
        udp_response_ip: Option<String>,
    ) -> Self {
        Self {
            accounts,
            inbound_tag: inbound_tag.to_string(),
            udp_enabled,
            udp_response_ip,
            user_level: 0,
        }
    }

    pub fn with_user_level(mut self, user_level: u32) -> Self {
        self.user_level = user_level;
        self
    }

    fn requires_auth(&self) -> bool {
        self.accounts.auth_required()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksMethod {
    NoAuth,
    UsernamePassword,
}

impl SocksMethod {
    fn code(self) -> u8 {
        match self {
            SocksMethod::NoAuth => METHOD_NO_AUTH,
            SocksMethod::UsernamePassword => METHOD_USERNAME_PASSWORD,
        }
    }
}

impl SocksTcpServerHandler {
    async fn setup_server_stream_inner(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        listener_addr: Option<SocketAddr>,
        handshake_timeout: Option<Duration>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let version = server_stream.read_u8().await?;
        if version != SOCKS4_VERSION && version != SOCKS_VERSION {
            // Xray's SOCKS inbound doubles as an HTTP proxy: any connection
            // whose first byte is neither SOCKS4 nor SOCKS5 is replayed into
            // the HTTP parser. HTTP authentication follows authType, not merely
            // the presence of configured accounts.
            let http_accounts = if self.requires_auth() {
                self.accounts
                    .snapshot()
                    .into_iter()
                    .map(|account| HttpUser {
                        username: account.username,
                        password: account.password,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let stream: Box<dyn AsyncStream> =
                Box::new(PrefixedStream::new(vec![version], server_stream));
            return HttpTcpServerHandler::new(
                http_accounts,
                false,
                &self.inbound_tag,
            )
            .setup_server_stream(stream)
            .await;
        }

        let handshake = async {
            if version == SOCKS4_VERSION {
                return setup_socks4_stream(
                    server_stream,
                    self.requires_auth(),
                    &self.inbound_tag,
                    self.user_level,
                )
                .await;
            }

            let mut server_stream = server_stream;
            let method =
                negotiate_method(&mut server_stream, self.requires_auth()).await?;

            let mut identity = None;
            if method == SocksMethod::UsernamePassword {
                let accounts = self.accounts.snapshot();
                identity = Some(authenticate(&accounts, &mut server_stream).await?)
                    .filter(|s| !s.is_empty());
            }

            // Xray v26.2.6 reads the complete SOCKS5 VER/CMD/RSV triplet before
            // dispatching the command, but only uses CMD. Keep the negotiated
            // SOCKS version authoritative while preserving that read timing.
            let _request_version = server_stream.read_u8().await?;
            let command = server_stream.read_u8().await?;
            let _reserved = server_stream.read_u8().await?;

            let traffic_context = Some(match identity {
                Some(id) => TrafficContext::new("socks")
                    .with_identity(id)
                    .with_inbound_tag(self.inbound_tag.clone())
                    .with_user_level(self.user_level),
                None => TrafficContext::new("socks")
                    .with_inbound_tag(self.inbound_tag.clone())
                    .with_user_level(self.user_level),
            });

            match command {
                CMD_CONNECT | CMD_TOR_RESOLVE | CMD_TOR_RESOLVE_PTR => {
                    let remote_location =
                        read_socks_address(&mut server_stream).await?;
                    // Xray v26.2.6 writes the SOCKS5 success response as part of
                    // the inbound handshake, before routing or outbound dialing.
                    // Preserve that observable timing even if the target later
                    // fails to connect.
                    let response = build_socks5_response(
                        REP_SUCCEEDED,
                        listener_addr.or(local_addr),
                    );
                    server_stream.write_all(&response).await?;
                    server_stream.flush().await?;

                    Ok(TcpServerSetupResult::TcpForward {
                        remote_location,
                        stream: server_stream,
                        need_initial_flush: false,
                        connection_success_response: None,
                        traffic_context,
                    })
                }
                CMD_UDP_ASSOCIATE if self.udp_enabled => {
                    handle_udp_associate(
                        server_stream,
                        traffic_context,
                        peer_addr,
                        local_addr.map(|addr| addr.ip()),
                        listener_addr,
                        self.udp_response_ip.clone(),
                        self.user_level,
                    )
                    .await
                }
                CMD_UDP_ASSOCIATE => {
                    send_command_response(
                        &mut server_stream,
                        REP_COMMAND_NOT_SUPPORTED,
                    )
                    .await?;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "socks udp associate is disabled by config",
                    ))
                }
                _ => {
                    send_command_response(
                        &mut server_stream,
                        REP_COMMAND_NOT_SUPPORTED,
                    )
                    .await?;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsupported socks command: {}", command),
                    ))
                }
            }
        };

        match handshake_timeout {
            Some(timeout) => tokio::time::timeout(timeout, handshake)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SOCKS handshake timed out",
                    )
                })?,
            None => handshake.await,
        }
    }
}

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        true
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_inner(server_stream, None, None, None, None)
            .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let handshake_timeout = context.inbound_handshake_runtime().map(|runtime| {
            runtime.xray_handshake_timeout_for_level(self.user_level)
        });
        self.setup_server_stream_inner(
            server_stream,
            context.peer_addr,
            context.local_addr,
            context.listener_addr,
            handshake_timeout,
        )
        .await
    }
}

async fn setup_socks4_stream(
    mut stream: Box<dyn AsyncStream>,
    auth_required: bool,
    inbound_tag: &str,
    user_level: u32,
) -> std::io::Result<TcpServerSetupResult> {
    let command = stream.read_u8().await?;
    if auth_required {
        send_socks4_response(&mut stream, SOCKS4_REQUEST_REJECTED).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socks4 is not allowed when username/password auth is required",
        ));
    }

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let mut address_bytes = [0u8; 4];
    stream.read_exact(&mut address_bytes).await?;

    let _user_id = read_until_null(&mut stream).await?;

    let address = if address_bytes[0] == 0 {
        let domain = read_until_null(&mut stream).await?;
        let domain = std::str::from_utf8(&domain).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode SOCKS4a domain: {error}"),
            )
        })?;
        parse_xray_socks4a_address(domain)
    } else {
        Address::Ipv4(std::net::Ipv4Addr::from(address_bytes))
    };

    if command != CMD_CONNECT {
        send_socks4_response(&mut stream, SOCKS4_REQUEST_REJECTED).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported socks4 command: {command}"),
        ));
    }

    send_socks4_response(&mut stream, SOCKS4_REQUEST_GRANTED).await?;
    Ok(TcpServerSetupResult::TcpForward {
        remote_location: NetLocation::new(address, port),
        stream,
        need_initial_flush: false,
        connection_success_response: None,
        traffic_context: Some(
            TrafficContext::new("socks")
                .with_inbound_tag(inbound_tag.to_string())
                .with_user_level(user_level),
        ),
    })
}

async fn read_until_null(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            return Ok(bytes);
        }
        bytes.push(byte);
        if bytes.len() >= XRAY_SOCKS4_NULL_FIELD_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS4 null-terminated field exceeds Xray buffer size",
            ));
        }
    }
}

async fn send_socks4_response(
    stream: &mut Box<dyn AsyncStream>,
    status: u8,
) -> std::io::Result<()> {
    stream
        .write_all(&[0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
}

async fn negotiate_method(
    stream: &mut Box<dyn AsyncStream>,
    has_accounts: bool,
) -> std::io::Result<SocksMethod> {
    let method_len = stream.read_u8().await? as usize;
    if method_len == 0 {
        send_method_response(stream, METHOD_REJECT).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "client did not provide authentication methods",
        ));
    }

    let mut methods = vec![0u8; method_len];
    stream.read_exact(&mut methods).await?;

    let supports_no_auth = methods.contains(&METHOD_NO_AUTH);
    let supports_password = methods.contains(&METHOD_USERNAME_PASSWORD);

    let selected = if has_accounts {
        if supports_password {
            SocksMethod::UsernamePassword
        } else {
            send_method_response(stream, METHOD_REJECT).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "username/password auth required",
            ));
        }
    } else if supports_no_auth {
        SocksMethod::NoAuth
    } else {
        send_method_response(stream, METHOD_REJECT).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no supported authentication method",
        ));
    };

    send_method_response(stream, selected.code()).await?;
    Ok(selected)
}

async fn authenticate(
    accounts: &[SocksUser],
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<String> {
    // Xray v26.2.6's ReadUsernamePassword reads but does not validate the
    // RFC 1929 subnegotiation version byte. Keep method negotiation strict,
    // but accept any auth message version once username/password was selected.
    let _version = stream.read_u8().await?;

    let username_len = stream.read_u8().await? as usize;
    let mut username_buf = vec![0u8; username_len];
    stream.read_exact(&mut username_buf).await?;
    let password_len = stream.read_u8().await? as usize;
    let mut password_buf = vec![0u8; password_len];
    stream.read_exact(&mut password_buf).await?;

    if let Some(account) = accounts.iter().find(|account| {
        let username_match = account.username.as_bytes().ct_eq(&username_buf);
        let password_match = account.password.as_bytes().ct_eq(&password_buf);
        (username_match & password_match).unwrap_u8() == 1
    }) {
        send_username_auth_status(stream, 0x00).await?;
        Ok(account.username.clone())
    } else {
        // Xray v26.2.6 reports credential mismatch with RFC 1929 status 0xFF.
        send_username_auth_status(stream, 0xff).await?;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid socks username/password",
        ))
    }
}

/// Read the address portion of a SOCKS5 request: ATYP + DST.ADDR + DST.PORT.
async fn read_socks_address(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<NetLocation> {
    read_address_from_stream(stream).await
}

/// Read ATYP + DST.ADDR + DST.PORT from the stream
async fn read_address_from_stream(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<NetLocation> {
    let address_type = stream.read_u8().await?;
    let remote_location = match address_type {
        ADDR_TYPE_IPV4 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let ipv4 = std::net::Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            );
            NetLocation::new(Address::Ipv4(ipv4), u16::from_be_bytes(port_bytes))
        }
        ADDR_TYPE_IPV6 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let address = xray_ip_address(std::net::Ipv6Addr::from(address).into());
            NetLocation::new(address, u16::from_be_bytes(port_bytes))
        }
        ADDR_TYPE_DOMAIN => {
            let domain_len = stream.read_u8().await? as usize;
            if domain_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid domain length",
                ));
            }

            let mut domain = vec![0u8; domain_len];
            stream.read_exact(&mut domain).await?;
            let domain_str = match std::str::from_utf8(&domain) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("failed to decode domain name: {}", e),
                    ));
                }
            };

            let address = parse_xray_socks_domain_address(domain_str)?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            NetLocation::new(address, port)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown address type: {}", address_type),
            ));
        }
    };

    Ok(remote_location)
}

/// Handle SOCKS5 UDP ASSOCIATE command.
///
/// Takes ownership of `server_stream` while the UDP relay task is active.
async fn handle_udp_associate(
    mut server_stream: Box<dyn AsyncStream>,
    traffic_context: Option<TrafficContext>,
    peer_addr: Option<SocketAddr>,
    response_default_ip: Option<std::net::IpAddr>,
    _listener_addr: Option<SocketAddr>,
    udp_response_ip: Option<String>,
    user_level: u32,
) -> std::io::Result<TcpServerSetupResult> {
    let client_hint = read_socks_address(&mut server_stream).await?;
    let (hint_address, hint_port) = client_hint.components();
    let expected_client = match hint_address {
        Address::Ipv4(ip) if !ip.is_unspecified() => {
            SocketAddr::new((*ip).into(), hint_port)
        }
        Address::Ipv6(ip) if !ip.is_unspecified() => {
            SocketAddr::new((*ip).into(), hint_port)
        }
        Address::Ipv4(_) | Address::Ipv6(_) | Address::Hostname(_) => {
            SocketAddr::new(
                peer_addr.map_or(std::net::Ipv4Addr::UNSPECIFIED.into(), |addr| {
                    addr.ip()
                }),
                0,
            )
        }
    };

    let default_ip = response_default_ip
        .or_else(|| peer_addr.map(|addr| addr.ip()))
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    let response_address = match udp_response_ip {
        Some(address) => Address::from(&address)?,
        None => xray_ip_address(default_ip),
    };
    let bind_ip = match &response_address {
        Address::Ipv4(ip) if !ip.is_unspecified() => (*ip).into(),
        Address::Ipv6(ip) if !ip.is_unspecified() => (*ip).into(),
        _ => default_ip,
    };
    let udp_socket =
        Arc::new(tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    let response_port = udp_socket.local_addr()?.port();
    let response = build_udp_associate_response(&response_address, response_port)?;
    server_stream.write_all(&response).await?;
    server_stream.flush().await?;

    Ok(TcpServerSetupResult::UdpAssociate {
        stream: server_stream,
        udp_socket,
        expected_client,
        user_level,
        traffic_context,
    })
}

/// Build a SOCKS5 UDP ASSOCIATE success response.
fn build_udp_associate_response(
    address: &Address,
    port: u16,
) -> std::io::Result<Vec<u8>> {
    let mut response = vec![SOCKS_VERSION, REP_SUCCEEDED, 0x00];

    match address {
        Address::Ipv4(ip) => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            response.push(ADDR_TYPE_IPV6);
            response.extend_from_slice(&ip.octets());
        }
        Address::Hostname(hostname) => {
            // Xray v26.2.6's AddressParser rejects domains longer than 256 bytes
            // when serializing the UDP ASSOCIATE response. It still permits the
            // 256-byte edge case, whose one-byte length field wraps to zero.
            if hostname.len() > 256 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS5 UDP response domain exceeds Xray address limit",
                ));
            }
            response.push(ADDR_TYPE_DOMAIN);
            response.push(hostname.len() as u8);
            response.extend_from_slice(hostname.as_bytes());
        }
    }
    response.extend_from_slice(&port.to_be_bytes());
    Ok(response)
}

/// Run the UDP ASSOCIATE relay.
///
/// 1. Forwards SOCKS5 UDP datagrams to their targets
/// 2. Returns responses back to the client
/// 3. Monitors the TCP connection for termination
///
/// When the TCP connection closes, the UDP relay is terminated.
/// Parse a SOCKS5 UDP address starting at `offset` in `data`.
/// Returns (target location, offset after the address+port).
fn parse_udp_address(
    data: &[u8],
    offset: usize,
) -> std::io::Result<(NetLocation, usize)> {
    if offset >= data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no address type",
        ));
    }

    let addr_type = data[offset];
    match addr_type {
        ADDR_TYPE_IPV4 => {
            if data.len() < offset + 1 + 4 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated IPv4 address",
                ));
            }
            let ip = std::net::Ipv4Addr::new(
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            );
            let port = u16::from_be_bytes([data[offset + 5], data[offset + 6]]);
            Ok((
                NetLocation::new(Address::Ipv4(ip), port),
                offset + 1 + 4 + 2,
            ))
        }
        ADDR_TYPE_IPV6 => {
            if data.len() < offset + 1 + 16 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated IPv6 address",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset + 1..offset + 17]);
            let address = xray_ip_address(std::net::Ipv6Addr::from(octets).into());
            let port = u16::from_be_bytes([data[offset + 17], data[offset + 18]]);
            Ok((NetLocation::new(address, port), offset + 1 + 16 + 2))
        }
        ADDR_TYPE_DOMAIN => {
            if offset + 1 >= data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated domain length",
                ));
            }
            let domain_len = data[offset + 1] as usize;
            if data.len() < offset + 1 + 1 + domain_len + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated domain address",
                ));
            }
            let domain_bytes = &data[offset + 2..offset + 2 + domain_len];
            let domain_str = std::str::from_utf8(domain_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid domain name",
                )
            })?;
            let address = parse_xray_socks_domain_address(domain_str)?;
            let port = u16::from_be_bytes([
                data[offset + 2 + domain_len],
                data[offset + 2 + domain_len + 1],
            ]);
            Ok((
                NetLocation::new(address, port),
                offset + 1 + 1 + domain_len + 2,
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown address type: {}", addr_type),
        )),
    }
}

fn xray_ip_address(ip: std::net::IpAddr) -> Address {
    match ip {
        std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
        std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => Address::Ipv4(ip),
            None => Address::Ipv6(ip),
        },
    }
}

fn parse_xray_socks4a_address(domain: &str) -> Address {
    let mut value = domain;
    if value.starts_with('[') && value.ends_with(']') && value.len() >= 2 {
        value = &value[1..value.len() - 1];
    }
    if value
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || value
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        value = value.trim();
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return xray_ip_address(ip);
    }
    Address::Hostname(value.to_string())
}

fn parse_xray_socks_domain_address(domain: &str) -> std::io::Result<Address> {
    let maybe_ip = if domain.starts_with('[') {
        domain
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .map(str::trim)
    } else if domain.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        Some(domain.trim())
    } else {
        None
    };
    if let Some(value) = maybe_ip
        && let Ok(ip) = value.parse::<std::net::IpAddr>()
    {
        return Ok(xray_ip_address(ip));
    }

    validate_socks5_domain(domain)?;
    Address::from(domain)
}

fn validate_socks5_domain(domain: &str) -> std::io::Result<()> {
    if domain.is_empty()
        || !domain.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid SOCKS5 domain name: {domain}"),
        ));
    }
    Ok(())
}

/// Build a SOCKS5 UDP response header from the response source address.
fn build_udp_response_header(src_addr: SocketAddr) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00]; // RSV + FRAG=0

    match src_addr {
        SocketAddr::V4(v4) => {
            header.push(ADDR_TYPE_IPV4);
            header.extend_from_slice(&v4.ip().octets());
            header.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            header.push(ADDR_TYPE_IPV6);
            header.extend_from_slice(&v6.ip().octets());
            header.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    header
}

fn build_udp_response_packet(src_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut response = build_udp_response_header(src_addr);
    if response.len().saturating_add(payload.len()) > XRAY_SOCKS_UDP_PACKET_SIZE {
        // Xray encodes SOCKS UDP responses into an 8 KiB buf.Buffer. Oversized
        // payloads clear that buffer, producing a zero-length UDP datagram.
        response.clear();
        return response;
    }
    response.extend_from_slice(payload);
    response
}

#[cfg(feature = "trojan")]
fn build_udp_response_packet_location(
    source: &NetLocation,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    if let Some(source) = source.to_socket_addr_nonblocking() {
        return Ok(build_udp_response_packet(source, payload));
    }

    let Address::Hostname(domain) = source.address() else {
        unreachable!("non-socket SOCKS UDP source must be a hostname")
    };
    let bytes = domain.as_bytes();
    if bytes.is_empty() || bytes.len() > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 UDP response domain must contain 1..=255 bytes",
        ));
    }
    let mut response = Vec::with_capacity(7 + bytes.len() + payload.len());
    response.extend_from_slice(&[0x00, 0x00, 0x00, ADDR_TYPE_DOMAIN]);
    response.push(bytes.len() as u8);
    response.extend_from_slice(bytes);
    response.extend_from_slice(&source.port().to_be_bytes());
    if response.len().saturating_add(payload.len()) > XRAY_SOCKS_UDP_PACKET_SIZE {
        response.clear();
        return Ok(response);
    }
    response.extend_from_slice(payload);
    Ok(response)
}

/// Create a UDP socket for forwarding to the target address.
/// Uses the same address family as the target.
fn create_udp_socket_for_target(
    target_addr: &SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    let is_ipv6 = target_addr.is_ipv6();
    let sock = crate::util::socket::new_socket2_udp_socket_with_buffer_size(
        is_ipv6,
        None,
        None,
        false,
        Some(UDP_BUFFER_SIZE),
    )?;
    let std_socket: std::net::UdpSocket = sock.into();
    std_socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_socket)
}

async fn send_method_response(
    stream: &mut Box<dyn AsyncStream>,
    method: u8,
) -> std::io::Result<()> {
    stream.write_all(&[SOCKS_VERSION, method]).await
}

async fn send_username_auth_status(
    stream: &mut Box<dyn AsyncStream>,
    status: u8,
) -> std::io::Result<()> {
    stream.write_all(&[AUTH_VERSION, status]).await
}

fn build_socks5_response(reply: u8, bound_addr: Option<SocketAddr>) -> Vec<u8> {
    let mut response = vec![SOCKS_VERSION, reply, 0x00];
    match bound_addr {
        Some(SocketAddr::V4(addr)) => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            response.push(ADDR_TYPE_IPV6);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    response
}

async fn send_command_response(
    stream: &mut Box<dyn AsyncStream>,
    reply: u8,
) -> std::io::Result<()> {
    stream.write_all(&build_socks5_response(reply, None)).await
}

#[cfg(test)]
mod tests;
