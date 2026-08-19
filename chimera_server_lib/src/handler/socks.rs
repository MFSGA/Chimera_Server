use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

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
    outbound::{
        DirectOutboundAction, connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{TrafficContext, record_transfer, register_connection},
    util::prefixed_stream::PrefixedStream,
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
const UDP_TARGET_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    accounts: SocksUserStore,
    inbound_tag: String,
    udp_enabled: bool,
    udp_bind_ip: Option<std::net::IpAddr>,
}

impl SocksTcpServerHandler {
    pub fn new(
        accounts: SocksUserStore,
        inbound_tag: &str,
        udp_enabled: bool,
        udp_bind_ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            accounts,
            inbound_tag: inbound_tag.to_string(),
            udp_enabled,
            udp_bind_ip,
        }
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
        local_ip: Option<std::net::IpAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let version = server_stream.read_u8().await?;
        if version == SOCKS4_VERSION {
            return setup_socks4_stream(
                server_stream,
                self.requires_auth(),
                &self.inbound_tag,
            )
            .await;
        }
        if version != SOCKS_VERSION {
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

        let method =
            negotiate_method(&mut server_stream, self.requires_auth()).await?;

        let mut identity = None;
        if method == SocksMethod::UsernamePassword {
            let accounts = self.accounts.snapshot();
            identity = Some(authenticate(&accounts, &mut server_stream).await?)
                .filter(|s| !s.is_empty());
        }

        // Xray v26.2.6 reads the SOCKS5 request VER/CMD/RSV triplet but
        // only uses CMD. Keep the negotiated SOCKS version authoritative and
        // mirror that permissive second-stage request parsing.
        let _request_version = server_stream.read_u8().await?;
        let command = server_stream.read_u8().await?;

        let traffic_context = Some(match identity {
            Some(id) => TrafficContext::new("socks")
                .with_identity(id)
                .with_inbound_tag(self.inbound_tag.clone()),
            None => TrafficContext::new("socks")
                .with_inbound_tag(self.inbound_tag.clone()),
        });

        match command {
            CMD_CONNECT | CMD_TOR_RESOLVE | CMD_TOR_RESOLVE_PTR => {
                let remote_location = read_socks_address(&mut server_stream).await?;

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: false,
                    connection_success_response: Some(
                        SUCCESS_RESPONSE.to_vec().into_boxed_slice(),
                    ),
                    traffic_context,
                })
            }
            CMD_UDP_ASSOCIATE if self.udp_enabled => {
                handle_udp_associate(
                    server_stream,
                    traffic_context,
                    self.udp_bind_ip.or(local_ip),
                )
                .await
            }
            CMD_UDP_ASSOCIATE => {
                send_command_response(&mut server_stream, REP_COMMAND_NOT_SUPPORTED)
                    .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "socks udp associate is disabled by config",
                ))
            }
            _ => {
                send_command_response(&mut server_stream, REP_COMMAND_NOT_SUPPORTED)
                    .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported socks command: {}", command),
                ))
            }
        }
    }
}

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_inner(server_stream, None).await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_inner(
            server_stream,
            context.local_addr.map(|addr| addr.ip()),
        )
        .await
    }
}

async fn setup_socks4_stream(
    mut stream: Box<dyn AsyncStream>,
    auth_required: bool,
    inbound_tag: &str,
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
        Address::from(domain)?
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
            TrafficContext::new("socks").with_inbound_tag(inbound_tag.to_string()),
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
        if bytes.len() >= 2048 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS4 null-terminated field exceeds 2048 bytes",
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
    let version = stream.read_u8().await?;
    if version != AUTH_VERSION {
        send_username_auth_status(stream, 0x01).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid auth version: {}", version),
        ));
    }

    let username_len = stream.read_u8().await? as usize;
    let mut username_buf = vec![0u8; username_len];
    stream.read_exact(&mut username_buf).await?;
    let password_len = stream.read_u8().await? as usize;
    let mut password_buf = vec![0u8; password_len];
    stream.read_exact(&mut password_buf).await?;

    let username = String::from_utf8(username_buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to decode username: {}", e),
        )
    })?;
    let password = String::from_utf8(password_buf).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to decode password: {}", e),
        )
    })?;

    if accounts
        .iter()
        .any(|account| account.username == username && account.password == password)
    {
        send_username_auth_status(stream, 0x00).await?;
        Ok(username)
    } else {
        send_username_auth_status(stream, 0x01).await?;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid socks username/password",
        ))
    }
}

/// Read the address portion of a SOCKS5 request: RSV + ATYP + DST.ADDR + DST.PORT
async fn read_socks_address(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<NetLocation> {
    // Xray v26.2.6 ignores the request RSV byte after method negotiation.
    let _reserved = stream.read_u8().await?;
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
            let ipv6 = std::net::Ipv6Addr::new(
                u16::from_be_bytes([address[0], address[1]]),
                u16::from_be_bytes([address[2], address[3]]),
                u16::from_be_bytes([address[4], address[5]]),
                u16::from_be_bytes([address[6], address[7]]),
                u16::from_be_bytes([address[8], address[9]]),
                u16::from_be_bytes([address[10], address[11]]),
                u16::from_be_bytes([address[12], address[13]]),
                u16::from_be_bytes([address[14], address[15]]),
            );
            NetLocation::new(Address::Ipv6(ipv6), u16::from_be_bytes(port_bytes))
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

            let address = parse_socks5_domain_address(domain_str)?;
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
    udp_bind_ip: Option<std::net::IpAddr>,
) -> std::io::Result<TcpServerSetupResult> {
    // Match Xray: a concrete UDP source IP in the ASSOCIATE request is
    // authoritative. Domain or unspecified addresses fall back to the TCP peer.
    let client_hint = read_socks_address(&mut server_stream).await?;
    let client_udp_ip_hint = match client_hint.address() {
        Address::Ipv4(ip) if !ip.is_unspecified() => Some(std::net::IpAddr::V4(*ip)),
        Address::Ipv6(ip) if !ip.is_unspecified() => Some(std::net::IpAddr::V6(*ip)),
        Address::Ipv4(_) | Address::Ipv6(_) | Address::Hostname(_) => None,
    };
    let client_udp_port_hint = client_udp_ip_hint
        .is_some()
        .then_some(client_hint.port())
        .filter(|port| *port != 0);
    tracing::debug!("SOCKS5 UDP ASSOCIATE: client hint = {:?}", client_hint);

    let udp_bind_addr = SocketAddr::new(
        udp_bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        0,
    );
    let udp_socket = crate::util::socket::new_socket2_udp_socket_with_buffer_size(
        udp_bind_addr.is_ipv6(),
        None,
        Some(udp_bind_addr),
        false,
        Some(UDP_BUFFER_SIZE),
    )?;
    let std_socket: std::net::UdpSocket = udp_socket.into();
    std_socket.set_nonblocking(true)?;
    let udp_socket = tokio::net::UdpSocket::from_std(std_socket)?;

    let bound_addr = udp_socket.local_addr()?;
    tracing::info!("SOCKS5 UDP ASSOCIATE: bound UDP relay at {}", bound_addr);

    let response = build_udp_associate_response(bound_addr);
    server_stream.write_all(&response).await?;
    server_stream.flush().await?;

    Ok(TcpServerSetupResult::UdpAssociate {
        stream: server_stream,
        socket: Arc::new(udp_socket),
        client_udp_ip_hint,
        client_udp_port_hint,
        traffic_context,
    })
}

/// Build a SOCKS5 UDP ASSOCIATE success response.
fn build_udp_associate_response(bound_addr: SocketAddr) -> Vec<u8> {
    let mut response = vec![SOCKS_VERSION, REP_SUCCEEDED, 0x00];

    match bound_addr {
        SocketAddr::V4(v4) => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&v4.ip().octets());
            response.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            response.push(ADDR_TYPE_IPV6);
            response.extend_from_slice(&v6.ip().octets());
            response.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    response
}

/// Run the UDP ASSOCIATE relay.
///
/// 1. Forwards SOCKS5 UDP datagrams to their targets
/// 2. Returns responses back to the client
/// 3. Monitors the TCP connection for termination
///
/// When the TCP connection closes, the UDP relay is terminated.
struct SocksUdpTargetSession {
    sender: mpsc::Sender<(Vec<u8>, Option<TrafficContext>)>,
    task: JoinHandle<()>,
}

impl Drop for SocksUdpTargetSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn start_udp_target_session(
    target_addr: SocketAddr,
    client_endpoint: SocketAddr,
    client_socket: Arc<tokio::net::UdpSocket>,
) -> std::io::Result<SocksUdpTargetSession> {
    let target_socket = create_udp_socket_for_target(&target_addr)?;
    let (sender, mut receiver) =
        mpsc::channel::<(Vec<u8>, Option<TrafficContext>)>(32);
    let task = tokio::spawn(async move {
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        let idle = sleep(UDP_TARGET_SESSION_IDLE_TIMEOUT);
        tokio::pin!(idle);
        let mut response_context = None;

        loop {
            tokio::select! {
                message = receiver.recv() => {
                    let Some((payload, traffic_context)) = message else {
                        return;
                    };
                    match target_socket.send_to(&payload, target_addr).await {
                        Ok(sent) => {
                            record_transfer(traffic_context.clone(), sent as u64, 0);
                            response_context = traffic_context;
                            idle.as_mut().reset(Instant::now() + UDP_TARGET_SESSION_IDLE_TIMEOUT);
                        }
                        Err(error) => {
                            tracing::warn!("SOCKS5 UDP relay: failed to send to target: {}", error);
                        }
                    }
                }
                result = target_socket.recv_from(&mut response_buf) => {
                    match result {
                        Ok((resp_len, resp_addr)) => {
                            let socks5_response =
                                build_udp_response_packet(resp_addr, &response_buf[..resp_len]);
                            let forwarded_payload_len = if socks5_response.is_empty() {
                                0
                            } else {
                                resp_len
                            };
                            if let Err(error) = client_socket.send_to(&socks5_response, client_endpoint).await {
                                tracing::warn!(
                                    "SOCKS5 UDP relay: failed to send response to client: {}",
                                    error
                                );
                            } else {
                                record_transfer(
                                    response_context.clone(),
                                    0,
                                    forwarded_payload_len as u64,
                                );
                                idle.as_mut().reset(Instant::now() + UDP_TARGET_SESSION_IDLE_TIMEOUT);
                            }
                        }
                        Err(error) => {
                            tracing::warn!("SOCKS5 UDP relay: failed to receive from target: {}", error);
                            return;
                        }
                    }
                }
                _ = &mut idle => return,
            }
        }
    });

    Ok(SocksUdpTargetSession { sender, task })
}

async fn send_udp_target_payload(
    target_sessions: &mut HashMap<SocketAddr, SocksUdpTargetSession>,
    target_addr: SocketAddr,
    client_endpoint: SocketAddr,
    client_socket: Arc<tokio::net::UdpSocket>,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let message = (payload, traffic_context);
    for attempt in 0..2 {
        if let std::collections::hash_map::Entry::Vacant(entry) =
            target_sessions.entry(target_addr)
        {
            entry.insert(start_udp_target_session(
                target_addr,
                client_endpoint,
                client_socket.clone(),
            )?);
        }

        let sender = &target_sessions
            .get(&target_addr)
            .expect("SOCKS5 UDP target session exists after insertion")
            .sender;
        match sender.send(message.clone()).await {
            Ok(()) => return Ok(()),
            Err(_) if attempt == 0 => {
                target_sessions.remove(&target_addr);
            }
            Err(_) => {
                target_sessions.remove(&target_addr);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "SOCKS5 UDP target session closed before payload was sent",
                ));
            }
        }
    }
    unreachable!("SOCKS5 UDP target payload retry loop is bounded")
}

pub(crate) async fn run_udp_relay(
    udp_socket: Arc<tokio::net::UdpSocket>,
    mut tcp_stream: Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    tcp_peer_addr: SocketAddr,
    client_udp_hint: (Option<std::net::IpAddr>, Option<u16>),
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let udp_socket_clone = udp_socket.clone();
    let _connection_guard = register_connection(traffic_context.as_ref());

    let mut tcp_monitor = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match tcp_stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    });

    // Xray v26.2.6 reads SOCKS UDP packets through an 8 KiB buf.Buffer.
    // Oversized datagrams are truncated to that packet size before decoding.
    let mut recv_buf = vec![0u8; XRAY_SOCKS_UDP_PACKET_SIZE];
    let mut target_sessions = HashMap::<SocketAddr, SocksUdpTargetSession>::new();
    let (client_udp_ip_hint, client_udp_port_hint) = client_udp_hint;
    let expected_client_ip = client_udp_ip_hint.unwrap_or(tcp_peer_addr.ip());
    let mut client_endpoint =
        client_udp_port_hint.map(|port| SocketAddr::new(expected_client_ip, port));

    loop {
        let (len, client_addr) = tokio::select! {
            _ = &mut tcp_monitor => {
                tracing::debug!("SOCKS5 UDP relay: TCP connection closed, terminating");
                return Ok(());
            }
            result = udp_socket_clone.recv_from(&mut recv_buf) => {
                result?
            }
        };

        if client_addr.ip() != expected_client_ip {
            tracing::warn!(
                "SOCKS5 UDP relay ignored datagram from {}; expected source IP {}",
                client_addr,
                expected_client_ip
            );
            continue;
        }
        match client_endpoint {
            Some(expected) if expected != client_addr => {
                tracing::warn!(
                    "SOCKS5 UDP relay ignored datagram from unexpected endpoint {}; expected {}",
                    client_addr,
                    expected
                );
                continue;
            }
            None => client_endpoint = Some(client_addr),
            Some(_) => {}
        }
        let response_endpoint =
            client_endpoint.expect("SOCKS5 UDP endpoint set after validation");
        let data = &recv_buf[..len];

        // Parse SOCKS5 UDP request header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2)
        if data.len() < 4 {
            continue;
        }

        let _rsv = &data[0..2];
        let frag = data[2];

        // We don't support fragmentation; per RFC 1928, drop FRAG != 0
        if frag != 0 {
            continue;
        }

        let (target_location, payload_offset) = match parse_udp_address(data, 3) {
            Ok((location, offset)) => (location, offset),
            Err(_) => continue,
        };

        let payload = &data[payload_offset..];
        let target_addr =
            match resolve_single_address(&resolver, &target_location).await {
                Ok(addr) => addr,
                Err(error) => {
                    tracing::warn!(
                        "SOCKS5 UDP relay: failed to resolve target: {}",
                        error
                    );
                    continue;
                }
            };
        let inbound_tag = traffic_context
            .as_ref()
            .and_then(|context| context.inbound_tag.as_deref())
            .unwrap_or_default();
        let identity = traffic_context
            .as_ref()
            .and_then(|context| context.identity.as_deref())
            .unwrap_or_default();
        let route_input = connection_routing_input(
            inbound_tag,
            identity,
            3,
            client_addr,
            target_addr,
            &target_location,
        );
        let action = select_direct_outbound(&runtime, &route_input, "udp")?;
        let mut datagram_context = traffic_context.clone();
        match action {
            DirectOutboundAction::Blackhole { tag } => {
                datagram_context = datagram_context
                    .map(|context| context.with_outbound_tag(tag.clone()));
                record_transfer(datagram_context, payload.len() as u64, 0);
                tracing::debug!(
                    "SOCKS5 UDP payload dropped by blackhole outbound {}",
                    tag
                );
                continue;
            }
            DirectOutboundAction::Freedom { tag: Some(tag) } => {
                datagram_context =
                    datagram_context.map(|context| context.with_outbound_tag(tag));
            }
            DirectOutboundAction::Freedom { tag: None } => {}
        }

        if let Err(error) = send_udp_target_payload(
            &mut target_sessions,
            target_addr,
            response_endpoint,
            udp_socket_clone.clone(),
            payload.to_vec(),
            datagram_context,
        )
        .await
        {
            tracing::warn!(
                "SOCKS5 UDP relay: failed to send payload to target {}: {}",
                target_addr,
                error
            );
        }
    }
}

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
            let ip = std::net::Ipv6Addr::new(
                u16::from_be_bytes([data[offset + 1], data[offset + 2]]),
                u16::from_be_bytes([data[offset + 3], data[offset + 4]]),
                u16::from_be_bytes([data[offset + 5], data[offset + 6]]),
                u16::from_be_bytes([data[offset + 7], data[offset + 8]]),
                u16::from_be_bytes([data[offset + 9], data[offset + 10]]),
                u16::from_be_bytes([data[offset + 11], data[offset + 12]]),
                u16::from_be_bytes([data[offset + 13], data[offset + 14]]),
                u16::from_be_bytes([data[offset + 15], data[offset + 16]]),
            );
            let port = u16::from_be_bytes([data[offset + 17], data[offset + 18]]);
            Ok((
                NetLocation::new(Address::Ipv6(ip), port),
                offset + 1 + 16 + 2,
            ))
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
            let address = parse_socks5_domain_address(domain_str)?;
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

fn parse_socks5_domain_address(domain: &str) -> std::io::Result<Address> {
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
        return Ok(match ip {
            std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
            std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => Address::Ipv4(ip),
                None => Address::Ipv6(ip),
            },
        });
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

async fn send_command_response(
    stream: &mut Box<dyn AsyncStream>,
    reply: u8,
) -> std::io::Result<()> {
    let mut response = [0u8; 10];
    response[0] = SOCKS_VERSION;
    response[1] = reply;
    response[3] = ADDR_TYPE_IPV4;
    stream.write_all(&response).await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(feature = "traffic")]
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    #[cfg(feature = "traffic")]
    use tokio::{net::UdpSocket, time::timeout};

    use super::*;
    #[cfg(feature = "traffic")]
    use crate::{
        resolver::NativeResolver,
        runtime::OutboundSummary,
        traffic::{active_connections, snapshot},
    };

    async fn socks4_setup(
        handler: &SocksTcpServerHandler,
        request: &[u8],
    ) -> (TcpServerSetupResult, [u8; 8]) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(request).await.unwrap();

        let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        (result, response)
    }

    #[test]
    fn socks5_domain_validation_matches_xray() {
        for domain in ["example.com", "srv_name-1.local", "127.0.0.1"] {
            validate_socks5_domain(domain).unwrap();
        }
        for domain in ["", "bad/name", "bad name", "bad:name", "café.test"] {
            assert!(validate_socks5_domain(domain).is_err(), "{domain}");
        }

        assert_eq!(
            parse_socks5_domain_address("[::1]").unwrap(),
            Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("[127.0.0.1]").unwrap(),
            Address::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("[::ffff:127.0.0.1]").unwrap(),
            Address::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("[ 127.0.0.1 ]").unwrap(),
            Address::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("[ ::1 ]").unwrap(),
            Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("127.0.0.1 ").unwrap(),
            Address::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            parse_socks5_domain_address("2001:db8::1 ").unwrap(),
            Address::Ipv6("2001:db8::1".parse().unwrap())
        );
        assert!(parse_socks5_domain_address("[ example.com ]").is_err());
        assert!(parse_socks5_domain_address(" 127.0.0.1").is_err());
        assert!(parse_socks5_domain_address("1.example.com ").is_err());
        assert!(parse_socks5_domain_address("::1").is_err());

        let domain = b"bad/name";
        let mut packet = vec![ADDR_TYPE_DOMAIN, domain.len() as u8];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&53u16.to_be_bytes());
        assert!(parse_udp_address(&packet, 0).is_err());
    }

    #[test]
    fn socks5_udp_domain_atyp_accepts_bracketed_ip_literals_like_xray() {
        for (domain, expected) in [
            ("[::1]", Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
            ("[127.0.0.1]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
            ("[::ffff:127.0.0.1]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
            ("[ 127.0.0.1 ]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
            ("[ ::1 ]", Address::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
            ("127.0.0.1 ", Address::Ipv4(Ipv4Addr::LOCALHOST)),
            (
                "2001:db8::1 ",
                Address::Ipv6("2001:db8::1".parse().unwrap()),
            ),
        ] {
            let domain = domain.as_bytes();
            let mut packet = vec![ADDR_TYPE_DOMAIN, domain.len() as u8];
            packet.extend_from_slice(domain);
            packet.extend_from_slice(&53u16.to_be_bytes());
            let (location, used) = parse_udp_address(&packet, 0).unwrap();
            assert_eq!(location.address(), &expected);
            assert_eq!(location.port(), 53);
            assert_eq!(used, packet.len());
        }
    }

    #[tokio::test]
    async fn socks5_tcp_domain_parser_rejects_xray_invalid_names() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let domain = b"bad/name";
        client
            .write_all(&[ADDR_TYPE_DOMAIN, domain.len() as u8])
            .await
            .unwrap();
        client.write_all(domain).await.unwrap();
        client.write_all(&53u16.to_be_bytes()).await.unwrap();

        let mut server: Box<dyn AsyncStream> = Box::new(server);
        assert!(read_address_from_stream(&mut server).await.is_err());
    }

    #[test]
    fn udp_response_packet_matches_xray_8kib_limit() {
        let src_addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let max_payload =
            XRAY_SOCKS_UDP_PACKET_SIZE - build_udp_response_header(src_addr).len();

        let at_limit = build_udp_response_packet(src_addr, &vec![0x5a; max_payload]);
        assert_eq!(at_limit.len(), XRAY_SOCKS_UDP_PACKET_SIZE);
        assert_eq!(&at_limit[10..], vec![0x5a; max_payload]);

        let oversized =
            build_udp_response_packet(src_addr, &vec![0x5a; max_payload + 1]);
        assert!(oversized.is_empty());
    }

    #[tokio::test]
    async fn socks5_command_version_and_reserved_are_ignored_like_xray() {
        for (request_version, reserved) in
            [(0x04, 0x00), (0x06, 0x00), (0x05, 0x07), (0x04, 0x07)]
        {
            let handler = SocksTcpServerHandler::new(
                SocksUserStore::with_auth_required(Vec::new(), false),
                "socks5-request-header",
                false,
                None,
            );
            let listener =
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let mut client = TcpStream::connect(listener_addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            client
                .write_all(&[
                    SOCKS_VERSION,
                    1,
                    METHOD_NO_AUTH,
                    request_version,
                    CMD_CONNECT,
                    reserved,
                    ADDR_TYPE_IPV4,
                    203,
                    0,
                    113,
                    7,
                    0x01,
                    0xbb,
                ])
                .await
                .unwrap();

            let result =
                handler.setup_server_stream(Box::new(server)).await.unwrap();
            let mut method_response = [0u8; 2];
            client.read_exact(&mut method_response).await.unwrap();
            assert_eq!(method_response, [SOCKS_VERSION, METHOD_NO_AUTH]);

            let TcpServerSetupResult::TcpForward {
                remote_location,
                connection_success_response,
                ..
            } = result
            else {
                panic!("expected SOCKS5 TCP forward result");
            };
            assert_eq!(remote_location.to_string(), "203.0.113.7:443");
            assert_eq!(
                connection_success_response.as_deref(),
                Some(SUCCESS_RESPONSE.as_slice())
            );
        }
    }

    #[tokio::test]
    async fn socks5_tor_resolve_commands_are_tcp_connect_like_xray() {
        for command in [CMD_TOR_RESOLVE, CMD_TOR_RESOLVE_PTR] {
            let handler = SocksTcpServerHandler::new(
                SocksUserStore::with_auth_required(Vec::new(), false),
                "socks5-tor-command",
                false,
                None,
            );
            let listener =
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let mut client = TcpStream::connect(listener_addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            client
                .write_all(&[
                    SOCKS_VERSION,
                    1,
                    METHOD_NO_AUTH,
                    SOCKS_VERSION,
                    command,
                    0,
                    ADDR_TYPE_IPV4,
                    203,
                    0,
                    113,
                    7,
                    0x01,
                    0xbb,
                ])
                .await
                .unwrap();

            let result =
                handler.setup_server_stream(Box::new(server)).await.unwrap();
            let mut method_response = [0u8; 2];
            client.read_exact(&mut method_response).await.unwrap();
            assert_eq!(method_response, [SOCKS_VERSION, METHOD_NO_AUTH]);

            let TcpServerSetupResult::TcpForward {
                remote_location,
                connection_success_response,
                ..
            } = result
            else {
                panic!("expected SOCKS5 TCP forward result");
            };
            assert_eq!(remote_location.to_string(), "203.0.113.7:443");
            assert_eq!(
                connection_success_response.as_deref(),
                Some(SUCCESS_RESPONSE.as_slice())
            );
        }
    }

    #[tokio::test]
    async fn socks4_connect_matches_xray_handshake() {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks4",
            false,
            None,
        );
        let request = [
            SOCKS4_VERSION,
            CMD_CONNECT,
            0x01,
            0xbb,
            203,
            0,
            113,
            7,
            b'u',
            b's',
            b'e',
            b'r',
            0,
        ];
        let (result, response) = socks4_setup(&handler, &request).await;

        assert_eq!(response, [0x00, SOCKS4_REQUEST_GRANTED, 0, 0, 0, 0, 0, 0]);
        let TcpServerSetupResult::TcpForward {
            remote_location,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("expected SOCKS4 TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "203.0.113.7:443");
        assert!(connection_success_response.is_none());
        assert!(traffic_context.is_some());
    }

    #[tokio::test]
    async fn socks4a_zero_prefix_uses_domain_like_xray() {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks4a",
            false,
            None,
        );
        let mut request =
            vec![SOCKS4_VERSION, CMD_CONNECT, 0x00, 0x50, 0, 9, 8, 7, 0];
        request.extend_from_slice(b"example.com\0");
        let (result, response) = socks4_setup(&handler, &request).await;

        assert_eq!(response[1], SOCKS4_REQUEST_GRANTED);
        let TcpServerSetupResult::TcpForward {
            remote_location, ..
        } = result
        else {
            panic!("expected SOCKS4a TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
    }

    #[tokio::test]
    async fn socks4_is_rejected_when_password_auth_is_required() {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(
                vec![SocksUser {
                    username: "user".into(),
                    password: "pass".into(),
                }],
                true,
            ),
            "socks4-auth",
            false,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(&[SOCKS4_VERSION, CMD_CONNECT])
            .await
            .unwrap();

        let error = match handler.setup_server_stream(Box::new(server)).await {
            Ok(_) => {
                panic!("SOCKS4 must be rejected when password auth is required")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x00, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]);
    }

    async fn http_fallback_setup(
        handler: &SocksTcpServerHandler,
        request: &[u8],
    ) -> TcpServerSetupResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(request).await.unwrap();
        handler.setup_server_stream(Box::new(server)).await.unwrap()
    }

    #[tokio::test]
    async fn non_socks_first_byte_falls_back_to_http_proxy() {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks-http",
            false,
            None,
        );
        let result = http_fallback_setup(
            &handler,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .await;

        let TcpServerSetupResult::TcpForward {
            remote_location,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("expected HTTP fallback TCP forward result");
        };
        assert_eq!(remote_location.to_string(), "example.com:443");
        assert_eq!(
            connection_success_response.as_deref(),
            Some(b"HTTP/1.1 200 Connection established\r\n\r\n".as_slice())
        );
        let traffic_context = traffic_context.expect("HTTP traffic context");
        assert_eq!(traffic_context.protocol, "http");
        assert_eq!(traffic_context.inbound_tag.as_deref(), Some("socks-http"));
    }

    #[tokio::test]
    async fn http_fallback_auth_follows_xray_auth_type() {
        let account = SocksUser {
            username: "alice".into(),
            password: "secret".into(),
        };
        let authenticated = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(vec![account.clone()], true),
            "socks-http-auth",
            false,
            None,
        );
        let result = http_fallback_setup(
            &authenticated,
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
        )
        .await;
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("expected authenticated HTTP fallback TCP forward result");
        };
        assert_eq!(
            traffic_context
                .expect("HTTP traffic context")
                .identity
                .as_deref(),
            Some("alice")
        );

        let no_auth = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(vec![account], false),
            "socks-http-noauth",
            false,
            None,
        );
        let result = http_fallback_setup(
            &no_auth,
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        )
        .await;
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("expected no-auth HTTP fallback TCP forward result");
        };
        assert!(
            traffic_context
                .expect("HTTP traffic context")
                .identity
                .is_none(),
            "configured accounts must not force HTTP auth when Xray authType is NO_AUTH"
        );
    }

    #[tokio::test]
    async fn udp_associate_uses_tcp_local_ip_by_default() {
        let handler = SocksTcpServerHandler::new(
            SocksUserStore::with_auth_required(Vec::new(), false),
            "socks-local",
            true,
            None,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_NO_AUTH,
                SOCKS_VERSION,
                CMD_UDP_ASSOCIATE,
                0,
                ADDR_TYPE_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .unwrap();

        let result = handler
            .setup_server_stream_with_context(
                Box::new(server),
                TcpServerConnectionContext {
                    local_addr: Some(listener_addr),
                    ..TcpServerConnectionContext::default()
                },
            )
            .await
            .expect("SOCKS UDP ASSOCIATE should succeed");
        let TcpServerSetupResult::UdpAssociate { socket, .. } = result else {
            panic!("expected UDP associate result");
        };
        assert_eq!(socket.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn udp_associate_preserves_explicit_client_ip_hint_like_xray() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        client
            .write_all(&[0x00, ADDR_TYPE_IPV4, 127, 0, 0, 2, 0x12, 0x34])
            .await
            .unwrap();

        let result = handle_udp_associate(Box::new(server), None, None)
            .await
            .unwrap();
        let TcpServerSetupResult::UdpAssociate {
            client_udp_ip_hint,
            client_udp_port_hint,
            ..
        } = result
        else {
            panic!("expected UDP associate result");
        };
        assert_eq!(
            client_udp_ip_hint,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
        );
        assert_eq!(client_udp_port_hint, Some(0x1234));
    }

    #[tokio::test]
    async fn udp_associate_ignores_port_hint_for_unspecified_ip_like_xray() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        client
            .write_all(&[0x00, ADDR_TYPE_IPV4, 0, 0, 0, 0, 0x12, 0x34])
            .await
            .unwrap();

        let result = handle_udp_associate(Box::new(server), None, None)
            .await
            .unwrap();
        let TcpServerSetupResult::UdpAssociate {
            client_udp_ip_hint,
            client_udp_port_hint,
            ..
        } = result
        else {
            panic!("expected UDP associate result");
        };
        assert_eq!(client_udp_ip_hint, None);
        assert_eq!(client_udp_port_hint, None);
    }

    #[tokio::test]
    async fn udp_associate_uses_configured_bind_ip() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        client
            .write_all(&[0x00, ADDR_TYPE_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let result = handle_udp_associate(
            Box::new(server),
            None,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .unwrap();

        let TcpServerSetupResult::UdpAssociate { socket, .. } = result else {
            panic!("expected UDP associate result");
        };
        assert_eq!(
            socket.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );

        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], SOCKS_VERSION);
        assert_eq!(response[1], REP_SUCCEEDED);
        assert_eq!(response[3], ADDR_TYPE_IPV4);
        assert_eq!(&response[4..8], &Ipv4Addr::LOCALHOST.octets());
    }

    #[cfg(feature = "traffic")]
    #[tokio::test]
    async fn udp_target_session_retries_payload_after_idle_task_closed() {
        let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_addr = origin_socket.local_addr().unwrap();
        let client_socket =
            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let client_endpoint = client_socket.local_addr().unwrap();

        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let closed_task = tokio::spawn(async {});
        closed_task.await.unwrap();
        let closed_task = tokio::spawn(async {});
        let mut sessions = HashMap::from([(
            origin_addr,
            SocksUdpTargetSession {
                sender,
                task: closed_task,
            },
        )]);

        send_udp_target_payload(
            &mut sessions,
            origin_addr,
            client_endpoint,
            client_socket,
            b"after-idle".to_vec(),
            None,
        )
        .await
        .unwrap();

        let mut buf = [0u8; 64];
        let (len, _) =
            timeout(Duration::from_secs(2), origin_socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"after-idle");
    }

    #[cfg(feature = "traffic")]
    #[tokio::test]
    async fn udp_relay_forwards_multiple_responses_from_one_target_like_xray() {
        let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_addr = origin_socket.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (len, peer) = origin_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"ping");
            origin_socket.send_to(b"one", peer).await.unwrap();
            origin_socket.send_to(b"two", peer).await.unwrap();
        });

        let relay_socket =
            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let control_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let client_control = TcpStream::connect(control_addr).await.unwrap();
        let (server_control, _) = control_listener.accept().await.unwrap();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
            }],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let relay_task = tokio::spawn(run_udp_relay(
            relay_socket,
            Box::new(server_control),
            resolver,
            runtime,
            client_control.local_addr().unwrap(),
            (None, None),
            None,
        ));

        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(origin_ip) = origin_addr.ip() else {
            unreachable!("test origin socket must use IPv4");
        };
        request.extend_from_slice(&origin_ip.octets());
        request.extend_from_slice(&origin_addr.port().to_be_bytes());
        request.extend_from_slice(b"ping");
        client_socket.send_to(&request, relay_addr).await.unwrap();

        let mut payloads = Vec::new();
        for _ in 0..2 {
            let mut response = [0u8; 128];
            let (response_len, _) = timeout(
                Duration::from_secs(2),
                client_socket.recv_from(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            payloads.push(response[10..response_len].to_vec());
        }
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);

        drop(client_control);
        timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin_task.await.unwrap();
    }

    #[cfg(feature = "traffic")]
    #[tokio::test]
    async fn udp_relay_truncates_oversized_requests_like_xray() {
        let origin_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_addr = origin_socket.local_addr().unwrap();

        let relay_socket =
            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let control_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let client_control = TcpStream::connect(control_addr).await.unwrap();
        let (server_control, _) = control_listener.accept().await.unwrap();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
            }],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let relay_task = tokio::spawn(run_udp_relay(
            relay_socket,
            Box::new(server_control),
            resolver,
            runtime,
            client_control.local_addr().unwrap(),
            (None, None),
            None,
        ));

        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(origin_ip) = origin_addr.ip() else {
            unreachable!("test origin socket must use IPv4");
        };
        request.extend_from_slice(&origin_ip.octets());
        request.extend_from_slice(&origin_addr.port().to_be_bytes());
        request.extend(std::iter::repeat_n(0x5a, XRAY_SOCKS_UDP_PACKET_SIZE));
        client_socket.send_to(&request, relay_addr).await.unwrap();

        let mut received = vec![0u8; XRAY_SOCKS_UDP_PACKET_SIZE * 2];
        let (len, _) = timeout(
            Duration::from_secs(2),
            origin_socket.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(len, XRAY_SOCKS_UDP_PACKET_SIZE - 10);
        assert!(received[..len].iter().all(|byte| *byte == 0x5a));

        drop(client_control);
        timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "traffic")]
    #[tokio::test]
    async fn udp_relay_routes_and_records_live_user_traffic() {
        let inbound_tag = "socks-udp-e2e-in";
        let outbound_tag = "socks-udp-e2e-out";
        let identity = "socks-udp-e2e-user";
        let payload = b"socks-udp-e2e";
        let before = snapshot();

        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (len, peer) = echo_socket.recv_from(&mut buf).await.unwrap();
            echo_socket.send_to(&buf[..len], peer).await.unwrap();
        });

        let relay_socket =
            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let control_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let client_control = TcpStream::connect(control_addr).await.unwrap();
        let (server_control, _) = control_listener.accept().await.unwrap();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: outbound_tag.into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
            }],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let client_ip: IpAddr = "203.0.113.19".parse().unwrap();
        let traffic_context = TrafficContext::new("socks")
            .with_identity(identity)
            .with_inbound_tag(inbound_tag)
            .with_client_ip(client_ip);
        let relay_task = tokio::spawn(run_udp_relay(
            relay_socket,
            Box::new(server_control),
            resolver,
            runtime,
            client_control.local_addr().unwrap(),
            (None, None),
            Some(traffic_context),
        ));

        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut request = vec![0, 0, 0, ADDR_TYPE_IPV4];
        let IpAddr::V4(echo_ip) = echo_addr.ip() else {
            unreachable!("test echo socket must use IPv4");
        };
        request.extend_from_slice(&echo_ip.octets());
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        request.extend_from_slice(payload);
        client_socket.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0u8; 128];
        let (response_len, _) = timeout(
            Duration::from_secs(2),
            client_socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[10..response_len], payload);
        assert!(active_connections().iter().any(|entry| {
            entry.inbound_tag.as_deref() == Some(inbound_tag)
                && entry.identity.as_deref() == Some(identity)
                && entry.client_ip == Some(client_ip)
        }));

        let after = snapshot();
        let before_inbound = before
            .per_inbound
            .get(inbound_tag)
            .cloned()
            .unwrap_or_default();
        let after_inbound = after.per_inbound.get(inbound_tag).unwrap();
        assert_eq!(
            after_inbound.upload_bytes - before_inbound.upload_bytes,
            payload.len() as u64
        );
        assert_eq!(
            after_inbound.download_bytes - before_inbound.download_bytes,
            payload.len() as u64
        );
        let outbound = after.per_outbound.get(outbound_tag).unwrap();
        let before_outbound = before
            .per_outbound
            .get(outbound_tag)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            outbound.upload_bytes - before_outbound.upload_bytes,
            payload.len() as u64
        );
        assert_eq!(
            outbound.download_bytes - before_outbound.download_bytes,
            payload.len() as u64
        );
        let user = after
            .per_inbound_user
            .get(&(inbound_tag.into(), identity.into()))
            .unwrap();
        assert_eq!(user.upload_bytes, payload.len() as u64);
        assert_eq!(user.download_bytes, payload.len() as u64);

        drop(client_control);
        timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        echo_task.await.unwrap();
    }
}
