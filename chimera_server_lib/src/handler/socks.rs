use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::{SocksUser, SocksUserStore},
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    outbound::{
        DirectOutboundAction, connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{TrafficContext, record_transfer, register_connection},
};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_REJECT: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

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

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    accounts: SocksUserStore,
    inbound_tag: String,
    udp_enabled: bool,
}

impl SocksTcpServerHandler {
    pub fn new(
        accounts: SocksUserStore,
        inbound_tag: &str,
        udp_enabled: bool,
    ) -> Self {
        Self {
            accounts,
            inbound_tag: inbound_tag.to_string(),
            udp_enabled,
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

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let method =
            negotiate_method(&mut server_stream, self.requires_auth()).await?;

        let mut identity = None;
        if method == SocksMethod::UsernamePassword {
            let accounts = self.accounts.snapshot();
            identity = Some(authenticate(&accounts, &mut server_stream).await?)
                .filter(|s| !s.is_empty());
        }

        let version = server_stream.read_u8().await?;
        if version != SOCKS_VERSION {
            send_command_response(&mut server_stream, REP_GENERAL_FAILURE).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid socks version: {}", version),
            ));
        }

        let command = server_stream.read_u8().await?;

        let traffic_context = Some(match identity {
            Some(id) => TrafficContext::new("socks")
                .with_identity(id)
                .with_inbound_tag(self.inbound_tag.clone()),
            None => TrafficContext::new("socks")
                .with_inbound_tag(self.inbound_tag.clone()),
        });

        match command {
            CMD_CONNECT => {
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
                handle_udp_associate(server_stream, traffic_context).await
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

async fn negotiate_method(
    stream: &mut Box<dyn AsyncStream>,
    has_accounts: bool,
) -> std::io::Result<SocksMethod> {
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported socks version: {}", version),
        ));
    }

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
    let reserved = stream.read_u8().await?;
    if reserved != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reserved byte must be zero",
        ));
    }

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

            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            NetLocation::new(Address::from(domain_str)?, port)
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
) -> std::io::Result<TcpServerSetupResult> {
    // Read client's hint address (RSV + ATYP + DST.ADDR + DST.PORT) - we ignore this per RFC
    let _client_hint = read_socks_address(&mut server_stream).await?;
    tracing::debug!("SOCKS5 UDP ASSOCIATE: client hint = {:?}", _client_hint);

    let udp_bind_addr = SocketAddr::from(([0, 0, 0, 0], 0u16));
    let udp_socket = crate::util::socket::new_socket2_udp_socket_with_buffer_size(
        false,
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
pub(crate) async fn run_udp_relay(
    udp_socket: Arc<tokio::net::UdpSocket>,
    mut tcp_stream: Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
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

    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

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

        // Forward payload to target
        let target_socket = match create_udp_socket_for_target(&target_addr) {
            Ok(s) => s,
            Err(_) => continue,
        };

        match target_socket.send_to(payload, target_addr).await {
            Ok(sent) => {
                record_transfer(datagram_context.clone(), sent as u64, 0);
            }
            Err(e) => {
                tracing::warn!("SOCKS5 UDP relay: failed to send to target: {}", e);
                continue;
            }
        }

        // Receive response
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        match target_socket.recv_from(&mut response_buf).await {
            Ok((resp_len, resp_addr)) => {
                let resp_data = &response_buf[..resp_len];

                // Build SOCKS5 UDP response: RSV(2) + FRAG(1) + ATYP(1) + SRC.ADDR + SRC.PORT(2) + DATA
                let mut socks5_response = build_udp_response_header(resp_addr);
                socks5_response.extend_from_slice(resp_data);

                if let Err(e) = udp_socket_clone
                    .send_to(&socks5_response, client_addr)
                    .await
                {
                    tracing::warn!(
                        "SOCKS5 UDP relay: failed to send response to client: {}",
                        e
                    );
                } else {
                    record_transfer(datagram_context, 0, resp_len as u64);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "SOCKS5 UDP relay: failed to receive from target: {}",
                    e
                );
            }
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
            let port = u16::from_be_bytes([
                data[offset + 2 + domain_len],
                data[offset + 2 + domain_len + 1],
            ]);
            Ok((
                NetLocation::new(Address::from(domain_str)?, port),
                offset + 1 + 1 + domain_len + 2,
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown address type: {}", addr_type),
        )),
    }
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
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use tokio::{
        net::{TcpListener, TcpStream, UdpSocket},
        time::timeout,
    };

    use super::*;
    use crate::{
        resolver::NativeResolver,
        runtime::OutboundSummary,
        traffic::{active_connections, snapshot},
    };

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
