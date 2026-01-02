use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::SocksUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
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

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    accounts: Vec<SocksUser>,
    inbound_tag: String,
}

impl SocksTcpServerHandler {
    pub fn new(accounts: Vec<SocksUser>, inbound_tag: &str) -> Self {
        Self {
            accounts,
            inbound_tag: inbound_tag.to_string(),
        }
    }

    fn requires_auth(&self) -> bool {
        !self.accounts.is_empty()
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
        let method = negotiate_method(&mut server_stream, self.requires_auth()).await?;

        let mut identity = None;
        if method == SocksMethod::UsernamePassword {
            identity = Some(authenticate(&self.accounts, &mut server_stream).await?)
                .filter(|s| !s.is_empty());
        }

        let remote_location = read_connect_request(&mut server_stream).await?;

        let traffic_context = Some(match identity {
            Some(id) => TrafficContext::new("socks")
                .with_identity(id)
                .with_inbound_tag(self.inbound_tag.clone()),
            None => TrafficContext::new("socks").with_inbound_tag(self.inbound_tag.clone()),
        });

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: Some(SUCCESS_RESPONSE.to_vec().into_boxed_slice()),
            traffic_context,
        })
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

    let supports_no_auth = methods.iter().any(|&m| m == METHOD_NO_AUTH);
    let supports_password = methods.iter().any(|&m| m == METHOD_USERNAME_PASSWORD);

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

async fn read_connect_request(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<NetLocation> {
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        send_command_response(stream, REP_GENERAL_FAILURE).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid connect version: {}", version),
        ));
    }

    let command = stream.read_u8().await?;
    if command == CMD_UDP_ASSOCIATE {
        send_command_response(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "udp associate is not supported",
        ));
    }
    if command != CMD_CONNECT {
        send_command_response(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported socks command: {}", command),
        ));
    }

    let reserved = stream.read_u8().await?;
    if reserved != 0x00 {
        send_command_response(stream, REP_GENERAL_FAILURE).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reserved byte must be zero",
        ));
    }

    let address_type = stream.read_u8().await?;
    let remote_location = match address_type {
        ADDR_TYPE_IPV4 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let ipv4 = std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]);
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
                send_command_response(stream, REP_GENERAL_FAILURE).await?;
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
                    send_command_response(stream, REP_GENERAL_FAILURE).await?;
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
            send_command_response(stream, REP_COMMAND_NOT_SUPPORTED).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown address type: {}", address_type),
            ));
        }
    };

    Ok(remote_location)
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
