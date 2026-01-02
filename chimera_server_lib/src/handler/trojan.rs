use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use aws_lc_rs::digest::{digest, SHA224};
use tokio::io::AsyncReadExt;

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::TrojanUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
};

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;
const MAX_PASSWORD_LINE: usize = 128;
const CRLF: [u8; 2] = [0x0d, 0x0a];

#[derive(Debug, Clone)]
struct TrojanCredential {
    password_hash: Box<[u8]>,
    identity: Option<String>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    credentials: Vec<TrojanCredential>,
    inbound_tag: String,
}

impl TrojanTcpHandler {
    pub fn new(users: Vec<TrojanUser>, inbound_tag: &str) -> Self {
        let credentials = users
            .into_iter()
            .map(|user| {
                let identity = user.email.filter(|value| !value.is_empty()).or_else(|| {
                    if user.password.is_empty() {
                        None
                    } else {
                        Some(user.password.clone())
                    }
                });
                TrojanCredential {
                    password_hash: create_password_hash(&user.password),
                    identity,
                }
            })
            .collect();
        Self {
            credentials,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let password_line = read_line_crlf(&mut server_stream, MAX_PASSWORD_LINE).await?;
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
            .find(|cred| cred.password_hash.as_ref() == password_line.as_slice())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "invalid trojan password",
                )
            })?;

        let command = server_stream.read_u8().await?;
        if command == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
        }

        if command != CMD_CONNECT {
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

        let traffic_context = credential
            .identity
            .as_ref()
            .map(|label| {
                TrafficContext::new("trojan")
                    .with_identity(label.clone())
                    .with_inbound_tag(self.inbound_tag.clone())
            });

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
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

async fn read_location(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<NetLocation> {
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
