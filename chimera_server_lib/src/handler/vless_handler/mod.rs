use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tracing::info;

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    traffic::TrafficContext,
};

use super::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

use crate::util::allocate_vec;

const SERVER_RESPONSE_HEADER: &[u8] = &[0u8, 0u8];

#[derive(Debug)]
pub struct VlessTcpHandler {
    user_id: Box<[u8]>,
    user_label: String,
    inbound_tag: String,
}

impl VlessTcpHandler {
    pub fn new(user_id: &str, user_label: &str, inbound_tag: &str) -> Self {
        Self {
            user_id: parse_hex(user_id),
            user_label: user_label.to_string(),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for VlessTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut prefix = [0u8; 18];
        server_stream.read_exact(&mut prefix).await?;

        if prefix[0] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "invalid client protocol version, expected 0, got {}",
                    prefix[0]
                ),
            ));
        }

        let target_id = &prefix[1..17];
        for (b1, b2) in self.user_id.iter().zip(target_id.iter()) {
            info!("todo: add the user check b1: {}, b2: {}", b1, b2);
        }

        let addon_length = prefix[17];

        if addon_length > 0 {
            read_addons(&mut server_stream, addon_length).await?;
        }

        let mut address_prefix = [0u8; 4];
        server_stream.read_exact(&mut address_prefix).await?;

        match address_prefix[0] {
            1 => {}
            2 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP was requested",
                ));
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {}", unknown_protocol_type),
                ));
            }
        }

        let port = ((address_prefix[1] as u16) << 8) | (address_prefix[2] as u16);

        let remote_location = match address_prefix[3] {
            1 => {
                let mut address_bytes = [0u8; 4];
                server_stream.read_exact(&mut address_bytes).await?;

                let v4addr = Ipv4Addr::new(
                    address_bytes[0],
                    address_bytes[1],
                    address_bytes[2],
                    address_bytes[3],
                );
                NetLocation::new(Address::Ipv4(v4addr), port)
            }
            2 => {
                let mut domain_name_len = [0u8; 1];
                server_stream.read_exact(&mut domain_name_len).await?;

                let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
                server_stream.read_exact(&mut domain_name_bytes).await?;

                let address_str = match std::str::from_utf8(&domain_name_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to decode address: {}", e),
                        ));
                    }
                };

                NetLocation::new(Address::from(address_str)?, port)
            }
            3 => {
                let mut address_bytes = [0u8; 16];
                server_stream.read_exact(&mut address_bytes).await?;

                let v6addr = Ipv6Addr::new(
                    ((address_bytes[0] as u16) << 8) | (address_bytes[1] as u16),
                    ((address_bytes[2] as u16) << 8) | (address_bytes[3] as u16),
                    ((address_bytes[4] as u16) << 8) | (address_bytes[5] as u16),
                    ((address_bytes[6] as u16) << 8) | (address_bytes[7] as u16),
                    ((address_bytes[8] as u16) << 8) | (address_bytes[9] as u16),
                    ((address_bytes[10] as u16) << 8) | (address_bytes[11] as u16),
                    ((address_bytes[12] as u16) << 8) | (address_bytes[13] as u16),
                    ((address_bytes[14] as u16) << 8) | (address_bytes[15] as u16),
                );

                NetLocation::new(Address::Ipv6(v6addr), port)
            }
            invalid_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address type: {}", invalid_type),
                ));
            }
        };

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: true,

            connection_success_response: Some(SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice()),
            traffic_context: Some(
                TrafficContext::new("vless")
                    .with_identity(self.user_label.clone())
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        })
    }
}

fn parse_hex(hex_asm: &str) -> Box<[u8]> {
    let mut hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes.into_boxed_slice()
}

fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    let mut cursor = 0usize;
    let mut length = 0u64;
    loop {
        let byte = data[cursor];
        if (byte & 0b10000000) != 0 {
            length = (length << 8) | ((byte ^ 0b10000000) as u64);
        } else {
            length = (length << 8) | (byte as u64);
            return Ok((length, cursor + 1));
        }
        if cursor == 7 || cursor == data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Varint is too long",
            ));
        }
        cursor += 1;
    }
}

async fn read_addons(stream: &mut Box<dyn AsyncStream>, addon_length: u8) -> std::io::Result<()> {
    let mut addon_bytes = allocate_vec(addon_length as usize).into_boxed_slice();
    stream.read_exact(&mut addon_bytes).await?;

    let mut addon_cursor = 0;
    let (flow_length, bytes_used) = read_varint(&addon_bytes)?;
    addon_cursor += bytes_used;

    let flow_bytes = &addon_bytes[addon_cursor..addon_cursor + flow_length as usize];
    addon_cursor += flow_length as usize;

    let (seed_length, bytes_used) = read_varint(&addon_bytes[addon_cursor..])?;
    addon_cursor += bytes_used;
    let seed_bytes = &addon_bytes[addon_cursor..addon_cursor + seed_length as usize];
    addon_cursor += seed_length as usize;

    if addon_cursor as u8 != addon_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Did not consume all addon bytes, cursor is at {}, length is {}",
                addon_cursor, addon_length
            ),
        ));
    }

    tracing::info!(
        "Read addon bytes: flow: {:?}, seed: {:?}",
        &flow_bytes,
        &seed_bytes
    );

    Ok(())
}
