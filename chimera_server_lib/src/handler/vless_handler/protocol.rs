use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    address::{Address, NetLocation},
    util::allocate_vec,
};

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;
pub const XTLS_VISION_FLOW: &str = "xtls-rprx-vision";

pub struct ParsedVlessHeader {
    pub user_id: [u8; 16],
    pub flow: String,
    pub command: u8,
    pub remote_location: NetLocation,
}

pub async fn read_request_header<S>(
    stream: &mut S,
) -> std::io::Result<ParsedVlessHeader>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 18];
    stream.read_exact(&mut prefix).await?;

    if prefix[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "invalid client protocol version, expected 0, got {}",
                prefix[0]
            ),
        ));
    }

    let mut user_id = [0u8; 16];
    user_id.copy_from_slice(&prefix[1..17]);

    let addon_length = prefix[17];
    let flow = if addon_length > 0 {
        read_addons(stream, addon_length).await?
    } else {
        String::new()
    };

    let mut address_prefix = [0u8; 4];
    stream.read_exact(&mut address_prefix).await?;

    let command = address_prefix[0];
    let port = ((address_prefix[1] as u16) << 8) | (address_prefix[2] as u16);
    let remote_location =
        read_remote_location(stream, address_prefix[3], port).await?;

    Ok(ParsedVlessHeader {
        user_id,
        flow,
        command,
        remote_location,
    })
}

pub fn encode_flow_addon_data(flow: &str) -> std::io::Result<Vec<u8>> {
    let flow_bytes = flow.as_bytes();
    if flow_bytes.len() > 127 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Flow string too long for simple varint encoding",
        ));
    }

    let mut result = Vec::with_capacity(flow_bytes.len() + 2);
    result.push(0x0a);
    result.push(flow_bytes.len() as u8);
    result.extend_from_slice(flow_bytes);
    Ok(result)
}

pub fn vision_flow_addon_data() -> &'static [u8] {
    static INSTANCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        encode_flow_addon_data(XTLS_VISION_FLOW)
            .expect("Failed to encode vision flow addon at initialization")
    });
    &INSTANCE
}

async fn read_remote_location<S>(
    stream: &mut S,
    address_type: u8,
    port: u16,
) -> std::io::Result<NetLocation>
where
    S: AsyncRead + Unpin,
{
    match address_type {
        1 => {
            let mut address_bytes = [0u8; 4];
            stream.read_exact(&mut address_bytes).await?;

            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );
            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        2 => {
            let mut domain_name_len = [0u8; 1];
            stream.read_exact(&mut domain_name_len).await?;

            let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
            stream.read_exact(&mut domain_name_bytes).await?;

            let address_str =
                std::str::from_utf8(&domain_name_bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {e}"),
                    )
                })?;

            Ok(NetLocation::new(Address::from(address_str)?, port))
        }
        3 => {
            let mut address_bytes = [0u8; 16];
            stream.read_exact(&mut address_bytes).await?;

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

            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        invalid_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid address type: {}", invalid_type),
        )),
    }
}

async fn read_addons<S>(stream: &mut S, addon_length: u8) -> std::io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut addon_bytes = allocate_vec(addon_length as usize);
    stream.read_exact(&mut addon_bytes).await?;

    let flow_bytes = if addon_bytes.first() == Some(&0x0a) {
        let (flow_length, bytes_used) = read_varint(&addon_bytes[1..])?;
        let flow_start = 1 + bytes_used;
        let flow_end = flow_start + flow_length as usize;
        addon_bytes.get(flow_start..flow_end).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "vision flow addon length {} exceeds payload size {}",
                    flow_length, addon_length
                ),
            )
        })?
    } else {
        let (flow_length, bytes_used) = read_varint(&addon_bytes)?;
        addon_bytes
            .get(bytes_used..bytes_used + flow_length as usize)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "legacy flow addon length {} exceeds payload size {}",
                        flow_length, addon_length
                    ),
                )
            })?
    };

    let flow = std::str::from_utf8(flow_bytes)
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode VLESS flow: {err}"),
            )
        })?
        .to_string();

    Ok(flow)
}

fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Varint is empty",
        ));
    }

    let mut cursor = 0usize;
    let mut length = 0u64;
    loop {
        if cursor >= data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Varint truncated",
            ));
        }
        let byte = data[cursor];
        if (byte & 0b1000_0000) != 0 {
            length = (length << 8) | ((byte ^ 0b1000_0000) as u64);
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

#[cfg(test)]
mod tests {
    use super::{XTLS_VISION_FLOW, encode_flow_addon_data, vision_flow_addon_data};

    #[test]
    fn vision_flow_addon_bytes_match_encoder() {
        assert_eq!(
            vision_flow_addon_data(),
            encode_flow_addon_data(XTLS_VISION_FLOW)
                .expect("vision flow addon should encode")
        );
    }
}
