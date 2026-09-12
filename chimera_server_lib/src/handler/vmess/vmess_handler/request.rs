use std::net::{Ipv4Addr, Ipv6Addr};

use crate::address::{Address, NetLocation};

use super::super::fnv1a::Fnv1aHasher;

pub(super) const COMMAND_TCP: u8 = 1;
pub(super) const COMMAND_UDP: u8 = 2;
pub(super) const COMMAND_MUX: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DataCipher {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

pub(super) struct ParsedRequest {
    pub(super) command: u8,
    pub(super) remote_location: NetLocation,
    pub(super) data_encryption_iv: [u8; 16],
    pub(super) data_encryption_key: [u8; 16],
    pub(super) response_authentication_v: u8,
    pub(super) enable_chunk_masking: bool,
    pub(super) enable_global_padding: bool,
    pub(super) data_cipher: DataCipher,
}

pub(super) fn parse_request_header(
    decrypted_header: &[u8],
    udp_enabled: bool,
) -> std::io::Result<ParsedRequest> {
    let mut cursor = 0usize;
    let mut fnv_hasher = Fnv1aHasher::new();

    let fixed_header = take_header_slice(decrypted_header, &mut cursor, 38)?;
    fnv_hasher.write(fixed_header);

    if fixed_header[0] != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid version {}", fixed_header[0]),
        ));
    }

    let command = fixed_header[37];
    validate_command(command, udp_enabled)?;

    let remote_location = if command == COMMAND_MUX {
        NetLocation::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        parse_target(decrypted_header, &mut cursor, &mut fnv_hasher)?
    };

    let margin_len = fixed_header[35] >> 4;
    if margin_len > 0 {
        let margin_bytes =
            take_header_slice(decrypted_header, &mut cursor, margin_len as usize)?;
        fnv_hasher.write(margin_bytes);
    }

    let check_bytes = take_header_slice(decrypted_header, &mut cursor, 4)?;
    let expected_check_value = u32::from_be_bytes(check_bytes.try_into().unwrap());
    let actual_check_value = fnv_hasher.finish();
    if expected_check_value != actual_check_value {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Bad fnv1a checksum, expected {expected_check_value}, got {actual_check_value}"
            ),
        ));
    }

    let option = fixed_header[34];
    if option & 0x01 != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Standard format data stream was not requested",
        ));
    }
    if option & 0x10 == 0x10 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Auth length option is not supported",
        ));
    }

    let enable_chunk_masking = option & 0x04 == 0x04;
    let enable_global_padding = option & 0x08 == 0x08;
    if enable_global_padding && !enable_chunk_masking {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Global padding cannot be enabled without chunk masking",
        ));
    }

    let data_cipher = match fixed_header[35] & 0b1111 {
        1 => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported aes-128-cfb data cipher requested",
            ));
        }
        3 => DataCipher::Aes128Gcm,
        4 => DataCipher::ChaCha20Poly1305,
        5 => DataCipher::None,
        unknown_cipher_type => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown requested cipher: {unknown_cipher_type}"),
            ));
        }
    };

    Ok(ParsedRequest {
        command,
        remote_location,
        data_encryption_iv: fixed_header[1..17].try_into().unwrap(),
        data_encryption_key: fixed_header[17..33].try_into().unwrap(),
        response_authentication_v: fixed_header[33],
        enable_chunk_masking,
        enable_global_padding,
        data_cipher,
    })
}

fn validate_command(command: u8, udp_enabled: bool) -> std::io::Result<()> {
    match command {
        COMMAND_TCP => Ok(()),
        COMMAND_UDP | COMMAND_MUX if udp_enabled => Ok(()),
        COMMAND_UDP => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VMess UDP command is disabled for this inbound",
        )),
        COMMAND_MUX => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VMess MUX/XUDP command is disabled for this inbound",
        )),
        unknown => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown VMess command: {unknown}"),
        )),
    }
}

fn parse_target(
    header: &[u8],
    cursor: &mut usize,
    fnv_hasher: &mut Fnv1aHasher,
) -> std::io::Result<NetLocation> {
    let port_and_addr_type = take_header_slice(header, cursor, 3)?;
    fnv_hasher.write(port_and_addr_type);
    let port = u16::from_be_bytes([port_and_addr_type[0], port_and_addr_type[1]]);

    match port_and_addr_type[2] {
        1 => {
            let address_bytes = take_header_slice(header, cursor, 4)?;
            fnv_hasher.write(address_bytes);
            Ok(NetLocation::new(
                Address::Ipv4(Ipv4Addr::new(
                    address_bytes[0],
                    address_bytes[1],
                    address_bytes[2],
                    address_bytes[3],
                )),
                port,
            ))
        }
        2 => {
            let domain_name_len = take_header_u8(header, cursor)?;
            fnv_hasher.write(&[domain_name_len]);
            if domain_name_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VMess domain must not be empty",
                ));
            }
            let domain_name_bytes =
                take_header_slice(header, cursor, domain_name_len as usize)?;
            fnv_hasher.write(domain_name_bytes);
            let address_str =
                std::str::from_utf8(domain_name_bytes).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {error}"),
                    )
                })?;
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }
        3 => {
            let address_bytes = take_header_slice(header, cursor, 16)?;
            fnv_hasher.write(address_bytes);
            let octets: [u8; 16] = address_bytes.try_into().unwrap();
            Ok(NetLocation::new(
                Address::Ipv6(Ipv6Addr::from(octets)),
                port,
            ))
        }
        invalid_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid address type: {invalid_type}"),
        )),
    }
}

fn take_header_slice<'a>(
    header: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> std::io::Result<&'a [u8]> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VMess request header length overflow",
        )
    })?;
    let slice = header.get(*cursor..end).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "truncated VMess request header at byte {} while reading {} bytes",
                *cursor, length
            ),
        )
    })?;
    *cursor = end;
    Ok(slice)
}

fn take_header_u8(header: &[u8], cursor: &mut usize) -> std::io::Result<u8> {
    Ok(take_header_slice(header, cursor, 1)?[0])
}
