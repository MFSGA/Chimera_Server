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
            std::io::ErrorKind::InvalidData,
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

    let command = stream.read_u8().await?;
    let remote_location = if command == COMMAND_MUX {
        NetLocation::new(Address::from("v1.mux.cool")?, 0)
    } else {
        let mut address_prefix = [0u8; 3];
        stream.read_exact(&mut address_prefix).await?;
        let port = ((address_prefix[0] as u16) << 8) | (address_prefix[1] as u16);
        read_remote_location(stream, address_prefix[2], port).await?
    };

    Ok(ParsedVlessHeader {
        user_id,
        flow,
        command,
        remote_location,
    })
}

pub fn encode_flow_addon_data(flow: &str) -> std::io::Result<Vec<u8>> {
    let flow_bytes = flow.as_bytes();
    let mut result = Vec::with_capacity(flow_bytes.len() + 3);
    result.push(0x0a);

    let mut remaining = flow_bytes.len() as u64;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if remaining == 0 {
            break;
        }
    }
    result.extend_from_slice(flow_bytes);

    if result.len() > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "VLESS addon exceeds 255 bytes after encoding: {}",
                result.len()
            ),
        ));
    }
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

            if domain_name_len[0] == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VLESS domain must not be empty",
                ));
            }
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
        checked_flow_slice(
            &addon_bytes,
            1 + bytes_used,
            flow_length,
            addon_length,
            "vision",
        )?
    } else {
        let (flow_length, bytes_used) = read_varint(&addon_bytes)?;
        checked_flow_slice(
            &addon_bytes,
            bytes_used,
            flow_length,
            addon_length,
            "legacy",
        )?
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

fn checked_flow_slice<'a>(
    addon_bytes: &'a [u8],
    flow_start: usize,
    flow_length: u64,
    addon_length: u8,
    format_name: &str,
) -> std::io::Result<&'a [u8]> {
    let flow_length = usize::try_from(flow_length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{format_name} flow addon length does not fit this platform"),
        )
    })?;
    let flow_end = flow_start.checked_add(flow_length).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{format_name} flow addon length overflows its payload"),
        )
    })?;
    addon_bytes.get(flow_start..flow_end).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{format_name} flow addon length {flow_length} exceeds payload size {addon_length}"
            ),
        )
    })
}

fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Varint is empty",
        ));
    }

    let mut value = 0u64;
    for (index, byte) in data.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Varint overflows u64",
            ));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }

    if data.len() < 10 {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Varint truncated",
        ))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Varint is too long",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use crate::address::{Address, NetLocation};

    use super::{
        COMMAND_MUX, COMMAND_TCP, XTLS_VISION_FLOW, encode_flow_addon_data,
        read_addons, read_remote_location, read_request_header, read_varint,
        vision_flow_addon_data,
    };

    #[tokio::test]
    async fn mux_header_does_not_consume_xudp_frame_bytes() {
        let (mut client, mut server) = duplex(128);
        let mut request = vec![0];
        request.extend_from_slice(&[7u8; 16]);
        request.push(0);
        request.push(COMMAND_MUX);
        request.extend_from_slice(&[0xaa, 0xbb]);
        client
            .write_all(&request)
            .await
            .expect("write VLESS MUX header");

        let header = read_request_header(&mut server)
            .await
            .expect("parse VLESS MUX header");

        assert_eq!(header.command, COMMAND_MUX);
        assert_eq!(
            header.remote_location,
            NetLocation::new(Address::from("v1.mux.cool").unwrap(), 0)
        );
        assert_eq!(server.read_u8().await.expect("read first XUDP byte"), 0xaa);
        assert_eq!(server.read_u8().await.expect("read second XUDP byte"), 0xbb);
    }

    #[tokio::test]
    async fn mux_header_truncated_at_each_prefix_returns_unexpected_eof() {
        let mut request = vec![0];
        request.extend_from_slice(&[7u8; 16]);
        request.push(0);
        request.push(COMMAND_MUX);

        for prefix_length in 0..request.len() {
            let mut input = Cursor::new(request[..prefix_length].to_vec());
            let error = match read_request_header(&mut input).await {
                Ok(_) => panic!("truncated VLESS MUX header must fail"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "prefix length {prefix_length}"
            );
        }
    }

    #[tokio::test]
    async fn address_matrix_parses_exact_targets() {
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let cases = [
            (
                1,
                Ipv4Addr::new(192, 0, 2, 1).octets().to_vec(),
                NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ),
            (
                2,
                [vec![12], b"example.test".to_vec()].concat(),
                NetLocation::new(Address::from("example.test").unwrap(), 443),
            ),
            (
                3,
                ipv6.octets().to_vec(),
                NetLocation::new(Address::Ipv6(ipv6), 443),
            ),
        ];

        for (address_type, encoded, expected) in cases {
            let mut input = Cursor::new(encoded);
            let actual = read_remote_location(&mut input, address_type, 443)
                .await
                .expect("parse VLESS address matrix entry");
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn address_payload_truncations_return_unexpected_eof() {
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let cases = [
            (1, Ipv4Addr::LOCALHOST.octets().to_vec()),
            (2, [vec![12], b"example.test".to_vec()].concat()),
            (3, ipv6.octets().to_vec()),
        ];

        for (address_type, encoded) in cases {
            for prefix_length in 0..encoded.len() {
                let mut input = Cursor::new(encoded[..prefix_length].to_vec());
                let error = read_remote_location(&mut input, address_type, 53)
                    .await
                    .expect_err("truncated VLESS address must fail");
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof,
                    "address type {address_type}, prefix {prefix_length}"
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_domain_utf8_and_address_type_are_rejected() {
        let mut invalid_domain = Cursor::new(vec![1, 0xff]);
        let domain_error = read_remote_location(&mut invalid_domain, 2, 53)
            .await
            .expect_err("invalid UTF-8 VLESS domain must fail");
        assert_eq!(domain_error.kind(), std::io::ErrorKind::InvalidData);

        let mut empty = Cursor::new(Vec::<u8>::new());
        let type_error = read_remote_location(&mut empty, 0xff, 53)
            .await
            .expect_err("unknown VLESS address type must fail");
        assert_eq!(type_error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn empty_domain_is_rejected() {
        let mut request = vec![0];
        request.extend_from_slice(&[7u8; 16]);
        request.push(0);
        request.push(COMMAND_TCP);
        request.extend_from_slice(&[0, 80, 2, 0]);
        let mut input = Cursor::new(request);

        let error = match read_request_header(&mut input).await {
            Ok(_) => panic!("empty VLESS domain must be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn protobuf_varint_two_byte_length_decodes() {
        assert_eq!(
            read_varint(&[0x80, 0x01]).expect("decode two-byte protobuf varint"),
            (128, 2)
        );
        assert_eq!(
            read_varint(&[0xac, 0x02]).expect("decode protobuf varint 300"),
            (300, 2)
        );
    }

    #[tokio::test]
    async fn long_flow_addon_uses_protobuf_varint_and_parses() {
        let flow = "a".repeat(128);
        let addon =
            encode_flow_addon_data(&flow).expect("128-byte VLESS flow must encode");
        assert_eq!(&addon[..3], &[0x0a, 0x80, 0x01]);

        let mut request = vec![0];
        request.extend_from_slice(&[7u8; 16]);
        request.push(addon.len() as u8);
        request.extend_from_slice(&addon);
        request.push(COMMAND_MUX);
        let mut input = Cursor::new(request);

        let header = read_request_header(&mut input)
            .await
            .expect("parse VLESS header with a two-byte flow length");

        assert_eq!(header.flow, flow);
        assert_eq!(header.command, COMMAND_MUX);
    }

    #[tokio::test]
    async fn maximum_flow_addon_parses_through_request_header() {
        let flow = "a".repeat(252);
        let addon = encode_flow_addon_data(&flow)
            .expect("maximum VLESS flow addon must encode");
        assert_eq!(addon.len(), u8::MAX as usize);
        let mut request = vec![0];
        request.extend_from_slice(&[7u8; 16]);
        request.push(addon.len() as u8);
        request.extend_from_slice(&addon);
        request.push(COMMAND_MUX);
        let mut input = Cursor::new(request);

        let header = read_request_header(&mut input)
            .await
            .expect("maximum VLESS flow addon must parse");

        assert_eq!(header.flow, flow);
        assert_eq!(header.command, COMMAND_MUX);
    }

    #[tokio::test]
    async fn huge_tagged_and_legacy_flow_lengths_are_rejected_without_panicking() {
        let tagged = [vec![0x0a], vec![0xff; 9], vec![0x01]].concat();
        let legacy = [vec![0xff; 9], vec![0x01]].concat();

        for (format_name, addon) in [("tagged", tagged), ("legacy", legacy)] {
            let addon_length = addon.len() as u8;
            let mut input = Cursor::new(addon);
            let error = read_addons(&mut input, addon_length)
                .await
                .expect_err("huge VLESS flow length must fail");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidData,
                "{format_name}"
            );
            assert!(
                error.to_string().contains("overflows")
                    || error.to_string().contains("exceeds")
            );
        }
    }

    #[tokio::test]
    async fn malformed_flow_addons_are_rejected() {
        for (description, addon, expected_kind) in [
            (
                "missing tagged varint",
                vec![0x0a],
                std::io::ErrorKind::UnexpectedEof,
            ),
            (
                "invalid UTF-8 flow",
                vec![0x0a, 0x01, 0xff],
                std::io::ErrorKind::InvalidData,
            ),
            (
                "declared flow exceeds addon",
                vec![0x0a, 0x04, b'a'],
                std::io::ErrorKind::InvalidData,
            ),
        ] {
            let addon_length = addon.len() as u8;
            let mut input = Cursor::new(addon);
            let error = read_addons(&mut input, addon_length)
                .await
                .expect_err("malformed VLESS flow addon must fail");
            assert_eq!(error.kind(), expected_kind, "{description}");
        }
    }

    #[tokio::test]
    async fn tagged_flow_ignores_unknown_trailing_fields() {
        let mut addon = encode_flow_addon_data("plain-flow")
            .expect("encode VLESS flow with trailing field");
        addon.extend_from_slice(&[0x10, 0x01]);
        let addon_length = addon.len() as u8;
        let mut input = Cursor::new(addon);

        let flow = read_addons(&mut input, addon_length)
            .await
            .expect("unknown protobuf fields must be ignored");

        assert_eq!(flow, "plain-flow");
    }

    #[test]
    fn flow_addon_respects_u8_total_length_boundary() {
        let largest = "a".repeat(252);
        let encoded = encode_flow_addon_data(&largest)
            .expect("252-byte VLESS flow must fit the addon length byte");
        assert_eq!(encoded.len(), u8::MAX as usize);

        let error = encode_flow_addon_data(&"a".repeat(253))
            .expect_err("253-byte VLESS flow must exceed the addon length byte");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn protobuf_varint_rejects_truncation_and_overflow() {
        let truncated = read_varint(&[0x80])
            .expect_err("continued protobuf varint without a terminator must fail");
        assert_eq!(truncated.kind(), std::io::ErrorKind::UnexpectedEof);

        let overflow = read_varint(&[0xff; 10])
            .expect_err("protobuf varint larger than u64 must fail");
        assert_eq!(overflow.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn invalid_version_is_invalid_data() {
        let mut request = vec![1];
        request.extend_from_slice(&[7u8; 16]);
        request.push(0);
        let mut input = Cursor::new(request);

        let error = match read_request_header(&mut input).await {
            Ok(_) => panic!("invalid VLESS version must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn vision_flow_addon_bytes_match_encoder() {
        assert_eq!(
            vision_flow_addon_data(),
            encode_flow_addon_data(XTLS_VISION_FLOW)
                .expect("vision flow addon should encode")
        );
    }
}
