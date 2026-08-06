use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{
    aead::{AES_128_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey},
    cipher::{
        AES_128, EncryptingKey as CipherEncryptingKey, EncryptionContext,
        UnboundCipherKey,
    },
};
use bytes::BytesMut;
use rand::Rng;

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncMessageStream, AsyncStream},
};

use super::{
    crc32::crc32c,
    fnv1a::Fnv1aHasher,
    md5::{compute_md5, create_chacha_key},
    nonce::{SingleUseNonce, VmessNonceSequence},
    sha2::{compute_sha256, kdf},
    vmess_stream::{ReadHeaderInfo, VmessStream},
};

const COMMAND_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const TAG_LEN: usize = 16;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmessDataSecurity {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl VmessDataSecurity {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                Ok(Self::ChaCha20Poly1305)
            }
            "none" | "zero" => Ok(Self::None),
            "" | "auto" => Err(
                "VMess outbound requires an explicit security value instead of auto"
                    .to_string(),
            ),
            other => Err(format!("unsupported VMess outbound security {other}")),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::None => "none",
        }
    }

    fn header_code(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::ChaCha20Poly1305 => 4,
            Self::None => 5,
        }
    }
}

pub(crate) fn parse_vmess_user_id(value: &str) -> Result<[u8; 16], String> {
    let value = value.trim();
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err("VMess user id must be a canonical UUID".to_string());
    }
    let mut output = [0u8; 16];
    let mut nibble = None;
    let mut offset = 0usize;
    for byte in value.bytes() {
        if byte == b'-' {
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err("VMess user id contains non-hex characters".to_string()),
        };
        if let Some(high) = nibble.take() {
            let slot = output
                .get_mut(offset)
                .ok_or_else(|| "VMess user id is too long".to_string())?;
            *slot = (high << 4) | value;
            offset += 1;
        } else {
            nibble = Some(value);
        }
    }
    if offset != 16 || nibble.is_some() {
        return Err("VMess user id must contain 16 bytes".to_string());
    }
    Ok(output)
}

pub(crate) fn format_vmess_user_id(value: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        value[9],
        value[10],
        value[11],
        value[12],
        value[13],
        value[14],
        value[15],
    )
}

pub(crate) fn connect_vmess_tcp(
    stream: Box<dyn AsyncStream>,
    user_uuid: [u8; 16],
    security: VmessDataSecurity,
    target: &NetLocation,
) -> std::io::Result<Box<dyn AsyncStream>> {
    Ok(Box::new(build_vmess_stream(
        stream,
        user_uuid,
        security,
        target,
        COMMAND_TCP,
        false,
    )?))
}

pub(crate) fn connect_vmess_udp(
    stream: Box<dyn AsyncStream>,
    user_uuid: [u8; 16],
    security: VmessDataSecurity,
    target: &NetLocation,
) -> std::io::Result<Box<dyn AsyncMessageStream>> {
    Ok(Box::new(build_vmess_stream(
        stream,
        user_uuid,
        security,
        target,
        COMMAND_UDP,
        true,
    )?))
}

fn build_vmess_stream(
    stream: Box<dyn AsyncStream>,
    user_uuid: [u8; 16],
    security: VmessDataSecurity,
    target: &NetLocation,
    command: u8,
    is_udp: bool,
) -> std::io::Result<VmessStream> {
    let mut rng = rand::rng();
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    let mut auth_random = [0u8; 4];
    let mut header_nonce = [0u8; 8];
    let mut response_authentication = [0u8; 1];
    rng.fill_bytes(&mut data_iv);
    rng.fill_bytes(&mut data_key);
    rng.fill_bytes(&mut auth_random);
    rng.fill_bytes(&mut header_nonce);
    rng.fill_bytes(&mut response_authentication);

    let auth_id = build_auth_id(user_uuid, auth_random)?;
    let header = build_request_header(
        security,
        &data_iv,
        &data_key,
        response_authentication[0],
        command,
        target,
    )?;
    let request_prefix =
        encrypt_request_header(user_uuid, auth_id, header_nonce, &header)?;

    let response_iv = first_16(&compute_sha256(&data_iv));
    let response_key = first_16(&compute_sha256(&data_key));
    let encryption_keys = match security {
        VmessDataSecurity::Aes128Gcm => Some((
            OpeningKey::new(
                UnboundKey::new(&AES_128_GCM, &response_key).map_err(|_| {
                    std::io::Error::other("invalid VMess AES response key")
                })?,
                VmessNonceSequence::new(&response_iv),
            ),
            SealingKey::new(
                UnboundKey::new(&AES_128_GCM, &data_key).map_err(|_| {
                    std::io::Error::other("invalid VMess AES request key")
                })?,
                VmessNonceSequence::new(&data_iv),
            ),
        )),
        VmessDataSecurity::ChaCha20Poly1305 => Some((
            OpeningKey::new(
                UnboundKey::new(
                    &aws_lc_rs::aead::CHACHA20_POLY1305,
                    &create_chacha_key(&response_key),
                )
                .map_err(|_| {
                    std::io::Error::other("invalid VMess ChaCha response key")
                })?,
                VmessNonceSequence::new(&response_iv),
            ),
            SealingKey::new(
                UnboundKey::new(
                    &aws_lc_rs::aead::CHACHA20_POLY1305,
                    &create_chacha_key(&data_key),
                )
                .map_err(|_| {
                    std::io::Error::other("invalid VMess ChaCha request key")
                })?,
                VmessNonceSequence::new(&data_iv),
            ),
        )),
        VmessDataSecurity::None => None,
    };

    Ok(VmessStream::new(
        stream,
        is_udp,
        encryption_keys,
        None,
        None,
        false,
        Some(BytesMut::from(request_prefix.as_slice())),
        Some(ReadHeaderInfo {
            response_header_key: response_key,
            response_header_iv: response_iv,
            response_authentication_v: response_authentication[0],
        }),
    ))
}

fn build_auth_id(user_uuid: [u8; 16], random: [u8; 4]) -> std::io::Result<[u8; 16]> {
    let instruction_key = command_key(user_uuid);
    let derived_key = kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
    let unbound_key = UnboundCipherKey::new(&AES_128, &derived_key[..16])
        .map_err(|_| std::io::Error::other("invalid VMess AuthID key"))?;
    let encrypting_key = CipherEncryptingKey::ecb(unbound_key)
        .map_err(|_| std::io::Error::other("failed to create VMess AuthID key"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            std::io::Error::other(format!(
                "system clock is before Unix epoch: {error}"
            ))
        })?
        .as_secs();
    let mut auth_id = [0u8; 16];
    auth_id[..8].copy_from_slice(&timestamp.to_be_bytes());
    auth_id[8..12].copy_from_slice(&random);
    let checksum = crc32c(&auth_id[..12]);
    auth_id[12..].copy_from_slice(&checksum.to_be_bytes());
    encrypting_key
        .less_safe_encrypt(&mut auth_id, EncryptionContext::None)
        .map_err(|_| std::io::Error::other("failed to encrypt VMess AuthID"))?;
    Ok(auth_id)
}

fn build_request_header(
    security: VmessDataSecurity,
    data_iv: &[u8; 16],
    data_key: &[u8; 16],
    response_authentication: u8,
    command: u8,
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(80);
    header.push(1);
    header.extend_from_slice(data_iv);
    header.extend_from_slice(data_key);
    header.push(response_authentication);
    header.push(0x01);
    header.push(security.header_code());
    header.push(0);
    header.push(command);
    header.extend_from_slice(&target.port().to_be_bytes());
    match target.address() {
        Address::Ipv4(address) => {
            header.push(1);
            header.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            let length = u8::try_from(hostname.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VMess target domain exceeds 255 bytes",
                )
            })?;
            if length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VMess target domain must not be empty",
                ));
            }
            header.push(2);
            header.push(length);
            header.extend_from_slice(hostname.as_bytes());
        }
        Address::Ipv6(address) => {
            header.push(3);
            header.extend_from_slice(&address.octets());
        }
    }
    let mut checksum = Fnv1aHasher::new();
    checksum.write(&header);
    header.extend_from_slice(&checksum.finish().to_be_bytes());
    Ok(header)
}

fn encrypt_request_header(
    user_uuid: [u8; 16],
    auth_id: [u8; 16],
    nonce: [u8; 8],
    header: &[u8],
) -> std::io::Result<Vec<u8>> {
    let instruction_key = command_key(user_uuid);
    let header_length_key = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let header_length_nonce = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let mut encrypted_length = [0u8; 2 + TAG_LEN];
    encrypted_length[..2].copy_from_slice(
        &u16::try_from(header.len())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VMess request header exceeds u16",
                )
            })?
            .to_be_bytes(),
    );
    let mut sealing_key = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &header_length_key[..16])
            .map_err(|_| std::io::Error::other("invalid VMess header length key"))?,
        SingleUseNonce::new(&header_length_nonce[..12]),
    );
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::from(&auth_id), &mut encrypted_length[..2])
        .map_err(|_| {
            std::io::Error::other("failed to encrypt VMess header length")
        })?;
    encrypted_length[2..].copy_from_slice(tag.as_ref());

    let header_key = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let mut encrypted_header = header.to_vec();
    let mut sealing_key = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &header_key[..16])
            .map_err(|_| std::io::Error::other("invalid VMess header key"))?,
        SingleUseNonce::new(&header_nonce[..12]),
    );
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::from(&auth_id), &mut encrypted_header)
        .map_err(|_| {
            std::io::Error::other("failed to encrypt VMess request header")
        })?;
    encrypted_header.extend_from_slice(tag.as_ref());

    let mut output = Vec::with_capacity(
        auth_id.len()
            + encrypted_length.len()
            + nonce.len()
            + encrypted_header.len(),
    );
    output.extend_from_slice(&auth_id);
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted_header);
    Ok(output)
}

fn command_key(user_uuid: [u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + COMMAND_KEY_SALT.len());
    input.extend_from_slice(&user_uuid);
    input.extend_from_slice(COMMAND_KEY_SALT);
    compute_md5(&input)
}

fn first_16(input: &[u8; 32]) -> [u8; 16] {
    let mut output = [0u8; 16];
    output.copy_from_slice(&input[..16]);
    output
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, pin::Pin};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    use crate::{
        async_stream::AsyncMessageStream,
        config::server_config::VmessUser,
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::*;
    use crate::handler::vmess::vmess_handler::VmessTcpServerHandler;

    async fn write_message(stream: &mut dyn AsyncMessageStream, payload: &[u8]) {
        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
            .await
            .unwrap();
    }

    async fn read_message(
        stream: &mut dyn AsyncMessageStream,
        buffer: &mut [u8],
    ) -> usize {
        let mut read_buffer = ReadBuf::new(buffer);
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut read_buffer))
            .await
            .unwrap();
        read_buffer.filled().len()
    }

    #[tokio::test]
    async fn client_roundtrips_supported_security_matrix() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let user_uuid = uuid::Uuid::parse_str(user_id).unwrap().into_bytes();
        let target = NetLocation::new(Address::Hostname("echo.example".into()), 443);
        for (security, name) in [
            (VmessDataSecurity::None, "none"),
            (VmessDataSecurity::Aes128Gcm, "aes-128-gcm"),
            (VmessDataSecurity::ChaCha20Poly1305, "chacha20-poly1305"),
        ] {
            let (client, server) = tokio::io::duplex(256 * 1024);
            let handler = VmessTcpServerHandler::new(
                vec![VmessUser {
                    user_id: user_id.into(),
                    user_label: "vmess-client-test".into(),
                    cipher: name.into(),
                }],
                false,
                "vmess-client-test",
            );
            let expected_target = target.clone();
            let server_task = tokio::spawn(async move {
                let result =
                    handler.setup_server_stream(Box::new(server)).await.unwrap();
                let TcpServerSetupResult::TcpForward {
                    remote_location,
                    mut stream,
                    ..
                } = result
                else {
                    panic!("expected VMess TCP forward");
                };
                assert_eq!(remote_location, expected_target);
                let mut payload = vec![0u8; 32 * 1024];
                stream.read_exact(&mut payload).await.unwrap();
                assert!(
                    payload
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| *byte == (index % 251) as u8)
                );
                stream.write_all(b"vmess-response").await.unwrap();
                stream.flush().await.unwrap();
            });

            let mut stream =
                connect_vmess_tcp(Box::new(client), user_uuid, security, &target)
                    .unwrap();
            let payload = (0..32 * 1024)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0u8; 14];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"vmess-response");
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_client_roundtrips_supported_security_matrix() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let user_uuid = uuid::Uuid::parse_str(user_id).unwrap().into_bytes();
        let target = NetLocation::new(Address::Hostname("dns.example".into()), 53);
        for (security, name) in [
            (VmessDataSecurity::None, "none"),
            (VmessDataSecurity::Aes128Gcm, "aes-128-gcm"),
            (VmessDataSecurity::ChaCha20Poly1305, "chacha20-poly1305"),
        ] {
            let (client, server) = tokio::io::duplex(256 * 1024);
            let handler = VmessTcpServerHandler::new(
                vec![VmessUser {
                    user_id: user_id.into(),
                    user_label: "vmess-udp-client-test".into(),
                    cipher: name.into(),
                }],
                true,
                "vmess-udp-client-test",
            );
            let expected_target = target.clone();
            let server_task = tokio::spawn(async move {
                let result =
                    handler.setup_server_stream(Box::new(server)).await.unwrap();
                let TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    mut stream,
                    ..
                } = result
                else {
                    panic!("expected VMess UDP forward");
                };
                assert_eq!(remote_location, expected_target);
                let mut payload = [0u8; 64];
                let len = read_message(&mut *stream, &mut payload).await;
                assert_eq!(&payload[..len], b"vmess-udp-query");
                write_message(&mut *stream, b"vmess-udp-answer").await;
            });

            let mut stream =
                connect_vmess_udp(Box::new(client), user_uuid, security, &target)
                    .unwrap();
            write_message(&mut *stream, b"vmess-udp-query").await;
            let mut response = [0u8; 64];
            let len = read_message(&mut *stream, &mut response).await;
            assert_eq!(&response[..len], b"vmess-udp-answer");
            server_task.await.unwrap();
        }
    }
}
