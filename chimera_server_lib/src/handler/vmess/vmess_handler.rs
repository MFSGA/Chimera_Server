use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use async_trait::async_trait;
use aws_lc_rs::aead::{
    AES_128_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey,
};
use aws_lc_rs::cipher::{
    AES_128, DecryptingKey as CipherDecryptingKey, DecryptionContext,
    UnboundCipherKey,
};
use bytes::BytesMut;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update};
use tokio::io::AsyncReadExt;

use super::fnv1a::Fnv1aHasher;
use super::md5::{compute_md5, create_chacha_key};
use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::vmess_stream::VmessStream;
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::traffic::TrafficContext;
use crate::util::allocate_vec;

const TAG_LEN: usize = 16;

const COMMAND_TCP: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DataCipher {
    Any,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl DataCipher {
    fn from_name(name: &str) -> Self {
        match name {
            "" | "any" => DataCipher::Any,
            "aes-128-gcm" => DataCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => DataCipher::ChaCha20Poly1305,
            "none" => DataCipher::None,
            _ => DataCipher::Any,
        }
    }
}

pub struct VmessTcpServerHandler {
    data_cipher: DataCipher,
    instruction_key: [u8; 16],
    aead_decrypting_key: CipherDecryptingKey,
    udp_enabled: bool,
    inbound_tag: String,
    user_label: String,
}

impl std::fmt::Debug for VmessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessTcpServerHandler")
            .field("data_cipher", &self.data_cipher)
            .field("udp_enabled", &self.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl VmessTcpServerHandler {
    pub fn new(
        cipher_name: &str,
        user_id: &str,
        udp_enabled: bool,
        inbound_tag: &str,
        user_label: &str,
    ) -> Self {
        let mut user_id_bytes = parse_uuid(user_id);
        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let unbound_key = UnboundCipherKey::new(&AES_128, &derived_key[0..16]).unwrap();
        let aead_decrypting_key = CipherDecryptingKey::ecb(unbound_key).unwrap();

        Self {
            data_cipher: DataCipher::from_name(cipher_name),
            aead_decrypting_key,
            instruction_key,
            udp_enabled,
            inbound_tag: inbound_tag.to_string(),
            user_label: user_label.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for VmessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut cert_hash = [0u8; 16];
        server_stream.read_exact(&mut cert_hash).await?;

        let mut aead_bytes = [0u8; 16];
        aead_bytes.copy_from_slice(&cert_hash);

        self.aead_decrypting_key
            .decrypt(&mut aead_bytes, DecryptionContext::None)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "AEAD auth ID decryption failed",
                )
            })?;

        let checksum = super::crc32::crc32c(&aead_bytes[0..12]);
        let expected_checksum = u32::from_be_bytes(aead_bytes[12..16].try_into().unwrap());

        if checksum != expected_checksum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AEAD authentication failed: checksum mismatch",
            ));
        }

        let time_secs = u64::from_be_bytes(aead_bytes[0..8].try_into().unwrap());
        let current_time_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let time_delta = time_secs.abs_diff(current_time_secs);
        if time_delta > 120 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Hash timestamp is too old ({time_secs} is {time_delta} seconds old)"),
            ));
        }

        let mut encrypted_payload_length = [0u8; 18];
        server_stream.read_exact(&mut encrypted_payload_length).await?;

        let mut nonce = [0u8; 8];
        server_stream.read_exact(&mut nonce).await?;

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );
        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_payload_length)
            .is_err()
        {
            return Err(std::io::Error::other("failed to open encrypted header length"));
        }

        let payload_length = u16::from_be_bytes(encrypted_payload_length[0..2].try_into().unwrap());

        let header_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );
        let header_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let mut encrypted_header = allocate_vec(payload_length as usize + TAG_LEN).into_boxed_slice();
        server_stream.read_exact(&mut encrypted_header).await?;

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut opening_key =
            OpeningKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_header)
            .is_err()
        {
            return Err(std::io::Error::other("failed to open encrypted header"));
        }

        let decrypted_header = encrypted_header;
        let mut cursor = 0usize;
        let mut fnv_hasher = Fnv1aHasher::new();

        let fixed_header = &decrypted_header[cursor..cursor + 38];
        cursor += 38;
        fnv_hasher.write(fixed_header);

        if fixed_header[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid version {}", fixed_header[0]),
            ));
        }

        let command = fixed_header[37];

        if command != COMMAND_TCP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("VMess command {} is not supported (only TCP is supported)", command),
            ));
        }

        let port_and_addr_type = &decrypted_header[cursor..cursor + 3];
        cursor += 3;
        fnv_hasher.write(port_and_addr_type);

        let port = u16::from_be_bytes(port_and_addr_type[0..2].try_into().unwrap());

        let remote_location = match port_and_addr_type[2] {
            1 => {
                let address_bytes = &decrypted_header[cursor..cursor + 4];
                cursor += 4;
                fnv_hasher.write(address_bytes);
                let v4addr = Ipv4Addr::new(
                    address_bytes[0], address_bytes[1], address_bytes[2], address_bytes[3],
                );
                NetLocation::new(Address::Ipv4(v4addr), port)
            }
            2 => {
                let domain_name_len = decrypted_header[cursor];
                cursor += 1;
                fnv_hasher.write(&[domain_name_len]);

                let domain_name_bytes = &decrypted_header[cursor..cursor + domain_name_len as usize];
                cursor += domain_name_len as usize;
                fnv_hasher.write(domain_name_bytes);

                let address_str = std::str::from_utf8(domain_name_bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {e}"),
                    )
                })?;
                NetLocation::new(Address::from(address_str)?, port)
            }
            3 => {
                let address_bytes = &decrypted_header[cursor..cursor + 16];
                cursor += 16;
                fnv_hasher.write(address_bytes);
                let v6addr = Ipv6Addr::new(
                    u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
                );
                NetLocation::new(Address::Ipv6(v6addr), port)
            }
            invalid_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address type: {invalid_type}"),
                ));
            }
        };

        let margin_len: u8 = fixed_header[35] >> 4;
        if margin_len > 0 {
            let margin_bytes = &decrypted_header[cursor..cursor + margin_len as usize];
            cursor += margin_len as usize;
            fnv_hasher.write(margin_bytes);
        }

        let check_bytes = &decrypted_header[cursor..cursor + 4];

        let expected_check_value = u32::from_be_bytes(check_bytes[0..4].try_into().unwrap());
        let actual_check_value = fnv_hasher.finish();
        if expected_check_value != actual_check_value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad fnv1a checksum, expected {expected_check_value}, got {actual_check_value}"),
            ));
        }

        let data_encryption_iv: &[u8] = &fixed_header[1..17];
        let data_encryption_key: &[u8] = &fixed_header[17..33];
        let response_authentication_v = fixed_header[33];
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

        let requested_data_cipher = match fixed_header[35] & 0b1111 {
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

        if self.data_cipher != DataCipher::Any && requested_data_cipher != self.data_cipher {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Server only allows {:?} but client requested {:?}",
                    self.data_cipher, requested_data_cipher
                ),
            ));
        }

        let response_header: [u8; 4] = [
            response_authentication_v,
            0,
            0,
            0,
        ];

        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

        let unbound_keys = match requested_data_cipher {
            DataCipher::Aes128Gcm => {
                Some((
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                ))
            }
            DataCipher::ChaCha20Poly1305 => {
                Some((
                    UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &create_chacha_key(data_encryption_key)).unwrap(),
                    UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &create_chacha_key(&response_header_key)).unwrap(),
                ))
            }
            DataCipher::None => None,
            DataCipher::Any => unreachable!(),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        let (read_length_shake_reader, write_length_shake_reader) = if enable_chunk_masking {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(request_reader), Some(response_reader))
        } else {
            (None, None)
        };

        let response_header_length_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Len Key"]);
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header Len IV"]);

        let mut encrypted_response_header = [0u8; 2 + TAG_LEN + 4 + TAG_LEN];
        encrypted_response_header[1] = 4;

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_response_header[0..2])
            .unwrap();
        encrypted_response_header[2..2 + TAG_LEN].copy_from_slice(tag.as_ref());

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header IV"]);
        let unbound_key = UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4].copy_from_slice(&response_header);

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4],
            )
            .unwrap();
        encrypted_response_header[2 + TAG_LEN + 4..].copy_from_slice(tag.as_ref());

        let prefix_bytes = BytesMut::from(&encrypted_response_header[..]);

        let vmess_stream = VmessStream::new(
            server_stream,
            false,
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            enable_global_padding,
            Some(prefix_bytes),
            None,
        );

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(vmess_stream),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context: Some(
                TrafficContext::new("vmess")
                    .with_identity(self.user_label.clone())
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        })
    }
}

fn parse_uuid(uuid_str: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    let mut first_nibble: Option<u8> = None;
    for &c in uuid_str.as_bytes() {
        let hex = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b'-' => continue,
            _ => continue,
        };
        if let Some(first) = first_nibble.take() {
            bytes.push((first << 4) | hex);
        } else {
            first_nibble = Some(hex);
        }
    }
    bytes
}
