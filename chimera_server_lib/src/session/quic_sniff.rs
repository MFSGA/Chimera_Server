//! QUIC Initial ClientHello inspection used by Xray TUN UDP route-only sniffing.

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{self, EncryptingKey, UnboundCipherKey},
    hkdf::{self, KeyType},
};

use crate::tls_client_hello::{
    ClientHelloInspection, inspect_client_hello_handshake_for_xray_quic,
};

const MAX_QUIC_CRYPTO_BYTES: usize = 32_767;
const MAX_QUIC_PACKET_BYTES: usize = u16::MAX as usize;
const MAX_ACK_RANGES: u64 = 1024;

#[derive(Clone, Copy)]
struct InitialVersion {
    version: u32,
    initial_type: u8,
    retry_type: u8,
    salt: &'static [u8],
    label_prefix: &'static str,
}

const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4,
    0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const DRAFT_29_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c,
    0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
];
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e,
    0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

const INITIAL_VERSIONS: [InitialVersion; 3] = [
    InitialVersion {
        version: 0x0000_0001,
        initial_type: 0,
        retry_type: 3,
        salt: &V1_SALT,
        label_prefix: "quic",
    },
    InitialVersion {
        version: 0xff00_001d,
        initial_type: 0,
        retry_type: 3,
        salt: &DRAFT_29_SALT,
        label_prefix: "quic",
    },
    InitialVersion {
        version: 0x6b33_43cf,
        initial_type: 1,
        retry_type: 0,
        salt: &V2_SALT,
        label_prefix: "quicv2",
    },
];

struct OutputLength(usize);

impl KeyType for OutputLength {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Clone, Default)]
pub(crate) struct CryptoStream {
    bytes: Vec<u8>,
    present: Vec<bool>,
}

impl CryptoStream {
    fn insert(&mut self, offset: usize, bytes: &[u8]) -> bool {
        let Some(end) = offset.checked_add(bytes.len()) else {
            return false;
        };
        if end > MAX_QUIC_CRYPTO_BYTES {
            return false;
        }
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
            self.present.resize(end, false);
        }
        for (index, byte) in (offset..end).zip(bytes.iter().copied()) {
            if self.present[index] && self.bytes[index] != byte {
                return false;
            }
            self.bytes[index] = byte;
            self.present[index] = true;
        }
        true
    }

    fn contiguous_prefix(&self) -> &[u8] {
        let length = self.present.iter().take_while(|present| **present).count();
        &self.bytes[..length]
    }

    pub(crate) fn xray_quic_client_hello_inspection(&self) -> ClientHelloInspection {
        inspect_client_hello_handshake_for_xray_quic(self.contiguous_prefix())
    }
}

/// Extract a QUIC Initial ClientHello SNI from one UDP datagram.
#[cfg(test)]
pub(crate) fn inspect_quic_initial_server_name(datagram: &[u8]) -> Option<String> {
    let mut crypto_stream = CryptoStream::default();
    if !append_quic_initial_crypto(datagram, &mut crypto_stream) {
        return None;
    }
    match crypto_stream.xray_quic_client_hello_inspection() {
        ClientHelloInspection::ServerName(server_name) => {
            Some(server_name.to_ascii_lowercase())
        }
        _ => None,
    }
}

/// Append Initial CRYPTO fragments from one datagram to a bounded per-flow
/// stream. A ClientHello can span multiple QUIC Initial datagrams, so callers
/// keep this state only for the lifetime of the corresponding UDP flow.
pub(crate) fn append_quic_initial_crypto(
    datagram: &[u8],
    crypto_stream: &mut CryptoStream,
) -> bool {
    if datagram.is_empty() || datagram.len() > MAX_QUIC_PACKET_BYTES {
        return false;
    }

    let mut offset = 0usize;
    let mut staged_crypto_stream = crypto_stream.clone();
    let mut saw_initial = false;
    while offset < datagram.len() {
        let packet_start = offset;
        let Some(first_byte) = datagram.get(offset).copied() else {
            return false;
        };
        if first_byte & 0xc0 != 0xc0 {
            return false;
        }
        offset += 1;

        let Some(version_bytes) = datagram.get(offset..offset + 4) else {
            return false;
        };
        let Ok(version_bytes) = <[u8; 4]>::try_from(version_bytes) else {
            return false;
        };
        let version_number = u32::from_be_bytes(version_bytes);
        offset += 4;
        let Some(version) = INITIAL_VERSIONS
            .iter()
            .find(|version| version.version == version_number)
        else {
            return false;
        };

        let Some(destination_connection_id) =
            take_connection_id(datagram, &mut offset)
        else {
            return false;
        };
        let Some(_source_connection_id) = take_connection_id(datagram, &mut offset)
        else {
            return false;
        };
        let packet_type = (first_byte >> 4) & 0x03;
        if packet_type == version.retry_type {
            return false;
        }
        let is_initial = packet_type == version.initial_type;
        if is_initial {
            let Some(token_length) = read_varint(datagram, &mut offset)
                .and_then(|length| usize::try_from(length).ok())
            else {
                return false;
            };
            if token_length > MAX_QUIC_PACKET_BYTES {
                return false;
            }
            if take(datagram, &mut offset, token_length).is_none() {
                return false;
            }
        }

        let Some(packet_length) = read_varint(datagram, &mut offset)
            .and_then(|length| usize::try_from(length).ok())
        else {
            return false;
        };
        let packet_number_offset = offset;
        let Some(packet_end) = packet_number_offset.checked_add(packet_length)
        else {
            return false;
        };
        if packet_length < 4 || packet_end > datagram.len() {
            return false;
        }

        if is_initial {
            let Some(plaintext) = decrypt_initial_packet(
                &datagram[packet_start..packet_end],
                packet_number_offset - packet_start,
                packet_length,
                *version,
                destination_connection_id,
            ) else {
                return false;
            };
            if !collect_crypto_frames(&plaintext, &mut staged_crypto_stream) {
                return false;
            }
            saw_initial = true;
        }

        offset = packet_end;
    }

    if saw_initial {
        *crypto_stream = staged_crypto_stream;
    }
    saw_initial
}

fn take_connection_id<'a>(input: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let length = *input.get(*offset)? as usize;
    *offset += 1;
    if length > 20 {
        return None;
    }
    take(input, offset, length)
}

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let bytes = input.get(*offset..end)?;
    *offset = end;
    Some(bytes)
}

fn read_varint(input: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *input.get(*offset)?;
    let length = 1usize << (first >> 6);
    let bytes = take(input, offset, length)?;
    let mut value = (bytes[0] & 0x3f) as u64;
    for byte in bytes.iter().skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

fn decrypt_initial_packet(
    packet: &[u8],
    packet_number_offset: usize,
    packet_length: usize,
    version: InitialVersion,
    destination_connection_id: &[u8],
) -> Option<Vec<u8>> {
    let packet_end = packet_number_offset.checked_add(packet_length)?;
    if packet_end > packet.len()
        || packet_number_offset.checked_add(4 + 16)? > packet_end
    {
        return None;
    }

    let initial_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, version.salt)
        .extract(destination_connection_id);
    let client_secret = expand_label(&initial_secret, "client in", 32)?;
    let client_secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);
    let header_key =
        expand_label(&client_secret, &format!("{} hp", version.label_prefix), 16)?;
    let payload_key =
        expand_label(&client_secret, &format!("{} key", version.label_prefix), 16)?;
    let mut nonce = <[u8; 12]>::try_from(
        expand_label(&client_secret, &format!("{} iv", version.label_prefix), 12)?
            .as_slice(),
    )
    .ok()?;

    let sample_start = packet_number_offset.checked_add(4)?;
    let sample = packet.get(sample_start..sample_start + 16)?;
    let mut mask = sample.to_vec();
    EncryptingKey::ecb(UnboundCipherKey::new(&cipher::AES_128, &header_key).ok()?)
        .ok()?
        .encrypt(&mut mask)
        .ok()?;

    let mut unprotected = packet[..packet_end].to_vec();
    unprotected[0] ^= mask[0] & 0x0f;
    let packet_number_length = usize::from(unprotected[0] & 0x03) + 1;
    let payload_start = packet_number_offset.checked_add(packet_number_length)?;
    if payload_start > packet_end || packet_end - payload_start < 16 {
        return None;
    }
    for index in 0..packet_number_length {
        unprotected[packet_number_offset + index] ^= mask[index + 1];
    }

    let mut packet_number = [0u8; 8];
    packet_number[8 - packet_number_length..].copy_from_slice(
        &unprotected
            [packet_number_offset..packet_number_offset + packet_number_length],
    );
    for (iv_byte, number_byte) in nonce[4..].iter_mut().zip(packet_number) {
        *iv_byte ^= number_byte;
    }

    let mut payload_key = payload_key;
    let key =
        LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &payload_key).ok()?);
    payload_key.fill(0);
    let (header, ciphertext) = unprotected.split_at_mut(payload_start);
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            ciphertext,
        )
        .ok()?
        .to_vec();
    Some(plaintext)
}

fn expand_label(prk: &hkdf::Prk, label: &str, length: usize) -> Option<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let encoded_label_len = u8::try_from(full_label.len()).ok()?;
    let encoded_length = u16::try_from(length).ok()?;
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&encoded_length.to_be_bytes());
    info.push(encoded_label_len);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // Empty context.

    let info_parts = [&info[..]];
    let okm = prk.expand(&info_parts, OutputLength(length)).ok()?;
    let mut output = vec![0; length];
    okm.fill(&mut output).ok()?;
    Some(output)
}

fn collect_crypto_frames(payload: &[u8], crypto: &mut CryptoStream) -> bool {
    let mut offset = 0usize;
    while offset < payload.len() {
        let frame_type = payload[offset];
        offset += 1;
        if frame_type & 0xc0 != 0 {
            return false;
        }
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                if read_varint(payload, &mut offset).is_none()
                    || read_varint(payload, &mut offset).is_none()
                {
                    return false;
                }
                let Some(range_count) = read_varint(payload, &mut offset) else {
                    return false;
                };
                if range_count > MAX_ACK_RANGES
                    || read_varint(payload, &mut offset).is_none()
                {
                    return false;
                }
                for _ in 0..range_count {
                    if read_varint(payload, &mut offset).is_none()
                        || read_varint(payload, &mut offset).is_none()
                    {
                        return false;
                    }
                }
                if frame_type == 0x03
                    && (read_varint(payload, &mut offset).is_none()
                        || read_varint(payload, &mut offset).is_none()
                        || read_varint(payload, &mut offset).is_none())
                {
                    return false;
                }
            }
            0x06 => {
                let Some(crypto_offset) = read_varint(payload, &mut offset)
                    .and_then(|value| usize::try_from(value).ok())
                else {
                    return false;
                };
                let Some(length) = read_varint(payload, &mut offset)
                    .and_then(|value| usize::try_from(value).ok())
                else {
                    return false;
                };
                let Some(crypto_bytes) = take(payload, &mut offset, length) else {
                    return false;
                };
                if !crypto.insert(crypto_offset, crypto_bytes) {
                    return false;
                }
            }
            0x1c => {
                if read_varint(payload, &mut offset).is_none()
                    || read_varint(payload, &mut offset).is_none()
                {
                    return false;
                }
                let Some(reason_length) = read_varint(payload, &mut offset)
                    .and_then(|value| usize::try_from(value).ok())
                else {
                    return false;
                };
                if take(payload, &mut offset, reason_length).is_none() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_stream_accepts_ordered_fragments_and_rejects_conflicts() {
        let mut crypto = CryptoStream::default();
        assert!(crypto.insert(3, b"def"));
        assert!(crypto.contiguous_prefix().is_empty());
        assert!(crypto.insert(0, b"abc"));
        assert_eq!(crypto.contiguous_prefix(), b"abcdef");
        assert!(!crypto.insert(1, b"z"));
        assert!(!crypto.insert(MAX_QUIC_CRYPTO_BYTES, b"x"));
    }

    #[test]
    fn varint_reads_all_quic_encodings_and_rejects_truncation() {
        for (encoded, expected) in [
            (&[0x25][..], 37),
            (&[0x7b, 0xbd][..], 15_293),
            (&[0x9d, 0x7f, 0x3e, 0x7d][..], 494_878_333),
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
                151_288_809_941_952_652,
            ),
        ] {
            let mut offset = 0;
            assert_eq!(read_varint(encoded, &mut offset), Some(expected));
            assert_eq!(offset, encoded.len());
        }
        let mut offset = 0;
        assert_eq!(read_varint(&[0x40], &mut offset), None);
    }

    #[test]
    fn unsupported_and_truncated_datagrams_do_not_sniff() {
        assert_eq!(inspect_quic_initial_server_name(&[]), None);
        assert_eq!(inspect_quic_initial_server_name(&[0xc0, 0, 0, 0]), None);
        assert_eq!(inspect_quic_initial_server_name(&[0x40; 64]), None);
    }

    #[test]
    fn extracts_v1_server_name_from_the_pinned_xray_fixture() {
        let packet = decode_hex(include_str!("testdata/quic_v1_google.hex"));
        assert_eq!(
            inspect_quic_initial_server_name(&packet).as_deref(),
            Some("www.google.com")
        );
    }

    #[test]
    fn extracts_v2_server_name_from_the_pinned_xray_fixture() {
        let packet = decode_hex(include_str!("testdata/quic_v2_example.hex"));
        assert_eq!(
            inspect_quic_initial_server_name(&packet).as_deref(),
            Some("test.example.com")
        );
    }

    #[test]
    fn extracts_server_name_from_xray_26_9_9_xhttp_h3_initial_fragments() {
        let mut crypto_stream = CryptoStream::default();
        let mut captures =
            include_str!("testdata/quic_v1_xray_26_9_9_initials.hex").lines();
        let first = decode_hex(captures.next().expect("first captured Initial"));
        let second = decode_hex(captures.next().expect("second captured Initial"));
        assert!(captures.next().is_none(), "expected exactly two datagrams");

        assert!(append_quic_initial_crypto(&first, &mut crypto_stream));
        assert_eq!(
            crypto_stream.xray_quic_client_hello_inspection(),
            ClientHelloInspection::Incomplete
        );
        assert!(append_quic_initial_crypto(&second, &mut crypto_stream));
        assert_eq!(
            crypto_stream.xray_quic_client_hello_inspection(),
            ClientHelloInspection::ServerName("www.google.com".into())
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.trim().as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "hex fixture has an incomplete byte");
        pairs
            .iter()
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid hexadecimal fixture"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }
}
