#![cfg(feature = "vless")]

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::ReadBuf;
use tracing::warn;

use crate::{
    async_stream::AsyncStream, config::server_config::VlessUser,
    traffic::TrafficContext,
};

pub(crate) mod protocol;
mod reality_vision_stream;
mod vision;
mod vision_pad;
mod vision_stream;
mod vision_unpad;

use self::protocol::{
    COMMAND_TCP, ParsedVlessHeader, XTLS_VISION_FLOW, read_request_header,
};
use super::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use vision_pad::{pad_with_command, pad_with_uuid_and_command};
use vision_unpad::{UnpadCommand, VisionUnpadder};

pub(crate) use vision::{ParsedVisionUser, parse_vision_users};
pub use vision::{VisionVlessTcpHandler, setup_reality_vision_server_stream};

const SERVER_RESPONSE_HEADER: &[u8] = &[0u8, 0u8];

#[derive(Debug)]
pub struct VlessTcpHandler {
    users: Vec<(Box<[u8]>, String, String)>,
    inbound_tag: String,
}

impl VlessTcpHandler {
    pub fn new(users: &[VlessUser], inbound_tag: &str) -> Self {
        Self {
            users: users
                .iter()
                .map(|user| {
                    (
                        parse_hex(&user.user_id),
                        user.user_label.clone(),
                        user.flow.clone(),
                    )
                })
                .collect(),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

pub fn users_require_vision(users: &[VlessUser]) -> bool {
    users.iter().any(|user| user.flow == XTLS_VISION_FLOW)
}

#[async_trait]
impl TcpServerHandler for VlessTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedVlessHeader {
            user_id,
            flow: request_flow,
            command,
            remote_location,
        } = read_request_header(&mut server_stream).await?;
        let matched_user = self.users.iter().find(|(stored_user_id, _, _)| {
            stored_user_id.len() == 16
                && stored_user_id.as_ref() == user_id.as_slice()
        });

        let Some((_, user_label, configured_flow)) = matched_user else {
            let expected = self
                .users
                .iter()
                .map(|(user_id, _, _)| encode_hex(user_id.as_ref()))
                .collect::<Vec<_>>()
                .join(",");
            let got = encode_hex(&user_id);
            warn!(
                inbound_tag = %self.inbound_tag,
                expected = %expected,
                got = %got,
                "VLESS inbound rejected request with mismatched user id"
            );

            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("invalid VLESS user id: {got}"),
            ));
        };

        validate_request_flow(configured_flow, &request_flow, command)?;

        match command {
            COMMAND_TCP => {}
            protocol::COMMAND_UDP => {
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

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: true,

            connection_success_response: Some(
                SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
            ),
            traffic_context: Some(
                TrafficContext::new("vless")
                    .with_identity(user_label.clone())
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        })
    }
}

fn validate_request_flow(
    configured_flow: &str,
    request_flow: &str,
    command: u8,
) -> std::io::Result<()> {
    match request_flow {
        "" => {
            if configured_flow == XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "client flow is empty but account requires xtls-rprx-vision",
                ));
            }
        }
        XTLS_VISION_FLOW => {
            if configured_flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("account is not allowed to use flow {XTLS_VISION_FLOW}"),
                ));
            }
            if command != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xtls-rprx-vision currently supports only TCP requests",
                ));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "xtls-rprx-vision requires a dedicated Vision handler",
            ));
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown request flow {other}"),
            ));
        }
    }

    Ok(())
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

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(crate) fn looks_like_tls_record(data: &[u8]) -> bool {
    data.len() >= 5
        && matches!(data[0], 0x14..=0x17)
        && data[1] == 0x03
        && matches!(data[2], 0x01..=0x03)
}

pub(crate) fn contains_tls_application_data(data: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor + 5 <= data.len() {
        let content_type = data[cursor];
        let version_major = data[cursor + 1];
        let version_minor = data[cursor + 2];
        let payload_len =
            u16::from_be_bytes([data[cursor + 3], data[cursor + 4]]) as usize;
        if version_major != 0x03 || !(0x01..=0x03).contains(&version_minor) {
            return false;
        }

        let end = cursor + 5 + payload_len;
        if end > data.len() {
            return false;
        }
        if content_type == 0x17 {
            return true;
        }
        cursor = end;
    }

    false
}

pub(crate) fn drain_pending_read(
    pending_read: &mut BytesMut,
    buf: &mut ReadBuf<'_>,
) -> bool {
    if pending_read.is_empty() {
        return false;
    }

    let len = buf.remaining().min(pending_read.len());
    buf.put_slice(&pending_read[..len]);
    pending_read.advance(len);
    true
}

pub(crate) fn append_plaintext_to_read_buf(
    pending_read: &mut BytesMut,
    buf: &mut ReadBuf<'_>,
    plaintext: &[u8],
) {
    let len = buf.remaining().min(plaintext.len());
    buf.put_slice(&plaintext[..len]);
    if len < plaintext.len() {
        pending_read.extend_from_slice(&plaintext[len..]);
    }
}

pub(crate) fn take_vless_response_header(
    vless_response_to_send: &mut bool,
) -> Option<&'static [u8]> {
    if *vless_response_to_send {
        *vless_response_to_send = false;
        Some(SERVER_RESPONSE_HEADER)
    } else {
        None
    }
}

pub(crate) fn bounded_write_chunk<'a>(
    buf: &'a [u8],
    max_content_len: usize,
) -> &'a [u8] {
    &buf[..buf.len().min(max_content_len)]
}

pub(crate) fn queue_padded_packet(
    pending_write: &mut BytesMut,
    first_write: &mut bool,
    user_uuid: &[u8; 16],
    content: &[u8],
    command: u8,
) {
    let is_tls = looks_like_tls_record(content);
    let packet = if *first_write {
        *first_write = false;
        pad_with_uuid_and_command(content, user_uuid, command, is_tls)
    } else {
        pad_with_command(content, command, is_tls)
    };
    pending_write.extend_from_slice(&packet);
}

pub(crate) fn unpad_into_pending_read(
    unpadder: &mut VisionUnpadder,
    pending_read: &mut BytesMut,
    padded: &[u8],
) -> std::io::Result<Option<UnpadCommand>> {
    let result = unpadder.unpad(padded)?;
    if !result.content.is_empty() {
        pending_read.extend_from_slice(&result.content);
    }
    Ok(result.command)
}

#[cfg(test)]
mod tests {
    use super::{
        XTLS_VISION_FLOW, append_plaintext_to_read_buf, bounded_write_chunk,
        contains_tls_application_data, drain_pending_read, looks_like_tls_record,
        queue_padded_packet, take_vless_response_header, unpad_into_pending_read,
        validate_request_flow,
    };
    use crate::handler::vless_handler::vision_unpad::{
        UnpadCommand, VisionUnpadder,
    };
    use bytes::BytesMut;
    use tokio::io::ReadBuf;

    #[test]
    fn validate_request_flow_allows_plain_vless() {
        validate_request_flow("", "", 1).expect("plain vless should be allowed");
    }

    #[test]
    fn validate_request_flow_rejects_vision_on_plain_account() {
        let err = validate_request_flow("", XTLS_VISION_FLOW, 1)
            .expect_err("plain account should reject vision");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_request_flow_rejects_missing_vision_flow() {
        let err = validate_request_flow(XTLS_VISION_FLOW, "", 1)
            .expect_err("vision account should require client flow");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_request_flow_marks_vision_as_unimplemented() {
        let err = validate_request_flow(XTLS_VISION_FLOW, XTLS_VISION_FLOW, 1)
            .expect_err("vision should require dedicated handler");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn looks_like_tls_record_accepts_tls_header() {
        assert!(looks_like_tls_record(&[0x16, 0x03, 0x03, 0x00, 0x10]));
    }

    #[test]
    fn contains_tls_application_data_detects_app_record() {
        let record = [0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02];
        assert!(contains_tls_application_data(&record));
    }

    #[test]
    fn drain_pending_read_moves_data_into_readbuf() {
        let mut pending = BytesMut::from(&b"hello"[..]);
        let mut storage = [0u8; 3];
        let mut read_buf = ReadBuf::new(&mut storage);

        assert!(drain_pending_read(&mut pending, &mut read_buf));
        assert_eq!(read_buf.filled(), b"hel");
        assert_eq!(&pending[..], b"lo");
    }

    #[test]
    fn append_plaintext_to_read_buf_spills_remainder() {
        let mut pending = BytesMut::new();
        let mut storage = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut storage);

        append_plaintext_to_read_buf(&mut pending, &mut read_buf, b"abcd");

        assert_eq!(read_buf.filled(), b"ab");
        assert_eq!(&pending[..], b"cd");
    }

    #[test]
    fn unpad_into_pending_read_returns_command_and_content() {
        let uuid = [9u8; 16];
        let mut padded = BytesMut::new();
        let mut first_write = true;
        queue_padded_packet(&mut padded, &mut first_write, &uuid, b"ping", 0);

        let mut pending = BytesMut::new();
        let mut unpadder = VisionUnpadder::new(uuid);
        let command = unpad_into_pending_read(&mut unpadder, &mut pending, &padded)
            .expect("unpad should succeed");

        assert_eq!(command, Some(UnpadCommand::Continue));
        assert_eq!(&pending[..], b"ping");
    }

    #[test]
    fn take_vless_response_header_only_returns_once() {
        let mut should_send = true;
        assert_eq!(
            take_vless_response_header(&mut should_send),
            Some(&[0, 0][..])
        );
        assert_eq!(take_vless_response_header(&mut should_send), None);
    }

    #[test]
    fn bounded_write_chunk_limits_to_max_content_len() {
        assert_eq!(bounded_write_chunk(b"abcdef", 4), b"abcd");
        assert_eq!(bounded_write_chunk(b"ab", 4), b"ab");
    }
}
