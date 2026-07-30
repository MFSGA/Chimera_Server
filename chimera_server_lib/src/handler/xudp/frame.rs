use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::address::{Address, NetLocation};

const MAX_METADATA_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SessionStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

impl TryFrom<u8> for SessionStatus {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::New),
            0x02 => Ok(Self::Keep),
            0x03 => Ok(Self::End),
            0x04 => Ok(Self::KeepAlive),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid XUDP session status: {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct FrameOption(u8);

impl FrameOption {
    pub(crate) const DATA: u8 = 0x01;
    pub(crate) const ERROR: u8 = 0x02;

    pub(crate) fn with_data(mut self) -> Self {
        self.0 |= Self::DATA;
        self
    }

    pub(crate) fn with_error(mut self) -> Self {
        self.0 |= Self::ERROR;
        self
    }

    pub(crate) fn has_data(self) -> bool {
        self.0 & Self::DATA != 0
    }

    pub(crate) fn has_error(self) -> bool {
        self.0 & Self::ERROR != 0
    }

    fn raw(self) -> u8 {
        self.0
    }
}

impl From<u8> for FrameOption {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum TargetNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TryFrom<u8> for TargetNetwork {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid XUDP target network: {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameMetadata {
    pub(crate) session_id: u16,
    pub(crate) status: SessionStatus,
    pub(crate) option: FrameOption,
    pub(crate) target: Option<NetLocation>,
    pub(crate) network: Option<TargetNetwork>,
    pub(crate) global_id: Option<[u8; 8]>,
}

impl FrameMetadata {
    pub(crate) fn encode(&self, output: &mut BytesMut) -> std::io::Result<()> {
        let frame_start = output.len();
        let result = self.encode_inner(output);
        if result.is_err() {
            output.truncate(frame_start);
        }
        result
    }

    fn encode_inner(&self, output: &mut BytesMut) -> std::io::Result<()> {
        let length_offset = output.len();
        output.put_u16(0);
        let metadata_start = output.len();

        output.put_u16(self.session_id);
        output.put_u8(self.status as u8);
        output.put_u8(self.option.raw());

        match self.status {
            SessionStatus::New => {
                let network = self.network.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "XUDP New frame requires a target network",
                    )
                })?;
                let target = self.target.as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "XUDP New frame requires a target",
                    )
                })?;
                encode_target(output, network, target)?;
                if network == TargetNetwork::Udp
                    && self.option.has_data()
                    && let Some(global_id) = self.global_id
                {
                    output.extend_from_slice(&global_id);
                }
            }
            SessionStatus::Keep => {
                if let (Some(TargetNetwork::Udp), Some(target)) =
                    (self.network, self.target.as_ref())
                {
                    encode_target(output, TargetNetwork::Udp, target)?;
                }
            }
            SessionStatus::End | SessionStatus::KeepAlive => {}
        }

        let metadata_length = output.len() - metadata_start;
        if metadata_length > MAX_METADATA_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "XUDP metadata exceeds {MAX_METADATA_LENGTH} bytes: {metadata_length}"
                ),
            ));
        }
        output[length_offset..length_offset + 2]
            .copy_from_slice(&(metadata_length as u16).to_be_bytes());
        Ok(())
    }

    pub(crate) fn decode(input: &mut BytesMut) -> std::io::Result<Option<Self>> {
        if input.len() < 2 {
            return Ok(None);
        }
        let metadata_length = u16::from_be_bytes([input[0], input[1]]) as usize;
        if metadata_length > MAX_METADATA_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "XUDP metadata exceeds {MAX_METADATA_LENGTH} bytes: {metadata_length}"
                ),
            ));
        }
        if input.len() < metadata_length + 2 {
            return Ok(None);
        }

        let frame = input.split_to(metadata_length + 2);
        let metadata = &frame[2..];
        if metadata.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("XUDP metadata is too short: {}", metadata.len()),
            ));
        }

        let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
        let status = SessionStatus::try_from(metadata[2])?;
        let option = FrameOption::from(metadata[3]);
        let mut cursor = 4;
        let mut network = None;
        let mut target = None;

        let has_target = status == SessionStatus::New
            || (status == SessionStatus::Keep
                && metadata.get(cursor) == Some(&(TargetNetwork::Udp as u8)));
        if has_target {
            let (decoded_network, decoded_target) =
                decode_target(metadata, &mut cursor)?;
            network = Some(decoded_network);
            target = Some(decoded_target);
        }

        let global_id = if status == SessionStatus::New
            && network == Some(TargetNetwork::Udp)
            && option.has_data()
            && metadata.len().saturating_sub(cursor) >= 8
        {
            let mut global_id = [0u8; 8];
            global_id.copy_from_slice(&metadata[cursor..cursor + 8]);
            Some(global_id)
        } else {
            None
        };

        Ok(Some(Self {
            session_id,
            status,
            option,
            target,
            network,
            global_id,
        }))
    }
}

fn encode_target(
    output: &mut BytesMut,
    network: TargetNetwork,
    target: &NetLocation,
) -> std::io::Result<()> {
    output.put_u8(network as u8);
    output.put_u16(target.port());
    match target.address() {
        Address::Ipv4(address) => {
            output.put_u8(0x01);
            output.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "XUDP hostname must not be empty",
                ));
            }
            if hostname.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "XUDP hostname exceeds 255 bytes",
                ));
            }
            output.put_u8(0x02);
            output.put_u8(hostname.len() as u8);
            output.extend_from_slice(hostname.as_bytes());
        }
        Address::Ipv6(address) => {
            output.put_u8(0x03);
            output.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

fn decode_target(
    metadata: &[u8],
    cursor: &mut usize,
) -> std::io::Result<(TargetNetwork, NetLocation)> {
    let network = TargetNetwork::try_from(take_u8(metadata, cursor)?)?;
    let port = take_u16(metadata, cursor)?;
    let address_type = take_u8(metadata, cursor)?;
    let address = match address_type {
        0x01 => {
            let octets = take_array::<4>(metadata, cursor)?;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        0x02 => {
            let length = take_u8(metadata, cursor)? as usize;
            if length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "XUDP hostname must not be empty",
                ));
            }
            let hostname = take_slice(metadata, cursor, length)?;
            let hostname = std::str::from_utf8(hostname).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid XUDP hostname: {error}"),
                )
            })?;
            Address::from(hostname)?
        }
        0x03 => {
            let octets = take_array::<16>(metadata, cursor)?;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid XUDP address type: {other}"),
            ));
        }
    };
    Ok((network, NetLocation::new(address, port)))
}

fn take_u8(input: &[u8], cursor: &mut usize) -> std::io::Result<u8> {
    let value = *input.get(*cursor).ok_or_else(unexpected_metadata_eof)?;
    *cursor += 1;
    Ok(value)
}

fn take_u16(input: &[u8], cursor: &mut usize) -> std::io::Result<u16> {
    let bytes = take_array::<2>(input, cursor)?;
    Ok(u16::from_be_bytes(bytes))
}

fn take_array<const LENGTH: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> std::io::Result<[u8; LENGTH]> {
    let mut output = [0u8; LENGTH];
    output.copy_from_slice(take_slice(input, cursor, LENGTH)?);
    Ok(output)
}

fn take_slice<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> std::io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(unexpected_metadata_eof)?;
    let output = input
        .get(*cursor..end)
        .ok_or_else(unexpected_metadata_eof)?;
    *cursor = end;
    Ok(output)
}

fn unexpected_metadata_eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated XUDP metadata")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_udp_frame_matches_xray_layout_and_roundtrips() {
        let metadata = FrameMetadata {
            session_id: 42,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::new(
                Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
                53,
            )),
            network: Some(TargetNetwork::Udp),
            global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let expected = [
            0x00, 0x14, 0x00, 0x2a, 0x01, 0x01, 0x02, 0x00, 0x35, 0x01, 0x01, 0x01,
            0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8,
        ];

        let mut encoded = BytesMut::new();
        metadata.encode(&mut encoded).expect("encode XUDP metadata");
        assert_eq!(&encoded[..], &expected);
        assert_eq!(
            FrameMetadata::decode(&mut encoded)
                .expect("decode XUDP metadata")
                .expect("complete XUDP metadata"),
            metadata
        );
        assert!(encoded.is_empty());
    }

    #[test]
    fn keep_udp_frame_preserves_domain_target() {
        let metadata = FrameMetadata {
            session_id: 7,
            status: SessionStatus::Keep,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::new(
                Address::from("example.test").unwrap(),
                443,
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        };
        let mut encoded = BytesMut::new();
        metadata.encode(&mut encoded).expect("encode Keep frame");

        let decoded = FrameMetadata::decode(&mut encoded)
            .expect("decode Keep frame")
            .expect("complete Keep frame");
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn every_incomplete_metadata_prefix_preserves_input() {
        let metadata = FrameMetadata {
            session_id: 0x1234,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::new(
                Address::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
                5353,
            )),
            network: Some(TargetNetwork::Udp),
            global_id: Some([11, 12, 13, 14, 15, 16, 17, 18]),
        };
        let mut complete = BytesMut::new();
        metadata
            .encode(&mut complete)
            .expect("encode complex XUDP metadata fixture");

        for prefix_length in 0..complete.len() {
            let mut input = BytesMut::from(&complete[..prefix_length]);
            let before = input.clone();
            let decoded = FrameMetadata::decode(&mut input)
                .expect("incomplete XUDP metadata prefix is not invalid");
            assert_eq!(decoded, None, "prefix length {prefix_length}");
            assert_eq!(input, before, "prefix length {prefix_length}");
        }
    }

    #[test]
    fn decoder_consumes_only_one_metadata_frame() {
        let first = FrameMetadata {
            session_id: 21,
            status: SessionStatus::KeepAlive,
            option: FrameOption::default(),
            target: None,
            network: None,
            global_id: None,
        };
        let second = FrameMetadata {
            session_id: 22,
            status: SessionStatus::End,
            option: FrameOption::default().with_error(),
            target: None,
            network: None,
            global_id: None,
        };
        let mut input = BytesMut::new();
        first
            .encode(&mut input)
            .expect("encode first XUDP metadata");
        let first_length = input.len();
        second
            .encode(&mut input)
            .expect("encode second XUDP metadata");
        let second_bytes = input[first_length..].to_vec();

        let decoded_first = FrameMetadata::decode(&mut input)
            .expect("decode first XUDP metadata")
            .expect("first XUDP metadata must be complete");

        assert_eq!(decoded_first, first);
        assert_eq!(&input[..], second_bytes.as_slice());
        assert_eq!(
            FrameMetadata::decode(&mut input)
                .expect("decode second XUDP metadata")
                .expect("second XUDP metadata must be complete"),
            second
        );
        assert!(input.is_empty());
    }

    #[test]
    fn new_address_and_network_matrix_roundtrips() {
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let cases = [
            (
                TargetNetwork::Tcp,
                NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 80),
            ),
            (
                TargetNetwork::Udp,
                NetLocation::new(Address::from("example.test").unwrap(), 53),
            ),
            (
                TargetNetwork::Udp,
                NetLocation::new(Address::Ipv6(ipv6), 443),
            ),
        ];

        for (index, (network, target)) in cases.into_iter().enumerate() {
            let metadata = FrameMetadata {
                session_id: 30 + index as u16,
                status: SessionStatus::New,
                option: FrameOption::default().with_data(),
                target: Some(target),
                network: Some(network),
                global_id: (network == TargetNetwork::Udp)
                    .then_some([index as u8; 8]),
            };
            let mut encoded = BytesMut::new();
            metadata
                .encode(&mut encoded)
                .expect("encode XUDP address matrix metadata");

            let decoded = FrameMetadata::decode(&mut encoded)
                .expect("decode XUDP address matrix metadata")
                .expect("XUDP address matrix metadata must be complete");

            assert_eq!(decoded, metadata);
            assert!(encoded.is_empty());
        }
    }

    #[test]
    fn incomplete_frame_does_not_consume_input() {
        let mut input = BytesMut::from(&[0, 8, 0, 1, 1][..]);
        let before = input.clone();

        assert!(
            FrameMetadata::decode(&mut input)
                .expect("incomplete frame is not invalid")
                .is_none()
        );
        assert_eq!(input, before);
    }

    #[test]
    fn accepts_metadata_at_xray_limit() {
        let mut raw = vec![0u8; 2 + MAX_METADATA_LENGTH];
        raw[..2].copy_from_slice(&(MAX_METADATA_LENGTH as u16).to_be_bytes());
        raw[2..6].copy_from_slice(&[0, 9, SessionStatus::KeepAlive as u8, 0]);
        let mut input = BytesMut::from(raw.as_slice());

        let metadata = FrameMetadata::decode(&mut input)
            .expect("metadata at Xray limit must decode")
            .expect("metadata at Xray limit must be complete");

        assert_eq!(metadata.session_id, 9);
        assert_eq!(metadata.status, SessionStatus::KeepAlive);
        assert!(input.is_empty());
    }

    #[test]
    fn hostname_at_protocol_limit_roundtrips() {
        let hostname = "a".repeat(u8::MAX as usize);
        let metadata = FrameMetadata {
            session_id: 10,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::new(
                Address::from(hostname.as_str()).unwrap(),
                53,
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        };
        let mut encoded = BytesMut::new();

        metadata
            .encode(&mut encoded)
            .expect("255-byte XUDP hostname must encode");
        let decoded = FrameMetadata::decode(&mut encoded)
            .expect("255-byte XUDP hostname must decode")
            .expect("255-byte XUDP hostname metadata must be complete");

        assert_eq!(decoded, metadata);
        assert!(encoded.is_empty());
    }

    #[test]
    fn rejects_metadata_larger_than_xray_limit() {
        let mut input = BytesMut::from(&[0x02, 0x01][..]);
        let error = FrameMetadata::decode(&mut input)
            .expect_err("oversized metadata must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_truncated_new_target() {
        let mut input = BytesMut::from(&[0, 5, 0, 1, 1, 1, 2][..]);
        let error = FrameMetadata::decode(&mut input)
            .expect_err("truncated target must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_unknown_session_status() {
        let mut input = BytesMut::from(&[0, 4, 0, 1, 0xff, 0][..]);
        let error = FrameMetadata::decode(&mut input)
            .expect_err("unknown XUDP status must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("session status"));
    }

    #[test]
    fn rejects_unknown_target_network() {
        let mut input =
            BytesMut::from(&[0, 8, 0, 1, 1, FrameOption::DATA, 0xff, 0, 53, 1][..]);
        let error = FrameMetadata::decode(&mut input)
            .expect_err("unknown XUDP target network must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("target network"));
    }

    #[test]
    fn rejects_unknown_address_type() {
        let mut input = BytesMut::from(
            &[
                0,
                8,
                0,
                1,
                1,
                FrameOption::DATA,
                TargetNetwork::Udp as u8,
                0,
                53,
                0xff,
            ][..],
        );
        let error = FrameMetadata::decode(&mut input)
            .expect_err("unknown XUDP address type must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("address type"));
    }

    #[test]
    fn rejects_empty_hostname() {
        let mut input = BytesMut::from(
            &[
                0,
                9,
                0,
                1,
                1,
                FrameOption::DATA,
                TargetNetwork::Udp as u8,
                0,
                53,
                2,
                0,
            ][..],
        );
        let error = FrameMetadata::decode(&mut input)
            .expect_err("empty XUDP hostname must be rejected");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn encode_error_does_not_leave_partial_frame() {
        let metadata = FrameMetadata {
            session_id: 11,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::new(
                Address::Hostname("a".repeat(u8::MAX as usize + 1)),
                53,
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        };
        let mut output = BytesMut::from(&[0xaa, 0xbb][..]);
        let before = output.clone();

        let error = metadata
            .encode(&mut output)
            .expect_err("overlong XUDP hostname must fail encoding");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(output, before);
    }

    #[test]
    fn rejects_invalid_utf8_hostname() {
        let mut input = BytesMut::from(
            &[
                0,
                10,
                0,
                1,
                1,
                FrameOption::DATA,
                TargetNetwork::Udp as u8,
                0,
                53,
                2,
                1,
                0xff,
            ][..],
        );
        let error = FrameMetadata::decode(&mut input)
            .expect_err("invalid UTF-8 XUDP hostname must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("hostname"));
    }

    #[test]
    fn error_option_is_preserved() {
        let option = FrameOption::from(FrameOption::ERROR);
        assert!(option.has_error());
        assert!(!option.has_data());
    }
}
