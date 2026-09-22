// Batch D consumes this codec from the Mux TCP worker before Batch E wires the
// worker into the public Portal runtime.
#![allow(dead_code)]

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::mux_frame::FrameMetadata;

const MAX_MUX_PAYLOAD_LENGTH: usize = u16::MAX as usize;
// Xray common/buf.Size. PacketReader rejects a single UDP packet above this size.
const XRAY_PACKET_BUFFER_SIZE: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MuxFrame {
    pub(crate) metadata: FrameMetadata,
    pub(crate) payload: Bytes,
}

pub(crate) fn encode_frame(frame: &MuxFrame) -> std::io::Result<Bytes> {
    if frame.payload.len() > MAX_MUX_PAYLOAD_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Xray Mux payload exceeds {MAX_MUX_PAYLOAD_LENGTH} bytes: {}",
                frame.payload.len()
            ),
        ));
    }
    if !frame.payload.is_empty() && !frame.metadata.option.has_data() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Xray Mux payload requires the DATA option",
        ));
    }
    validate_packet_payload(
        &frame.metadata,
        frame.payload.len(),
        std::io::ErrorKind::InvalidInput,
    )?;

    let mut encoded = BytesMut::new();
    frame.metadata.encode(&mut encoded)?;
    if frame.metadata.option.has_data() {
        encoded.put_u16(frame.payload.len() as u16);
        encoded.extend_from_slice(&frame.payload);
    }
    Ok(encoded.freeze())
}

pub(crate) async fn read_frame<R>(reader: &mut R) -> std::io::Result<MuxFrame>
where
    R: AsyncRead + Unpin,
{
    read_frame_with_source_and_local(reader, false).await
}

pub(crate) async fn read_frame_with_source_and_local<R>(
    reader: &mut R,
    read_source_and_local: bool,
) -> std::io::Result<MuxFrame>
where
    R: AsyncRead + Unpin,
{
    let metadata_length = reader.read_u16().await? as usize;
    if metadata_length > 512 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Xray Mux metadata exceeds 512 bytes: {metadata_length}"),
        ));
    }

    let mut encoded_metadata = BytesMut::with_capacity(metadata_length + 2);
    encoded_metadata.put_u16(metadata_length as u16);
    encoded_metadata.resize(metadata_length + 2, 0);
    reader.read_exact(&mut encoded_metadata[2..]).await?;

    let metadata =
        FrameMetadata::decode(&mut encoded_metadata, read_source_and_local)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "complete Xray Mux metadata did not decode",
                )
            })?;
    if !encoded_metadata.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Xray Mux metadata decoder left trailing bytes",
        ));
    }

    let payload = if metadata.option.has_data() {
        let payload_length = reader.read_u16().await? as usize;
        validate_packet_payload(
            &metadata,
            payload_length,
            std::io::ErrorKind::InvalidData,
        )?;
        let mut payload = vec![0u8; payload_length];
        reader.read_exact(&mut payload).await?;
        Bytes::from(payload)
    } else {
        Bytes::new()
    };

    Ok(MuxFrame { metadata, payload })
}

fn validate_packet_payload(
    metadata: &FrameMetadata,
    payload_length: usize,
    error_kind: std::io::ErrorKind,
) -> std::io::Result<()> {
    let is_packet_new = metadata.status == super::mux_frame::SessionStatus::New
        && metadata.target.as_ref().is_some_and(|target| {
            target.network == super::mux_frame::TargetNetwork::Udp
        });
    if is_packet_new && payload_length > XRAY_PACKET_BUFFER_SIZE {
        return Err(std::io::Error::new(
            error_kind,
            format!("Xray Mux UDP packet size too large: {payload_length}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::duplex;

    use crate::address::{Address, NetLocation};

    use super::*;
    use crate::handler::vless_reverse::mux_frame::{
        Destination, FrameOption, SessionStatus, TargetNetwork,
    };

    fn tcp_target() -> Destination {
        Destination {
            network: TargetNetwork::Tcp,
            location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 8080),
        }
    }

    #[tokio::test]
    async fn tcp_new_payload_round_trips_with_xray_length_prefix() {
        let frame = MuxFrame {
            metadata: FrameMetadata {
                session_id: 7,
                status: SessionStatus::New,
                option: FrameOption::default().with_data(),
                target: Some(tcp_target()),
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"hello"),
        };
        let encoded = encode_frame(&frame).expect("encode Mux payload frame");
        assert_eq!(
            encoded.as_ref(),
            [
                0x00, 0x0c, 0x00, 0x07, 0x01, 0x01, 0x01, 0x1f, 0x90, 0x01, 127, 0,
                0, 1, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
            ]
        );

        let (mut tx, mut rx) = duplex(128);
        tokio::io::AsyncWriteExt::write_all(&mut tx, &encoded)
            .await
            .expect("write encoded frame");
        let decoded = read_frame(&mut rx).await.expect("decode Mux payload frame");
        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn metadata_only_frame_does_not_consume_following_frame() {
        let first = MuxFrame {
            metadata: FrameMetadata {
                session_id: 1,
                status: SessionStatus::End,
                option: FrameOption::default(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::new(),
        };
        let second = MuxFrame {
            metadata: FrameMetadata {
                session_id: 2,
                status: SessionStatus::KeepAlive,
                option: FrameOption::default(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::new(),
        };

        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_frame(&first).expect("encode first"));
        wire.extend_from_slice(&encode_frame(&second).expect("encode second"));
        let (mut tx, mut rx) = duplex(128);
        tokio::io::AsyncWriteExt::write_all(&mut tx, &wire)
            .await
            .expect("write frames");

        assert_eq!(read_frame(&mut rx).await.expect("read first"), first);
        assert_eq!(read_frame(&mut rx).await.expect("read second"), second);
    }

    #[tokio::test]
    async fn truncated_payload_fails_with_unexpected_eof() {
        let frame = MuxFrame {
            metadata: FrameMetadata {
                session_id: 7,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"abc"),
        };
        let encoded = encode_frame(&frame).expect("encode frame");
        let truncated = &encoded[..encoded.len() - 1];
        let (mut tx, mut rx) = duplex(128);
        tokio::io::AsyncWriteExt::write_all(&mut tx, truncated)
            .await
            .expect("write truncated frame");
        drop(tx);

        let error = read_frame(&mut rx)
            .await
            .expect_err("truncated payload must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn udp_new_rejects_packet_larger_than_xray_buffer() {
        let error = encode_frame(&MuxFrame {
            metadata: FrameMetadata {
                session_id: 9,
                status: SessionStatus::New,
                option: FrameOption::default().with_data(),
                target: Some(Destination {
                    network: TargetNetwork::Udp,
                    location: NetLocation::new(
                        Address::Ipv4(Ipv4Addr::LOCALHOST),
                        53,
                    ),
                }),
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from(vec![0; XRAY_PACKET_BUFFER_SIZE + 1]),
        })
        .expect_err("Xray PacketReader rejects packets above common/buf.Size");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("8193"));
    }

    #[test]
    fn payload_without_data_option_is_rejected() {
        let error = encode_frame(&MuxFrame {
            metadata: FrameMetadata {
                session_id: 1,
                status: SessionStatus::Keep,
                option: FrameOption::default(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"x"),
        })
        .expect_err("payload without DATA flag must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
