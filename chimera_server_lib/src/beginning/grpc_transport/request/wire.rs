use std::{io, ops::Range};

use bytes::{Buf, Bytes, BytesMut};

const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const PROTOBUF_MAX_FIELD_NUMBER: usize = (1 << 29) - 1;

#[derive(Debug)]
pub(super) struct GrpcMessageTooLarge {
    received: usize,
}

impl std::fmt::Display for GrpcMessageTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "grpc: received message larger than max ({} vs. {})",
            self.received, MAX_GRPC_MESSAGE_BYTES
        )
    }
}

impl std::error::Error for GrpcMessageTooLarge {}

#[derive(Debug)]
pub(super) struct GrpcCompressedMessage;

impl std::fmt::Display for GrpcCompressedMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("grpc: compressed flag set with identity or empty encoding")
    }
}

impl std::error::Error for GrpcCompressedMessage {}

#[derive(Debug)]
pub(super) struct GrpcUnexpectedPayloadFormat(pub(super) u8);

impl std::fmt::Display for GrpcUnexpectedPayloadFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "grpc: received unexpected payload format {}",
            self.0
        )
    }
}

impl std::error::Error for GrpcUnexpectedPayloadFormat {}

#[derive(Debug)]
pub(super) struct GrpcInvalidProtobuf;

impl std::fmt::Display for GrpcInvalidProtobuf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data",
        )
    }
}

impl std::error::Error for GrpcInvalidProtobuf {}

pub(crate) struct DecodedGrpcMessage {
    pub(crate) data: Bytes,
    pub(crate) payloads: Vec<Range<usize>>,
}

pub(crate) fn decode_grpc_message_view(
    buffer: &mut BytesMut,
    multi_mode: bool,
) -> io::Result<Option<DecodedGrpcMessage>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    match buffer[0] {
        0 => {}
        1 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                GrpcCompressedMessage,
            ));
        }
        format => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                GrpcUnexpectedPayloadFormat(format),
            ));
        }
    }
    let message_len =
        u32::from_be_bytes(buffer[1..5].try_into().expect("gRPC length")) as usize;
    if message_len > MAX_GRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            GrpcMessageTooLarge {
                received: message_len,
            },
        ));
    }
    if buffer.len() < 5 + message_len {
        return Ok(None);
    }
    buffer.advance(5);
    let message = buffer.split_to(message_len).freeze();
    let payloads = decode_data_field_ranges(&message, multi_mode).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, GrpcInvalidProtobuf)
    })?;
    Ok(Some(DecodedGrpcMessage {
        data: message,
        payloads,
    }))
}

pub(crate) fn decode_grpc_message_payloads(
    buffer: &mut BytesMut,
    multi_mode: bool,
) -> io::Result<Option<Vec<Bytes>>> {
    decode_grpc_message_view(buffer, multi_mode).map(|message| {
        message.map(|message| {
            message
                .payloads
                .into_iter()
                .map(|range| message.data.slice(range))
                .collect()
        })
    })
}

#[cfg(test)]
pub(crate) fn decode_grpc_message(
    buffer: &mut BytesMut,
    multi_mode: bool,
) -> io::Result<Option<Vec<Vec<u8>>>> {
    decode_grpc_message_payloads(buffer, multi_mode).map(|message| {
        message.map(|payloads| {
            payloads
                .into_iter()
                .map(|payload| payload.to_vec())
                .collect()
        })
    })
}

fn decode_data_field_ranges(
    message: &[u8],
    multi_mode: bool,
) -> io::Result<Vec<Range<usize>>> {
    let mut offset = 0;
    let mut payloads = Vec::new();
    while offset < message.len() {
        let (key, key_len) = decode_varint(&message[offset..])?;
        offset += key_len;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 || field_number > PROTOBUF_MAX_FIELD_NUMBER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protobuf field number",
            ));
        }

        if field_number == 1 && wire_type == 2 {
            let (length, varint_len) = decode_varint(&message[offset..])?;
            offset += varint_len;
            let end = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC payload length overflow",
                )
            })?;
            if end > message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated gRPC protobuf payload",
                ));
            }
            let payload = offset..end;
            offset = end;
            if multi_mode {
                payloads.push(payload);
            } else if let Some(existing) = payloads.first_mut() {
                *existing = payload;
            } else {
                payloads.push(payload);
            }
            continue;
        }

        // Generated protobuf decoders treat a known field with the wrong wire
        // type as an unknown field. Xray therefore skips it instead of failing.
        offset = skip_protobuf_field(message, offset, field_number, wire_type)?;
    }

    if payloads.is_empty() {
        payloads.push(0..0);
    }
    Ok(payloads)
}

fn skip_protobuf_field(
    message: &[u8],
    mut offset: usize,
    field_number: usize,
    wire_type: usize,
) -> io::Result<usize> {
    match wire_type {
        0 => {
            let (_, len) = decode_varint(&message[offset..])?;
            offset += len;
        }
        1 => {
            offset = offset.checked_add(8).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        2 => {
            let (length, len) = decode_varint(&message[offset..])?;
            offset += len;
            offset = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        3 => loop {
            if offset >= message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated protobuf group",
                ));
            }
            let (key, key_len) = decode_varint(&message[offset..])?;
            offset += key_len;
            let nested_field_number = key >> 3;
            let nested_wire_type = key & 0x07;
            if nested_field_number == 0
                || nested_field_number > PROTOBUF_MAX_FIELD_NUMBER
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid protobuf field number",
                ));
            }
            if nested_wire_type == 4 {
                if nested_field_number != field_number {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "protobuf group end field mismatch",
                    ));
                }
                break;
            }
            offset = skip_protobuf_field(
                message,
                offset,
                nested_field_number,
                nested_wire_type,
            )?;
        },
        4 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected protobuf end group",
            ));
        }
        5 => {
            offset = offset.checked_add(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported protobuf wire type",
            ));
        }
    }
    if offset > message.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated protobuf field",
        ));
    }
    Ok(offset)
}

pub(crate) fn encode_grpc_message(data: &[u8], _multi_mode: bool) -> Bytes {
    // Hunk and MultiHunk both encode their data using protobuf field 1. A single
    // field is a valid repeated-field encoding, so replies can use the same wire form.
    let mut frame = Vec::with_capacity(data.len() + 11);
    frame.extend_from_slice(&[0; 5]);
    frame.push(0x0a);
    encode_varint(data.len(), &mut frame);
    frame.extend_from_slice(data);
    let message_len = frame.len() - 5;
    frame[1..5].copy_from_slice(&(message_len as u32).to_be_bytes());
    Bytes::from(frame)
}

fn decode_varint(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in data.iter().copied().enumerate().take(10) {
        if index == 9 && byte > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protobuf varint",
            ));
        }
        value |= ((byte & 0x7f) as usize) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid protobuf varint",
    ))
}

pub(crate) fn encode_varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}
