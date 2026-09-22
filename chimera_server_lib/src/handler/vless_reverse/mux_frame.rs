// Batch C lands the Xray-compatible wire primitive before Batch D adds the
// supervised Reverse Mux runtime that consumes it.
#![allow(dead_code)]

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};

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
                format!("unknown Xray Mux session status: {other}"),
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
                format!("unknown Xray Mux target network: {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferType {
    Stream,
    Packet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Destination {
    pub(crate) network: TargetNetwork,
    pub(crate) location: NetLocation,
}

impl Destination {
    pub(crate) fn transfer_type(&self) -> TransferType {
        match self.network {
            TargetNetwork::Tcp => TransferType::Stream,
            TargetNetwork::Udp => TransferType::Packet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameMetadata {
    pub(crate) session_id: u16,
    pub(crate) status: SessionStatus,
    pub(crate) option: FrameOption,
    pub(crate) target: Option<Destination>,
    pub(crate) source: Option<Destination>,
    pub(crate) local: Option<Destination>,
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
                let target = self.target.as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Xray Mux New frame requires a target",
                    )
                })?;
                encode_destination(output, target)?;

                if let Some(source) = self.source.as_ref() {
                    encode_destination(output, source)?;
                    if let Some(local) = self.local.as_ref() {
                        encode_destination(output, local)?;
                    }
                } else {
                    if self.local.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Xray Reverse Mux local metadata requires source metadata",
                        ));
                    }
                    if target.network == TargetNetwork::Udp && self.option.has_data()
                    {
                        // Xray's Mux Writer always reserves the eight-byte GlobalID on a
                        // packet NEW frame, including the all-zero value used by ordinary
                        // (non-reattachable) UDP sessions.
                        output.extend_from_slice(&self.global_id.unwrap_or([0; 8]));
                    }
                }
            }
            SessionStatus::Keep => {
                if let Some(target) = self.target.as_ref() {
                    if target.network != TargetNetwork::Udp {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Xray Mux Keep frame may only carry a UDP target",
                        ));
                    }
                    encode_destination(output, target)?;
                }
            }
            SessionStatus::End | SessionStatus::KeepAlive => {
                if self.target.is_some()
                    || self.source.is_some()
                    || self.local.is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Xray Mux control frame cannot carry destinations",
                    ));
                }
            }
        }

        let metadata_length = output.len() - metadata_start;
        if metadata_length > MAX_METADATA_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Xray Mux metadata exceeds {MAX_METADATA_LENGTH} bytes: {metadata_length}"
                ),
            ));
        }
        output[length_offset..length_offset + 2]
            .copy_from_slice(&(metadata_length as u16).to_be_bytes());
        Ok(())
    }

    pub(crate) fn decode(
        input: &mut BytesMut,
        read_source_and_local: bool,
    ) -> std::io::Result<Option<Self>> {
        if input.len() < 2 {
            return Ok(None);
        }
        let metadata_length = u16::from_be_bytes([input[0], input[1]]) as usize;
        if metadata_length > MAX_METADATA_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Xray Mux metadata exceeds {MAX_METADATA_LENGTH} bytes: {metadata_length}"
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
                format!("Xray Mux metadata is too short: {}", metadata.len()),
            ));
        }

        let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
        let status = SessionStatus::try_from(metadata[2])?;
        let option = FrameOption::from(metadata[3]);
        let mut cursor = 4;

        let mut target = None;
        if status == SessionStatus::New
            || (status == SessionStatus::Keep
                && metadata.get(cursor) == Some(&(TargetNetwork::Udp as u8)))
        {
            target = Some(decode_destination(metadata, &mut cursor)?);
        }

        let mut source = None;
        let mut local = None;
        if status == SessionStatus::New && read_source_and_local {
            source = decode_optional_destination(metadata, &mut cursor)?;
            if source.is_some() {
                local = decode_optional_destination(metadata, &mut cursor)?;
            }
        }

        let global_id = if status == SessionStatus::New
            && !read_source_and_local
            && target
                .as_ref()
                .is_some_and(|target| target.network == TargetNetwork::Udp)
            && option.has_data()
            && metadata.len().saturating_sub(cursor) >= 8
        {
            let mut global_id = [0u8; 8];
            global_id.copy_from_slice(&metadata[cursor..cursor + 8]);
            // common/mux.ServerWorker explicitly ignores an empty GlobalID.
            (global_id != [0; 8]).then_some(global_id)
        } else {
            None
        };

        Ok(Some(Self {
            session_id,
            status,
            option,
            target,
            source,
            local,
            global_id,
        }))
    }

    pub(crate) fn transfer_type(&self) -> Option<TransferType> {
        self.target.as_ref().map(Destination::transfer_type)
    }
}

#[derive(Debug, Default)]
pub(crate) struct SessionIdTracker {
    active: HashSet<u16>,
}

impl SessionIdTracker {
    pub(crate) fn observe(
        &mut self,
        metadata: &FrameMetadata,
    ) -> std::io::Result<()> {
        match metadata.status {
            SessionStatus::New => {
                if !self.active.insert(metadata.session_id) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "duplicate Xray Mux session id: {}",
                            metadata.session_id
                        ),
                    ));
                }
            }
            SessionStatus::End => {
                self.active.remove(&metadata.session_id);
            }
            SessionStatus::Keep | SessionStatus::KeepAlive => {}
        }
        Ok(())
    }
}

fn encode_destination(
    output: &mut BytesMut,
    destination: &Destination,
) -> std::io::Result<()> {
    output.put_u8(destination.network as u8);
    output.put_u16(destination.location.port());
    match destination.location.address() {
        Address::Ipv4(address) => {
            output.put_u8(0x01);
            output.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Xray Mux hostname must not be empty",
                ));
            }
            if hostname.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Xray Mux hostname exceeds 255 bytes",
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

fn decode_optional_destination(
    metadata: &[u8],
    cursor: &mut usize,
) -> std::io::Result<Option<Destination>> {
    let Some(network) = metadata.get(*cursor).copied() else {
        return Ok(None);
    };
    if network == 0 {
        *cursor += 1;
        return Ok(None);
    }
    decode_destination(metadata, cursor).map(Some)
}

fn decode_destination(
    metadata: &[u8],
    cursor: &mut usize,
) -> std::io::Result<Destination> {
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
                    "Xray Mux hostname must not be empty",
                ));
            }
            let bytes = take_bytes(metadata, cursor, length)?;
            let hostname = std::str::from_utf8(bytes).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Xray Mux hostname: {error}"),
                )
            })?;
            Address::Hostname(hostname.to_string())
        }
        0x03 => {
            let octets = take_array::<16>(metadata, cursor)?;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown Xray Mux address type: {other}"),
            ));
        }
    };

    Ok(Destination {
        network,
        location: NetLocation::new(address, port),
    })
}

fn take_u8(input: &[u8], cursor: &mut usize) -> std::io::Result<u8> {
    Ok(take_array::<1>(input, cursor)?[0])
}

fn take_u16(input: &[u8], cursor: &mut usize) -> std::io::Result<u16> {
    Ok(u16::from_be_bytes(take_array::<2>(input, cursor)?))
}

fn take_array<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> std::io::Result<[u8; N]> {
    let bytes = take_bytes(input, cursor, N)?;
    Ok(bytes
        .try_into()
        .expect("slice length checked by take_bytes"))
}

fn take_bytes<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> std::io::Result<&'a [u8]> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Xray Mux metadata cursor overflow",
        )
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated Xray Mux metadata",
        )
    })?;
    *cursor = end;
    Ok(bytes)
}

#[cfg(test)]
#[path = "mux_frame_tests.rs"]
mod tests;
