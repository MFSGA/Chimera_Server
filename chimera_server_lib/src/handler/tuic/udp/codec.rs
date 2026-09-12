use std::{net::SocketAddr, num::NonZeroUsize};

use bytes::{Bytes, BytesMut};
use lru::LruCache;

use crate::address::{Address, NetLocation};

use super::super::{COMMAND_TYPE_HEARTBEAT, COMMAND_TYPE_PACKET, TUIC_VERSION};

const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

pub(super) struct ParsedDatagramPacket<'a> {
    pub(super) assoc_id: u16,
    pub(super) packet_id: u16,
    pub(super) frag_total: u8,
    pub(super) frag_id: u8,
    pub(super) remote_location: Option<NetLocation>,
    pub(super) payload_fragment: &'a [u8],
}

pub(super) enum ParsedDatagram<'a> {
    Heartbeat,
    Packet(ParsedDatagramPacket<'a>),
}

pub(super) struct FragmentAssembler {
    fragments: LruCache<u16, FragmentedPacket>,
}

impl FragmentAssembler {
    pub(super) fn new() -> Self {
        Self {
            fragments: LruCache::new(
                NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE)
                    .unwrap_or_else(|| NonZeroUsize::new(1).expect("non-zero")),
            ),
        }
    }

    pub(super) fn assemble(
        &mut self,
        assoc_id: u16,
        packet_id: u16,
        frag_total: u8,
        frag_id: u8,
        remote_location: Option<NetLocation>,
        payload_fragment: &[u8],
    ) -> std::io::Result<Option<(NetLocation, Bytes)>> {
        assemble_fragment(
            &mut self.fragments,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
        )
    }
}

pub(in crate::handler::tuic) fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut res = match addr {
        SocketAddr::V4(addr_v4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01);
            res.extend_from_slice(&addr_v4.ip().octets());
            res
        }
        SocketAddr::V6(addr_v6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02);
            res.extend_from_slice(&addr_v6.ip().octets());
            res
        }
    };

    res.extend_from_slice(&addr.port().to_be_bytes());
    res
}

pub(super) fn parse_datagram(data: &[u8]) -> std::io::Result<ParsedDatagram<'_>> {
    if data.len() < 2 {
        return Err(std::io::Error::other("invalid message: too short"));
    }

    let tuic_version = data[0];
    if tuic_version != TUIC_VERSION {
        return Err(std::io::Error::other(format!(
            "unknown version: {tuic_version}"
        )));
    }

    let command_type = data[1];
    if command_type == COMMAND_TYPE_HEARTBEAT {
        return Ok(ParsedDatagram::Heartbeat);
    }
    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "unknown command: {command_type}"
        )));
    }

    let data_len = data.len();
    if data_len < 11 {
        return Err(std::io::Error::other("decode UDP message: too short"));
    }

    let assoc_id = u16::from_be_bytes([data[2], data[3]]);
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let frag_total = data[6];
    let frag_id = data[7];
    let payload_size = u16::from_be_bytes([data[8], data[9]]) as usize;
    let address_type = data[10];

    let (remote_location, offset) = match address_type {
        0xff => (None, 11),
        0x00 => {
            if data_len < 14 {
                return Err(std::io::Error::other(
                    "decode UDP message: hostname too short",
                ));
            }
            let address_len = data[11] as usize;
            if data_len < 12 + address_len + 2 + payload_size {
                return Err(std::io::Error::other(
                    "decode UDP message: truncated hostname",
                ));
            }
            let address_bytes = &data[12..12 + address_len];
            let address_str = std::str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::other(format!(
                    "decode UDP message: invalid UTF-8: {e}"
                ))
            })?;
            let address = Address::from(address_str).map_err(|e| {
                std::io::Error::other(format!(
                    "decode UDP message: invalid address: {e}"
                ))
            })?;
            let port = u16::from_be_bytes([
                data[12 + address_len],
                data[12 + address_len + 1],
            ]);
            (Some(NetLocation::new(address, port)), 12 + address_len + 2)
        }
        0x01 => {
            if data_len < 17 + payload_size {
                return Err(std::io::Error::other(
                    "decode UDP message: IPv4 too short",
                ));
            }
            let ipv4_addr =
                std::net::Ipv4Addr::new(data[11], data[12], data[13], data[14]);
            let port = u16::from_be_bytes([data[15], data[16]]);
            (Some(NetLocation::new(Address::Ipv4(ipv4_addr), port)), 17)
        }
        0x02 => {
            if data_len < 29 + payload_size {
                return Err(std::io::Error::other(
                    "decode UDP message: IPv6 too short",
                ));
            }
            let ipv6_bytes: [u8; 16] = data[11..27].try_into().map_err(|_| {
                std::io::Error::other("decode UDP message: invalid IPv6 bytes")
            })?;
            let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
            let port = u16::from_be_bytes([data[27], data[28]]);
            (Some(NetLocation::new(Address::Ipv6(ipv6_addr), port)), 29)
        }
        _ => {
            return Err(std::io::Error::other(format!(
                "decode UDP message: invalid address type: {address_type}"
            )));
        }
    };

    if data_len < offset + payload_size {
        return Err(std::io::Error::other(
            "decode UDP message: truncated payload",
        ));
    }

    Ok(ParsedDatagram::Packet(ParsedDatagramPacket {
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment: &data[offset..offset + payload_size],
    }))
}

pub(super) fn validate_fragment_header(
    frag_total: u8,
    frag_id: u8,
) -> std::io::Result<()> {
    if frag_total == 0 {
        return Err(std::io::Error::other(
            "ignoring packet with empty fragment total",
        ));
    }
    if frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "invalid fragment id {frag_id} >= total {frag_total}"
        )));
    }
    Ok(())
}

fn assemble_fragment(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
) -> std::io::Result<Option<(NetLocation, Bytes)>> {
    validate_fragment_header(frag_total, frag_id)?;

    if frag_total == 1 {
        let remote_location = remote_location.ok_or_else(|| {
            std::io::Error::other(
                "ignoring packet with single fragment and no address",
            )
        })?;
        return Ok(Some((
            remote_location,
            Bytes::copy_from_slice(payload_fragment),
        )));
    }

    let is_new = !fragments.contains(&packet_id);
    if is_new {
        fragments.put(
            packet_id,
            FragmentedPacket {
                fragment_count: frag_total,
                fragment_received: 0,
                packet_len: 0,
                received: vec![None; frag_total as usize],
                remote_location: remote_location.clone(),
            },
        );
    }

    let packet = fragments
        .get_mut(&packet_id)
        .ok_or_else(|| std::io::Error::other("fragment cache error"))?;

    if is_new && frag_id == 0 && packet.remote_location.is_none() {
        if remote_location.is_none() {
            fragments.pop(&packet_id);
            return Err(std::io::Error::other(format!(
                "ignoring packet with empty first fragment address for session {assoc_id}"
            )));
        }
        packet.remote_location = remote_location;
    }

    if packet.fragment_count != frag_total {
        fragments.pop(&packet_id);
        return Err(std::io::Error::other(format!(
            "mismatched fragment count for session {assoc_id} packet {packet_id}"
        )));
    }
    if packet.received[frag_id as usize].is_some() {
        fragments.pop(&packet_id);
        return Err(std::io::Error::other(format!(
            "duplicate fragment for session {assoc_id} packet {packet_id}"
        )));
    }

    packet.fragment_received += 1;
    packet.packet_len += payload_fragment.len();
    packet.received[frag_id as usize] = Some(payload_fragment.to_vec().into());

    if packet.fragment_received != packet.fragment_count {
        return Ok(None);
    }

    let FragmentedPacket {
        remote_location,
        received,
        packet_len,
        ..
    } = fragments
        .pop(&packet_id)
        .ok_or_else(|| std::io::Error::other("fragment cache missing"))?;
    let remote_location = remote_location
        .ok_or_else(|| std::io::Error::other("missing fragment address"))?;

    let mut complete_payload = BytesMut::with_capacity(packet_len);
    for frag in &received {
        match frag.as_ref() {
            Some(bytes) => complete_payload.extend_from_slice(bytes),
            None => {
                return Err(std::io::Error::other(
                    "missing fragment while assembling payload",
                ));
            }
        }
    }

    Ok(Some((remote_location, complete_payload.freeze())))
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
}
