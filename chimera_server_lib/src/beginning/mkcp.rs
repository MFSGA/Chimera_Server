use std::{collections::HashSet, io, net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;

use crate::{
    address::BindLocation,
    config::{MkcpTransportConfig, server_config::TcpSocketPolicy},
};

use super::udp::{bind_location_to_socket_addr, create_udp_listener};

const COMMAND_ACK: u8 = 0;
const COMMAND_DATA: u8 = 1;
const COMMAND_TERMINATE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MkcpSegment {
    Data {
        conversation: u16,
        option: u8,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    },
    Ack {
        conversation: u16,
        option: u8,
        receiving_window: u32,
        receiving_next: u32,
        timestamp: u32,
        numbers: Vec<u32>,
    },
    Command {
        conversation: u16,
        command: u8,
        option: u8,
        sending_next: u32,
        receiving_next: u32,
        peer_rto: u32,
    },
}

impl MkcpSegment {
    pub(crate) fn conversation(&self) -> u16 {
        match self {
            Self::Data { conversation, .. }
            | Self::Ack { conversation, .. }
            | Self::Command { conversation, .. } => *conversation,
        }
    }

    pub(crate) fn command(&self) -> u8 {
        match self {
            Self::Data { .. } => COMMAND_DATA,
            Self::Ack { .. } => COMMAND_ACK,
            Self::Command { command, .. } => *command,
        }
    }
}

pub(crate) fn parse_packet(mut input: &[u8]) -> Vec<MkcpSegment> {
    let mut segments = Vec::new();
    while !input.is_empty() {
        let Some((segment, remaining)) = parse_segment(input) else {
            break;
        };
        segments.push(segment);
        input = remaining;
    }
    segments
}

fn parse_segment(input: &[u8]) -> Option<(MkcpSegment, &[u8])> {
    if input.len() < 4 {
        return None;
    }

    let conversation = u16::from_be_bytes([input[0], input[1]]);
    let command = input[2];
    let option = input[3];
    let body = &input[4..];

    match command {
        COMMAND_DATA => {
            // Keep the current Xray parser boundary exactly: its DataSegment
            // parser requires at least 15 bytes after the common header.
            if body.len() < 15 {
                return None;
            }
            let timestamp = u32::from_be_bytes(body[0..4].try_into().ok()?);
            let number = u32::from_be_bytes(body[4..8].try_into().ok()?);
            let sending_next = u32::from_be_bytes(body[8..12].try_into().ok()?);
            let data_len =
                u16::from_be_bytes(body[12..14].try_into().ok()?) as usize;
            if body.len() < 14 + data_len {
                return None;
            }
            let payload = body[14..14 + data_len].to_vec();
            Some((
                MkcpSegment::Data {
                    conversation,
                    option,
                    timestamp,
                    number,
                    sending_next,
                    payload,
                },
                &body[14 + data_len..],
            ))
        }
        COMMAND_ACK => {
            if body.len() < 13 {
                return None;
            }
            let receiving_window = u32::from_be_bytes(body[0..4].try_into().ok()?);
            let receiving_next = u32::from_be_bytes(body[4..8].try_into().ok()?);
            let timestamp = u32::from_be_bytes(body[8..12].try_into().ok()?);
            let count = body[12] as usize;
            if body.len() < 13 + count * 4 {
                return None;
            }
            let mut numbers = Vec::with_capacity(count);
            for chunk in body[13..13 + count * 4].as_chunks::<4>().0 {
                numbers.push(u32::from_be_bytes(*chunk));
            }
            Some((
                MkcpSegment::Ack {
                    conversation,
                    option,
                    receiving_window,
                    receiving_next,
                    timestamp,
                    numbers,
                },
                &body[13 + count * 4..],
            ))
        }
        _ => {
            if body.len() < 12 {
                return None;
            }
            Some((
                MkcpSegment::Command {
                    conversation,
                    command,
                    option,
                    sending_next: u32::from_be_bytes(body[0..4].try_into().ok()?),
                    receiving_next: u32::from_be_bytes(body[4..8].try_into().ok()?),
                    peer_rto: u32::from_be_bytes(body[8..12].try_into().ok()?),
                },
                &body[12..],
            ))
        }
    }
}

pub(crate) fn encode_packet(segments: &[MkcpSegment]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for segment in segments {
        encode_segment(segment, &mut output)?;
    }
    Ok(output)
}

fn encode_segment(segment: &MkcpSegment, output: &mut Vec<u8>) -> io::Result<()> {
    output.extend_from_slice(&segment.conversation().to_be_bytes());
    output.push(segment.command());

    match segment {
        MkcpSegment::Data {
            option,
            timestamp,
            number,
            sending_next,
            payload,
            ..
        } => {
            let payload_len = u16::try_from(payload.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mKCP data payload exceeds u16 length",
                )
            })?;
            output.push(*option);
            output.extend_from_slice(&timestamp.to_be_bytes());
            output.extend_from_slice(&number.to_be_bytes());
            output.extend_from_slice(&sending_next.to_be_bytes());
            output.extend_from_slice(&payload_len.to_be_bytes());
            output.extend_from_slice(payload);
        }
        MkcpSegment::Ack {
            option,
            receiving_window,
            receiving_next,
            timestamp,
            numbers,
            ..
        } => {
            let count = u8::try_from(numbers.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mKCP ACK number list exceeds u8 length",
                )
            })?;
            output.push(*option);
            output.extend_from_slice(&receiving_window.to_be_bytes());
            output.extend_from_slice(&receiving_next.to_be_bytes());
            output.extend_from_slice(&timestamp.to_be_bytes());
            output.push(count);
            for number in numbers {
                output.extend_from_slice(&number.to_be_bytes());
            }
        }
        MkcpSegment::Command {
            option,
            sending_next,
            receiving_next,
            peer_rto,
            ..
        } => {
            output.push(*option);
            output.extend_from_slice(&sending_next.to_be_bytes());
            output.extend_from_slice(&receiving_next.to_be_bytes());
            output.extend_from_slice(&peer_rto.to_be_bytes());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MkcpSessionKey {
    pub(crate) remote: SocketAddr,
    pub(crate) conversation: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MkcpDemuxOutcome {
    New(MkcpSessionKey),
    Existing(MkcpSessionKey),
    IgnoreUnknownTerminate(MkcpSessionKey),
    Invalid,
}

#[derive(Debug, Default)]
pub(crate) struct MkcpSessionDemux {
    sessions: HashSet<MkcpSessionKey>,
}

impl MkcpSessionDemux {
    pub(crate) fn observe(
        &mut self,
        remote: SocketAddr,
        segments: &[MkcpSegment],
    ) -> MkcpDemuxOutcome {
        let Some(first) = segments.first() else {
            return MkcpDemuxOutcome::Invalid;
        };
        let key = MkcpSessionKey {
            remote,
            conversation: first.conversation(),
        };
        if self.sessions.contains(&key) {
            return MkcpDemuxOutcome::Existing(key);
        }
        if first.command() == COMMAND_TERMINATE {
            return MkcpDemuxOutcome::IgnoreUnknownTerminate(key);
        }
        self.sessions.insert(key);
        MkcpDemuxOutcome::New(key)
    }

    pub(crate) fn remove(&mut self, key: MkcpSessionKey) -> bool {
        self.sessions.remove(&key)
    }
}

pub(crate) struct PreparedMkcpListener {
    socket: Arc<UdpSocket>,
    mtu: usize,
}

impl PreparedMkcpListener {
    pub(crate) fn bind(
        bind_location: &BindLocation,
        socket_policy: Option<&TcpSocketPolicy>,
        config: MkcpTransportConfig,
    ) -> io::Result<Self> {
        let bind_addr = bind_location_to_socket_addr(bind_location)?;
        let socket = create_udp_listener(bind_addr, socket_policy, false)?;
        Ok(Self {
            socket,
            mtu: config.mtu as usize,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) async fn recv_packet(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(SocketAddr, Vec<MkcpSegment>)> {
        let (length, source) = self.socket.recv_from(buffer).await?;
        Ok((source, parse_packet(&buffer[..length])))
    }

    pub(crate) async fn send_packet(
        &self,
        destination: SocketAddr,
        segments: &[MkcpSegment],
    ) -> io::Result<usize> {
        let packet = encode_packet(segments)?;
        if packet.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "mKCP packet length {} exceeds configured MTU {}",
                    packet.len(),
                    self.mtu
                ),
            ));
        }
        self.socket.send_to(&packet, destination).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::address::NetLocation;

    fn ping(conversation: u16) -> MkcpSegment {
        MkcpSegment::Command {
            conversation,
            command: 3,
            option: 1,
            sending_next: 11,
            receiving_next: 13,
            peer_rto: 15,
        }
    }

    #[test]
    fn segment_codec_matches_xray_shapes_and_packet_chaining() {
        let segments = vec![
            MkcpSegment::Data {
                conversation: 1,
                option: 0,
                timestamp: 3,
                number: 4,
                sending_next: 5,
                payload: b"abcd".to_vec(),
            },
            MkcpSegment::Ack {
                conversation: 1,
                option: 0,
                receiving_window: 2,
                receiving_next: 3,
                timestamp: 10,
                numbers: vec![1, 3, 5, 7, 9],
            },
            ping(1),
        ];

        let encoded = encode_packet(&segments).expect("encode Xray KCP packet");
        assert_eq!(parse_packet(&encoded), segments);
        assert!(parse_packet(&[]).is_empty());
        assert!(parse_packet(&[1]).is_empty());
    }

    #[test]
    fn session_demux_matches_xray_remote_port_and_conversation_identity() {
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 10001));
        let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 10002));
        let mut demux = MkcpSessionDemux::default();
        let segments = vec![ping(7)];

        assert!(matches!(
            demux.observe(first, &segments),
            MkcpDemuxOutcome::New(_)
        ));
        assert!(matches!(
            demux.observe(first, &segments),
            MkcpDemuxOutcome::Existing(_)
        ));
        assert!(matches!(
            demux.observe(second, &segments),
            MkcpDemuxOutcome::New(_)
        ));

        let terminate = vec![MkcpSegment::Command {
            conversation: 99,
            command: COMMAND_TERMINATE,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        }];
        assert!(matches!(
            demux.observe(first, &terminate),
            MkcpDemuxOutcome::IgnoreUnknownTerminate(_)
        ));
    }

    #[tokio::test]
    async fn prepared_listener_owns_udp_socket_and_round_trips_kcp_packets() {
        let bind = BindLocation::Address(NetLocation::from_ip_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ));
        let listener =
            PreparedMkcpListener::bind(&bind, None, MkcpTransportConfig::default())
                .expect("bind prepared mKCP listener");
        let listener_addr = listener.local_addr().expect("listener address");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP client");
        let outbound = encode_packet(&[ping(42)]).expect("encode ping");
        client
            .send_to(&outbound, listener_addr)
            .await
            .expect("send mKCP packet");

        let mut buffer = [0u8; 2048];
        let (source, segments) = listener
            .recv_packet(&mut buffer)
            .await
            .expect("receive prepared mKCP packet");
        assert_eq!(source, client.local_addr().expect("client address"));
        assert_eq!(segments, vec![ping(42)]);

        listener
            .send_packet(source, &segments)
            .await
            .expect("send mKCP response packet");
        let (length, response_source) = client
            .recv_from(&mut buffer)
            .await
            .expect("receive mKCP response");
        assert_eq!(response_source, listener_addr);
        assert_eq!(parse_packet(&buffer[..length]), segments);
    }
}
