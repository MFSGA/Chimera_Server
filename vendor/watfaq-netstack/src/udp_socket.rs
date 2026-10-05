use crate::{
    Packet,
    fragment::{FRAGMENT_EXPIRY_SCAN_INTERVAL, FragmentReassembler},
    packet::IpPacket,
};
use etherparse::PacketBuilder;
use log::{error, trace, warn};
use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
use tokio::time::Instant;

const DEFAULT_UDP_PACKET_MTU: usize = 1500;

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::Receiver<Packet>,
    outbound: mpsc::Sender<Packet>,
    mtu: usize,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self {
            inbound,
            outbound,
            mtu: DEFAULT_UDP_PACKET_MTU,
        }
    }

    /// Creates a UDP packet adapter using the supplied output MTU.
    pub fn new_with_mtu(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        mtu: usize,
    ) -> Result<Self, std::io::Error> {
        crate::stack::validate_mtu(mtu)?;
        Ok(Self::with_mtu(inbound, outbound, mtu))
    }

    pub(crate) fn with_mtu(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        mtu: usize,
    ) -> Self {
        Self {
            inbound,
            outbound,
            mtu,
        }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead {
            recv: self.inbound,
            fragments: FragmentReassembler::new(etherparse::ip_number::UDP, "UDP"),
            next_fragment_expiry: Instant::now() + FRAGMENT_EXPIRY_SCAN_INTERVAL,
        };
        let write = SplitWrite {
            send: self.outbound,
            dropped_on_full: Arc::new(AtomicU64::new(0)),
            next_ipv4_fragment_id: Arc::new(AtomicU16::new(1)),
            next_ipv6_fragment_id: Arc::new(AtomicU32::new(1)),
            mtu: self.mtu,
        };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<Packet>,
    fragments: FragmentReassembler,
    next_fragment_expiry: Instant,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        loop {
            let data = tokio::select! {
                packet = self.recv.recv() => match packet {
                    Some(packet) => packet,
                    None => return None,
                },
                _ = tokio::time::sleep_until(self.next_fragment_expiry), if self.fragments.has_active() => {
                    self.fragments.expire_stale();
                    self.next_fragment_expiry = Instant::now() + FRAGMENT_EXPIRY_SCAN_INTERVAL;
                    continue;
                }
            };

            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    continue;
                }
            };

            if !packet.verify_checksum() {
                error!("invalid IP checksum");
                continue;
            }

            let fragmented = match crate::fragment::is_fragmented(data.data()) {
                Ok(fragmented) => fragmented,
                Err(err) => {
                    error!("invalid fragmented IP packet: {err}");
                    continue;
                }
            };

            let (src_ip, dst_ip, udp_data) = if fragmented {
                match self.fragments.push(data.data()) {
                    Ok(Some(reassembled)) => (
                        reassembled.template.source_ip(),
                        reassembled.template.destination_ip(),
                        Cow::Owned(reassembled.payload),
                    ),
                    Ok(None) => continue,
                    Err(err) => {
                        error!("invalid UDP fragment sequence: {err}");
                        continue;
                    }
                }
            } else {
                let src_ip = packet.src_addr();
                let dst_ip = packet.dst_addr();
                let sliced = match etherparse::IpSlice::from_slice(data.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        error!("invalid IP packet: {err}");
                        continue;
                    }
                };
                let payload = sliced.payload();
                if payload.ip_number != etherparse::ip_number::UDP {
                    error!(
                        "UDP input contained non-UDP payload: {:?}",
                        payload.ip_number
                    );
                    continue;
                }
                (src_ip, dst_ip, Cow::Borrowed(payload.payload))
            };

            let packet = match smoltcp::wire::UdpPacket::new_checked(
                udp_data.as_ref(),
            ) {
                Ok(packet) => packet,
                Err(err) => {
                    error!(
                        "invalid UDP frame: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload_len: {}",
                        udp_data.as_ref().len()
                    );
                    continue;
                }
            };
            if !packet.verify_checksum(&src_ip.into(), &dst_ip.into()) {
                error!("invalid UDP checksum: {src_ip} -> {dst_ip}");
                continue;
            }
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("created UDP socket for {src_addr} <-> {dst_addr}");

            return Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            });
        }
    }
}

#[cfg(test)]
mod fragment_expiry_tests {
    use super::*;
    use std::time::Duration;

    fn ipv4_fragment(
        identification: u16,
        offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> Packet {
        let mut header = etherparse::Ipv4Header::new(
            payload.len() as u16,
            64,
            etherparse::ip_number::UDP,
            [10, 0, 0, 2],
            [10, 0, 0, 3],
        )
        .expect("IPv4 header should be valid");
        header.identification = identification;
        header.more_fragments = more_fragments;
        header.fragment_offset = etherparse::IpFragOffset::try_new(offset)
            .expect("fragment offset should be valid");
        header.header_checksum = header.calc_header_checksum();

        Packet::new([header.to_bytes().as_slice(), payload].concat())
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_udp_fragments_expire_while_reader_is_idle() {
        let (sender, receiver) = mpsc::channel(2);
        let mut reader = UdpSocket::new(receiver, mpsc::channel(2).0).split().0;
        let receive_task = tokio::spawn(async move { reader.recv().await });
        let udp_header = [0x30, 0x39, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00];

        sender
            .send(ipv4_fragment(7, 0, true, &udp_header))
            .await
            .expect("first fragment should be accepted");
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;

        sender
            .send(ipv4_fragment(7, 1, false, b"12345678"))
            .await
            .expect("tail fragment should be accepted");
        drop(sender);

        assert!(
            receive_task
                .await
                .expect("UDP reader task should finish")
                .is_none(),
            "a tail arriving after the idle TTL must not complete the expired datagram"
        );
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
    dropped_on_full: Arc<AtomicU64>,
    next_ipv4_fragment_id: Arc<AtomicU16>,
    next_ipv6_fragment_id: Arc<AtomicU32>,
    mtu: usize,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut ip_packet_writer =
            Vec::with_capacity(builder.size(packet.data.data().len()));
        builder
            .write(&mut ip_packet_writer, packet.data.data())
            .map_err(std::io::Error::other)?;

        let packets = fragment_udp_ip_packet(
            &ip_packet_writer,
            &self.next_ipv4_fragment_id,
            &self.next_ipv6_fragment_id,
            self.mtu,
        )?;

        // Reserve space for every fragment before publishing any of them. UDP
        // stays non-blocking under pressure, but the stack never emits a
        // partial datagram when its bounded device queue is full.
        match self.send.try_reserve_many(packets.len()) {
            Ok(permits) => {
                for (packet, permit) in packets.into_iter().zip(permits) {
                    permit.send(packet);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                let dropped =
                    self.dropped_on_full.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped == 1 || dropped.is_power_of_two() {
                    warn!(
                        "dropping UDP packet because outbound queue is full; total dropped on this split writer: {dropped}"
                    );
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                Err(std::io::Error::other("packet outbound channel closed"))
            }
        }
    }
}

fn fragment_udp_ip_packet(
    packet: &[u8],
    next_ipv4_fragment_id: &AtomicU16,
    next_ipv6_fragment_id: &AtomicU32,
    mtu: usize,
) -> Result<Vec<Packet>, std::io::Error> {
    if packet.len() <= mtu {
        return Ok(vec![Packet::new(packet.to_vec())]);
    }

    match packet.first().map(|version| version >> 4) {
        Some(4) => fragment_ipv4_packet(packet, next_ipv4_fragment_id, mtu),
        Some(6) => fragment_ipv6_packet(packet, next_ipv6_fragment_id, mtu),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP packet has an unsupported IP version",
        )),
    }
}

fn fragment_ipv4_packet(
    packet: &[u8],
    next_fragment_id: &AtomicU16,
    mtu: usize,
) -> Result<Vec<Packet>, std::io::Error> {
    let header_slice = etherparse::Ipv4HeaderSlice::from_slice(packet)
        .map_err(std::io::Error::other)?;
    let header_len = header_slice.slice().len();
    let fragment_payload = &packet[header_len..];
    let max_fragment_payload = ((mtu - header_len) / 8) * 8;
    if max_fragment_payload == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IPv4 header leaves no room for a UDP fragment",
        ));
    }

    let identification = next_fragment_id.fetch_add(1, Ordering::Relaxed);
    let mut packets =
        Vec::with_capacity(fragment_payload.len().div_ceil(max_fragment_payload));
    let mut offset = 0;
    while offset < fragment_payload.len() {
        let end = (offset + max_fragment_payload).min(fragment_payload.len());
        let mut header = header_slice.to_header();
        header.identification = identification;
        header.dont_fragment = false;
        header.more_fragments = end < fragment_payload.len();
        header.fragment_offset =
            etherparse::IpFragOffset::try_new((offset / 8) as u16)
                .map_err(std::io::Error::other)?;
        header
            .set_payload_len(end - offset)
            .map_err(std::io::Error::other)?;
        header.header_checksum = header.calc_header_checksum();

        let mut fragment = header.to_bytes().to_vec();
        fragment.extend_from_slice(&fragment_payload[offset..end]);
        packets.push(Packet::new(fragment));
        offset = end;
    }
    Ok(packets)
}

fn fragment_ipv6_packet(
    packet: &[u8],
    next_fragment_id: &AtomicU32,
    mtu: usize,
) -> Result<Vec<Packet>, std::io::Error> {
    let header_slice = etherparse::Ipv6HeaderSlice::from_slice(packet)
        .map_err(std::io::Error::other)?;
    let header_len = etherparse::Ipv6Header::LEN;
    if header_slice.next_header() != etherparse::ip_number::UDP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized IPv6 UDP packet has an unexpected next header",
        ));
    }
    let fragment_payload = &packet[header_len..];
    let max_fragment_payload =
        ((mtu - header_len - etherparse::Ipv6FragmentHeader::LEN) / 8) * 8;
    if max_fragment_payload == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IPv6 headers leave no room for a UDP fragment",
        ));
    }

    let identification = next_fragment_id.fetch_add(1, Ordering::Relaxed);
    let mut packets =
        Vec::with_capacity(fragment_payload.len().div_ceil(max_fragment_payload));
    let mut offset = 0;
    while offset < fragment_payload.len() {
        let end = (offset + max_fragment_payload).min(fragment_payload.len());
        let mut header = header_slice.to_header();
        header.next_header = etherparse::ip_number::IPV6_FRAG;
        header
            .set_payload_length(etherparse::Ipv6FragmentHeader::LEN + end - offset)
            .map_err(std::io::Error::other)?;
        let fragment_header = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::UDP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16)
                .map_err(std::io::Error::other)?,
            end < fragment_payload.len(),
            identification,
        );

        let mut fragment = header.to_bytes().to_vec();
        fragment.extend_from_slice(&fragment_header.to_bytes());
        fragment.extend_from_slice(&fragment_payload[offset..end]);
        packets.push(Packet::new(fragment));
        offset = end;
    }
    Ok(packets)
}
