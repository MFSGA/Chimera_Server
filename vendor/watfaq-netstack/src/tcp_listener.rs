use crate::{
    Packet,
    device::NetstackDevice,
    fragment::{FRAGMENT_EXPIRY_SCAN_INTERVAL, FragmentReassembler},
    packet::IpPacket,
    ring_buffer::LockFreeRingBuffer,
    stack::IfaceEvent,
    tcp_stream::TcpStream,
};
use futures::task::AtomicWaker;
use log::{debug, error, trace, warn};
use smoltcp::{iface::Interface, socket::tcp, wire::TcpPacket};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};
use tokio::sync::{mpsc, oneshot};

const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 256 * 1024; // 256 KiB
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 256 * 1024; // 256 KiB

/// Time-to-live for SYN tracker entries. Duplicates within this window are
/// suppressed to prevent the same SYN from creating multiple smoltcp sockets.
const SYN_TRACK_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum tracked half-open SYN entries. Bounds memory under a SYN flood.
const SYN_TRACK_MAX: usize = 10_000;

/// Hard cap on live TUN TCP streams. Each stream currently reserves roughly
/// 1 MiB across smoltcp and application-side buffers, so this bounds that
/// portion of memory to about 512 MiB.
const ACTIVE_TCP_STREAM_MAX: usize = 512;

// smoltcp requires a plain function pointer for TCP Timestamp generation.
// Use monotonic elapsed milliseconds plus a per-process random offset,
// never wall time (which can jump) or a zero-based timestamp fingerprint.
// This API does not support per-connection Xray/gVisor timestamp offsets.
// Only explicit Xray TUN opts in; peers lacking a SYN Timestamp decline it.
fn xray_tun_tcp_timestamp() -> u32 {
    static CLOCK: std::sync::OnceLock<(std::time::Instant, u32)> =
        std::sync::OnceLock::new();
    let (start, offset) =
        CLOCK.get_or_init(|| (std::time::Instant::now(), rand::random()));
    offset.wrapping_add(start.elapsed().as_millis() as u32)
}

// smoltcp 0.13.1 limits outgoing TCP payload by the interface MTU minus
// *base* IP and TCP headers, not the header length with options.
// A full-MSS packet with TS/SACK then fails its MTU check after the
// socket has advanced the TCP send sequence. Clamp only the internal
// peer MSS on verified inbound Xray TUN SYNs; neither the original
// on-wire SYN nor the physical TUN MTU changes. Reserving the full
// 40-byte TCP option budget covers Timestamp and SACK blocks together.
// An omitted MSS retains smoltcp's 536-byte fallback.
fn xray_tun_clamp_syn_mss(
    frame: &Packet,
    tcp: &[u8],
    source: IpAddr,
    destination: IpAddr,
    mtu: usize,
) -> Option<Packet> {
    const BASE_TCP_HEADER_LEN: usize = 20;
    const MAX_TCP_OPTION_BYTES: usize = 40;
    let ip_header_len = if source.is_ipv4() { 20 } else { 40 };
    let bound = u16::try_from(
        mtu.checked_sub(ip_header_len + BASE_TCP_HEADER_LEN + MAX_TCP_OPTION_BYTES)?,
    )
    .ok()?;
    let options_end = usize::from(*tcp.get(12)? >> 4) * 4;
    if !(20..=60).contains(&options_end) || options_end > tcp.len() {
        return None;
    }
    let mut offset = 20;
    while offset < options_end {
        match tcp[offset] {
            0 => break,
            1 => offset += 1,
            2 if tcp.get(offset + 1) == Some(&4) && offset + 4 <= options_end => {
                let mss_at = offset + 2;
                let original =
                    u16::from_be_bytes(tcp[mss_at..mss_at + 2].try_into().ok()?);
                if original == 0 || original <= bound {
                    return None;
                }
                let tcp_at = frame.data().len().checked_sub(tcp.len())?;
                let mut bytes = frame.data().to_vec();
                bytes[tcp_at + mss_at..tcp_at + mss_at + 2]
                    .copy_from_slice(&bound.to_be_bytes());
                let mut packet = TcpPacket::new_unchecked(&mut bytes[tcp_at..]);
                packet.fill_checksum(&source.into(), &destination.into());
                return Some(Packet::new(bytes));
            }
            _ => {
                let length = usize::from(*tcp.get(offset + 1)?);
                if length < 2 || offset + length > options_end {
                    break;
                }
                offset += length;
            }
        }
    }
    None
}

// The pinned gVisor oracle retains the most recent *newer* TSval for TSecr,
// even when it accepts data with an older TSval. smoltcp instead blindly
// replaces its echo field. Keep this small state with a weak socket owner:
// at most one entry for each accepted Xray TUN Timestamp-enabled flow.
struct XrayTimestampRecent {
    owner: Weak<TcpStreamHandle>,
    recent: u32,
    next_seq: u32,
    // Received segments ahead of a missing prefix, [start, end).
    // This bounded metadata is not an additional TCP payload buffer.
    out_of_order: Vec<(u32, u32)>,
}

impl XrayTimestampRecent {
    fn observe(
        &mut self,
        seq: u32,
        payload_len: usize,
        fin: bool,
        tsval: Option<u32>,
    ) -> Option<u32> {
        let accepted_sequence = (seq.wrapping_sub(self.next_seq) as i32) <= 0;
        if let Some(tsval) = tsval
            && accepted_sequence
            && (tsval.wrapping_sub(self.recent) as i32) > 0
        {
            self.recent = tsval;
        }
        let length = (payload_len as u32).saturating_add(u32::from(fin));
        if length != 0 {
            let end = seq.wrapping_add(length);
            let start_delta = seq.wrapping_sub(self.next_seq) as i32;
            let end_delta = end.wrapping_sub(self.next_seq) as i32;
            if end_delta > 0 && start_delta <= 0 {
                // Bridging the missing prefix also ACKs any previously
                // buffered suffix contiguous with the newly received data.
                self.next_seq = end;
                loop {
                    let following =
                        self.out_of_order.iter().position(|&(start, end)| {
                            (start.wrapping_sub(self.next_seq) as i32) <= 0
                                && (end.wrapping_sub(self.next_seq) as i32) > 0
                        });
                    let Some(index) = following else { break };
                    let (_, end) = self.out_of_order.swap_remove(index);
                    self.next_seq = end;
                }
                self.out_of_order.retain(|&(_, end)| {
                    (end.wrapping_sub(self.next_seq) as i32) > 0
                });
            } else if start_delta > 0
                && end_delta > start_delta
                && end_delta <= DEFAULT_TCP_RECV_BUFFER_SIZE as i32
                && self.out_of_order.len() < 32
            {
                self.out_of_order.push((seq, end));
            }
        }
        tsval.map(|_| self.recent)
    }
}

// Return the byte offset of the TSval in a checked TCP segment. Unknown TCP
// options are skipped by their declared length; malformed options terminate
// the scan rather than changing their bytes or their checksum.
fn tcp_tsval_field(tcp: &[u8]) -> Option<(usize, u32)> {
    let options_end = usize::from(*tcp.get(12)? >> 4) * 4;
    if !(20..=60).contains(&options_end) || options_end > tcp.len() {
        return None;
    }
    let mut offset = 20;
    while offset < options_end {
        match tcp[offset] {
            0 => break,
            1 => offset += 1,
            8 if tcp.get(offset + 1) == Some(&10) && offset + 10 <= options_end => {
                let value_offset = offset + 2;
                let tsval = u32::from_be_bytes(
                    tcp[value_offset..value_offset + 4].try_into().ok()?,
                );
                return Some((value_offset, tsval));
            }
            _ => {
                let len = usize::from(*tcp.get(offset + 1)?);
                if len < 2 || offset + len > options_end {
                    break;
                }
                offset += len;
            }
        }
    }
    None
}

/// Pending streams not yet accepted by the TUN dispatcher.
const TCP_ACCEPT_QUEUE_SIZE: usize = 128;
const IFACE_EVENT_QUEUE_SIZE: usize = 4096;

#[derive(Clone, Debug)]
struct LastTcpPacketMeta {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    ack_flag: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    payload_len: usize,
    window_len: u16,
}

impl std::fmt::Display for LastTcpPacketMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {} seq={} ack={:?} flags={}{}{}{}{} payload_len={} window={}",
            self.src_addr,
            self.dst_addr,
            self.seq,
            self.ack,
            if self.syn { "S" } else { "-" },
            if self.ack_flag { "A" } else { "-" },
            if self.fin { "F" } else { "-" },
            if self.rst { "R" } else { "-" },
            if self.psh { "P" } else { "-" },
            self.payload_len,
            self.window_len
        )
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(msg) => *msg,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(msg) => (*msg).to_string(),
            Err(_) => "unknown panic payload".to_string(),
        },
    }
}

fn invalid_tcp_packet_diagnostic(
    error: impl std::fmt::Display,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment_len: usize,
) -> String {
    format!(
        "invalid TCP segment: {error}, src_ip: {source_ip}, \
         dst_ip: {destination_ip}, segment_len: {segment_len}"
    )
}

fn mark_stream_closed(socket_control: &TcpStreamHandle) {
    socket_control.socket_closed.store(true, Ordering::Release);
    socket_control.read_closed.store(true, Ordering::Release);
    socket_control.write_closed.store(true, Ordering::Release);
    socket_control.recv_waker.wake();
    socket_control.send_waker.wake();
}

fn mark_all_streams_closed(
    socket_maps: &HashMap<smoltcp::iface::SocketHandle, Arc<TcpStreamHandle>>,
) {
    for socket_control in socket_maps.values() {
        mark_stream_closed(socket_control);
    }
}

fn mark_tracked_streams_closed(streams: &Mutex<Vec<Weak<TcpStreamHandle>>>) {
    if let Ok(mut streams) = streams.lock() {
        streams.retain(|stream| {
            if let Some(stream) = stream.upgrade() {
                mark_stream_closed(&stream);
                true
            } else {
                false
            }
        });
    }
}

fn normalize_invalid_ipv4_icmp_echo_checksum(packet: &[u8]) -> Option<Vec<u8>> {
    const IPV4_MIN_HEADER_LENGTH: usize = 20;
    const IPV4_ICMP_PROTOCOL: u8 = 1;
    const ICMPV4_ECHO_HEADER_LENGTH: usize = 8;
    const ICMPV4_ECHO_REQUEST_TYPE: u8 = 8;

    if packet.len() < IPV4_MIN_HEADER_LENGTH
        || packet[0] >> 4 != 4
        || packet[9] != IPV4_ICMP_PROTOCOL
    {
        return None;
    }

    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_length < IPV4_MIN_HEADER_LENGTH
        || total_length < header_length + ICMPV4_ECHO_HEADER_LENGTH
        || total_length > packet.len()
    {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let message = &packet[header_length..total_length];
    if message[0] != ICMPV4_ECHO_REQUEST_TYPE
        || message[1] != 0
        || internet_checksum(message) == 0
    {
        return None;
    }

    let mut normalized = packet.to_vec();
    normalized[header_length + 2] = 0;
    normalized[header_length + 3] = 0;
    let checksum =
        internet_checksum(&normalized[header_length..total_length]).to_be_bytes();
    normalized[header_length + 2..header_length + 4].copy_from_slice(&checksum);
    Some(normalized)
}

// Pinned Xray/gVisor stops option parsing at a malformed TCP option instead
// of rejecting the entire segment. smoltcp rejects some of these packets.
// Only normalize already-reassembled IPv6 SYN, ACK, FIN+ACK, RST+ACK or
// bare RST in the explicit Xray TUN mode, after verifying the original TCP
// checksum. Keep valid preceding options, replace invalid suffix with NOPs.
// For RST, gVisor validates the sequence using a zero-length segment while
// smoltcp otherwise counts any trailing payload toward its receive-window
// overlap. Strip RST-only trailing data *after* verifying the original
// checksum so an out-of-window RST cannot reset an established flow.
// Other TCP flag combinations are left unchanged.
fn normalize_xray_fragmented_ipv6_tcp_options(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 60
        || packet[0] >> 4 != 6
        || packet[6] != etherparse::ip_number::TCP.0
    {
        return None;
    }
    let tcp_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if tcp_len < 20 || packet.len() != 40 + tcp_len {
        return None;
    }
    let tcp = &packet[40..];
    let header_len = usize::from(tcp[12] >> 4) * 4;
    if !(20..=60).contains(&header_len)
        || header_len > tcp_len
        || !(tcp[13] & 0x12 == 0x02 || matches!(tcp[13], 0x04 | 0x10 | 0x11 | 0x14))
    {
        return None;
    }

    let mut pseudo = Vec::with_capacity(40 + tcp_len);
    pseudo.extend_from_slice(&packet[8..40]);
    pseudo.extend_from_slice(&(tcp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, etherparse::ip_number::TCP.0]);
    pseudo.extend_from_slice(tcp);
    if internet_checksum(&pseudo) != 0 {
        return None;
    }

    let rst_with_data = matches!(tcp[13], 0x04 | 0x14) && tcp_len > header_len;
    let options = &tcp[20..header_len];
    let mut at = 0usize;
    let bad_offset = loop {
        let Some(&kind) = options.get(at) else {
            break None;
        };
        if kind == 0 {
            break None; // EOL ignores the remaining padding bytes.
        }
        if kind == 1 {
            at += 1;
            continue;
        }
        let length = usize::from(*options.get(at + 1).unwrap_or(&0));
        let expected = match kind {
            2 => Some(4),  // MSS
            3 => Some(3),  // Window scale
            4 => Some(2),  // SACK permitted
            8 => Some(10), // Timestamp
            _ => None,
        };
        if length < 2
            || at + length > options.len()
            || expected.is_some_and(|expected| length != expected)
        {
            break Some(at);
        }
        at += length;
    };
    if bad_offset.is_none() && !rst_with_data {
        return None;
    }
    let mut normalized = packet.to_vec();
    if let Some(bad_offset) = bad_offset {
        normalized[40 + 20 + bad_offset..40 + header_len].fill(1);
    }
    if rst_with_data {
        normalized.truncate(40 + header_len);
        normalized[4..6].copy_from_slice(&(header_len as u16).to_be_bytes());
        pseudo[32..36].copy_from_slice(&(header_len as u32).to_be_bytes());
    }
    normalized[40 + 16..40 + 18].fill(0);
    pseudo.truncate(40);
    pseudo.extend_from_slice(&normalized[40..]);
    normalized[40 + 16..40 + 18]
        .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    Some(normalized)
}

fn unknown_ipv6_option_error(
    quoted: &Packet,
    pointer: u32,
) -> std::io::Result<Packet> {
    let header = etherparse::Ipv6HeaderSlice::from_slice(quoted.data())
        .map_err(std::io::Error::other)?;
    // Keep the error within IPv6's minimum MTU, including the quoted packet.
    let quote_length = quoted.data().len().min(1280 - 40 - 8);
    let mut response = Vec::new();
    etherparse::PacketBuilder::ipv6(header.destination(), header.source(), 64)
        .icmpv6(etherparse::Icmpv6Type::ParameterProblem(
            etherparse::icmpv6::ParameterProblemHeader {
                code:
                    etherparse::icmpv6::ParameterProblemCode::UnrecognizedIpv6Option,
                pointer,
            },
        ))
        .write(&mut response, &quoted.data()[..quote_length])
        .map_err(std::io::Error::other)?;
    Ok(Packet::new(response))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        let high = u32::from(word[0]) << 8;
        let low = word.get(1).copied().map(u32::from).unwrap_or_default();
        sum += high | low;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn has_active_stream_capacity(
    streams: &Mutex<Vec<Weak<TcpStreamHandle>>>,
    limit: usize,
) -> std::io::Result<bool> {
    let mut streams = streams
        .lock()
        .map_err(|_| std::io::Error::other("TCP stream tracker lock poisoned"))?;
    streams.retain(|stream| stream.strong_count() > 0);
    Ok(streams.len() < limit)
}

fn try_reserve_accept_slot(
    sender: &mpsc::Sender<TcpStream>,
) -> std::io::Result<Option<mpsc::Permit<'_, TcpStream>>> {
    match sender.try_reserve() {
        Ok(permit) => Ok(Some(permit)),
        Err(mpsc::error::TrySendError::Full(_)) => Ok(None),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "TCP accept queue closed",
        )),
    }
}

struct StreamShutdownGuard {
    streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,
}

impl Drop for StreamShutdownGuard {
    fn drop(&mut self) {
        mark_tracked_streams_closed(&self.streams);
    }
}

fn record_last_tcp_packet(
    sink: &Arc<Mutex<Option<LastTcpPacketMeta>>>,
    packet: &TcpPacket<&[u8]>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) {
    if let Ok(mut guard) = sink.lock() {
        *guard = Some(LastTcpPacketMeta {
            src_addr,
            dst_addr,
            seq: packet.seq_number().0 as u32,
            ack: packet.ack().then(|| packet.ack_number().0 as u32),
            syn: packet.syn(),
            ack_flag: packet.ack(),
            fin: packet.fin(),
            rst: packet.rst(),
            psh: packet.psh(),
            payload_len: packet.payload().len(),
            window_len: packet.window_len(),
        });
    }
}

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    // Mirrored by the smoltcp socket owner after receive-buffer draining.
    // Xray-TUN-only Timestamp processing uses this to avoid allowing a
    // window-rejected data segment to poison the recent TSecr value.
    recv_window_zero: AtomicBool,
    // If Window Scale was negotiated, a 0 advertised window can still
    // leave fewer than 2^N free bytes in smoltcp's ring buffer.
    recv_window_quantum: usize,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) send_waker: AtomicWaker,

    /// Set by the relay task through TcpStream::drop when the app-side stream
    /// is dropped. poll_sockets drains send_buffer, then calls socket.close()
    /// to start the FIN handshake.
    pub(crate) socket_dropped: AtomicBool,
    /// Set by poll_sockets when the smoltcp socket becomes inactive. poll_read
    /// returns EOF once recv_buffer is drained.
    pub(crate) socket_closed: AtomicBool,
    /// Set when smoltcp reports the receive side is closed, and defensively in
    /// TcpStream::drop().
    pub(crate) read_closed: AtomicBool,
    /// Set when smoltcp reports the send side is closed, and defensively in
    /// TcpStream::drop().
    pub(crate) write_closed: AtomicBool,
    /// Set by poll_shutdown(); poll_sockets closes once send_buffer is drained.
    pub(crate) write_shutdown: AtomicBool,
    // Present for accepted sockets, absent for isolated stream unit tests.
    // Used only to reserve the old four-tuple while Xray TUN is in TIME-WAIT.
    connection_tuple: Option<(SocketAddr, SocketAddr)>,
}

impl TcpStreamHandle {
    pub fn new() -> Self {
        Self {
            recv_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_RECV_BUFFER_SIZE as usize,
            ),
            recv_waker: AtomicWaker::new(),
            recv_window_zero: AtomicBool::new(false),
            recv_window_quantum: 1,
            send_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_SEND_BUFFER_SIZE as usize,
            ),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
            socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            connection_tuple: None,
        }
    }

    fn for_connection(
        source: SocketAddr,
        destination: SocketAddr,
        peer_window_scale: bool,
    ) -> Self {
        let mut handle = Self::new();
        handle.connection_tuple = Some((source, destination));
        if peer_window_scale {
            // smoltcp 0.13.1 calculates the announced shift using the
            // capacity's bit length minus 16 (256 KiB -> shift 3).
            let bits = usize::BITS
                - (DEFAULT_TCP_RECV_BUFFER_SIZE as usize).leading_zeros();
            handle.recv_window_quantum = 1usize << bits.saturating_sub(16);
        }
        handle
    }
}

impl Drop for TcpStreamHandle {
    fn drop(&mut self) {
        trace!("TcpStreamHandle dropped");
    }
}

struct PacketPumpContext {
    device_injector: mpsc::Sender<Packet>,
    response_sender: mpsc::Sender<Packet>,
    accept_invalid_ipv4_icmp_echo_checksum: bool,
    xray_unknown_destination_options: bool,
    tcp_mtu: usize,
}

pub struct TcpListener {
    socket_stream: mpsc::Receiver<TcpStream>,
    tracked_streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,

    shutdown_sender: Option<oneshot::Sender<()>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        trace!("TcpListener dropped");
        mark_tracked_streams_closed(&self.tracked_streams);
        if let Some(task_handle) = &self.task_handle {
            task_handle.abort();
        }
    }
}

impl TcpListener {
    /// Stop the TCP packet engine, close accepted streams with EOF, and wait
    /// until its background task has finished.
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(shutdown_sender) = self.shutdown_sender.take() {
            let _ = shutdown_sender.send(());
        }
        if let Some(task_handle) = self.task_handle.take() {
            task_handle
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))
        } else {
            Ok(())
        }
    }

    fn build_interface(device: &mut NetstackDevice) -> Interface {
        let mut config =
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = smoltcp::iface::Interface::new(
            config,
            device,
            smoltcp::time::Instant::now(),
        );
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1).into(),
                24,
            ));
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
                64,
            ));
        });

        if let Err(err) = iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
        {
            warn!("failed to add default IPv4 route to smoltcp interface: {err}");
        }
        if let Err(err) = iface.routes_mut().add_default_ipv6_route(
            smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1),
        ) {
            warn!("failed to add default IPv6 route to smoltcp interface: {err}");
        }

        iface
    }

    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self::with_mtu(inbound, outbound, 1500, false, false)
    }

    pub(crate) fn with_mtu(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        mtu: usize,
        accept_invalid_ipv4_icmp_echo_checksum: bool,
        xray_unknown_destination_options: bool,
    ) -> Self {
        let response_sender = outbound.clone();
        // the global bus that drives the iface polling
        let (iface_notifier, iface_notifier_rx) =
            mpsc::channel(IFACE_EVENT_QUEUE_SIZE);
        // Retain the real interface MTU. Lowering it alone does not
        // fix smoltcp's TCP option sizing: both MSS and the egress MTU
        // check use this capability. The opt-in Xray SYN MSS clamp below
        // bounds *data* without making the device report a false MTU.
        let mut device =
            NetstackDevice::with_mtu(outbound, iface_notifier.clone(), mtu);
        let mut iface = Self::build_interface(&mut device);

        let (socket_stream_emitter, socket_stream) =
            mpsc::channel::<TcpStream>(TCP_ACCEPT_QUEUE_SIZE);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();

        let tracked_streams = Arc::new(Mutex::new(Vec::new()));
        let last_tcp_packet = Arc::new(Mutex::new(None));

        let poll_packet_tracked_streams = tracked_streams.clone();
        let task_tracked_streams = tracked_streams.clone();
        let poll_packet_last_tcp_packet = last_tcp_packet.clone();
        let poll_socket_last_tcp_packet = last_tcp_packet;
        // Shared only between the packet admission and socket-state loops.
        // The existing 512-stream cap also bounds retained TIME-WAIT sockets.
        let time_wait_tuples = Arc::new(Mutex::new(HashSet::new()));
        let packet_time_wait_tuples = time_wait_tuples.clone();
        let task_handle = tokio::spawn(async move {
            let _shutdown_guard = StreamShutdownGuard {
                streams: task_tracked_streams,
            };
            let rv = tokio::select! {
                biased;
                _ = shutdown_receiver => Ok(()),
                rv = Self::poll_packets(inbound, PacketPumpContext { device_injector: device.create_injector(), response_sender, accept_invalid_ipv4_icmp_echo_checksum, xray_unknown_destination_options, tcp_mtu: mtu }, iface_notifier, socket_stream_emitter, poll_packet_tracked_streams, poll_packet_last_tcp_packet, packet_time_wait_tuples) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx, poll_socket_last_tcp_packet, time_wait_tuples, xray_unknown_destination_options) => rv,
            };
            if let Err(e) = rv {
                error!("Error in TCP listener: {e}");
            }
        });

        TcpListener {
            socket_stream,
            shutdown_sender: Some(shutdown_sender),
            task_handle: Some(task_handle),
            tracked_streams,
        }
    }

    async fn poll_packets(
        mut inbound: mpsc::Receiver<Packet>,
        context: PacketPumpContext,
        iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::Sender<TcpStream>,
        tracked_streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,
        last_tcp_packet: Arc<Mutex<Option<LastTcpPacketMeta>>>,
        time_wait_tuples: Arc<Mutex<HashSet<(SocketAddr, SocketAddr)>>>,
    ) -> std::io::Result<()> {
        let PacketPumpContext {
            device_injector,
            response_sender,
            accept_invalid_ipv4_icmp_echo_checksum,
            xray_unknown_destination_options,
            tcp_mtu,
        } = context;
        let mut packet_buf = Vec::with_capacity(32);
        let mut syn_tracker: HashMap<(SocketAddr, SocketAddr), std::time::Instant> =
            HashMap::new();
        // Packet loop owns TSecr recency; weak owners ensure stale tuples
        // do not survive socket close/panic or a new incarnation.
        let mut xray_timestamp_recent: HashMap<
            (SocketAddr, SocketAddr),
            XrayTimestampRecent,
        > = HashMap::new();
        let mut last_prune_time = std::time::Instant::now();
        let mut syn_drop_count: u64 = 0;
        let mut last_syn_drop_log = std::time::Instant::now();
        let mut control_fragments = FragmentReassembler::new_any("TCP/ICMP");
        if xray_unknown_destination_options {
            control_fragments =
                control_fragments.with_xray_unknown_destination_options();
        }
        let mut next_fragment_expiry =
            tokio::time::Instant::now() + FRAGMENT_EXPIRY_SCAN_INTERVAL;

        loop {
            let n = tokio::select! {
                count = inbound.recv_many(&mut packet_buf, 32) => count,
                _ = tokio::time::sleep_until(next_fragment_expiry), if control_fragments.has_active() => {
                    control_fragments.expire_stale();
                    next_fragment_expiry = tokio::time::Instant::now() + FRAGMENT_EXPIRY_SCAN_INTERVAL;
                    continue;
                }
            };
            if n == 0 {
                break;
            }
            let now = std::time::Instant::now();
            if now.duration_since(last_prune_time) > SYN_TRACK_TTL {
                syn_tracker
                    .retain(|_, time| now.duration_since(*time) < SYN_TRACK_TTL);
                last_prune_time = now;
            }

            trace!("Received {n} packets from inbound channel");
            for mut frame in packet_buf.drain(..) {
                {
                    let packet = match IpPacket::new_checked(frame.data()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            warn!("Invalid packet: {err}");
                            continue;
                        }
                    };
                    if !packet.verify_checksum() {
                        warn!("Invalid IP checksum");
                        continue;
                    }
                }

                let rebuilt_frame = match crate::fragment::is_fragmented(
                    frame.data(),
                ) {
                    Ok(true) => match control_fragments.push(frame.data()) {
                        Ok(Some(reassembled)) => {
                            if let Some(pointer) = reassembled.unknown_option_pointer
                            {
                                let quote = match reassembled.template.rebuild(
                                    reassembled.protocol,
                                    &reassembled.payload,
                                ) {
                                    Ok(quote) => quote,
                                    Err(err) => {
                                        warn!(
                                            "failed to rebuild IPv6 option error quote: {err}"
                                        );
                                        continue;
                                    }
                                };
                                match unknown_ipv6_option_error(&quote, pointer) {
                                    Ok(response) => {
                                        // ICMP errors must not block the packet pump.
                                        if response_sender
                                            .try_send(response)
                                            .is_err()
                                        {
                                            warn!(
                                                "dropping IPv6 option error: output full or closed"
                                            );
                                        }
                                    }
                                    Err(err) => warn!(
                                        "failed to create IPv6 option error: {err}"
                                    ),
                                }
                                continue;
                            }
                            match reassembled
                                .template
                                .rebuild(reassembled.protocol, &reassembled.payload)
                            {
                                Ok(packet) => Some(packet),
                                Err(err) => {
                                    warn!(
                                        "failed to rebuild fragmented TCP packet: {err}"
                                    );
                                    continue;
                                }
                            }
                        }
                        Ok(None) => continue,
                        Err(err) => {
                            warn!("invalid TCP fragment sequence: {err}");
                            continue;
                        }
                    },
                    Ok(false) => None,
                    Err(err) => {
                        warn!("invalid fragmented TCP packet: {err}");
                        continue;
                    }
                };
                let was_reassembled = rebuilt_frame.is_some();
                if let Some(rebuilt_frame) = rebuilt_frame {
                    frame = rebuilt_frame;
                }

                if xray_unknown_destination_options
                    && was_reassembled
                    && let Some(normalized) =
                        normalize_xray_fragmented_ipv6_tcp_options(frame.data())
                {
                    frame = Packet::new(normalized);
                }

                if accept_invalid_ipv4_icmp_echo_checksum
                    && let Some(normalized) =
                        normalize_invalid_ipv4_icmp_echo_checksum(frame.data())
                {
                    frame = Packet::new(normalized);
                }

                let packet = match IpPacket::new_checked(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid rebuilt IP packet: {err}");
                        continue;
                    }
                };
                let sliced = match etherparse::SlicedPacket::from_ip(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid IP transport packet: {err}");
                        continue;
                    }
                };

                if matches!(
                    sliced.transport,
                    Some(
                        etherparse::TransportSlice::Icmpv4(_)
                            | etherparse::TransportSlice::Icmpv6(_)
                    )
                ) {
                    match device_injector.send(frame.clone()).await {
                        Ok(_) => {}
                        Err(err) => {
                            warn!("Failed to send packet to device: {err}");
                            continue;
                        }
                    };
                    match iface_notifier.send(IfaceEvent::Icmp).await {
                        Ok(_) => continue,
                        Err(err) => {
                            warn!("Failed to send ICMP event: {err}");
                            continue;
                        }
                    }
                }

                let src_ip = packet.src_addr();
                let dst_ip = packet.dst_addr();
                let tcp = match sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => tcp,
                    None => {
                        // Unknown transport protocols still need the IP stack
                        // to generate IPv4/IPv6 protocol error responses.
                        match device_injector.send(frame.clone()).await {
                            Ok(_) => {}
                            Err(err) => {
                                warn!("Failed to send packet to device: {err}");
                                continue;
                            }
                        }
                        continue;
                    }
                    _ => {
                        warn!("TCP input did not contain a complete TCP segment");
                        continue;
                    }
                };

                let packet = match TcpPacket::new_checked(tcp.slice()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "{}",
                            invalid_tcp_packet_diagnostic(
                                err,
                                src_ip,
                                dst_ip,
                                tcp.slice().len(),
                            )
                        );
                        continue;
                    }
                };
                if !packet.verify_checksum(&src_ip.into(), &dst_ip.into()) {
                    warn!("Invalid TCP checksum: {src_ip} -> {dst_ip}");
                    continue;
                }
                let src_port = packet.src_port();
                let dst_port = packet.dst_port();

                let src_addr = SocketAddr::new(src_ip, src_port);
                let dst_addr = SocketAddr::new(dst_ip, dst_port);
                let conn_tuple = (src_addr, dst_addr);
                record_last_tcp_packet(
                    &last_tcp_packet,
                    &packet,
                    src_addr,
                    dst_addr,
                );

                // The real Xray TUN MTU must include any TCP options
                // on a full-size data segment. Rewrite the peer MSS only
                // on the private copy injected into smoltcp; this packet
                // has already passed the original checksum validation.
                let syn_mss_clamped = if xray_unknown_destination_options
                    && packet.syn()
                    && !packet.ack()
                {
                    xray_tun_clamp_syn_mss(
                        &frame,
                        tcp.slice(),
                        src_ip,
                        dst_ip,
                        tcp_mtu,
                    )
                } else {
                    None
                };

                // Pinned Xray/gVisor drops RST while a tuple is
                // TIME-WAIT (RFC 1337). smoltcp 0.13 instead closes that
                // socket and admits an immediate same-tuple incarnation.
                // Only drop this packet after the original TCP checksum
                // was verified, and only in explicit Xray TUN mode.
                if xray_unknown_destination_options
                    && packet.rst()
                    && time_wait_tuples
                        .lock()
                        .map_err(|_| {
                            std::io::Error::other("TCP TIME-WAIT lock poisoned")
                        })?
                        .contains(&(src_addr, dst_addr))
                {
                    continue;
                }

                let mut timestamp_adjusted: Option<Packet> = syn_mss_clamped.clone();
                if packet.syn() && !packet.ack() {
                    let conn_tuple = (src_addr, dst_addr);
                    // An existing Xray TUN TIME-WAIT socket must see this SYN
                    // itself; opening a second listener on the old tuple could
                    // accept a new incarnation before its close timer expires.
                    if xray_unknown_destination_options
                        && time_wait_tuples
                            .lock()
                            .map_err(|_| {
                                std::io::Error::other("TCP TIME-WAIT lock poisoned")
                            })?
                            .contains(&conn_tuple)
                    {
                        device_injector
                            .send(
                                syn_mss_clamped
                                    .clone()
                                    .unwrap_or_else(|| frame.clone()),
                            )
                            .await
                            .map_err(|error| {
                                std::io::Error::other(format!(
                                    "TIME-WAIT SYN inject failed: {error}"
                                ))
                            })?;
                        iface_notifier.send(IfaceEvent::DeviceReady).await.map_err(
                            |error| {
                                std::io::Error::other(format!(
                                    "TIME-WAIT SYN wake failed: {error}"
                                ))
                            },
                        )?;
                        continue;
                    }

                    if let Some(time) = syn_tracker.get_mut(&conn_tuple)
                        && now.duration_since(*time) < SYN_TRACK_TTL
                    {
                        // Refresh timestamp so the entry doesn't expire
                        // while the connection is still retransmitting SYNs.
                        *time = now;
                        device_injector
                            .send(
                                syn_mss_clamped
                                    .clone()
                                    .unwrap_or_else(|| frame.clone()),
                            )
                            .await
                            .map_err(|e| {
                                error!(
                                    "Failed to inject retransmitted SYN packet: {e}"
                                );
                                std::io::Error::other(
                                    "Failed to inject retransmitted SYN packet",
                                )
                            })?;
                        continue;
                    }

                    // TODO: get rid of this stupid log
                    if syn_tracker.len() >= SYN_TRACK_MAX {
                        syn_drop_count += 1;
                        if syn_drop_count == 1
                            || now.duration_since(last_syn_drop_log)
                                >= Duration::from_secs(10)
                        {
                            debug!(
                                "SYN flood protection: dropping SYN from \
                                 {src_addr} ({syn_drop_count} total dropped)"
                            );
                            last_syn_drop_log = now;
                        }
                        continue;
                    }

                    if !has_active_stream_capacity(
                        &tracked_streams,
                        ACTIVE_TCP_STREAM_MAX,
                    )? {
                        syn_drop_count += 1;
                        if syn_drop_count == 1
                            || now.duration_since(last_syn_drop_log)
                                >= Duration::from_secs(10)
                        {
                            warn!(
                                "TCP active stream limit reached ({ACTIVE_TCP_STREAM_MAX}); dropping SYN from {src_addr}"
                            );
                            last_syn_drop_log = now;
                        }
                        continue;
                    }

                    let Some(stream_permit) =
                        try_reserve_accept_slot(&tcp_stream_emitter)?
                    else {
                        debug!(
                            "TCP accept queue full ({TCP_ACCEPT_QUEUE_SIZE}); dropping SYN from {src_addr}"
                        );
                        continue;
                    };

                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![
                            0u8;
                            DEFAULT_TCP_RECV_BUFFER_SIZE
                                as usize
                        ]),
                        tcp::SocketBuffer::new(vec![
                            0u8;
                            DEFAULT_TCP_SEND_BUFFER_SIZE
                                as usize
                        ]),
                    );
                    if xray_unknown_destination_options {
                        socket.set_tsval_generator(Some(xray_tun_tcp_timestamp));
                    }
                    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
                        28,
                    )));

                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                        if cfg!(target_os = "linux") { 7200 } else { 60 },
                    )));
                    // Default
                    socket.set_ack_delay(Some(Duration::from_millis(10).into()));
                    socket.set_nagle_enabled(false);
                    socket.set_congestion_control(tcp::CongestionControl::Cubic);

                    if let Err(err) = socket.listen(dst_addr) {
                        error!("listen error: {err:?}");
                        continue;
                    }

                    // Track after listen() succeeds so a failed listen
                    // doesn't block future SYNs for the same tuple.
                    syn_tracker.insert(conn_tuple, now);

                    trace!("created TCP connection for {src_addr} <-> {dst_addr}");

                    let peer_window_scale =
                        tcp.options_iterator().filter_map(Result::ok).any(|opt| {
                            matches!(
                                opt,
                                etherparse::TcpOptionElement::WindowScale(_)
                            )
                        });
                    let handle = Arc::new(TcpStreamHandle::for_connection(
                        src_addr,
                        dst_addr,
                        peer_window_scale,
                    ));
                    if xray_unknown_destination_options {
                        // A new incarnation without a SYN Timestamp must
                        // not inherit a prior one's TSecr recency state.
                        xray_timestamp_recent.remove(&conn_tuple);
                        if let Some((_, tsval)) = tcp_tsval_field(tcp.slice()) {
                            // Reclaim released owners at the stream cap;
                            // short connections cannot grow the map beyond
                            // the 512-stream admission limit.
                            if xray_timestamp_recent.len() >= ACTIVE_TCP_STREAM_MAX {
                                xray_timestamp_recent.retain(|_, recent| {
                                    recent.owner.strong_count() > 0
                                });
                            }
                            xray_timestamp_recent.insert(
                                conn_tuple,
                                XrayTimestampRecent {
                                    owner: Arc::downgrade(&handle),
                                    recent: tsval,
                                    next_seq: tcp.sequence_number().wrapping_add(1),
                                    out_of_order: Vec::new(),
                                },
                            );
                        }
                    }
                    if let Ok(mut streams) = tracked_streams.lock() {
                        streams.retain(|stream| stream.strong_count() > 0);
                        streams.push(Arc::downgrade(&handle));
                    }

                    stream_permit.send(TcpStream {
                        local_addr: src_addr,
                        remote_addr: dst_addr,
                        handle: handle.clone(),
                        stack_notifier: iface_notifier.clone(),
                    });
                    iface_notifier
                        .send(IfaceEvent::TcpStream(Box::new((socket, handle))))
                        .await
                        .map_err(|e| {
                            error!("Failed to send TCP stream event: {e}");
                            std::io::Error::other("Failed to send TCP stream event")
                        })?;
                } else {
                    // Non-SYN packet: the connection has progressed past the
                    // handshake, so remove the tracker entry to free the slot.
                    syn_tracker.remove(&conn_tuple);
                    if xray_unknown_destination_options {
                        let mut expired = false;
                        if let Some(recent) =
                            xray_timestamp_recent.get_mut(&conn_tuple)
                        {
                            if recent.owner.strong_count() == 0 {
                                expired = true;
                            } else {
                                let tcp_bytes = tcp.slice();
                                let ts_field = tcp_tsval_field(tcp_bytes);
                                let header_len = usize::from(tcp_bytes[12] >> 4) * 4;
                                // At a genuine zero receive window, gVisor
                                // rejects payload/FIN sequence consumption
                                // before updating recent TSecr. Do not
                                // advance either our timestamp state or
                                // receive cursor for those rejected bytes.
                                // Pure ACKs remain eligible: pinned Xray
                                // updates recent TS even with a future ACK
                                // number when the incoming SEQ is valid.
                                let window_rejects_data =
                                    recent.owner.upgrade().is_some_and(|owner| {
                                        owner
                                            .recv_window_zero
                                            .load(Ordering::Acquire)
                                    }) && (tcp_bytes.len() > header_len
                                        || packet.fin());
                                let recent_value = if window_rejects_data {
                                    ts_field.map(|_| recent.recent)
                                } else {
                                    recent.observe(
                                        tcp.sequence_number(),
                                        tcp_bytes.len().saturating_sub(header_len),
                                        packet.fin(),
                                        ts_field.map(|(_, value)| value),
                                    )
                                };
                                if let (Some((ts_at, original)), Some(value)) =
                                    (ts_field, recent_value)
                                    && original != value
                                {
                                    // The original TCP checksum was checked above.
                                    // Canonicalize only the TSval passed to smoltcp,
                                    // so it echoes gVisor's retained recent value;
                                    // no TCP sequence, flags or payload is changed.
                                    let tcp_at =
                                        frame.data().len() - tcp_bytes.len();
                                    let mut bytes = frame.data().to_vec();
                                    bytes[tcp_at + ts_at..tcp_at + ts_at + 4]
                                        .copy_from_slice(&value.to_be_bytes());
                                    let mut tcp_packet = TcpPacket::new_unchecked(
                                        &mut bytes[tcp_at..],
                                    );
                                    tcp_packet.fill_checksum(
                                        &src_ip.into(),
                                        &dst_ip.into(),
                                    );
                                    timestamp_adjusted = Some(Packet::new(bytes));
                                }
                            }
                        }
                        if expired {
                            xray_timestamp_recent.remove(&conn_tuple);
                        }
                    }
                }

                device_injector
                    .send(timestamp_adjusted.unwrap_or_else(|| frame.clone()))
                    .await
                    .map_err(|e| {
                        error!("Failed to send packet to device: {e}");
                        std::io::Error::other("Failed to inject packet to device")
                    })?;
            }

            // trigger another poll to drive the socket state machine
            iface_notifier
                .send(IfaceEvent::DeviceReady)
                .await
                .map_err(|e| {
                    error!("Failed to send device ready event: {e}");
                    std::io::Error::other("Failed to send device ready event")
                })?;
        }

        Ok(())
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::Receiver<IfaceEvent<'_>>,
        last_tcp_packet: Arc<Mutex<Option<LastTcpPacketMeta>>>,
        time_wait_tuples: Arc<Mutex<HashSet<(SocketAddr, SocketAddr)>>>,
        xray_time_wait: bool,
    ) -> std::io::Result<()> {
        // Create a socket set for TCP sockets
        let mut sockets = smoltcp::iface::SocketSet::new(vec![]);
        let mut socket_maps: HashMap<
            smoltcp::iface::SocketHandle,
            Arc<TcpStreamHandle>,
        > = HashMap::new();
        let mut next_poll = None;
        let mut poll_requested = false;
        let mut panic_window_start = StdInstant::now();
        let mut panic_count = 0usize;

        loop {
            trace!(
                "Polling TCP sockets, next_poll: {:?}, num of sockets: {}",
                next_poll,
                socket_maps.len()
            );

            let should_poll_now = if poll_requested {
                true
            } else {
                match (next_poll, socket_maps.len()) {
                    (None, 0) => {
                        trace!("No sockets to poll, waiting indefinitely");
                        false
                    }
                    (None, _) => {
                        trace!("Polling sockets with no delay");
                        true
                    }
                    (Some(dur), _) => {
                        trace!("Polling sockets with delay: {dur:?}");
                        false
                    }
                }
            };
            poll_requested = false;
            let now = smoltcp::time::Instant::now();

            if should_poll_now {
                trace!("Woke up to poll sockets");

                // Drain pending notifier events before polling smoltcp.
                //
                // The critical race is IfaceEvent::TcpStream: poll_packets
                // creates the listening socket and queues it here before the
                // raw SYN is injected into the device buffer. If iface.poll()
                // runs first, smoltcp can observe the SYN without a matching
                // listener and immediately reply with RST.
                //
                // During active downloads poll_delay often returns 0/None, keeping
                // should_poll_now=true and never entering the else branch below.
                // Draining here ensures sockets are always registered in time.
                loop {
                    match notifier_rx.try_recv() {
                        Ok(IfaceEvent::TcpStream(stream)) => {
                            let socket_handle = sockets.add(stream.0);
                            socket_maps.insert(socket_handle, stream.1);
                            trace!(
                                "Added pending TCP socket before iface poll: {socket_handle:?}"
                            );
                        }
                        Ok(_) => {
                            // Other events only mean "poll soon", which is
                            // already what this branch is about to do.
                        }
                        Err(_) => break,
                    }
                }

                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                    iface.poll(now, device, &mut sockets);
                })) {
                    let panic_message = panic_payload_to_string(payload);
                    let active_socket_count = socket_maps.len();
                    let last_packet =
                        last_tcp_packet.lock().ok().and_then(|guard| guard.clone());
                    mark_all_streams_closed(&socket_maps);
                    socket_maps.clear();
                    // The previous socket set was discarded; no tuple may
                    // remain reserved by its old TIME-WAIT state.
                    if let Ok(mut reserved) = time_wait_tuples.lock() {
                        reserved.clear();
                    }
                    sockets = smoltcp::iface::SocketSet::new(vec![]);
                    *iface = Self::build_interface(device);
                    next_poll = None;

                    let now = StdInstant::now();
                    if now.duration_since(panic_window_start)
                        > Duration::from_secs(10)
                    {
                        panic_window_start = now;
                        panic_count = 0;
                    }
                    panic_count += 1;
                    let last_packet_log = last_packet
                        .as_ref()
                        .map(std::string::ToString::to_string)
                        .unwrap_or_else(|| "<none>".to_string());
                    error!(
                        "smoltcp iface.poll panicked: {panic_message}; active sockets: {}; last tcp packet: {}",
                        active_socket_count, last_packet_log
                    );
                    if panic_count >= 5 {
                        return Err(std::io::Error::other(format!(
                            "smoltcp iface.poll panicked repeatedly ({panic_count} times in 10s): {panic_message}"
                        )));
                    }
                    continue;
                }

                // Poll the sockets for new connections or data
                for (socket_handle, socket_control) in socket_maps.iter() {
                    let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);
                    trace!(
                        "Polling TCP socket: {:?}, can_recv: {}, can_send: {}",
                        socket_handle,
                        socket.can_recv(),
                        socket.can_send()
                    );

                    let buf = &socket_control.recv_buffer;
                    let mut notify_read = false;
                    while socket.can_recv() && !buf.is_full() {
                        if let Ok(n) = socket.recv(|buffer| {
                            let n = buf.enqueue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Received {n} bytes from TCP socket");
                        }
                        notify_read = true;
                    }
                    if notify_read {
                        socket_control.recv_waker.wake();
                    }
                    // Only the explicit Xray TUN packet path consumes this
                    // state; default tun-gateway retains its TCP behavior.
                    if xray_time_wait {
                        let free = socket
                            .recv_capacity()
                            .saturating_sub(socket.recv_queue());
                        socket_control.recv_window_zero.store(
                            free < socket_control.recv_window_quantum,
                            Ordering::Release,
                        );
                    }

                    let buf = &socket_control.send_buffer;
                    let mut notify_write = false;
                    while socket.can_send() && !buf.is_empty() {
                        if let Ok(n) = socket.send(|buffer| {
                            let n = buf.dequeue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Sent {n} bytes to TCP socket");
                        }
                        notify_write = true;
                    }

                    if notify_write {
                        socket_control.send_waker.wake();
                    }

                    // Only signal EOF/close after the socket has moved past
                    // the handshake states (Listen, SynSent, SynReceived).
                    // During the handshake may_recv()/may_send() return false
                    // but that does NOT mean the connection is closing — the
                    // flags are one-way and would permanently break the stream.
                    let past_handshake = !matches!(
                        socket.state(),
                        tcp::State::Listen
                            | tcp::State::SynSent
                            | tcp::State::SynReceived
                    );

                    if past_handshake
                        && !socket.may_recv()
                        && !socket.can_recv()
                        && !socket_control.read_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.recv_waker.wake();
                    }

                    if socket_control.write_shutdown.load(Ordering::Acquire)
                        && buf.is_empty()
                        && socket.may_send()
                    {
                        trace!("Closing TCP socket send half after buffer drained");
                        socket.close();
                    }

                    if past_handshake
                        && !socket.may_send()
                        && !socket_control.write_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.send_waker.wake();
                    }
                }

                {
                    let mut time_wait_guard =
                        time_wait_tuples.lock().map_err(|_| {
                            std::io::Error::other("TCP TIME-WAIT lock poisoned")
                        })?;
                    socket_maps.retain(|handle, socket_control| {
                        let socket = sockets.get_mut::<tcp::Socket>(*handle);

                        if socket_control.socket_dropped.load(Ordering::Acquire) {
                            // The app-side TcpStream was dropped. Flush remaining
                            // data from send_buffer into smoltcp's TX buffer, then
                            // initiate a graceful FIN. Do not remove immediately,
                            // otherwise smoltcp may discard queued TX data.
                            let buf = &socket_control.send_buffer;
                            while socket.can_send() && !buf.is_empty() {
                                if let Ok(n) = socket.send(|buffer| {
                                    let n = buf.dequeue_slice(buffer);
                                    (n, n)
                                }) {
                                    trace!(
                                        "Flushing {n} bytes to closing TCP socket"
                                    );
                                }
                            }
                            if buf.is_empty() {
                                socket.close();
                            }
                            // Keep the socket until smoltcp finishes the close
                            // handshake and reports is_active() == false.
                        }

                        if xray_time_wait && socket.state() == tcp::State::TimeWait {
                            if let Some(tuple) = socket_control.connection_tuple {
                                time_wait_guard.insert(tuple);
                            }
                            // smoltcp 0.13's is_active() excludes TIME-WAIT,
                            // though its packet handler still ACKs retransmitted
                            // FINs and its 10s close timer eventually expires.
                            true
                        } else if socket.is_active() {
                            true
                        } else {
                            if let Some(tuple) = socket_control.connection_tuple {
                                time_wait_guard.remove(&tuple);
                            }
                            trace!("Removing inactive TCP socket");
                            // Unblock any in-flight poll_read / poll_write on this
                            // stream. socket_closed covers RST/timeout paths where
                            // read_closed may not have been set by the data path.
                            socket_control
                                .socket_closed
                                .store(true, Ordering::Release);
                            socket_control
                                .write_closed
                                .store(true, Ordering::Release);
                            socket_control.recv_waker.wake();
                            socket_control.send_waker.wake();
                            sockets.remove(*handle);
                            false
                        }
                    });
                }

                next_poll = match iface.poll_delay(now, &sockets) {
                    Some(smoltcp::time::Duration::ZERO) => None,
                    Some(delay) => {
                        trace!("device poll delay: {delay:?}");
                        Some(delay.into())
                    }
                    None => None,
                };

                // Yield to the tokio scheduler so StackSplitStream can drain
                // outbound packets and send ACKs back. Without this, sustained
                // zero poll_delay can create a tight loop that starves readers.
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    Some(event) = notifier_rx.recv() => {
                        trace!("Received iface event, will poll sockets");
                        next_poll = None; // reset the next poll time
                        poll_requested = true;
                        match event {
                            IfaceEvent::TcpStream(stream) => {
                                let socket_handle = sockets.add(stream.0);
                                socket_maps.insert(socket_handle, stream.1);
                                trace!("Added new TCP socket: {socket_handle:?}");
                            }
                            IfaceEvent::TcpSocketReady => {
                                trace!("TCP socket is ready to read/write");
                            }
                            IfaceEvent::TcpSocketClosed => {
                                trace!("TCP socket closed by application");
                            }
                            IfaceEvent::DeviceReady => {
                                trace!("Device generated some packets, will poll sockets");
                            }
                            IfaceEvent::Icmp => {
                                trace!("ICMP packet received, will poll sockets");
                            }
                        }
                    }
                    _ = tokio::time::sleep(next_poll.unwrap_or(Duration::MAX)) => {
                        trace!("Woke up to poll sockets after delay");
                        next_poll = None; // reset the next poll time
                    }
                }
            }
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.socket_stream.poll_recv(cx)
    }
}

#[cfg(test)]
mod resource_limit_tests {
    use super::*;

    #[test]
    fn xray_internal_syn_mss_clamp_preserves_wire_and_checksum() {
        use etherparse::TcpOptionElement as Opt;

        for (source, destination, advertised_mss, expected_mss) in [
            (
                IpAddr::V6(std::net::Ipv6Addr::from([0x79; 16])),
                IpAddr::V6(std::net::Ipv6Addr::from([0x7a; 16])),
                1460,
                1300,
            ),
            (
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 3)),
                1460,
                1320,
            ),
        ] {
            let mut header = etherparse::TcpHeader::new(46281, 39643, 1000, 8192);
            header.syn = true;
            header
                .set_options(&[
                    Opt::MaximumSegmentSize(advertised_mss),
                    Opt::WindowScale(7),
                    Opt::SelectiveAcknowledgementPermitted,
                    Opt::Timestamp(50_000, 0),
                ])
                .unwrap();
            let mut frame = Vec::new();
            match (source, destination) {
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                        .tcp_header(header)
                        .write(&mut frame, &[])
                        .unwrap();
                }
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
                        .tcp_header(header)
                        .write(&mut frame, &[])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let original = Packet::new(frame);
            let original_sliced =
                etherparse::SlicedPacket::from_ip(original.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(original_tcp)) =
                original_sliced.transport
            else {
                panic!("expected original SYN");
            };
            let rewritten = xray_tun_clamp_syn_mss(
                &original,
                original_tcp.slice(),
                source,
                destination,
                1400,
            )
            .expect("large MSS should be clamped");
            let sliced =
                etherparse::SlicedPacket::from_ip(rewritten.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport else {
                panic!("expected rewritten SYN");
            };
            assert_eq!(
                tcp.options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|option| {
                        match option {
                            Opt::MaximumSegmentSize(size) => Some(size),
                            _ => None,
                        }
                    }),
                Some(expected_mss)
            );
            assert!(
                tcp.options_iterator()
                    .filter_map(Result::ok)
                    .any(|option| matches!(option, Opt::Timestamp(50_000, 0)))
            );
            let parsed = TcpPacket::new_checked(tcp.slice()).unwrap();
            assert!(parsed.verify_checksum(&source.into(), &destination.into()));
            assert_eq!(
                original_tcp
                    .options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|option| match option {
                        Opt::MaximumSegmentSize(size) => Some(size),
                        _ => None,
                    }),
                Some(advertised_mss),
                "original on-wire SYN must remain unchanged"
            );
            assert!(
                xray_tun_clamp_syn_mss(
                    &rewritten,
                    tcp.slice(),
                    source,
                    destination,
                    1400
                )
                .is_none(),
                "already-safe MSS must not be rewritten again"
            );
        }
    }

    #[test]
    fn xray_tcp_receive_window_rounding_respects_negotiated_window_scale() {
        let src: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let unscaled = TcpStreamHandle::for_connection(src, dst, false);
        let scaled = TcpStreamHandle::for_connection(src, dst, true);
        assert_eq!(unscaled.recv_window_quantum, 1);
        // Match smoltcp's 256 KiB ring-buffer Window Scale shift of 3.
        assert_eq!(scaled.recv_window_quantum, 8);
    }

    #[test]
    fn xray_tsecr_recency_retains_newest_value_through_old_tsval_and_wrap() {
        let owner = Arc::new(TcpStreamHandle::new());
        let mut recent = XrayTimestampRecent {
            owner: Arc::downgrade(&owner),
            recent: 40_000,
            next_seq: 1_001,
            out_of_order: Vec::new(),
        };
        assert_eq!(recent.observe(1_001, 10, false, Some(41_000)), Some(41_000));
        assert_eq!(recent.observe(1_011, 10, false, Some(40_001)), Some(41_000));
        assert_eq!(recent.next_seq, 1_021);
        assert_eq!(recent.observe(1_021, 0, false, None), None);
        assert_eq!(recent.observe(1_021, 5, false, Some(42_000)), Some(42_000));
        // A future out-of-order TCP sequence cannot poison recent TSval.
        assert_eq!(recent.observe(40_000, 0, false, Some(43_000)), Some(42_000));
        assert_eq!(recent.next_seq, 1_026);
        // Modular signed comparison accepts a legitimate TSval wrap.
        recent.recent = u32::MAX - 15;
        recent.next_seq = 2_001;
        assert_eq!(
            recent.observe(2_001, 4, false, Some(u32::MAX - 7)),
            Some(u32::MAX - 7)
        );
        assert_eq!(recent.observe(2_005, 4, false, Some(8)), Some(8));
        assert_eq!(recent.observe(2_009, 0, false, Some(u32::MAX - 1)), Some(8));
        assert!(recent.owner.strong_count() > 0);
        drop(owner);
        assert_eq!(recent.owner.strong_count(), 0);
    }

    #[test]
    fn xray_tsecr_gap_reassembly_advances_ack_cursor_without_future_ts_poisoning() {
        let owner = Arc::new(TcpStreamHandle::new());
        let mut recent = XrayTimestampRecent {
            owner: Arc::downgrade(&owner),
            recent: 40_000,
            next_seq: 1_001,
            out_of_order: Vec::new(),
        };
        // Future data arrives before the 10-byte missing prefix. Its newer
        // timestamp must not be accepted while the gap is unacknowledged.
        assert_eq!(recent.observe(1_011, 10, false, Some(50_000)), Some(40_000));
        assert_eq!(recent.next_seq, 1_001);
        // Receiving the prefix unlocks a contiguous 20-byte sequence, as
        // the TCP stack's next cumulative ACK would cover the buffered tail.
        assert_eq!(recent.observe(1_001, 10, false, Some(41_000)), Some(41_000));
        assert_eq!(recent.next_seq, 1_021);
        assert_eq!(recent.observe(1_021, 4, false, Some(42_000)), Some(42_000));
        // The receive sequence number may also wrap at 2^32. A buffered
        // tail starting after wrap must be consumed on prefix repair.
        recent.out_of_order.clear();
        recent.next_seq = u32::MAX - 4;
        assert_eq!(recent.observe(2, 3, false, Some(60_000)), Some(42_000));
        assert_eq!(
            recent.observe(u32::MAX - 4, 7, false, Some(43_000)),
            Some(43_000)
        );
        assert_eq!(recent.next_seq, 5);
        assert_eq!(recent.observe(5, 2, false, Some(44_000)), Some(44_000));
    }

    #[test]
    fn xray_tsecr_future_ack_and_zero_length_window_probe_do_not_advance_cursor() {
        let owner = Arc::new(TcpStreamHandle::new());
        let mut recent = XrayTimestampRecent {
            owner: Arc::downgrade(&owner),
            recent: 40_000,
            next_seq: 1_001,
            out_of_order: Vec::new(),
        };
        // Pure ACKs and zero-length keepalive/window probes consume no
        // receive sequence even when they carry newer Timestamp options.
        assert_eq!(recent.observe(1_001, 0, false, Some(41_000)), Some(41_000));
        assert_eq!(recent.observe(1_000, 0, false, Some(42_000)), Some(42_000));
        assert_eq!(recent.next_seq, 1_001);
        // An off-window, future-sequence ACK must not poison TSecr.
        assert_eq!(
            recent.observe(400_000, 0, false, Some(70_000)),
            Some(42_000)
        );
        assert_eq!(recent.next_seq, 1_001);
        assert_eq!(recent.observe(1_001, 5, false, Some(43_000)), Some(43_000));
        assert_eq!(recent.next_seq, 1_006);
        // This tests recency metadata, not an application receive window
        // at zero; actual smoltcp and pinned gVisor ACKs remain authoritative.
    }

    #[test]
    fn xray_tsval_field_rejects_truncated_options() {
        let mut header = etherparse::TcpHeader::new(40001, 80, 1234, 4096);
        header.syn = true;
        header
            .set_options(&[
                etherparse::TcpOptionElement::Noop,
                etherparse::TcpOptionElement::Timestamp(123, 456),
            ])
            .unwrap();
        let wire = header.to_bytes();
        let (offset, tsval) = tcp_tsval_field(&wire).unwrap();
        assert_eq!(tsval, 123);
        assert_eq!(&wire[offset..offset + 4], &123u32.to_be_bytes());
        let mut truncated = wire.clone();
        truncated[12] = 0x50; // Declares no TCP options.
        assert_eq!(tcp_tsval_field(&truncated), None);
    }

    #[test]
    fn invalid_tcp_packet_diagnostic_reports_length_without_segment_bytes() {
        let secret = b"credential-like-payload";
        let diagnostic = invalid_tcp_packet_diagnostic(
            "truncated TCP header",
            IpAddr::from([192, 0, 2, 10]),
            IpAddr::from([192, 0, 2, 20]),
            secret.len(),
        );

        assert_eq!(
            diagnostic,
            format!(
                "invalid TCP segment: truncated TCP header, src_ip: \
                 192.0.2.10, dst_ip: 192.0.2.20, segment_len: {}",
                secret.len()
            )
        );
        assert!(!diagnostic.contains("credential-like-payload"));
    }

    #[test]
    fn active_stream_capacity_recovers_after_drop() {
        let streams = Mutex::new(Vec::new());
        let first = Arc::new(TcpStreamHandle::new());
        let second = Arc::new(TcpStreamHandle::new());
        {
            let mut tracked = streams.lock().unwrap();
            tracked.push(Arc::downgrade(&first));
            tracked.push(Arc::downgrade(&second));
        }

        assert!(!has_active_stream_capacity(&streams, 2).unwrap());
        drop(first);
        assert!(has_active_stream_capacity(&streams, 2).unwrap());
    }

    #[test]
    fn accept_queue_capacity_recovers_after_permit_release() {
        let (sender, _receiver) = mpsc::channel::<TcpStream>(2);
        let first = try_reserve_accept_slot(&sender)
            .unwrap()
            .expect("first accept slot missing");
        let _second = try_reserve_accept_slot(&sender)
            .unwrap()
            .expect("second accept slot missing");

        assert!(
            try_reserve_accept_slot(&sender).unwrap().is_none(),
            "full accept queue must reject additional reservations"
        );

        drop(first);
        assert!(
            try_reserve_accept_slot(&sender).unwrap().is_some(),
            "released accept slot was not reusable"
        );
    }
}

#[cfg(test)]
mod fragment_expiry_tests {
    use super::*;
    use std::time::Duration;

    fn ipv4_icmp_fragment(
        identification: u16,
        offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> Packet {
        let mut header = etherparse::Ipv4Header::new(
            payload.len() as u16,
            64,
            etherparse::ip_number::ICMP,
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

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for word in bytes.chunks(2) {
            let high = u32::from(word[0]) << 8;
            let low = word.get(1).copied().map(u32::from).unwrap_or_default();
            sum += high | low;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_control_fragments_expire_while_listener_is_idle() {
        let (inbound_sender, inbound_receiver) = mpsc::channel(2);
        let (device_sender, mut device_receiver) = mpsc::channel(2);
        let (iface_sender, _iface_receiver) = mpsc::channel(2);
        let (stream_sender, _stream_receiver) = mpsc::channel(2);
        let tracked_streams = Arc::new(Mutex::new(Vec::new()));
        let last_tcp_packet = Arc::new(Mutex::new(None));
        let poll_task = tokio::spawn(TcpListener::poll_packets(
            inbound_receiver,
            PacketPumpContext {
                device_injector: device_sender.clone(),
                response_sender: device_sender,
                accept_invalid_ipv4_icmp_echo_checksum: false,
                xray_unknown_destination_options: false,
                tcp_mtu: 1500,
            },
            iface_sender,
            stream_sender,
            tracked_streams,
            last_tcp_packet,
            Arc::new(Mutex::new(HashSet::new())),
        ));

        let icmp_payload = [
            8, 0, 0, 0, // echo request type, code and checksum
            0x12, 0x34, 0, 1, // identifier and sequence
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h',
        ];
        let checksum = internet_checksum(&icmp_payload);
        let mut icmp_payload = icmp_payload;
        icmp_payload[2..4].copy_from_slice(&checksum.to_be_bytes());

        inbound_sender
            .send(ipv4_icmp_fragment(9, 0, true, &icmp_payload[..8]))
            .await
            .expect("first ICMP fragment should be accepted");
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;

        inbound_sender
            .send(ipv4_icmp_fragment(9, 1, false, &icmp_payload[8..]))
            .await
            .expect("tail ICMP fragment should be accepted");
        drop(inbound_sender);

        poll_task
            .await
            .expect("packet poll task should join")
            .expect("packet poll should end cleanly");
        assert!(
            device_receiver.try_recv().is_err(),
            "expired ICMP fragments must not be reassembled and injected"
        );
    }
}
