use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use quinn::{AsyncUdpSocket, UdpPoller, udp};
use rand::{Rng, RngExt};

const SALAMANDER_MIN_PSK_LEN: usize = 4;
const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const XRAY_FINALMASK_UDP_SIZE: usize = 4096;
const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_FRAGMENT_CHUNKS: u8 = 2;
const GECKO_MAX_FRAGMENT_CHUNKS: u8 = 8;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;
const GECKO_BUFFER_SIZE: usize = 2048;
const GECKO_DEFAULT_MIN_PACKET: usize = 512;
const GECKO_DEFAULT_MAX_PACKET: usize = 1200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeckoFrameHeader {
    pad_len: u16,
    msg_id: u8,
    chunk_idx: u8,
    total_chunks: u8,
}

fn encode_gecko_frame(
    header: GeckoFrameHeader,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS)
        .contains(&header.total_chunks)
        || header.chunk_idx >= header.total_chunks
    {
        return Err("invalid gecko fragment header");
    }

    let mut output =
        vec![0_u8; GECKO_HEADER_LEN + usize::from(header.pad_len) + payload.len()];
    output[0] = GECKO_FRAGMENT_FLAG;
    output[1] = header.msg_id;
    output[2] = header.chunk_idx << 4 | header.total_chunks & 0x0f;
    output[3..5].copy_from_slice(&header.pad_len.to_be_bytes());
    rand::rng().fill_bytes(
        &mut output
            [GECKO_HEADER_LEN..GECKO_HEADER_LEN + usize::from(header.pad_len)],
    );
    output[GECKO_HEADER_LEN + usize::from(header.pad_len)..]
        .copy_from_slice(payload);
    Ok(output)
}

fn decode_gecko_frame(
    input: &[u8],
) -> Result<(GeckoFrameHeader, &[u8]), &'static str> {
    if input.len() < GECKO_HEADER_LEN {
        return Err("truncated gecko fragment frame");
    }
    if input[0] & GECKO_FRAGMENT_FLAG == 0 {
        return Err("invalid gecko fragment marker");
    }

    let header = GeckoFrameHeader {
        msg_id: input[1],
        chunk_idx: input[2] >> 4,
        total_chunks: input[2] & 0x0f,
        pad_len: u16::from_be_bytes([input[3], input[4]]),
    };
    if !(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS)
        .contains(&header.total_chunks)
        || header.chunk_idx >= header.total_chunks
    {
        return Err("invalid gecko fragment header");
    }
    let payload_offset = GECKO_HEADER_LEN + usize::from(header.pad_len);
    if payload_offset > input.len() {
        return Err("truncated gecko fragment padding");
    }
    Ok((header, &input[payload_offset..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GeckoReassemblyKey {
    addr: SocketAddr,
    msg_id: u8,
}

#[derive(Debug)]
struct GeckoReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct GeckoReassembly {
    entries: HashMap<GeckoReassemblyKey, GeckoReassemblyEntry>,
    per_source: HashMap<SocketAddr, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeckoPacketSize {
    min: usize,
    max: usize,
}

impl GeckoPacketSize {
    fn new(min: usize, max: usize) -> Result<Self, &'static str> {
        let min = if min == 0 {
            GECKO_DEFAULT_MIN_PACKET
        } else {
            min
        };
        let max = if max == 0 {
            GECKO_DEFAULT_MAX_PACKET
        } else {
            max
        };
        if min == 0 || min > max || max > GECKO_BUFFER_SIZE {
            return Err("gecko: invalid min/max packet size");
        }
        Ok(Self { min, max })
    }

    fn random_pad_len(&self, chunk_len: usize) -> u16 {
        let base = SALAMANDER_SALT_LEN + GECKO_HEADER_LEN + chunk_len;
        let lo = self.min.max(base);
        if lo > self.max {
            return 0;
        }
        let span = self.max - lo + 1;
        let extra = if span <= 1 {
            0
        } else {
            rand::rng().random_range(0..span)
        };
        u16::try_from(lo - base + extra).unwrap_or(0)
    }
}

fn random_gecko_fragment_chunks() -> u8 {
    rand::rng().random_range(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS)
}

fn gecko_fragment_packet(
    payload: &[u8],
    msg_id: u8,
    packet_size: GeckoPacketSize,
    chunks: u8,
) -> Result<Vec<Vec<u8>>, &'static str> {
    if !(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS).contains(&chunks) {
        return Err("invalid gecko fragment count");
    }
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if payload[0] & GECKO_FRAGMENT_FLAG == 0 {
        return Ok(vec![payload.to_vec()]);
    }

    let chunk_size = payload.len() / usize::from(chunks);
    let mut packets = Vec::with_capacity(usize::from(chunks));
    for chunk_index in 0..chunks {
        let start = usize::from(chunk_index) * chunk_size;
        let end = if chunk_index + 1 == chunks {
            payload.len()
        } else {
            start + chunk_size
        };
        let chunk = &payload[start..end];
        packets.push(encode_gecko_frame(
            GeckoFrameHeader {
                pad_len: packet_size.random_pad_len(chunk.len()),
                msg_id,
                chunk_idx: chunk_index,
                total_chunks: chunks,
            },
            chunk,
        )?);
    }
    Ok(packets)
}

impl GeckoReassembly {
    fn accept_chunk(
        &mut self,
        addr: SocketAddr,
        header: GeckoFrameHeader,
        payload: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let key = GeckoReassemblyKey {
            addr,
            msg_id: header.msg_id,
        };
        if !self.entries.contains_key(&key) {
            if self.per_source.get(&addr).copied().unwrap_or_default()
                >= GECKO_MAX_PER_SOURCE
            {
                return None;
            }
            if self.entries.len() >= GECKO_MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.entries.insert(
                key,
                GeckoReassemblyEntry {
                    chunks: vec![None; usize::from(header.total_chunks)],
                    received: 0,
                    total: header.total_chunks,
                    deadline: now + GECKO_REASSEMBLY_TTL,
                },
            );
            *self.per_source.entry(addr).or_default() += 1;
        }

        let entry = self.entries.get_mut(&key)?;
        if entry.total != header.total_chunks {
            return None;
        }
        let chunk = entry.chunks.get_mut(usize::from(header.chunk_idx))?;
        if chunk.is_some() {
            return None;
        }
        *chunk = Some(payload.to_vec());
        entry.received += 1;
        if entry.received < usize::from(entry.total) {
            return None;
        }

        let mut output = Vec::new();
        for chunk in &entry.chunks {
            output.extend_from_slice(chunk.as_deref()?);
        }
        self.drop_entry(key);
        Some(output)
    }

    fn gc_expired(&mut self, now: Instant) {
        let expired = self
            .entries
            .iter()
            .filter_map(|(key, entry)| (now > entry.deadline).then_some(*key))
            .collect::<Vec<_>>();
        for key in expired {
            self.drop_entry(key);
        }
    }

    fn drop_entry(&mut self, key: GeckoReassemblyKey) {
        if self.entries.remove(&key).is_none() {
            return;
        }
        if let Some(count) = self.per_source.get_mut(&key.addr) {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(&key.addr);
            }
        }
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.drop_entry(key);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SalamanderObfuscator {
    psk: Vec<u8>,
}

impl SalamanderObfuscator {
    pub(crate) fn new(psk: impl Into<Vec<u8>>) -> Result<Self, &'static str> {
        let psk = psk.into();
        if psk.len() < SALAMANDER_MIN_PSK_LEN {
            return Err("salamander PSK must be at least 4 bytes");
        }
        Ok(Self { psk })
    }

    pub(crate) fn obfuscate(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0_u8; SALAMANDER_SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        self.obfuscate_with_salt(payload, salt)
    }

    fn obfuscate_with_salt(
        &self,
        payload: &[u8],
        salt: [u8; SALAMANDER_SALT_LEN],
    ) -> Vec<u8> {
        let key = self.derive_key(&salt);
        let mut output = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
        output.extend_from_slice(&salt);
        output.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % SALAMANDER_KEY_LEN]),
        );
        output
    }

    pub(crate) fn deobfuscate(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let (salt, payload) = packet.split_at_checked(SALAMANDER_SALT_LEN)?;
        let key = self.derive_key(salt);
        Some(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % SALAMANDER_KEY_LEN])
                .collect(),
        )
    }

    fn derive_key(&self, salt: &[u8]) -> [u8; SALAMANDER_KEY_LEN] {
        let mut hasher = Blake2bVar::new(SALAMANDER_KEY_LEN)
            .expect("BLAKE2b-256 output length is valid");
        hasher.update(&self.psk);
        hasher.update(salt);
        let mut key = [0_u8; SALAMANDER_KEY_LEN];
        hasher
            .finalize_variable(&mut key)
            .expect("BLAKE2b output buffer has the configured length");
        key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeckoTransmitKey {
    destination: SocketAddr,
    ecn: Option<udp::EcnCodepoint>,
    src_ip: Option<std::net::IpAddr>,
    contents: Vec<u8>,
}

impl GeckoTransmitKey {
    fn matches(&self, transmit: &udp::Transmit<'_>) -> bool {
        self.destination == transmit.destination
            && self.ecn == transmit.ecn
            && self.src_ip == transmit.src_ip
            && self.contents == transmit.contents
    }
}

#[derive(Debug)]
struct PendingGeckoSend {
    original: GeckoTransmitKey,
    fragments: Vec<Vec<u8>>,
    next_fragment: usize,
}

#[derive(Debug, Default)]
struct GeckoSendState {
    next_msg_id: u8,
    pending: Option<PendingGeckoSend>,
}

#[derive(Debug)]
pub(crate) struct GeckoUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfuscator: SalamanderObfuscator,
    packet_size: GeckoPacketSize,
    send_state: Mutex<GeckoSendState>,
    reassembly: Mutex<GeckoReassembly>,
}

impl GeckoUdpSocket {
    pub(crate) fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        password: impl Into<Vec<u8>>,
        min_packet_size: usize,
        max_packet_size: usize,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            inner,
            obfuscator: SalamanderObfuscator::new(password)?,
            packet_size: GeckoPacketSize::new(min_packet_size, max_packet_size)?,
            send_state: Mutex::new(GeckoSendState::default()),
            reassembly: Mutex::new(GeckoReassembly::default()),
        })
    }

    fn send_obfuscated(
        &self,
        payload: &[u8],
        transmit: &udp::Transmit<'_>,
    ) -> io::Result<()> {
        let contents = self.obfuscator.obfuscate(payload);
        self.inner.try_send(&udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn flush_pending(
        &self,
        state: &mut GeckoSendState,
        transmit: &udp::Transmit<'_>,
    ) -> io::Result<bool> {
        let Some(pending) = state.pending.as_mut() else {
            return Ok(false);
        };
        let same_transmit = pending.original.matches(transmit);
        while let Some(fragment) = pending.fragments.get(pending.next_fragment) {
            let contents = self.obfuscator.obfuscate(fragment);
            let fragment_transmit = udp::Transmit {
                destination: pending.original.destination,
                ecn: pending.original.ecn,
                contents: &contents,
                segment_size: None,
                src_ip: pending.original.src_ip,
            };
            match self.inner.try_send(&fragment_transmit) {
                Ok(()) => pending.next_fragment += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(error);
                }
                Err(error) => {
                    state.pending = None;
                    return Err(error);
                }
            }
        }
        state.pending = None;
        Ok(same_transmit)
    }
}

impl AsyncUdpSocket for GeckoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gecko UDP mask does not support segmented transmits",
            ));
        }

        let mut state = self
            .send_state
            .lock()
            .map_err(|_| io::Error::other("gecko send state poisoned"))?;
        if self.flush_pending(&mut state, transmit)? {
            return Ok(());
        }
        if transmit.contents.is_empty() {
            return Ok(());
        }
        if transmit.contents[0] & GECKO_FRAGMENT_FLAG == 0 {
            return self.send_obfuscated(transmit.contents, transmit);
        }

        state.next_msg_id = state.next_msg_id.wrapping_add(1);
        let fragments = gecko_fragment_packet(
            transmit.contents,
            state.next_msg_id,
            self.packet_size,
            random_gecko_fragment_chunks(),
        )
        .map_err(io::Error::other)?;
        let original = GeckoTransmitKey {
            destination: transmit.destination,
            ecn: transmit.ecn,
            src_ip: transmit.src_ip,
            contents: transmit.contents.to_vec(),
        };
        state.pending = Some(PendingGeckoSend {
            original,
            fragments,
            next_fragment: 0,
        });
        if self.flush_pending(&mut state, transmit)? {
            return Ok(());
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(output) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(output_meta) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        loop {
            let mut packet = vec![0_u8; XRAY_FINALMASK_UDP_SIZE];
            let mut packet_buf = [IoSliceMut::new(&mut packet)];
            let mut packet_meta = [udp::RecvMeta::default()];
            let count =
                match self.inner.poll_recv(cx, &mut packet_buf, &mut packet_meta) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                };
            if count == 0 {
                return Poll::Ready(Ok(0));
            }

            let raw_meta = packet_meta[0];
            let Some(payload) = self.obfuscator.deobfuscate(&packet[..raw_meta.len])
            else {
                continue;
            };
            let now = Instant::now();
            let is_fragment = payload
                .first()
                .is_some_and(|byte| byte & GECKO_FRAGMENT_FLAG != 0);
            let payload = {
                let mut reassembly = match self.reassembly.lock() {
                    Ok(reassembly) => reassembly,
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::other(
                            "gecko reassembly state poisoned",
                        )));
                    }
                };
                // Xray runs Gecko reassembly GC independently of fragment input.
                // Opportunistically run the same expiry check for every packet so
                // active short-header traffic cannot keep stale fragment state alive.
                reassembly.gc_expired(now);
                if is_fragment {
                    let Ok((header, chunk)) = decode_gecko_frame(&payload) else {
                        continue;
                    };
                    let Some(payload) =
                        reassembly.accept_chunk(raw_meta.addr, header, chunk, now)
                    else {
                        continue;
                    };
                    payload
                } else {
                    payload
                }
            };

            let copied = payload.len().min(output.len());
            output[..copied].copy_from_slice(&payload[..copied]);
            *output_meta = raw_meta;
            output_meta.len = copied;
            output_meta.stride = copied;
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub(crate) struct SalamanderUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfuscator: SalamanderObfuscator,
}

impl SalamanderUdpSocket {
    pub(crate) fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        password: impl Into<Vec<u8>>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            inner,
            obfuscator: SalamanderObfuscator::new(password)?,
        })
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander UDP mask does not support segmented transmits",
            ));
        }
        if transmit.contents.len() + SALAMANDER_SALT_LEN > XRAY_FINALMASK_UDP_SIZE {
            // Xray's headerManagerConn silently drops UDP payloads that no longer fit
            // into its fixed 4096-byte finalMask buffer after header expansion.
            return Ok(());
        }
        let contents = self.obfuscator.obfuscate(transmit.contents);
        self.inner.try_send(&udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(output) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(output_meta) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        loop {
            let mut packet = vec![0_u8; XRAY_FINALMASK_UDP_SIZE];
            let mut packet_buf = [IoSliceMut::new(&mut packet)];
            let mut packet_meta = [udp::RecvMeta::default()];
            let count =
                match self.inner.poll_recv(cx, &mut packet_buf, &mut packet_meta) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                };
            if count == 0 {
                return Poll::Ready(Ok(0));
            }

            let raw_meta = packet_meta[0];
            let Some(payload) = self.obfuscator.deobfuscate(&packet[..raw_meta.len])
            else {
                continue;
            };
            let copied = payload.len().min(output.len());
            output[..copied].copy_from_slice(&payload[..copied]);
            *output_meta = raw_meta;
            output_meta.len = copied;
            output_meta.stride = copied;
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use quinn::Runtime;

    use super::*;

    #[derive(Debug, Default)]
    struct ReadyPoller;

    impl UdpPoller for ReadyPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SentDatagram {
        destination: SocketAddr,
        ecn: Option<udp::EcnCodepoint>,
        src_ip: Option<std::net::IpAddr>,
        contents: Vec<u8>,
    }

    #[derive(Debug, Default)]
    struct BlockingSendSocket {
        calls: AtomicUsize,
        blocked_once: AtomicBool,
        sent: Mutex<Vec<SentDatagram>>,
    }

    impl AsyncUdpSocket for BlockingSendSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(ReadyPoller)
        }

        fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 2 && !self.blocked_once.swap(true, Ordering::SeqCst) {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.sent.lock().unwrap().push(SentDatagram {
                destination: transmit.destination,
                ecn: transmit.ecn,
                src_ip: transmit.src_ip,
                contents: transmit.contents.to_vec(),
            });
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    #[test]
    fn gecko_udp_socket_resumes_partial_fragment_send_without_duplicates() {
        let inner = Arc::new(BlockingSendSocket::default());
        let masked =
            GeckoUdpSocket::new(inner.clone(), b"password".to_vec(), 64, 96)
                .expect("valid gecko socket");
        let payload = vec![0x80_u8; 120];
        let transmit = udp::Transmit {
            destination: "127.0.0.1:443".parse().unwrap(),
            ecn: None,
            contents: &payload,
            segment_size: None,
            src_ip: None,
        };

        let error = masked
            .try_send(&transmit)
            .expect_err("second fragment should block once");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        masked
            .try_send(&transmit)
            .expect("retry should resume pending fragments");

        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        let sent = inner.sent.lock().unwrap();
        assert!(
            (GECKO_MIN_FRAGMENT_CHUNKS as usize
                ..=GECKO_MAX_FRAGMENT_CHUNKS as usize)
                .contains(&sent.len())
        );
        let mut chunks = Vec::new();
        for packet in sent.iter() {
            let clear = obfuscator.deobfuscate(&packet.contents).unwrap();
            let (header, chunk) = decode_gecko_frame(&clear).unwrap();
            chunks.push((header.chunk_idx, header.total_chunks, chunk.to_vec()));
        }
        let total = chunks[0].1;
        assert_eq!(chunks.len(), usize::from(total));
        chunks.sort_by_key(|(index, _, _)| *index);
        assert_eq!(
            chunks
                .iter()
                .map(|(index, _, _)| *index)
                .collect::<Vec<_>>(),
            (0..total).collect::<Vec<_>>()
        );
        assert_eq!(
            chunks
                .into_iter()
                .flat_map(|(_, _, chunk)| chunk)
                .collect::<Vec<_>>(),
            payload
        );
    }

    #[test]
    fn gecko_udp_socket_keeps_pending_fragment_metadata_on_new_transmit() {
        let inner = Arc::new(BlockingSendSocket::default());
        let masked =
            GeckoUdpSocket::new(inner.clone(), b"password".to_vec(), 64, 96)
                .expect("valid gecko socket");
        let first_payload = vec![0x80_u8; 120];
        let first_destination: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let first_source = Some("192.0.2.10".parse().unwrap());
        let first = udp::Transmit {
            destination: first_destination,
            ecn: Some(udp::EcnCodepoint::Ect0),
            contents: &first_payload,
            segment_size: None,
            src_ip: first_source,
        };

        let error = masked
            .try_send(&first)
            .expect_err("second fragment should block once");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        let second_payload = b"short-header";
        let second_destination: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let second_source = Some("198.51.100.20".parse().unwrap());
        masked
            .try_send(&udp::Transmit {
                destination: second_destination,
                ecn: Some(udp::EcnCodepoint::Ect1),
                contents: second_payload,
                segment_size: None,
                src_ip: second_source,
            })
            .expect(
                "new transmit should flush old fragments first, then send itself",
            );

        let sent = inner.sent.lock().unwrap();
        assert!(sent.len() >= 3);
        for fragment in &sent[..sent.len() - 1] {
            assert_eq!(fragment.destination, first_destination);
            assert_eq!(fragment.ecn, Some(udp::EcnCodepoint::Ect0));
            assert_eq!(fragment.src_ip, first_source);
        }
        let second = sent.last().unwrap();
        assert_eq!(second.destination, second_destination);
        assert_eq!(second.ecn, Some(udp::EcnCodepoint::Ect1));
        assert_eq!(second.src_ip, second_source);

        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        assert_eq!(
            obfuscator.deobfuscate(&second.contents).unwrap(),
            second_payload
        );
    }

    #[tokio::test]
    async fn gecko_udp_socket_reassembles_loopback_fragments() {
        let masked_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        masked_std.set_nonblocking(true).unwrap();
        let masked_addr = masked_std.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(masked_std).unwrap();
        let masked = Arc::new(
            GeckoUdpSocket::new(inner, b"password".to_vec(), 64, 96)
                .expect("valid gecko socket"),
        );
        let payload = vec![0x80_u8; 120];
        let mut poller = masked.clone().create_io_poller();
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        masked
            .try_send(&udp::Transmit {
                destination: peer_addr,
                ecn: None,
                contents: &payload,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        let mut wire_packets = Vec::new();
        let mut total_chunks = None;
        while total_chunks.is_none_or(|total| wire_packets.len() < total) {
            let mut wire = [0_u8; 256];
            let (wire_len, source) = peer.recv_from(&mut wire).await.unwrap();
            assert_eq!(source, masked_addr);
            let clear = obfuscator.deobfuscate(&wire[..wire_len]).unwrap();
            let (header, _) = decode_gecko_frame(&clear).unwrap();
            total_chunks = Some(usize::from(header.total_chunks));
            wire_packets.push(wire[..wire_len].to_vec());
        }

        for packet in wire_packets.iter().rev() {
            peer.send_to(packet, masked_addr).await.unwrap();
        }
        let mut output = [0_u8; 256];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        let count = poll_fn(|cx| masked.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, payload.len());
        assert_eq!(meta[0].stride, payload.len());
        assert_eq!(&output[..payload.len()], payload);
    }

    #[tokio::test]
    async fn gecko_udp_socket_matches_xray_small_receive_buffer_copy() {
        let masked_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        masked_std.set_nonblocking(true).unwrap();
        let masked_addr = masked_std.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(masked_std).unwrap();
        let masked = Arc::new(
            GeckoUdpSocket::new(inner, b"password".to_vec(), 64, 96)
                .expect("valid gecko socket"),
        );
        let payload = vec![0x40_u8; 128];
        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        let wire = obfuscator.obfuscate(&payload);
        peer.send_to(&wire, masked_addr).await.unwrap();

        let mut output = [0_u8; 16];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        let count = poll_fn(|cx| masked.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, output.len());
        assert_eq!(meta[0].stride, output.len());
        assert_eq!(output, payload[..output.len()]);
    }

    #[test]
    fn salamander_matches_xray_blake2b_256_packet_format() {
        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        let packet =
            obfuscator.obfuscate_with_salt(b"hello quic", [0, 1, 2, 3, 4, 5, 6, 7]);

        assert_eq!(
            packet,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xd9, 0xe3, 0x5a,
                0x28, 0xe0, 0x0d, 0x28, 0x15, 0xc2, 0xaf,
            ]
        );
        assert_eq!(
            obfuscator.deobfuscate(&packet).as_deref(),
            Some(&b"hello quic"[..])
        );
    }

    #[test]
    fn gecko_fragment_frame_matches_xray_layout() {
        let header = GeckoFrameHeader {
            pad_len: 3,
            msg_id: 0x2a,
            chunk_idx: 1,
            total_chunks: 4,
        };
        let frame = encode_gecko_frame(header, b"chunk").expect("valid gecko frame");

        assert_eq!(frame[0], 0x80);
        assert_eq!(frame[1], 0x2a);
        assert_eq!(frame[2], 0x14);
        assert_eq!(&frame[3..5], &[0, 3]);
        assert_eq!(&frame[8..], b"chunk");

        let (decoded, payload) =
            decode_gecko_frame(&frame).expect("decode gecko frame");
        assert_eq!(decoded, header);
        assert_eq!(payload, b"chunk");
    }

    #[test]
    fn gecko_fragment_frame_rejects_xray_invalid_bounds() {
        for header in [
            GeckoFrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 0,
                total_chunks: 1,
            },
            GeckoFrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 0,
                total_chunks: 9,
            },
            GeckoFrameHeader {
                pad_len: 0,
                msg_id: 1,
                chunk_idx: 2,
                total_chunks: 2,
            },
        ] {
            assert!(encode_gecko_frame(header, b"x").is_err());
        }

        assert!(decode_gecko_frame(&[0x80, 1, 0x01, 0, 0]).is_err());
        assert!(decode_gecko_frame(&[0x80, 1, 0x22, 0, 0]).is_err());
        assert!(decode_gecko_frame(&[0x00, 1, 0x02, 0, 0]).is_err());
        assert!(decode_gecko_frame(&[0x80, 1, 0x02, 0, 1]).is_err());
        assert!(decode_gecko_frame(&[0x80, 1, 0x02, 0]).is_err());
    }

    #[test]
    fn gecko_packetizer_matches_xray_long_and_short_header_rules() {
        let packet_size = GeckoPacketSize::new(64, 96).unwrap();
        let long_header = [0x80_u8; 120];
        let fragments =
            gecko_fragment_packet(&long_header, 9, packet_size, 4).unwrap();
        assert_eq!(fragments.len(), 4);

        let mut rebuilt = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            let (header, payload) = decode_gecko_frame(fragment).unwrap();
            assert_eq!(header.msg_id, 9);
            assert_eq!(header.chunk_idx, index as u8);
            assert_eq!(header.total_chunks, 4);
            let wire_len = fragment.len() + SALAMANDER_SALT_LEN;
            assert!((packet_size.min..=packet_size.max).contains(&wire_len));
            rebuilt.extend_from_slice(payload);
        }
        assert_eq!(rebuilt, long_header);

        let short_header = b"\x40short-header";
        assert_eq!(
            gecko_fragment_packet(short_header, 10, packet_size, 4).unwrap(),
            vec![short_header.to_vec()]
        );
    }

    #[test]
    fn gecko_packet_size_matches_xray_defaults_and_bounds() {
        assert_eq!(
            GeckoPacketSize::new(0, 0).unwrap(),
            GeckoPacketSize {
                min: GECKO_DEFAULT_MIN_PACKET,
                max: GECKO_DEFAULT_MAX_PACKET,
            }
        );
        assert!(GeckoPacketSize::new(1200, 512).is_err());
        assert!(GeckoPacketSize::new(1, GECKO_BUFFER_SIZE + 1).is_err());
        assert!(
            gecko_fragment_packet(
                b"\x80long",
                1,
                GeckoPacketSize::new(64, 96).unwrap(),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn gecko_reassembly_matches_xray_chunk_rules() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut reassembly = GeckoReassembly::default();

        let second = GeckoFrameHeader {
            pad_len: 0,
            msg_id: 7,
            chunk_idx: 1,
            total_chunks: 3,
        };
        let first = GeckoFrameHeader {
            chunk_idx: 0,
            ..second
        };
        let third = GeckoFrameHeader {
            chunk_idx: 2,
            ..second
        };

        assert_eq!(reassembly.accept_chunk(addr, second, b"middle", now), None);
        assert_eq!(
            reassembly.accept_chunk(addr, second, b"duplicate", now),
            None
        );
        assert_eq!(reassembly.accept_chunk(addr, first, b"first-", now), None);
        assert_eq!(
            reassembly.accept_chunk(addr, third, b"-last", now),
            Some(b"first-middle-last".to_vec())
        );
        assert!(reassembly.entries.is_empty());
        assert!(reassembly.per_source.is_empty());
    }

    #[test]
    fn gecko_reassembly_enforces_xray_source_cap_and_ttl() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut reassembly = GeckoReassembly::default();
        for msg_id in 0..GECKO_MAX_PER_SOURCE as u8 {
            let header = GeckoFrameHeader {
                pad_len: 0,
                msg_id,
                chunk_idx: 0,
                total_chunks: 2,
            };
            assert_eq!(reassembly.accept_chunk(addr, header, b"half", now), None);
        }
        assert_eq!(reassembly.entries.len(), GECKO_MAX_PER_SOURCE);

        let blocked = GeckoFrameHeader {
            pad_len: 0,
            msg_id: GECKO_MAX_PER_SOURCE as u8,
            chunk_idx: 0,
            total_chunks: 2,
        };
        assert_eq!(reassembly.accept_chunk(addr, blocked, b"half", now), None);
        assert_eq!(reassembly.entries.len(), GECKO_MAX_PER_SOURCE);

        reassembly.gc_expired(now + GECKO_REASSEMBLY_TTL + Duration::from_millis(1));
        assert!(reassembly.entries.is_empty());
        assert!(reassembly.per_source.is_empty());
    }

    #[test]
    fn salamander_rejects_short_psk_and_packet() {
        assert!(SalamanderObfuscator::new(b"abc".to_vec()).is_err());

        let obfuscator = SalamanderObfuscator::new(b"abcd".to_vec()).unwrap();
        assert_eq!(
            obfuscator.deobfuscate(&[0; SALAMANDER_SALT_LEN]),
            Some(Vec::new())
        );
        assert_eq!(obfuscator.deobfuscate(&[0; SALAMANDER_SALT_LEN - 1]), None);
    }

    #[tokio::test]
    async fn salamander_udp_socket_round_trips_single_datagrams() {
        let masked_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        masked_std.set_nonblocking(true).unwrap();
        let masked_addr = masked_std.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(masked_std).unwrap();
        let masked =
            Arc::new(SalamanderUdpSocket::new(inner, b"password".to_vec()).unwrap());

        let payload = b"quinn salamander packet";
        let mut poller = masked.clone().create_io_poller();
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        masked
            .try_send(&udp::Transmit {
                destination: peer_addr,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        let mut wire = [0_u8; 128];
        let (wire_len, source) = peer.recv_from(&mut wire).await.unwrap();
        assert_eq!(source, masked_addr);
        assert_eq!(wire_len, payload.len() + SALAMANDER_SALT_LEN);
        assert_ne!(&wire[..wire_len], payload);

        peer.send_to(&wire[..wire_len], masked_addr).await.unwrap();

        let mut output = [0_u8; 128];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        let count = poll_fn(|cx| masked.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, payload.len());
        assert_eq!(meta[0].stride, payload.len());
        assert_eq!(&output[..meta[0].len], payload);
        assert_eq!(masked.max_transmit_segments(), 1);
        assert_eq!(masked.max_receive_segments(), 1);
    }

    #[test]
    fn salamander_udp_socket_matches_xray_finalmask_send_limit() {
        let destination: SocketAddr = "127.0.0.1:443".parse().unwrap();

        let oversized_inner = Arc::new(BlockingSendSocket::default());
        let oversized =
            SalamanderUdpSocket::new(oversized_inner.clone(), b"password".to_vec())
                .unwrap();
        let oversized_payload =
            vec![0x40_u8; XRAY_FINALMASK_UDP_SIZE - SALAMANDER_SALT_LEN + 1];
        oversized
            .try_send(&udp::Transmit {
                destination,
                ecn: None,
                contents: &oversized_payload,
                segment_size: None,
                src_ip: None,
            })
            .expect("Xray silently drops oversized header-mask UDP payloads");
        assert!(oversized_inner.sent.lock().unwrap().is_empty());

        let boundary_inner = Arc::new(BlockingSendSocket::default());
        let boundary =
            SalamanderUdpSocket::new(boundary_inner.clone(), b"password".to_vec())
                .unwrap();
        let boundary_payload =
            vec![0x40_u8; XRAY_FINALMASK_UDP_SIZE - SALAMANDER_SALT_LEN];
        boundary
            .try_send(&udp::Transmit {
                destination,
                ecn: None,
                contents: &boundary_payload,
                segment_size: None,
                src_ip: None,
            })
            .expect("4096-byte masked packet is still valid");
        let sent = boundary_inner.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].contents.len(), XRAY_FINALMASK_UDP_SIZE);
    }

    #[tokio::test]
    async fn salamander_udp_socket_matches_xray_small_receive_buffer_copy() {
        let masked_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        masked_std.set_nonblocking(true).unwrap();
        let masked_addr = masked_std.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(masked_std).unwrap();
        let masked =
            Arc::new(SalamanderUdpSocket::new(inner, b"password".to_vec()).unwrap());
        let payload = vec![0x40_u8; 128];
        let obfuscator = SalamanderObfuscator::new(b"password".to_vec()).unwrap();
        let wire = obfuscator.obfuscate(&payload);
        peer.send_to(&wire, masked_addr).await.unwrap();

        let mut output = [0_u8; 16];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        let count = poll_fn(|cx| masked.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, output.len());
        assert_eq!(meta[0].stride, output.len());
        assert_eq!(output, payload[..output.len()]);
    }
}
