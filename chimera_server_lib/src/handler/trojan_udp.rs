use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, WriteHalf, split},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{
    address::{Address, NetLocation},
    async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage,
        AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream,
        AsyncWriteSourcedMessage,
    },
};

const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;
const MAX_PACKET_LENGTH: usize = 8192;
const CRLF: [u8; 2] = [0x0d, 0x0a];

type PacketResult = std::io::Result<(NetLocation, Vec<u8>)>;

pub(crate) struct TrojanUdpStream {
    receiver: mpsc::Receiver<PacketResult>,
    writer: WriteHalf<Box<dyn AsyncStream>>,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
    reader_task: JoinHandle<()>,
}

impl std::fmt::Debug for TrojanUdpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrojanUdpStream")
            .field("pending_write_len", &self.pending_write.len())
            .field("pending_write_offset", &self.pending_write_offset)
            .finish_non_exhaustive()
    }
}

impl TrojanUdpStream {
    pub(crate) fn new(stream: Box<dyn AsyncStream>) -> Self {
        let (mut reader, writer) = split(stream);
        let (sender, receiver) = mpsc::channel(16);
        let reader_task = tokio::spawn(async move {
            loop {
                let packet = read_packet(&mut reader).await;
                let is_terminal = packet.is_err();
                if sender.send(packet).await.is_err() || is_terminal {
                    break;
                }
            }
        });

        Self {
            receiver,
            writer,
            pending_write: Vec::new(),
            pending_write_offset: 0,
            reader_task,
        }
    }
}

impl Drop for TrojanUdpStream {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl AsyncReadTargetedMessage for TrojanUdpStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some(Ok((target, payload)))) => {
                if payload.len() > buffer.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "trojan udp payload exceeds receive buffer: {} > {}",
                            payload.len(),
                            buffer.remaining()
                        ),
                    )));
                }
                buffer.put_slice(&payload);
                Poll::Ready(Ok(target))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "trojan udp stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteSourcedMessage for TrojanUdpStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_write.is_empty() {
            this.pending_write = encode_packet(source, payload)?;
            this.pending_write_offset = 0;
        }

        while this.pending_write_offset < this.pending_write.len() {
            match Pin::new(&mut this.writer)
                .poll_write(cx, &this.pending_write[this.pending_write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "trojan udp stream closed while writing packet",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    this.pending_write_offset += written;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.pending_write.clear();
        this.pending_write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for TrojanUdpStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for TrojanUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl AsyncPing for TrojanUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncTargetedMessageStream for TrojanUdpStream {}

pub(crate) async fn read_packet<R>(reader: &mut R) -> PacketResult
where
    R: AsyncRead + Unpin + ?Sized,
{
    let target = read_location(reader).await?;
    let payload_length = reader.read_u16().await? as usize;
    if payload_length > MAX_PACKET_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("trojan udp payload exceeds {MAX_PACKET_LENGTH} bytes"),
        ));
    }

    let mut suffix = [0u8; 2];
    reader.read_exact(&mut suffix).await?;
    if suffix != CRLF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid trojan udp packet suffix",
        ));
    }

    let mut payload = vec![0u8; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok((target, payload))
}

async fn read_location<R>(reader: &mut R) -> std::io::Result<NetLocation>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let address = match reader.read_u8().await? {
        ADDR_TYPE_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        ADDR_TYPE_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "trojan udp domain is empty",
                ));
            }
            let mut domain = vec![0u8; length];
            reader.read_exact(&mut domain).await?;
            let domain = std::str::from_utf8(&domain).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid trojan udp domain: {error}"),
                )
            })?;
            Address::from(domain)?
        }
        address_type => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown trojan udp address type: {address_type}"),
            ));
        }
    };
    let port = reader.read_u16().await?;
    Ok(NetLocation::new(address, port))
}

fn encode_packet(source: &SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    encode_packet_location(
        &NetLocation::from_ip_addr(source.ip(), source.port()),
        payload,
    )
}

pub(crate) fn encode_packet_location(
    location: &NetLocation,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    if payload.len() > MAX_PACKET_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("trojan udp payload exceeds {MAX_PACKET_LENGTH} bytes"),
        ));
    }

    let mut packet = Vec::with_capacity(1 + 16 + 2 + 2 + 2 + payload.len());
    match location.address() {
        Address::Ipv4(address) => {
            packet.push(ADDR_TYPE_IPV4);
            packet.extend_from_slice(&address.octets());
        }
        Address::Ipv6(address) => {
            packet.push(ADDR_TYPE_IPV6);
            packet.extend_from_slice(&address.octets());
        }
        Address::Hostname(domain) => {
            let bytes = domain.as_bytes();
            let length = u8::try_from(bytes.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "trojan udp domain exceeds 255 bytes",
                )
            })?;
            if length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "trojan udp domain is empty",
                ));
            }
            packet.push(ADDR_TYPE_DOMAIN_NAME);
            packet.push(length);
            packet.extend_from_slice(bytes);
        }
    }
    packet.extend_from_slice(&location.port().to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&CRLF);
    packet.extend_from_slice(payload);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, io::Cursor};

    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn packet_location_roundtrips_domain_target() {
        let location =
            NetLocation::new(Address::Hostname("dns.example".into()), 5353);
        let encoded = encode_packet_location(&location, b"domain payload").unwrap();
        let mut input = Cursor::new(encoded);
        let (decoded_location, payload) = read_packet(&mut input).await.unwrap();
        assert_eq!(decoded_location, location);
        assert_eq!(payload, b"domain payload");
    }

    #[tokio::test]
    async fn read_packet_rejects_invalid_crlf() {
        let (mut client, mut server) = duplex(64);
        client
            .write_all(&[
                ADDR_TYPE_IPV4,
                127,
                0,
                0,
                1,
                0,
                53,
                0,
                1,
                b'\n',
                b'\n',
                b'x',
            ])
            .await
            .expect("write malformed Trojan UDP packet");

        let error = read_packet(&mut server)
            .await
            .expect_err("invalid CRLF must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("packet suffix"));
    }

    #[tokio::test]
    async fn read_packet_truncated_at_each_prefix_returns_unexpected_eof() {
        let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 53));
        let packet = encode_packet(&source, b"payload")
            .expect("encode Trojan UDP truncation fixture");

        for prefix_length in 0..packet.len() {
            let mut input = Cursor::new(packet[..prefix_length].to_vec());
            let error = read_packet(&mut input)
                .await
                .expect_err("truncated Trojan UDP packet must fail");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "prefix length {prefix_length}"
            );
        }
    }

    #[tokio::test]
    async fn read_packet_roundtrips_consecutive_ipv4_and_ipv6_packets() {
        let ipv4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        let mut encoded =
            encode_packet(&ipv4, b"first").expect("encode first Trojan UDP packet");
        encoded.extend_from_slice(
            &encode_packet(&ipv6, b"second")
                .expect("encode second Trojan UDP packet"),
        );
        let mut input = Cursor::new(encoded);

        let (first_target, first_payload) = read_packet(&mut input)
            .await
            .expect("read first Trojan UDP packet");
        let (second_target, second_payload) = read_packet(&mut input)
            .await
            .expect("read second Trojan UDP packet");

        assert_eq!(
            first_target,
            NetLocation::from_ip_addr(ipv4.ip(), ipv4.port())
        );
        assert_eq!(first_payload, b"first");
        assert_eq!(
            second_target,
            NetLocation::from_ip_addr(ipv6.ip(), ipv6.port())
        );
        assert_eq!(second_payload, b"second");
    }

    #[tokio::test]
    async fn zero_and_maximum_payload_lengths_roundtrip() {
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        for payload in [Vec::new(), vec![0x5a; MAX_PACKET_LENGTH]] {
            let packet = encode_packet(&source, &payload)
                .expect("encode bounded Trojan UDP payload");
            let mut input = Cursor::new(packet);
            let (target, decoded_payload) = read_packet(&mut input)
                .await
                .expect("read bounded Trojan UDP payload");
            assert_eq!(
                target,
                NetLocation::from_ip_addr(source.ip(), source.port())
            );
            assert_eq!(decoded_payload, payload);
        }
    }

    #[tokio::test]
    async fn read_packet_rejects_invalid_domain_and_address_type() {
        for (description, packet) in [
            ("empty domain", vec![ADDR_TYPE_DOMAIN_NAME, 0]),
            ("invalid UTF-8 domain", vec![ADDR_TYPE_DOMAIN_NAME, 1, 0xff]),
            ("unknown address type", vec![0xff]),
        ] {
            let mut input = Cursor::new(packet);
            let error = read_packet(&mut input)
                .await
                .expect_err("invalid Trojan UDP address must fail");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidData,
                "{description}"
            );
        }
    }

    #[tokio::test]
    async fn read_packet_rejects_oversized_declared_payload_before_body() {
        let mut packet = vec![ADDR_TYPE_IPV4, 127, 0, 0, 1, 0, 53];
        packet.extend_from_slice(&((MAX_PACKET_LENGTH + 1) as u16).to_be_bytes());
        let mut input = Cursor::new(packet);

        let error = read_packet(&mut input)
            .await
            .expect_err("oversized declared Trojan UDP payload must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("8192"));
    }

    #[tokio::test]
    async fn stream_rejects_payload_larger_than_caller_buffer() {
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let packet = encode_packet(&source, b"too-large")
            .expect("encode Trojan UDP caller-buffer fixture");
        let (mut client, server) = duplex(128);
        client
            .write_all(&packet)
            .await
            .expect("write Trojan UDP caller-buffer fixture");
        let mut stream = TrojanUdpStream::new(Box::new(TestStream(server)));
        let mut output = [0u8; 4];

        let error = poll_fn(|cx| {
            let mut buffer = ReadBuf::new(&mut output);
            Pin::new(&mut stream).poll_read_targeted_message(cx, &mut buffer)
        })
        .await
        .expect_err("Trojan UDP payload larger than caller buffer must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds receive buffer"));
        assert_eq!(output, [0; 4]);
    }

    struct TestStream(tokio::io::DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[tokio::test]
    async fn partial_writes_do_not_duplicate_packet_bytes() {
        let source_a = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
        let source_b = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        let expected_a = encode_packet(&source_a, b"first")
            .expect("encode first partial-write Trojan UDP packet");
        let expected_b = encode_packet(&source_b, b"second")
            .expect("encode second partial-write Trojan UDP packet");
        let (mut client, server) = duplex(1);
        let writer_task = tokio::spawn(async move {
            let mut stream = TrojanUdpStream::new(Box::new(TestStream(server)));
            for (payload, source) in [
                (b"first".as_slice(), source_a),
                (b"second".as_slice(), source_b),
            ] {
                poll_fn(|cx| {
                    Pin::new(&mut stream)
                        .poll_write_sourced_message(cx, payload, &source)
                })
                .await
                .expect("write Trojan UDP packet through one-byte transport");
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .expect("shutdown Trojan UDP partial writer");
        });

        let mut actual = Vec::new();
        client
            .read_to_end(&mut actual)
            .await
            .expect("read partial-write Trojan UDP packets");
        writer_task.await.expect("Trojan UDP partial writer task");

        let expected = [expected_a, expected_b].concat();
        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_packet_rejects_oversized_payload() {
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let error = encode_packet(&source, &vec![0u8; MAX_PACKET_LENGTH + 1])
            .expect_err("oversized Trojan UDP payload must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("8192"));
    }
}
