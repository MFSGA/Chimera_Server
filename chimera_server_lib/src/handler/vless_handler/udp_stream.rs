use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage,
    AsyncShutdownMessage, AsyncStream, AsyncWriteMessage,
};

const RESPONSE_HEADER: [u8; 2] = [0, 0];
const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub(crate) struct VlessUdpStream {
    stream: Box<dyn AsyncStream>,
    read_length: [u8; 2],
    read_length_offset: usize,
    read_payload: Vec<u8>,
    read_payload_offset: usize,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
    response_header_pending: bool,
}

impl std::fmt::Debug for VlessUdpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VlessUdpStream")
            .field("read_length_offset", &self.read_length_offset)
            .field("read_payload_len", &self.read_payload.len())
            .field("read_payload_offset", &self.read_payload_offset)
            .field("pending_write_len", &self.pending_write.len())
            .field("pending_write_offset", &self.pending_write_offset)
            .field("response_header_pending", &self.response_header_pending)
            .finish()
    }
}

impl VlessUdpStream {
    pub(crate) fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            read_length: [0; 2],
            read_length_offset: 0,
            read_payload: Vec::new(),
            read_payload_offset: 0,
            pending_write: Vec::new(),
            pending_write_offset: 0,
            response_header_pending: true,
        }
    }

    fn poll_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.pending_write_offset < self.pending_write.len() {
            match Pin::new(&mut self.stream)
                .poll_write(cx, &self.pending_write[self.pending_write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "VLESS UDP stream closed while writing packet",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_write_offset += written;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.pending_write.clear();
        self.pending_write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for VlessUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.read_payload.is_empty() {
                while this.read_length_offset < this.read_length.len() {
                    let mut read_buffer = ReadBuf::new(
                        &mut this.read_length[this.read_length_offset..],
                    );
                    match Pin::new(&mut this.stream).poll_read(cx, &mut read_buffer)
                    {
                        Poll::Ready(Ok(())) => {
                            let read = read_buffer.filled().len();
                            if read == 0 {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "VLESS UDP stream closed while reading packet length",
                                )));
                            }
                            this.read_length_offset += read;
                        }
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(error));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let payload_length = u16::from_be_bytes(this.read_length) as usize;
                this.read_length_offset = 0;
                if payload_length == 0 {
                    continue;
                }
                this.read_payload.resize(payload_length, 0);
                this.read_payload_offset = 0;
            }

            while this.read_payload_offset < this.read_payload.len() {
                let mut read_buffer =
                    ReadBuf::new(&mut this.read_payload[this.read_payload_offset..]);
                match Pin::new(&mut this.stream).poll_read(cx, &mut read_buffer) {
                    Poll::Ready(Ok(())) => {
                        let read = read_buffer.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "VLESS UDP stream closed while reading packet payload",
                            )));
                        }
                        this.read_payload_offset += read;
                    }
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.read_payload.len() > buffer.remaining() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "VLESS UDP payload exceeds receive buffer: {} > {}",
                        this.read_payload.len(),
                        buffer.remaining()
                    ),
                )));
            }

            buffer.put_slice(&this.read_payload);
            this.read_payload.clear();
            this.read_payload_offset = 0;
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWriteMessage for VlessUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.pending_write.is_empty() {
            if payload.len() > MAX_PACKET_LENGTH {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("VLESS UDP payload exceeds {MAX_PACKET_LENGTH} bytes"),
                )));
            }

            let response_header_length = if this.response_header_pending {
                RESPONSE_HEADER.len()
            } else {
                0
            };
            this.pending_write
                .reserve(response_header_length + 2 + payload.len());
            if this.response_header_pending {
                this.pending_write.extend_from_slice(&RESPONSE_HEADER);
                this.response_header_pending = false;
            }
            this.pending_write
                .extend_from_slice(&(payload.len() as u16).to_be_bytes());
            this.pending_write.extend_from_slice(payload);
            this.pending_write_offset = 0;
        }

        this.poll_pending_write(cx)
    }
}

impl AsyncFlushMessage for VlessUdpStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for VlessUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncPing for VlessUdpStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for VlessUdpStream {}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::{
        io::{
            AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream,
            ReadBuf, duplex,
        },
        time::{Duration, timeout},
    };

    use super::*;

    struct TestStream(DuplexStream);

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

    async fn read_message(
        stream: &mut VlessUdpStream,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(buffer);
            match Pin::new(&mut *stream).poll_read_message(cx, &mut read_buffer) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    #[tokio::test]
    async fn reads_length_prefixed_datagrams() {
        let (mut client, server) = duplex(128);
        client
            .write_all(&[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o'])
            .await
            .expect("write VLESS UDP packets");
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
        let mut buffer = [0u8; 16];

        let first = read_message(&mut stream, &mut buffer)
            .await
            .expect("read first packet");
        assert_eq!(&buffer[..first], b"one");
        let second = read_message(&mut stream, &mut buffer)
            .await
            .expect("read second packet");
        assert_eq!(&buffer[..second], b"two");
    }

    #[tokio::test]
    async fn skips_empty_frames() {
        let (mut client, server) = duplex(128);
        client
            .write_all(&[0, 0, 0, 3, b'o', b'n', b'e'])
            .await
            .expect("write VLESS UDP packets");
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
        let mut buffer = [0u8; 16];

        let length = read_message(&mut stream, &mut buffer)
            .await
            .expect("read non-empty packet");
        assert_eq!(&buffer[..length], b"one");
    }

    #[tokio::test]
    async fn truncated_frame_prefixes_return_unexpected_eof() {
        let frame = [0, 3, b'o', b'n', b'e'];

        for prefix_length in 0..frame.len() {
            let (mut client, server) = duplex(128);
            client
                .write_all(&frame[..prefix_length])
                .await
                .expect("write truncated VLESS UDP frame prefix");
            client
                .shutdown()
                .await
                .expect("close truncated VLESS UDP writer");
            let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
            let mut buffer = [0u8; 16];

            let error = read_message(&mut stream, &mut buffer)
                .await
                .expect_err("truncated VLESS UDP frame must fail");

            assert_eq!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "prefix length {prefix_length}"
            );
        }
    }

    #[tokio::test]
    async fn maximum_datagram_roundtrips() {
        let payload = vec![0x5a; MAX_PACKET_LENGTH];
        let (mut client, server) = duplex(MAX_PACKET_LENGTH + 4);
        client
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await
            .expect("write maximum VLESS UDP length");
        client
            .write_all(&payload)
            .await
            .expect("write maximum VLESS UDP payload");
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
        let mut buffer = vec![0u8; MAX_PACKET_LENGTH];

        let length = read_message(&mut stream, &mut buffer)
            .await
            .expect("read maximum VLESS UDP datagram");

        assert_eq!(length, MAX_PACKET_LENGTH);
        assert_eq!(buffer, payload);
    }

    #[tokio::test]
    async fn small_caller_buffer_preserves_datagram_for_retry() {
        let (mut client, server) = duplex(128);
        client
            .write_all(&[0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd'])
            .await
            .expect("write VLESS UDP caller-buffer fixture");
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
        let mut small = [0u8; 4];

        let error = read_message(&mut stream, &mut small)
            .await
            .expect_err("small VLESS UDP caller buffer must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds receive buffer"));
        assert_eq!(small, [0; 4]);

        let mut large = [0u8; 16];
        let length = read_message(&mut stream, &mut large)
            .await
            .expect("retry VLESS UDP datagram with a large buffer");
        assert_eq!(&large[..length], b"payload");
    }

    #[tokio::test]
    async fn writes_response_header_only_once() {
        let (mut client, server) = duplex(128);
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));

        for payload in [b"one".as_slice(), b"two".as_slice()] {
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                .await
                .expect("write VLESS UDP response datagram");
        }
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .expect("flush VLESS UDP response datagrams");

        let mut encoded = [0u8; 12];
        client
            .read_exact(&mut encoded)
            .await
            .expect("read two encoded VLESS UDP responses");
        assert_eq!(
            &encoded,
            &[0, 0, 0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o']
        );
    }

    #[tokio::test]
    async fn partial_writes_do_not_duplicate_response_header_or_datagrams() {
        let (mut client, server) = duplex(1);
        let writer_task = tokio::spawn(async move {
            let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
            for payload in [b"one".as_slice(), b"two".as_slice()] {
                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                    .await
                    .expect("write VLESS UDP datagram through one-byte transport");
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .expect("shutdown VLESS UDP partial writer");
        });

        let mut actual = Vec::new();
        client
            .read_to_end(&mut actual)
            .await
            .expect("read partial-write VLESS UDP frames");
        writer_task.await.expect("VLESS UDP partial writer task");

        assert_eq!(
            actual,
            [0, 0, 0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o']
        );
    }

    #[tokio::test]
    async fn oversized_write_is_rejected_without_emitting_response_header() {
        let (mut client, server) = duplex(128);
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));
        let payload = vec![0u8; MAX_PACKET_LENGTH + 1];

        let error =
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
                .await
                .expect_err("oversized VLESS UDP response must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("65535"));
        assert!(
            timeout(Duration::from_millis(20), client.read_u8())
                .await
                .is_err(),
            "oversized VLESS UDP response must not emit the response header"
        );
    }

    #[tokio::test]
    async fn writes_response_header_before_first_datagram() {
        let (mut client, server) = duplex(128);
        let mut stream = VlessUdpStream::new(Box::new(TestStream(server)));

        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"pong"))
            .await
            .expect("write VLESS UDP packet");
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .expect("flush VLESS UDP packet");

        let mut encoded = [0u8; 8];
        client
            .read_exact(&mut encoded)
            .await
            .expect("read encoded VLESS UDP packet");
        assert_eq!(&encoded, &[0, 0, 0, 4, b'p', b'o', b'n', b'g']);
    }
}
