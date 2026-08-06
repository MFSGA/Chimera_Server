use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream, RawTcpRelayState},
    handler::xudp::frame::{
        FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
    },
};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;
const VLESS_COMMAND_MUX: u8 = 3;

pub(crate) fn encode_vless_tcp_request(
    user_uuid: &[u8; 16],
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    encode_vless_request(user_uuid, VLESS_COMMAND_TCP, target)
}

pub(crate) fn encode_vless_udp_request(
    user_uuid: &[u8; 16],
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    encode_vless_request(user_uuid, VLESS_COMMAND_UDP, target)
}

pub(crate) fn encode_vless_xudp_request(
    user_uuid: &[u8; 16],
) -> std::io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(19);
    request.push(VLESS_VERSION);
    request.extend_from_slice(user_uuid);
    request.push(0); // addon length
    request.push(VLESS_COMMAND_MUX);
    Ok(request)
}

pub(crate) fn encode_vless_xudp_packet(
    target: &NetLocation,
    payload: &[u8],
    first: bool,
) -> std::io::Result<Vec<u8>> {
    let payload_length = u16::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "XUDP payload exceeds 65535 bytes",
        )
    })?;
    if payload_length == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "XUDP payload must not be empty",
        ));
    }
    let metadata = FrameMetadata {
        session_id: 0,
        status: if first {
            SessionStatus::New
        } else {
            SessionStatus::Keep
        },
        option: FrameOption::default().with_data(),
        target: first.then(|| target.clone()),
        network: first.then_some(TargetNetwork::Udp),
        global_id: first.then_some([0u8; 8]),
    };
    let mut packet = BytesMut::with_capacity(32 + payload.len());
    metadata.encode(&mut packet)?;
    packet.put_u16(payload_length);
    packet.extend_from_slice(payload);
    Ok(packet.to_vec())
}

pub(crate) fn encode_vless_udp_packet(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS UDP payload exceeds 65535 bytes",
        )
    })?;
    if length == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS UDP payload must not be empty",
        ));
    }
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_vless_request(
    user_uuid: &[u8; 16],
    command: u8,
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(40);
    request.push(VLESS_VERSION);
    request.extend_from_slice(user_uuid);
    request.push(0); // addon length
    request.push(command);
    request.extend_from_slice(&target.port().to_be_bytes());

    match target.address() {
        Address::Ipv4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            let hostname = hostname.as_bytes();
            let hostname_length = u8::try_from(hostname.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS target domain exceeds 255 bytes",
                )
            })?;
            if hostname_length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS target domain must not be empty",
                ));
            }
            request.push(2);
            request.push(hostname_length);
            request.extend_from_slice(hostname);
        }
        Address::Ipv6(address) => {
            request.push(3);
            request.extend_from_slice(&address.octets());
        }
    }

    Ok(request)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    Prefix,
    Addons { remaining: usize },
    Ready,
}

pub(crate) struct VlessTcpOutboundStream {
    inner: Box<dyn AsyncStream>,
    state: ResponseState,
    prefix: [u8; 2],
    prefix_offset: usize,
}

impl VlessTcpOutboundStream {
    pub(crate) fn new(inner: Box<dyn AsyncStream>) -> Self {
        Self {
            inner,
            state: ResponseState::Prefix,
            prefix: [0; 2],
            prefix_offset: 0,
        }
    }

    fn poll_consume_response_header(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.state {
                ResponseState::Prefix => {
                    let mut read_buf =
                        ReadBuf::new(&mut self.prefix[self.prefix_offset..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "VLESS server closed before response header",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            self.prefix_offset += read_buf.filled().len();
                            if self.prefix_offset < self.prefix.len() {
                                continue;
                            }
                            if self.prefix[0] != VLESS_VERSION {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "invalid VLESS server response version {}, expected {}",
                                        self.prefix[0], VLESS_VERSION
                                    ),
                                )));
                            }
                            self.state = ResponseState::Addons {
                                remaining: usize::from(self.prefix[1]),
                            };
                        }
                    }
                }
                ResponseState::Addons { remaining: 0 } => {
                    self.state = ResponseState::Ready;
                }
                ResponseState::Addons { remaining } => {
                    let mut discard = [0u8; 256];
                    let read_length = remaining.min(discard.len());
                    let mut read_buf = ReadBuf::new(&mut discard[..read_length]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "VLESS server closed inside response addons",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            self.state = ResponseState::Addons {
                                remaining: remaining - read_buf.filled().len(),
                            };
                        }
                    }
                }
                ResponseState::Ready => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncPing for VlessTcpOutboundStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}

impl AsyncRead for VlessTcpOutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_consume_response_header(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VlessTcpOutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncStream for VlessTcpOutboundStream {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        RawTcpRelayState::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
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

    #[test]
    fn request_encoding_preserves_ipv4_domain_and_ipv6_targets() {
        let uuid = [7u8; 16];
        let ipv4 = encode_vless_tcp_request(
            &uuid,
            &NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443),
        )
        .expect("IPv4 request should encode");
        assert_eq!(
            &ipv4[..19],
            &[0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 1]
        );
        assert_eq!(&ipv4[19..], &[1, 187, 1, 192, 0, 2, 1]);

        let domain = encode_vless_tcp_request(
            &uuid,
            &NetLocation::new(Address::Hostname("example.com".into()), 80),
        )
        .expect("domain request should encode");
        assert_eq!(&domain[19..23], &[0, 80, 2, 11]);
        assert_eq!(&domain[23..], b"example.com");

        let ipv6 = encode_vless_tcp_request(
            &uuid,
            &NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
        )
        .expect("IPv6 request should encode");
        assert_eq!(&ipv6[19..22], &[32, 251, 3]);
        assert_eq!(&ipv6[22..], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn udp_request_and_packet_encoding_use_vless_udp_framing() {
        let uuid = [9u8; 16];
        let target = NetLocation::new(Address::Hostname("dns.example".into()), 53);
        let request = encode_vless_udp_request(&uuid, &target)
            .expect("UDP request should encode");
        assert_eq!(
            &request[..17],
            &[0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
        );
        assert_eq!(request[17], 0);
        assert_eq!(request[18], VLESS_COMMAND_UDP);
        assert_eq!(&request[19..23], &[0, 53, 2, 11]);
        assert_eq!(&request[23..], b"dns.example");

        let packet =
            encode_vless_udp_packet(b"query").expect("UDP packet should encode");
        assert_eq!(&packet[..2], &[0, 5]);
        assert_eq!(&packet[2..], b"query");
    }

    #[test]
    fn udp_packet_encoding_rejects_empty_and_oversized_payloads() {
        let empty =
            encode_vless_udp_packet(&[]).expect_err("empty UDP payload must fail");
        assert_eq!(empty.kind(), std::io::ErrorKind::InvalidInput);

        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        let error = encode_vless_udp_packet(&oversized)
            .expect_err("oversized UDP payload must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn response_header_is_consumed_lazily_and_payload_is_preserved() {
        let (mut peer, client) = duplex(128);
        let mut stream = VlessTcpOutboundStream::new(Box::new(TestStream(client)));
        stream
            .write_all(b"request")
            .await
            .expect("writes must not wait for the response header");
        let mut request = [0u8; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        peer.write_all(&[0, 3, 1]).await.unwrap();
        peer.write_all(&[2, 3, b'p', b'o', b'n', b'g'])
            .await
            .unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    }

    #[tokio::test]
    async fn invalid_response_version_fails_closed() {
        let (mut peer, client) = duplex(32);
        let mut stream = VlessTcpOutboundStream::new(Box::new(TestStream(client)));
        peer.write_all(&[1, 0]).await.unwrap();
        let error = stream
            .read_u8()
            .await
            .expect_err("invalid response version must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
