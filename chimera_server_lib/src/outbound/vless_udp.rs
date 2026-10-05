use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{address::NetLocation, async_stream::AsyncStream};

// Xray v26.9.9's MultiLengthPacketWriter skips empty payloads and packets
// whose payload plus the two-byte frame header exceeds common/buf.Size (8192).
const XRAY_VLESS_UDP_MAX_WRITE_LENGTH: usize = 8 * 1024 - 2;

pub(crate) struct VlessUdpOutboundStream {
    stream: Box<dyn AsyncStream>,
    target: NetLocation,
}

impl VlessUdpOutboundStream {
    pub(crate) fn new(stream: Box<dyn AsyncStream>, target: NetLocation) -> Self {
        Self { stream, target }
    }

    pub(crate) async fn send_to(
        &mut self,
        target: &NetLocation,
        payload: &[u8],
    ) -> std::io::Result<()> {
        if target != &self.target {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VLESS UDP session cannot change its target",
            ));
        }
        if payload.is_empty() {
            return Ok(());
        }
        if payload.len() > XRAY_VLESS_UDP_MAX_WRITE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "VLESS UDP payload exceeds Xray packet writer limit {XRAY_VLESS_UDP_MAX_WRITE_LENGTH}"
                ),
            ));
        }

        self.stream.write_u16(payload.len() as u16).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await
    }

    pub(crate) async fn recv_from(
        &mut self,
        buffer: &mut [u8],
    ) -> std::io::Result<(NetLocation, usize)> {
        loop {
            let payload_length = self.stream.read_u16().await? as usize;
            if payload_length == 0 {
                // Xray's packet writer never emits empty datagrams.
                continue;
            }
            if payload_length > buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "VLESS UDP payload exceeds receive buffer: {payload_length} > {}",
                        buffer.len()
                    ),
                ));
            }
            self.stream
                .read_exact(&mut buffer[..payload_length])
                .await?;
            return Ok((self.target.clone(), payload_length));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn vless_udp_outbound_frames_packets_without_a_response_header() {
        let target =
            NetLocation::from_str("192.0.2.8:53", None).expect("parse UDP target");
        let (client, mut server) = duplex(64);
        let mut stream =
            VlessUdpOutboundStream::new(Box::new(client), target.clone());

        stream
            .send_to(&target, b"query")
            .await
            .expect("write VLESS UDP packet");
        let length = server.read_u16().await.expect("read VLESS UDP length");
        assert_eq!(length, 5);
        let mut payload = [0u8; 5];
        server
            .read_exact(&mut payload)
            .await
            .expect("read VLESS UDP payload");
        assert_eq!(&payload, b"query");

        server
            .write_all(&[0, 4, b'p', b'o', b'n', b'g'])
            .await
            .expect("write VLESS UDP response");
        let mut response = [0u8; 16];
        let (source, length) = stream
            .recv_from(&mut response)
            .await
            .expect("read VLESS UDP response");
        assert_eq!(source, target);
        assert_eq!(&response[..length], b"pong");
    }

    #[tokio::test]
    async fn vless_udp_outbound_drops_empty_packets_and_rejects_oversized_packets() {
        let target =
            NetLocation::from_str("192.0.2.8:53", None).expect("parse UDP target");
        let (client, mut server) = duplex(16 * 1024);
        let mut stream =
            VlessUdpOutboundStream::new(Box::new(client), target.clone());

        let max_payload = vec![0x5a; XRAY_VLESS_UDP_MAX_WRITE_LENGTH];
        stream
            .send_to(&target, &max_payload)
            .await
            .expect("write maximum Xray VLESS UDP packet");
        assert_eq!(
            server.read_u16().await.expect("read maximum packet length") as usize,
            XRAY_VLESS_UDP_MAX_WRITE_LENGTH
        );
        let mut received = vec![0; XRAY_VLESS_UDP_MAX_WRITE_LENGTH];
        server
            .read_exact(&mut received)
            .await
            .expect("read maximum packet payload");
        assert_eq!(received, max_payload);

        stream
            .send_to(&target, &[])
            .await
            .expect("drop empty VLESS UDP packet");
        stream
            .send_to(&target, b"x")
            .await
            .expect("write packet after empty packet");
        assert_eq!(server.read_u16().await.expect("read packet length"), 1);
        assert_eq!(server.read_u8().await.expect("read packet payload"), b'x');

        let oversized = vec![0u8; XRAY_VLESS_UDP_MAX_WRITE_LENGTH + 1];
        let error = stream
            .send_to(&target, &oversized)
            .await
            .expect_err("reject packet above Xray's writer limit");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn vless_udp_outbound_rejects_truncated_response_payload() {
        let target =
            NetLocation::from_str("192.0.2.8:53", None).expect("parse UDP target");
        let (client, mut server) = duplex(16);
        let mut stream = VlessUdpOutboundStream::new(Box::new(client), target);
        server
            .write_all(&[0, 5, b'a', b'b'])
            .await
            .expect("write truncated VLESS UDP frame");
        server
            .shutdown()
            .await
            .expect("close truncated VLESS UDP frame");

        let error = stream
            .recv_from(&mut [0u8; 8])
            .await
            .expect_err("reject truncated VLESS UDP packet");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn vless_udp_outbound_rejects_a_changed_target() {
        let target =
            NetLocation::from_str("192.0.2.8:53", None).expect("parse UDP target");
        let changed = NetLocation::from_str("192.0.2.9:53", None)
            .expect("parse changed UDP target");
        let (client, _server) = duplex(16);
        let mut stream = VlessUdpOutboundStream::new(Box::new(client), target);

        let error = stream
            .send_to(&changed, b"query")
            .await
            .expect_err("reject target change in a fixed-target session");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
