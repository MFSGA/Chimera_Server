use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

const V1_PREFIX: &[u8] = b"PROXY ";
const V1_MAX_HEADER_BYTES: usize = 108;
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V2_FIXED_HEADER_BYTES: usize = 16;
const V2_MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Debug)]
pub struct ProxyProtocolServerHandler {
    inner: Box<dyn TcpServerHandler>,
}

impl ProxyProtocolServerHandler {
    pub fn new(inner: Box<dyn TcpServerHandler>) -> Self {
        Self { inner }
    }

    async fn setup(
        &self,
        mut stream: Box<dyn AsyncStream>,
        context: Option<TcpServerConnectionContext>,
    ) -> io::Result<TcpServerSetupResult> {
        let client_addr = read_proxy_header(&mut stream).await?;
        let mut result = match context {
            Some(context) => {
                self.inner
                    .setup_server_stream_with_context(stream, context)
                    .await?
            }
            None => self.inner.setup_server_stream(stream).await?,
        };
        if let Some(client_addr) = client_addr {
            result.set_client_addr(client_addr);
        }
        Ok(result)
    }
}

#[async_trait]
impl TcpServerHandler for ProxyProtocolServerHandler {
    fn requires_original_destination(&self) -> bool {
        self.inner.requires_original_destination()
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup(server_stream, None).await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup(server_stream, Some(context)).await
    }
}

async fn read_proxy_header(
    stream: &mut Box<dyn AsyncStream>,
) -> io::Result<Option<SocketAddr>> {
    let mut prefix = [0u8; 12];
    stream.read_exact(&mut prefix).await?;
    if &prefix == V2_SIGNATURE {
        return read_v2_header(stream).await;
    }
    if prefix.starts_with(V1_PREFIX) {
        return read_v1_header(stream, prefix.to_vec()).await;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "PROXY protocol header is required",
    ))
}

async fn read_v1_header(
    stream: &mut Box<dyn AsyncStream>,
    mut header: Vec<u8>,
) -> io::Result<Option<SocketAddr>> {
    while !header.ends_with(b"\r\n") {
        if header.len() >= V1_MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PROXY protocol v1 header exceeds 108 bytes",
            ));
        }
        header.push(stream.read_u8().await?);
    }
    let line = std::str::from_utf8(&header[..header.len() - 2]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY protocol v1 header is not UTF-8",
        )
    })?;
    parse_v1_line(line)
}

fn parse_v1_line(line: &str) -> io::Result<Option<SocketAddr>> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.first().copied() != Some("PROXY") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PROXY protocol v1 signature",
        ));
    }
    if fields.get(1).copied() == Some("UNKNOWN") {
        return Ok(None);
    }
    if fields.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PROXY protocol v1 field count",
        ));
    }

    let source_ip = fields[2].parse::<IpAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PROXY protocol source address: {error}"),
        )
    })?;
    let destination_ip = fields[3].parse::<IpAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PROXY protocol destination address: {error}"),
        )
    })?;
    let source_port = parse_port(fields[4])?;
    let _destination_port = parse_port(fields[5])?;

    match (fields[1], source_ip, destination_ip) {
        ("TCP4", IpAddr::V4(source), IpAddr::V4(_)) => {
            Ok(Some(SocketAddr::new(IpAddr::V4(source), source_port)))
        }
        ("TCP6", IpAddr::V6(source), IpAddr::V6(_)) => {
            Ok(Some(SocketAddr::new(IpAddr::V6(source), source_port)))
        }
        ("TCP4" | "TCP6", _, _) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY protocol v1 address family mismatch",
        )),
        (family, _, _) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY protocol v1 family {family}"),
        )),
    }
}

fn parse_port(value: &str) -> io::Result<u16> {
    value.parse::<u16>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PROXY protocol port: {error}"),
        )
    })
}

async fn read_v2_header(
    stream: &mut Box<dyn AsyncStream>,
) -> io::Result<Option<SocketAddr>> {
    let mut fixed = [0u8; V2_FIXED_HEADER_BYTES - V2_SIGNATURE.len()];
    stream.read_exact(&mut fixed).await?;
    let version_command = fixed[0];
    if version_command >> 4 != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PROXY protocol v2 version",
        ));
    }
    let command = version_command & 0x0f;
    let family_protocol = fixed[1];
    let payload_len = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;
    if payload_len > V2_MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY protocol v2 payload exceeds 4096 bytes",
        ));
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    match command {
        0 => return Ok(None),
        1 => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v2 command",
            ));
        }
    }

    let family = family_protocol >> 4;
    let protocol = family_protocol & 0x0f;
    if protocol != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY protocol v2 transport must be STREAM",
        ));
    }

    match family {
        0 => Ok(None),
        1 => parse_v2_ipv4(&payload),
        2 => parse_v2_ipv6(&payload),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PROXY protocol v2 address family",
        )),
    }
}

fn parse_v2_ipv4(payload: &[u8]) -> io::Result<Option<SocketAddr>> {
    if payload.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated PROXY protocol v2 IPv4 address",
        ));
    }
    let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let source_port = u16::from_be_bytes([payload[8], payload[9]]);
    Ok(Some(SocketAddr::new(IpAddr::V4(source), source_port)))
}

fn parse_v2_ipv6(payload: &[u8]) -> io::Result<Option<SocketAddr>> {
    if payload.len() < 36 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated PROXY protocol v2 IPv6 address",
        ));
    }
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&payload[..16]).expect("IPv6 length checked"),
    );
    let source_port = u16::from_be_bytes([payload[32], payload[33]]);
    Ok(Some(SocketAddr::new(IpAddr::V6(source), source_port)))
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{
        AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };

    use super::*;
    use crate::async_stream::AsyncPing;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
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
        ) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    async fn parse_bytes(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
        let (mut client, server) = duplex(8192);
        client.write_all(bytes).await?;
        drop(client);
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream(server));
        read_proxy_header(&mut stream).await
    }

    #[tokio::test]
    async fn parses_v1_and_requires_a_header() {
        assert_eq!(
            parse_bytes(b"PROXY TCP4 203.0.113.7 192.0.2.1 4567 443\r\n")
                .await
                .unwrap(),
            Some("203.0.113.7:4567".parse().unwrap())
        );
        assert_eq!(parse_bytes(b"PROXY UNKNOWN\r\n").await.unwrap(), None);
        assert_eq!(
            parse_bytes(b"GET / HTTP/1.1\r\n").await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn parses_v2_ipv6_with_tlv_tail() {
        let source: Ipv6Addr = "2001:db8::7".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::8".parse().unwrap();
        let mut header = V2_SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x21]);
        header.extend_from_slice(&39u16.to_be_bytes());
        header.extend_from_slice(&source.octets());
        header.extend_from_slice(&destination.octets());
        header.extend_from_slice(&4567u16.to_be_bytes());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&[0x01, 0x00, 0x00]);

        assert_eq!(
            parse_bytes(&header).await.unwrap(),
            Some(SocketAddr::new(IpAddr::V6(source), 4567))
        );
    }
}
