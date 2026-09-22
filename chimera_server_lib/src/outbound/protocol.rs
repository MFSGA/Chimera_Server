use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::address::{Address, NetLocation};

#[cfg(feature = "vless-reverse")]
use super::VlessReverseBridgeEndpoint;
use super::{SocksOutboundEndpoint, TrojanOutboundEndpoint, VlessOutboundEndpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrojanCommand {
    Tcp,
    #[allow(dead_code)]
    // UDP is selected by protocol combinations not present in minimal builds.
    Udp,
}

impl TrojanCommand {
    fn byte(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x03,
        }
    }
}

#[derive(Debug)]
pub(super) enum TcpProtocolHandshake {
    None,
    Socks {
        target: NetLocation,
        endpoint: SocksOutboundEndpoint,
    },
    Vless {
        target: NetLocation,
        endpoint: VlessOutboundEndpoint,
    },
    Trojan {
        target: NetLocation,
        endpoint: TrojanOutboundEndpoint,
    },
}

#[cfg(feature = "vless-reverse")]
pub(super) async fn vless_reverse_connect<S>(
    stream: &mut S,
    endpoint: &VlessReverseBridgeEndpoint,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    if !endpoint.flow.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VLESS Reverse Vision outbound requires transport-aware support",
        ));
    }

    let mut request = Vec::with_capacity(19);
    request.push(0);
    request.extend_from_slice(&endpoint.user_id);
    request.push(0); // empty addons
    request.push(0x04); // RequestCommandRvs has no destination
    stream.write_all(&request).await?;
    stream.flush().await?;
    read_vless_response_header(stream).await
}

pub(super) async fn vless_tcp_connect<S>(
    stream: &mut S,
    endpoint: &VlessOutboundEndpoint,
    target: &NetLocation,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    if !endpoint.flow.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VLESS Vision outbound requires transport-aware support",
        ));
    }

    let mut request = Vec::with_capacity(64);
    request.push(0);
    request.extend_from_slice(&endpoint.user_id);
    request.push(0); // empty addons
    request.push(1); // TCP
    request.extend_from_slice(&target.port().to_be_bytes());
    match target.address() {
        Address::Ipv4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Address::Hostname(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS target domain must contain 1..=255 bytes",
                ));
            }
            request.push(2);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
        Address::Ipv6(ip) => {
            request.push(3);
            request.extend_from_slice(&ip.octets());
        }
    }
    stream.write_all(&request).await?;
    stream.flush().await?;
    read_vless_response_header(stream).await
}

async fn read_vless_response_header<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected VLESS response version {version}"),
        ));
    }
    let addon_len = stream.read_u8().await? as usize;
    if addon_len > 0 {
        let mut addons = vec![0u8; addon_len];
        stream.read_exact(&mut addons).await?;
    }
    Ok(())
}

pub(super) fn build_trojan_request(
    endpoint: &TrojanOutboundEndpoint,
    target: &NetLocation,
    command: TrojanCommand,
) -> std::io::Result<Vec<u8>> {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA224,
        endpoint.password.as_bytes(),
    );
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut request = Vec::with_capacity(128);
    for byte in digest.as_ref() {
        request.push(HEX[(byte >> 4) as usize]);
        request.push(HEX[(byte & 0x0f) as usize]);
    }
    request.extend_from_slice(b"\r\n");
    request.push(command.byte());
    encode_socks5_target(&mut request, target)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

pub(super) async fn trojan_connect<S>(
    stream: &mut S,
    endpoint: &TrojanOutboundEndpoint,
    target: &NetLocation,
    command: TrojanCommand,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let request = build_trojan_request(endpoint, target, command)?;
    stream.write_all(&request).await?;
    stream.flush().await
}

pub(super) async fn socks5_connect<S>(
    stream: &mut S,
    endpoint: &SocksOutboundEndpoint,
    target: &NetLocation,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let auth_method = if endpoint.username.is_some() {
        0x02
    } else {
        0x00
    };
    stream.write_all(&[0x05, 0x01, auth_method]).await?;
    stream.flush().await?;

    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response).await?;
    if method_response[0] != 0x05 || method_response[1] != auth_method {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "SOCKS server selected unsupported auth method 0x{:02x}",
                method_response[1]
            ),
        ));
    }

    if auth_method == 0x02 {
        let username = endpoint.username.as_deref().unwrap_or_default().as_bytes();
        let password = endpoint.password.as_deref().unwrap_or_default().as_bytes();
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS username or password exceeds 255 bytes",
            ));
        }
        let mut request = Vec::with_capacity(username.len() + password.len() + 3);
        request.push(0x01);
        request.push(username.len() as u8);
        request.extend_from_slice(username);
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut auth_response = [0u8; 2];
        stream.read_exact(&mut auth_response).await?;
        if auth_response[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SOCKS server rejected account: {}", auth_response[1]),
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    encode_socks5_target(&mut request, target)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected SOCKS server version {}", response[0]),
        ));
    }
    if response[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS server rejected CONNECT request: {}", response[1]),
        ));
    }
    consume_socks5_bound_address(stream, response[3]).await
}

fn encode_socks5_target(
    output: &mut Vec<u8>,
    target: &NetLocation,
) -> std::io::Result<()> {
    match target.address() {
        Address::Ipv4(ip) => {
            output.push(0x01);
            output.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            output.push(0x04);
            output.extend_from_slice(&ip.octets());
        }
        Address::Hostname(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS target domain must contain 1..=255 bytes",
                ));
            }
            output.push(0x03);
            output.push(bytes.len() as u8);
            output.extend_from_slice(bytes);
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

async fn consume_socks5_bound_address<S>(
    stream: &mut S,
    address_type: u8,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    match address_type {
        0x01 => {
            let mut bytes = [0u8; 4 + 2];
            stream.read_exact(&mut bytes).await?;
        }
        0x04 => {
            let mut bytes = [0u8; 16 + 2];
            stream.read_exact(&mut bytes).await?;
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0u8; length + 2];
            stream.read_exact(&mut bytes).await?;
        }
        value => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS server returned unknown address type {value}"),
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "vless-reverse"))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn reverse_connect_emits_addressless_xray_command_and_reads_response() {
        let endpoint = VlessReverseBridgeEndpoint {
            server: NetLocation::new(Address::from("127.0.0.1").unwrap(), 443),
            user_id: [
                0x3a, 0xc9, 0xb3, 0x83, 0x75, 0xa1, 0x43, 0x1c, 0x81, 0x84, 0x10,
                0x6c, 0x80, 0xeb, 0x22, 0x73,
            ],
            flow: String::new(),
            reverse_tag: "bridge-in".to_string(),
        };
        let expected_user = endpoint.user_id;
        let (mut client, mut server) = duplex(128);

        let server_task = tokio::spawn(async move {
            let mut request = [0u8; 19];
            server
                .read_exact(&mut request)
                .await
                .expect("read Reverse VLESS request");
            assert_eq!(request[0], 0);
            assert_eq!(&request[1..17], &expected_user);
            assert_eq!(request[17], 0);
            assert_eq!(request[18], 0x04);
            server
                .write_all(&[0, 0])
                .await
                .expect("write VLESS response");
        });

        vless_reverse_connect(&mut client, &endpoint)
            .await
            .expect("perform addressless Reverse handshake");
        server_task.await.expect("server task");
    }
}
