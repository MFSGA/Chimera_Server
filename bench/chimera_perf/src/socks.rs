use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub async fn connect_via_socks5(
    proxy: SocketAddr,
    target_host: &str,
    target_port: u16,
    tcp_nodelay: bool,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .with_context(|| format!("connect SOCKS5 proxy {proxy}"))?;
    stream.set_nodelay(tcp_nodelay)?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        bail!("SOCKS5 proxy rejected no-auth method: {method:?}");
    }

    let mut request = Vec::with_capacity(4 + 16 + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let host = target_host.as_bytes();
            let host_len =
                u8::try_from(host.len()).context("SOCKS5 host is too long")?;
            request.push(0x03);
            request.push(host_len);
            request.extend_from_slice(host);
        }
    }
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response_head = [0_u8; 4];
    stream.read_exact(&mut response_head).await?;
    if response_head[0] != 0x05 || response_head[1] != 0x00 {
        bail!("SOCKS5 connect failed with reply {}", response_head[1]);
    }
    let address_len = match response_head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        atyp => bail!("SOCKS5 proxy returned invalid address type {atyp}"),
    };
    let mut ignored = vec![0_u8; address_len + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(stream)
}
