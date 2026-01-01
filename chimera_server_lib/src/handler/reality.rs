use std::io::{self, Cursor};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::async_stream::AsyncStream;
use crate::config::server_config::RealityTransportConfig;
use crate::handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::reality::{BufReader, RealityServerConfig, RealityServerConnection, RealityTlsStream};

async fn read_client_hello(stream: &mut Box<dyn AsyncStream>) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected record type {}, expected handshake", header[0]),
        ));
    }

    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;

    let mut full = Vec::with_capacity(5 + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

fn extract_sni_from_client_hello(client_hello: &[u8]) -> io::Result<Option<String>> {
    if client_hello.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client hello too short for TLS header",
        ));
    }

    // Skip TLS record header
    let mut reader = BufReader::new(&client_hello[5..]);
    let handshake_type = reader.read_u8()?;
    if handshake_type != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected handshake type {handshake_type}"),
        ));
    }

    // We don't strictly validate handshake length; BufReader bounds checks on read
    let _handshake_len = reader.read_u24_be()?;
    reader.read_u16_be()?; // version
    reader.skip(32)?; // random

    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    let cipher_suites_len = reader.read_u16_be()? as usize;
    reader.skip(cipher_suites_len)?;

    let compression_len = reader.read_u8()? as usize;
    reader.skip(compression_len)?;

    if reader.is_consumed() {
        return Ok(None);
    }

    let extensions_len = reader.read_u16_be()? as usize;
    let extensions_end = reader.position() + extensions_len;

    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;

        if ext_type == 0 {
            // Server Name extension
            let list_len = reader.read_u16_be()? as usize;
            let list_end = reader.position() + list_len;
            while reader.position() < list_end {
                let name_type = reader.read_u8()?;
                let name_len = reader.read_u16_be()? as usize;
                let name = reader.read_str(name_len)?;
                if name_type == 0 {
                    return Ok(Some(name.to_string()));
                }
            }
            return Ok(None);
        } else {
            reader.skip(ext_len)?;
        }
    }

    Ok(None)
}

#[derive(Debug)]
pub struct RealityServerHandler {
    handshake_config: RealityServerConfig,
    server_names: Vec<String>,
    inner: Box<dyn TcpServerHandler>,
}

impl RealityServerHandler {
    pub fn new(config: RealityTransportConfig, inner: Box<dyn TcpServerHandler>) -> Self {
        Self {
            handshake_config: config.to_reality_server_config(),
            server_names: config.server_names,
            inner,
        }
    }
}

#[async_trait]
impl TcpServerHandler for RealityServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let client_hello = read_client_hello(&mut server_stream).await?;

        if !self.server_names.is_empty() {
            let sni = extract_sni_from_client_hello(&client_hello)?;
            match sni {
                Some(name)
                    if self
                        .server_names
                        .iter()
                        .any(|expected| expected.eq_ignore_ascii_case(&name)) => {}
                Some(name) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("SNI {name} not allowed for REALITY inbound"),
                    ))
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "REALITY inbound requires an SNI value",
                    ))
                }
            }
        }

        let mut reality_conn = RealityServerConnection::new(self.handshake_config.clone())?;
        reality_conn.read_tls(&mut Cursor::new(&client_hello))?;
        reality_conn.process_new_packets()?;

        let mut handshake_bytes = Vec::new();
        while reality_conn.wants_write() {
            reality_conn.write_tls(&mut handshake_bytes)?;
        }
        if !handshake_bytes.is_empty() {
            server_stream.write_all(&handshake_bytes).await?;
            server_stream.flush().await?;
        }

        while reality_conn.is_handshaking() {
            let mut buf = vec![0u8; 4096];
            let n = server_stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF while waiting for REALITY client Finished",
                ));
            }
            reality_conn.read_tls(&mut Cursor::new(&buf[..n]))?;
            reality_conn.process_new_packets()?;
        }

        let mut final_flush = Vec::new();
        while reality_conn.wants_write() {
            reality_conn.write_tls(&mut final_flush)?;
        }
        if !final_flush.is_empty() {
            server_stream.write_all(&final_flush).await?;
            server_stream.flush().await?;
        }

        let wrapped_stream = RealityTlsStream::new(server_stream, reality_conn);
        self.inner.setup_server_stream(Box::new(wrapped_stream)).await
    }
}
