use std::{
    io::{self, Cursor},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::async_stream::AsyncStream;
use crate::config::server_config::RealityTransportConfig;
use crate::handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::handler::tls_deframer::TlsDeframer;
use crate::handler::vless_handler::{
    ParsedVisionUser, parse_vision_users, setup_reality_vision_server_stream,
};
use crate::reality::{BufReader, RealityServerConnection, RealityTlsStream};
use crate::resolver::{NativeResolver, Resolver, resolve_single_address};
use crate::util::socket::new_tcp_socket;

async fn read_client_hello(
    stream: &mut Box<dyn AsyncStream>,
) -> io::Result<Vec<u8>> {
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

async fn connect_dest(
    config: &RealityTransportConfig,
) -> io::Result<Box<dyn AsyncStream>> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target_addr = resolve_single_address(&resolver, &config.dest).await?;
    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let stream = tcp_socket.connect(target_addr).await?;
    if let Err(err) = stream.set_nodelay(true) {
        tracing::warn!("failed to set TCP no-delay on REALITY dest stream: {err}");
    }
    Ok(Box::new(stream))
}

async fn read_dest_records(
    dest_stream: &mut Box<dyn AsyncStream>,
) -> io::Result<(Vec<Bytes>, Bytes)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut records = Vec::new();
    let mut buf = vec![0u8; 8192];

    loop {
        let n = match timeout_at(deadline, dest_stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "REALITY dest closed during TLS handshake",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "REALITY timed out waiting for dest TLS handshake",
                ));
            }
        };

        deframer.feed(&buf[..n]);
        let new_records = deframer.next_records()?;
        records.extend(new_records);

        if records.len() >= 6 {
            break;
        }
        if records.len() >= 3 && records[2].len() > 512 {
            break;
        }
    }

    Ok((records, deframer.into_remaining_data()))
}

fn start_forward_to_dest(
    mut client_stream: Box<dyn AsyncStream>,
    mut dest_stream: Box<dyn AsyncStream>,
    dest_records: Vec<Bytes>,
    remaining_data: Bytes,
) {
    tokio::spawn(async move {
        for record in dest_records {
            if let Err(err) = client_stream.write_all(&record).await {
                tracing::debug!(
                    "REALITY fallback failed to forward dest record: {err}"
                );
                let _ =
                    futures::join!(client_stream.shutdown(), dest_stream.shutdown());
                return;
            }
        }

        if !remaining_data.is_empty()
            && let Err(err) = client_stream.write_all(&remaining_data).await
        {
            tracing::debug!("REALITY fallback failed to forward dest tail: {err}");
            let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());
            return;
        }

        if let Err(err) = client_stream.flush().await {
            tracing::debug!("REALITY fallback failed to flush client stream: {err}");
            let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());
            return;
        }

        let result =
            tokio::io::copy_bidirectional(&mut client_stream, &mut dest_stream)
                .await;
        let _ = futures::join!(client_stream.shutdown(), dest_stream.shutdown());

        if let Err(err) = result {
            tracing::debug!("REALITY fallback copy ended with error: {err}");
        }
    });
}

pub async fn accept_reality_stream(
    mut server_stream: Box<dyn AsyncStream>,
    config: &RealityTransportConfig,
) -> io::Result<RealityTlsStream<Box<dyn AsyncStream>, RealityServerConnection>> {
    let client_hello = read_client_hello(&mut server_stream).await?;

    if !config.server_names.is_empty() {
        let sni = extract_sni_from_client_hello(&client_hello)?;
        match sni {
            Some(name)
                if config
                    .server_names
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(&name)) => {}
            Some(name) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SNI {name} not allowed for REALITY inbound"),
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "REALITY inbound requires an SNI value",
                ));
            }
        }
    }

    let mut dest_stream = connect_dest(config).await?;
    dest_stream.write_all(&client_hello).await?;
    dest_stream.flush().await?;

    let mut reality_conn =
        RealityServerConnection::new(config.to_reality_server_config())?;
    let auth_result = reality_conn.validate_client_hello(&client_hello);
    let (dest_records, remaining_dest_data) =
        read_dest_records(&mut dest_stream).await?;

    match auth_result {
        Ok(()) => {
            reality_conn.build_server_response(dest_records)?;
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            start_forward_to_dest(
                server_stream,
                dest_stream,
                dest_records,
                remaining_dest_data,
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("REALITY auth failed, forwarding to dest: {err}"),
            ));
        }
        Err(err) => return Err(err),
    }
    drop(dest_stream);

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

    Ok(RealityTlsStream::new(server_stream, reality_conn))
}

#[derive(Debug)]
pub struct RealityServerHandler {
    transport_config: RealityTransportConfig,
    inner: Box<dyn TcpServerHandler>,
}

impl RealityServerHandler {
    pub fn new(
        config: RealityTransportConfig,
        inner: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            transport_config: config,
            inner,
        }
    }
}

#[async_trait]
impl TcpServerHandler for RealityServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let wrapped_stream =
            accept_reality_stream(server_stream, &self.transport_config).await?;
        self.inner
            .setup_server_stream(Box::new(wrapped_stream))
            .await
    }
}

#[derive(Debug)]
pub struct RealityVisionVlessServerHandler {
    transport_config: RealityTransportConfig,
    users: Vec<ParsedVisionUser>,
    inbound_tag: String,
}

impl RealityVisionVlessServerHandler {
    pub fn new(
        config: RealityTransportConfig,
        users: Vec<crate::config::server_config::VlessUser>,
        inbound_tag: &str,
    ) -> Self {
        Self {
            transport_config: config,
            users: parse_vision_users(&users),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for RealityVisionVlessServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let tls_stream =
            accept_reality_stream(server_stream, &self.transport_config).await?;
        setup_reality_vision_server_stream(
            tls_stream,
            &self.users,
            &self.inbound_tag,
        )
        .await
    }
}
