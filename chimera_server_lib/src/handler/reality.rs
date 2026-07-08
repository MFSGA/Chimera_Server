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
    validate_client_hello_body(&body)?;

    let mut full = Vec::with_capacity(5 + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    Ok(full)
}

fn validate_client_hello_body(body: &[u8]) -> io::Result<()> {
    let mut reader = BufReader::new(body);
    let handshake_type = reader.read_u8()?;
    if handshake_type != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ClientHello handshake",
        ));
    }

    let handshake_len = reader.read_u24_be()? as usize;
    if handshake_len + 4 != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client hello message length mismatch",
        ));
    }

    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    if version_major != 0x03 || !matches!(version_minor, 0x01 | 0x03) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected ClientHello TLS version {version_major}.{version_minor}"
            ),
        ));
    }

    Ok(())
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
    let mut requested_server_name = None;

    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;

        if ext_type == 0 {
            if requested_server_name.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "multiple server names",
                ));
            }

            // Server Name extension
            let list_len = reader.read_u16_be()? as usize;
            let list_end = reader.position() + list_len;
            while reader.position() < list_end {
                let name_type = reader.read_u8()?;
                if name_type != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected server name type to be hostname (0)",
                    ));
                }
                let name_len = reader.read_u16_be()? as usize;
                let name = reader.read_str(name_len)?;
                if requested_server_name.replace(name.to_string()).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "multiple server names",
                    ));
                }
            }
        } else {
            reader.skip(ext_len)?;
        }
    }

    Ok(requested_server_name)
}

fn validate_reality_sni(
    server_names: &[String],
    sni: Option<&str>,
) -> io::Result<()> {
    if server_names.is_empty() {
        return Ok(());
    }

    match sni {
        Some(name)
            if server_names
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(name)) =>
        {
            Ok(())
        }
        Some(name) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SNI {name} not allowed for REALITY inbound"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY inbound requires an SNI value",
        )),
    }
}

fn client_hello_supports_tls13(client_hello: &[u8]) -> io::Result<bool> {
    if client_hello.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client hello too short for TLS header",
        ));
    }

    let mut reader = BufReader::new(&client_hello[5..]);
    let handshake_type = reader.read_u8()?;
    if handshake_type != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected handshake type {handshake_type}"),
        ));
    }

    let _handshake_len = reader.read_u24_be()?;
    reader.read_u16_be()?;
    reader.skip(32)?;

    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    let cipher_suites_len = reader.read_u16_be()? as usize;
    reader.skip(cipher_suites_len)?;

    let compression_len = reader.read_u8()? as usize;
    reader.skip(compression_len)?;

    if reader.is_consumed() {
        return Ok(false);
    }

    let extensions_len = reader.read_u16_be()? as usize;
    let extensions_end = reader.position() + extensions_len;
    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;

        if ext_type == 0x002b {
            let version_list_len = reader.read_u8()? as usize;
            if !version_list_len.is_multiple_of(2) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid odd version list length: 0x{version_list_len:02x}"
                    ),
                ));
            }
            let version_list = reader.read_slice(version_list_len)?;
            return Ok(version_list
                .chunks_exact(2)
                .any(|version| version == [0x03, 0x04]));
        }

        reader.skip(ext_len)?;
    }

    Ok(false)
}

#[derive(Debug, Clone, Copy)]
struct ParsedDestServerHello {
    is_tls13: bool,
}

fn parse_dest_server_hello(
    server_hello: &[u8],
) -> io::Result<ParsedDestServerHello> {
    const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
    const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
    const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const RETRY_REQUEST_RANDOM_BYTES: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
        0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    ];

    if server_hello.len() < 47 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello frame too short",
        ));
    }

    if server_hello[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake content type",
        ));
    }
    if server_hello[1] != 0x03 || server_hello[2] != 0x03 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected record TLS version {}.{}",
                server_hello[1], server_hello[2]
            ),
        ));
    }

    let mut reader = BufReader::new(&server_hello[5..]);
    let handshake_type = reader.read_u8()?;
    if handshake_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }

    let message_len = reader.read_u24_be()? as usize;
    if server_hello[5..].len().saturating_sub(reader.position()) < message_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello message length exceeds frame",
        ));
    }

    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    if version_major != 0x03 || version_minor != 0x03 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected TLS version 3.3, got {version_major}.{version_minor}"),
        ));
    }

    let server_random = reader.read_slice(32)?;
    if server_random == RETRY_REQUEST_RANDOM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server sent a HelloRetryRequest",
        ));
    }
    let session_id_len = reader.read_u8()?;
    if session_id_len > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid session_id_len {session_id_len}, max is 32"),
        ));
    }
    reader.skip(session_id_len as usize)?;
    reader.skip(2)?; // cipher suite
    reader.skip(1)?; // compression method

    let mut is_tls13 = false;
    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        if server_hello[5..].len().saturating_sub(reader.position()) < extensions_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extensions length exceeds remaining data",
            ));
        }

        let extensions_data = reader.read_slice(extensions_len)?;
        let mut ext_reader = BufReader::new(extensions_data);
        while !ext_reader.is_consumed() {
            let ext_type = ext_reader.read_u16_be()?;
            let ext_len = ext_reader.read_u16_be()? as usize;

            if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
                if ext_len != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "supported_versions extension should be 2 bytes, got {ext_len}"
                        ),
                    ));
                }
                let version = ext_reader.read_slice(2)?;
                is_tls13 = version == [0x03, 0x04];
            } else {
                ext_reader.skip(ext_len)?;
            }
        }
    }

    Ok(ParsedDestServerHello { is_tls13 })
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
) -> io::Result<DestRecordRead> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut records = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut fallback_error = None;
    let mut handshake_complete = false;

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
                tracing::debug!("REALITY timed out waiting for dest TLS handshake");
                break;
            }
        };

        deframer.feed(&buf[..n]);
        let new_records = match deframer.next_records() {
            Ok(records) => records,
            Err(err) => {
                tracing::debug!("REALITY failed to parse dest TLS records: {err}");
                break;
            }
        };
        let should_parse_server_hello =
            records.is_empty() && !new_records.is_empty();
        records.extend(new_records);

        if should_parse_server_hello {
            match parse_dest_server_hello(&records[0]) {
                Ok(parsed) if parsed.is_tls13 => {
                    tracing::debug!("REALITY dest confirmed TLS 1.3");
                }
                Ok(_) => {
                    fallback_error = Some(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "REALITY dest does not support TLS 1.3",
                    ));
                    break;
                }
                Err(err) => {
                    fallback_error = Some(io::Error::new(
                        err.kind(),
                        format!("REALITY failed to parse dest ServerHello: {err}"),
                    ));
                    break;
                }
            }
        }

        if dest_handshake_looks_complete(&records) {
            handshake_complete = true;
            break;
        }
    }

    Ok(DestRecordRead {
        records,
        remaining_data: deframer.into_remaining_data(),
        fallback_error,
        handshake_complete,
    })
}

struct DestRecordRead {
    records: Vec<Bytes>,
    remaining_data: Bytes,
    fallback_error: Option<io::Error>,
    handshake_complete: bool,
}

fn dest_handshake_looks_complete(records: &[Bytes]) -> bool {
    const MIN_COMPLETE_TLS13_RECORDS: usize = 6;
    const LARGE_CERTIFICATE_RECORD_MIN_LEN: usize = 512;

    records.len() >= MIN_COMPLETE_TLS13_RECORDS
        || records
            .get(2)
            .is_some_and(|record| record.len() > LARGE_CERTIFICATE_RECORD_MIN_LEN)
}

fn start_forward_to_dest(
    mut client_stream: Box<dyn AsyncStream>,
    mut dest_stream: Box<dyn AsyncStream>,
    dest_records: Vec<Bytes>,
    remaining_data: Bytes,
) {
    tokio::spawn(async move {
        let dest_record_count = dest_records.len();
        for record in dest_records {
            if let Err(err) = client_stream.write_all(&record).await {
                tracing::debug!(
                    "REALITY fallback failed to forward dest record: {err}"
                );
                let _ =
                    futures::join!(client_stream.shutdown(), dest_stream.shutdown());
                return;
            }
            if let Err(err) = client_stream.flush().await {
                tracing::debug!(
                    "REALITY fallback failed to flush dest record: {err}"
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

        tracing::debug!(
            "REALITY fallback forwarded {} dest records and {} remaining bytes",
            dest_record_count,
            remaining_data.len()
        );

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
    let sni = extract_sni_from_client_hello(&client_hello)?;

    let mut dest_stream = connect_dest(config).await?;
    dest_stream.write_all(&client_hello).await?;
    dest_stream.flush().await?;

    if let Err(err) = validate_reality_sni(&config.server_names, sni.as_deref()) {
        tracing::warn!(
            sni = sni.as_deref().unwrap_or("<none>"),
            dest = %config.dest,
            "REALITY SNI validation failed, forwarding to dest: {err}"
        );
        start_forward_to_dest(server_stream, dest_stream, vec![], Bytes::new());
        return Err(err);
    }

    if !client_hello_supports_tls13(&client_hello)? {
        tracing::warn!(
            sni = sni.as_deref().unwrap_or("<none>"),
            dest = %config.dest,
            "REALITY client does not support TLS 1.3, forwarding to dest"
        );
        start_forward_to_dest(server_stream, dest_stream, vec![], Bytes::new());
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "REALITY client does not support TLS 1.3, forwarding to dest",
        ));
    }

    let mut reality_conn =
        RealityServerConnection::new(config.to_reality_server_config())?;
    let auth_result = reality_conn.validate_client_hello(&client_hello);
    let dest_read = read_dest_records(&mut dest_stream).await?;
    if !dest_read.handshake_complete {
        let fallback_error = dest_read.fallback_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "REALITY dest TLS handshake incomplete, forwarding to dest",
            )
        });
        tracing::warn!(
            sni = sni.as_deref().unwrap_or("<none>"),
            dest = %config.dest,
            records = dest_read.records.len(),
            "REALITY dest TLS handshake incomplete, forwarding to dest: {fallback_error}"
        );
        start_forward_to_dest(
            server_stream,
            dest_stream,
            dest_read.records,
            dest_read.remaining_data,
        );
        return Err(fallback_error);
    }
    let dest_records = dest_read.records;
    let remaining_dest_data = dest_read.remaining_data;

    match auth_result {
        Ok(()) => {
            reality_conn.build_server_response(dest_records)?;
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            tracing::warn!(
                sni = sni.as_deref().unwrap_or("<none>"),
                dest = %config.dest,
                "REALITY auth failed, forwarding to dest: {err}"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_with_raw_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x24; 32]);
        body.push(0); // session_id_len
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // cipher suite
        body.push(1); // compression methods len
        body.push(0); // null compression

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = body.len() as u32;
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn client_hello_with_supported_versions(versions: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x2b]);
        extensions.extend_from_slice(&((versions.len() + 1) as u16).to_be_bytes());
        extensions.push(versions.len() as u8);
        extensions.extend_from_slice(versions);

        client_hello_with_raw_extensions(&extensions)
    }

    fn sni_extension(name_type: u8, name: &str) -> Vec<u8> {
        let mut names = Vec::new();
        names.push(name_type);
        names.extend_from_slice(&(name.len() as u16).to_be_bytes());
        names.extend_from_slice(name.as_bytes());

        let mut extension = Vec::new();
        extension.extend_from_slice(&[0x00, 0x00]);
        extension.extend_from_slice(&((2 + names.len()) as u16).to_be_bytes());
        extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
        extension.extend_from_slice(&names);
        extension
    }

    fn server_hello_with_supported_version(version: Option<[u8; 2]>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0); // session_id_len
        body.extend_from_slice(&[0x13, 0x01]); // cipher suite
        body.push(0); // compression

        let mut extensions = Vec::new();
        if let Some(version) = version {
            extensions.extend_from_slice(&[0x00, 0x2b]);
            extensions.extend_from_slice(&[0x00, 0x02]);
            extensions.extend_from_slice(&version);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x02);
        let len = body.len() as u32;
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn validate_client_hello_body_accepts_well_formed_body() {
        let record = client_hello_with_supported_versions(&[0x03, 0x04]);

        validate_client_hello_body(&record[5..]).unwrap();
    }

    #[test]
    fn validate_client_hello_body_rejects_length_mismatch() {
        let record = client_hello_with_supported_versions(&[0x03, 0x04]);
        let mut body = record[5..].to_vec();
        body[1] = 0;
        body[2] = 0;
        body[3] = 0;

        let err = validate_client_hello_body(&body).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("length mismatch"));
    }

    #[test]
    fn validate_client_hello_body_rejects_unexpected_legacy_version() {
        let record = client_hello_with_supported_versions(&[0x03, 0x04]);
        let mut body = record[5..].to_vec();
        body[4] = 0x04;
        body[5] = 0x04;

        let err = validate_client_hello_body(&body).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("unexpected ClientHello TLS version")
        );
    }

    #[test]
    fn extract_sni_accepts_hostname() {
        let record =
            client_hello_with_raw_extensions(&sni_extension(0, "example.com"));

        assert_eq!(
            extract_sni_from_client_hello(&record).unwrap(),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_sni_rejects_non_hostname_name_type() {
        let record =
            client_hello_with_raw_extensions(&sni_extension(1, "example.com"));

        let err = extract_sni_from_client_hello(&record).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("expected server name type to be hostname")
        );
    }

    #[test]
    fn extract_sni_rejects_multiple_server_name_extensions() {
        let mut extensions = sni_extension(0, "example.com");
        extensions.extend_from_slice(&sni_extension(0, "example.org"));
        let record = client_hello_with_raw_extensions(&extensions);

        let err = extract_sni_from_client_hello(&record).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("multiple server names"));
    }

    #[test]
    fn validate_reality_sni_accepts_matching_name_case_insensitive() {
        let server_names = vec!["Example.COM".to_string()];

        validate_reality_sni(&server_names, Some("example.com")).unwrap();
    }

    #[test]
    fn validate_reality_sni_rejects_mismatch() {
        let server_names = vec!["example.com".to_string()];

        let err =
            validate_reality_sni(&server_names, Some("probe.example")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn validate_reality_sni_rejects_missing_when_names_are_configured() {
        let server_names = vec!["example.com".to_string()];

        let err = validate_reality_sni(&server_names, None).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("requires an SNI"));
    }

    #[test]
    fn client_hello_supports_tls13_when_advertised() {
        let record = client_hello_with_supported_versions(&[0x03, 0x03, 0x03, 0x04]);

        assert!(client_hello_supports_tls13(&record).unwrap());
    }

    #[test]
    fn client_hello_does_not_support_tls13_when_missing() {
        let record = client_hello_with_supported_versions(&[0x03, 0x03]);

        assert!(!client_hello_supports_tls13(&record).unwrap());
    }

    #[test]
    fn client_hello_rejects_odd_supported_versions_len() {
        let record = client_hello_with_supported_versions(&[0x03]);

        let err = client_hello_supports_tls13(&record).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid odd version list length"));
    }

    #[test]
    fn parse_dest_server_hello_accepts_tls13() {
        let parsed =
            parse_dest_server_hello(&server_hello_with_supported_version(Some([
                0x03, 0x04,
            ])))
            .unwrap();

        assert!(parsed.is_tls13);
    }

    #[test]
    fn parse_dest_server_hello_rejects_hello_retry_request() {
        let mut record = server_hello_with_supported_version(Some([0x03, 0x04]));
        record[11..43].copy_from_slice(&[
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
            0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
            0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        ]);

        let err = parse_dest_server_hello(&record).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("HelloRetryRequest"));
    }

    #[test]
    fn parse_dest_server_hello_marks_tls12() {
        let parsed =
            parse_dest_server_hello(&server_hello_with_supported_version(None))
                .unwrap();

        assert!(!parsed.is_tls13);
    }

    #[test]
    fn parse_dest_server_hello_rejects_wrong_content_type() {
        let mut record = server_hello_with_supported_version(Some([0x03, 0x04]));
        record[0] = 0x17;

        let err = parse_dest_server_hello(&record).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("expected handshake content type"));
    }

    #[test]
    fn dest_handshake_looks_complete_after_six_records() {
        let records = vec![Bytes::from_static(b"r"); 6];

        assert!(dest_handshake_looks_complete(&records));
    }

    #[test]
    fn dest_handshake_looks_complete_for_large_certificate_record() {
        let records = vec![
            Bytes::from_static(b"server-hello"),
            Bytes::from_static(b"encrypted-extensions"),
            Bytes::from(vec![0u8; 513]),
        ];

        assert!(dest_handshake_looks_complete(&records));
    }

    #[test]
    fn dest_handshake_looks_incomplete_for_short_record_prefix() {
        let records = vec![
            Bytes::from_static(b"server-hello"),
            Bytes::from_static(b"encrypted-extensions"),
            Bytes::from(vec![0u8; 512]),
            Bytes::from_static(b"partial"),
            Bytes::from_static(b"partial"),
        ];

        assert!(!dest_handshake_looks_complete(&records));
    }
}
