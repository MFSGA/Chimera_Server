#[cfg(feature = "ws")]
use base64::Engine as _;
#[cfg(feature = "ws")]
use rand::RngExt as _;
#[cfg(feature = "ws")]
use std::time::Duration;
#[cfg(any(feature = "httpupgrade", feature = "ws"))]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[cfg(feature = "httpupgrade")]
use super::OutboundHttpUpgradeClientSettings;
#[cfg(feature = "ws")]
use super::OutboundWebsocketClientSettings;
#[cfg(feature = "ws")]
use crate::handler::ws::WebsocketStream;
#[cfg(any(feature = "httpupgrade", feature = "ws"))]
use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    util::prefixed_stream::PrefixedStream,
};

#[cfg(feature = "httpupgrade")]
pub(super) async fn connect_httpupgrade_transport(
    mut stream: Box<dyn AsyncStream>,
    settings: &OutboundHttpUpgradeClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    early_data: Option<&[u8]>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let path = normalize_httpupgrade_request_target(&settings.path)?;
    let host = if !settings.host.trim().is_empty() {
        settings.host.trim().to_string()
    } else if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        server_name.trim().to_string()
    } else {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => format!("[{ip}]"),
        }
    };
    validate_httpupgrade_header_value("Host", &host)?;

    let mut headers = settings.headers.iter().collect::<Vec<_>>();
    headers.sort_unstable_by(|(left, _), (right, _)| {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    });
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    );
    for (name, value) in headers {
        validate_httpupgrade_header_name(name)?;
        validate_httpupgrade_header_value(name, value)?;
        if name.eq_ignore_ascii_case("host") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTPUpgrade outbound headers can't contain Host; use host instead",
            ));
        }
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    if let Some(early_data) = early_data {
        stream.write_all(early_data).await?;
    }
    stream.flush().await?;
    let leftover = read_httpupgrade_response(&mut *stream).await?;
    if leftover.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(PrefixedStream::new(leftover, stream)))
    }
}

#[cfg(feature = "httpupgrade")]
fn normalize_httpupgrade_request_target(path: &str) -> std::io::Result<String> {
    let path = path.trim();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTPUpgrade outbound path contains an invalid HTTP request-target byte",
        ));
    }
    Ok(path)
}

#[cfg(feature = "httpupgrade")]
fn validate_httpupgrade_header_name(name: &str) -> std::io::Result<()> {
    let valid = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTPUpgrade outbound header name {name:?}"),
        ))
    }
}

#[cfg(feature = "httpupgrade")]
fn validate_httpupgrade_header_value(
    name: &str,
    value: &str,
) -> std::io::Result<()> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTPUpgrade outbound header value for {name}"),
        ));
    }
    Ok(())
}

#[cfg(feature = "httpupgrade")]
async fn read_httpupgrade_response<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut response = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) =
            response.windows(4).position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if response.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTPUpgrade outbound response headers are too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade outbound closed before the HTTP upgrade completed",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
    };

    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTPUpgrade outbound response headers are not valid UTF-8/ASCII",
        )
    })?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts.next().unwrap_or_default();
    let reason = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/")
        || status != "101"
        || reason != "Switching Protocols"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("HTTPUpgrade outbound rejected with {status_line}"),
        ));
    }

    let mut upgrade = None::<&str>;
    let mut connection = None::<&str>;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTPUpgrade outbound response header",
            ));
        };
        if name.eq_ignore_ascii_case("upgrade") && upgrade.is_none() {
            upgrade = Some(value.trim());
        } else if name.eq_ignore_ascii_case("connection") && connection.is_none() {
            connection = Some(value.trim());
        }
    }
    if !upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unrecognized HTTPUpgrade outbound response",
        ));
    }
    Ok(response[header_end..].to_vec())
}

#[cfg(feature = "ws")]
pub(super) async fn connect_websocket_transport(
    mut stream: Box<dyn AsyncStream>,
    settings: &OutboundWebsocketClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    early_data: Option<&[u8]>,
) -> std::io::Result<WebsocketStream> {
    const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

    let path = normalize_websocket_request_target(&settings.path)?;
    let host = websocket_request_host(settings, server, tls_server_name);
    validate_websocket_header_value("Host", &host)?;

    let mut nonce = [0u8; 16];
    rand::rng().fill(&mut nonce);
    let websocket_key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let expected_accept = websocket_accept_value(&websocket_key);
    let early_data_protocol = early_data
        .map(|data| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data));

    let mut headers = settings.headers.iter().collect::<Vec<_>>();
    headers.sort_unstable_by(|(left, _), (right, _)| {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    });
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in headers {
        validate_websocket_header_name(name)?;
        validate_websocket_header_value(name, value)?;
        if is_reserved_websocket_request_header(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "WebSocket outbound header {name} is reserved by the handshake"
                ),
            ));
        }
        if early_data_protocol.is_some()
            && name.eq_ignore_ascii_case("sec-websocket-protocol")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(protocol) = &early_data_protocol {
        request.push_str("Sec-WebSocket-Protocol: ");
        request.push_str(protocol);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let leftover = tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_websocket_upgrade_response(&mut *stream, &expected_accept).await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "WebSocket outbound handshake timed out",
        )
    })??;

    let stream: Box<dyn AsyncStream> = if leftover.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream::new(leftover, stream))
    };
    Ok(WebsocketStream::new_with_heartbeat(
        stream,
        true,
        &[],
        settings.heartbeat_period,
    ))
}

#[cfg(feature = "ws")]
fn normalize_websocket_request_target(path: &str) -> std::io::Result<String> {
    let path = path.trim();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "WebSocket outbound path contains an invalid HTTP request-target byte",
        ));
    }
    Ok(path)
}

#[cfg(feature = "ws")]
fn websocket_request_host(
    settings: &OutboundWebsocketClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
) -> String {
    if !settings.host.trim().is_empty() {
        return settings.host.trim().to_string();
    }
    if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        return server_name.trim().to_string();
    }
    match server.address() {
        Address::Hostname(hostname) => hostname.clone(),
        Address::Ipv4(ip) => ip.to_string(),
        Address::Ipv6(ip) => format!("[{ip}]"),
    }
}

#[cfg(feature = "ws")]
fn validate_websocket_header_name(name: &str) -> std::io::Result<()> {
    let valid = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid WebSocket outbound header name {name:?}"),
        ))
    }
}

#[cfg(feature = "ws")]
fn validate_websocket_header_value(name: &str, value: &str) -> std::io::Result<()> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid WebSocket outbound header value for {name}"),
        ));
    }
    Ok(())
}

#[cfg(feature = "ws")]
fn is_reserved_websocket_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
    )
}

#[cfg(feature = "ws")]
pub(super) fn websocket_accept_value(key: &str) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID);
    let hash = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &input,
    );
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

#[cfg(feature = "ws")]
async fn read_websocket_upgrade_response<S>(
    stream: &mut S,
    expected_accept: &str,
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut response = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) =
            response.windows(4).position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if response.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket outbound response headers are too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "WebSocket outbound closed before the HTTP upgrade completed",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_HEADER_BYTES
            && !response.windows(4).any(|window| window == b"\r\n\r\n")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket outbound response headers are too large",
            ));
        }
    };

    let header_bytes = &response[..header_end];
    let headers = std::str::from_utf8(header_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WebSocket outbound response headers are not valid UTF-8/ASCII",
        )
    })?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts.next().unwrap_or_default();
    if version != "HTTP/1.1" || status != "101" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("WebSocket outbound upgrade rejected with {status_line}"),
        ));
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut accept = None::<&str>;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed WebSocket outbound response header",
            ));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept")
            && accept.replace(value).is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "duplicate Sec-WebSocket-Accept response header",
            ));
        }
    }
    if !upgrade || !connection_upgrade || accept != Some(expected_accept) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid WebSocket outbound upgrade response",
        ));
    }

    Ok(response[header_end..].to_vec())
}
