use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
};

const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpProxyCredentials {
    pub username: String,
    pub password: String,
}

pub(crate) async fn connect_http_proxy(
    stream: &mut dyn AsyncStream,
    credentials: Option<&HttpProxyCredentials>,
    headers: &HashMap<String, String>,
    target: &NetLocation,
) -> std::io::Result<()> {
    let authority = format_authority(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(credentials) = credentials {
        if credentials.username.is_empty() {
            return Err(invalid_input("HTTP proxy username must not be empty"));
        }
        reject_crlf("HTTP proxy username", &credentials.username)?;
        reject_crlf("HTTP proxy password", &credentials.password)?;
        let token = STANDARD
            .encode(format!("{}:{}", credentials.username, credentials.password));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&token);
        request.push_str("\r\n");
    }
    for (name, value) in headers {
        validate_header(name, value)?;
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let response = read_response_header(stream).await?;
    validate_connect_response(&response)
}

fn format_authority(target: &NetLocation) -> String {
    match target.address() {
        Address::Ipv6(address) => format!("[{address}]:{}", target.port()),
        address => format!("{address}:{}", target.port()),
    }
}

async fn read_response_header(
    stream: &mut dyn AsyncStream,
) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(512);
    while response.len() < MAX_RESPONSE_HEADER_BYTES {
        response.push(stream.read_u8().await?);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err(invalid_data(format!(
        "HTTP proxy response header exceeds {MAX_RESPONSE_HEADER_BYTES} bytes"
    )))
}

fn validate_connect_response(response: &[u8]) -> std::io::Result<()> {
    let response = std::str::from_utf8(response).map_err(|_| {
        invalid_data("HTTP proxy response header is not valid UTF-8")
    })?;
    let status_line = response.split("\r\n").next().ok_or_else(|| {
        invalid_data("HTTP proxy response is missing a status line")
    })?;
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| invalid_data("HTTP proxy response is missing a version"))?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(invalid_data(format!(
            "HTTP proxy response used unsupported version {version}"
        )));
    }
    let status = parts
        .next()
        .ok_or_else(|| invalid_data("HTTP proxy response is missing a status code"))?
        .parse::<u16>()
        .map_err(|_| {
            invalid_data("HTTP proxy response has an invalid status code")
        })?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    let kind = match status {
        401 | 403 | 407 => std::io::ErrorKind::PermissionDenied,
        408 | 504 => std::io::ErrorKind::TimedOut,
        502 | 503 => std::io::ErrorKind::ConnectionRefused,
        _ => std::io::ErrorKind::ConnectionAborted,
    };
    Err(std::io::Error::new(
        kind,
        format!("HTTP CONNECT failed with status {status}"),
    ))
}

pub(crate) fn validate_http_proxy_headers(
    headers: &HashMap<String, String>,
) -> Result<(), String> {
    for (name, value) in headers {
        validate_header(name, value).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_header(name: &str, value: &str) -> std::io::Result<()> {
    if name.trim().is_empty() {
        return Err(invalid_input("HTTP proxy header name must not be empty"));
    }
    reject_crlf("HTTP proxy header name", name)?;
    reject_crlf("HTTP proxy header value", value)?;
    if !name.bytes().all(is_header_name_byte) {
        return Err(invalid_input(format!(
            "HTTP proxy header name contains invalid bytes: {name}"
        )));
    }
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "proxy-authorization"
            | "proxy-connection"
            | "connection"
            | "content-length"
            | "transfer-encoding"
    ) {
        return Err(invalid_input(format!(
            "HTTP proxy header {name} is reserved"
        )));
    }
    Ok(())
}

fn reject_crlf(label: &str, value: &str) -> std::io::Result<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(invalid_input(format!("{label} contains CR/LF")));
    }
    Ok(())
}

fn is_header_name_byte(byte: u8) -> bool {
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
}

fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn connect_uses_basic_auth_custom_headers_and_preserves_early_payload() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_response_header(&mut server).await.unwrap();
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(
                "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n"
            ));
            assert!(
                request.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n")
            );
            assert!(request.contains("X-Test: dynamic\r\n"));
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\nX-Upstream: yes\r\n\r\nready")
                .await
                .unwrap();
        });

        connect_http_proxy(
            &mut client,
            Some(&HttpProxyCredentials {
                username: "alice".into(),
                password: "secret".into(),
            }),
            &HashMap::from([("X-Test".into(), "dynamic".into())]),
            &NetLocation::new(Address::Hostname("example.test".into()), 443),
        )
        .await
        .unwrap();
        let mut payload = [0u8; 5];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ready");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_formats_ipv6_authority() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let request = read_response_header(&mut server).await.unwrap();
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with("CONNECT [::1]:8443 HTTP/1.1\r\n")
            );
            server
                .write_all(b"HTTP/1.0 204 No Content\r\n\r\n")
                .await
                .unwrap();
        });
        connect_http_proxy(
            &mut client,
            None,
            &HashMap::new(),
            &NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn authentication_and_upstream_failures_map_to_io_errors() {
        for (status, expected) in [
            (407, std::io::ErrorKind::PermissionDenied),
            (502, std::io::ErrorKind::ConnectionRefused),
            (504, std::io::ErrorKind::TimedOut),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let server_task = tokio::spawn(async move {
                let _ = read_response_header(&mut server).await.unwrap();
                server
                    .write_all(
                        format!("HTTP/1.1 {status} Failure\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let error = connect_http_proxy(
                &mut client,
                None,
                &HashMap::new(),
                &NetLocation::new(Address::Hostname("example.test".into()), 443),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), expected);
            server_task.await.unwrap();
        }
    }

    #[test]
    fn rejects_reserved_or_injected_headers() {
        for headers in [
            HashMap::from([("Host".into(), "override".into())]),
            HashMap::from([("X-Test\r\nInjected".into(), "yes".into())]),
            HashMap::from([("X-Test".into(), "yes\r\nInjected: true".into())]),
        ] {
            assert!(validate_http_proxy_headers(&headers).is_err());
        }
    }
}
