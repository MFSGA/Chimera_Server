use std::time::SystemTime;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;

pub(super) async fn write_xray_websocket_not_found(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    let response = format!(
        concat!(
            "HTTP/1.1 404 Not Found\r\n",
            "Date: {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_xray_method_not_allowed(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Method Not Allowed\n";
    let response = format!(
        concat!(
            "HTTP/1.1 405 Method Not Allowed\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_xray_bad_request_line(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
        )
        .await?;
    stream.flush().await
}

pub(super) async fn write_xray_malformed_host(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str = "400 Bad Request: malformed Host header";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_xray_missing_host(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str = "400 Bad Request: missing required Host header";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_xray_invalid_header_name(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str = "400 Bad Request: invalid header name";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_xray_unsupported_transfer_encoding(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nUnsupported transfer encoding",
        )
        .await?;
    stream.flush().await
}

pub(super) async fn write_xray_websocket_header_too_large(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large",
        )
        .await?;
    stream.flush().await
}

pub(super) async fn write_xray_unsupported_http_version(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str =
        "505 HTTP Version Not Supported: unsupported protocol version";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) async fn write_bad_websocket_request(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Bad Request\n";
    let response = format!(
        concat!(
            "HTTP/1.1 400 Bad Request\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(super) fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}
