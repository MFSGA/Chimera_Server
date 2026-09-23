use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::StreamExt as _;
use http_body_util::{BodyExt as _, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Uri,
    body::Frame,
    client::conn::http2 as client_http2,
    header::{self, HeaderName, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngExt as _;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf, duplex, split},
    task::AbortHandle,
};
use tokio_util::io::ReaderStream;

use super::{OutboundXhttpClientSettings, OutboundXhttpSessionPlacement};
use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
};

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
type XhttpBody = UnsyncBoxBody<Bytes, io::Error>;

pub(super) struct XhttpOutboundStream {
    inner: tokio::io::DuplexStream,
    shared_error: Arc<Mutex<Option<(io::ErrorKind, String)>>>,
    connection_abort: AbortHandle,
    downlink_abort: AbortHandle,
    uplink_abort: AbortHandle,
}

impl Drop for XhttpOutboundStream {
    fn drop(&mut self) {
        self.uplink_abort.abort();
        self.downlink_abort.abort();
        self.connection_abort.abort();
    }
}

impl AsyncRead for XhttpOutboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                match take_xhttp_error(&self.shared_error) {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Ready(Ok(())),
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for XhttpOutboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = clone_xhttp_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = clone_xhttp_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpOutboundStream {
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

impl AsyncStream for XhttpOutboundStream {}

pub(super) async fn connect_xhttp_stream_up_h2(
    stream: Box<dyn AsyncStream>,
    settings: &OutboundXhttpClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
) -> io::Result<XhttpOutboundStream> {
    let authority = xhttp_authority(settings, server, tls_server_name);
    let session_id = xhttp_session_id();
    let request_uri = xhttp_request_uri(settings, &authority, &session_id)?;
    let referer = xhttp_padding_referer(settings, &authority)?;

    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    builder.initial_stream_window_size(1024 * 1024);
    builder.initial_connection_window_size(1024 * 1024);
    let (mut sender, connection) = builder
        .handshake::<_, XhttpBody>(TokioIo::new(stream))
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("XHTTP outbound HTTP/2 handshake failed: {error}"),
            )
        })?;

    let shared_error = Arc::new(Mutex::new(None));
    let connection_error = Arc::clone(&shared_error);
    let connection_task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            set_xhttp_error(
                &connection_error,
                io::ErrorKind::ConnectionAborted,
                format!("XHTTP outbound HTTP/2 connection failed: {error}"),
            );
        }
    });
    let connection_abort = connection_task.abort_handle();
    drop(connection_task);

    let get_body = Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync();
    let mut downlink_request = Request::builder()
        .method(Method::GET)
        .uri(request_uri.clone());
    downlink_request = apply_xhttp_headers(
        downlink_request,
        settings,
        &referer,
        &session_id,
        false,
    )?;
    let downlink_request = downlink_request.body(get_body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to build XHTTP downlink request: {error}"),
        )
    })?;
    let downlink_response =
        sender
            .send_request(downlink_request)
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("XHTTP downlink request failed: {error}"),
                )
            })?;
    if downlink_response.status() != hyper::StatusCode::OK {
        connection_abort.abort();
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "XHTTP downlink returned HTTP status {}",
                downlink_response.status()
            ),
        ));
    }

    let (app_stream, transport_stream) = duplex(XHTTP_PIPE_CAPACITY);
    let (upload_read, mut download_write) = split(transport_stream);
    let body_stream =
        ReaderStream::new(upload_read).map(|chunk| chunk.map(Frame::data));
    let upload_body = StreamBody::new(body_stream).boxed_unsync();
    let method = Method::from_bytes(settings.uplink_http_method.as_bytes())
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid XHTTP uplinkHTTPMethod {}: {error}",
                    settings.uplink_http_method
                ),
            )
        })?;
    let mut uplink_request = Request::builder().method(method).uri(request_uri);
    uplink_request =
        apply_xhttp_headers(uplink_request, settings, &referer, &session_id, true)?;
    let uplink_request = uplink_request.body(upload_body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to build XHTTP uplink request: {error}"),
        )
    })?;
    let uplink_response =
        sender.send_request(uplink_request).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("XHTTP uplink request failed: {error}"),
            )
        })?;
    if uplink_response.status() != hyper::StatusCode::OK {
        connection_abort.abort();
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "XHTTP uplink returned HTTP status {}",
                uplink_response.status()
            ),
        ));
    }

    let downlink_error = Arc::clone(&shared_error);
    let downlink_task = tokio::spawn(async move {
        let mut body = downlink_response.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref()
                        && download_write.write_all(data).await.is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    set_xhttp_error(
                        &downlink_error,
                        io::ErrorKind::ConnectionAborted,
                        format!("XHTTP downlink response failed: {error}"),
                    );
                    break;
                }
            }
        }
        let _ = download_write.shutdown().await;
    });
    let downlink_abort = downlink_task.abort_handle();
    drop(downlink_task);

    let uplink_error = Arc::clone(&shared_error);
    let uplink_task = tokio::spawn(async move {
        let mut body = uplink_response.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(_) => {}
                Err(error) => {
                    set_xhttp_error(
                        &uplink_error,
                        io::ErrorKind::ConnectionAborted,
                        format!("XHTTP uplink response failed: {error}"),
                    );
                    break;
                }
            }
        }
    });
    let uplink_abort = uplink_task.abort_handle();
    drop(uplink_task);

    Ok(XhttpOutboundStream {
        inner: app_stream,
        shared_error,
        connection_abort,
        downlink_abort,
        uplink_abort,
    })
}

fn apply_xhttp_headers(
    mut builder: http::request::Builder,
    settings: &OutboundXhttpClientSettings,
    referer: &str,
    session_id: &str,
    upload: bool,
) -> io::Result<http::request::Builder> {
    for (name, value) in &settings.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid XHTTP outbound header name {name:?}: {error}"),
            )
        })?;
        let value = HeaderValue::from_str(value).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid XHTTP outbound header value: {error}"),
            )
        })?;
        builder = builder.header(name, value);
    }

    let headers = builder.headers_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XHTTP outbound request builder has no header map",
        )
    })?;
    headers.insert(
        header::REFERER,
        HeaderValue::from_str(referer).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid XHTTP Referer value: {error}"),
            )
        })?,
    );
    if upload && !settings.no_grpc_header {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
    }

    match &settings.session_placement {
        OutboundXhttpSessionPlacement::Path
        | OutboundXhttpSessionPlacement::Query(_) => {}
        OutboundXhttpSessionPlacement::Header(key) => {
            let name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP sessionIDKey header {key:?}: {error}"),
                )
            })?;
            headers.insert(
                name,
                HeaderValue::from_str(session_id).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid XHTTP session ID: {error}"),
                    )
                })?,
            );
        }
        OutboundXhttpSessionPlacement::Cookie(key) => {
            let cookie = match headers
                .get(header::COOKIE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
            {
                Some(existing) => format!("{existing}; {key}={session_id}"),
                None => format!("{key}={session_id}"),
            };
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&cookie).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid XHTTP session cookie {key:?}: {error}"),
                    )
                })?,
            );
        }
    }

    Ok(builder)
}

fn xhttp_authority(
    settings: &OutboundXhttpClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
) -> String {
    if !settings.host.trim().is_empty() {
        return settings.host.trim().to_string();
    }
    if let Some(server_name) = tls_server_name.filter(|value| !value.is_empty()) {
        return server_name.to_string();
    }
    match server.address() {
        Address::Hostname(host) => host.clone(),
        Address::Ipv4(ip) => ip.to_string(),
        Address::Ipv6(ip) => format!("[{ip}]"),
    }
}

fn xhttp_request_uri(
    settings: &OutboundXhttpClientSettings,
    authority: &str,
    session_id: &str,
) -> io::Result<Uri> {
    let raw_query = settings.path.split_once('?').map(|(_, query)| query);
    let base_path = xhttp_normalized_base_path(settings);
    let (path, query) = match &settings.session_placement {
        OutboundXhttpSessionPlacement::Path => (
            format!("{base_path}{session_id}"),
            raw_query.map(str::to_string),
        ),
        OutboundXhttpSessionPlacement::Query(key) => {
            (base_path, Some(xhttp_query_set(raw_query, key, session_id)))
        }
        OutboundXhttpSessionPlacement::Header(_)
        | OutboundXhttpSessionPlacement::Cookie(_) => {
            (base_path, raw_query.map(str::to_string))
        }
    };
    let uri = match query.filter(|query| !query.is_empty()) {
        Some(query) => format!("https://{authority}{path}?{query}"),
        None => format!("https://{authority}{path}"),
    };
    uri.parse::<Uri>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid XHTTP outbound URI: {error}"),
        )
    })
}

fn xhttp_padding_referer(
    settings: &OutboundXhttpClientSettings,
    authority: &str,
) -> io::Result<String> {
    let padding = if settings.padding_from == settings.padding_to {
        settings.padding_from
    } else {
        rand::rng().random_range(settings.padding_from..=settings.padding_to)
    };
    let padding = "X".repeat(usize::try_from(padding).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XHTTP outbound padding length is invalid",
        )
    })?);
    let path = xhttp_normalized_base_path(settings);
    Ok(format!("https://{authority}{path}?x_padding={padding}"))
}

fn xhttp_normalized_base_path(settings: &OutboundXhttpClientSettings) -> String {
    let path = settings
        .path
        .split_once('?')
        .map_or(settings.path.as_str(), |(path, _)| path);
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    }
}

fn xhttp_query_set(raw_query: Option<&str>, key: &str, value: &str) -> String {
    use std::collections::BTreeMap;

    let mut values = BTreeMap::<String, Vec<String>>::new();
    if let Some(raw_query) = raw_query {
        for pair in raw_query.split('&') {
            if pair.is_empty() || pair.contains(';') {
                continue;
            }
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let Some(decoded_key) = xhttp_query_decode(raw_key) else {
                continue;
            };
            let Some(decoded_value) = xhttp_query_decode(raw_value) else {
                continue;
            };
            values.entry(decoded_key).or_default().push(decoded_value);
        }
    }
    values.insert(key.to_string(), vec![value.to_string()]);

    values
        .into_iter()
        .flat_map(|(key, values)| {
            values.into_iter().map(move |value| {
                format!(
                    "{}={}",
                    xhttp_query_escape(&key),
                    xhttp_query_escape(&value)
                )
            })
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn xhttp_query_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = xhttp_hex_value(bytes[index + 1])?;
                let low = xhttp_hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return None,
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn xhttp_query_escape(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte))
            }
            b' ' => encoded.push('+'),
            byte => {
                use std::fmt::Write as _;
                write!(&mut encoded, "%{byte:02X}")
                    .expect("writing to String cannot fail");
            }
        }
    }
    encoded
}

fn xhttp_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn xhttp_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn set_xhttp_error(
    shared: &Mutex<Option<(io::ErrorKind, String)>>,
    kind: io::ErrorKind,
    message: String,
) {
    let mut guard = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some((kind, message));
    }
}

fn clone_xhttp_error(
    shared: &Mutex<Option<(io::ErrorKind, String)>>,
) -> Option<io::Error> {
    let guard = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .as_ref()
        .map(|(kind, message)| io::Error::new(*kind, message.clone()))
}

fn take_xhttp_error(
    shared: &Mutex<Option<(io::ErrorKind, String)>>,
) -> Option<io::Error> {
    let mut guard = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .take()
        .map(|(kind, message)| io::Error::new(kind, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> OutboundXhttpClientSettings {
        OutboundXhttpClientSettings {
            host: "example.com".to_string(),
            path: "/reverse?existing=1".to_string(),
            headers: Default::default(),
            padding_from: 4,
            padding_to: 4,
            no_grpc_header: false,
            uplink_http_method: "POST".to_string(),
            session_placement: OutboundXhttpSessionPlacement::Path,
        }
    }

    #[test]
    fn path_session_and_legacy_padding_match_xray_shape() {
        let settings = settings();
        let uri = xhttp_request_uri(&settings, "example.com", "session").unwrap();
        assert_eq!(
            uri.to_string(),
            "https://example.com/reverse/session?existing=1"
        );
        assert_eq!(
            xhttp_padding_referer(&settings, "example.com").unwrap(),
            "https://example.com/reverse/?x_padding=XXXX"
        );
    }

    #[test]
    fn host_override_and_custom_headers_match_xray_request_shape() {
        let mut settings = settings();
        settings.host = "cdn.reverse.test".to_string();
        settings
            .headers
            .insert("X-Reverse-Edge".to_string(), "chimera".to_string());
        settings
            .headers
            .insert("User-Agent".to_string(), "edge-probe".to_string());

        assert_eq!(
            xhttp_authority(
                &settings,
                &NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443),
                Some("localhost"),
            ),
            "cdn.reverse.test"
        );

        let referer = xhttp_padding_referer(&settings, "cdn.reverse.test").unwrap();
        let request = apply_xhttp_headers(
            Request::builder()
                .method(Method::GET)
                .uri("https://cdn.reverse.test/reverse/session"),
            &settings,
            &referer,
            "session",
            false,
        )
        .unwrap()
        .body(())
        .unwrap();

        assert_eq!(request.headers().get("X-Reverse-Edge").unwrap(), "chimera");
        assert_eq!(
            request.headers().get(header::USER_AGENT).unwrap(),
            "edge-probe"
        );
        assert_eq!(
            request.headers().get(header::REFERER).unwrap(),
            "https://cdn.reverse.test/reverse/?x_padding=XXXX"
        );
    }

    #[test]
    fn session_metadata_placements_match_xray_shapes() {
        let mut settings = settings();

        settings.session_placement =
            OutboundXhttpSessionPlacement::Query("x_session".to_string());
        settings.path = "/reverse?z=2&a=1".to_string();
        assert_eq!(
            xhttp_request_uri(&settings, "example.com", "session")
                .unwrap()
                .to_string(),
            "https://example.com/reverse/?a=1&x_session=session&z=2"
        );

        settings.session_placement =
            OutboundXhttpSessionPlacement::Header("X-Session".to_string());
        let uri = xhttp_request_uri(&settings, "example.com", "session").unwrap();
        assert_eq!(uri.to_string(), "https://example.com/reverse/?z=2&a=1");
        let request = apply_xhttp_headers(
            Request::builder().method(Method::GET).uri(uri),
            &settings,
            "https://example.com/reverse/?x_padding=XXXX",
            "session",
            false,
        )
        .unwrap()
        .body(())
        .unwrap();
        assert_eq!(request.headers().get("X-Session").unwrap(), "session");

        settings.session_placement =
            OutboundXhttpSessionPlacement::Cookie("x_session".to_string());
        settings
            .headers
            .insert("Cookie".to_string(), "existing=1".to_string());
        let uri = xhttp_request_uri(&settings, "example.com", "session").unwrap();
        let request = apply_xhttp_headers(
            Request::builder().method(Method::GET).uri(uri),
            &settings,
            "https://example.com/reverse/?x_padding=XXXX",
            "session",
            false,
        )
        .unwrap()
        .body(())
        .unwrap();
        assert_eq!(
            request.headers().get(header::COOKIE).unwrap(),
            "existing=1; x_session=session"
        );
    }

    #[test]
    fn session_id_is_uuid_v4_shape() {
        let id = xhttp_session_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
    }
}
