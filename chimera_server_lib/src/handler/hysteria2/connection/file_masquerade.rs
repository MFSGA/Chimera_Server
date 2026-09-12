use std::{
    io::{Error, ErrorKind},
    path::{Component, Path, PathBuf},
};

use bytes::Bytes;
use http::{Response, StatusCode};
use tracing::debug;

use super::{auth_reject_response, hex_nibble};

pub(super) async fn xray_file_masquerade_response(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    root: &str,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let Some(decoded_uri_path) = xray_file_percent_decode_path_bytes(uri.path())
    else {
        return auth_reject_response(true);
    };
    if decoded_uri_path.ends_with(b"/index.html") {
        return xray_file_redirect_response(uri, "./");
    }

    let Some(relative) =
        decode_file_masquerade_decoded_path_bytes(&decoded_uri_path, cfg!(windows))
    else {
        return auth_reject_response(true);
    };
    let mut path = PathBuf::from(root);
    if !relative.as_os_str().is_empty() {
        path.push(relative);
    }

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(err) => return xray_file_server_error_response(&err),
    };

    if metadata.is_dir() {
        let directory_modified = metadata.modified().ok();
        if !decoded_uri_path.ends_with(b"/") {
            let base = xray_file_path_base_bytes(&decoded_uri_path);
            let mut location = Vec::with_capacity(base.len() + 1);
            location.extend_from_slice(base);
            location.push(b'/');
            return xray_file_redirect_response_bytes(uri, &location);
        }
        let index = path.join("index.html");
        match tokio::fs::metadata(&index).await {
            Ok(index_metadata) if index_metadata.is_file() => path = index,
            Ok(index_metadata) if index_metadata.is_dir() => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &index,
                    index_metadata.modified().ok(),
                )
                .await;
            }
            Ok(_) => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &path,
                    directory_modified,
                )
                .await;
            }
            Err(_) => {
                return xray_file_directory_response(
                    method,
                    request_headers,
                    &path,
                    directory_modified,
                )
                .await;
            }
        }
    } else if metadata.is_file() {
        if decoded_uri_path.ends_with(b"/") {
            let base = xray_file_path_base_bytes(&decoded_uri_path);
            if base.is_empty() || base == b"." {
                return xray_file_non_directory_traversal_response();
            }
            let mut location = Vec::with_capacity(base.len() + 3);
            location.extend_from_slice(b"../");
            location.extend_from_slice(base);
            return xray_file_redirect_response_bytes(uri, &location);
        }
    } else {
        return auth_reject_response(true);
    }

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(err) => return xray_file_server_error_response(&err),
    };
    let modified = metadata.modified().ok();
    let last_modified = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date);
    if let Some(status) =
        xray_file_precondition_status(method, request_headers, modified)
    {
        let mut response = Response::builder().status(status);
        if let Some(last_modified) = last_modified.as_deref() {
            response = response.header(http::header::LAST_MODIFIED, last_modified);
        }
        return Ok((response.body(()).map_err(Error::other)?, None));
    }

    let body = match tokio::fs::read(&path).await {
        Ok(body) => body,
        Err(err) => return xray_file_server_error_response(&err),
    };
    let content_type = if let Some(content_type) =
        xray_file_extension_content_type(&path)
    {
        content_type.to_string()
    } else {
        match mime_guess::from_path(&path).first() {
            Some(guessed_type) if guessed_type.type_() == mime_guess::mime::TEXT => {
                format!("{}; charset=utf-8", guessed_type.essence_str())
            }
            Some(guessed_type) => guessed_type.essence_str().to_string(),
            None => {
                xray_detect_content_type(&body[..body.len().min(512)]).to_string()
            }
        }
    };
    let range_header = request_headers
        .get(http::header::RANGE)
        .filter(|_| xray_if_range_matches(method, request_headers, modified));
    let mut ranges = match range_header {
        Some(value) => match xray_parse_ranges(value.as_bytes(), body.len()) {
            Ok(ranges) => ranges,
            Err(XrayRangeError::NoOverlap) if body.is_empty() => Vec::new(),
            Err(err) => return xray_range_error_response(err, body.len()),
        },
        None => Vec::new(),
    };
    if ranges.iter().map(|range| range.length).sum::<usize>() > body.len() {
        ranges.clear();
    }

    let (status, response_body, content_range, response_content_type) = match ranges
        .as_slice()
    {
        [] => (StatusCode::OK, Bytes::from(body), None, content_type),
        [range] => {
            let end = range.start + range.length;
            (
                StatusCode::PARTIAL_CONTENT,
                Bytes::copy_from_slice(&body[range.start..end]),
                Some(format!("bytes {}-{}/{}", range.start, end - 1, body.len())),
                content_type,
            )
        }
        _ => {
            let (multipart_body, multipart_content_type) =
                xray_multipart_ranges(&ranges, &body, &content_type);
            (
                StatusCode::PARTIAL_CONTENT,
                multipart_body,
                None,
                multipart_content_type,
            )
        }
    };

    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, response_content_type)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(
            http::header::CONTENT_LENGTH,
            response_body.len().to_string(),
        );
    if let Some(content_range) = content_range {
        response = response.header(http::header::CONTENT_RANGE, content_range);
    }
    if let Some(last_modified) = last_modified.as_deref() {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    let response = response.body(()).map_err(Error::other)?;
    Ok((response, Some(response_body)))
}

fn xray_file_non_directory_traversal_response()
-> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::from_static(b"http: attempting to traverse a non-directory\n");
    let response = Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(Error::other)?;
    Ok((response, Some(body)))
}

fn xray_file_directory_error_response(
    modified: Option<std::time::SystemTime>,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::from_static(b"Error reading directory\n");
    let mut response = Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if let Some(last_modified) = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date)
    {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}

pub(super) fn xray_file_server_error_response(
    err: &std::io::Error,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) {
        return auth_reject_response(true);
    }

    let (status, body) = if err.kind() == ErrorKind::PermissionDenied {
        (
            StatusCode::FORBIDDEN,
            Bytes::from_static(b"403 Forbidden\n"),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from_static(b"500 Internal Server Error\n"),
        )
    };
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(Error::other)?;
    Ok((response, Some(body)))
}

pub(super) fn xray_file_precondition_status(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    modified: Option<std::time::SystemTime>,
) -> Option<StatusCode> {
    let if_match = request_headers
        .get(http::header::IF_MATCH)
        .filter(|value| !value.as_bytes().is_empty());
    if let Some(if_match) = if_match {
        // Xray's FileServer does not set ETag, so only If-Match: * can match.
        if !xray_etag_list_has_wildcard(if_match.as_bytes()) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let Some(value) = request_headers
        .get(http::header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && !xray_modified_not_after(modified, since)
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }

    let if_none_match = request_headers
        .get(http::header::IF_NONE_MATCH)
        .filter(|value| !value.as_bytes().is_empty());
    if let Some(if_none_match) = if_none_match {
        // With no server ETag, only the wildcard matches the existing file.
        if xray_etag_list_has_wildcard(if_none_match.as_bytes()) {
            return Some(
                if matches!(*method, http::Method::GET | http::Method::HEAD) {
                    StatusCode::NOT_MODIFIED
                } else {
                    StatusCode::PRECONDITION_FAILED
                },
            );
        }
    } else if matches!(*method, http::Method::GET | http::Method::HEAD)
        && let Some(value) = request_headers
            .get(http::header::IF_MODIFIED_SINCE)
            .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && xray_modified_not_after(modified, since)
    {
        return Some(StatusCode::NOT_MODIFIED);
    }

    None
}

mod ranges;
pub(super) use ranges::*;

pub(super) fn xray_file_extension_content_type(path: &Path) -> Option<&'static str> {
    // Keep only the Go builtin MIME entries that differ from mime_guess 2.0.5.
    let extension = path.extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("com") {
        Some("application/octet-stream")
    } else if extension.eq_ignore_ascii_case("docx") {
        Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    } else if extension.eq_ignore_ascii_case("ehtml") {
        Some("text/html; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("ico") {
        Some("image/vnd.microsoft.icon")
    } else if extension.eq_ignore_ascii_case("m4a") {
        Some("audio/mp4")
    } else if extension.eq_ignore_ascii_case("mjs") {
        Some("text/javascript; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("pjp")
        || extension.eq_ignore_ascii_case("pjpeg")
    {
        Some("image/jpeg")
    } else if extension.eq_ignore_ascii_case("pptx") {
        Some(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
    } else if extension.eq_ignore_ascii_case("webm") {
        Some("audio/webm")
    } else if extension.eq_ignore_ascii_case("xbl") {
        Some("text/xml; charset=utf-8")
    } else if extension.eq_ignore_ascii_case("xlsx") {
        Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    } else {
        None
    }
}

pub(super) fn xray_detect_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(512)];
    let first_non_ws = data
        .iter()
        .position(|byte| !matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' '))
        .unwrap_or(data.len());
    let trimmed = &data[first_non_ws..];

    const HTML_SIGNATURES: &[&[u8]] = &[
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    if HTML_SIGNATURES.iter().any(|signature| {
        trimmed.len() > signature.len()
            && trimmed[..signature.len()].eq_ignore_ascii_case(signature)
            && matches!(trimmed[signature.len()], b' ' | b'>')
    }) {
        return "text/html; charset=utf-8";
    }
    if trimmed.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }

    const EXACT_SIGNATURES: &[(&[u8], &str)] = &[
        (b"%PDF-", "application/pdf"),
        (b"%!PS-Adobe-", "application/postscript"),
        (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"\x00\x00\x02\x00", "image/x-icon"),
        (b"BM", "image/bmp"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"ID3", "audio/mpeg"),
        (b"OggS\x00", "application/ogg"),
        (b"MThd\x00\x00\x00\x06", "audio/midi"),
        (b"\x1a\x45\xdf\xa3", "video/webm"),
        (b"\x00\x01\x00\x00", "font/ttf"),
        (b"OTTO", "font/otf"),
        (b"ttcf", "font/collection"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"\x1f\x8b\x08", "application/x-gzip"),
        (b"PK\x03\x04", "application/zip"),
        (b"Rar!\x1a\x07\x00", "application/x-rar-compressed"),
        (b"Rar!\x1a\x07\x01\x00", "application/x-rar-compressed"),
        (b"\x00asm", "application/wasm"),
    ];
    if let Some((_, content_type)) = EXACT_SIGNATURES
        .iter()
        .find(|(signature, _)| data.starts_with(signature))
    {
        return content_type;
    }

    if data.len() >= 4 && data.starts_with(b"\xfe\xff") {
        return "text/plain; charset=utf-16be";
    }
    if data.len() >= 4 && data.starts_with(b"\xff\xfe") {
        return "text/plain; charset=utf-16le";
    }
    if data.len() >= 4 && data.starts_with(b"\xef\xbb\xbf") {
        return "text/plain; charset=utf-8";
    }
    if data.len() >= 14 && data.starts_with(b"RIFF") && &data[8..14] == b"WEBPVP" {
        return "image/webp";
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") {
        if &data[8..12] == b"AVI " {
            return "video/avi";
        }
        if &data[8..12] == b"WAVE" {
            return "audio/wave";
        }
    }
    if data.len() >= 12 && data.starts_with(b"FORM") && &data[8..12] == b"AIFF" {
        return "audio/aiff";
    }
    if data.len() >= 36 && &data[34..36] == b"LP" {
        return "application/vnd.ms-fontobject";
    }
    if data.len() >= 12 {
        let box_size =
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if box_size >= 12
            && box_size <= data.len()
            && box_size.is_multiple_of(4)
            && &data[4..8] == b"ftyp"
            && (8..box_size)
                .step_by(4)
                .filter(|offset| *offset != 12)
                .any(|offset| data.get(offset..offset + 3) == Some(b"mp4"))
        {
            return "video/mp4";
        }
    }

    if data[first_non_ws..].iter().all(|byte| {
        !matches!(
            *byte,
            0x00..=0x08 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f
        )
    }) {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn xray_file_redirect_response(
    uri: &http::Uri,
    location: &str,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    xray_file_redirect_response_bytes(uri, location.as_bytes())
}

fn xray_file_redirect_response_bytes(
    uri: &http::Uri,
    location: &[u8],
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let mut location_with_query = Vec::with_capacity(
        location.len() + uri.query().map_or(0, |query| query.len() + 1),
    );
    location_with_query.extend_from_slice(location);
    if let Some(query) = uri.query() {
        location_with_query.push(b'?');
        location_with_query.extend_from_slice(query.as_bytes());
    }
    let location = xray_file_hex_escape_non_ascii_bytes(&location_with_query);
    let response = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(http::header::LOCATION, location)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(Error::other)?;
    Ok((response, None))
}

pub(super) async fn xray_file_directory_response(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    path: &Path,
    modified: Option<std::time::SystemTime>,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if matches!(*method, http::Method::GET | http::Method::HEAD)
        && let Some(value) = request_headers
            .get(http::header::IF_MODIFIED_SINCE)
            .and_then(|value| value.to_str().ok())
        && let Some(since) = xray_parse_http_date(value)
        && let Some(modified) = modified
        && !xray_is_zero_modtime(modified)
        && xray_modified_not_after(modified, since)
    {
        let response = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(())
            .map_err(Error::other)?;
        return Ok((response, None));
    }

    let mut read_dir = match tokio::fs::read_dir(path).await {
        Ok(read_dir) => read_dir,
        Err(err) => {
            debug!(error = %err, path = %path.display(), "Xray file masquerade directory read failed");
            return xray_file_directory_error_response(modified);
        }
    };
    let mut entries = Vec::new();
    loop {
        let entry = match read_dir.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(err) => {
                debug!(error = %err, path = %path.display(), "Xray file masquerade directory iteration failed");
                return xray_file_directory_error_response(modified);
            }
        };
        let file_type = match entry.file_type().await {
            Ok(file_type) => file_type,
            Err(err) if xray_file_directory_entry_disappeared(&err) => continue,
            Err(err) => {
                debug!(error = %err, path = %path.display(), "Xray file masquerade directory entry stat failed");
                return xray_file_directory_error_response(modified);
            }
        };
        let file_name = entry.file_name();
        let mut name = xray_file_name_bytes(&file_name);
        if file_type.is_dir() {
            name.push(b'/');
        }
        entries.push(name);
    }
    entries.sort_unstable();

    let mut body = Vec::from(
        &b"<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n"[..],
    );
    for name in entries {
        body.extend_from_slice(b"<a href=\"");
        body.extend_from_slice(xray_file_url_escape_bytes(&name).as_bytes());
        body.extend_from_slice(b"\">");
        body.extend_from_slice(&xray_file_html_escape_bytes(&name));
        body.extend_from_slice(b"</a>\n");
    }
    body.extend_from_slice(b"</pre>\n");
    let body = Bytes::from(body);
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if let Some(last_modified) = modified
        .filter(|modified| !xray_is_zero_modtime(*modified))
        .map(xray_format_http_date)
    {
        response = response.header(http::header::LAST_MODIFIED, last_modified);
    }
    let response = response.body(()).map_err(Error::other)?;
    Ok((response, Some(body)))
}

pub(super) fn xray_file_directory_entry_disappeared(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::NotFound
}

fn xray_file_name_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }

    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn xray_file_html_escape_bytes(value: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'&' => escaped.extend_from_slice(b"&amp;"),
            b'\'' => escaped.extend_from_slice(b"&#39;"),
            b'<' => escaped.extend_from_slice(b"&lt;"),
            b'>' => escaped.extend_from_slice(b"&gt;"),
            b'"' => escaped.extend_from_slice(b"&#34;"),
            byte => escaped.push(byte),
        }
    }
    escaped
}

pub(super) fn xray_file_url_escape(value: &str) -> String {
    xray_file_url_escape_bytes(value.as_bytes())
}

fn xray_file_url_escape_bytes(value: &[u8]) -> String {
    let mut escaped = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'/'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            )
        {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

fn decode_file_masquerade_path(uri_path: &str) -> Option<PathBuf> {
    decode_file_masquerade_path_for_platform(uri_path, cfg!(windows))
}

pub(super) fn decode_file_masquerade_path_for_platform(
    uri_path: &str,
    windows: bool,
) -> Option<PathBuf> {
    let decoded = xray_file_percent_decode_path_bytes(uri_path)?;
    decode_file_masquerade_decoded_path_bytes(&decoded, windows)
}

fn xray_file_percent_decode_path_bytes(uri_path: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(uri_path.len());
    let bytes = uri_path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_nibble(high)? << 4) | hex_nibble(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

fn decode_file_masquerade_decoded_path_bytes(
    decoded: &[u8],
    windows: bool,
) -> Option<PathBuf> {
    if windows {
        let decoded = std::str::from_utf8(decoded).ok()?;
        if decoded
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b':' | b'\\' | 0))
        {
            return None;
        }
        if decoded.split('/').any(xray_windows_reserved_path_component) {
            return None;
        }
        return xray_file_normalize_utf8_path(decoded);
    }

    #[cfg(unix)]
    {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        if decoded.contains(&0) {
            return None;
        }
        let mut normalized = PathBuf::new();
        for component in decoded.split(|byte| *byte == b'/') {
            match component {
                b"" | b"." => {}
                b".." => {
                    normalized.pop();
                }
                component => normalized.push(OsStr::from_bytes(component)),
            }
        }
        Some(normalized)
    }

    #[cfg(not(unix))]
    {
        let decoded = std::str::from_utf8(decoded).ok()?;
        xray_file_normalize_utf8_path(decoded)
    }
}

fn xray_file_normalize_utf8_path(decoded: &str) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in Path::new(decoded.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn xray_file_hex_escape_non_ascii(value: &str) -> String {
    xray_file_hex_escape_non_ascii_bytes(value.as_bytes())
}

fn xray_file_hex_escape_non_ascii_bytes(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii() {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

fn xray_file_path_base_bytes(path: &[u8]) -> &[u8] {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.rsplit(|byte| *byte == b'/').next().unwrap_or_default()
}

fn xray_windows_reserved_path_component(component: &str) -> bool {
    let upper = component.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }

    let Some(suffix) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    matches!(
        suffix,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
    )
}
