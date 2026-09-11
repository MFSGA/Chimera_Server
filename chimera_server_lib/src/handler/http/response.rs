use std::collections::{BTreeMap, BTreeSet};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::request::{
    canonical_http_header_name, has_invalid_http_header_value, is_http_header_name,
    parse_chunk_size_line, parse_http_content_length,
};
use super::{
    MAX_HEADER_BYTES, MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_HEADER_BYTES,
    read_http_line,
};

pub(crate) async fn relay_plain_http_response<R, W>(
    upstream: &mut R,
    downstream: &mut W,
    request_method: &str,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let status_line =
            read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
        let status_code = parse_http_status_code(&status_line)?;
        let mut header_bytes = 0usize;
        let mut header_lines: Vec<String> = Vec::new();
        let mut headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut content_length = None;
        let mut transfer_encoding = false;
        let mut transfer_encoding_seen = false;
        let mut trailer_names = Vec::new();

        loop {
            let line = read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > MAX_RESPONSE_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP proxy response headers exceed 65536 bytes",
                ));
            }
            if line.is_empty() {
                break;
            }
            if line.starts_with([' ', '\t']) {
                let previous = header_lines.last_mut().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP response header continuation has no preceding field",
                    )
                })?;
                previous.push(' ');
                previous.push_str(line.trim());
            } else {
                header_lines.push(line);
            }
        }

        for line in header_lines {
            let Some((name, value)) = line.split_once(':') else {
                write_http_service_unavailable(downstream).await?;
                return Ok(false);
            };
            if !is_http_header_name(name) {
                continue;
            }
            if has_invalid_http_header_value(value) {
                write_http_service_unavailable(downstream).await?;
                return Ok(false);
            }
            let name = name.to_ascii_lowercase();
            let value = value.trim();
            if name == "connection" {
                connection_hop_headers.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase),
                );
            } else if name == "content-length" {
                let length = match parse_http_content_length(value) {
                    Ok(length) => length,
                    Err(_) => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                };
                match content_length {
                    Some(previous) if previous != length => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                    Some(_) => continue,
                    None => content_length = Some(length),
                }
                headers.push((name, format!("Content-Length: {length}")));
                continue;
            } else if name == "transfer-encoding" {
                if transfer_encoding_seen || !value.eq_ignore_ascii_case("chunked") {
                    write_http_service_unavailable(downstream).await?;
                    return Ok(false);
                }
                transfer_encoding_seen = true;
                transfer_encoding = true;
            } else if name == "trailer" {
                match parse_http_trailer_names(value) {
                    Ok(names) => trailer_names.extend(names),
                    Err(_) => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                }
            }
            headers.push((name, line));
        }

        if (100..200).contains(&status_code) {
            write_http_header_block(downstream, &status_line, &headers).await?;
            continue;
        }

        let no_body = request_method.eq_ignore_ascii_case("HEAD")
            || matches!(status_code, 204 | 304);
        let body_length = if no_body {
            Some(0)
        } else if !transfer_encoding {
            content_length
        } else {
            None
        };

        let mut response_head = format!("{status_line}\r\n");
        for (name, line) in headers {
            let strip_static = matches!(
                name.as_str(),
                "proxy-connection"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "upgrade"
            ) || (name == "transfer-encoding"
                && body_length.is_some());
            if name == "connection"
                || name == "trailer"
                || (body_length.is_some() && name == "keep-alive")
                || (transfer_encoding && name == "content-length")
                || strip_static
                || connection_hop_headers.iter().any(|hop| hop == &name)
            {
                continue;
            }
            response_head.push_str(&line);
            response_head.push_str("\r\n");
        }
        if transfer_encoding && !trailer_names.is_empty() {
            let names = trailer_names
                .iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|name| canonical_http_header_name(name))
                .collect::<Vec<_>>()
                .join(",");
            response_head.push_str("Trailer: ");
            response_head.push_str(&names);
            response_head.push_str("\r\n");
        }
        if body_length.is_some() {
            response_head.push_str(
                "Connection: keep-alive\r\n\
                 Keep-Alive: timeout=60\r\n\
                 Proxy-Connection: keep-alive\r\n",
            );
        } else {
            response_head.push_str("Connection: close\r\n");
        }
        response_head.push_str("\r\n");
        downstream.write_all(response_head.as_bytes()).await?;

        if let Some(length) = body_length {
            let mut body = upstream.take(length);
            let copied = tokio::io::copy(&mut body, downstream).await?;
            if copied != length {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP proxy upstream response body ended early",
                ));
            }
        } else if transfer_encoding {
            relay_chunked_http_response_body(upstream, downstream, &trailer_names)
                .await?;
        } else {
            tokio::io::copy(upstream, downstream).await?;
        }
        downstream.flush().await?;
        return Ok(body_length.is_some());
    }
}

async fn relay_chunked_http_response_body<R, W>(
    upstream: &mut R,
    downstream: &mut W,
    trailer_names: &[String],
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const REENCODE_BUFFER_SIZE: usize = 32 * 1024;

    let mut decoded = Vec::with_capacity(REENCODE_BUFFER_SIZE);
    loop {
        let chunk_size_line =
            match read_http_line(upstream, MAX_REQUEST_LINE_BYTES).await {
                Ok(line) => line,
                Err(error) => {
                    write_reencoded_chunk(downstream, &mut decoded).await?;
                    return Err(error);
                }
            };
        let chunk_size = match parse_chunk_size_line(chunk_size_line.as_bytes()) {
            Ok(size) => size,
            Err(error) => {
                write_reencoded_chunk(downstream, &mut decoded).await?;
                return Err(error);
            }
        };

        if chunk_size == 0 {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            let trailers =
                read_chunked_response_trailers(upstream, trailer_names).await?;
            downstream.write_all(b"0\r\n").await?;
            for trailer in trailers {
                downstream.write_all(trailer.as_bytes()).await?;
                downstream.write_all(b"\r\n").await?;
            }
            downstream.write_all(b"\r\n").await?;
            return Ok(());
        }

        let mut remaining = chunk_size;
        while remaining != 0 {
            let available = REENCODE_BUFFER_SIZE - decoded.len();
            let read_len = available.min(remaining.min(usize::MAX as u64) as usize);
            let start = decoded.len();
            decoded.resize(start + read_len, 0);
            let read = upstream.read(&mut decoded[start..]).await?;
            if read == 0 {
                decoded.truncate(start);
                write_reencoded_chunk(downstream, &mut decoded).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP chunked response body ended early",
                ));
            }
            decoded.truncate(start + read);
            remaining -= read as u64;
            if decoded.len() == REENCODE_BUFFER_SIZE {
                write_reencoded_chunk(downstream, &mut decoded).await?;
            }
        }

        let mut chunk_terminator = [0u8; 2];
        if let Err(error) = upstream.read_exact(&mut chunk_terminator).await {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            return Err(error);
        }
        if chunk_terminator != *b"\r\n" {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP chunk data terminator",
            ));
        }
    }
}

fn parse_http_trailer_names(value: &str) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for name in value.split(',').map(str::trim) {
        if !is_http_header_name(name)
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "trailer"
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP response trailer declaration",
            ));
        }
        names.push(name.to_ascii_lowercase());
    }
    Ok(names)
}

async fn read_chunked_response_trailers<R>(
    upstream: &mut R,
    trailer_names: &[String],
) -> std::io::Result<Vec<String>>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = 0usize;
    let mut trailers: Vec<String> = Vec::new();
    loop {
        let line = read_http_line(upstream, MAX_HEADER_BYTES).await?;
        header_bytes = header_bytes.saturating_add(line.len() + 2);
        if header_bytes > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP chunked response trailers exceed 16384 bytes",
            ));
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let previous = trailers.last_mut().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response trailer continuation has no preceding field",
                )
            })?;
            previous.push(' ');
            previous.push_str(line.trim());
        } else {
            trailers.push(line);
        }
    }

    let mut forwarded: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for trailer in trailers {
        let Some((name, value)) = trailer.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP response trailer line",
            ));
        };
        if !is_http_header_name(name) {
            continue;
        }
        if has_invalid_http_header_value(value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid control character in HTTP response trailer value",
            ));
        }
        if trailer_names
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(name))
        {
            forwarded
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }
    Ok(forwarded
        .into_iter()
        .flat_map(|(name, values)| {
            let name = canonical_http_header_name(&name);
            values
                .into_iter()
                .map(move |value| format!("{name}: {value}"))
        })
        .collect())
}

async fn write_reencoded_chunk<W>(
    downstream: &mut W,
    decoded: &mut Vec<u8>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if decoded.is_empty() {
        return Ok(());
    }
    downstream
        .write_all(format!("{:x}\r\n", decoded.len()).as_bytes())
        .await?;
    downstream.write_all(decoded).await?;
    downstream.write_all(b"\r\n").await?;
    decoded.clear();
    Ok(())
}

fn parse_http_status_code(status_line: &str) -> std::io::Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status line: {status_line}"),
        ));
    }
    status.parse::<u16>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status code {status}: {error}"),
        )
    })
}

async fn write_http_service_unavailable<W>(writer: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\n\
              Connection: close\r\n\
              Proxy-Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    writer.flush().await
}

async fn write_http_header_block<W>(
    writer: &mut W,
    status_line: &str,
    headers: &[(String, String)],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(status_line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    for (_, line) in headers {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.write_all(b"\r\n").await
}
