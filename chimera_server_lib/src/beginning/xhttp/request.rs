use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, Request, StatusCode, body::Body, header};
use rand::RngExt;

use crate::config::server_config::{
    XhttpDataPlacement, XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement,
    XhttpPlacement,
};

pub(super) fn normalize_base_path(
    mut path: String,
    session_placement: XhttpPlacement,
    seq_placement: XhttpPlacement,
) -> String {
    if let Some(query_index) = path.find('?') {
        path.truncate(query_index);
    }
    if path.is_empty() || !path.starts_with('/') {
        path.insert(0, '/');
    }
    if (session_placement == XhttpPlacement::Path
        || seq_placement == XhttpPlacement::Path)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

pub(super) fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    for pair in query?.split('&') {
        // Go's url.ParseQuery rejects a value containing an unescaped semicolon
        // and URL.Query silently discards that malformed pair. Percent-encoded
        // semicolons remain valid data because the rejection happens first.
        if pair.contains(';') {
            continue;
        }
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(name) = decode_query_component(raw_name) else {
            continue;
        };
        if name != key {
            continue;
        }
        let Some(value) = decode_query_component(raw_value) else {
            continue;
        };
        return (!value.is_empty()).then_some(value);
    }
    None
}

pub(super) fn decode_query_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).ok()
}

pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn header_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn trusted_forwarded_peer(
    headers: &hyper::HeaderMap,
    trusted_x_forwarded_for: &[String],
) -> Option<std::net::SocketAddr> {
    if trusted_x_forwarded_for.is_empty()
        || !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(header))
    {
        return None;
    }

    let first = headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()?;
    let mut candidate = first;
    if candidate.starts_with('[') && candidate.ends_with(']') {
        candidate = &candidate[1..candidate.len() - 1];
    }
    if candidate
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || candidate
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        candidate = candidate.trim();
    }

    let ip = candidate.parse::<std::net::IpAddr>().ok()?;
    let ip = match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ipv6), std::net::IpAddr::V4),
        ip => ip,
    };
    Some(std::net::SocketAddr::new(ip, 0))
}

pub(super) fn cookie_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(header_value) = header_value.to_str() else {
            continue;
        };
        for cookie in header_value.split(';') {
            let Some((name, raw_value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name != key {
                continue;
            }
            let Some(value) = parse_cookie_value_like_go(raw_value) else {
                continue;
            };
            // Go's Request.Cookie returns the first successfully parsed cookie
            // with this name. An empty first value therefore means "missing"
            // to XHTTP and must not fall through to a later duplicate.
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

pub(super) fn parse_cookie_value_like_go(raw: &str) -> Option<String> {
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    if value.bytes().all(|byte| {
        (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b';' && byte != b'\\'
    }) {
        Some(value.to_string())
    } else {
        None
    }
}

pub(super) fn has_uplink_marker(
    headers: &hyper::HeaderMap,
    placement: XhttpDataPlacement,
    key: &str,
) -> bool {
    match placement {
        XhttpDataPlacement::Header => {
            header_value(headers, &format!("{key}-Upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Cookie => {
            cookie_value(headers, &format!("{key}_upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body => false,
    }
}

pub(super) fn decode_chunked_header_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let header_name = format!("{key}-{index}");
        let Some(chunk) = header_value(headers, &header_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

pub(super) fn decode_chunked_cookie_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let cookie_name = format!("{key}_{index}");
        let Some(chunk) = cookie_value(headers, &cookie_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

pub(super) fn payload_exceeds_post_limit(
    payload_len: usize,
    max_bytes: i64,
) -> bool {
    i64::try_from(payload_len).unwrap_or(i64::MAX) > max_bytes
}

pub(super) fn declared_body_length_exceeds_post_limit(
    data_placement: XhttpDataPlacement,
    headers: &hyper::HeaderMap,
    max_bytes: i64,
) -> bool {
    if !matches!(
        data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        return false;
    }

    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| i128::from(length) > i128::from(max_bytes))
}

pub(super) async fn collect_body_limited<B>(
    mut body: B,
    max_bytes: usize,
) -> Result<Vec<u8>, StatusCode>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut payload = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(chunk) = frame.data_ref() {
            let next_len = payload.len().saturating_add(chunk.len());
            if next_len > max_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            payload.extend_from_slice(chunk);
        }
    }
    Ok(payload)
}

pub(super) fn decode_xhttp_payload(encoded: &str) -> std::io::Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid XHTTP uplink payload encoding: {error}"),
        )
    })
}

pub(super) fn matches_base_path(request_path: &str, base_path: &str) -> bool {
    request_path.starts_with(base_path)
}

pub(super) fn xray_path_metadata_value_for_placement(
    path_tail: &str,
    path_part: &mut usize,
    placement: XhttpPlacement,
) -> Option<String> {
    if placement != XhttpPlacement::Path {
        return None;
    }
    let value = xray_path_metadata_value(path_tail, *path_part);
    *path_part += 1;
    value
}

pub(super) fn xray_path_metadata_value(
    path_tail: &str,
    index: usize,
) -> Option<String> {
    path_tail
        .split('/')
        .nth(index)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn decode_xray_url_path(raw_path: &str) -> Result<String, ()> {
    if !raw_path.as_bytes().contains(&b'%') {
        return Ok(raw_path.to_string());
    }

    let bytes = raw_path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = hex_value(bytes[index + 1]).ok_or(())?;
        let low = hex_value(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }

    String::from_utf8(decoded).or_else(|_| Ok(raw_path.to_string()))
}

pub(super) fn extract_xray_request_padding(
    obfs_mode: bool,
    padding_key: &str,
    padding_header: &str,
    padding_placement: XhttpPaddingPlacement,
    path_query: Option<&str>,
    headers: &hyper::HeaderMap,
) -> Option<String> {
    if !obfs_mode {
        if let Some(referer) = header_value(headers, "referer") {
            // Xray v26.2.6 returns immediately when url.Parse succeeds, even
            // if Referer does not contain x_padding. Only a parse failure falls
            // through to the configurable cookie/header/query extraction below.
            if xray_url_parse_succeeds(&referer) {
                return query_value_from_url(&referer, "x_padding");
            }
        } else {
            return query_value(path_query, "x_padding");
        }
    }

    cookie_value(headers, padding_key)
        .or_else(|| {
            header_value(headers, padding_header).and_then(|value| {
                match padding_placement {
                    XhttpPaddingPlacement::Header => Some(value),
                    _ => query_value_from_url(&value, padding_key),
                }
            })
        })
        .or_else(|| query_value(path_query, padding_key))
}

pub(super) fn xray_url_parse_succeeds(raw_url: &str) -> bool {
    let bytes = raw_url.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] < b' ' || bytes[index] == 0x7f {
            return false;
        }
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || hex_value(bytes[index + 1]).is_none()
            || hex_value(bytes[index + 2]).is_none()
        {
            return false;
        }
        index += 3;
    }
    true
}

pub(super) fn query_value_from_url(raw_url: &str, key: &str) -> Option<String> {
    if !xray_url_parse_succeeds(raw_url) {
        return None;
    }
    let query = raw_url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    query_value(Some(query), key)
}

pub(super) fn request_head_bytes<B>(request: &Request<B>) -> usize {
    // XHTTP's HTTP/1 paths use HTTP/1.0 or HTTP/1.1; both protocol tokens are
    // eight bytes long and count against Go net/http's MaxHeaderBytes budget.
    let request_line_bytes = request
        .method()
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(request.uri().to_string().len())
        .saturating_add(1)
        .saturating_add(8)
        .saturating_add(2);

    request.headers().iter().fold(
        request_line_bytes.saturating_add(2),
        |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(2)
                .saturating_add(value.as_bytes().len())
                .saturating_add(2)
        },
    )
}

pub(super) fn random_xray_range(from: usize, to: usize) -> usize {
    let low = from.min(to);
    let high = from.max(to);
    if low == high {
        low
    } else {
        // Xray's crypto.RandBetween swaps reversed bounds and samples [from, to).
        rand::rng().random_range(low..high)
    }
}

pub(super) fn is_padding_valid(
    padding: &str,
    min_padding: usize,
    max_padding: usize,
    method: XhttpPaddingMethod,
) -> bool {
    if padding.is_empty() {
        return false;
    }

    match method {
        XhttpPaddingMethod::RepeatX => {
            padding.len() >= min_padding && padding.len() <= max_padding
        }
        XhttpPaddingMethod::Tokenish => {
            let encoded_len = hpack_huffman_encoded_len(padding);
            encoded_len >= min_padding.saturating_sub(2)
                && encoded_len <= max_padding.saturating_add(2)
        }
    }
}

pub(super) fn generate_padding(
    method: XhttpPaddingMethod,
    target_len: usize,
) -> String {
    match method {
        XhttpPaddingMethod::RepeatX => "X".repeat(target_len),
        XhttpPaddingMethod::Tokenish => generate_tokenish_padding(target_len),
    }
}

pub(super) fn generate_tokenish_padding(target_len: usize) -> String {
    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if target_len == 0 {
        return String::new();
    }

    let initial_len = target_len.saturating_mul(5).div_ceil(4).max(1);
    let mut rng = rand::rng();
    let mut padding = String::with_capacity(initial_len + 4);
    for _ in 0..initial_len {
        let index = rng.random_range(0..BASE62.len());
        padding.push(BASE62[index] as char);
    }
    drop(rng);

    let mut adjust_char = 'X';
    for _ in 0..150 {
        let current_len = hpack_huffman_encoded_len(&padding);
        if current_len.abs_diff(target_len) <= 2 {
            return padding;
        }
        if current_len < target_len {
            padding.push(adjust_char);
            adjust_char = if adjust_char == 'X' { 'Z' } else { 'X' };
        } else if padding.pop().is_none() {
            break;
        }
    }
    padding
}

pub(super) fn hpack_huffman_encoded_len(value: &str) -> usize {
    let bits = value.bytes().fold(0usize, |total, byte| {
        total.saturating_add(hpack_huffman_bit_len(byte))
    });
    bits.div_ceil(8)
}

pub(super) fn hpack_huffman_bit_len(byte: u8) -> usize {
    match byte {
        b'0' | b'1' | b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'B'..=b'W' | b'Y' | b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
        b'X' | b'Z' => 8,
        _ => 8,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum XhttpRequestDispatch {
    StreamDown,
    StreamOne,
    StreamUp,
    PacketUp,
}

pub(super) fn is_xray_uplink_request(method: &Method, has_seq: bool) -> bool {
    method != Method::GET || has_seq
}

pub(super) fn classify_request(
    mode: XhttpMode,
    is_get: bool,
    is_uplink_method: bool,
    has_session_id: bool,
    has_seq: bool,
) -> Result<XhttpRequestDispatch, StatusCode> {
    if !has_session_id && mode == XhttpMode::PacketUp {
        return Err(StatusCode::BAD_REQUEST);
    }

    if is_uplink_method && has_session_id {
        if !has_seq {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::StreamUp) {
                return Err(StatusCode::BAD_REQUEST);
            }
            return Ok(XhttpRequestDispatch::StreamUp);
        }

        if !matches!(mode, XhttpMode::Auto | XhttpMode::PacketUp) {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(XhttpRequestDispatch::PacketUp);
    }

    if is_get || !has_session_id {
        return Ok(if has_session_id {
            XhttpRequestDispatch::StreamDown
        } else {
            XhttpRequestDispatch::StreamOne
        });
    }

    Err(StatusCode::METHOD_NOT_ALLOWED)
}
