use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WebsocketRequestLineError {
    Malformed,
    UnsupportedVersion,
}

pub(super) fn parse_xray_websocket_request_line(
    line: &str,
) -> Result<(&str, &str, bool), WebsocketRequestLineError> {
    let (method, rest) = line
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (request_target, version) = rest
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if method.is_empty()
        || !method.bytes().all(is_http_method_token_byte)
        || request_target.is_empty()
        || version.is_empty()
        || request_target
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || !xray_websocket_request_target_has_valid_form(request_target)
        || version.bytes().any(|byte| byte.is_ascii_whitespace())
        || xray_websocket_absolute_authority_has_malformed_escape(request_target)
        || xray_websocket_absolute_authority_has_invalid_bracketed_host(
            request_target,
        )
        || xray_websocket_absolute_authority_has_invalid_userinfo_character(
            request_target,
        )
        || xray_websocket_absolute_authority_has_invalid_host_character(
            request_target,
        )
        || xray_websocket_absolute_authority_has_invalid_port(request_target)
    {
        return Err(WebsocketRequestLineError::Malformed);
    }

    let version = version
        .strip_prefix("HTTP/")
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if major.len() != 1
        || minor.len() != 1
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WebsocketRequestLineError::Malformed);
    }
    if major != "1" {
        return Err(WebsocketRequestLineError::UnsupportedVersion);
    }

    Ok((method, request_target, minor != "0"))
}

pub(super) fn valid_xray_host_header(host: &str) -> bool {
    host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b'-'
                    | b'.'
                    | b':'
                    | b';'
                    | b'='
                    | b'['
                    | b']'
                    | b'_'
                    | b'~'
            )
    })
}

fn xray_websocket_request_target_has_valid_form(request_target: &str) -> bool {
    if request_target == "*" || request_target.starts_with('/') {
        return true;
    }

    let Some(colon) = request_target.find(':') else {
        return false;
    };
    let scheme = &request_target[..colon];
    !scheme.is_empty()
        && scheme.as_bytes()[0].is_ascii_alphabetic()
        && scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
}

fn xray_websocket_absolute_authority_has_malformed_escape(
    request_target: &str,
) -> bool {
    let Some(scheme_end) = request_target.find("://") else {
        return false;
    };
    let scheme = &request_target[..scheme_end];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
    {
        return false;
    }

    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, host) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(userinfo, host)| (Some(userinfo), host));

    if userinfo.is_some_and(has_malformed_percent_escape) {
        return true;
    }

    let bytes = host.as_bytes();
    let zone_start = host
        .strip_prefix('[')
        .and_then(|bracketed| bracketed.find(']'))
        .and_then(|closing| host[..=closing].find("%25"))
        .map(|index| index + 3);
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return true;
        }
        let Some(high) = decode_hex_nibble(bytes[index + 1]) else {
            return true;
        };
        let Some(low) = decode_hex_nibble(bytes[index + 2]) else {
            return true;
        };
        let decoded = high << 4 | low;
        if !bytes[index + 1..index + 3].eq_ignore_ascii_case(b"25")
            && decoded.is_ascii()
            && !zone_start.is_some_and(|start| {
                index >= start && xray_websocket_zone_escape_allowed(decoded)
            })
        {
            return true;
        }
        index += 3;
    }
    false
}

fn xray_websocket_zone_escape_allowed(byte: u8) -> bool {
    byte == b' '
        || byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
        )
}

fn xray_websocket_absolute_authority_has_invalid_bracketed_host(
    request_target: &str,
) -> bool {
    let Some(scheme_end) = request_target.find("://") else {
        return false;
    };
    let scheme = &request_target[..scheme_end];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
    {
        return false;
    }

    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    if host.contains('[') && !host.starts_with('[') {
        return true;
    }
    let Some(bracketed) = host.strip_prefix('[') else {
        return false;
    };
    let Some(closing) = bracketed.find(']') else {
        return true;
    };
    let literal = &bracketed[..closing];
    let (address, zone) = literal
        .split_once("%25")
        .map_or((literal, None), |(address, zone)| (address, Some(zone)));

    address.parse::<Ipv6Addr>().is_err() || zone.is_some_and(str::is_empty)
}

pub(super) fn xray_websocket_absolute_authority_has_non_ascii_userinfo(
    request_target: &[u8],
) -> bool {
    let Some(scheme_end) =
        request_target.windows(3).position(|bytes| bytes == b"://")
    else {
        return false;
    };
    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some(last_at) = authority.iter().rposition(|byte| *byte == b'@') else {
        return false;
    };

    !authority[..last_at].is_ascii()
}

fn xray_websocket_absolute_authority_has_invalid_userinfo_character(
    request_target: &str,
) -> bool {
    let Some(scheme_end) = request_target.find("://") else {
        return false;
    };
    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return false;
    };

    userinfo.bytes().any(|byte| {
        matches!(
            byte,
            b'"' | b'#'
                | b'<'
                | b'>'
                | b'['
                | b'\\'
                | b']'
                | b'^'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
        )
    })
}

fn xray_websocket_absolute_authority_has_invalid_host_character(
    request_target: &str,
) -> bool {
    let Some(scheme_end) = request_target.find("://") else {
        return false;
    };
    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    host.bytes()
        .any(|byte| matches!(byte, b'#' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'))
}

fn xray_websocket_absolute_authority_has_invalid_port(request_target: &str) -> bool {
    let Some(scheme_end) = request_target.find("://") else {
        return false;
    };
    let scheme = &request_target[..scheme_end];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
    {
        return false;
    }

    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    let port = if let Some(bracketed) = host.strip_prefix('[') {
        let Some(closing) = bracketed.find(']') else {
            return false;
        };
        &bracketed[closing + 1..]
    } else {
        host.rfind(':').map_or("", |colon| &host[colon..])
    };

    !port.is_empty()
        && (!port.starts_with(':')
            || !port[1..].bytes().all(|byte| byte.is_ascii_digit()))
}

fn has_malformed_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || decode_hex_nibble(bytes[index + 1]).is_none()
            || decode_hex_nibble(bytes[index + 2]).is_none()
        {
            return true;
        }
        index += 3;
    }
    false
}

fn xray_websocket_absolute_parts(request_target: &str) -> Option<(&str, &str)> {
    let scheme_end = request_target.find("://")?;
    let scheme = &request_target[..scheme_end];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
    {
        return None;
    }

    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    let path = rest.get(authority_end..).and_then(|remainder| {
        remainder.starts_with('/').then(|| {
            remainder
                .split_once('?')
                .map_or(remainder, |(path, _)| path)
        })
    });
    Some((host, path.unwrap_or("")))
}

pub(super) fn xray_websocket_absolute_host(request_target: &str) -> Option<String> {
    let (host, _) = xray_websocket_absolute_parts(request_target)?;
    if host.is_empty() {
        return None;
    }

    let bytes = host.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let Some(high) = decode_hex_nibble(bytes[index + 1]) else {
                return Some(host.to_string());
            };
            let Some(low) = decode_hex_nibble(bytes[index + 2]) else {
                return Some(host.to_string());
            };
            decoded.push(high << 4 | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    Some(String::from_utf8_lossy(&decoded).into_owned())
}

pub(super) fn xray_websocket_host_matches(actual: &str, expected: &str) -> bool {
    let actual = xray_unicode_lowercase(actual);
    let expected = xray_unicode_lowercase(expected);
    if !actual.contains(':') {
        return actual == expected;
    }

    split_http_host_port(&actual).is_some_and(|host| host == expected)
}

fn xray_unicode_lowercase(value: &str) -> String {
    value
        .chars()
        .map(|ch| ch.to_lowercase().next().unwrap_or(ch))
        .collect()
}

fn split_http_host_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']')?;
        let host = &rest[..closing];
        let suffix = &rest[closing + 1..];
        return (suffix.starts_with(':') && !suffix[1..].contains(':'))
            .then_some(host);
    }

    let mut parts = authority.split(':');
    let host = parts.next()?;
    parts.next()?;
    parts.next().is_none().then_some(host)
}

fn is_http_method_token_byte(byte: u8) -> bool {
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

pub(super) fn websocket_request_path_raw(request_target: &str) -> String {
    if let Some((_, path)) = xray_websocket_absolute_parts(request_target) {
        return path.to_string();
    }

    request_target
        .split_once('?')
        .map_or(request_target, |(path, _)| path)
        .to_string()
}

pub(super) fn raw_xray_request_target(first_line: &[u8]) -> Option<&[u8]> {
    let first_space = first_line.iter().position(|byte| *byte == b' ')?;
    let rest = &first_line[first_space + 1..];
    let second_space = rest.iter().position(|byte| *byte == b' ')?;
    Some(&rest[..second_space])
}

pub(super) fn xray_websocket_request_path(
    request_target: &str,
) -> Result<Vec<u8>, ()> {
    xray_websocket_request_path_raw_bytes(request_target, request_target.as_bytes())
}

pub(super) fn xray_websocket_request_path_raw_bytes(
    request_target: &str,
    raw_request_target: &[u8],
) -> Result<Vec<u8>, ()> {
    let raw_owned;
    let bytes = if let Some(path) =
        xray_websocket_raw_hierarchical_path(raw_request_target)
    {
        path
    } else {
        raw_owned = websocket_request_path_raw(request_target);
        raw_owned.as_bytes()
    };
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = decode_hex_nibble(bytes[index + 1]).ok_or(())?;
        let low = decode_hex_nibble(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    Ok(decoded)
}

fn xray_websocket_raw_hierarchical_path(request_target: &[u8]) -> Option<&[u8]> {
    if request_target.starts_with(b"/") {
        return Some(
            request_target
                .split(|byte| *byte == b'?')
                .next()
                .unwrap_or(request_target),
        );
    }

    let colon = request_target.iter().position(|byte| *byte == b':')?;
    let remainder = &request_target[colon + 1..];
    let path = if let Some(authority) = remainder.strip_prefix(b"//") {
        let path_start = authority
            .iter()
            .position(|byte| matches!(byte, b'/' | b'?'))?;
        if authority[path_start] == b'?' {
            return Some(b"");
        }
        &authority[path_start..]
    } else if remainder.starts_with(b"/") {
        remainder
    } else {
        return None;
    };

    Some(path.split(|byte| *byte == b'?').next().unwrap_or(path))
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn valid_xray_content_length(
    headers: &HashMap<String, Vec<String>>,
) -> bool {
    let Some(values) = headers.get("content-length") else {
        return true;
    };
    let Some(first) = values.first() else {
        return false;
    };
    if first.is_empty()
        || !first.bytes().all(|byte| byte.is_ascii_digit())
        || first.parse::<i64>().is_err()
    {
        return false;
    }
    values.iter().skip(1).all(|value| value == first)
}

pub(super) fn valid_xray_transfer_encoding(
    headers: &HashMap<String, Vec<String>>,
) -> bool {
    match headers.get("transfer-encoding") {
        None => true,
        Some(values) => {
            values.len() == 1 && values[0].eq_ignore_ascii_case("chunked")
        }
    }
}

pub(super) fn valid_xray_chunked_trailers(
    headers: &HashMap<String, Vec<String>>,
) -> bool {
    if !headers.contains_key("transfer-encoding") {
        return true;
    }

    headers.get("trailer").is_none_or(|values| {
        values.iter().all(|value| {
            value.split(',').map(str::trim).all(|key| {
                !key.eq_ignore_ascii_case("content-length")
                    && !key.eq_ignore_ascii_case("transfer-encoding")
                    && !key.eq_ignore_ascii_case("trailer")
            })
        })
    })
}

pub(super) fn header_contains_token(
    headers: &HashMap<String, Vec<String>>,
    name: &str,
    token: &str,
) -> bool {
    headers.get(name).is_some_and(|values| {
        values.iter().any(|value| {
            value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case(token))
        })
    })
}

pub(super) fn valid_websocket_key(key: &str) -> bool {
    BASE64.decode(key).is_ok_and(|decoded| decoded.len() == 16)
}

pub(super) fn xray_websocket_forwarded_peer(
    headers: &HashMap<String, Vec<String>>,
    trusted_x_forwarded_for: &[String],
) -> Option<SocketAddr> {
    if trusted_x_forwarded_for.is_empty()
        || !trusted_x_forwarded_for.iter().any(|header| {
            !header.eq_ignore_ascii_case("host")
                && headers.contains_key(&header.to_ascii_lowercase())
        })
    {
        return None;
    }

    let first = headers.get("x-forwarded-for")?.first()?.split(',').next()?;
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

    let ip = candidate.parse::<IpAddr>().ok()?;
    let ip = match ip {
        IpAddr::V6(ipv6) => {
            ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4)
        }
        ip => ip,
    };
    Some(SocketAddr::new(ip, 0))
}

pub(super) fn decode_xray_websocket_early_data(value: &str) -> Option<Vec<u8>> {
    let normalized = value.replace('+', "-").replace('/', "_").replace('=', "");
    URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .filter(|decoded| !decoded.is_empty())
}
