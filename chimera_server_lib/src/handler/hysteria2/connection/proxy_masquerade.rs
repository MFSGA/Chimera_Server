use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use tracing::debug;

pub(super) fn xray_proxy_target_url(
    base: &str,
    uri: &http::Uri,
) -> std::io::Result<reqwest::Url> {
    let mut base_url = reqwest::Url::parse(base).map_err(Error::other)?;
    let base_query = base_url.query().map(str::to_owned);
    base_url.set_query(None);
    base_url.set_fragment(None);
    if base_url.has_authority() {
        let _ = base_url.set_username("");
        let _ = base_url.set_password(None);
    }

    let base_path_has_slash = base_url.path().ends_with('/');
    let request_path = uri.path();
    let request_path_has_slash = request_path.starts_with('/');
    let mut raw = base_url.as_str().to_string();
    match (base_path_has_slash, request_path_has_slash) {
        (true, true) => raw.push_str(&request_path[1..]),
        (false, false) => {
            raw.push('/');
            raw.push_str(request_path);
        }
        _ => raw.push_str(request_path),
    }
    let mut target = reqwest::Url::parse(&raw).map_err(Error::other)?;
    let request_query = uri.query().map(xray_proxy_clean_query);
    let query = match (base_query.as_deref(), request_query.as_deref()) {
        (Some(base), Some(request)) if !base.is_empty() && !request.is_empty() => {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_string()),
        _ => None,
    };
    if query.is_none() && uri.query() == Some("") {
        target.set_query(Some(""));
    } else {
        target.set_query(query.as_deref());
    }
    Ok(target)
}

pub(super) fn xray_proxy_clean_query(value: &str) -> String {
    let parameter_count = value
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b'&')
        .count()
        + 1;
    let needs_cleaning = parameter_count > 10_000
        || value.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b';'
                || (*byte == b'%'
                    && (index + 2 >= value.len()
                        || !value.as_bytes()[index + 1].is_ascii_hexdigit()
                        || !value.as_bytes()[index + 2].is_ascii_hexdigit()))
        });
    if !needs_cleaning {
        return value.to_string();
    }

    let mut pairs = std::collections::BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    for field in value.as_bytes().split(|byte| *byte == b'&') {
        if field.contains(&b';') || field.is_empty() {
            continue;
        }
        let (key, value) = match field.iter().position(|byte| *byte == b'=') {
            Some(index) => (&field[..index], &field[index + 1..]),
            None => (field, &[][..]),
        };
        let (Some(key), Some(value)) = (
            xray_proxy_query_unescape(key),
            xray_proxy_query_unescape(value),
        ) else {
            continue;
        };
        pairs.entry(key).or_default().push(value);
    }

    let mut clean = String::new();
    for (key, values) in pairs {
        for value in values {
            if !clean.is_empty() {
                clean.push('&');
            }
            xray_proxy_query_escape(&mut clean, &key);
            clean.push('=');
            xray_proxy_query_escape(&mut clean, &value);
        }
    }
    clean
}

fn xray_proxy_query_unescape(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = *value.get(index + 1)?;
                let low = *value.get(index + 2)?;
                decoded.push((xray_proxy_hex(high)? << 4) | xray_proxy_hex(low)?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    Some(decoded)
}

fn xray_proxy_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn xray_proxy_query_escape(output: &mut String, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            b' ' => output.push('+'),
            _ => {
                output.push('%');
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
}

fn xray_proxy_hop_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn xray_proxy_forwarding_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto"
    )
}

pub(super) fn xray_proxy_supports_trailers(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::TE).iter().any(|value| {
        xray_proxy_header_value_contains_token(value.as_bytes(), b"trailers", false)
    })
}

fn xray_proxy_header_value_contains_token(
    value: &[u8],
    token: &[u8],
    trim_ascii_space: bool,
) -> bool {
    value.split(|byte| *byte == b',').any(|part| {
        xray_proxy_trim_header_token(part, trim_ascii_space)
            .eq_ignore_ascii_case(token)
    })
}

fn xray_proxy_trim_header_token(mut value: &[u8], trim_ascii_space: bool) -> &[u8] {
    let is_space = |byte: u8| {
        matches!(byte, b' ' | b'\t')
            || (trim_ascii_space && matches!(byte, b'\n' | b'\r'))
    };
    while value.first().copied().is_some_and(is_space) {
        value = &value[1..];
    }
    while value.last().copied().is_some_and(is_space) {
        value = &value[..value.len() - 1];
    }
    value
}

pub(super) fn xray_proxy_auto_gzip(
    method: &http::Method,
    headers: &http::HeaderMap,
) -> bool {
    *method != http::Method::HEAD
        && headers
            .get(http::header::ACCEPT_ENCODING)
            .is_none_or(|value| value.as_bytes().is_empty())
        && headers
            .get(http::header::RANGE)
            .is_none_or(|value| value.as_bytes().is_empty())
}

pub(super) fn xray_proxy_connection_header(
    name: &http::HeaderName,
    headers: &http::HeaderMap,
) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            xray_proxy_header_value_contains_token(
                value.as_bytes(),
                name.as_str().as_bytes(),
                true,
            )
        })
}

pub(crate) struct XrayProxyTransport {
    client: reqwest::Client,
}

impl XrayProxyTransport {
    pub(super) fn new(insecure: bool) -> std::io::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .tls_danger_accept_invalid_certs(insecure)
            .no_gzip()
            .pool_max_idle_per_host(2)
            .build()
            .map_err(Error::other)?;
        Ok(Self { client })
    }
}

pub(super) fn xray_proxy_validate_target_url(value: &str) -> std::io::Result<()> {
    if value.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains a control character",
        ));
    }

    let (without_fragment, fragment) = value.split_once('#').unwrap_or((value, ""));
    if !xray_proxy_valid_percent_escapes(fragment) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains an invalid fragment escape",
        ));
    }
    let main = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(main, _)| main);
    let opaque = main.find(':').is_some_and(|colon| {
        xray_proxy_valid_scheme(&main[..colon])
            && !main[colon + 1..].starts_with('/')
    });
    if !opaque && !xray_proxy_valid_percent_escapes(main) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Xray proxy masquerade URL contains an invalid escape",
        ));
    }
    Ok(())
}

fn xray_proxy_valid_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
}

fn xray_proxy_valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    true
}

pub(super) fn build_xray_proxy_transport_impl(
    masquerade: Option<
        &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    >,
) -> std::io::Result<Option<Arc<XrayProxyTransport>>> {
    masquerade
        .map(|masquerade| {
            xray_proxy_validate_target_url(&masquerade.url)?;
            XrayProxyTransport::new(masquerade.insecure).map(Arc::new)
        })
        .transpose()
}

fn xray_proxy_bad_gateway_response() -> std::io::Result<(Response<()>, Option<Bytes>)>
{
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(())
        .map_err(Error::other)?;
    Ok((response, None))
}

pub(super) async fn xray_proxy_masquerade_response(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    body: Bytes,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let transport = XrayProxyTransport::new(masquerade.insecure)?;
    xray_proxy_masquerade_response_with_transport(
        method,
        uri,
        request_headers,
        body,
        masquerade,
        &transport,
    )
    .await
}

pub(super) async fn xray_proxy_masquerade_response_with_transport(
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    body: Bytes,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    transport: &XrayProxyTransport,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let target = match xray_proxy_target_url(&masquerade.url, uri) {
        Ok(target) => target,
        Err(err) => {
            debug!(error = %err, url = %masquerade.url, "Xray proxy masquerade target cannot be forwarded");
            return xray_proxy_bad_gateway_response();
        }
    };
    let auto_gzip = xray_proxy_auto_gzip(method, request_headers);
    let mut request = transport.client.request(method.clone(), target);
    for (name, value) in request_headers {
        if !xray_proxy_hop_header(name)
            && !xray_proxy_connection_header(name, request_headers)
            && !xray_proxy_forwarding_header(name)
            && name != http::header::HOST
        {
            request = request.header(name, value);
        }
    }
    if auto_gzip {
        request = request.header(http::header::ACCEPT_ENCODING, "gzip");
    }
    if xray_proxy_supports_trailers(request_headers) {
        request = request.header(http::header::TE, "trailers");
    }
    if !masquerade.rewrite_host
        && let Some(authority) = uri.authority()
    {
        request = request.header(http::header::HOST, authority.as_str());
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let upstream = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            debug!(error = %err, url = %masquerade.url, "Xray proxy masquerade upstream request failed");
            return xray_proxy_bad_gateway_response();
        }
    };
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    let mut body = upstream.bytes().await.map_err(Error::other)?;
    if auto_gzip
        && headers
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"))
    {
        let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded)
            .map_err(Error::other)?;
        body = Bytes::from(decoded);
        headers.remove(http::header::CONTENT_ENCODING);
        headers.remove(http::header::CONTENT_LENGTH);
    }
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !xray_proxy_hop_header(name)
            && !xray_proxy_connection_header(name, &headers)
        {
            response = response.header(name, value);
        }
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}
