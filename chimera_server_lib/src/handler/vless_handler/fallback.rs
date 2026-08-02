use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

use crate::{
    async_stream::AsyncStream, config::server_config::VlessFallback,
    handler::tcp::tcp_handler::TcpServerSetupResult,
    util::prefixed_stream::PrefixedStream,
};

const AUTH_PREFIX_LEN: usize = 17;
const PATH_INSPECTION_LIMIT: usize = 64;
const PATH_READ_GRACE: Duration = Duration::from_millis(20);

type FallbackScore = (u8, usize, u8, u8);
type FallbackSelection<'a> = Option<(&'a VlessFallback, FallbackScore)>;

pub(crate) async fn read_vless_auth_prefix<S>(
    stream: &mut S,
) -> (Vec<u8>, Option<[u8; 16]>)
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(AUTH_PREFIX_LEN);
    for _ in 0..AUTH_PREFIX_LEN {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return (prefix, None);
        }
        prefix.push(byte[0]);
    }
    if prefix[0] != 0 {
        return (prefix, None);
    }
    let mut user_id = [0u8; 16];
    user_id.copy_from_slice(&prefix[1..AUTH_PREFIX_LEN]);
    (prefix, Some(user_id))
}

pub(crate) async fn extend_prefix_for_path<S>(
    stream: &mut S,
    prefix: &mut Vec<u8>,
    fallbacks: &[VlessFallback],
) where
    S: AsyncRead + Unpin,
{
    if prefix.len() >= PATH_INSPECTION_LIMIT
        || !fallbacks.iter().any(|fallback| !fallback.path.is_empty())
        || extract_http_path(prefix).is_some()
    {
        return;
    }

    let remaining = PATH_INSPECTION_LIMIT - prefix.len();
    let mut buffer = vec![0u8; remaining];
    if let Ok(Ok(read)) = timeout(PATH_READ_GRACE, stream.read(&mut buffer)).await
        && read > 0
    {
        prefix.extend_from_slice(&buffer[..read]);
    }
}

pub(crate) fn select_vless_fallback<'a>(
    fallbacks: &'a [VlessFallback],
    server_name: &str,
    alpn: &str,
    prefix: &[u8],
) -> Option<&'a VlessFallback> {
    let server_name = server_name.trim().to_ascii_lowercase();
    let alpn = alpn.trim().to_ascii_lowercase();
    let path = extract_http_path(prefix).unwrap_or_default();

    let mut selected: FallbackSelection<'_> = None;
    for fallback in fallbacks {
        let name_score = if fallback.name.is_empty() {
            0
        } else if server_name == fallback.name {
            2
        } else if !server_name.is_empty() && server_name.contains(&fallback.name) {
            1
        } else {
            continue;
        };
        if !fallback.alpn.is_empty() && fallback.alpn != alpn {
            continue;
        }
        if !fallback.path.is_empty() && fallback.path != path {
            continue;
        }

        let score = (
            name_score,
            fallback.name.len(),
            u8::from(!fallback.alpn.is_empty()),
            u8::from(!fallback.path.is_empty()),
        );
        if selected
            .as_ref()
            .is_none_or(|(_, selected_score)| score >= *selected_score)
        {
            selected = Some((fallback, score));
        }
    }
    selected.map(|(fallback, _)| fallback)
}

pub(crate) fn vless_fallback_result(
    fallback: &VlessFallback,
    prefix: Vec<u8>,
    stream: Box<dyn AsyncStream>,
) -> TcpServerSetupResult {
    let stream: Box<dyn AsyncStream> = Box::new(PrefixedStream::new(prefix, stream));
    if fallback.xver == 0 {
        TcpServerSetupResult::TcpForward {
            remote_location: fallback.dest.clone(),
            stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context: None,
        }
    } else {
        TcpServerSetupResult::TcpFallback {
            remote_location: fallback.dest.clone(),
            stream,
            proxy_protocol_version: fallback.xver,
            traffic_context: None,
        }
    }
}

fn extract_http_path(prefix: &[u8]) -> Option<String> {
    let line_end = prefix
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(prefix.len());
    let line = std::str::from_utf8(&prefix[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty()
        || method.len() >= 8
        || !target.starts_with('/')
        || !version.starts_with("HTTP/")
    {
        return None;
    }
    Some(target.split(['?', '#']).next()?.to_string())
}

#[cfg(test)]
mod tests {
    use crate::{
        address::{Address, NetLocation},
        config::server_config::VlessFallback,
    };

    use super::{extract_http_path, select_vless_fallback};

    fn fallback(name: &str, alpn: &str, path: &str, port: u16) -> VlessFallback {
        VlessFallback {
            name: name.into(),
            alpn: alpn.into(),
            path: path.into(),
            dest: NetLocation::new(
                Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                port,
            ),
            xver: 0,
        }
    }

    #[test]
    fn does_not_treat_partial_request_line_as_complete_path() {
        assert_eq!(extract_http_path(b"GET /vision-fallb"), None);
    }

    #[test]
    fn extracts_http_path_without_query() {
        assert_eq!(
            extract_http_path(b"GET /api?q=1 HTTP/1.1\r\n"),
            Some("/api".into())
        );
    }

    #[test]
    fn selection_prefers_name_then_alpn_then_path() {
        let fallbacks = vec![
            fallback("", "", "", 8000),
            fallback("example.com", "", "", 8001),
            fallback("example.com", "h2", "", 8002),
            fallback("example.com", "h2", "/api", 8003),
        ];
        let selected = select_vless_fallback(
            &fallbacks,
            "edge.example.com",
            "h2",
            b"GET /api HTTP/1.1\r\n",
        )
        .expect("matching fallback");
        assert_eq!(selected.dest.port(), 8003);
    }

    #[test]
    fn selection_uses_default_when_specific_rule_does_not_match() {
        let fallbacks = vec![
            fallback("", "", "", 8000),
            fallback("example.com", "h2", "/api", 8001),
        ];
        let selected = select_vless_fallback(
            &fallbacks,
            "other.test",
            "http/1.1",
            b"GET /other HTTP/1.1\r\n",
        )
        .expect("default fallback");
        assert_eq!(selected.dest.port(), 8000);
    }
}
