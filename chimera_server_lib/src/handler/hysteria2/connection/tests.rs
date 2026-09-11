use std::{
    future::pending,
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

use super::*;
use crate::config::server_config::{
    Hysteria2Client, Hysteria2MasqueradeProxyConfig,
};
use crate::runtime::RuntimeState;

fn hysteria2_config(
    congestion: Option<&str>,
    brutal_up: Option<u64>,
    brutal_down: Option<u64>,
) -> Hysteria2ServerConfig {
    serde_json::from_value(serde_json::json!({
        "clients": [{"password": "secret"}],
        "xrayCongestion": congestion,
        "xrayBrutalUp": brutal_up,
        "xrayBrutalDown": brutal_down
    }))
    .expect("valid Hysteria2 test config")
}

fn auth_request(auth: &str, uri: &str) -> Request<()> {
    Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(AUTH_HEADER, auth)
        .body(())
        .expect("valid Hysteria2 auth request")
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn traffic_context_applies_client_level_and_stats_policy() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let mut levels = std::collections::HashMap::new();
    levels.insert(
        7,
        Some(crate::config::def::PolicyLevelConfig {
            stats_user_uplink: false,
            stats_user_downlink: true,
            stats_user_online: false,
            ..crate::config::def::PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&crate::config::def::PolicyConfig {
        levels,
        system: Some(crate::config::def::SystemPolicyConfig {
            stats_inbound_uplink: true,
            stats_inbound_downlink: false,
            stats_outbound_uplink: false,
            stats_outbound_downlink: true,
        }),
    }));
    let client: Hysteria2Client = serde_json::from_value(serde_json::json!({
        "password": "policy-secret",
        "email": "policy@example.com",
        "level": 7
    }))
    .expect("valid Hysteria2 policy client");
    let context = hysteria2_traffic_context(
        &client,
        "hysteria-policy",
        "127.0.0.1:12345".parse().unwrap(),
        &runtime.data_plane(),
    );

    assert_eq!(context.user_level, 7);
    assert_eq!(context.identity.as_deref(), Some("policy@example.com"));
    assert_eq!(context.stats_user_uplink, Some(false));
    assert_eq!(context.stats_user_downlink, Some(true));
    assert_eq!(context.stats_user_online, Some(false));
    assert_eq!(context.stats_inbound_uplink, Some(true));
    assert_eq!(context.stats_inbound_downlink, Some(false));
    assert_eq!(context.stats_outbound_uplink, Some(false));
    assert_eq!(context.stats_outbound_downlink, Some(true));
}

#[test]
fn auth_timeout_matches_xray_and_shoes() {
    assert_eq!(configured_auth_timeout(false), Some(AUTH_TIMEOUT));
    assert_eq!(configured_auth_timeout(true), None);
}

#[tokio::test]
async fn authentication_times_out_after_shoes_window() {
    let started = Instant::now();
    let err = await_authentication(pending::<std::io::Result<()>>(), false)
        .await
        .expect_err("pending shoes Hysteria2 auth must time out");

    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(started.elapsed() >= AUTH_TIMEOUT);
}

#[tokio::test]
async fn hysteria_tcp_stream_cleanup_aborts_and_drains_children() {
    let dropped = Arc::new(AtomicBool::new(false));
    let task_drop = dropped.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut stream_tasks = JoinSet::new();
    stream_tasks.spawn(async move {
        let _drop_flag = DropFlag(task_drop);
        let _ = started_tx.send(());
        pending::<()>().await;
    });

    started_rx
        .await
        .expect("Hysteria2 child task should start before cleanup");
    assert_eq!(stream_tasks.len(), 1);

    abort_and_drain_hysteria_stream_tasks(&mut stream_tasks).await;

    assert!(dropped.load(Ordering::SeqCst));
    assert!(stream_tasks.is_empty());
}

#[tokio::test]
async fn tcp_request_parser_accepts_xray_raw_stream_format() {
    let target = "127.0.0.1:443";
    let mut frame = Vec::new();
    push_varint(&mut frame, TCP_REQUEST_ID).expect("request type varint");
    push_varint(&mut frame, target.len() as u64).expect("address length varint");
    frame.extend_from_slice(target.as_bytes());
    push_varint(&mut frame, 3).expect("padding length varint");
    frame.extend_from_slice(b"pad");

    let (mut writer, mut reader) = tokio::io::duplex(frame.len());
    writer.write_all(&frame).await.expect("write request frame");
    writer.shutdown().await.expect("finish request frame");

    let request = TcpRequest::read(&mut reader, true)
        .await
        .expect("parse Xray Hysteria2 TCP request");
    assert_eq!(request.target.to_string(), target);
}

#[tokio::test]
async fn tcp_request_target_parse_order_matches_xray_and_shoes() {
    let mut frame = Vec::new();
    push_varint(&mut frame, TCP_REQUEST_ID).unwrap();
    push_varint(&mut frame, 3).unwrap();
    frame.extend_from_slice(b"bad");
    push_varint(&mut frame, 1).unwrap();

    let (mut shoes_writer, mut shoes_reader) = tokio::io::duplex(64);
    shoes_writer.write_all(&frame).await.unwrap();
    let shoes_error = match tokio::time::timeout(
        Duration::from_secs(1),
        read_tcp_request(&mut shoes_reader, None, false),
    )
    .await
    .expect("shoes mode must parse the target before waiting for padding")
    {
        Ok(_) => panic!("invalid shoes target unexpectedly parsed"),
        Err(error) => error,
    };
    assert!(shoes_error.to_string().contains("No port"));

    let (mut xray_writer, mut xray_reader) = tokio::io::duplex(64);
    xray_writer.write_all(&frame).await.unwrap();
    let xray_task =
        tokio::spawn(
            async move { read_tcp_request(&mut xray_reader, None, true).await },
        );
    tokio::task::yield_now().await;
    assert!(
        !xray_task.is_finished(),
        "Xray mode must consume declared padding before parsing the target"
    );
    xray_writer.write_all(b"x").await.unwrap();
    let xray_error = match tokio::time::timeout(Duration::from_secs(1), xray_task)
        .await
        .expect("Xray parser should finish after padding arrives")
        .expect("Xray parser task should not panic")
    {
        Ok(_) => panic!("invalid Xray target unexpectedly parsed"),
        Err(error) => error,
    };
    assert!(xray_error.to_string().contains("No port"));
}

#[test]
fn tcp_request_timeout_uses_xray_user_level_policy_only() {
    use crate::config::def::{PolicyConfig, PolicyLevelConfig};
    use std::collections::HashMap;

    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert_eq!(
        configured_tcp_request_timeout(true, 7, &runtime.data_plane()),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        configured_tcp_request_timeout(false, 7, &runtime.data_plane()),
        None
    );

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            handshake: Some(2),
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));
    assert_eq!(
        configured_tcp_request_timeout(true, 7, &runtime.data_plane()),
        Some(Duration::from_secs(2))
    );
    assert_eq!(
        configured_tcp_request_timeout(true, 8, &runtime.data_plane()),
        Some(Duration::from_secs(60))
    );
}

#[test]
fn auth_success_content_length_matches_xray_and_shoes_writers() {
    let shoes = build_auth_success_response(true, 750_000, false, false)
        .expect("valid shoes auth response");
    assert_eq!(shoes.status().as_u16(), SUCCESS_STATUS);
    assert_eq!(
        shoes.headers().get(CLIENT_CC_RX_HEADER),
        Some(&http::HeaderValue::from_static("0"))
    );
    assert!(shoes.headers().get(http::header::CONTENT_LENGTH).is_none());
    assert!(shoes.headers().get(http::header::DATE).is_none());

    let xray = build_auth_success_response(true, 750_000, false, true)
        .expect("valid Xray auth response");
    assert_eq!(
        xray.headers().get(CLIENT_CC_RX_HEADER),
        Some(&http::HeaderValue::from_static("750000"))
    );
    assert_eq!(xray.status().as_u16(), SUCCESS_STATUS);
    assert_eq!(
        xray.headers().get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("0"))
    );
    assert!(xray.headers().get(http::header::DATE).is_some());
}

#[test]
fn auth_rejections_match_xray_and_shoes_default_masquerade() {
    let (shoes_response, shoes_body) =
        auth_reject_response(false).expect("valid shoes reject response");
    assert_eq!(shoes_response.status(), StatusCode::NOT_FOUND);
    assert!(
        shoes_response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none()
    );
    assert!(shoes_response.headers().get(http::header::DATE).is_none());
    assert!(shoes_body.is_none());

    let (xray_response, xray_body) =
        auth_reject_response(true).expect("valid Xray reject response");
    assert_eq!(xray_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        xray_response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
    );
    assert_eq!(
        xray_response.headers().get("x-content-type-options"),
        Some(&http::HeaderValue::from_static("nosniff"))
    );
    assert_eq!(
        xray_response.headers().get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("19"))
    );
    assert!(xray_response.headers().get(http::header::DATE).is_some());
    assert_eq!(xray_body.as_deref(), Some(&b"404 page not found\n"[..]));
}

#[test]
fn auth_rejections_match_xray_string_masquerade() {
    let masquerade = crate::config::server_config::Hysteria2MasqueradeStringConfig {
        content: "hello from xray".to_string(),
        headers: [("x-test-header".to_string(), "present".to_string())]
            .into_iter()
            .collect(),
        status_code: 418,
    };
    let (response, body) =
        xray_string_masquerade_response(&http::Method::GET, &masquerade)
            .expect("valid Xray string masquerade response");
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
        response.headers().get("x-test-header"),
        Some(&http::HeaderValue::from_static("present"))
    );
    assert!(response.headers().get(http::header::DATE).is_some());
    assert_eq!(
        response.headers().get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("15"))
    );
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
    );
    assert_eq!(body.as_deref(), Some(&b"hello from xray"[..]));

    let mut explicit_date = masquerade.clone();
    explicit_date.headers.insert(
        "date".to_string(),
        "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
    );
    let (explicit_date_response, _) =
        xray_string_masquerade_response(&http::Method::GET, &explicit_date)
            .expect("preserve explicit Xray string Date header");
    assert_eq!(
        explicit_date_response.headers().get(http::header::DATE),
        Some(&http::HeaderValue::from_static(
            "Sun, 06 Nov 1994 08:49:37 GMT"
        ))
    );

    let (head_response, head_body) =
        xray_string_masquerade_response(&http::Method::HEAD, &masquerade)
            .expect("valid Xray HEAD string masquerade response");
    assert_eq!(
        head_response.headers().get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("15"))
    );
    assert!(
        head_response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_none()
    );
    assert_eq!(head_body.as_deref(), Some(&b"hello from xray"[..]));

    let no_content = crate::config::server_config::Hysteria2MasqueradeStringConfig {
        content: "ignored body".to_string(),
        headers: HashMap::new(),
        status_code: 204,
    };
    let (no_content_response, no_content_body) =
        xray_string_masquerade_response(&http::Method::GET, &no_content)
            .expect("valid Xray no-content string masquerade response");
    assert_eq!(no_content_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        no_content_response
            .headers()
            .get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("0"))
    );
    assert!(
        no_content_response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_none()
    );
    assert!(no_content_body.is_none());
}

#[test]
fn xray_proxy_query_cleaning_matches_go_reverse_proxy_rewrite() {
    assert_eq!(xray_proxy_clean_query("a=1&a=2;b=3"), "a=1");
    assert_eq!(xray_proxy_clean_query("a=1&a=%zz&b=3"), "a=1&b=3");
    assert_eq!(xray_proxy_clean_query("a=%zz"), "");
    assert_eq!(xray_proxy_clean_query("a=%zz&&b=2"), "b=2");
    assert_eq!(xray_proxy_clean_query("&&a=%zz"), "");
    assert_eq!(xray_proxy_clean_query("=&&a=%zz"), "=");
    assert_eq!(
        xray_proxy_clean_query("b=2&a=first&a=second%20value"),
        "b=2&a=first&a=second%20value"
    );
    assert_eq!(
        xray_proxy_clean_query("b=2;a=ignored&a=first&a=second+value"),
        "a=first&a=second+value"
    );
    let at_limit = "b=2&".repeat(9_999) + "a=1";
    assert_eq!(xray_proxy_clean_query(&at_limit), at_limit);

    let over_limit_same_key = "a=1&".repeat(10_000) + "a=1";
    assert_eq!(
        xray_proxy_clean_query(&over_limit_same_key),
        over_limit_same_key
    );
    let over_limit_sorted = "b=2&".repeat(10_000) + "a=1";
    let cleaned = xray_proxy_clean_query(&over_limit_sorted);
    assert!(cleaned.starts_with("a=1&b=2&b=2"));
    assert_eq!(cleaned.matches("b=2").count(), 10_000);

    let uri: http::Uri = "https://original.test/path?a=1&a=%25zz&b=3"
        .parse()
        .expect("valid encoded proxy URI");
    let target = xray_proxy_target_url("https://upstream.test/base?fixed=1", &uri)
        .expect("build cleaned proxy target");
    assert_eq!(
        target.as_str(),
        "https://upstream.test/base/path?fixed=1&a=1&a=%25zz&b=3"
    );

    let escaped_uri: http::Uri = "https://original.test/c%2Fd?q=2"
        .parse()
        .expect("valid escaped proxy URI");
    let escaped_target = xray_proxy_target_url(
        "https://user:pass@upstream.test/base//?fixed=1",
        &escaped_uri,
    )
    .expect("build Xray-compatible proxy target");
    assert_eq!(
        escaped_target.as_str(),
        "https://upstream.test/base//c%2Fd?fixed=1&q=2"
    );

    let malformed_uri: http::Uri = "https://original.test/path?a=1&a=2;b=3&b=3"
        .parse()
        .expect("valid proxy URI with semicolon query");
    let target =
        xray_proxy_target_url("https://upstream.test/base?fixed=1", &malformed_uri)
            .expect("build sanitized proxy target");
    assert_eq!(
        target.as_str(),
        "https://upstream.test/base/path?fixed=1&a=1&b=3"
    );

    let force_query_uri: http::Uri = "https://original.test/path?"
        .parse()
        .expect("valid explicit-empty-query proxy URI");
    let force_query_target =
        xray_proxy_target_url("https://upstream.test/base", &force_query_uri)
            .expect("preserve Xray incoming ForceQuery");
    assert_eq!(
        force_query_target.as_str(),
        "https://upstream.test/base/path?"
    );
    let plain_uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid queryless proxy URI");
    let target_force_query =
        xray_proxy_target_url("https://upstream.test/base?", &plain_uri)
            .expect("drop target-only ForceQuery like Xray");
    assert_eq!(
        target_force_query.as_str(),
        "https://upstream.test/base/path"
    );
}

#[test]
fn xray_proxy_target_validation_matches_go_url_parse_escape_failures() {
    assert!(
        xray_proxy_validate_target_url("https://upstream.test/a%2Fb?q=%zz").is_ok()
    );
    assert!(xray_proxy_validate_target_url("mailto:%zz?q=%zz").is_ok());

    for invalid in [
        "https://upstream.test/a%zz?q=ok",
        "https://upstream.test/a#frag%zz",
        "https://upstream.test/a\u{7f}",
    ] {
        assert!(
            xray_proxy_validate_target_url(invalid).is_err(),
            "Xray net/url.Parse should reject {invalid:?}"
        );
        let config = Hysteria2MasqueradeProxyConfig {
            url: invalid.to_string(),
            rewrite_host: false,
            insecure: false,
        };
        assert!(
            build_xray_proxy_transport(Some(&config)).is_err(),
            "invalid Xray proxy URL should fail transport setup"
        );
    }
}

#[test]
fn xray_proxy_header_tokens_tolerate_obs_text_like_go() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_bytes(b"X-Hop,\x80")
            .expect("obs-text connection value"),
    );
    let x_hop = http::HeaderName::from_static("x-hop");
    assert!(xray_proxy_connection_header(&x_hop, &headers));

    headers.insert(
        http::header::TE,
        http::HeaderValue::from_bytes(b"trailers,\x80").expect("obs-text TE value"),
    );
    assert!(xray_proxy_supports_trailers(&headers));

    headers.insert(
        http::header::TE,
        http::HeaderValue::from_bytes(b"x-trailers,\x80")
            .expect("obs-text non-token TE value"),
    );
    assert!(!xray_proxy_supports_trailers(&headers));
}

#[test]
fn xray_proxy_auto_gzip_matches_go_transport_conditions() {
    let mut headers = http::HeaderMap::new();
    assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));
    assert!(!xray_proxy_auto_gzip(&http::Method::HEAD, &headers));

    headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=0-1"),
    );
    assert!(!xray_proxy_auto_gzip(&http::Method::GET, &headers));
    headers.insert(http::header::RANGE, http::HeaderValue::from_static(""));
    assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));

    headers.insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("br"),
    );
    assert!(!xray_proxy_auto_gzip(&http::Method::GET, &headers));
    headers.insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static(""),
    );
    assert!(xray_proxy_auto_gzip(&http::Method::GET, &headers));
}

#[tokio::test]
async fn xray_proxy_masquerade_forwards_request_and_upstream_response() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy masquerade upstream");
    let upstream_addr = listener
        .local_addr()
        .expect("read proxy masquerade upstream address");
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept proxy request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.expect("read proxy request");
            assert_ne!(read, 0, "proxy request closed before headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) =
                request.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let header_end = header_end + 4;
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .expect("read proxy request body");
                    assert_ne!(read, 0, "proxy request closed before body");
                    request.extend_from_slice(&buffer[..read]);
                }
                break;
            }
        }
        stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nX-Upstream: yes\r\nConnection: close, X-Upstream-Hop\r\nX-Upstream-Hop: hidden\r\n\r\nhello",
                )
                .await
                .expect("write proxy response");
        String::from_utf8(request).expect("proxy request should be utf8")
    });

    let uri: http::Uri = "https://original.test/path?q=2"
        .parse()
        .expect("valid proxy request URI");
    let mut headers = http::HeaderMap::new();
    headers.insert("x-test", http::HeaderValue::from_static("forwarded"));
    headers.append(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static(""),
    );
    headers.append(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("br"),
    );
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("keep-alive, X-Client-Hop"),
    );
    headers.insert("x-client-hop", http::HeaderValue::from_static("hidden"));
    headers.insert(
        http::header::TE,
        http::HeaderValue::from_static("gzip, trailers"),
    );
    headers.insert("forwarded", http::HeaderValue::from_static("for=spoofed"));
    headers.insert(
        "x-forwarded-for",
        http::HeaderValue::from_static("203.0.113.7"),
    );
    headers.insert(
        "x-forwarded-host",
        http::HeaderValue::from_static("spoofed.example"),
    );
    headers.insert("x-forwarded-proto", http::HeaderValue::from_static("http"));
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("http://url-user:url-pass@{upstream_addr}/base?fixed=1"),
        rewrite_host: false,
        insecure: false,
    };
    let (response, body) = xray_proxy_masquerade_response(
        &http::Method::POST,
        &uri,
        &headers,
        Bytes::from_static(b"payload"),
        &config,
    )
    .await
    .expect("proxy Xray masquerade request");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("x-upstream"),
        Some(&http::HeaderValue::from_static("yes"))
    );
    assert!(response.headers().get(http::header::CONNECTION).is_none());
    assert!(response.headers().get("x-upstream-hop").is_none());
    assert_eq!(body.as_deref(), Some(&b"hello"[..]));

    let request = upstream.await.expect("join proxy upstream");
    assert!(request.starts_with("POST /base/path?fixed=1&q=2 HTTP/1.1\r\n"));
    assert!(
        request.contains("host: original.test\r\n")
            || request.contains("Host: original.test\r\n")
    );
    assert!(
        request.contains("x-test: forwarded\r\n")
            || request.contains("X-Test: forwarded\r\n")
    );
    let request_lower = request.to_ascii_lowercase();
    assert!(!request_lower.contains("\r\nx-client-hop:"));
    assert!(!request_lower.contains("\r\nconnection:"));
    assert!(request_lower.contains("\r\nte: trailers\r\n"));
    assert!(!request_lower.contains("te: gzip"));
    assert!(request_lower.contains("\r\naccept-encoding: \r\n"));
    assert!(request_lower.contains("\r\naccept-encoding: br\r\n"));
    assert!(request_lower.contains("\r\naccept-encoding: gzip\r\n"));
    assert!(!request_lower.contains("\r\nforwarded:"));
    assert!(!request_lower.contains("\r\nx-forwarded-for:"));
    assert!(!request_lower.contains("\r\nx-forwarded-host:"));
    assert!(!request_lower.contains("\r\nx-forwarded-proto:"));
    assert!(!request_lower.contains("\r\nauthorization:"));
    assert!(request.ends_with("\r\npayload"));
}

#[tokio::test]
async fn xray_proxy_masquerade_auto_decompresses_transport_gzip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gzip proxy upstream");
    let upstream_addr = listener.local_addr().expect("read gzip upstream address");
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept gzip request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read gzip request");
            assert_ne!(read, 0, "gzip request closed before headers");
            request.extend_from_slice(&buffer[..read]);
        }
        let request =
            String::from_utf8(request).expect("gzip request should be utf8");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("\r\naccept-encoding: gzip\r\n")
        );

        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 25\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write gzip response headers");
        stream
            .write_all(&[
                0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb,
                0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05,
                0x00, 0x00, 0x00,
            ])
            .await
            .expect("write gzip response body");
    });

    let uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid gzip proxy URI");
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("http://{upstream_addr}/"),
        rewrite_host: true,
        insecure: false,
    };
    let (response, body) = xray_proxy_masquerade_response(
        &http::Method::GET,
        &uri,
        &http::HeaderMap::new(),
        Bytes::new(),
        &config,
    )
    .await
    .expect("proxy gzip Xray masquerade request");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_none()
    );
    assert!(
        response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none()
    );
    assert_eq!(body.as_deref(), Some(&b"hello"[..]));
    upstream.await.expect("join gzip upstream");
}

#[tokio::test]
async fn xray_proxy_masquerade_preserves_caller_requested_gzip() {
    const GZIP_HELLO: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48,
        0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00,
        0x00,
    ];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind explicit-gzip proxy upstream");
    let upstream_addr = listener
        .local_addr()
        .expect("read explicit-gzip upstream address");
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept explicit-gzip request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("read explicit-gzip request");
            assert_ne!(read, 0, "explicit-gzip request closed before headers");
            request.extend_from_slice(&buffer[..read]);
        }
        let request = String::from_utf8(request)
            .expect("explicit-gzip request should be utf8");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("\r\naccept-encoding: gzip\r\n")
        );

        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 25\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write explicit-gzip response headers");
        stream
            .write_all(GZIP_HELLO)
            .await
            .expect("write explicit-gzip response body");
    });

    let uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid explicit-gzip proxy URI");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("http://{upstream_addr}/"),
        rewrite_host: true,
        insecure: false,
    };
    let (response, body) = xray_proxy_masquerade_response(
        &http::Method::GET,
        &uri,
        &headers,
        Bytes::new(),
        &config,
    )
    .await
    .expect("proxy explicit-gzip Xray masquerade request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_ENCODING),
        Some(&http::HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        response.headers().get(http::header::CONTENT_LENGTH),
        Some(&http::HeaderValue::from_static("25"))
    );
    assert_eq!(body.as_deref(), Some(GZIP_HELLO));
    upstream.await.expect("join explicit-gzip upstream");
}

#[tokio::test]
async fn xray_proxy_masquerade_reuses_upstream_transport_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reusable proxy upstream");
    let upstream_addr = listener
        .local_addr()
        .expect("read reusable upstream address");
    let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts_for_task = accepts.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept reusable proxy request");
            accepts_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut stream = stream;
                let mut pending = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    while !pending.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream
                            .read(&mut buffer)
                            .await
                            .expect("read reusable proxy request");
                        if read == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buffer[..read]);
                    }
                    let header_end = pending
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .expect("complete reusable proxy request")
                        + 4;
                    pending.drain(..header_end);
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .expect("write reusable proxy response");
                }
            });
        }
    });

    let uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid reusable proxy URI");
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("http://{upstream_addr}/"),
        rewrite_host: true,
        insecure: false,
    };
    let transport =
        XrayProxyTransport::new(false).expect("build reusable Xray proxy transport");
    for _ in 0..2 {
        let (response, body) = xray_proxy_masquerade_response_with_transport(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            &config,
            &transport,
        )
        .await
        .expect("proxy reusable Xray masquerade request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body.as_deref(), Some(&b"ok"[..]));
    }

    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Xray DefaultTransport reuses the upstream keep-alive connection",
    );
    upstream.abort();
}

#[tokio::test]
async fn xray_proxy_transport_caps_idle_connections_per_host_like_go() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pooled proxy upstream");
    let upstream_addr = listener.local_addr().expect("read pooled upstream address");
    let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress = std::sync::Arc::new(tokio::sync::Notify::new());
    let accepts_for_task = accepts.clone();
    let requests_for_task = requests.clone();
    let progress_for_task = progress.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (stream, _) =
                listener.accept().await.expect("accept pooled request");
            accepts_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let requests = requests_for_task.clone();
            let progress = progress_for_task.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let mut pending = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    while !pending.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream
                            .read(&mut buffer)
                            .await
                            .expect("read pooled proxy request");
                        if read == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buffer[..read]);
                    }
                    let header_end = pending
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .expect("complete pooled proxy request")
                        + 4;
                    pending.drain(..header_end);

                    let request_number = requests
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        + 1;
                    progress.notify_waiters();
                    let threshold = if request_number <= 3 { 3 } else { 6 };
                    while requests.load(std::sync::atomic::Ordering::SeqCst)
                        < threshold
                    {
                        progress.notified().await;
                    }
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .expect("write pooled proxy response");
                }
            });
        }
    });

    let uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid pooled proxy URI");
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("http://{upstream_addr}/"),
        rewrite_host: true,
        insecure: false,
    };
    let transport =
        XrayProxyTransport::new(false).expect("build pooled proxy transport");
    let method = http::Method::GET;
    let headers = http::HeaderMap::new();
    let request = || {
        xray_proxy_masquerade_response_with_transport(
            &method,
            &uri,
            &headers,
            Bytes::new(),
            &config,
            &transport,
        )
    };

    let first = tokio::join!(request(), request(), request());
    for result in [first.0, first.1, first.2] {
        let (response, body) = result.expect("proxy first pooled request round");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body.as_deref(), Some(&b"ok"[..]));
    }
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "first concurrent round should establish three upstream connections",
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = tokio::join!(request(), request(), request());
    for result in [second.0, second.1, second.2] {
        let (response, body) = result.expect("proxy second pooled request round");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body.as_deref(), Some(&b"ok"[..]));
    }
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "Go DefaultTransport retains only two idle connections per host",
    );
    upstream.abort();
}

#[tokio::test]
async fn xray_proxy_masquerade_supports_https_http2_upstream() {
    let generated_cert =
        rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate h2 upstream certificate");
    let cert_bytes = generated_cert.cert.pem().into_bytes();
    let key_bytes = generated_cert.signing_key.serialize_pem().into_bytes();
    let server_config = crate::util::rustls_util::create_server_config(
        &cert_bytes,
        &key_bytes,
        &["h2".to_string()],
        &[],
    )
    .expect("build h2-only TLS upstream config");
    let acceptor =
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind h2-only proxy upstream");
    let upstream_addr = listener.local_addr().expect("read h2 upstream address");
    let upstream = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept h2 proxy request");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("accept h2 upstream TLS");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "Xray DefaultTransport negotiates HTTP/2 with an h2-only HTTPS upstream",
        );

        let service = hyper::service::service_fn(
            |request: hyper::Request<hyper::body::Incoming>| async move {
                assert_eq!(request.version(), http::Version::HTTP_2);
                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                    http_body_util::Full::new(Bytes::from_static(b"h2 upstream")),
                ))
            },
        );
        hyper::server::conn::http2::Builder::new(
            hyper_util::rt::TokioExecutor::new(),
        )
        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
        .await
        .expect("serve h2-only upstream request");
    });

    let uri: http::Uri = "https://original.test/path"
        .parse()
        .expect("valid h2 proxy URI");
    let config = Hysteria2MasqueradeProxyConfig {
        url: format!("https://localhost:{}/", upstream_addr.port()),
        rewrite_host: true,
        insecure: true,
    };
    let (response, body) = xray_proxy_masquerade_response(
        &http::Method::GET,
        &uri,
        &http::HeaderMap::new(),
        Bytes::new(),
        &config,
    )
    .await
    .expect("proxy Xray masquerade request to h2-only upstream");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body.as_deref(), Some(&b"h2 upstream"[..]));
    upstream.await.expect("join h2 upstream");
}

#[tokio::test]
async fn xray_proxy_masquerade_returns_bad_gateway_for_relative_target() {
    let uri: http::Uri = "https://original.test/path?q=2"
        .parse()
        .expect("valid proxy request URI");
    let config = Hysteria2MasqueradeProxyConfig {
        url: "/relative-upstream".to_string(),
        rewrite_host: false,
        insecure: false,
    };

    let (response, body) = xray_proxy_masquerade_response(
        &http::Method::GET,
        &uri,
        &http::HeaderMap::new(),
        Bytes::new(),
        &config,
    )
    .await
    .expect("relative Xray proxy target should become a gateway failure");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(body.is_none());
}

#[tokio::test]
async fn xray_file_masquerade_serves_files_indexes_redirects_and_listings() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chimera-hysteria2-file-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::create_dir_all(root.join("sub"))
        .await
        .expect("create file masquerade subdir");
    tokio::fs::create_dir_all(root.join("encoded.dir"))
        .await
        .expect("create encoded directory fixture");
    tokio::fs::create_dir_all(root.join("list/dir"))
        .await
        .expect("create file masquerade listing dir");
    tokio::fs::create_dir_all(root.join("indexdir/index.html"))
        .await
        .expect("create file masquerade index directory");
    #[cfg(unix)]
    tokio::fs::create_dir_all(root.join("badindex"))
        .await
        .expect("create file masquerade bad-index directory");
    tokio::fs::write(root.join("hello.txt"), b"hello file")
        .await
        .expect("write file masquerade file");
    tokio::fs::write(root.join("你好.txt"), b"unicode file")
        .await
        .expect("write unicode redirect fixture");
    tokio::fs::write(
        root.join("page.unknown"),
        b"<!doctype html><title>x</title>",
    )
    .await
    .expect("write sniffed html file");
    tokio::fs::write(
        root.join("image.unknown"),
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR",
    )
    .await
    .expect("write sniffed png file");
    tokio::fs::write(root.join("plain.unknown"), b"plain text without extension")
        .await
        .expect("write sniffed text file");
    tokio::fs::write(root.join("binary.unknown"), b"\x00\x01\x02binary")
        .await
        .expect("write sniffed binary file");
    tokio::fs::write(root.join("module.mjs"), b"plain bytes")
        .await
        .expect("write Xray MIME override file");
    tokio::fs::write(root.join("sub/index.html"), b"sub index")
        .await
        .expect("write file masquerade index");
    tokio::fs::write(root.join("list/z.txt"), b"z")
        .await
        .expect("write listing entry");
    tokio::fs::write(root.join("list/a&b.txt"), b"a")
        .await
        .expect("write escaped listing entry");
    tokio::fs::write(root.join("indexdir/parent.txt"), b"parent")
        .await
        .expect("write parent index-directory entry");
    tokio::fs::write(root.join("indexdir/index.html/inside.txt"), b"inside")
        .await
        .expect("write nested index-directory entry");
    #[cfg(unix)]
    {
        tokio::fs::write(root.join("badindex/visible.txt"), b"visible")
            .await
            .expect("write bad-index parent listing entry");
        std::os::unix::fs::symlink("index.html", root.join("badindex/index.html"))
            .expect("create self-referential index symlink");
    }

    let root_str = root.to_string_lossy();
    let get = http::Method::GET;
    let headers = http::HeaderMap::new();
    let file_uri: http::Uri = "https://example.test/hello%2Etxt"
        .parse()
        .expect("valid file URI");
    let (file_response, file_body) =
        xray_file_masquerade_response(&get, &file_uri, &headers, &root_str)
            .await
            .expect("serve Xray file masquerade file");
    assert_eq!(file_response.status(), StatusCode::OK);
    assert_eq!(
        file_response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
    );
    assert_eq!(file_body.as_deref(), Some(&b"hello file"[..]));

    let encoded_file_redirect_uri: http::Uri =
        "https://example.test/hello%2Etxt/?keep=yes"
            .parse()
            .expect("valid encoded file redirect URI");
    let (encoded_file_redirect_response, encoded_file_redirect_body) =
        xray_file_masquerade_response(
            &get,
            &encoded_file_redirect_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("redirect encoded Xray file basename");
    assert_eq!(
        encoded_file_redirect_response.status(),
        StatusCode::MOVED_PERMANENTLY
    );
    assert_eq!(
        encoded_file_redirect_response
            .headers()
            .get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("../hello.txt?keep=yes"))
    );
    assert!(encoded_file_redirect_body.is_none());

    let unicode_file_redirect_uri: http::Uri =
        "https://example.test/%e4%bd%a0%e5%a5%bd%2Etxt/"
            .parse()
            .expect("valid unicode file redirect URI");
    let (unicode_file_redirect_response, _) = xray_file_masquerade_response(
        &get,
        &unicode_file_redirect_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("redirect unicode Xray file basename");
    assert_eq!(
        unicode_file_redirect_response
            .headers()
            .get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("../%E4%BD%A0%E5%A5%BD.txt"))
    );

    let last_modified = file_response
        .headers()
        .get(http::header::LAST_MODIFIED)
        .cloned()
        .expect("Xray file response should expose Last-Modified");
    let mut conditional_headers = http::HeaderMap::new();
    conditional_headers
        .insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
    let (not_modified_response, not_modified_body) = xray_file_masquerade_response(
        &get,
        &file_uri,
        &conditional_headers,
        &root_str,
    )
    .await
    .expect("honor Xray If-Modified-Since condition");
    assert_eq!(not_modified_response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        not_modified_response
            .headers()
            .get(http::header::LAST_MODIFIED),
        Some(&last_modified)
    );
    assert!(
        not_modified_response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none()
    );
    assert!(not_modified_body.is_none());

    let mut if_match_headers = http::HeaderMap::new();
    if_match_headers.insert(
        http::header::IF_MATCH,
        http::HeaderValue::from_static("\"missing-etag\""),
    );
    if_match_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=0-1"),
    );
    let (if_match_response, if_match_body) =
        xray_file_masquerade_response(&get, &file_uri, &if_match_headers, &root_str)
            .await
            .expect("reject unmatched Xray If-Match before Range");
    assert_eq!(if_match_response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        if_match_response.headers().get(http::header::LAST_MODIFIED),
        Some(&last_modified)
    );
    assert!(
        if_match_response
            .headers()
            .get(http::header::CONTENT_RANGE)
            .is_none()
    );
    assert!(if_match_body.is_none());

    let mut if_unmodified_headers = http::HeaderMap::new();
    if_unmodified_headers.insert(
        http::header::IF_UNMODIFIED_SINCE,
        http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:01 GMT"),
    );
    let (if_unmodified_response, _) = xray_file_masquerade_response(
        &get,
        &file_uri,
        &if_unmodified_headers,
        &root_str,
    )
    .await
    .expect("reject stale Xray If-Unmodified-Since");
    assert_eq!(
        if_unmodified_response.status(),
        StatusCode::PRECONDITION_FAILED
    );

    if_unmodified_headers
        .insert(http::header::IF_MATCH, http::HeaderValue::from_static("*"));
    let (if_match_star_response, if_match_star_body) =
        xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_unmodified_headers,
            &root_str,
        )
        .await
        .expect("Xray If-Match should take precedence over If-Unmodified-Since");
    assert_eq!(if_match_star_response.status(), StatusCode::OK);
    assert_eq!(if_match_star_body.as_deref(), Some(&b"hello file"[..]));

    let mut if_none_match_headers = http::HeaderMap::new();
    if_none_match_headers.insert(
        http::header::IF_NONE_MATCH,
        http::HeaderValue::from_static("*"),
    );
    let (if_none_match_response, if_none_match_body) =
        xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_none_match_headers,
            &root_str,
        )
        .await
        .expect("honor Xray If-None-Match wildcard");
    assert_eq!(if_none_match_response.status(), StatusCode::NOT_MODIFIED);
    assert!(if_none_match_body.is_none());

    let post = http::Method::POST;
    let (post_if_none_match_response, post_if_none_match_body) =
        xray_file_masquerade_response(
            &post,
            &file_uri,
            &if_none_match_headers,
            &root_str,
        )
        .await
        .expect("reject matching Xray If-None-Match on non-GET request");
    assert_eq!(
        post_if_none_match_response.status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert!(post_if_none_match_body.is_none());

    if_none_match_headers.insert(
        http::header::IF_NONE_MATCH,
        http::HeaderValue::from_static("\"missing-etag\""),
    );
    if_none_match_headers
        .insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
    let (nonmatching_if_none_match_response, nonmatching_if_none_match_body) =
        xray_file_masquerade_response(
            &get,
            &file_uri,
            &if_none_match_headers,
            &root_str,
        )
        .await
        .expect("Xray If-None-Match presence should suppress If-Modified-Since");
    assert_eq!(nonmatching_if_none_match_response.status(), StatusCode::OK);
    assert_eq!(
        nonmatching_if_none_match_body.as_deref(),
        Some(&b"hello file"[..])
    );

    let mut empty_range_headers = http::HeaderMap::new();
    empty_range_headers
        .insert(http::header::RANGE, http::HeaderValue::from_static(""));
    let (empty_range_response, empty_range_body) = xray_file_masquerade_response(
        &get,
        &file_uri,
        &empty_range_headers,
        &root_str,
    )
    .await
    .expect("ignore empty Xray Range header");
    assert_eq!(empty_range_response.status(), StatusCode::OK);
    assert_eq!(empty_range_body.as_deref(), Some(&b"hello file"[..]));

    let mut range_headers = http::HeaderMap::new();
    range_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=1-4"),
    );
    let (range_response, range_body) =
        xray_file_masquerade_response(&get, &file_uri, &range_headers, &root_str)
            .await
            .expect("serve Xray byte range");
    assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range_response.headers().get(http::header::ACCEPT_RANGES),
        Some(&http::HeaderValue::from_static("bytes"))
    );
    assert_eq!(
        range_response.headers().get(http::header::CONTENT_RANGE),
        Some(&http::HeaderValue::from_static("bytes 1-4/10"))
    );
    assert_eq!(range_body.as_deref(), Some(&b"ello"[..]));

    range_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=-4"),
    );
    let (_, suffix_body) =
        xray_file_masquerade_response(&get, &file_uri, &range_headers, &root_str)
            .await
            .expect("serve Xray suffix range");
    assert_eq!(suffix_body.as_deref(), Some(&b"file"[..]));

    range_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=0-1,6-9"),
    );
    let (multi_response, multi_body) =
        xray_file_masquerade_response(&get, &file_uri, &range_headers, &root_str)
            .await
            .expect("serve Xray multipart ranges");
    assert_eq!(multi_response.status(), StatusCode::PARTIAL_CONTENT);
    let multipart_content_type = multi_response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("multipart Xray range Content-Type");
    let boundary = multipart_content_type
        .strip_prefix("multipart/byteranges; boundary=")
        .expect("multipart Xray range boundary");
    assert_eq!(boundary.len(), 60);
    assert!(
        boundary
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "Xray multipart boundary must be lowercase hex",
    );
    let multi_body = multi_body.expect("multipart range body");
    assert!(multi_body.windows(2).any(|window| window == b"he"));
    assert!(multi_body.windows(4).any(|window| window == b"file"));

    let mut if_range_headers = http::HeaderMap::new();
    if_range_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=0-1"),
    );
    if_range_headers.insert(http::header::IF_RANGE, last_modified.clone());
    let (if_range_response, if_range_body) =
        xray_file_masquerade_response(&get, &file_uri, &if_range_headers, &root_str)
            .await
            .expect("honor matching Xray If-Range date");
    assert_eq!(if_range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(if_range_body.as_deref(), Some(&b"he"[..]));

    if_range_headers.insert(
        http::header::IF_RANGE,
        http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:01 GMT"),
    );
    let (stale_if_range_response, stale_if_range_body) =
        xray_file_masquerade_response(&get, &file_uri, &if_range_headers, &root_str)
            .await
            .expect("ignore stale Xray If-Range range");
    assert_eq!(stale_if_range_response.status(), StatusCode::OK);
    assert_eq!(stale_if_range_body.as_deref(), Some(&b"hello file"[..]));

    let (post_if_range_response, post_if_range_body) =
        xray_file_masquerade_response(
            &http::Method::POST,
            &file_uri,
            &if_range_headers,
            &root_str,
        )
        .await
        .expect("ignore Xray If-Range outside GET/HEAD");
    assert_eq!(post_if_range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(post_if_range_body.as_deref(), Some(&b"he"[..]));

    range_headers.insert(
        http::header::RANGE,
        http::HeaderValue::from_static("bytes=50-60"),
    );
    let (unsatisfied_response, unsatisfied_body) =
        xray_file_masquerade_response(&get, &file_uri, &range_headers, &root_str)
            .await
            .expect("reject unsatisfied Xray range");
    assert_eq!(
        unsatisfied_response.status(),
        StatusCode::RANGE_NOT_SATISFIABLE
    );
    assert_eq!(
        unsatisfied_response
            .headers()
            .get(http::header::CONTENT_RANGE),
        Some(&http::HeaderValue::from_static("bytes */10"))
    );
    assert_eq!(
        unsatisfied_body.as_deref(),
        Some(&b"invalid range: failed to overlap\n"[..])
    );

    for overflow_range in [
        "bytes=9223372036854775808-",
        "bytes=0-9223372036854775808",
        "bytes=-9223372036854775808",
    ] {
        range_headers.insert(
            http::header::RANGE,
            http::HeaderValue::from_static(overflow_range),
        );
        let (overflow_response, overflow_body) = xray_file_masquerade_response(
            &get,
            &file_uri,
            &range_headers,
            &root_str,
        )
        .await
        .expect("reject Xray signed-int64 Range overflow");
        assert_eq!(
            overflow_response.status(),
            StatusCode::RANGE_NOT_SATISFIABLE,
            "Range {overflow_range}",
        );
        assert!(
            overflow_response
                .headers()
                .get(http::header::CONTENT_RANGE)
                .is_none(),
            "overflow is invalid rather than merely non-overlapping for {overflow_range}",
        );
        assert_eq!(
            overflow_body.as_deref(),
            Some(&b"invalid range\n"[..]),
            "Range {overflow_range}",
        );
    }

    let redirect_uri: http::Uri = "https://example.test/sub?keep=yes"
        .parse()
        .expect("valid directory URI");
    let (redirect_response, _) =
        xray_file_masquerade_response(&get, &redirect_uri, &headers, &root_str)
            .await
            .expect("redirect Xray file masquerade directory");
    assert_eq!(redirect_response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        redirect_response.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("sub/?keep=yes"))
    );

    let encoded_directory_redirect_uri: http::Uri =
        "https://example.test/encoded%2Edir"
            .parse()
            .expect("valid encoded directory redirect URI");
    let (encoded_directory_redirect_response, _) = xray_file_masquerade_response(
        &get,
        &encoded_directory_redirect_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("redirect encoded Xray directory basename");
    assert_eq!(
        encoded_directory_redirect_response
            .headers()
            .get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("encoded.dir/"))
    );

    let encoded_directory_slash_uri: http::Uri = "https://example.test/sub%2F"
        .parse()
        .expect("valid encoded directory slash URI");
    let (encoded_directory_slash_response, encoded_directory_slash_body) =
        xray_file_masquerade_response(
            &get,
            &encoded_directory_slash_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("treat decoded slash as Xray directory slash");
    assert_eq!(encoded_directory_slash_response.status(), StatusCode::OK);
    assert_eq!(
        encoded_directory_slash_body.as_deref(),
        Some(&b"sub index"[..])
    );

    let encoded_index_uri: http::Uri =
        "https://example.test/sub/index%2Ehtml?keep=yes"
            .parse()
            .expect("valid encoded index redirect URI");
    let (encoded_index_response, encoded_index_body) =
        xray_file_masquerade_response(&get, &encoded_index_uri, &headers, &root_str)
            .await
            .expect("redirect encoded Xray index.html path");
    assert_eq!(
        encoded_index_response.status(),
        StatusCode::MOVED_PERMANENTLY
    );
    assert_eq!(
        encoded_index_response.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("./?keep=yes"))
    );
    assert!(encoded_index_body.is_none());

    let index_uri: http::Uri = "https://example.test/sub/"
        .parse()
        .expect("valid index URI");
    let (_, index_body) =
        xray_file_masquerade_response(&get, &index_uri, &headers, &root_str)
            .await
            .expect("serve Xray file masquerade index");
    assert_eq!(index_body.as_deref(), Some(&b"sub index"[..]));

    let explicit_index_uri: http::Uri = "https://example.test/sub/index.html?q=1"
        .parse()
        .expect("valid explicit index URI");
    let (explicit_index_response, _) = xray_file_masquerade_response(
        &get,
        &explicit_index_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("redirect explicit Xray index path");
    assert_eq!(
        explicit_index_response
            .headers()
            .get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("./?q=1"))
    );

    let list_uri: http::Uri = "https://example.test/list/"
        .parse()
        .expect("valid listing URI");
    let (list_response, list_body) =
        xray_file_masquerade_response(&get, &list_uri, &headers, &root_str)
            .await
            .expect("serve Xray directory listing");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_last_modified = list_response
        .headers()
        .get(http::header::LAST_MODIFIED)
        .cloned()
        .expect("Xray directory listing should expose Last-Modified");
    let listing = std::str::from_utf8(list_body.as_deref().expect("listing body"))
        .expect("utf8 directory listing");
    assert!(listing.contains("href=\"a&b.txt\">a&amp;b.txt</a>"));
    assert!(listing.contains("href=\"dir/\">dir/</a>"));
    assert!(listing.find("a&amp;b.txt").unwrap() < listing.find("z.txt").unwrap());

    let mut list_conditional_headers = http::HeaderMap::new();
    list_conditional_headers
        .insert(http::header::IF_MODIFIED_SINCE, list_last_modified);
    let (list_not_modified_response, list_not_modified_body) =
        xray_file_masquerade_response(
            &get,
            &list_uri,
            &list_conditional_headers,
            &root_str,
        )
        .await
        .expect("honor Xray directory If-Modified-Since condition");
    assert_eq!(
        list_not_modified_response.status(),
        StatusCode::NOT_MODIFIED
    );
    assert!(
        list_not_modified_response
            .headers()
            .get(http::header::LAST_MODIFIED)
            .is_none()
    );
    assert!(list_not_modified_body.is_none());

    let index_directory_uri: http::Uri = "https://example.test/indexdir/"
        .parse()
        .expect("valid index-directory URI");
    let (index_directory_response, index_directory_body) =
        xray_file_masquerade_response(
            &get,
            &index_directory_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("serve Xray index.html directory listing");
    assert_eq!(index_directory_response.status(), StatusCode::OK);
    let index_directory_listing = std::str::from_utf8(
        index_directory_body
            .as_deref()
            .expect("index-directory listing body"),
    )
    .expect("utf8 index-directory listing");
    assert!(index_directory_listing.contains("inside.txt"));
    assert!(!index_directory_listing.contains("parent.txt"));
    assert!(!index_directory_listing.contains("index.html/"));

    #[cfg(unix)]
    {
        let bad_index_uri: http::Uri = "https://example.test/badindex/"
            .parse()
            .expect("valid bad-index URI");
        let (bad_index_response, bad_index_body) =
            xray_file_masquerade_response(&get, &bad_index_uri, &headers, &root_str)
                .await
                .expect("ignore Xray index.html stat failure");
        assert_eq!(bad_index_response.status(), StatusCode::OK);
        let bad_index_listing = std::str::from_utf8(
            bad_index_body.as_deref().expect("bad-index listing body"),
        )
        .expect("utf8 bad-index listing");
        assert!(bad_index_listing.contains("visible.txt"));
        assert!(bad_index_listing.contains("index.html"));

        let invalid_uri: http::Uri = "https://example.test/bad%00path"
            .parse()
            .expect("valid encoded-NUL URI");
        let (invalid_response, invalid_body) =
            xray_file_masquerade_response(&get, &invalid_uri, &headers, &root_str)
                .await
                .expect("map invalid filesystem path to Xray HTTP error");
        assert_eq!(invalid_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            invalid_response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(
            invalid_response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(invalid_body.as_deref(), Some(&b"404 page not found\n"[..]));
    }

    let cleaned_uri: http::Uri = "https://example.test/../hello.txt"
        .parse()
        .expect("valid cleaned URI");
    let (_, cleaned_body) =
        xray_file_masquerade_response(&get, &cleaned_uri, &headers, &root_str)
            .await
            .expect("clean Xray file path within root");
    assert_eq!(cleaned_body.as_deref(), Some(&b"hello file"[..]));

    for (name, expected_type) in [
        ("page.unknown", "text/html; charset=utf-8"),
        ("image.unknown", "image/png"),
        ("plain.unknown", "text/plain; charset=utf-8"),
        ("binary.unknown", "application/octet-stream"),
        ("module.mjs", "text/javascript; charset=utf-8"),
    ] {
        let uri: http::Uri = format!("https://example.test/{name}")
            .parse()
            .expect("valid sniffed file URI");
        let (response, _) =
            xray_file_masquerade_response(&get, &uri, &headers, &root_str)
                .await
                .expect("serve sniffed Xray file masquerade file");
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(expected_type),
            "content type for {name}",
        );
    }

    tokio::fs::remove_dir_all(&root)
        .await
        .expect("remove file masquerade tempdir");
}

#[cfg(unix)]
#[tokio::test]
async fn xray_file_unix_names_preserve_non_utf8_bytes() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chimera-hysteria2-nonutf8-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::create_dir_all(&root)
        .await
        .expect("create non-UTF8 file masquerade root");

    let file_name = OsString::from_vec(b"raw\xFF.bin".to_vec());
    tokio::fs::write(root.join(&file_name), b"\0raw")
        .await
        .expect("write non-UTF8 file fixture");
    let directory_name = OsString::from_vec(b"dir\xFE".to_vec());
    tokio::fs::create_dir(root.join(&directory_name))
        .await
        .expect("create non-UTF8 directory fixture");
    tokio::fs::write(root.join(&directory_name).join("inside.txt"), b"inside")
        .await
        .expect("write non-UTF8 directory child");

    let root_str = root.to_string_lossy();
    let headers = http::HeaderMap::new();
    let file_uri: http::Uri = "https://example.test/raw%FF.bin"
        .parse()
        .expect("valid encoded non-UTF8 file URI");
    let (file_response, file_body) = xray_file_masquerade_response(
        &http::Method::GET,
        &file_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("serve encoded non-UTF8 Xray file");
    assert_eq!(file_response.status(), StatusCode::OK);
    assert_eq!(file_body.as_deref(), Some(&b"\0raw"[..]));

    let directory_uri: http::Uri = "https://example.test/dir%FE"
        .parse()
        .expect("valid encoded non-UTF8 directory URI");
    let (directory_redirect, directory_redirect_body) =
        xray_file_masquerade_response(
            &http::Method::GET,
            &directory_uri,
            &headers,
            &root_str,
        )
        .await
        .expect("redirect encoded non-UTF8 Xray directory");
    assert_eq!(directory_redirect.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        directory_redirect.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("dir%FE/"))
    );
    assert!(directory_redirect_body.is_none());

    let list_uri: http::Uri = "https://example.test/"
        .parse()
        .expect("valid non-UTF8 listing URI");
    let (list_response, list_body) = xray_file_masquerade_response(
        &http::Method::GET,
        &list_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("list non-UTF8 Xray file names");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = list_body.expect("non-UTF8 directory listing body");
    for expected in [
        &b"href=\"raw%FF.bin\">raw\xFF.bin</a>"[..],
        &b"href=\"dir%FE/\">dir\xFE/</a>"[..],
    ] {
        assert!(
            list_body
                .windows(expected.len())
                .any(|window| window == expected),
            "directory listing should preserve {:?}",
            expected,
        );
    }

    let nested_uri: http::Uri = "https://example.test/dir%FE/inside.txt"
        .parse()
        .expect("valid nested non-UTF8 directory URI");
    let (nested_response, nested_body) = xray_file_masquerade_response(
        &http::Method::GET,
        &nested_uri,
        &headers,
        &root_str,
    )
    .await
    .expect("serve file below non-UTF8 Xray directory");
    assert_eq!(nested_response.status(), StatusCode::OK);
    assert_eq!(nested_body.as_deref(), Some(&b"inside"[..]));

    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove non-UTF8 file masquerade root");
}

#[test]
fn xray_file_windows_paths_match_localize_rejections() {
    for path in [
        "/a%5Cb",
        "/a:b",
        "/a%00b",
        "/CON",
        "/nested/prn",
        "/AUX",
        "/nul",
        "/COM1",
        "/com9",
        "/LPT1",
        "/lpt9",
        "/COM¹",
        "/com²",
        "/LPT³",
        "/ConIn$",
        "/conout$",
    ] {
        assert!(
            decode_file_masquerade_path_for_platform(path, true).is_none(),
            "Windows should reject Xray file path {path}",
        );
    }
    for path in ["/a/b", "/COM0", "/COM10", "/LPT0", "/console"] {
        assert!(
            decode_file_masquerade_path_for_platform(path, true).is_some(),
            "Windows should keep non-reserved Xray file path {path}",
        );
    }
    assert!(
        decode_file_masquerade_path_for_platform("/a%5Cb", false).is_some(),
        "Unix should preserve backslash as a filename character",
    );
}

#[tokio::test]
async fn xray_file_root_file_with_slash_returns_non_directory_error() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chimera-hysteria2-file-root-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::write(&root, b"root file")
        .await
        .expect("write file masquerade root file");
    let root_str = root.to_string_lossy();

    for uri in [
        "https://example.test/",
        "https://example.test/./",
        "https://example.test/%2E/",
    ] {
        let uri: http::Uri = uri.parse().expect("valid root-file URI");
        let (response, body) = xray_file_masquerade_response(
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            &root_str,
        )
        .await
        .expect("map root file slash to Xray non-directory error");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            body.as_deref(),
            Some(&b"http: attempting to traverse a non-directory\n"[..])
        );
    }

    tokio::fs::remove_file(root)
        .await
        .expect("remove file masquerade root file");
}

#[test]
fn xray_file_extension_types_match_go_builtin_mime_differences() {
    for (name, expected) in [
        ("sample.com", "application/octet-stream"),
        (
            "sample.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        ("sample.ehtml", "text/html; charset=utf-8"),
        ("sample.ico", "image/vnd.microsoft.icon"),
        ("sample.m4a", "audio/mp4"),
        ("sample.MJS", "text/javascript; charset=utf-8"),
        ("sample.pjp", "image/jpeg"),
        ("sample.pjpeg", "image/jpeg"),
        (
            "sample.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        ("sample.webm", "audio/webm"),
        ("sample.xbl", "text/xml; charset=utf-8"),
        (
            "sample.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    ] {
        assert_eq!(
            xray_file_extension_content_type(Path::new(name)),
            Some(expected),
            "Xray MIME type for {name}",
        );
    }
    assert_eq!(
        xray_file_extension_content_type(Path::new("sample.txt")),
        None
    );
}

#[test]
fn xray_file_url_escape_matches_go_path_encoding() {
    assert_eq!(
        xray_file_url_escape("azAZ09-._~/$&+,:;=@"),
        "azAZ09-._~/$&+,:;=@"
    );
    assert_eq!(
        xray_file_url_escape("space ?#%!'()*[]"),
        "space%20%3F%23%25%21%27%28%29%2A%5B%5D"
    );
    assert_eq!(xray_file_url_escape("你好.txt"), "%E4%BD%A0%E5%A5%BD.txt");
}

#[test]
fn xray_file_directory_entry_errors_match_go_readdir_behavior() {
    assert!(xray_file_directory_entry_disappeared(&Error::new(
        ErrorKind::NotFound,
        "entry vanished",
    )));
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::InvalidData,
        ErrorKind::Other,
    ] {
        assert!(
            !xray_file_directory_entry_disappeared(&Error::new(
                kind,
                "entry stat failed"
            )),
            "{kind:?} must fail the directory listing instead of being skipped",
        );
    }
}

#[tokio::test]
async fn xray_file_directory_read_errors_return_http_500() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "chimera-hysteria2-not-directory-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::write(&path, b"not a directory")
        .await
        .expect("write non-directory fixture");
    let modified = tokio::fs::metadata(&path)
        .await
        .expect("stat non-directory fixture")
        .modified()
        .ok();

    let (response, body) = xray_file_directory_response(
        &http::Method::GET,
        &http::HeaderMap::new(),
        &path,
        modified,
    )
    .await
    .expect("map directory read error to HTTP response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
    );
    assert_eq!(
        response.headers().get("x-content-type-options"),
        Some(&http::HeaderValue::from_static("nosniff"))
    );
    if modified.is_some() {
        assert!(response.headers().contains_key(http::header::LAST_MODIFIED));
    }
    assert_eq!(body.as_deref(), Some(&b"Error reading directory\n"[..]));

    tokio::fs::remove_file(path)
        .await
        .expect("remove non-directory fixture");
}

#[test]
fn xray_file_server_errors_match_go_http_error_responses() {
    for (kind, status, expected_body) in [
        (
            ErrorKind::NotFound,
            StatusCode::NOT_FOUND,
            &b"404 page not found\n"[..],
        ),
        (
            ErrorKind::NotADirectory,
            StatusCode::NOT_FOUND,
            &b"404 page not found\n"[..],
        ),
        (
            ErrorKind::PermissionDenied,
            StatusCode::FORBIDDEN,
            &b"403 Forbidden\n"[..],
        ),
        (
            ErrorKind::InvalidInput,
            StatusCode::INTERNAL_SERVER_ERROR,
            &b"500 Internal Server Error\n"[..],
        ),
    ] {
        let err = Error::new(kind, "sensitive filesystem detail");
        let (response, body) = xray_file_server_error_response(&err)
            .expect("build Xray file-server error response");
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH),
            Some(
                &http::HeaderValue::from_str(&expected_body.len().to_string())
                    .unwrap()
            )
        );
        assert_eq!(body.as_deref(), Some(expected_body));
    }
}

#[tokio::test]
async fn xray_file_non_directory_path_component_maps_to_not_found() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chimera-hysteria2-enotdir-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::create_dir(&root)
        .await
        .expect("create ENOTDIR fixture root");
    tokio::fs::write(root.join("file"), b"leaf")
        .await
        .expect("write ENOTDIR fixture file");
    let root_str = root.to_string_lossy().into_owned();
    let uri: http::Uri = "https://example.test/file/child"
        .parse()
        .expect("valid ENOTDIR fixture URI");

    let (response, body) = xray_file_masquerade_response(
        &http::Method::GET,
        &uri,
        &http::HeaderMap::new(),
        &root_str,
    )
    .await
    .expect("map Xray intermediate non-directory path");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body.as_deref(), Some(&b"404 page not found\n"[..]));

    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove ENOTDIR fixture root");
}

#[cfg(unix)]
#[tokio::test]
async fn xray_file_unreadable_file_maps_to_forbidden() {
    use std::os::unix::fs::PermissionsExt;

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "chimera-hysteria2-unreadable-{}-{suffix}",
        std::process::id()
    ));
    tokio::fs::create_dir(&root)
        .await
        .expect("create unreadable fixture root");
    let path = root.join("secret.txt");
    tokio::fs::write(&path, b"secret")
        .await
        .expect("write unreadable fixture file");
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .await
        .expect("make fixture unreadable");
    let root_str = root.to_string_lossy().into_owned();
    let uri: http::Uri = "https://example.test/secret.txt"
        .parse()
        .expect("valid unreadable fixture URI");

    let result = xray_file_masquerade_response(
        &http::Method::GET,
        &uri,
        &http::HeaderMap::new(),
        &root_str,
    )
    .await;

    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .await
        .expect("restore fixture permissions");
    tokio::fs::remove_dir_all(root)
        .await
        .expect("remove unreadable fixture root");

    let (response, body) = result.expect("map unreadable file to Xray HTTP error");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body.as_deref(), Some(&b"403 Forbidden\n"[..]));
}

#[test]
fn xray_file_etag_wildcard_scanner_stops_on_invalid_tags() {
    assert!(xray_etag_list_has_wildcard(b"*"));
    assert!(xray_etag_list_has_wildcard(
        b"\"missing\", W/\"also-missing\", *"
    ));
    assert!(!xray_etag_list_has_wildcard(b"\"missing\""));
    assert!(!xray_etag_list_has_wildcard(b"\"bad tag\", *"));
    assert!(!xray_etag_list_has_wildcard(b"W/\"unterminated, *"));
}

#[test]
fn xray_file_preconditions_ignore_unix_epoch_modtime() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::IF_MODIFIED_SINCE,
        http::HeaderValue::from_static("Thu, 01 Jan 2099 00:00:00 GMT"),
    );

    assert_eq!(
        xray_file_precondition_status(
            &http::Method::GET,
            &headers,
            Some(std::time::UNIX_EPOCH),
        ),
        None
    );
}

#[test]
fn xray_if_range_matches_pre_epoch_modtime() {
    let modified = UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("pre-epoch SystemTime");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::IF_RANGE,
        http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:59 GMT"),
    );

    assert!(xray_if_range_matches(
        &http::Method::GET,
        &headers,
        Some(modified),
    ));

    headers.insert(
        http::header::IF_RANGE,
        http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:58 GMT"),
    );
    assert!(!xray_if_range_matches(
        &http::Method::GET,
        &headers,
        Some(modified),
    ));
}

#[test]
fn xray_range_parser_rejects_non_utf8_header_bytes() {
    assert_eq!(xray_parse_ranges(b"\x80", 5), Err(XrayRangeError::Invalid),);
}

#[test]
fn xray_http_dates_support_pre_epoch_file_times() {
    let modified = UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("pre-epoch SystemTime");
    let formatted = xray_format_http_date(modified);
    assert_eq!(formatted, "Wed, 31 Dec 1969 23:59:59 GMT");
    assert_eq!(xray_parse_http_date(&formatted), Some(modified));

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::IF_MODIFIED_SINCE,
        http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:59 GMT"),
    );
    assert_eq!(
        xray_file_precondition_status(&http::Method::GET, &headers, Some(modified)),
        Some(StatusCode::NOT_MODIFIED),
    );

    headers.clear();
    headers.insert(
        http::header::IF_UNMODIFIED_SINCE,
        http::HeaderValue::from_static("Wed, 31 Dec 1969 23:59:58 GMT"),
    );
    assert_eq!(
        xray_file_precondition_status(&http::Method::GET, &headers, Some(modified)),
        Some(StatusCode::PRECONDITION_FAILED),
    );
}

#[test]
fn xray_http_date_parser_accepts_pre_epoch_legacy_formats() {
    let expected = UNIX_EPOCH
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("pre-epoch SystemTime");
    for value in [
        "Wednesday, 31-Dec-69 23:59:59 GMT",
        "Thursday, 31-Dec-69 23:59:59 GMT",
        "Wed Dec 31 23:59:59 1969",
        "Thu Dec 31 23:59:59 1969",
        "Wed, 31 Dec 1969 23:59:59 GMT",
        "Thu, 31 Dec 1969 23:59:59 GMT",
    ] {
        assert_eq!(
            xray_parse_http_date(value),
            Some(expected),
            "Xray/Go should parse HTTP date without validating weekday {value}",
        );
    }
    assert!(xray_parse_http_date("Nope, 31 Dec 1969 23:59:59 GMT").is_none());
}

#[test]
fn auth_password_matches_xray_and_shoes_exactly() {
    let clients = vec![Hysteria2Client {
        password: " spaced-secret ".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: false,
    }];

    validate_auth_request(
        auth_request(" spaced-secret ", AUTH_URI),
        &clients,
        false,
    )
    .expect("exact Xray Hysteria auth should match");
    assert!(matches!(
        validate_auth_request(
            auth_request("spaced-secret", AUTH_URI),
            &clients,
            false,
        ),
        Err(AuthReject::Unauthorized("password mismatch"))
    ));
}

#[test]
fn xray_empty_user_auth_matches_missing_header_without_relaxing_shoes() {
    let clients = vec![Hysteria2Client {
        password: String::new(),
        email: Some("empty@example.com".to_string()),
        level: 0,
        xray_uuid_route: true,
        xray_transport_auth_fallback: false,
    }];
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(AUTH_URI)
        .body(())
        .expect("valid Hysteria2 auth request without auth header");

    validate_auth_request(request.clone(), &clients, true)
        .expect("Xray Header.Get maps a missing auth header to an empty key");
    assert!(matches!(
        validate_auth_request(request, &clients, false),
        Err(AuthReject::Unauthorized("missing auth header"))
    ));
}

#[test]
fn xray_transport_auth_fallback_yields_to_validator_users() {
    let fallback = Hysteria2Client {
        password: "transport-fallback".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: true,
    };
    let dynamic_user = Hysteria2Client {
        password: "dynamic-user-auth".to_string(),
        email: Some("dynamic@example.com".to_string()),
        level: 0,
        xray_uuid_route: true,
        xray_transport_auth_fallback: false,
    };

    let mut clients = vec![fallback];
    assert!(
        match_hysteria_auth("transport-fallback", &clients, true).is_some(),
        "Xray transport auth fallback should work while the validator is empty"
    );

    clients.push(dynamic_user);
    assert!(
        match_hysteria_auth("transport-fallback", &clients, true).is_none(),
        "adding an Xray user must disable transport auth fallback"
    );
    assert_eq!(
        match_hysteria_auth("dynamic-user-auth", &clients, true)
            .and_then(|(client, _)| client.email),
        Some("dynamic@example.com".to_string())
    );

    clients.retain(|client| client.email.as_deref() != Some("dynamic@example.com"));
    assert!(
        match_hysteria_auth("transport-fallback", &clients, true).is_some(),
        "removing the last Xray user must re-enable transport auth fallback"
    );
}

#[test]
fn runtime_user_store_matches_xray_validator_index_lifecycle() {
    let fallback = Hysteria2Client {
        password: "transport-fallback".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: true,
    };
    let store = HysteriaUserStore::new(vec![fallback]);
    assert!(store.match_auth("transport-fallback", true).is_some());

    store.add_user(Hysteria2Client {
        password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        email: Some("first@example.com".to_string()),
        level: 3,
        xray_uuid_route: true,
        xray_transport_auth_fallback: false,
    });
    assert!(
        store.match_auth("transport-fallback", true).is_none(),
        "a non-empty Xray validator disables transport auth fallback"
    );
    let first = store
        .match_auth("00112233-4455-abcd-8899-aabbccddeeff", true)
        .expect("masked UUID should authenticate the first user");
    assert_eq!(first.0.email.as_deref(), Some("first@example.com"));
    assert_eq!(first.1, 0xabcd);

    store.add_user(Hysteria2Client {
        password: "00112233-4455-1234-8899-aabbccddeeff".to_string(),
        email: Some("second@example.com".to_string()),
        level: 7,
        xray_uuid_route: true,
        xray_transport_auth_fallback: false,
    });
    let shadowed = store
        .match_auth("00112233-4455-beef-8899-aabbccddeeff", true)
        .expect("later masked UUID user should own the secondary index");
    assert_eq!(shadowed.0.email.as_deref(), Some("second@example.com"));
    assert_eq!(shadowed.0.level, 7);
    assert_eq!(shadowed.1, 0xbeef);

    store.remove_user_by_email("first@example.com");
    assert!(
        store
            .match_auth("00112233-4455-beef-8899-aabbccddeeff", true)
            .is_none(),
        "deleting a colliding UUID user must remove the masked index without resurrecting another user"
    );
    assert!(
        store.match_auth("transport-fallback", true).is_none(),
        "the remaining validator user must keep transport fallback disabled"
    );

    store.remove_user_by_email("second@example.com");
    assert!(
        store.match_auth("transport-fallback", true).is_some(),
        "removing the final validator user re-enables transport fallback"
    );
}

#[test]
fn xray_uuid_user_auth_masks_route_bytes_but_shoes_id_stays_exact() {
    let xray_clients = vec![
        Hysteria2Client {
            password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            email: Some("shadowed@example.com".to_string()),
            level: 0,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        },
        Hysteria2Client {
            password: "00112233-4455-1234-8899-aabbccddeeff".to_string(),
            email: Some("route-user@example.com".to_string()),
            level: 0,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        },
    ];
    let routed = validate_auth_request(
        auth_request("00112233-4455-abcd-8899-aabbccddeeff", AUTH_URI),
        &xray_clients,
        true,
    )
    .expect("Xray UUID auth should ignore route bytes during lookup");
    assert_eq!(
        routed.client.email.as_deref(),
        Some("route-user@example.com")
    );
    assert_eq!(routed.vless_route, 0xabcd);

    let shoes_clients = vec![Hysteria2Client {
        password: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: false,
    }];
    assert!(matches!(
        validate_auth_request(
            auth_request("00112233-4455-abcd-8899-aabbccddeeff", AUTH_URI),
            &shoes_clients,
            false,
        ),
        Err(AuthReject::Unauthorized("password mismatch"))
    ));
}

#[test]
fn malformed_cc_rx_does_not_reject_authentication() {
    let clients = vec![Hysteria2Client {
        password: "secret".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: false,
    }];
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(AUTH_URI)
        .header(AUTH_HEADER, "secret")
        .header(CLIENT_CC_RX_HEADER, "not-a-number")
        .body(())
        .expect("valid Hysteria2 auth request");

    let auth = validate_auth_request(request, &clients, true)
        .expect("malformed CC-RX should be treated as zero like Xray");
    assert_eq!(auth.client_rx_limit, None);
}

#[test]
fn xray_congestion_tx_matches_hysteria_negotiation() {
    let shoes = hysteria2_config(None, None, None);
    assert_eq!(
        resolve_congestion_tx_bps(&shoes, Some(300_000), 200_000),
        200_000
    );

    for mode in ["reno", "bbr"] {
        let config = hysteria2_config(Some(mode), Some(500_000), None);
        assert_eq!(
            resolve_congestion_tx_bps(&config, Some(300_000), 200_000),
            0
        );
    }

    let brutal = hysteria2_config(Some("brutal"), Some(500_000), None);
    assert_eq!(
        resolve_congestion_tx_bps(&brutal, Some(300_000), 0),
        300_000
    );
    assert_eq!(resolve_congestion_tx_bps(&brutal, None, 0), 0);

    let forced = hysteria2_config(Some("force-brutal"), Some(500_000), None);
    assert_eq!(resolve_congestion_tx_bps(&forced, None, 0), 500_000);
}

#[test]
fn xray_defaults_without_finalmask_ignore_deprecated_bandwidth() {
    let config: Hysteria2ServerConfig = serde_json::from_value(serde_json::json!({
        "clients": [{"password": "secret"}],
        "bandwidth": {"up": 500000, "down": 750000},
        "xrayCompat": true
    }))
    .expect("valid Xray-default Hysteria2 config");

    assert_eq!(
        resolve_bandwidth_settings(&config, Some(300_000)),
        (300_000, 0, false)
    );
    assert_eq!(
        resolve_congestion_tx_bps(&config, Some(300_000), 200_000),
        0
    );
}

#[test]
fn xray_brutal_down_replaces_shoes_bandwidth_response() {
    let config = hysteria2_config(Some("brutal"), Some(500_000), Some(750_000));
    assert_eq!(
        resolve_bandwidth_settings(&config, Some(300_000)),
        (300_000, 750_000, false)
    );
}

#[test]
fn udp_cleanup_interval_matches_xray_and_shoes() {
    assert_eq!(udp_idle_cleanup_interval(true), Duration::from_secs(1));
    assert_eq!(udp_idle_cleanup_interval(false), Duration::from_secs(10));
}

#[test]
fn udp_activity_refresh_matches_xray_and_shoes() {
    assert!(refresh_udp_activity_on_datagram(true));
    assert!(refresh_udp_activity_on_response(true));
    assert!(!refresh_udp_activity_on_datagram(false));
    assert!(!refresh_udp_activity_on_response(false));
}

#[test]
fn xray_udp_idle_timeout_uses_strict_expiry_boundary() {
    let last_active = Instant::now();
    let timeout = Duration::from_secs(2);
    assert!(!udp_session_is_idle(
        last_active,
        last_active + timeout,
        timeout
    ));
    assert!(udp_session_is_idle(
        last_active,
        last_active + timeout + Duration::from_millis(1),
        timeout
    ));
}

#[test]
fn auth_requires_exact_shoes_uri() {
    let clients = vec![Hysteria2Client {
        password: "secret".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: false,
    }];
    assert!(
        validate_auth_request(auth_request("secret", AUTH_URI), &clients, false,)
            .is_ok()
    );
    for uri in [
        "https://hysteria/auth?extra=1",
        "https://example.com/auth",
        "http://hysteria/auth",
    ] {
        assert!(
            matches!(
                validate_auth_request(auth_request("secret", uri), &clients, false,),
                Err(AuthReject::NotAuthRequest)
            ),
            "unexpected auth URI accepted: {uri}"
        );
    }
}

#[test]
fn xray_auth_uri_matches_decoded_path_exact_authority_and_ignores_query() {
    let clients = vec![Hysteria2Client {
        password: "secret".to_string(),
        email: None,
        level: 0,
        xray_uuid_route: false,
        xray_transport_auth_fallback: false,
    }];
    let query_uri = "https://hysteria/auth?extra=1";

    for uri in [
        query_uri,
        "https://hysteria/%61uth",
        "https://hysteria/a%75th",
    ] {
        validate_auth_request(auth_request("secret", uri), &clients, true)
            .expect("Xray matches Hysteria auth against Go's decoded URL.Path");
    }
    assert!(matches!(
        validate_auth_request(auth_request("secret", query_uri), &clients, false,),
        Err(AuthReject::NotAuthRequest)
    ));
    assert!(matches!(
        validate_auth_request(
            auth_request("secret", "https://hysteria/%61uth"),
            &clients,
            false,
        ),
        Err(AuthReject::NotAuthRequest)
    ));
    assert!(matches!(
        validate_auth_request(
            auth_request("secret", "https://hysteria:443/auth"),
            &clients,
            true,
        ),
        Err(AuthReject::NotAuthRequest)
    ));
    for path in ["/Auth", "/%2Fauth", "/auth%2F", "/%zzuth", "/aut%"] {
        assert!(
            !xray_auth_path_matches(path),
            "unexpected Xray auth path: {path}"
        );
    }
}

#[tokio::test]
async fn udp_session_socket_is_dual_stack_like_shoes() {
    let socket =
        new_hysteria2_socket2_udp_socket().expect("create dual-stack UDP socket");
    assert!(
        socket
            .local_addr()
            .expect("dual-stack socket address")
            .as_socket()
            .expect("IP socket address")
            .is_ipv6()
    );
    assert!(!socket.only_v6().expect("read IPV6_V6ONLY"));

    let std_socket: std::net::UdpSocket = socket.into();
    let socket =
        UdpSocket::from_std(std_socket).expect("convert dual-stack UDP socket");
    let ipv4 = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind IPv4 UDP receiver");

    let ipv4_addr = ipv4.local_addr().expect("IPv4 receiver address");
    socket
        .send_to(b"v4", hysteria2_udp_send_addr(ipv4_addr))
        .await
        .expect("dual-stack socket should send to IPv4");

    let mut buf = [0u8; 2];
    let (len, sender) =
        tokio::time::timeout(Duration::from_secs(1), ipv4.recv_from(&mut buf))
            .await
            .expect("IPv4 receive should not time out")
            .expect("receive IPv4 datagram");
    assert_eq!(&buf[..len], b"v4");

    ipv4.send_to(b"ok", sender)
        .await
        .expect("reply to dual-stack socket");
    let (len, source) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .expect("dual-stack reply should not time out")
            .expect("receive IPv4 reply on dual-stack socket");
    assert_eq!(&buf[..len], b"ok");
    assert_eq!(normalize_hysteria2_udp_peer_addr(source), ipv4_addr);
}

#[test]
fn udp_session_send_address_maps_ipv4_for_dual_stack_sockets() {
    let ipv4 = SocketAddr::from(([192, 0, 2, 1], 443));
    let mapped = hysteria2_udp_send_addr(ipv4);
    assert_eq!(mapped, "[::ffff:192.0.2.1]:443".parse().unwrap());
    assert_eq!(normalize_hysteria2_udp_peer_addr(mapped), ipv4);

    let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    assert_eq!(hysteria2_udp_send_addr(ipv6), ipv6);
}

#[test]
fn fragment_cache_matches_shoes_bound() {
    let mut cache = hysteria2_fragment_cache();
    let remote_location = NetLocation::from_str("127.0.0.1:53", None)
        .expect("valid fragment test location");

    for packet_id in 0..=MAX_FRAGMENT_CACHE_SIZE as u16 {
        cache.put(
            packet_id,
            FragmentedPacket {
                fragment_count: 2,
                fragment_received: 1,
                packet_len: 1,
                received: vec![Some(Bytes::from_static(b"x")), None],
                remote_location: remote_location.clone(),
            },
        );
    }

    assert_eq!(cache.len(), MAX_FRAGMENT_CACHE_SIZE);
    assert!(
        !cache.contains(&0),
        "oldest incomplete packet should be evicted"
    );
    assert!(cache.contains(&(MAX_FRAGMENT_CACHE_SIZE as u16)));
}

#[test]
fn fragment_reassembly_matches_xray_single_packet_and_shoes_lru_semantics() {
    let remote_location = NetLocation::from_str("127.0.0.1:53", None)
        .expect("valid fragment test location");
    let packet = |fragment_count| FragmentedPacket {
        fragment_count,
        fragment_received: 1,
        packet_len: 1,
        received: vec![Some(Bytes::from_static(b"x")); fragment_count as usize],
        remote_location: remote_location.clone(),
    };

    let mut xray_cache = hysteria2_fragment_cache();
    xray_cache.put(10, packet(2));
    prepare_fragment_cache(&mut xray_cache, 11, 2, true);
    assert!(
        xray_cache.is_empty(),
        "new Xray packet should replace partial state"
    );

    xray_cache.put(11, packet(2));
    prepare_fragment_cache(&mut xray_cache, 11, 3, true);
    assert!(
        xray_cache.is_empty(),
        "changed Xray fragment count should replace partial state"
    );

    xray_cache.put(11, packet(3));
    prepare_fragment_cache(&mut xray_cache, 11, 3, true);
    assert_eq!(
        xray_cache.len(),
        1,
        "matching Xray fragments should retain state"
    );

    let mut shoes_cache = hysteria2_fragment_cache();
    shoes_cache.put(10, packet(2));
    prepare_fragment_cache(&mut shoes_cache, 11, 2, false);
    assert!(
        shoes_cache.contains(&10),
        "shoes should retain older partial packets"
    );
}

#[test]
fn completed_fragment_state_matches_xray_and_shoes_semantics() {
    let completed_packet = FragmentedPacket {
        fragment_count: 2,
        fragment_received: 2,
        packet_len: 2,
        received: vec![
            Some(Bytes::from_static(b"a")),
            Some(Bytes::from_static(b"b")),
        ],
        remote_location: NetLocation::from_str("127.0.0.1:53", None)
            .expect("valid fragment location"),
    };

    let mut xray_cache = hysteria2_fragment_cache();
    xray_cache.put(7, completed_packet.clone());
    let xray_completed = completed_fragment_packet(&mut xray_cache, 7, true)
        .expect("Xray completed packet should be readable");
    assert_eq!(xray_completed.packet_len, 2);
    assert!(
        xray_cache.contains(&7),
        "Xray retains completed defragmentation state until another packet resets it"
    );

    let mut shoes_cache = hysteria2_fragment_cache();
    shoes_cache.put(7, completed_packet);
    let shoes_completed = completed_fragment_packet(&mut shoes_cache, 7, false)
        .expect("shoes completed packet should be readable");
    assert_eq!(shoes_completed.packet_len, 2);
    assert!(
        !shoes_cache.contains(&7),
        "shoes removes a packet from its fragment cache after reassembly"
    );
}

#[test]
fn duplicate_fragments_match_xray_and_shoes_semantics() {
    let remote_location = NetLocation::from_str("127.0.0.1:53", None)
        .expect("valid fragment test location");
    let packet = FragmentedPacket {
        fragment_count: 2,
        fragment_received: 1,
        packet_len: 1,
        received: vec![Some(Bytes::from_static(b"x")), None],
        remote_location,
    };

    let mut xray_cache = hysteria2_fragment_cache();
    xray_cache.put(7, packet);
    handle_duplicate_fragment(&mut xray_cache, 7, true);
    assert!(
        xray_cache.contains(&7),
        "Xray should ignore a duplicate fragment and retain partial state"
    );

    let mut shoes_cache = hysteria2_fragment_cache();
    shoes_cache.put(
        7,
        FragmentedPacket {
            fragment_count: 2,
            fragment_received: 1,
            packet_len: 1,
            received: vec![Some(Bytes::from_static(b"x")), None],
            remote_location: NetLocation::from_str("127.0.0.1:53", None)
                .expect("valid fragment test location"),
        },
    );
    handle_duplicate_fragment(&mut shoes_cache, 7, false);
    assert!(
        !shoes_cache.contains(&7),
        "shoes should discard partial state after a duplicate fragment"
    );
}

#[test]
fn fragment_completion_address_matches_xray_and_shoes_semantics() {
    let first = NetLocation::from_str("127.0.0.1:53", None)
        .expect("valid first fragment location");
    let completing = NetLocation::from_str("127.0.0.1:5353", None)
        .expect("valid completing fragment location");

    assert_eq!(
        fragment_completion_location(first.clone(), completing.clone(), true),
        completing,
        "Xray keeps the address of the fragment that completes reassembly"
    );
    assert_eq!(
        fragment_completion_location(first.clone(), completing, false),
        first,
        "shoes keeps the first fragment address for the reassembled packet"
    );
}

#[test]
fn response_packet_ids_match_xray_and_shoes_semantics() {
    let mut xray_next = 41;
    assert_eq!(udp_response_packet_id(&mut xray_next, false, true), 0);
    assert_eq!(
        xray_next, 41,
        "Xray unfragmented packets do not consume IDs"
    );
    let fragmented_id = udp_response_packet_id(&mut xray_next, true, true);
    assert_ne!(fragmented_id, 0, "Xray fragmented packets use non-zero IDs");
    assert_eq!(
        xray_next, 41,
        "Xray fragmented IDs are random, not sequential"
    );

    let mut shoes_next = u16::MAX;
    assert_eq!(
        udp_response_packet_id(&mut shoes_next, false, false),
        u16::MAX
    );
    assert_eq!(shoes_next, 0, "shoes increments IDs for every datagram");
    assert_eq!(udp_response_packet_id(&mut shoes_next, true, false), 0);
    assert_eq!(shoes_next, 1);
}

#[test]
fn zero_fragment_udp_datagrams_match_xray_and_shoes_semantics() {
    assert!(accept_unfragmented_udp_datagram(0, true));
    assert!(!accept_unfragmented_udp_datagram(0, false));
    assert!(accept_unfragmented_udp_datagram(1, true));
    assert!(accept_unfragmented_udp_datagram(1, false));
    assert!(!accept_unfragmented_udp_datagram(2, true));
    assert!(!accept_unfragmented_udp_datagram(2, false));
}

#[test]
fn malformed_udp_datagram_bounds_are_rejected_without_panicking() {
    assert!(udp_datagram_address_bounds(&[], false).is_err());
    assert!(udp_datagram_address_bounds(&[0; 8], false).is_err());

    let mut truncated_varint = vec![0; 9];
    truncated_varint[8] = 0x40;
    assert!(udp_datagram_address_bounds(&truncated_varint, false).is_err());

    let mut truncated_address = vec![0; 9];
    truncated_address[8] = 5;
    assert!(udp_datagram_address_bounds(&truncated_address, false).is_err());

    let mut valid = vec![0; 8];
    valid.push(3);
    valid.extend_from_slice(b"dns");
    valid.extend_from_slice(b"payload");
    assert_eq!(
        udp_datagram_address_bounds(&valid, false)
            .expect("valid UDP datagram bounds"),
        (9, 12)
    );
    assert_eq!(
        udp_datagram_address_bounds(&valid, true)
            .expect("valid Xray UDP datagram bounds"),
        (9, 12)
    );
}

#[test]
fn empty_udp_payload_matches_xray_and_shoes_semantics() {
    let mut empty_payload = vec![0; 8];
    empty_payload.push(3);
    empty_payload.extend_from_slice(b"dns");

    assert_eq!(
        udp_datagram_address_bounds(&empty_payload, false)
            .expect("shoes accepts an empty UDP payload"),
        (9, 12)
    );
    assert!(
        udp_datagram_address_bounds(&empty_payload, true).is_err(),
        "Xray rejects UDP datagrams without payload bytes"
    );
}

#[test]
fn shoes_padding_bounds_apply_to_auth_and_tcp_frames() {
    assert_eq!(MAX_ADDRESS_LEN, 2048);

    for _ in 0..64 {
        let padding = random_auth_padding(false);
        assert!((1..80).contains(&padding.len()));
        assert!(padding.is_ascii());
    }

    assert_eq!(
        validate_tcp_request_padding_len(MAX_TCP_REQUEST_PADDING_LEN)
            .expect("maximum Shoes request padding should pass"),
        MAX_TCP_REQUEST_PADDING_LEN as usize
    );
    assert!(
        validate_tcp_request_padding_len(MAX_TCP_REQUEST_PADDING_LEN + 1).is_err()
    );

    for _ in 0..64 {
        let frame = build_tcp_response(TCP_SUCCESS_STATUS, "ok", false)
            .expect("TCP response frame should build");
        assert_eq!(frame[0], TCP_SUCCESS_STATUS);
        let (message_len, message_varint_len) =
            decode_varint_from_slice(&frame[1..]).expect("message length varint");
        assert_eq!(message_len, 2);
        let message_start = 1 + message_varint_len;
        assert_eq!(&frame[message_start..message_start + message_len], b"ok");
        let padding_start = message_start + message_len;
        let (padding_len, padding_varint_len) =
            decode_varint_from_slice(&frame[padding_start..])
                .expect("padding length varint");
        assert!(padding_len <= 63);
        assert_eq!(
            frame.len(),
            padding_start + padding_varint_len + padding_len
        );
    }
}

#[test]
fn xray_padding_bounds_and_alphabet_match_reference() {
    for _ in 0..64 {
        let padding = random_auth_padding(true);
        assert!((256..2048).contains(&padding.len()));
        assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));

        let frame = build_tcp_response(TCP_SUCCESS_STATUS, "ok", true)
            .expect("Xray TCP response frame should build");
        let (message_len, message_varint_len) =
            decode_varint_from_slice(&frame[1..]).expect("message length varint");
        let padding_start = 1 + message_varint_len + message_len;
        let (padding_len, padding_varint_len) =
            decode_varint_from_slice(&frame[padding_start..])
                .expect("padding length varint");
        assert!((128..1024).contains(&padding_len));
        let padding_bytes = &frame[padding_start + padding_varint_len
            ..padding_start + padding_varint_len + padding_len];
        assert!(
            padding_bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
    }
}
