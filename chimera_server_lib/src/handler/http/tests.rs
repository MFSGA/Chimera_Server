use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    duplex,
};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    config::{
        def::{PolicyConfig, PolicyLevelConfig},
        server_config::HttpUser,
    },
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    runtime::RuntimeState,
};

use super::{
    HttpTcpServerHandler, parse_absolute_http_authority, parse_http_request_line,
    relay_plain_http_response,
};

struct TestStream(DuplexStream);

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl AsyncPing for TestStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for TestStream {}

#[tokio::test]
async fn http_handshake_policy_covers_first_byte_like_xray() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            handshake: Some(0),
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    let (_client, server) = duplex(1024);
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-policy")
        .with_user_level(7);
    let context = TcpServerConnectionContext {
        runtime: Some(runtime.data_plane()),
        ..TcpServerConnectionContext::default()
    };
    assert_eq!(
        handler.pre_transport_handshake_timeout(&context),
        Some(std::time::Duration::ZERO)
    );
    let result = handler
        .setup_server_stream_with_context(Box::new(TestStream(server)), context)
        .await;
    let error = match result {
        Ok(_) => panic!(
            "zero-second Xray HTTP handshake policy must time out before first byte"
        ),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn request_line_spacing_matches_xray() {
    assert_eq!(
        parse_http_request_line("GET http://example.com/x HTTP/1.1").unwrap(),
        ("GET", "http://example.com/x", "HTTP/1.1")
    );
    for request_line in [
        "GET  http://example.com/x HTTP/1.1",
        "GET\thttp://example.com/x\tHTTP/1.1",
        " GET http://example.com/x HTTP/1.1",
        "GET http://example.com/x HTTP/1.1 ",
    ] {
        let error = parse_http_request_line(request_line)
            .expect_err("Xray rejects non-canonical request-line spacing");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn malformed_header_lines_match_xray_rejection() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
    for request in [
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nNoColon\r\n\r\n"
                .as_slice(),
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nX-Test: a\x01b\r\n\r\n"
                .as_slice(),
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nX-Test: a\x7fb\r\n\r\n"
                .as_slice(),
        ] {
            let (mut client, server) = duplex(1024);
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects malformed HTTP header framing"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
}

#[tokio::test]
async fn duplicate_host_headers_are_rejected_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), true, "http-host");
    for headers in [
        "Host: example.com\r\nHost: example.com\r\n",
        "Host: example.com\r\nHost: example.net\r\n",
        "Host:\r\nHost: example.com\r\n",
        "Host: example.com\r\nHost:\r\n",
    ] {
        let request = format!("GET /x HTTP/1.1\r\n{headers}\r\n");
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray rejects multiple Host headers"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("multiple HTTP Host headers"));
    }
}

#[tokio::test]
async fn absolute_form_allows_one_empty_host_header_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-host");
    let request = b"GET http://example.com/x HTTP/1.1\r\nHost:\r\n\r\n";
    let (mut client, server) = duplex(1024);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("absolute-form URL authority replaces one empty Host header");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("HTTP forward returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:80");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn folded_headers_are_unfolded_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
    for continuation in [" two", "\ttwo"] {
        let request = format!(
            "GET http://example.com/x HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 X-Test: one\r\n{continuation}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray unfolds obsolete header continuations");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded
                .windows(b"X-Test: one two\r\n".len())
                .any(|window| window == b"X-Test: one two\r\n")
        );
    }
}

#[tokio::test]
async fn invalid_header_names_are_dropped_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
    for invalid_header in ["X-Test : hidden", "Bad Header: hidden"] {
        let request = format!(
            "GET http://example.com/x HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 {invalid_header}\r\n\
                 X-Keep: visible\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect(
                "Xray drops invalid HTTP field names without rejecting the request",
            );
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            !forwarded
                .windows(b"hidden".len())
                .any(|window| window == b"hidden")
        );
        assert!(
            forwarded
                .windows(b"X-Keep: visible\r\n".len())
                .any(|window| window == b"X-Keep: visible\r\n")
        );
    }
}

#[tokio::test]
async fn header_value_tab_remains_accepted_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
    let request = b"GET http://example.com/x HTTP/1.1\r\n\
Host: example.com\r\n\
X-Test: a\tb\r\n\r\n";
    let (mut client, server) = duplex(1024);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray accepts horizontal tabs in HTTP header values");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("HTTP forward returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert!(
        forwarded
            .windows(b"X-Test: a\tb\r\n".len())
            .any(|window| window == b"X-Test: a\tb\r\n")
    );
}

#[tokio::test]
async fn connect_preserves_early_tunnel_bytes() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-in");
    let request =
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nearly";
    let (mut client, server) = duplex(1024);
    client.write_all(request).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("CONNECT should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        connection_success_response,
        traffic_context,
        ..
    } = result
    else {
        panic!("HTTP CONNECT returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:443");
    assert_eq!(
        connection_success_response.as_deref(),
        Some(b"HTTP/1.1 200 Connection established\r\n\r\n".as_slice())
    );
    assert_eq!(
        traffic_context.unwrap().inbound_tag.as_deref(),
        Some("http-in")
    );
    let mut early = [0u8; 5];
    stream.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"early");
}

#[tokio::test]
async fn basic_auth_sets_user_identity() {
    let handler = HttpTcpServerHandler::new(
        vec![HttpUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        false,
        "http-auth",
    );
    let token = BASE64.encode("alice:secret");
    let request = format!(
        "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    let (mut client, server) = duplex(1024);
    client.write_all(request.as_bytes()).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("authenticated CONNECT should succeed");
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = result
    else {
        panic!("HTTP CONNECT returned non-TCP result");
    };
    assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
}

#[tokio::test]
async fn basic_auth_matches_xray_scheme_and_spacing() {
    let handler = HttpTcpServerHandler::new(
        vec![HttpUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        false,
        "http-auth",
    );
    let token = BASE64.encode("alice:secret");

    for authorization in [
        format!("basic {token}"),
        format!("Basic  {token}"),
        format!("Basic\t{token}"),
    ] {
        let request = format!(
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: {authorization}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray rejects non-canonical Basic authorization"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required"));
    }
}

#[tokio::test]
async fn duplicate_proxy_authorization_uses_first_value_like_xray() {
    let handler = HttpTcpServerHandler::new(
        vec![HttpUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        false,
        "http-auth",
    );
    let valid = BASE64.encode("alice:secret");
    let invalid = BASE64.encode("alice:wrong");

    let request = format!(
        "CONNECT 127.0.0.1:80 HTTP/1.1\r\n\
             Proxy-Authorization: Basic {valid}\r\n\
             Proxy-Authorization: Basic {invalid}\r\n\r\n"
    );
    let (mut client, server) = duplex(1024);
    client.write_all(request.as_bytes()).await.unwrap();
    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray accepts when the first authorization is valid");
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = result
    else {
        panic!("HTTP CONNECT returned non-TCP result");
    };
    assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));

    let request = format!(
        "CONNECT 127.0.0.1:80 HTTP/1.1\r\n\
             Proxy-Authorization: Basic {invalid}\r\n\
             Proxy-Authorization: Basic {valid}\r\n\r\n"
    );
    let (mut client, server) = duplex(1024);
    client.write_all(request.as_bytes()).await.unwrap();
    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("Xray rejects when the first authorization is invalid"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required"));
}

#[tokio::test]
async fn absolute_form_request_is_rewritten_and_proxy_headers_are_removed() {
    let handler = HttpTcpServerHandler::new(
        vec![HttpUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        false,
        "http-forward",
    );
    let token = BASE64.encode("alice:secret");
    let request = format!(
        "POST http://example.com:8080/upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             Proxy-Authorization: Basic {token}\r\n\
             Proxy-Authenticate: Basic realm=\"upstream\"\r\n\
             TE: trailers\r\n\
             Trailers: X-Checksum\r\n\
             Upgrade: websocket\r\n\
             X-Remove-Early: hidden\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: keep-alive, X-Remove-Early, x-remove-late\r\n\
             X-Test: forwarded\r\n\
             X-Remove-Late: hidden-too\r\n\r\nbody"
    );
    let (mut client, server) = duplex(4096);
    client.write_all(request.as_bytes()).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("absolute-form HTTP proxy request should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        connection_success_response,
        traffic_context,
        ..
    } = result
    else {
        panic!("HTTP forward returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:8080");
    assert!(connection_success_response.is_none());
    assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "POST /upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             X-Test: forwarded\r\n\
             Connection: close\r\n\r\nbody"
    );
}

#[tokio::test]
async fn https_absolute_form_uses_default_https_semantics_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-https");
    let request = b"GET https://example.com/secure?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\
X-Test: forwarded\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("HTTPS absolute-form HTTP proxy request should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("HTTPS absolute-form request returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:443");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /secure?q=1 HTTP/1.1\r\n\
Host: example.com\r\n\
X-Test: forwarded\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn absolute_form_path_hashes_are_escaped_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-fragment");
    let request = b"GET http://example.com/path#frag?x=#query HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("absolute-form path hash should be normalized like Xray");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("absolute-form path hash returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:80");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /path%23frag?x=#query HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn absolute_form_rejects_invalid_percent_escapes_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-percent");
    for target in [
        "http://example.com/a%zz",
        "http://example.com/a%",
        "http://example.com/a%2",
        "http://example.com/ok?q=%zz",
    ] {
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n");
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("invalid percent escape should be rejected: {target}")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("invalid URL escape"));
    }
}

#[tokio::test]
async fn absolute_form_rejects_percent_escaped_host_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-host-escape");
    for target in [
        "http://exa%6dple.invalid/a",
        "http://127.0.0.1%40evil.invalid/a",
    ] {
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n");
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("percent-escaped host should be rejected: {target}"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("invalid URL escape"));
    }
}

#[tokio::test]
async fn absolute_form_accepts_percent_escaped_userinfo_like_xray() {
    let handler =
        HttpTcpServerHandler::new(Vec::new(), false, "http-userinfo-escape");
    let request = b"GET http://user%40name:pass@example.com/a HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("percent-escaped userinfo should remain accepted");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("percent-escaped userinfo returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:80");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /a HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn absolute_form_preserves_valid_percent_escapes_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-percent");
    let request = b"GET http://example.com/a%2Fb?q=%25 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("valid percent escapes should remain accepted");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("valid percent escapes returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /a%2Fb?q=%25 HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
    );
}

#[test]
fn absolute_form_ports_match_xray_uint16_conversion() {
    let defaulted = parse_absolute_http_authority("example.com:", 80)
        .expect("empty HTTP port should use the scheme default");
    assert_eq!(defaulted.to_string(), "example.com:80");

    let wrapped_zero = parse_absolute_http_authority("example.com:65536", 80)
        .expect("Xray wraps numeric HTTP ports to uint16");
    assert_eq!(wrapped_zero.to_string(), "example.com:0");

    let wrapped = parse_absolute_http_authority("example.com:99999", 80)
        .expect("Xray wraps large numeric HTTP ports to uint16");
    assert_eq!(wrapped.to_string(), "example.com:34463");

    let ipv6 = parse_absolute_http_authority("[2001:db8::1]:65536", 80)
        .expect("bracketed IPv6 uses the same Xray port conversion");
    assert_eq!(ipv6.address().to_string(), "2001:db8::1");
    assert_eq!(ipv6.port(), 0);
}

#[tokio::test]
async fn absolute_form_ipv6_authority_is_forwarded_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-ipv6");
    let request = b"GET http://[2001:db8::1]:8080/ipv6?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("bracketed IPv6 absolute-form request should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("IPv6 absolute-form request returned non-TCP result");
    };
    assert_eq!(remote_location.address().to_string(), "2001:db8::1");
    assert_eq!(remote_location.port(), 8080);
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /ipv6?q=1 HTTP/1.1\r\n\
Host: [2001:db8::1]:8080\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn absolute_form_ipv6_userinfo_uses_default_port_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-ipv6-user");
    let request = b"GET http://user:pass@[2001:db8::2]/secret HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("IPv6 userinfo absolute-form request should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("IPv6 userinfo absolute-form request returned non-TCP result");
    };
    assert_eq!(remote_location.address().to_string(), "2001:db8::2");
    assert_eq!(remote_location.port(), 80);
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /secret HTTP/1.1\r\n\
Host: [2001:db8::2]\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn absolute_form_userinfo_is_not_forwarded_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-userinfo");
    let request = b"GET http://user:pass@example.com:8080/secret?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("absolute-form userinfo should be accepted like Xray");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("absolute-form userinfo returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:8080");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /secret?q=1 HTTP/1.1\r\n\
Host: example.com:8080\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn chunked_request_drops_conflicting_content_length_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-chunked");
    let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 99\r\n\
Transfer-Encoding: chunked\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("chunked HTTP proxy request should succeed");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("HTTP forward returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n"
    );
}

#[tokio::test]
async fn chunked_request_trailers_match_xray_normalization() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-trailers");
    let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: x-foo, X-Foo\r\n\
Trailer: X-Bar\r\n\r\n\
4\r\ntest\r\n0\r\n\
X-Foo: one\r\nX-Unused: hidden\r\nX-Bar: two\r\nX-Foo: three\r\n\r\n";
    let (mut client, server) = duplex(4096);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("declared chunked trailers should succeed");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("chunked HTTP request returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    let forwarded = String::from_utf8(forwarded).unwrap();
    assert!(forwarded.contains("Trailer: X-Bar,X-Foo\r\n"));
    assert!(forwarded.ends_with(
        "4\r\ntest\r\n0\r\nX-Bar: two\r\nX-Foo: one\r\nX-Foo: three\r\n\r\n"
    ));
    assert!(!forwarded.contains("X-Unused"));

    let (mut client, server) = duplex(2048);
    client
            .write_all(
                b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("forbidden request trailer declaration must fail"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn invalid_first_chunk_size_fails_before_forwarding_bytes() {
    for chunk_size in ["Z", "0x4", "+4", " 4", "00000000000000000"] {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-chunk-size");
        let request = format!(
            "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 {chunk_size}\r\ntest\r\n0\r\n\r\n"
        );
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("chunk syntax validation is deferred until relay starts");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("chunked HTTP request returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        let error = stream.read_to_end(&mut forwarded).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(forwarded.is_empty());
    }
}

#[tokio::test]
async fn supported_first_chunk_size_variants_still_stream() {
    for chunk_size in ["4 ", "4;foo=bar"] {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-chunk-size");
        let request = format!(
            "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 {chunk_size}\r\ntest\r\n0\r\n\r\n"
        );
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray-compatible first chunk size should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("chunked HTTP request returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert!(forwarded.ends_with(b"4\r\ntest\r\n0\r\n\r\n"));
    }
}

#[tokio::test]
async fn http_10_chunked_body_is_ignored_like_xray() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-10-chunked");
    let request = b"POST http://example.com/upload HTTP/1.0\r\n\
Host: ignored.invalid\r\n\
Transfer-Encoding: chunked\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("HTTP/1.0 chunked request should succeed");
    let TcpServerSetupResult::HttpPlainForward {
        request_head,
        keep_alive,
        ..
    } = result
    else {
        panic!("HTTP/1.0 chunked request returned non-plain-HTTP result");
    };
    assert!(!keep_alive);
    assert_eq!(
        request_head.as_ref(),
        b"POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn unsupported_transfer_encoding_is_rejected_like_xray() {
    for transfer_encoding in [
        "gzip",
        "chunked, gzip",
        "gzip, chunked",
        "chunked\r\nTransfer-Encoding: chunked",
    ] {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-transfer-encoding");
        let request = format!(
            "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: {transfer_encoding}\r\n\r\n\
                 4\r\ntest\r\n0\r\n\r\n"
        );
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!(
                "unsupported Transfer-Encoding {transfer_encoding:?} must be rejected"
            ),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("unsupported HTTP Transfer-Encoding")
        );
    }
}

#[tokio::test]
async fn duplicate_content_length_is_collapsed_like_xray() {
    let handler =
        HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
    let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 4\r\n\r\nbody";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("matching duplicate Content-Length should succeed");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("HTTP forward returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Connection: close\r\n\r\nbody"
    );
}

#[tokio::test]
async fn content_length_numeric_syntax_matches_xray() {
    let handler =
        HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
    let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 0004\r\n\r\nbody";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("leading-zero Content-Length should succeed");
    let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
        panic!("HTTP forward returned non-TCP result");
    };
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Connection: close\r\n\r\nbody"
    );

    for content_length in ["+4", "9223372036854775808"] {
        let request = format!(
            "POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: {content_length}\r\n\r\nbody"
        );
        let (mut client, server) = duplex(2048);
        client.write_all(request.as_bytes()).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("invalid Content-Length {content_length:?} must fail")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("invalid HTTP Content-Length"));
    }
}

#[tokio::test]
async fn conflicting_content_length_is_rejected_like_xray() {
    let handler =
        HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
    let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 5\r\n\r\nbody";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("conflicting Content-Length must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("conflicting HTTP Content-Length")
    );
}

#[tokio::test]
async fn keep_alive_get_uses_plain_http_forward() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-keepalive");
    let request = b"GET http://example.com/one HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Proxy-Connection: keep-alive\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("keep-alive GET should use the plain HTTP relay");
    let TcpServerSetupResult::HttpPlainForward {
        remote_location,
        request_head,
        request_method,
        keep_alive,
        traffic_context,
        ..
    } = result
    else {
        panic!("keep-alive GET returned non-HTTP plain result");
    };
    assert_eq!(remote_location.to_string(), "example.com:80");
    assert_eq!(request_method, "GET");
    assert!(keep_alive);
    assert_eq!(
        traffic_context.unwrap().inbound_tag.as_deref(),
        Some("http-keepalive")
    );
    assert_eq!(
        request_head.as_ref(),
        b"GET /one HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn plain_http_response_with_content_length_is_reusable() {
    let upstream_response = b"HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
                                  HTTP/1.1 200 OK\r\n\
                                  Content-Length: 5\r\n\
                                  Connection: close, X-Remove\r\n\
                                  Keep-Alive: timeout=5\r\n\
                                  X-Remove: hidden\r\n\
                                  X-Keep: visible\r\n\r\nhello";
    let (mut upstream_client, mut upstream_server) = duplex(4096);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(4096);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 5\r\n\
             X-Keep: visible\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nhello"
    );
}

#[tokio::test]
async fn plain_http_response_collapses_duplicate_content_length_like_xray() {
    let upstream_response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 02\r\nContent-Length: 2\r\n\r\nok";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
    );
}

#[tokio::test]
async fn invalid_plain_http_response_content_length_returns_503_like_xray() {
    for content_lengths in [
        "Content-Length: nope",
        "Content-Length: +2",
        "Content-Length: 9223372036854775808",
        "Content-Length: 2\r\nContent-Length: 3",
    ] {
        let upstream_response =
            format!("HTTP/1.1 200 OK\r\n{content_lengths}\r\n\r\nok!");
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client
            .write_all(upstream_response.as_bytes())
            .await
            .unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable, "{content_lengths:?} must close");
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            "{content_lengths:?}"
        );
    }
}

#[tokio::test]
async fn chunked_plain_http_response_drops_content_length_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Content-Length: 99\r\n\
                                  X-Test: yes\r\n\r\n\
                                  2\r\nok\r\n0\r\n\r\n";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(!reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             X-Test: yes\r\n\
             Connection: close\r\n\r\n\
             2\r\nok\r\n0\r\n\r\n"
    );
}

#[tokio::test]
async fn chunked_plain_http_response_reencodes_payload_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\r\n\
                                  4;foo=bar\r\ntest\r\n3\r\nxyz\r\n0\r\n\r\n";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(!reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n\
              7\r\ntestxyz\r\n0\r\n\r\n"
    );
}

#[tokio::test]
async fn late_invalid_response_chunks_flush_decoded_payload_like_xray() {
    for body in [
        b"4\r\ntest\r\nZ\r\noops\r\n".as_slice(),
        b"5\r\ntest".as_slice(),
        b"4\r\ntestX\r\n0\r\n\r\n".as_slice(),
    ] {
        let mut upstream_response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        upstream_response.extend_from_slice(body);
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(&upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .expect_err("malformed later chunk framing must terminate relay");
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  4\r\ntest\r\n",
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn chunked_response_trailers_are_stripped_like_xray() {
    for trailer in [
        b"X-Trailer: yes\r\n".as_slice(),
        b"Bad Header: yes\r\n".as_slice(),
        b"X-Trailer: one\r\n two\r\n".as_slice(),
    ] {
        let mut upstream_response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"
                .to_vec();
        upstream_response.extend_from_slice(trailer);
        upstream_response.extend_from_slice(b"\r\n");
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(&upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  2\r\nok\r\n0\r\n\r\n",
            "{trailer:?}"
        );
    }
}

#[tokio::test]
async fn declared_chunked_response_trailer_is_forwarded_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Trailer: X-Foo\r\n\r\n\
                                  2\r\nok\r\n0\r\nX-Foo: bar\r\n\r\n";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(!reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Trailer: X-Foo\r\n\
              Connection: close\r\n\r\n\
              2\r\nok\r\n0\r\nX-Foo: bar\r\n\r\n"
    );
}

#[tokio::test]
async fn response_trailers_are_canonicalized_and_sorted_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Trailer: x-foo, X-Foo\r\n\
                                  Trailer: X-Bar\r\n\r\n\
                                  2\r\nok\r\n0\r\n\
                                  X-Foo: one\r\n\
                                  X-Bar: two\r\n\
                                  x-foo: three\r\n\r\n";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(!reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Trailer: X-Bar,X-Foo\r\n\
              Connection: close\r\n\r\n\
              2\r\nok\r\n0\r\n\
              X-Bar: two\r\n\
              X-Foo: one\r\n\
              X-Foo: three\r\n\r\n"
    );
}

#[tokio::test]
async fn forbidden_response_trailer_declarations_return_503_like_xray() {
    for trailer_name in ["Content-Length", "Transfer-Encoding", "Trailer"] {
        let upstream_response = format!(
            "HTTP/1.1 200 OK\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Trailer: {trailer_name}\r\n\r\n\
                 2\r\nok\r\n0\r\n\r\n"
        );
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client
            .write_all(upstream_response.as_bytes())
            .await
            .unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            "{trailer_name}"
        );
    }
}

#[tokio::test]
async fn malformed_chunked_response_trailer_stops_before_terminal_chunk_like_xray() {
    for trailer in [
        b"NoColon\r\n".as_slice(),
        b"X-Trailer: a\x01b\r\n".as_slice(),
    ] {
        let mut upstream_response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"
                .to_vec();
        upstream_response.extend_from_slice(trailer);
        upstream_response.extend_from_slice(b"\r\n");
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(&upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .expect_err("malformed response trailer must terminate relay");
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  2\r\nok\r\n",
            "{trailer:?}"
        );
    }
}

#[tokio::test]
async fn invalid_first_response_chunk_size_stops_after_headers_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\r\n\
                                  Z\r\nok\r\n0\r\n\r\n";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let error = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .expect_err("invalid first response chunk size must terminate relay");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn invalid_plain_http_response_transfer_encoding_returns_503_like_xray() {
    for transfer_encoding in [
        "Transfer-Encoding: gzip",
        "Transfer-Encoding: chunked, gzip",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
    ] {
        let upstream_response = format!(
            "HTTP/1.1 200 OK\r\n{transfer_encoding}\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        );
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client
            .write_all(upstream_response.as_bytes())
            .await
            .unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable, "{transfer_encoding:?} must close");
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            "{transfer_encoding:?}"
        );
    }
}

#[tokio::test]
async fn plain_http_response_unfolds_headers_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: one\r\n two\r\nConnection: close\r\n\r\nok";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             X-Test: one two\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
    );
}

#[tokio::test]
async fn plain_http_response_drops_invalid_header_names_like_xray() {
    let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nBad Header: hidden\r\nX-Keep: visible\r\n\r\nok";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             X-Keep: visible\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
    );
}

#[tokio::test]
async fn malformed_plain_http_response_headers_return_503_like_xray() {
    for invalid_header in ["NoColon", "X-Test: a\u{1}b", "X-Test: a\u{7f}b"] {
        let upstream_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{invalid_header}\r\n\r\nok"
        );
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client
            .write_all(upstream_response.as_bytes())
            .await
            .unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable, "invalid header {invalid_header:?} must close");
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
            "invalid header {invalid_header:?}"
        );
    }
}

#[tokio::test]
async fn plain_http_response_without_length_closes_connection() {
    let upstream_response = b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nhello";
    let (mut upstream_client, mut upstream_server) = duplex(2048);
    upstream_client.write_all(upstream_response).await.unwrap();
    upstream_client.shutdown().await.unwrap();
    let (mut downstream_client, mut downstream_server) = duplex(2048);

    let reusable = relay_plain_http_response(
        &mut upstream_server,
        &mut downstream_server,
        "GET",
    )
    .await
    .unwrap();
    assert!(!reusable);
    downstream_server.shutdown().await.unwrap();

    let mut response = Vec::new();
    downstream_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 200 OK\r\nX-Test: yes\r\nConnection: close\r\n\r\nhello"
    );
}

#[tokio::test]
async fn transparent_origin_form_uses_host_header() {
    let handler = HttpTcpServerHandler::new(Vec::new(), true, "http-transparent");
    let request = b"GET /health HTTP/1.1\r\nHost: example.com:8081\r\n\r\n";
    let (mut client, server) = duplex(2048);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("transparent HTTP request should succeed");
    let TcpServerSetupResult::TcpForward {
        remote_location,
        mut stream,
        ..
    } = result
    else {
        panic!("transparent HTTP returned non-TCP result");
    };
    assert_eq!(remote_location.to_string(), "example.com:8081");
    let mut forwarded = Vec::new();
    stream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(
        String::from_utf8(forwarded).unwrap(),
        "GET /health HTTP/1.1\r\n\
             Host: example.com:8081\r\n\
             Connection: close\r\n\r\n"
    );
}

#[tokio::test]
async fn origin_form_requires_allow_transparent() {
    let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-proxy");
    let (mut client, server) = duplex(1024);
    client
        .write_all(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("origin-form request must require transparent mode"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("allowTransparent"));
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 400 Bad Request\r\n\
              Connection: close\r\n\
              Proxy-Connection: close\r\n\
              Content-Length: 0\r\n\r\n"
    );
}

#[tokio::test]
async fn missing_auth_returns_407() {
    let handler = HttpTcpServerHandler::new(
        vec![HttpUser {
            username: "alice".into(),
            password: "secret".into(),
        }],
        false,
        "http-auth",
    );
    let (mut client, server) = duplex(2048);
    client
        .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("missing auth must fail"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
    );
}
