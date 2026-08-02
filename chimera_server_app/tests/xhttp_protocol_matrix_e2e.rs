mod xhttp_support;

use std::net::{Ipv4Addr, SocketAddr};

use serde_json::json;
use xhttp_support::{
    ChildGuard, TEST_UUID, create_test_dir, free_localhost_port, open_http_request,
    send_http_request, serial_xray_guard, start_chimera, wait_for_tcp,
    workspace_root, write_json,
};

const VALID_PADDING: &str = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#[derive(Clone, Copy)]
struct ServerOptions {
    mode: &'static str,
    host: Option<&'static str>,
    max_post_bytes: usize,
    padding_obfs: bool,
    padding_key: &'static str,
    padding_header: &'static str,
    padding_placement: &'static str,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            mode: "auto",
            host: None,
            max_post_bytes: 1024,
            padding_obfs: false,
            padding_key: "x_padding",
            padding_header: "X-Padding",
            padding_placement: "queryInHeader",
        }
    }
}

fn start_server(name: &str, options: ServerOptions) -> (ChildGuard, SocketAddr) {
    let workspace = workspace_root();
    let work_dir = create_test_dir(name);
    let port = free_localhost_port();
    let config_path = work_dir.join("chimera.json");
    write_json(
        &config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "tag": format!("xhttp-protocol-{name}"),
                "settings": {
                    "clients": [{"id": TEST_UUID, "email": format!("{name}@xhttp.test")}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "host": options.host,
                        "path": "/xhttp",
                        "mode": options.mode,
                        "noGRPCHeader": true,
                        "noSSEHeader": true,
                        "xPaddingBytes": {"from": 100, "to": 100},
                        "xPaddingObfsMode": options.padding_obfs,
                        "xPaddingKey": options.padding_key,
                        "xPaddingHeader": options.padding_header,
                        "xPaddingPlacement": options.padding_placement,
                        "xPaddingMethod": "repeat-x",
                        "scMaxEachPostBytes": {
                            "from": options.max_post_bytes,
                            "to": options.max_post_bytes
                        },
                        "scMaxBufferedPosts": 4,
                        "scStreamUpServerSecs": {"from": 1, "to": 1},
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Session",
                        "seqPlacement": "header",
                        "seqKey": "X-Seq",
                        "uplinkDataPlacement": "body"
                    }
                }
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
    let mut child = start_chimera(&workspace, &work_dir, &config_path);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    wait_for_tcp(addr);
    child.assert_running();
    (child, addr)
}

fn padded_path() -> String {
    format!("/xhttp?x_padding={VALID_PADDING}")
}

fn request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, String)],
    declared_length: usize,
    body: &[u8],
) -> Vec<u8> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {declared_length}\r\nConnection: keep-alive\r\n"
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
#[ignore = "starts Chimera and validates XHTTP OPTIONS/CORS semantics"]
fn options_reflects_cors_and_returns_padding() {
    let _serial = serial_xray_guard();
    let (_server, addr) = start_server("options-cors", ServerOptions::default());
    let headers = [
        ("Origin", "https://browser.example".to_string()),
        ("Access-Control-Request-Method", "PATCH".to_string()),
        ("Access-Control-Request-Headers", "X-Test".to_string()),
    ];
    let head = send_http_request(
        addr,
        &request("OPTIONS", &padded_path(), "localhost", &headers, 0, b""),
    );
    assert_eq!(head.status, 200);
    assert_eq!(
        head.headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://browser.example")
    );
    assert_eq!(
        head.headers
            .get("access-control-allow-methods")
            .map(String::as_str),
        Some("PATCH")
    );
    assert_eq!(
        head.headers
            .get("access-control-allow-headers")
            .map(String::as_str),
        Some("X-Test")
    );
    assert_eq!(head.headers.get("x-padding").map(String::len), Some(100));
}

#[test]
#[ignore = "starts Chimera and validates XHTTP host rejection"]
fn wrong_host_returns_404_before_padding_validation() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        host: Some("expected.example"),
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("wrong-host", options);
    let head = send_http_request(
        addr,
        &request("GET", "/xhttp", "wrong.example", &[], 0, b""),
    );
    assert_eq!(head.status, 404);
}

#[test]
#[ignore = "starts Chimera and validates XHTTP path rejection"]
fn wrong_path_returns_404_before_padding_validation() {
    let _serial = serial_xray_guard();
    let (_server, addr) = start_server("wrong-path", ServerOptions::default());
    let head =
        send_http_request(addr, &request("GET", "/other", "localhost", &[], 0, b""));
    assert_eq!(head.status, 404);
}

#[test]
#[ignore = "starts Chimera and validates required XHTTP padding"]
fn missing_or_short_padding_returns_400() {
    let _serial = serial_xray_guard();
    let (_server, addr) = start_server("invalid-padding", ServerOptions::default());
    let missing =
        send_http_request(addr, &request("GET", "/xhttp", "localhost", &[], 0, b""));
    let short = send_http_request(
        addr,
        &request("GET", "/xhttp?x_padding=X", "localhost", &[], 0, b""),
    );
    assert_eq!(missing.status, 400);
    assert_eq!(short.status, 400);
}

#[test]
#[ignore = "starts Chimera and validates packet-up sequence parsing"]
fn invalid_packet_sequence_returns_500() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        mode: "packet-up",
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("invalid-seq", options);
    let headers = [
        ("X-Session", "session-a".to_string()),
        ("X-Seq", "NaN".to_string()),
    ];
    let head = send_http_request(
        addr,
        &request("POST", &padded_path(), "localhost", &headers, 0, b""),
    );
    assert_eq!(head.status, 500);
}

#[test]
#[ignore = "starts Chimera and validates Content-Length limits"]
fn oversized_content_length_returns_413() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        mode: "packet-up",
        max_post_bytes: 8,
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("content-length-limit", options);
    let headers = [
        ("X-Session", "session-b".to_string()),
        ("X-Seq", "0".to_string()),
    ];
    let head = send_http_request(
        addr,
        &request("POST", &padded_path(), "localhost", &headers, 9, b""),
    );
    assert_eq!(head.status, 413);
}

#[test]
#[ignore = "starts Chimera and validates chunked-body limits"]
fn oversized_chunked_body_returns_413() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        mode: "packet-up",
        max_post_bytes: 8,
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("chunked-limit", options);
    let raw = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nX-Session: session-c\r\nX-Seq: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
        padded_path()
    );
    assert_eq!(send_http_request(addr, raw.as_bytes()).status, 413);
}

#[test]
#[ignore = "starts Chimera and validates mode-specific request rejection"]
fn stream_up_request_in_packet_mode_returns_400() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        mode: "packet-up",
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("packet-rejects-stream", options);
    let headers = [("X-Session", "session-d".to_string())];
    let head = send_http_request(
        addr,
        &request("POST", &padded_path(), "localhost", &headers, 0, b""),
    );
    assert_eq!(head.status, 400);
}

#[test]
#[ignore = "starts Chimera and validates duplicate stream-up rejection"]
fn duplicate_stream_up_returns_409() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        mode: "stream-up",
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("duplicate-stream-up", options);
    let headers = [("X-Session", "session-e".to_string())];
    let request = request("POST", &padded_path(), "localhost", &headers, 1024, b"");
    let (_first_stream, first) = open_http_request(addr, &request);
    let second = send_http_request(addr, &request);
    assert_eq!(first.status, 200);
    assert_eq!(second.status, 409);
}

#[test]
#[ignore = "starts Chimera and validates permanent per-session upload mode"]
fn packet_then_stream_up_returns_409() {
    let _serial = serial_xray_guard();
    let (_server, addr) = start_server("uplink-mode-lock", ServerOptions::default());
    let packet_headers = [
        ("X-Session", "session-f".to_string()),
        ("X-Seq", "0".to_string()),
    ];
    let packet = send_http_request(
        addr,
        &request("POST", &padded_path(), "localhost", &packet_headers, 0, b""),
    );
    let stream_headers = [("X-Session", "session-f".to_string())];
    let stream = send_http_request(
        addr,
        &request(
            "POST",
            &padded_path(),
            "localhost",
            &stream_headers,
            1024,
            b"",
        ),
    );
    assert_eq!(packet.status, 200);
    assert_eq!(stream.status, 409);
}

#[test]
#[ignore = "starts Chimera and validates custom header padding"]
fn custom_header_padding_roundtrips() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        padding_obfs: true,
        padding_key: "pad",
        padding_header: "X-Test-Pad",
        padding_placement: "header",
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("header-padding", options);
    let headers = [("X-Test-Pad", VALID_PADDING.to_string())];
    let head = send_http_request(
        addr,
        &request("OPTIONS", "/xhttp", "localhost", &headers, 0, b""),
    );
    assert_eq!(head.status, 200);
    assert_eq!(head.headers.get("x-test-pad").map(String::len), Some(100));
}

#[test]
#[ignore = "starts Chimera and validates cookie padding/CORS credentials"]
fn cookie_padding_roundtrips_with_credentials() {
    let _serial = serial_xray_guard();
    let options = ServerOptions {
        padding_obfs: true,
        padding_key: "pad",
        padding_placement: "cookie",
        ..ServerOptions::default()
    };
    let (_server, addr) = start_server("cookie-padding", options);
    let headers = [
        ("Cookie", format!("pad={VALID_PADDING}")),
        ("Origin", "https://browser.example".to_string()),
    ];
    let head = send_http_request(
        addr,
        &request("OPTIONS", "/xhttp", "localhost", &headers, 0, b""),
    );
    assert_eq!(head.status, 200);
    assert!(
        head.headers.get("set-cookie").is_some_and(|value| value
            .starts_with("pad=")
            && value.contains("Path=/"))
    );
    assert_eq!(
        head.headers
            .get("access-control-allow-credentials")
            .map(String::as_str),
        Some("true")
    );
}
