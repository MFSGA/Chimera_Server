use super::*;
use crate::beginning::transport_plan::{InboundListenerPlan, compile_listener_plan};
#[cfg(feature = "tls")]
use crate::config::server_config::TlsServerConfig;

#[derive(Debug)]
struct PendingXhttpHandler;

#[async_trait::async_trait]
impl TcpServerHandler for PendingXhttpHandler {
    async fn setup_server_stream(
        &self,
        _server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<crate::handler::tcp::tcp_handler::TcpServerSetupResult>
    {
        std::future::pending().await
    }
}

fn test_xhttp_server_config() -> XhttpServerConfig {
    XhttpServerConfig {
        mode: XhttpMode::Auto,
        host: None,
        path: "/xhttp".to_string(),
        trusted_x_forwarded_for: Vec::new(),
        min_padding: 100,
        max_padding: 1000,
        max_each_post_bytes: 1_000_000,
        max_buffered_posts: 30,
        session_ttl_secs: 300,
        stream_up_server_secs: (20, 80),
        server_max_header_bytes: 8192,
        padding_obfs_mode: false,
        padding_key: "x_padding".to_string(),
        padding_header: "X-Padding".to_string(),
        padding_placement: XhttpPaddingPlacement::QueryInHeader,
        padding_method: XhttpPaddingMethod::RepeatX,
        no_grpc_header: false,
        no_sse_header: false,
        uplink_http_method: "POST".to_string(),
        min_posts_interval_ms: (30, 30),
        session_placement: XhttpPlacement::Path,
        session_key: String::new(),
        seq_placement: XhttpPlacement::Path,
        seq_key: String::new(),
        uplink_data_placement: XhttpDataPlacement::Auto,
        uplink_data_key: "x_data".to_string(),
        xray_congestion: None,
        xray_brutal_up: None,
        xray_max_idle_timeout_secs: None,
        xray_max_incoming_streams: None,
        xray_init_stream_receive_window: None,
        xray_max_stream_receive_window: None,
        xray_init_connection_receive_window: None,
        xray_max_connection_receive_window: None,
        xray_disable_path_mtu_discovery: None,
    }
}

fn pending_xhttp_state(
    runtime: RuntimeState,
    shutdown: CancellationToken,
) -> Arc<AppState> {
    let handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(Box::new(PendingXhttpHandler));
    Arc::new(AppState::new(
        test_xhttp_server_config(),
        handler,
        Arc::new(NativeResolver::new()),
        runtime.data_plane(),
        None,
        shutdown,
    ))
}

async fn wait_for_tracked_xhttp_tasks(runtime: &RuntimeState, expected: usize) {
    for _ in 0..100 {
        if runtime.tracked_inbound_connection_count() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(runtime.tracked_inbound_connection_count(), expected);
}

#[tokio::test]
async fn stream_one_background_tasks_use_server_owner() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let shutdown = CancellationToken::new();
    let state = pending_xhttp_state(runtime.clone(), shutdown.clone());
    let body = StreamBody::new(futures::stream::pending::<
        Result<Frame<Bytes>, Infallible>,
    >());

    let response = handle_stream_one(
        body,
        state,
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
    )
    .await;

    wait_for_tracked_xhttp_tasks(&runtime, 2).await;
    shutdown.cancel();
    wait_for_tracked_xhttp_tasks(&runtime, 0).await;
    drop(response);
}

#[tokio::test]
async fn split_session_handler_and_ttl_use_server_owner() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let shutdown = CancellationToken::new();
    let state = pending_xhttp_state(runtime.clone(), shutdown.clone());

    let response = handle_stream_down(
        state,
        "session".to_string(),
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
    )
    .await;

    wait_for_tracked_xhttp_tasks(&runtime, 2).await;
    shutdown.cancel();
    wait_for_tracked_xhttp_tasks(&runtime, 0).await;
    drop(response);
}

#[tokio::test]
async fn session_without_task_registration_is_closed_immediately() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert!(runtime.close_inbound_connection_tasks());
    let store = SessionStore::new(
        Duration::from_secs(30),
        30,
        CancellationToken::new(),
        runtime.data_plane(),
    );

    let session = store.get_or_create("session");

    assert!(!store.inner.read().unwrap().contains_key("session"));
    assert!(session.closed.is_cancelled());
    assert!(session.upload_queue.closed.load(Ordering::Acquire));
}

#[tokio::test]
async fn tcp_listener_stop_preserves_accepted_connection_like_xray() {
    let probe = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve test port");
    let port = probe.local_addr().expect("test address").port();
    drop(probe);

    let config = ServerConfig {
        tag: "xhttp-lifecycle".to_string(),
        bind_location: BindLocation::Address(
            crate::address::NetLocation::from_ip_addr(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            ),
        ),
        protocol: ServerProxyConfig::Xhttp {
            config: test_xhttp_server_config(),
            inner: Box::new(ServerProxyConfig::Socks {
                accounts: crate::config::server_config::SocksUserStore::new(
                    Vec::new(),
                ),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            }),
        },
        transport: crate::config::Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
    let InboundListenerPlan::Xhttp(plan) = compile_listener_plan(&config.protocol)
    else {
        panic!("expected XHTTP listener plan");
    };
    let mut listener_tasks = start_xhttp_server(config, runtime, *plan)
        .await
        .expect("start XHTTP listener");
    let listener_task = listener_tasks.pop().expect("listener task");

    let stream =
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect XHTTP client");
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("HTTP/1 handshake");
    let client_task = tokio::spawn(connection);

    let request = || {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/xhttp/")
            .header(header::HOST, "localhost")
            .body(Empty::<Bytes>::new())
            .expect("OPTIONS request")
    };
    let first = sender
        .send_request(request())
        .await
        .expect("first request on accepted connection");
    assert_eq!(first.status(), StatusCode::OK);
    first
        .into_body()
        .collect()
        .await
        .expect("first response body");

    listener_task.abort();
    let _ = listener_task.await;
    assert!(
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_err(),
        "stopped XHTTP listener must reject new TCP connections"
    );

    let second = sender
        .send_request(request())
        .await
        .expect("accepted XHTTP connection should survive listener stop");
    assert_eq!(second.status(), StatusCode::OK);
    second
        .into_body()
        .collect()
        .await
        .expect("second response body");

    drop(sender);
    client_task.abort();
}

#[cfg(feature = "tls")]
#[test]
fn h3_transport_uses_xray_initial_mtu() {
    let mut transport = quinn::TransportConfig::default();
    apply_xray_xhttp_h3_initial_mtu(&mut transport);
    let debug = format!("{transport:?}");
    assert!(debug.contains("initial_mtu: 1280"), "{debug}");
}

#[cfg(feature = "tls")]
#[test]
fn h3_bbr_initial_window_matches_xray() {
    let mut bbr = quinn::congestion::BbrConfig::default();
    bbr.initial_window(XRAY_XHTTP_H3_BBR_INITIAL_WINDOW);
    let debug = format!("{bbr:?}");
    assert!(debug.contains("initial_window: 40960"), "{debug}");
}

#[cfg(feature = "tls")]
#[test]
fn h3_congestion_mode_matches_xray_explicit_reno_and_bbr() {
    assert_eq!(
        configured_xhttp_h3_congestion_mode(None),
        XhttpH3CongestionMode::Bbr
    );
    assert_eq!(
        configured_xhttp_h3_congestion_mode(Some("")),
        XhttpH3CongestionMode::Bbr
    );
    assert_eq!(
        configured_xhttp_h3_congestion_mode(Some("bbr")),
        XhttpH3CongestionMode::Bbr
    );
    assert_eq!(
        configured_xhttp_h3_congestion_mode(Some("reno")),
        XhttpH3CongestionMode::Reno
    );
    assert_eq!(
        configured_xhttp_h3_congestion_mode(Some("force-brutal")),
        XhttpH3CongestionMode::ForceBrutal
    );
}

#[cfg(feature = "tls")]
#[test]
fn h3_receive_window_uses_xray_initial_value_and_defaults() {
    assert_eq!(
        configured_xhttp_receive_window(
            None,
            XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW
        )
        .expect("unset receive window")
        .into_inner(),
        XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW
    );
    assert_eq!(
        configured_xhttp_receive_window(
            Some(0),
            XRAY_XHTTP_H3_INITIAL_CONNECTION_RECEIVE_WINDOW
        )
        .expect("zero receive window")
        .into_inner(),
        XRAY_XHTTP_H3_INITIAL_CONNECTION_RECEIVE_WINDOW
    );
    assert_eq!(
        configured_xhttp_receive_window(
            Some(65_536),
            XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW
        )
        .expect("explicit receive window")
        .into_inner(),
        65_536
    );
    assert!(
        configured_xhttp_receive_window(
            Some(1_u64 << 62),
            XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW
        )
        .is_err()
    );
}

#[test]
fn request_dispatch_accepts_transport_neutral_http_body() {
    fn assert_body<B>()
    where
        B: Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let _ = handle_request::<B>;
    }

    assert_body::<http_body_util::Full<Bytes>>();
    assert_body::<H3RequestBody>();
}

#[test]
fn h3_request_stream_split_preserves_response_half_type() {
    fn assert_splitter(
        _splitter: fn(H3BidiRequestStream) -> (H3SendRequestStream, H3RequestBody),
    ) {
    }

    assert_splitter(split_h3_request_stream);
}

#[test]
fn normalized_path_only_requires_trailing_slash_for_path_metadata() {
    assert_eq!(
        normalize_base_path(
            "stream".to_string(),
            XhttpPlacement::Path,
            XhttpPlacement::Path,
        ),
        "/stream/"
    );
    assert_eq!(
        normalize_base_path(
            "/stream".to_string(),
            XhttpPlacement::Query,
            XhttpPlacement::Query,
        ),
        "/stream"
    );
    assert_eq!(
        normalize_base_path(
            "/stream/filename.extension".to_string(),
            XhttpPlacement::Query,
            XhttpPlacement::Header,
        ),
        "/stream/filename.extension"
    );
    assert_eq!(
        normalize_base_path(
            "/stream?ignored=1".to_string(),
            XhttpPlacement::Query,
            XhttpPlacement::Cookie,
        ),
        "/stream"
    );
    assert_eq!(
        normalize_base_path(
            "?ignored=1".to_string(),
            XhttpPlacement::Query,
            XhttpPlacement::Header,
        ),
        "/"
    );
}

#[test]
fn packet_up_without_body_disables_caching_like_current_xray() {
    let response = packet_up_success_response(true);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );

    let response = packet_up_success_response(false);
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
}

#[test]
fn response_padding_placements_match_current_xray() {
    let mut headers = hyper::HeaderMap::new();
    apply_response_padding_value(
        &mut headers,
        true,
        XhttpPaddingPlacement::Cookie,
        "pad",
        "x-pad",
        XhttpPaddingMethod::RepeatX,
        4,
    );
    assert_eq!(
        headers.get(header::SET_COOKIE),
        Some(&HeaderValue::from_static("pad=XXXX; Path=/"))
    );

    apply_response_padding_value(
        &mut headers,
        true,
        XhttpPaddingPlacement::Header,
        "pad",
        "x-pad",
        XhttpPaddingMethod::RepeatX,
        4,
    );
    assert_eq!(headers.get("x-pad").unwrap(), "XXXX");
}

#[test]
fn http1_header_read_limit_includes_xray_bufio_slop() {
    assert_eq!(xray_http1_header_read_limit(8192), 12_288);
    assert_eq!(xray_http1_header_read_limit(16_384), 20_480);
    assert!(uses_http1_header_read_limit(hyper::Version::HTTP_10));
    assert!(uses_http1_header_read_limit(hyper::Version::HTTP_11));
    assert!(!uses_http1_header_read_limit(hyper::Version::HTTP_2));
    assert!(!uses_http1_header_read_limit(hyper::Version::HTTP_3));

    let request = Request::builder()
        .uri("/x/")
        .header("x-test", "a".repeat(12_000))
        .body(())
        .unwrap();
    assert!(request_head_bytes(&request) <= xray_http1_header_read_limit(8192));
    let request = Request::builder()
        .uri("/x/")
        .header("x-test", "a".repeat(13_000))
        .body(())
        .unwrap();
    assert!(request_head_bytes(&request) > xray_http1_header_read_limit(8192));

    let request = Request::builder()
        .uri(format!("/x/?q={}", "a".repeat(12_000)))
        .header("host", "localhost")
        .body(())
        .unwrap();
    assert!(request_head_bytes(&request) <= xray_http1_header_read_limit(8192));
    let request = Request::builder()
        .uri(format!("/x/?q={}", "a".repeat(13_000)))
        .header("host", "localhost")
        .body(())
        .unwrap();
    assert!(request_head_bytes(&request) > xray_http1_header_read_limit(8192));
}

#[test]
fn http2_settings_match_xray_v26_2_6() {
    assert_eq!(xray_http2_header_list_limit(8192), 8512);
    assert_eq!(xray_http2_header_list_limit(16_384), 16_704);
    assert_eq!(XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS, 250);
    assert_eq!(XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE, 1_048_576);
}

#[test]
fn http_host_validation_matches_xray_v26_2_6() {
    assert!(xray_valid_http_host("example.com", "example.com"));
    assert!(xray_valid_http_host("EXAMPLE.COM:443", "example.com"));
    assert!(xray_valid_http_host("[::1]:443", "::1"));
    assert!(!xray_valid_http_host("::1", "::1"));
    assert!(!xray_valid_http_host("[::1]", "::1"));
    assert!(!xray_valid_http_host("[::2]:443", "::1"));
}

#[test]
fn request_dispatch_matches_current_xray() {
    assert_eq!(
        classify_request(XhttpMode::Auto, false, false, false, false),
        Ok(XhttpRequestDispatch::StreamOne),
        "a non-uplink method without a session is still stream-one"
    );
    assert_eq!(
        classify_request(XhttpMode::Auto, true, false, false, false),
        Ok(XhttpRequestDispatch::StreamOne),
        "GET without a session is stream-one"
    );
    assert_eq!(
        classify_request(XhttpMode::StreamOne, true, true, true, true),
        Err(StatusCode::BAD_REQUEST),
        "GET with sequence metadata is packet-up shaped even in stream-one mode"
    );
    assert_eq!(
        classify_request(XhttpMode::Auto, true, false, true, false),
        Ok(XhttpRequestDispatch::StreamDown),
        "plain GET with a session remains stream-down"
    );
    assert_eq!(
        classify_request(XhttpMode::PacketUp, false, true, false, false),
        Err(StatusCode::BAD_REQUEST),
        "explicit packet-up requires a session id"
    );
    assert_eq!(
        classify_request(XhttpMode::PacketUp, false, true, true, false),
        Err(StatusCode::BAD_REQUEST),
        "stream-up shaped request is invalid in packet-up mode"
    );
    assert_eq!(
        classify_request(XhttpMode::StreamUp, false, true, true, true),
        Err(StatusCode::BAD_REQUEST),
        "packet-up shaped request is invalid in stream-up mode"
    );
    assert_eq!(
        classify_request(XhttpMode::Auto, false, false, true, false),
        Err(StatusCode::METHOD_NOT_ALLOWED),
        "non-uplink non-GET request with a session remains unsupported"
    );
}

#[test]
fn uplink_method_dispatch_matches_current_xray() {
    assert!(!is_xray_uplink_request(&Method::GET, false));
    assert!(is_xray_uplink_request(&Method::GET, true));
    assert!(is_xray_uplink_request(&Method::POST, false));
    assert!(is_xray_uplink_request(&Method::PUT, false));
    assert!(is_xray_uplink_request(&Method::PATCH, false));

    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "x-data-upstream",
        hyper::header::HeaderValue::from_static("1"),
    );
    assert!(has_uplink_marker(
        &headers,
        XhttpDataPlacement::Header,
        "X-Data"
    ));
    assert!(!has_uplink_marker(
        &headers,
        XhttpDataPlacement::Body,
        "X-Data"
    ));

    headers.insert(
        "x-data-upstream",
        hyper::header::HeaderValue::from_static("2"),
    );
    assert!(!has_uplink_marker(
        &headers,
        XhttpDataPlacement::Header,
        "X-Data"
    ));

    let mut cookie_headers = hyper::HeaderMap::new();
    cookie_headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static("other=0; x_data_upstream=1"),
    );
    assert!(has_uplink_marker(
        &cookie_headers,
        XhttpDataPlacement::Cookie,
        "x_data"
    ));

    cookie_headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static("x_data_upstream=0"),
    );
    assert!(!has_uplink_marker(
        &cookie_headers,
        XhttpDataPlacement::Cookie,
        "x_data"
    ));
}

#[test]
fn cookie_uplink_payload_matches_current_xray_chunks() {
    let headers = hyper::HeaderMap::new();
    assert_eq!(
        decode_chunked_cookie_payload(&headers, "x_data")
            .expect("empty cookie payload is valid"),
        b""
    );

    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static("x_data_0=!!!"),
    );
    assert!(decode_chunked_cookie_payload(&headers, "x_data").is_err());

    headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static("x_data_0=cGlu; x_data_1=Zw"),
    );
    assert_eq!(
        decode_chunked_cookie_payload(&headers, "x_data")
            .expect("valid cookie payload"),
        b"ping"
    );
}

#[test]
fn header_uplink_payload_matches_current_xray_chunks_without_length_marker() {
    let headers = hyper::HeaderMap::new();
    assert_eq!(
        decode_chunked_header_payload(&headers, "X-Data")
            .expect("empty header payload is valid"),
        b""
    );

    let mut headers = hyper::HeaderMap::new();
    headers.insert("x-data-0", hyper::header::HeaderValue::from_static("cGlu"));
    headers.insert("x-data-1", hyper::header::HeaderValue::from_static("Zw"));
    assert_eq!(
        decode_chunked_header_payload(&headers, "X-Data")
            .expect("current Xray does not send a data length marker"),
        b"ping"
    );

    headers.insert("x-data-0", hyper::header::HeaderValue::from_static("!!!"));
    assert!(decode_chunked_header_payload(&headers, "X-Data").is_err());
}

#[test]
fn xhttp_cors_headers_match_current_xray_browser_preflight() {
    let mut request_headers = hyper::HeaderMap::new();
    request_headers.insert(
        header::ORIGIN,
        hyper::header::HeaderValue::from_static("https://example.com"),
    );
    request_headers.insert(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        hyper::header::HeaderValue::from_static("POST"),
    );
    request_headers.insert(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        hyper::header::HeaderValue::from_static("content-type, x-session"),
    );

    let mut headers = hyper::HeaderMap::new();
    apply_xray_cors_headers(&mut headers, &Method::OPTIONS, &request_headers, true);

    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&hyper::header::HeaderValue::from_static(
            "https://example.com"
        ))
    );
    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_METHODS),
        Some(&hyper::header::HeaderValue::from_static("POST"))
    );
    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS),
        Some(&hyper::header::HeaderValue::from_static(
            "content-type, x-session"
        ))
    );
    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        Some(&hyper::header::HeaderValue::from_static("true"))
    );
}

#[test]
fn xhttp_cors_non_preflight_keeps_current_xray_minimal_headers() {
    let request_headers = hyper::HeaderMap::new();
    let mut headers = hyper::HeaderMap::new();
    apply_xray_cors_headers(&mut headers, &Method::GET, &request_headers, false);

    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&hyper::header::HeaderValue::from_static("*"))
    );
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_none());
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_none());
    assert!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );
}

#[test]
fn xhttp_trusted_forwarded_peer_requires_xray_trusted_marker() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        hyper::header::HeaderValue::from_static("203.0.113.77, 198.51.100.2"),
    );

    assert_eq!(trusted_forwarded_peer(&headers, &[]), None);
    assert_eq!(
        trusted_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
        None
    );

    headers.insert(
        "x-trusted-cdn",
        hyper::header::HeaderValue::from_static("yes"),
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
        Some("203.0.113.77:0".parse().expect("trusted forwarded peer"))
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &[" X-Trusted-CDN ".to_string()]),
        None,
        "Xray v26.2.6 matches trusted marker names exactly and does not trim config text"
    );
}

#[tokio::test]
async fn xhttp_times_out_incomplete_headers_like_xray_v26_2_6() {
    let (mut client, server) = tokio::io::duplex(4096);
    let io = TokioIo::new(server);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http_builder(&mut builder, 8192);
    let service = service_fn(|_request| async {
        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
    });
    let mut server_task =
        tokio::spawn(async move { builder.serve_connection(io, service).await });

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example\r\n")
        .await
        .expect("write incomplete XHTTP request");
    assert!(
        tokio::time::timeout(Duration::from_millis(3500), &mut server_task)
            .await
            .is_err(),
        "XHTTP header timeout must not fire before Xray's four-second window"
    );

    let result = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("XHTTP header timeout should fire near four seconds")
        .expect("server task should not panic");
    let error = result.expect_err("incomplete XHTTP headers must time out");
    assert!(
        error
            .to_string()
            .contains("read header from client timeout"),
        "expected Hyper header timeout, got {error}"
    );
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_xhttp_times_out_handshake_like_xray_v26_2_6() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate test certificate");
    let tls_config = build_server_config(
        &[crate::config::server_config::TlsCertificateConfig {
            certificate_path: None,
            certificate_pem: generated.cert.pem().into_bytes(),
            key_path: None,
            key_pem: Some(generated.signing_key.serialize_pem().into_bytes()),
            usage: crate::config::server_config::TlsCertificateUsage::Encipherment,
        }],
        &["h2".to_string()],
        true,
        false,
        None,
        None,
    )
    .expect("build TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("test listener address");
    let client = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect test client");
    let (server, _) = listener.accept().await.expect("accept test client");
    let mut server_task = tokio::spawn(async move {
        accept_xhttp_tls(acceptor, Box::new(server) as Box<dyn AsyncStream>).await
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(3500), &mut server_task)
            .await
            .is_err(),
        "XHTTP TLS timeout must not fire before Xray's four-second window"
    );

    let result = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("XHTTP TLS timeout should fire near four seconds")
        .expect("server task should not panic");
    let error = match result {
        Ok(_) => panic!("idle TLS handshake must time out"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(client);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_xhttp_honors_xray_tls_version_settings() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate test certificate");
    let xhttp_config = XhttpServerConfig {
        mode: XhttpMode::Auto,
        host: None,
        path: "/xhttp".to_string(),
        trusted_x_forwarded_for: Vec::new(),
        min_padding: 100,
        max_padding: 1000,
        max_each_post_bytes: 1_000_000,
        max_buffered_posts: 30,
        session_ttl_secs: 300,
        stream_up_server_secs: (20, 80),
        server_max_header_bytes: 8192,
        padding_obfs_mode: false,
        padding_key: "x_padding".to_string(),
        padding_header: "X-Padding".to_string(),
        padding_placement: XhttpPaddingPlacement::QueryInHeader,
        padding_method: XhttpPaddingMethod::RepeatX,
        no_grpc_header: false,
        no_sse_header: false,
        uplink_http_method: "POST".to_string(),
        min_posts_interval_ms: (30, 30),
        session_placement: XhttpPlacement::Path,
        session_key: String::new(),
        seq_placement: XhttpPlacement::Path,
        seq_key: String::new(),
        uplink_data_placement: XhttpDataPlacement::Auto,
        uplink_data_key: "x_data".to_string(),
        xray_congestion: None,
        xray_brutal_up: None,
        xray_max_idle_timeout_secs: None,
        xray_max_incoming_streams: None,
        xray_init_stream_receive_window: None,
        xray_max_stream_receive_window: None,
        xray_init_connection_receive_window: None,
        xray_max_connection_receive_window: None,
        xray_disable_path_mtu_discovery: None,
    };
    let protocol = ServerProxyConfig::Tls(TlsServerConfig {
        certificates: vec![crate::config::server_config::TlsCertificateConfig {
            certificate_path: None,
            certificate_pem: generated.cert.pem().into_bytes(),
            key_path: None,
            key_pem: Some(generated.signing_key.serialize_pem().into_bytes()),
            usage: crate::config::server_config::TlsCertificateUsage::Encipherment,
        }],
        alpn_protocols: vec![],
        enable_session_resumption: true,
        reject_unknown_sni: false,
        min_version: Some("1.3".to_string()),
        max_version: None,
        server_name: None,
        inner: Box::new(ServerProxyConfig::Xhttp {
            config: xhttp_config,
            inner: Box::new(ServerProxyConfig::Socks {
                accounts: crate::config::server_config::SocksUserStore::new(vec![]),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            }),
        }),
    });

    let parsed = {
        let InboundListenerPlan::Xhttp(plan) = compile_listener_plan(&protocol)
        else {
            panic!("expected XHTTP listener plan");
        };
        prepare_xhttp_listener(*plan).expect("valid TLS XHTTP")
    };
    let XhttpSecurityLayer::Tls(acceptor) = parsed.security else {
        panic!("expected TLS XHTTP security");
    };

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            generated.cert.der().to_vec(),
        ))
        .expect("trust test certificate");
    let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
    ])
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move { acceptor.accept(server_io).await });
    let client = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .expect("valid server name"),
            client_io,
        )
        .await;

    assert!(
        client.is_err(),
        "TLS 1.2 must be rejected by minVersion=1.3"
    );
    assert!(
        server.await.expect("server task").is_err(),
        "server must reject a TLS 1.2 client"
    );
}

#[test]
fn tokenish_padding_tracks_hpack_target() {
    for target in [1usize, 100, 1000] {
        let padding = generate_tokenish_padding(target);
        let encoded_len = hpack_huffman_encoded_len(&padding);
        assert!(encoded_len.abs_diff(target) <= 2);
    }
}

#[test]
fn random_range_matches_xray_half_open_bounds() {
    assert_eq!(random_xray_range(7, 7), 7);
    for _ in 0..64 {
        assert_eq!(random_xray_range(7, 8), 7);
        assert_eq!(random_xray_range(8, 7), 7);
        let sampled = random_xray_range(7, 10);
        assert!((7..10).contains(&sampled));
    }
}

#[test]
fn padding_validation_matches_repeat_and_tokenish_rules() {
    assert!(is_padding_valid(
        &"X".repeat(100),
        100,
        1000,
        XhttpPaddingMethod::RepeatX,
    ));
    assert!(!is_padding_valid(
        &"X".repeat(99),
        100,
        1000,
        XhttpPaddingMethod::RepeatX,
    ));

    let tokenish = generate_tokenish_padding(100);
    assert!(is_padding_valid(
        &tokenish,
        100,
        100,
        XhttpPaddingMethod::Tokenish,
    ));
}

#[test]
fn cookie_value_matches_xray_quoted_cookie_parsing() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static(
            "x_session=\"abc\"; x_seq=\"0\"; invalid=\"a\\\\b\"",
        ),
    );

    assert_eq!(cookie_value(&headers, "x_session").as_deref(), Some("abc"));
    assert_eq!(cookie_value(&headers, "x_seq").as_deref(), Some("0"));
    assert_eq!(cookie_value(&headers, "invalid"), None);

    headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static(
            "x_session=; x_session=abc; x_seq=; x_seq=0",
        ),
    );
    assert_eq!(cookie_value(&headers, "x_session"), None);
    assert_eq!(cookie_value(&headers, "x_seq"), None);

    headers.insert(
        header::COOKIE,
        hyper::header::HeaderValue::from_static(
            "x_session=abc; x_session=; x_seq=0; x_seq=",
        ),
    );
    assert_eq!(cookie_value(&headers, "x_session").as_deref(), Some("abc"));
    assert_eq!(cookie_value(&headers, "x_seq").as_deref(), Some("0"));
}

#[test]
fn url_path_decoding_matches_xray_v26_2_6() {
    assert_eq!(decode_xray_url_path("/x/abc/0").as_deref(), Ok("/x/abc/0"));
    assert_eq!(
        decode_xray_url_path("/x/abc%2Fdef/0").as_deref(),
        Ok("/x/abc/def/0"),
    );
    assert_eq!(
        decode_xray_url_path("/x%2Fabc/0").as_deref(),
        Ok("/x/abc/0"),
    );
    assert_eq!(
        decode_xray_url_path("/x/abc%252Fdef/0").as_deref(),
        Ok("/x/abc%2Fdef/0"),
    );
    assert!(decode_xray_url_path("/x/abc%ZZ/0").is_err());
}

#[test]
fn path_metadata_preserves_empty_segments_like_xray_v26_2_6() {
    assert_eq!(xray_path_metadata_value("abc/0", 0).as_deref(), Some("abc"));
    assert_eq!(xray_path_metadata_value("abc/0", 1).as_deref(), Some("0"));
    assert_eq!(
        xray_path_metadata_value("abc//0", 0).as_deref(),
        Some("abc")
    );
    assert_eq!(xray_path_metadata_value("abc//0", 1), None);
    assert_eq!(xray_path_metadata_value("abc//0", 2).as_deref(), Some("0"));
    assert_eq!(xray_path_metadata_value("/0", 0), None);
    assert_eq!(xray_path_metadata_value("/0", 1).as_deref(), Some("0"));
}

#[test]
fn path_metadata_advances_only_for_path_placements_like_current_xray() {
    let mut path_part = 0;
    assert_eq!(
        xray_path_metadata_value_for_placement(
            "session/0",
            &mut path_part,
            XhttpPlacement::Path,
        )
        .as_deref(),
        Some("session")
    );
    assert_eq!(path_part, 1);
    assert_eq!(
        xray_path_metadata_value_for_placement(
            "session/0",
            &mut path_part,
            XhttpPlacement::Query,
        ),
        None
    );
    assert_eq!(path_part, 1);
    assert_eq!(
        xray_path_metadata_value_for_placement(
            "session/0",
            &mut path_part,
            XhttpPlacement::Path,
        )
        .as_deref(),
        Some("0")
    );

    let mut path_part = 0;
    assert_eq!(
        xray_path_metadata_value_for_placement(
            "0",
            &mut path_part,
            XhttpPlacement::Query
        ),
        None
    );
    assert_eq!(
        xray_path_metadata_value_for_placement(
            "0",
            &mut path_part,
            XhttpPlacement::Path
        )
        .as_deref(),
        Some("0")
    );
}

#[test]
fn query_value_matches_xray_url_query_decoding() {
    assert_eq!(
        query_value(Some("x_session=abc%2Fdef"), "x_session").as_deref(),
        Some("abc/def"),
    );
    assert_eq!(
        query_value(Some("x%5Fsession=hello+world"), "x_session").as_deref(),
        Some("hello world"),
    );
    assert_eq!(query_value(Some("x_session=bad%ZZ"), "x_session"), None);
    assert_eq!(
        query_value(Some("x_session=bad%ZZ&x_session=ok"), "x_session").as_deref(),
        Some("ok"),
    );
    assert_eq!(
        query_value(Some("other=bad%ZZ&x_session=ok"), "x_session").as_deref(),
        Some("ok"),
    );
    assert_eq!(
        query_value(Some("x_session=&x_session=ok"), "x_session"),
        None,
    );
    assert_eq!(
        query_value(Some("x_session=first&x_session="), "x_session").as_deref(),
        Some("first"),
    );
    assert_eq!(
        query_value(Some("x_session=bad;raw&x_session=ok"), "x_session").as_deref(),
        Some("ok"),
    );
    assert_eq!(
        query_value(Some("x_session=abc%3Bdef"), "x_session").as_deref(),
        Some("abc;def"),
    );
}

#[test]
fn query_value_from_header_url_extracts_padding() {
    assert_eq!(
        query_value_from_url("https://example.com/path?pad=XXXX#fragment", "pad")
            .as_deref(),
        Some("XXXX"),
    );
}

#[test]
fn malformed_padding_urls_fall_back_like_xray_v26_2_6() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("referer", hyper::header::HeaderValue::from_static("%"));

    assert_eq!(
        extract_xray_request_padding(
            false,
            "x_padding",
            "X-Padding",
            XhttpPaddingPlacement::Header,
            Some("x_padding=XXXX"),
            &headers,
        )
        .as_deref(),
        Some("XXXX"),
    );

    headers.insert(
        "referer",
        hyper::header::HeaderValue::from_static("https://example.com/"),
    );
    assert_eq!(
        extract_xray_request_padding(
            false,
            "x_padding",
            "X-Padding",
            XhttpPaddingPlacement::Header,
            Some("x_padding=XXXX"),
            &headers,
        ),
        None,
        "a successfully parsed Referer must suppress query fallback even without x_padding",
    );

    headers.remove("referer");
    headers.insert(
        "x-padding",
        hyper::header::HeaderValue::from_static("%ZZ?x_padding=BAD"),
    );
    assert_eq!(
        extract_xray_request_padding(
            true,
            "x_padding",
            "X-Padding",
            XhttpPaddingPlacement::QueryInHeader,
            Some("x_padding=X"),
            &headers,
        )
        .as_deref(),
        Some("X"),
        "a malformed query-in-header URL must be ignored before falling back to request query",
    );
}

#[test]
fn negative_post_limit_rejects_every_payload_like_xray_v26_2_6() {
    assert!(payload_exceeds_post_limit(0, -1));
    assert!(payload_exceeds_post_limit(1, -1));
    assert!(!payload_exceeds_post_limit(0, 0));
}

#[test]
fn declared_content_length_only_limits_body_placements_like_current_xray() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_static("8"),
    );

    for placement in [XhttpDataPlacement::Auto, XhttpDataPlacement::Body] {
        assert!(declared_body_length_exceeds_post_limit(
            placement, &headers, 7
        ));
        assert!(!declared_body_length_exceeds_post_limit(
            placement, &headers, 8
        ));
    }
    for placement in [XhttpDataPlacement::Header, XhttpDataPlacement::Cookie] {
        assert!(!declared_body_length_exceeds_post_limit(
            placement, &headers, 7
        ));
    }

    headers.remove(header::CONTENT_LENGTH);
    assert!(!declared_body_length_exceeds_post_limit(
        XhttpDataPlacement::Body,
        &headers,
        7,
    ));
}

#[test]
fn upload_reassembly_plan_preserves_xray_priority_order() {
    let snapshot =
        |has_current_payload, has_next_buffered_payload, buffered_packets| {
            UploadReassemblySnapshot {
                has_current_payload,
                has_next_buffered_payload,
                buffered_packets,
                max_buffered_posts: 2,
            }
        };

    assert_eq!(
        plan_upload_reassembly(snapshot(true, true, 4)),
        UploadReassemblyPlan::ConsumeCurrent,
    );
    assert_eq!(
        plan_upload_reassembly(snapshot(false, true, 4)),
        UploadReassemblyPlan::PromoteBuffered,
    );
    assert_eq!(
        plan_upload_reassembly(snapshot(false, false, 4)),
        UploadReassemblyPlan::RejectTooLarge,
    );
    assert_eq!(
        plan_upload_reassembly(snapshot(false, false, 3)),
        UploadReassemblyPlan::PollReceiver,
    );
}

#[test]
fn upload_payload_plan_only_drops_stale_sequences() {
    assert_eq!(plan_upload_payload(7, 6), UploadPayloadPlan::DropStale);
    assert_eq!(plan_upload_payload(7, 7), UploadPayloadPlan::Buffer);
    assert_eq!(plan_upload_payload(7, 8), UploadPayloadPlan::Buffer);
}

#[tokio::test]
async fn collect_body_limited_rejects_oversized_streaming_payload() {
    let frames = futures::stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"1234"))),
        Ok(Frame::data(Bytes::from_static(b"5678"))),
    ]);
    let body = StreamBody::new(frames);

    let result = collect_body_limited(body, 7).await;

    assert_eq!(result, Err(StatusCode::PAYLOAD_TOO_LARGE));
}

#[test]
fn stream_up_padding_accepts_current_xray_obfs_marker() {
    let mut headers = hyper::HeaderMap::new();
    assert!(!stream_up_padding_enabled(&headers, false));
    assert!(stream_up_padding_enabled(&headers, true));

    headers.insert(
        "referer",
        hyper::header::HeaderValue::from_static("https://example.com/"),
    );
    assert!(stream_up_padding_enabled(&headers, false));
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn h3_connection_task_uses_server_owner_and_listener_shutdown() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let shutdown = CancellationToken::new();

    spawn_xhttp_h3_connection(
        &runtime.data_plane(),
        shutdown.clone(),
        std::future::pending(),
    );
    for _ in 0..50 {
        if runtime.tracked_inbound_connection_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(runtime.tracked_inbound_connection_count(), 1);

    shutdown.cancel();
    for _ in 0..50 {
        if runtime.tracked_inbound_connection_count() == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("XHTTP H3 connection should leave owner when listener closes");
}

#[cfg(feature = "tls")]
#[test]
fn h3_local_addr_prefers_connection_destination_like_current_xray() {
    let listener_addr = "0.0.0.0:8443".parse().unwrap();
    let destination_ip = "192.0.2.10".parse().unwrap();
    assert_eq!(
        xhttp_h3_connection_local_addr(listener_addr, Some(destination_ip)),
        "192.0.2.10:8443".parse().unwrap()
    );
    assert_eq!(
        xhttp_h3_connection_local_addr(listener_addr, None),
        listener_addr
    );
}

#[test]
fn stream_up_padding_flush_scope_matches_xray_v26_2_6() {
    assert!(!stream_up_can_flush_while_uploading(
        hyper::Version::HTTP_10
    ));
    assert!(!stream_up_can_flush_while_uploading(
        hyper::Version::HTTP_11
    ));
    assert!(stream_up_can_flush_while_uploading(hyper::Version::HTTP_2));
    assert!(stream_up_can_flush_while_uploading(hyper::Version::HTTP_3));
}

#[tokio::test]
async fn stream_up_response_waits_for_session_close_without_padding_like_current_xray()
 {
    let session_closed = CancellationToken::new();
    let mut wait = Box::pin(wait_for_stream_up_response_start(
        session_closed.clone(),
        false,
        100,
        100,
    ));

    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut wait)
            .await
            .is_err(),
        "stream-up response must stay pending while the logical session is open"
    );

    session_closed.cancel();
    assert!(
        wait.await.is_none(),
        "stream-up without padding should finish when the logical session closes"
    );
}

#[tokio::test]
async fn stream_up_padding_starts_immediately_like_current_xray() {
    let session_closed = CancellationToken::new();
    let started = tokio::time::timeout(
        Duration::from_millis(20),
        wait_for_stream_up_response_start(session_closed, true, 7, 7),
    )
    .await
    .expect("current Xray writes the first stream-up padding chunk immediately")
    .expect("padding should start the response while upload remains open");

    assert_eq!(started.1, Bytes::from_static(b"XXXXXXX"));
}

#[tokio::test]
async fn split_session_creates_each_logical_connection_on_downlink() {
    use tokio::io::AsyncReadExt;

    let session = XhttpSession::new(4);
    session
        .upload_queue
        .push_payload(0, Bytes::from_static(b"ping"))
        .await
        .expect("queue first packet-up payload");

    let (mut first_stream, _first_downlink) = session.new_downlink_connection();
    let (mut second_stream, _second_downlink) = session.new_downlink_connection();

    let mut first_payload = [0u8; 4];
    first_stream.read_exact(&mut first_payload).await.unwrap();
    assert_eq!(&first_payload, b"ping");

    session
        .upload_queue
        .push_payload(1, Bytes::from_static(b"pong"))
        .await
        .expect("queue second packet-up payload");
    let mut second_payload = [0u8; 4];
    second_stream.read_exact(&mut second_payload).await.unwrap();
    assert_eq!(&second_payload, b"pong");
}

#[tokio::test]
async fn empty_packet_advances_sequence_without_signaling_eof_like_current_xray() {
    use tokio::io::AsyncReadExt;

    let (queue, mut reader) = XhttpUploadReader::new(4);
    queue.push_payload(0, Bytes::new()).await.unwrap();
    queue
        .push_payload(1, Bytes::from_static(b"next"))
        .await
        .unwrap();

    let mut output = [0u8; 4];
    reader.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"next");
}

#[tokio::test]
async fn duplicate_packet_sequence_keeps_first_payload_like_xray_v26_2_6() {
    use tokio::io::AsyncReadExt;

    let (queue, mut reader) = XhttpUploadReader::new(4);
    queue
        .push_payload(1, Bytes::from_static(b"first"))
        .await
        .unwrap();
    queue
        .push_payload(1, Bytes::from_static(b"second"))
        .await
        .unwrap();
    queue
        .push_payload(0, Bytes::from_static(b"zero"))
        .await
        .unwrap();

    let mut output = [0u8; 9];
    reader.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"zerofirst");
}

#[tokio::test]
async fn duplicate_future_packets_count_toward_current_xray_reassembly_limit() {
    use tokio::io::AsyncReadExt;

    let (queue, mut reader) = XhttpUploadReader::new(2);
    let queue = Arc::new(queue);

    let pushes = (0..4)
        .map(|_| {
            let queue = queue.clone();
            tokio::spawn(async move {
                queue
                    .push_payload(1, Bytes::from_static(b"duplicate"))
                    .await
            })
        })
        .collect::<Vec<_>>();

    let mut byte = [0u8; 1];
    let error = tokio::time::timeout(
        Duration::from_millis(200),
        reader.read_exact(&mut byte),
    )
    .await
    .expect("duplicate future packets should trip the reassembly limit")
    .expect_err("current Xray rejects an oversized reassembly heap");
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(error.to_string(), "packet queue is too large");

    for push in pushes {
        push.await
            .expect("packet push task")
            .expect("queue remains open until reader is dropped");
    }
}

#[tokio::test]
async fn stream_up_claim_is_single_use_like_xray_v26_2_6() {
    let (queue, _reader) = XhttpUploadReader::new(4);

    queue
        .push_reader(Box::pin(tokio::io::empty()))
        .await
        .expect("first stream-up reader");
    assert!(
        queue
            .push_reader(Box::pin(tokio::io::empty()))
            .await
            .is_err(),
        "a second stream-up reader must conflict"
    );
    assert!(
        queue
            .push_payload(0, Bytes::from_static(b"packet"))
            .await
            .is_err(),
        "packet-up must fail after stream-up claims the upload queue"
    );
}

#[tokio::test]
async fn stream_up_claim_remains_visible_while_queue_is_backpressured_like_current_xray()
 {
    let (queue, _reader) = XhttpUploadReader::new(1);
    let queue = Arc::new(queue);
    queue
        .push_payload(0, Bytes::from_static(b"0"))
        .await
        .expect("first packet fills upload channel");

    let blocked_packet = tokio::spawn({
        let queue = queue.clone();
        async move { queue.push_payload(1, Bytes::from_static(b"1")).await }
    });
    sleep(Duration::from_millis(20)).await;
    assert!(!blocked_packet.is_finished());

    let blocked_stream = tokio::spawn({
        let queue = queue.clone();
        async move { queue.push_reader(Box::pin(tokio::io::empty())).await }
    });
    for _ in 0..20 {
        if queue.reader_claimed.load(Ordering::Acquire) {
            break;
        }
        sleep(Duration::from_millis(5)).await;
    }
    assert!(
        queue.reader_claimed.load(Ordering::Acquire),
        "current Xray claims stream-up before waiting for channel capacity"
    );

    let later_packet = tokio::time::timeout(
        Duration::from_millis(100),
        queue.push_payload(2, Bytes::from_static(b"2")),
    )
    .await
    .expect("packet after stream-up claim must not block behind the full channel");
    assert!(
        later_packet.is_err(),
        "packet-up must fail once stream-up has claimed the session"
    );

    blocked_packet.abort();
    blocked_stream.abort();
}

#[tokio::test]
async fn stream_up_reader_preempts_buffered_packets_like_current_xray() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (queue, mut reader) = XhttpUploadReader::new(1);
    let queue = Arc::new(queue);
    queue
        .push_payload(0, Bytes::from_static(b"packet"))
        .await
        .expect("packet fills upload channel");

    let (mut stream_writer, stream_reader) = tokio::io::duplex(32);
    stream_writer
        .write_all(b"stream")
        .await
        .expect("seed stream-up body");

    let blocked_stream = tokio::spawn({
        let queue = queue.clone();
        async move { queue.push_reader(Box::pin(stream_reader)).await }
    });
    for _ in 0..20 {
        if queue.reader_claimed.load(Ordering::Acquire) {
            break;
        }
        sleep(Duration::from_millis(5)).await;
    }
    assert!(queue.reader_claimed.load(Ordering::Acquire));
    assert!(
        !blocked_stream.is_finished(),
        "stream-up response should still wait for channel capacity"
    );

    let mut output = [0u8; 6];
    tokio::time::timeout(Duration::from_millis(100), reader.read_exact(&mut output))
        .await
        .expect("claimed stream reader must bypass buffered packet queue")
        .expect("read stream-up body");
    assert_eq!(&output, b"stream");

    blocked_stream.abort();
}

#[tokio::test]
async fn buffered_packet_posts_backpressure_until_reader_consumes_like_xray_v26_2_6()
{
    use tokio::io::AsyncReadExt;

    let (queue, mut reader) = XhttpUploadReader::new(1);
    let queue = Arc::new(queue);
    queue
        .push_payload(1, Bytes::from_static(b"1"))
        .await
        .expect("first buffered post fills Xray channel");

    let second = tokio::spawn({
        let queue = queue.clone();
        async move { queue.push_payload(2, Bytes::from_static(b"2")).await }
    });
    sleep(Duration::from_millis(20)).await;
    assert!(
        !second.is_finished(),
        "a full scMaxBufferedPosts channel must backpressure the HTTP request"
    );

    let read = tokio::spawn(async move {
        let mut output = [0u8; 3];
        reader.read_exact(&mut output).await.unwrap();
        output
    });
    second
        .await
        .expect("second packet task")
        .expect("reader consumption should release one channel slot");
    queue
        .push_payload(0, Bytes::from_static(b"0"))
        .await
        .expect("missing packet completes reorder sequence");

    assert_eq!(read.await.expect("ordered read task"), *b"012");
}

#[test]
fn session_ttl_plan_only_reaps_current_unconnected_generation() {
    assert_eq!(
        plan_session_ttl(SessionTtlSnapshot {
            is_current: true,
            fully_connected: false,
        }),
        SessionTtlPlan::RemoveAndClose
    );
    assert_eq!(
        plan_session_ttl(SessionTtlSnapshot {
            is_current: true,
            fully_connected: true,
        }),
        SessionTtlPlan::Keep
    );
    assert_eq!(
        plan_session_ttl(SessionTtlSnapshot {
            is_current: false,
            fully_connected: false,
        }),
        SessionTtlPlan::Keep
    );
}

#[tokio::test]
async fn expired_session_closes_upload_queue_like_current_xray() {
    let store = SessionStore::new(
        Duration::from_millis(20),
        1,
        CancellationToken::new(),
        RuntimeState::new(Vec::new(), Vec::new()).data_plane(),
    );
    let session = store.get_or_create("session");
    session
        .upload_queue
        .push_payload(1, Bytes::from_static(b"first"))
        .await
        .expect("first packet fills upload channel");

    let blocked_session = session.clone();
    let blocked_push = tokio::spawn(async move {
        blocked_session
            .upload_queue
            .push_payload(2, Bytes::from_static(b"second"))
            .await
    });
    sleep(Duration::from_millis(5)).await;
    assert!(!blocked_push.is_finished(), "second push should be blocked");

    let result = tokio::time::timeout(Duration::from_millis(100), blocked_push)
        .await
        .expect("expired session should wake blocked upload")
        .expect("blocked upload task should finish");
    assert_eq!(
        result
            .expect_err("expired upload queue should reject pending push")
            .to_string(),
        "packet queue closed"
    );
    assert!(!store.inner.read().unwrap().contains_key("session"));
}

#[tokio::test]
async fn successful_upload_push_rechecks_closed_state_like_current_xray() {
    let (packet_queue, _packet_reader) = XhttpUploadReader::new(4);
    packet_queue.closed.store(true, Ordering::Release);

    let packet_error = packet_queue
        .push_payload(0, Bytes::from_static(b"raced"))
        .await
        .expect_err("a packet push that races queue close must not report success");
    assert_eq!(packet_error.to_string(), "packet queue closed");

    let (stream_queue, _stream_reader) = XhttpUploadReader::new(4);
    stream_queue.closed.store(true, Ordering::Release);

    let stream_error = stream_queue
        .push_reader(Box::pin(tokio::io::empty()))
        .await
        .expect_err("a stream push that races queue close must not report success");
    assert_eq!(stream_error.to_string(), "packet queue closed");
}

#[tokio::test]
async fn closed_upload_queue_discards_buffered_packets_like_current_xray() {
    use tokio::io::AsyncReadExt;

    let session = XhttpSession::new(4);
    session
        .upload_queue
        .push_payload(0, Bytes::from_static(b"stale"))
        .await
        .expect("packet should queue before session closes");

    session.close_upload_queue();

    let mut reader = SharedUploadReader {
        inner: session.upload_reader.clone(),
    };
    let mut output = [0u8; 5];
    let read =
        tokio::time::timeout(Duration::from_millis(50), reader.read(&mut output))
            .await
            .expect("closed upload queue should return promptly")
            .expect("closed upload queue should report EOF");

    assert_eq!(read, 0, "buffered packet must be discarded after close");
}

#[tokio::test]
async fn expired_session_timer_does_not_reap_reused_session_id() {
    let store = SessionStore::new(
        Duration::from_millis(60),
        30,
        CancellationToken::new(),
        RuntimeState::new(Vec::new(), Vec::new()).data_plane(),
    );
    let old = store.get_or_create("session");
    old.fully_connected.store(true, Ordering::Release);
    store.remove("session");

    sleep(Duration::from_millis(20)).await;
    let reused = store.get_or_create("session");
    sleep(Duration::from_millis(50)).await;

    let current = store
        .inner
        .read()
        .unwrap()
        .get("session")
        .cloned()
        .expect("old timer must not reap reused session id");
    assert!(Arc::ptr_eq(&current, &reused));

    sleep(Duration::from_millis(30)).await;
    assert!(
        !store.inner.read().unwrap().contains_key("session"),
        "reused session must still expire on its own TTL"
    );
}

#[tokio::test]
async fn stream_down_cleanup_guard_removes_connected_session() {
    let store = SessionStore::new(
        Duration::from_secs(30),
        30,
        CancellationToken::new(),
        RuntimeState::new(Vec::new(), Vec::new()).data_plane(),
    );
    let session = store.get_or_create("session");
    session.fully_connected.store(true, Ordering::Release);
    assert!(store.inner.read().unwrap().contains_key("session"));

    drop(SessionCleanupGuard {
        sessions: store.clone(),
        session_id: "session".to_string(),
        session: session.clone(),
    });

    assert!(!store.inner.read().unwrap().contains_key("session"));
    assert!(session.closed.is_cancelled());
    assert!(session.upload_queue.closed.load(Ordering::Acquire));
}
