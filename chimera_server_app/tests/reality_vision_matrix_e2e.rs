mod reality_vision_support;

use std::{sync::Arc, thread};

use reality_vision_support::{
    CURRENT_XRAY_VERSION, REALITY_SERVER_NAME, REALITY_SHORT_ID,
    VisionClientOptions, VisionServerOptions, assert_socks5_domain_echo,
    assert_socks5_echo, assert_tls_echo_through_socks,
    assert_tls13_only_echo_through_socks, deterministic_payload, probe_half_close,
    serial_guard, start_half_close_server, start_tcp_echo_server,
    start_tls_echo_server, start_vision_harness, start_xray_reference_harness,
    try_start_tcp_echo_server_v6,
};

async fn run_fingerprint_case(name: &str, fingerprint: &str) {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let client = VisionClientOptions {
        fingerprint: fingerprint.to_string(),
        ..VisionClientOptions::default()
    };
    let mut harness =
        start_vision_harness(name, VisionServerOptions::default(), client).await;
    harness.assert_running();
    assert_socks5_echo(
        harness.socks_addr,
        target,
        format!("REALITY Vision fingerprint {fingerprint}").as_bytes(),
    );
    assert_socks5_echo(
        harness.socks_addr,
        target,
        &deterministic_payload(64 * 1024),
    );
}

macro_rules! fingerprint_case {
    ($test_name:ident, $fingerprint:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "starts Chimera and Xray to validate one REALITY Vision uTLS fingerprint"]
        async fn $test_name() {
            run_fingerprint_case(stringify!($test_name), $fingerprint).await;
        }
    };
}

fingerprint_case!(reality_vision_fingerprint_chrome, "chrome");
fingerprint_case!(reality_vision_fingerprint_firefox, "firefox");
fingerprint_case!(reality_vision_fingerprint_safari, "safari");
fingerprint_case!(reality_vision_fingerprint_edge, "edge");
fingerprint_case!(reality_vision_fingerprint_randomized, "randomized");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates Vision framing boundaries"]
async fn reality_vision_payload_boundaries_and_large_transfer() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_vision_harness(
        "payload-boundaries",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    for size in [
        1usize,
        2,
        15,
        16,
        17,
        255,
        256,
        257,
        1023,
        1024,
        1025,
        4095,
        4096,
        4097,
        16 * 1024 - 1,
        16 * 1024,
        16 * 1024 + 1,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
    ] {
        assert_socks5_echo(harness.socks_addr, target, &deterministic_payload(size));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates SOCKS domain address routing"]
async fn reality_vision_domain_address_type_resolves_to_ipv4() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_vision_harness(
        "domain-ipv4",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_socks5_domain_echo(
        harness.socks_addr,
        "127.0.0.1",
        target.port(),
        b"REALITY Vision SOCKS domain address type",
    );
    assert_socks5_domain_echo(
        harness.socks_addr,
        "127.0.0.1",
        target.port(),
        &deterministic_payload(64 * 1024),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates domain to IPv6 routing"]
async fn reality_vision_domain_target_resolves_to_ipv6() {
    let _serial = serial_guard().await;
    let Some(target) = try_start_tcp_echo_server_v6() else {
        eprintln!("IPv6 loopback is unavailable; skipping IPv6 target coverage");
        return;
    };
    let mut harness = start_vision_harness(
        "domain-ipv6",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_socks5_domain_echo(
        harness.socks_addr,
        "localhost",
        target.port(),
        b"REALITY Vision domain target over IPv6",
    );
    assert_socks5_domain_echo(
        harness.socks_addr,
        "localhost",
        target.port(),
        &deterministic_payload(64 * 1024),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates TLS application-data direct transition"]
async fn reality_vision_tls13_application_data_transition() {
    let _serial = serial_guard().await;
    let target = start_tls_echo_server().await;
    let mut harness = start_vision_harness(
        "tls13-application-data",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_tls_echo_through_socks(
        harness.socks_addr,
        target,
        b"TLS 1.3 application data through REALITY Vision",
    )
    .await;
    assert_tls_echo_through_socks(
        harness.socks_addr,
        target,
        &deterministic_payload(256 * 1024),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "validates repeated real TLS 1.3 sessions through Vision"]
async fn reality_vision_repeated_real_tls13_sessions() {
    let _serial = serial_guard().await;
    let target = start_tls_echo_server().await;
    let mut harness = start_vision_harness(
        "repeated-real-tls13",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    for index in 0..32 {
        let payload = format!("TLS session {index:02} through REALITY Vision");
        assert_tls_echo_through_socks(
            harness.socks_addr,
            target,
            payload.as_bytes(),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "validates repeated TLS 1.3-only ClientHello sessions through Vision"]
async fn reality_vision_repeated_tls13_only_sessions() {
    let _serial = serial_guard().await;
    let target = start_tls_echo_server().await;
    let mut harness = start_vision_harness(
        "repeated-tls13-only",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    for index in 0..32 {
        let payload =
            format!("TLS13-only session {index:02} through REALITY Vision");
        assert_tls13_only_echo_through_socks(
            harness.socks_addr,
            target,
            payload.as_bytes(),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "compares TCP half-close behavior with an Xray server baseline"]
async fn reality_vision_half_close_matches_xray_server_baseline() {
    let _serial = serial_guard().await;
    let payload = deterministic_payload(128 * 1024);

    let chimera_target = start_half_close_server();
    let mut chimera = start_vision_harness(
        "half-close-chimera",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    chimera.assert_running();
    let chimera_result =
        probe_half_close(chimera.socks_addr, chimera_target, &payload);

    let xray_target = start_half_close_server();
    let mut reference = start_xray_reference_harness("half-close").await;
    reference.server.assert_running();
    reference.client.assert_running();
    let xray_result = probe_half_close(reference.socks_addr, xray_target, &payload);

    eprintln!(
        "half-close parity: chimera={:?}, xray={:?}",
        chimera_result.as_ref().map(Vec::len),
        xray_result.as_ref().map(Vec::len),
    );
    assert_eq!(
        chimera_result.is_ok(),
        xray_result.is_ok(),
        "Chimera and Xray server differ in TCP half-close behavior"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates many sequential connections"]
async fn reality_vision_handles_many_sequential_connections() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_vision_harness(
        "sequential-connections",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    for index in 0..32usize {
        let mut payload = format!("sequential-{index:02}-").into_bytes();
        payload.extend_from_slice(&deterministic_payload(8 * 1024 + index));
        assert_socks5_echo(harness.socks_addr, target, &payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates concurrent Vision connections"]
async fn reality_vision_handles_concurrent_connections() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_vision_harness(
        "concurrent-connections",
        VisionServerOptions::default(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    let socks_addr = harness.socks_addr;
    let target = Arc::new(target);
    let workers = (0..16usize)
        .map(|index| {
            let target = target.clone();
            thread::spawn(move || {
                let mut payload = format!("concurrent-{index:02}-").into_bytes();
                payload.extend_from_slice(&deterministic_payload(64 * 1024 + index));
                assert_socks5_echo(socks_addr, *target, &payload);
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("REALITY Vision concurrent worker");
    }
    harness.assert_running();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates multiple accepted server names"]
async fn reality_vision_accepts_second_configured_server_name() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        server_names: vec![
            "other.example.test".to_string(),
            REALITY_SERVER_NAME.to_string(),
        ],
        ..VisionServerOptions::default()
    };
    let mut harness = start_vision_harness(
        "second-server-name",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(harness.socks_addr, target, b"second REALITY server name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates multiple accepted short IDs"]
async fn reality_vision_accepts_second_configured_short_id() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        short_ids: vec![
            "1111111111111111".to_string(),
            REALITY_SHORT_ID.to_string(),
        ],
        ..VisionServerOptions::default()
    };
    let mut harness = start_vision_harness(
        "second-short-id",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(harness.socks_addr, target, b"second REALITY short ID");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates exact version upper bound"]
async fn reality_vision_accepts_exact_client_version_bounds() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        min_client_ver: Some(CURRENT_XRAY_VERSION.to_string()),
        max_client_ver: Some(CURRENT_XRAY_VERSION.to_string()),
        ..VisionServerOptions::default()
    };
    let mut harness = start_vision_harness(
        "exact-version-bounds",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(
        harness.socks_addr,
        target,
        b"exact REALITY client version bounds",
    );
}
