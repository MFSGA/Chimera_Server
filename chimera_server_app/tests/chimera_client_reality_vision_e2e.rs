mod reality_vision_support;

use std::{sync::Arc, thread};

use reality_vision_support::{
    CHIMERA_CLIENT_REALITY_VERSION, REALITY_SERVER_NAME, REALITY_SHORT_ID,
    VisionClientOptions, VisionServerOptions, assert_socks5_domain_echo,
    assert_socks5_echo, assert_tls_echo_through_socks, deterministic_payload,
    serial_guard, start_chimera_client_harness, start_tcp_echo_server,
    start_tls_echo_server,
};

fn compatible_server_options() -> VisionServerOptions {
    VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        ..VisionServerOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client for REALITY Vision TCP interoperability"]
async fn chimera_client_reality_vision_basic_tcp_and_large_payload() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(
        "basic-tcp",
        compatible_server_options(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_socks5_echo(
        harness.socks_addr,
        target,
        b"Chimera Client REALITY Vision basic TCP",
    );
    assert_socks5_echo(
        harness.socks_addr,
        target,
        &deterministic_payload(64 * 1024),
    );
    assert_socks5_echo(
        harness.socks_addr,
        target,
        &deterministic_payload(1024 * 1024),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates Vision framing boundaries"]
async fn chimera_client_reality_vision_payload_boundaries() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(
        "payload-boundaries",
        compatible_server_options(),
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
    ] {
        assert_socks5_echo(harness.socks_addr, target, &deterministic_payload(size));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates SOCKS domain targets"]
async fn chimera_client_reality_vision_domain_target() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(
        "domain-target",
        compatible_server_options(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_socks5_domain_echo(
        harness.socks_addr,
        "localhost",
        target.port(),
        b"Chimera Client domain target",
    );
    assert_socks5_domain_echo(
        harness.socks_addr,
        "localhost",
        target.port(),
        &deterministic_payload(64 * 1024),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates inner TLS 1.3 application data"]
async fn chimera_client_reality_vision_tls13_application_data() {
    let _serial = serial_guard().await;
    let target = start_tls_echo_server().await;
    let mut harness = start_chimera_client_harness(
        "tls13-application-data",
        compatible_server_options(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    assert_tls_echo_through_socks(
        harness.socks_addr,
        target,
        b"TLS 1.3 through Chimera Client REALITY Vision",
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
#[ignore = "starts Chimera Server and Chimera Client and validates sequential connections"]
async fn chimera_client_reality_vision_sequential_connections() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(
        "sequential-connections",
        compatible_server_options(),
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();

    for index in 0..32usize {
        let mut payload =
            format!("chimera-client-sequential-{index:02}-").into_bytes();
        payload.extend_from_slice(&deterministic_payload(8 * 1024 + index));
        assert_socks5_echo(harness.socks_addr, target, &payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates concurrent connections"]
async fn chimera_client_reality_vision_concurrent_connections() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(
        "concurrent-connections",
        compatible_server_options(),
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
                let mut payload =
                    format!("chimera-client-concurrent-{index:02}-").into_bytes();
                payload.extend_from_slice(&deterministic_payload(64 * 1024 + index));
                assert_socks5_echo(socks_addr, *target, &payload);
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("Chimera Client concurrent worker");
    }
    harness.assert_running();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates multiple REALITY server names"]
async fn chimera_client_reality_vision_second_server_name() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        server_names: vec![
            "other.example.test".to_string(),
            REALITY_SERVER_NAME.to_string(),
        ],
        ..VisionServerOptions::default()
    };
    let mut harness = start_chimera_client_harness(
        "second-server-name",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(harness.socks_addr, target, b"second REALITY server name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates multiple REALITY short IDs"]
async fn chimera_client_reality_vision_second_short_id() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        short_ids: vec![
            "1111111111111111".to_string(),
            REALITY_SHORT_ID.to_string(),
        ],
        ..VisionServerOptions::default()
    };
    let mut harness = start_chimera_client_harness(
        "second-short-id",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(harness.socks_addr, target, b"second REALITY short ID");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates exact REALITY version bounds"]
async fn chimera_client_reality_vision_exact_version_bounds() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        max_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        ..VisionServerOptions::default()
    };
    let mut harness = start_chimera_client_harness(
        "exact-version-bounds",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(
        harness.socks_addr,
        target,
        b"exact Chimera Client REALITY version bounds",
    );
}
