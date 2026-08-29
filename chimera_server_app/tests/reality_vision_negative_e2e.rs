mod reality_vision_support;

use reality_vision_support::{
    CURRENT_XRAY_VERSION, REALITY_PUBLIC_KEY, REALITY_SERVER_NAME, REALITY_SHORT_ID,
    TEST_UUID, VisionClientOptions, VisionServerOptions, WRONG_REALITY_PUBLIC_KEY,
    WRONG_UUID, assert_socks5_proxy_fails, serial_guard, start_tcp_echo_server,
    start_vision_harness, wait_for_counter, wait_for_log,
};

async fn run_rejected_case(
    name: &str,
    server: VisionServerOptions,
    client: VisionClientOptions,
) -> reality_vision_support::VisionHarness {
    let target = start_tcp_echo_server();
    let mut harness = start_vision_harness(name, server, client).await;
    harness.assert_running();
    assert_socks5_proxy_fails(harness.socks_addr, target);
    harness
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and bundled Xray and validates the current Xray default REALITY version floor"]
async fn reality_omitted_minimum_rejects_bundled_xray_26_2_6() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: None,
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "omitted-minimum-version",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(&harness.chimera, "Client version is below minimum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates an explicit minimum above the client"]
async fn reality_minimum_version_above_client_is_rejected() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: Some("26.2.7".to_string()),
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "minimum-version-above-client",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(&harness.chimera, "Client version is below minimum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates a maximum below the client"]
async fn reality_maximum_version_below_client_is_rejected() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: Some("0.0.0".to_string()),
        max_client_ver: Some("26.2.5".to_string()),
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "maximum-version-below-client",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(&harness.chimera, "Client version is above maximum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates REALITY short ID authentication"]
async fn reality_wrong_short_id_is_rejected_and_falls_back() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        short_id: "1111111111111111".to_string(),
        ..VisionClientOptions::default()
    };
    let harness =
        run_rejected_case("wrong-short-id", VisionServerOptions::default(), client)
            .await;
    wait_for_counter(&harness.dest_accepts, 1);
    wait_for_log(&harness.chimera, "Invalid short_id");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates REALITY server name authentication"]
async fn reality_wrong_server_name_is_rejected_and_falls_back() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        server_name: "wrong.example.test".to_string(),
        ..VisionClientOptions::default()
    };
    let harness = run_rejected_case(
        "wrong-server-name",
        VisionServerOptions::default(),
        client,
    )
    .await;
    wait_for_counter(&harness.dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates REALITY public key authentication"]
async fn reality_wrong_public_key_cannot_proxy() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        public_key: WRONG_REALITY_PUBLIC_KEY.to_string(),
        ..VisionClientOptions::default()
    };
    let harness = run_rejected_case(
        "wrong-public-key",
        VisionServerOptions::default(),
        client,
    )
    .await;
    wait_for_counter(&harness.dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates VLESS UUID authentication after REALITY"]
async fn reality_valid_handshake_with_wrong_vless_uuid_cannot_proxy() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        user_id: WRONG_UUID.to_string(),
        ..VisionClientOptions::default()
    };
    let mut harness = run_rejected_case(
        "wrong-vless-uuid",
        VisionServerOptions::default(),
        client,
    )
    .await;
    harness.assert_running();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates the required Vision flow marker"]
async fn reality_vision_account_rejects_client_without_flow() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        flow: None,
        ..VisionClientOptions::default()
    };
    let harness = run_rejected_case(
        "missing-client-flow",
        VisionServerOptions::default(),
        client,
    )
    .await;
    wait_for_log(
        &harness.chimera,
        "client flow is empty but account requires xtls-rprx-vision",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and Xray and validates Vision is rejected for a plain account"]
async fn reality_plain_account_rejects_client_vision_flow() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        user_flow: None,
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "vision-flow-on-plain-account",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(
        &harness.chimera,
        "account is not allowed to use flow xtls-rprx-vision",
    );
}

#[test]
fn matrix_constants_match_bundled_client_contract() {
    assert_eq!(CURRENT_XRAY_VERSION, "26.2.6");
    assert_eq!(TEST_UUID, "3ac9b383-75a1-431c-8184-106c80eb2273");
    assert_eq!(REALITY_SERVER_NAME, "www.apple.com");
    assert_eq!(REALITY_SHORT_ID.len(), 16);
    assert_ne!(WRONG_REALITY_PUBLIC_KEY, REALITY_PUBLIC_KEY);
}
