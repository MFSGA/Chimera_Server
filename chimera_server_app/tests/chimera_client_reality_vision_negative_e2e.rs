mod reality_vision_support;

use reality_vision_support::{
    CHIMERA_CLIENT_REALITY_VERSION, VisionClientOptions, VisionServerOptions,
    WRONG_REALITY_PUBLIC_KEY, WRONG_UUID, assert_socks5_echo,
    assert_socks5_proxy_fails, serial_guard, start_chimera_client_harness,
    start_tcp_echo_server, wait_for_counter, wait_for_log,
};

async fn run_rejected_case(
    name: &str,
    server: VisionServerOptions,
    client: VisionClientOptions,
) -> reality_vision_support::ChimeraClientHarness {
    let target = start_tcp_echo_server();
    let mut harness = start_chimera_client_harness(name, server, client).await;
    harness.assert_running();
    assert_socks5_proxy_fails(harness.socks_addr, target);
    harness
}

fn compatible_server_options() -> VisionServerOptions {
    VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        ..VisionServerOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates omitted REALITY version bounds"]
async fn chimera_client_is_accepted_without_server_version_floor() {
    let _serial = serial_guard().await;
    let target = start_tcp_echo_server();
    let server = VisionServerOptions {
        min_client_ver: None,
        ..VisionServerOptions::default()
    };
    let mut harness = start_chimera_client_harness(
        "omitted-version-floor",
        server,
        VisionClientOptions::default(),
    )
    .await;
    harness.assert_running();
    assert_socks5_echo(
        harness.socks_addr,
        target,
        b"omitted REALITY minimum accepts Chimera Client",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates a minimum above client metadata"]
async fn chimera_client_below_explicit_minimum_is_rejected() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: Some("1.8.1".to_string()),
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "minimum-above-client",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(&harness.server, "Client version is below minimum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates a maximum below client metadata"]
async fn chimera_client_above_explicit_maximum_is_rejected() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: Some("0.0.0".to_string()),
        max_client_ver: Some("1.7.255".to_string()),
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "maximum-below-client",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(&harness.server, "Client version is above maximum");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates REALITY short ID authentication"]
async fn chimera_client_wrong_short_id_is_rejected() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        short_id: "1111111111111111".to_string(),
        ..VisionClientOptions::default()
    };
    let harness =
        run_rejected_case("wrong-short-id", compatible_server_options(), client)
            .await;
    wait_for_counter(&harness.dest_accepts, 1);
    wait_for_log(&harness.server, "Invalid short_id");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates REALITY server name authentication"]
async fn chimera_client_wrong_server_name_is_rejected() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        server_name: "wrong.example.test".to_string(),
        ..VisionClientOptions::default()
    };
    let harness =
        run_rejected_case("wrong-server-name", compatible_server_options(), client)
            .await;
    wait_for_counter(&harness.dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates REALITY public key authentication"]
async fn chimera_client_wrong_public_key_is_rejected() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        public_key: WRONG_REALITY_PUBLIC_KEY.to_string(),
        ..VisionClientOptions::default()
    };
    let harness =
        run_rejected_case("wrong-public-key", compatible_server_options(), client)
            .await;
    wait_for_counter(&harness.dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates VLESS UUID authentication"]
async fn chimera_client_wrong_vless_uuid_is_rejected() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        user_id: WRONG_UUID.to_string(),
        ..VisionClientOptions::default()
    };
    let _harness =
        run_rejected_case("wrong-vless-uuid", compatible_server_options(), client)
            .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates the required Vision flow marker"]
async fn chimera_client_without_vision_flow_is_rejected() {
    let _serial = serial_guard().await;
    let client = VisionClientOptions {
        flow: None,
        ..VisionClientOptions::default()
    };
    let harness = run_rejected_case(
        "missing-client-flow",
        compatible_server_options(),
        client,
    )
    .await;
    wait_for_log(
        &harness.server,
        "client flow is empty but account requires xtls-rprx-vision",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera Server and Chimera Client and validates Vision is rejected for a plain account"]
async fn chimera_client_vision_flow_on_plain_account_is_rejected() {
    let _serial = serial_guard().await;
    let server = VisionServerOptions {
        min_client_ver: Some(CHIMERA_CLIENT_REALITY_VERSION.to_string()),
        user_flow: None,
        ..VisionServerOptions::default()
    };
    let harness = run_rejected_case(
        "vision-on-plain-account",
        server,
        VisionClientOptions::default(),
    )
    .await;
    wait_for_log(
        &harness.server,
        "account is not allowed to use flow xtls-rprx-vision",
    );
}
