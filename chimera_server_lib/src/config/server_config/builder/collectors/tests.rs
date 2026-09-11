use super::*;
use crate::config::{
    XhttpSettings,
    server_config::{
        XhttpDataPlacement, XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement,
        XhttpPlacement,
    },
};

#[cfg(feature = "tuic")]
#[test]
fn collect_tuic_settings_accepts_valid_config() {
    let settings = SettingObject(serde_json::json!({
        "uuid": "dd206ca8-f026-47a3-8861-733c738a6242",
        "password": "tuic-password",
        "zeroRttHandshake": true
    }));

    let config = collect_tuic_settings(settings).expect("valid tuic settings");
    assert_eq!(config.uuid, "dd206ca8-f026-47a3-8861-733c738a6242");
    assert_eq!(config.password, "tuic-password");
    assert!(config.zero_rtt_handshake);
}

#[cfg(feature = "tuic")]
#[test]
fn collect_tuic_settings_rejects_invalid_uuid() {
    let settings = SettingObject(serde_json::json!({
        "uuid": "not-a-uuid",
        "password": "tuic-password"
    }));

    let err = collect_tuic_settings(settings).expect_err("invalid uuid");
    assert!(
        matches!(err, Error::InvalidConfig(_)),
        "expected InvalidConfig"
    );
}

#[test]
fn collect_socks_settings_accepts_udp_true() {
    let settings = SettingObject(serde_json::json!({
        "auth": "noauth",
        "udp": true
    }));

    let (users, udp_enabled, udp_response_ip, _) =
        collect_socks_settings(settings).expect("socks udp should be accepted");
    assert!(!users.auth_required());
    assert!(udp_enabled);
    assert!(udp_response_ip.is_none());
}

#[test]
fn collect_socks_unknown_auth_defaults_to_noauth() {
    let settings = SettingObject(serde_json::json!({
        "auth": "future-auth",
        "accounts": [{"user": "alice", "pass": "secret"}],
        "udp": true,
        "ip": "127.0.0.1"
    }));

    let (users, udp_enabled, udp_response_ip, _) = collect_socks_settings(settings)
        .expect("unknown socks auth should match Xray noauth fallback");
    assert!(!users.auth_required());
    assert_eq!(users.snapshot()[0].username, "alice");
    assert!(udp_enabled);
    assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
}

#[test]
fn collect_socks_password_auth_accepts_empty_accounts_like_xray() {
    let settings = SettingObject(serde_json::json!({
        "auth": "password",
        "accounts": []
    }));

    let (users, udp_enabled, udp_response_ip, user_level) =
        collect_socks_settings(settings)
            .expect("Xray accepts password auth before any accounts are configured");
    assert!(users.auth_required());
    assert!(users.snapshot().is_empty());
    assert!(!udp_enabled);
    assert!(udp_response_ip.is_none());
    assert_eq!(user_level, 0);
}

#[test]
fn collect_socks_users_alias_and_accounts_override_match_xray() {
    let users_only = SettingObject(serde_json::json!({
        "auth": "password",
        "users": [{"user": "legacy", "pass": "secret"}]
    }));
    let (users, _, _, _) = collect_socks_settings(users_only)
        .expect("legacy socks users should be accepted");
    assert!(users.auth_required());
    assert_eq!(users.snapshot()[0].username, "legacy");

    let accounts_override = SettingObject(serde_json::json!({
        "users": [{"user": "legacy", "pass": "secret"}],
        "accounts": []
    }));
    let (users, _, _, _) = collect_socks_settings(accounts_override)
        .expect("explicit accounts should override legacy users");
    assert!(!users.auth_required());
    assert!(users.snapshot().is_empty());
}

#[test]
fn collect_socks_settings_preserves_xray_user_level() {
    let settings = SettingObject(serde_json::json!({
        "auth": "noauth",
        "userLevel": 7
    }));

    let (_, _, _, user_level) =
        collect_socks_settings(settings).expect("Xray userLevel should be accepted");
    assert_eq!(user_level, 7);
}

#[test]
fn collect_socks_settings_preserves_udp_response_ip() {
    let settings = SettingObject(serde_json::json!({
        "auth": "noauth",
        "udp": true,
        "ip": "127.0.0.1"
    }));

    let (_, udp_enabled, udp_response_ip, _) =
        collect_socks_settings(settings).expect("socks ip should be accepted");
    assert!(udp_enabled);
    assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
}

#[test]
fn collect_socks_settings_accepts_domain_udp_response_address() {
    let settings = SettingObject(serde_json::json!({
        "auth": "noauth",
        "udp": true,
        "ip": "localhost"
    }));

    let (_, udp_enabled, udp_response_ip, _) =
        collect_socks_settings(settings).expect("Xray accepts domain settings.ip");
    assert!(udp_enabled);
    assert_eq!(udp_response_ip.as_deref(), Some("localhost"));
}

#[test]
fn collect_socks_accounts_accepts_explicit_udp_false() {
    let settings = SettingObject(serde_json::json!({
        "auth": "noauth",
        "udp": false
    }));

    let (users, udp_enabled, udp_response_ip, _) =
        collect_socks_settings(settings).expect("udp false is a no-op");
    assert!(!users.auth_required());
    assert!(!udp_enabled);
    assert!(udp_response_ip.is_none());
}

#[cfg(feature = "trojan")]
#[test]
fn collect_trojan_fallbacks_preserves_xray_fields() {
    let settings = SettingObject(serde_json::json!({
        "fallbacks": [{
            "name": "EXAMPLE.COM",
            "alpn": "H2",
            "dest": 8080,
            "path": "/ws",
            "type": "tcp",
            "xver": 2
        }]
    }));

    let fallbacks = collect_trojan_fallbacks(&settings)
        .expect("Trojan fallback fields should build");
    assert_eq!(fallbacks.len(), 1);
    assert_eq!(fallbacks[0].name, "example.com");
    assert_eq!(fallbacks[0].alpn, "h2");
    assert_eq!(fallbacks[0].path, "/ws");
    assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8080");
    assert_eq!(fallbacks[0].xver, 2);
}

#[cfg(feature = "trojan")]
#[test]
fn collect_trojan_fallbacks_rejects_invalid_type_path_and_xver() {
    for (field, value, expected) in [
        (
            "type",
            serde_json::json!("unix"),
            "trojan fallback type=unix is not supported yet",
        ),
        (
            "path",
            serde_json::json!("ws"),
            "trojan fallback path must be empty or start with /",
        ),
        (
            "xver",
            serde_json::json!(3),
            "trojan fallback xver must be 0, 1, or 2; got 3",
        ),
    ] {
        let mut fallback = serde_json::json!({"dest": 8080});
        fallback[field] = value;
        let settings = SettingObject(serde_json::json!({
            "fallbacks": [fallback]
        }));
        let error = collect_trojan_fallbacks(&settings)
            .expect_err("invalid Trojan fallback field must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn collect_xhttp_settings_applies_reference_defaults() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp/?ed=2048"
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
    assert_eq!(config.mode, XhttpMode::Auto);
    assert_eq!(config.path, "/xhttp/");
    assert_eq!(config.max_each_post_bytes, 1_000_000);
    assert_eq!(config.max_buffered_posts, 30);
    assert_eq!(config.session_ttl_secs, 30);
    assert_eq!(config.stream_up_server_secs, (20, 80));
    assert_eq!(config.server_max_header_bytes, 8192);
    assert!(!config.padding_obfs_mode);
    assert_eq!(config.padding_key, "x_padding");
    assert_eq!(config.padding_header, "X-Padding");
    assert_eq!(
        config.padding_placement,
        XhttpPaddingPlacement::QueryInHeader
    );
    assert_eq!(config.padding_method, XhttpPaddingMethod::RepeatX);
    assert!(!config.no_grpc_header);
    assert!(!config.no_sse_header);
    assert_eq!(config.uplink_http_method, "POST");
    assert_eq!(config.min_posts_interval_ms, (30, 30));
    assert_eq!(config.session_placement, XhttpPlacement::Path);
    assert!(config.session_key.is_empty());
    assert_eq!(config.seq_placement, XhttpPlacement::Path);
    assert!(config.seq_key.is_empty());
    assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Auto);
    assert_eq!(config.uplink_data_key, "X-Data");
}

#[test]
fn collect_xhttp_settings_preserves_negative_post_limit_like_xray_v26_2_6() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "scMaxEachPostBytes": -1
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
    assert_eq!(config.max_each_post_bytes, -1);
}

#[test]
fn collect_xhttp_settings_disables_min_post_delay_for_negative_range_like_xray_v26_2_6()
 {
    for value in [serde_json::json!(-1), serde_json::json!("-5--1")] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scMinPostsIntervalMs": value
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.min_posts_interval_ms, (0, 0));
    }

    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "scMinPostsIntervalMs": 0
    }))
    .expect("xhttp settings");
    let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
    assert_eq!(config.min_posts_interval_ms, (30, 30));
}

#[test]
fn collect_xhttp_settings_disables_stream_up_padding_for_negative_range_like_xray_v26_2_6()
 {
    for value in [serde_json::json!(-1), serde_json::json!("-5--1")] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scStreamUpServerSecs": value
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.stream_up_server_secs, (0, 0));
    }
}

#[test]
fn collect_xhttp_settings_normalizes_zero_buffered_posts_like_xray_v26_2_6() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "scMaxBufferedPosts": 0
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
    assert_eq!(config.max_buffered_posts, 30);
}

#[test]
fn collect_xhttp_settings_rejects_negative_buffered_posts_like_xray_v26_2_6() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "scMaxBufferedPosts": -1
    }))
    .expect("xhttp settings");

    let error = collect_xhttp_settings(settings)
        .expect_err("negative scMaxBufferedPosts must be rejected");
    assert!(
        error
            .to_string()
            .contains("xhttpSettings.scMaxBufferedPosts cannot be negative"),
        "{error}"
    );
}

#[test]
fn collect_xhttp_settings_treats_zero_padding_range_as_xray_default() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "xPaddingBytes": 0
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("Xray v26.2.6 accepts zero xPaddingBytes as the default range");
    assert_eq!((config.min_padding, config.max_padding), (100, 1000));
}

#[test]
fn collect_xhttp_settings_accepts_padding_obfuscation_and_header_limit() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "xPaddingObfsMode": true,
        "xPaddingKey": "pad",
        "xPaddingHeader": "X-Custom-Pad",
        "xPaddingPlacement": "cookie",
        "xPaddingMethod": "tokenish",
        "xPaddingBytes": {"from": 64, "to": 128},
        "serverMaxHeaderBytes": 32768,
        "scStreamUpServerSecs": {"from": 5, "to": 10}
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("custom XHTTP padding settings should be supported");
    assert!(config.padding_obfs_mode);
    assert_eq!(config.padding_key, "pad");
    assert_eq!(config.padding_header, "X-Custom-Pad");
    assert_eq!(config.padding_placement, XhttpPaddingPlacement::Cookie);
    assert_eq!(config.padding_method, XhttpPaddingMethod::Tokenish);
    assert_eq!((config.min_padding, config.max_padding), (64, 128));
    assert_eq!(config.server_max_header_bytes, 32768);
    assert_eq!(config.stream_up_server_secs, (5, 10));
}

#[test]
fn collect_xhttp_settings_rejects_invalid_padding_configuration() {
    for (field, field_value, expected) in [
        (
            "xPaddingBytes",
            serde_json::json!({"from": 0, "to": 100}),
            "xPaddingBytes cannot be disabled",
        ),
        (
            "xPaddingPlacement",
            serde_json::json!("fragment"),
            "unsupported xhttpSettings.xPaddingPlacement",
        ),
        (
            "xPaddingMethod",
            serde_json::json!("random"),
            "unsupported xhttpSettings.xPaddingMethod",
        ),
    ] {
        let mut settings_value = serde_json::json!({"path": "/xhttp"});
        settings_value[field] = field_value;
        let settings = serde_json::from_value::<XhttpSettings>(settings_value)
            .expect("xhttp settings should deserialize");
        let error = collect_xhttp_settings(settings)
            .expect_err("invalid XHTTP padding setting must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn collect_xhttp_settings_defaults_zero_header_limit_like_current_xray() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "serverMaxHeaderBytes": 0
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("current Xray defaults zero serverMaxHeaderBytes");
    assert_eq!(config.server_max_header_bytes, 8192);
}

#[test]
fn collect_xhttp_settings_rejects_negative_header_limit_like_current_xray() {
    for value in [-1, i32::MIN] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "serverMaxHeaderBytes": value
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("current Xray rejects negative serverMaxHeaderBytes");
        assert!(
            error
                .to_string()
                .contains("xhttpSettings.serverMaxHeaderBytes cannot be negative"),
            "{error}"
        );
    }
}

#[test]
fn collect_xhttp_settings_accepts_reference_modes() {
    for (mode, expected) in [
        ("auto", XhttpMode::Auto),
        ("packet-up", XhttpMode::PacketUp),
        ("stream-up", XhttpMode::StreamUp),
        ("stream-one", XhttpMode::StreamOne),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": mode
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .unwrap_or_else(|err| panic!("mode {mode} should be accepted: {err}"));
        assert_eq!(config.mode, expected);
    }
}

#[test]
fn collect_xhttp_settings_accepts_mixed_metadata_placements_like_current_xray() {
    for (session_placement, seq_placement) in [
        ("path", "query"),
        ("query", "path"),
        ("path", "header"),
        ("cookie", "path"),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "mode": "packet-up",
            "sessionIDPlacement": session_placement,
            "seqPlacement": seq_placement
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).unwrap_or_else(|err| {
            panic!(
                "current Xray accepts mixed metadata placements {session_placement}/{seq_placement}: {err}"
            )
        });
        assert_eq!(
            config.session_placement,
            parse_xhttp_placement(Some(session_placement), "sessionIDPlacement")
                .unwrap()
        );
        assert_eq!(
            config.seq_placement,
            parse_xhttp_placement(Some(seq_placement), "seqPlacement").unwrap()
        );
    }
}

#[test]
fn collect_xhttp_settings_validates_session_id_generator_like_current_xray() {
    for settings_value in [
        serde_json::json!({
            "path": "/xhttp",
            "sessionIDTable": "Base62",
            "sessionIDLength": 6
        }),
        serde_json::json!({
            "path": "/xhttp",
            "sessionIDTable": "0123456789abcdef",
            "sessionIDLength": {"from": 8, "to": 10}
        }),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(settings_value)
            .expect("xhttp settings should deserialize");
        collect_xhttp_settings(settings).expect(
            "current Xray accepts sufficiently large ASCII session ID generators",
        );
    }

    for settings_value in [
        serde_json::json!({
            "path": "/xhttp",
            "sessionIDTable": "number",
            "sessionIDLength": 1
        }),
        serde_json::json!({
            "path": "/xhttp",
            "sessionIDTable": "表格",
            "sessionIDLength": 16
        }),
        serde_json::json!({
            "path": "/xhttp",
            "sessionIDTable": "Base62",
            "sessionIDLength": 0
        }),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(settings_value)
            .expect("xhttp settings should deserialize");
        assert!(
            collect_xhttp_settings(settings).is_err(),
            "current Xray rejects undersized, non-ASCII, and non-positive session ID generators"
        );
    }
}

#[test]
fn collect_xhttp_settings_matches_current_xray_path_normalization() {
    for (settings_value, expected_path) in [
        (
            serde_json::json!({
                "path": "/stream",
                "sessionIDPlacement": "query",
                "seqPlacement": "query"
            }),
            "/stream",
        ),
        (
            serde_json::json!({
                "path": "/stream/filename.extension",
                "sessionIDPlacement": "query",
                "seqPlacement": "header"
            }),
            "/stream/filename.extension",
        ),
        (
            serde_json::json!({
                "path": "/stream",
                "sessionIDPlacement": "query",
                "seqPlacement": "path"
            }),
            "/stream/",
        ),
        (
            serde_json::json!({
                "path": "/stream"
            }),
            "/stream/",
        ),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(settings_value)
            .expect("xhttp settings");
        let config = collect_xhttp_settings(settings)
            .expect("current Xray path placement should be accepted");
        assert_eq!(config.path, expected_path);
    }
}

#[test]
fn collect_xhttp_settings_accepts_reference_header_and_method_options() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "stream-one",
        "noGRPCHeader": true,
        "noSSEHeader": true,
        "uplinkHTTPMethod": "patch",
        "scMinPostsIntervalMs": {"from": 40, "to": 60},
        "sessionPlacement": "header",
        "seqPlacement": "query"
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("supported XHTTP header and method options");
    assert!(config.no_grpc_header);
    assert!(config.no_sse_header);
    assert_eq!(config.uplink_http_method, "PATCH");
    assert_eq!(config.min_posts_interval_ms, (40, 60));
    assert_eq!(config.session_placement, XhttpPlacement::Header);
    assert_eq!(config.session_key, "X-Session");
    assert_eq!(config.seq_placement, XhttpPlacement::Query);
    assert_eq!(config.seq_key, "x_seq");
}

#[test]
fn collect_xhttp_settings_preserves_xray_uplink_method_text_semantics() {
    for (raw_method, expected) in
        [("FOO BAR", "FOO BAR"), (":", ":"), (" get ", " GET ")]
    {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "stream-one",
            "uplinkHTTPMethod": raw_method
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("Xray v26.2.6 accepts arbitrary uplink method text");
        assert_eq!(config.uplink_http_method, expected);
    }

    let exact_get = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "stream-one",
        "uplinkHTTPMethod": "get"
    }))
    .expect("xhttp settings");
    assert!(collect_xhttp_settings(exact_get).is_err());
}

#[test]
fn collect_xhttp_settings_accepts_explicit_auto_data_placement_like_current_xray() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "packet-up",
        "uplinkDataPlacement": "auto"
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("current Xray accepts explicit auto uplink data placement");
    assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Auto);
    assert_eq!(config.uplink_data_key, "X-Data");
}

#[test]
fn collect_xhttp_settings_accepts_packet_up_header_data() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "packet-up",
        "uplinkDataPlacement": "header"
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("packet-up header data should be supported");
    assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Header);
    assert_eq!(config.uplink_data_key, "X-Data");
}

#[test]
fn collect_xhttp_settings_accepts_packet_up_cookie_data() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "packet-up",
        "uplinkDataPlacement": "cookie"
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("packet-up cookie data should be supported");
    assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Cookie);
    assert_eq!(config.uplink_data_key, "x_data");
}

#[test]
fn collect_xhttp_settings_rejects_header_data_outside_packet_up() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "stream-up",
        "uplinkDataPlacement": "header"
    }))
    .expect("xhttp settings");

    let error = collect_xhttp_settings(settings)
        .expect_err("header data must require packet-up");
    assert!(error.to_string().contains(
        "xhttpSettings.uplinkDataPlacement=header requires mode=packet-up"
    ));
}

#[test]
fn collect_xhttp_settings_preserves_path_without_path_metadata() {
    let settings: XhttpSettings = serde_json::from_value(serde_json::json!({
        "path": "/x",
        "mode": "packet-up",
        "sessionIDPlacement": "query",
        "seqPlacement": "query"
    }))
    .expect("valid xhttp settings");

    let config =
        collect_xhttp_settings(settings).expect("xhttp settings should parse");
    assert_eq!(config.path, "/x");
}

#[test]
fn collect_xhttp_settings_preserves_key_text_like_xray_v26_2_6() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "packet-up",
        "sessionPlacement": "query",
        "sessionKey": " x_session ",
        "seqPlacement": "query",
        "seqKey": " x_seq ",
        "uplinkDataPlacement": "header",
        "uplinkDataKey": " X-Data "
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("Xray v26.2.6 preserves non-empty key text verbatim");
    assert_eq!(config.session_key, " x_session ");
    assert_eq!(config.seq_key, " x_seq ");
    assert_eq!(config.uplink_data_key, " X-Data ");
}

#[test]
fn collect_xhttp_settings_rejects_unknown_meta_placement() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "sessionPlacement": "fragment"
    }))
    .expect("xhttp settings");

    let error = collect_xhttp_settings(settings)
        .expect_err("unknown session placement must fail");
    assert!(
        error
            .to_string()
            .contains("unsupported xhttpSettings.sessionPlacement: fragment")
    );
}

#[test]
fn collect_xhttp_settings_rejects_get_outside_packet_up() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "stream-one",
        "uplinkHTTPMethod": "GET"
    }))
    .expect("xhttp settings");

    let error = collect_xhttp_settings(settings)
        .expect_err("GET uplink must be packet-up only");
    assert!(
        error
            .to_string()
            .contains("xhttpSettings.uplinkHTTPMethod=GET requires mode=packet-up")
    );
}

#[test]
fn collect_xhttp_settings_rejects_noncanonical_selector_text_like_xray_v26_2_6() {
    let cases = [
        ("mode", "Packet-Up"),
        ("mode", " packet-up "),
        ("sessionPlacement", "Query"),
        ("sessionPlacement", " query "),
        ("seqPlacement", "Header"),
        ("seqPlacement", " header "),
        ("uplinkDataPlacement", "Header"),
        ("uplinkDataPlacement", " header "),
        ("xPaddingPlacement", "Header"),
        ("xPaddingPlacement", " header "),
        ("xPaddingMethod", "Tokenish"),
        ("xPaddingMethod", " tokenish "),
    ];

    for (field, value) in cases {
        let mut object = serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "sessionPlacement": "query"
        });
        object.as_object_mut().expect("xhttp object").insert(
            field.to_string(),
            serde_json::Value::String(value.to_string()),
        );
        let settings = serde_json::from_value::<XhttpSettings>(object)
            .expect("xhttp settings should deserialize before validation");

        let error = collect_xhttp_settings(settings).expect_err(
            "Xray v26.2.6 treats selector values as exact case-sensitive text",
        );
        assert!(
            error.to_string().contains("unsupported xhttpSettings"),
            "{field}={value:?} returned unexpected error: {error}"
        );
    }
}

#[test]
fn collect_xhttp_settings_rejects_unsupported_mode() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "grpc"
    }))
    .expect("xhttp settings");

    let err = collect_xhttp_settings(settings).expect_err("unsupported mode");
    assert!(
        err.to_string()
            .contains("unsupported xhttpSettings.mode: grpc")
    );
}

#[test]
fn collect_xhttp_settings_rejects_host_header() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "headers": {
            "Host": "edge.example.com"
        }
    }))
    .expect("xhttp settings");

    let err = collect_xhttp_settings(settings).expect_err("host header");
    assert!(
        err.to_string()
            .contains("xhttpSettings.headers cannot contain host")
    );
}

#[test]
fn collect_xhttp_settings_accepts_client_request_headers() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "headers": {
            "X-Test": "ok"
        }
    }))
    .expect("xhttp settings");

    collect_xhttp_settings(settings)
        .expect("server should accept client-side XHTTP request headers");
}

#[test]
fn collect_xhttp_settings_accepts_shared_client_only_fields() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "path": "/xhttp",
        "mode": "packet-up",
        "downloadSettings": {"network": "xhttp"},
        "xmux": {
            "maxConnections": {"from": 2, "to": 3},
            "hMaxRequestTimes": {"from": 100, "to": 200}
        },
        "uplinkChunkSize": 2048,
        "sessionIDTable": "Base62",
        "sessionIDLength": {"from": 6, "to": 8}
    }))
    .expect("xhttp settings");

    collect_xhttp_settings(settings)
        .expect("server should accept valid XHTTP fields consumed by the client");
}

#[test]
fn xhttp_uplink_chunk_size_matches_current_xray_range_schema() {
    for value in [
        serde_json::json!(63),
        serde_json::json!({"from": 1024, "to": 2048}),
        serde_json::json!(-1),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "mode": "packet-up",
            "uplinkChunkSize": value
        }))
        .expect("current Xray Int32Range forms should deserialize");
        collect_xhttp_settings(settings)
            .expect("current Xray uplinkChunkSize range form should be accepted");
    }
}

#[test]
fn collect_xhttp_settings_applies_extra_with_outer_identity_fields() {
    let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
        "host": "outer.example",
        "path": "/outer",
        "mode": "packet-up",
        "extra": {
            "host": "ignored.example",
            "path": "/ignored",
            "mode": "stream-one",
            "uplinkDataPlacement": "cookie",
            "xPaddingObfsMode": true,
            "xPaddingPlacement": "header",
            "xPaddingMethod": "tokenish"
        }
    }))
    .expect("xhttp settings");

    let config = collect_xhttp_settings(settings)
        .expect("xhttpSettings.extra should overlay non-identity fields");
    assert_eq!(config.host.as_deref(), Some("outer.example"));
    assert_eq!(config.path, "/outer/");
    assert_eq!(config.mode, XhttpMode::PacketUp);
    assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Cookie);
    assert!(config.padding_obfs_mode);
    assert_eq!(config.padding_placement, XhttpPaddingPlacement::Header);
    assert_eq!(config.padding_method, XhttpPaddingMethod::Tokenish);
}

#[test]
fn collect_xhttp_settings_rejects_invalid_shared_client_fields() {
    for (settings_value, expected) in [
        (
            serde_json::json!({
                "path": "/xhttp",
                "mode": "stream-one",
                "downloadSettings": {"network": "xhttp"}
            }),
            "downloadSettings cannot be used with mode=stream-one",
        ),
        (
            serde_json::json!({
                "path": "/xhttp",
                "xmux": {
                    "maxConnections": {"from": 1, "to": 1},
                    "maxConcurrency": {"from": 1, "to": 1}
                }
            }),
            "maxConnections cannot be specified together with maxConcurrency",
        ),
    ] {
        let settings = serde_json::from_value::<XhttpSettings>(settings_value)
            .expect("xhttp settings should deserialize");
        let error = collect_xhttp_settings(settings)
            .expect_err("invalid shared XHTTP field must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_xray_client_auth() {
    let settings = SettingObject(serde_json::json!({
        "clients": [{
            "auth": "xray-auth-token",
            "email": "hy@example.com",
            "level": 7
        }]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("hysteria auth should map to password");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "xray-auth-token");
    assert_eq!(config.clients[0].email.as_deref(), Some("hy@example.com"));
    assert_eq!(config.clients[0].level, 7);
    assert!(config.clients[0].xray_uuid_route);
    assert_eq!(config.xray_udp_idle_timeout_secs, Some(60));
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_empty_auth_only_for_xray_users() {
    let xray_settings = SettingObject(serde_json::json!({
        "version": 2,
        "clients": [{"auth": "", "email": "empty@example.com"}]
    }));
    let xray_stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2
        }))
        .expect("valid Xray hysteriaSettings");
    let config =
        collect_hysteria2_settings(xray_settings, Some(&xray_stream_settings))
            .expect("Xray validator accepts an empty auth key");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "");
    assert!(config.clients[0].xray_uuid_route);

    let shoes_settings = SettingObject(serde_json::json!({
        "clients": [{"auth": "", "email": "empty@example.com"}]
    }));
    let err = collect_hysteria2_settings(shoes_settings, None)
        .expect_err("non-Xray empty auth must stay invalid");
    assert!(err.to_string().contains("non-empty auth or id"), "{err}");
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_xray_transport_auth_fallback() {
    let settings = SettingObject(serde_json::json!({
        "version": 2
    }));
    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "auth": "transport-auth-token",
            "up": "1 kbps",
            "down": "2 kbps"
        }))
        .expect("valid hysteriaSettings auth");

    let config = collect_hysteria2_settings(settings, Some(&stream_settings))
        .expect("Xray transport auth fallback should be accepted");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "transport-auth-token");
    assert_eq!(config.clients[0].email, None);
    assert!(!config.clients[0].xray_uuid_route);
    assert!(config.clients[0].xray_transport_auth_fallback);
    assert!(config.xray_compat);
    assert_eq!(config.bandwidth.max_tx, 0);
    assert_eq!(config.bandwidth.max_rx, 0);
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_supported_xray_masquerade() {
    let settings = || {
        SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{"auth": "xray-auth-token"}]
        }))
    };

    for kind in ["", "404"] {
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "masquerade": {"type": kind}
            }))
            .expect("valid Xray masquerade shape");
        let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect("Xray default 404 masquerade should be accepted");
        assert!(config.xray_masquerade_string.is_none());
        assert!(config.xray_masquerade_file.is_none());
    }

    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "masquerade": {
                "type": "FILE",
                "dir": "/srv/hysteria-site"
            }
        }))
        .expect("valid Xray file masquerade shape");
    let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
        .expect("Xray file masquerade should be accepted case-insensitively");
    assert_eq!(
        config
            .xray_masquerade_file
            .expect("file masquerade should reach runtime config")
            .dir,
        "/srv/hysteria-site"
    );

    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "masquerade": {
                "type": "string",
                "content": "hello",
                "headers": {"X-Test": "yes"},
                "statusCode": 201
            }
        }))
        .expect("valid Xray string masquerade shape");
    let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
        .expect("Xray string masquerade should be accepted");
    let masquerade = config
        .xray_masquerade_string
        .expect("string masquerade should reach runtime config");
    assert_eq!(masquerade.content, "hello");
    assert_eq!(
        masquerade.headers.get("X-Test").map(String::as_str),
        Some("yes")
    );
    assert_eq!(masquerade.status_code, 201);

    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "masquerade": {
                "type": "PrOxY",
                "url": "https://example.test/base",
                "rewriteHost": true,
                "insecure": true
            }
        }))
        .expect("valid Xray proxy masquerade shape");
    let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
        .expect("Xray proxy masquerade should be accepted case-insensitively");
    let masquerade = config
        .xray_masquerade_proxy
        .expect("proxy masquerade should reach runtime config");
    assert_eq!(masquerade.url, "https://example.test/base");
    assert!(masquerade.rewrite_host);
    assert!(masquerade.insecure);

    let kind = "unknown";
    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "masquerade": {"type": kind}
        }))
        .expect("valid Xray masquerade shape");
    let err = collect_hysteria2_settings(settings(), Some(&stream_settings))
        .expect_err("unsupported Xray masquerade must fail explicitly");
    assert!(
        err.to_string()
            .contains("supports Xray 404, file, proxy, and string masquerades"),
        "unexpected masquerade error for {kind}: {err}"
    );
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_keeps_shoes_id_exact() {
    let settings = SettingObject(serde_json::json!({
        "clients": [{"id": "00112233-4455-6677-8899-aabbccddeeff"}]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("shoes-style Hysteria id should be accepted");
    assert_eq!(
        config.clients[0].password,
        "00112233-4455-6677-8899-aabbccddeeff"
    );
    assert!(!config.clients[0].xray_uuid_route);
    assert!(!config.clients[0].xray_transport_auth_fallback);
    assert!(!config.xray_compat);
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_matches_shoes_udp_switch_and_xray_udp_default() {
    let shoes = SettingObject(serde_json::json!({
        "clients": [{"id": "secret"}],
        "udp_enabled": false
    }));
    let shoes_config = collect_hysteria2_settings(shoes, None)
        .expect("shoes-style Hysteria UDP switch should parse");
    assert!(!shoes_config.xray_compat);
    assert!(!shoes_config.udp_enabled);

    let xray = SettingObject(serde_json::json!({
        "version": 2,
        "clients": [{"auth": "secret"}],
        "udpEnabled": false
    }));
    let xray_transport = serde_json::from_value::<HysteriaSettings>(
        serde_json::json!({"version": 2}),
    )
    .expect("valid Xray Hysteria transport");
    let xray_config = collect_hysteria2_settings(xray, Some(&xray_transport))
        .expect("Xray Hysteria config should parse");
    assert!(xray_config.xray_compat);
    assert!(xray_config.udp_enabled);
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_users_override_transport_auth_fallback() {
    let settings = SettingObject(serde_json::json!({
        "clients": [{"auth": "user-auth-token"}]
    }));
    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "auth": "transport-auth-token"
        }))
        .expect("valid hysteriaSettings auth");

    let config = collect_hysteria2_settings(settings, Some(&stream_settings))
        .expect("configured users should take precedence over transport auth");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "user-auth-token");
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_keeps_xray_transport_auth_latent_with_users() {
    let settings = SettingObject(serde_json::json!({
        "version": 2,
        "clients": [{
            "auth": "user-auth-token",
            "email": "user@example.com"
        }]
    }));
    let stream_settings =
        serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "auth": "transport-auth-token"
        }))
        .expect("valid Xray hysteriaSettings auth");

    let config = collect_hysteria2_settings(settings, Some(&stream_settings))
        .expect("valid Xray users plus transport auth should parse");
    assert!(config.xray_compat);
    assert_eq!(config.clients.len(), 2);
    assert_eq!(config.clients[0].password, "user-auth-token");
    assert!(!config.clients[0].xray_transport_auth_fallback);
    assert_eq!(config.clients[1].password, "transport-auth-token");
    assert!(config.clients[1].xray_transport_auth_fallback);
    assert_eq!(
        config
            .clients
            .iter()
            .filter(|client| client.email.is_some())
            .count(),
        1,
        "transport fallback must stay hidden from Xray user-manager listings"
    );
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_preserves_xray_auth_whitespace() {
    let settings = SettingObject(serde_json::json!({
        "clients": [{"auth": " spaced-secret "}]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("Xray Hysteria auth should be preserved exactly");
    assert_eq!(config.clients[0].password, " spaced-secret ");
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_xray_users_alias() {
    let settings = SettingObject(serde_json::json!({
        "users": [{
            "auth": "legacy-xray-auth",
            "email": "legacy@example.com"
        }]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("Xray users alias should be accepted");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "legacy-xray-auth");
    assert_eq!(
        config.clients[0].email.as_deref(),
        Some("legacy@example.com")
    );
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_clients_override_xray_users() {
    let settings = SettingObject(serde_json::json!({
        "users": [{"auth": "legacy-xray-auth"}],
        "clients": [{"auth": "current-xray-auth"}]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("Xray clients should replace users when present");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "current-xray-auth");
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_accepts_xray_settings_version() {
    let settings = SettingObject(serde_json::json!({
        "version": 2,
        "clients": [{
            "auth": "xray-auth-token",
            "email": "hy@example.com"
        }]
    }));

    let config = collect_hysteria2_settings(settings, None)
        .expect("hysteria settings.version should be accepted");
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].password, "xray-auth-token");
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_rejects_non_v2_settings_version() {
    let settings = SettingObject(serde_json::json!({
        "version": 1,
        "clients": [{
            "auth": "xray-auth-token"
        }]
    }));

    let err = collect_hysteria2_settings(settings, None)
        .expect_err("hysteria settings.version other than 2 should fail");
    assert!(
        err.to_string()
            .contains("hysteria settings.version must be 2")
    );
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_rejects_conflicting_versions() {
    let settings = SettingObject(serde_json::json!({
        "version": 2,
        "clients": [{
            "auth": "xray-auth-token"
        }]
    }));
    let stream_settings = HysteriaSettings {
        version: Some(3),
        auth: String::new(),
        congestion: None,
        up: None,
        down: None,
        ignore_client_bandwidth: None,
        udp_idle_timeout: 0,
        masquerade: None,
    };

    let err = collect_hysteria2_settings(settings, Some(&stream_settings))
        .expect_err("conflicting versions should fail");
    assert!(
        err.to_string()
            .contains("hysteriaSettings.version must be 2")
    );
}

#[cfg(feature = "hysteria")]
#[test]
fn collect_hysteria2_settings_matches_xray_udp_idle_timeout() {
    let settings = || {
        SettingObject(serde_json::json!({
            "clients": [{"auth": "xray-auth-token"}]
        }))
    };

    for (configured, expected) in [(0, 60), (2, 2), (600, 600)] {
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "udpIdleTimeout": configured
            }))
            .expect("valid hysteriaSettings");
        let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect("Xray UDP idle timeout should be accepted");
        assert_eq!(config.xray_udp_idle_timeout_secs, Some(expected));
    }

    for configured in [1, 601] {
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "udpIdleTimeout": configured
            }))
            .expect("hysteriaSettings should deserialize");
        let error = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect_err("Xray rejects out-of-range UDP idle timeout");
        assert!(error.to_string().contains("udpIdleTimeout"), "{error}");
    }
}
