use prost::Message;

use crate::{
    config::rule::{NetworkListConfig, PortListConfig, PortRangeConfig},
    geodata::{GeodataStore, proto as geodata_proto},
};

use super::*;

fn outbound(tag: &str) -> OutboundSummary {
    OutboundSummary {
        tag: tag.to_string(),
        protocol: "freedom".to_string(),
        proxy_settings_type: None,
        proxy_settings_value: None,
        sender_settings_type: None,
        sender_settings_value: None,
    }
}

fn test_geodata() -> GeodataStore {
    let mut store = GeodataStore::default();
    store
        .load_geoip_bytes(
            &geodata_proto::GeoIpList {
                entry: vec![
                    geodata_proto::GeoIp {
                        code: "TEST".into(),
                        cidr: vec![geodata_proto::Cidr {
                            ip: vec![203, 0, 113, 0],
                            prefix: 24,
                        }],
                        reverse_match: false,
                    },
                    geodata_proto::GeoIp {
                        code: "EMPTY".into(),
                        cidr: vec![],
                        reverse_match: false,
                    },
                ],
            }
            .encode_to_vec(),
        )
        .expect("load routing geoip fixture");
    store
            .load_geosite_bytes(
                &geodata_proto::GeoSiteList {
                    entry: vec![
                        geodata_proto::GeoSite {
                            code: "TEST".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "example.com".into(),
                                    attribute: vec![geodata_proto::domain::Attribute {
                                        key: "ads".into(),
                                        typed_value: Some(
                                            geodata_proto::domain::attribute::TypedValue::BoolValue(
                                                true,
                                            ),
                                        ),
                                    }],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Full as i32,
                                    value: "only.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: r"^api[0-9]+\.example$".into(),
                                    attribute: vec![geodata_proto::domain::Attribute {
                                        key: "ads".into(),
                                        typed_value: None,
                                    }],
                                },
                            ],
                        },
                        geodata_proto::GeoSite {
                            code: "MIXED".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Full as i32,
                                    value: "valid.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: 99,
                                    value: "unknown.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "bad_name.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: "(".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Substr as i32,
                                    value: String::new(),
                                    attribute: vec![],
                                },
                            ],
                        },
                        geodata_proto::GeoSite {
                            code: "ALL_INVALID".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: 99,
                                    value: "unknown.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "bad_name.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: "(".into(),
                                    attribute: vec![],
                                },
                            ],
                        },
                    ],
                }
                .encode_to_vec(),
            )
            .expect("load routing geosite fixture");
    store
}

#[test]
fn routing_state_matches_inbound_and_domain_rules() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                inbound_tag: vec!["api-in".into()],
                outbound_tag: Some("api".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                domain: vec!["domain:example.com".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            },
        ],
        vec![],
    )
    .expect("routing state should build");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "api-in".into(),
                ..RoutingInput::default()
            },
            &[outbound("api"), outbound("direct")],
            &HashMap::new(),
        )
        .expect("api rule should match");
    assert_eq!(matched.outbound_tag, "api");

    let matched = state
        .route(
            &RoutingInput {
                target_domain: "www.example.com".into(),
                ..RoutingInput::default()
            },
            &[outbound("api"), outbound("direct")],
            &HashMap::new(),
        )
        .expect("domain rule should match");
    assert_eq!(matched.outbound_tag, "direct");
}

#[test]
fn routing_state_supports_regexp_domain_rules() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec![r"regexp:^api[0-9]+\.example\.com$".into()],
            outbound_tag: Some("regexp".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("regexp routing rule should compile");

    let matched = state
        .route(
            &RoutingInput {
                target_domain: "API42.EXAMPLE.COM".into(),
                ..RoutingInput::default()
            },
            &[outbound("regexp")],
            &HashMap::new(),
        )
        .expect("regexp routing rule should match lowercased target domain");
    assert_eq!(matched.outbound_tag, "regexp");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "api.example.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("regexp")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn invalid_regexp_domain_rule_is_rejected_during_compile() {
    let error = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["regexp:(unterminated".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect_err("invalid regexp routing rule must be rejected");

    assert!(error.contains("invalid regexp routing rule"));
}

#[test]
fn non_regexp_domain_rules_are_ascii_case_insensitive() {
    for rule in [
        "keyword:EXAMPLE",
        "domain:EXAMPLE.COM",
        "full:WWW.EXAMPLE.COM",
    ] {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec![rule.into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("case-normalized routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "WWW.Example.Com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "rule {rule} should match case-insensitively"
        );
    }
}

#[test]
fn domain_rule_requires_label_boundary() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["domain:example.com".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("domain boundary routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "notexample.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "sub.example.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn regexp_pattern_remains_case_sensitive_after_domain_lowercasing() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec![r"regexp:^API\.example\.com$".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("case-sensitive regexp routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "API.EXAMPLE.COM".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

fn strategy_state(strategy: &str, rules: Vec<RuleConfig>) -> RoutingState {
    RoutingState::from_config(Some(&RoutingConfig {
        domain_strategy: Some(strategy.into()),
        rules,
        balancers: Vec::new(),
    }))
    .expect("domain strategy routing state should build")
}

fn domain_and_ip_rules() -> Vec<RuleConfig> {
    vec![
        RuleConfig {
            ip: vec!["203.0.113.7/32".into()],
            outbound_tag: Some("ip".into()),
            ..RuleConfig::default()
        },
        RuleConfig {
            domain: vec!["full:example.com".into()],
            outbound_tag: Some("domain".into()),
            ..RuleConfig::default()
        },
    ]
}

fn resolved_domain_input(domain: &str) -> RoutingInput {
    RoutingInput {
        target_domain: domain.into(),
        target_ips: vec![vec![203, 0, 113, 7]],
        ..RoutingInput::default()
    }
}

#[test]
fn as_is_ignores_resolved_ips_for_domain_targets() {
    let state = strategy_state("AsIs", domain_and_ip_rules());
    let outbounds = [outbound("ip"), outbound("domain")];

    let matched = state
        .route(
            &resolved_domain_input("example.com"),
            &outbounds,
            &HashMap::new(),
        )
        .expect("AsIs domain rule should match");
    assert_eq!(matched.outbound_tag, "domain");

    assert!(
        state
            .route(
                &resolved_domain_input("other.example"),
                &outbounds,
                &HashMap::new(),
            )
            .is_none(),
        "AsIs must not fall through to resolved target IP rules"
    );
}

#[test]
fn ip_if_non_match_retries_with_resolved_ips_only_after_domain_miss() {
    let state = strategy_state("IPIfNonMatch", domain_and_ip_rules());
    let outbounds = [outbound("ip"), outbound("domain")];

    let domain_match = state
        .route(
            &resolved_domain_input("example.com"),
            &outbounds,
            &HashMap::new(),
        )
        .expect("IPIfNonMatch domain rule should win first pass");
    assert_eq!(domain_match.outbound_tag, "domain");

    let ip_match = state
        .route(
            &resolved_domain_input("other.example"),
            &outbounds,
            &HashMap::new(),
        )
        .expect("IPIfNonMatch should retry target IP rules");
    assert_eq!(ip_match.outbound_tag, "ip");
}

#[test]
fn ip_on_demand_allows_ip_rule_in_first_pass() {
    let state = strategy_state("IPOnDemand", domain_and_ip_rules());
    let matched = state
        .route(
            &resolved_domain_input("example.com"),
            &[outbound("ip"), outbound("domain")],
            &HashMap::new(),
        )
        .expect("IPOnDemand target IP rule should match");

    assert_eq!(matched.outbound_tag, "ip");
}

#[test]
fn as_is_still_matches_ip_rules_for_literal_ip_targets() {
    let state = strategy_state("AsIs", domain_and_ip_rules());
    let matched = state
        .route(
            &RoutingInput {
                target_ips: vec![vec![203, 0, 113, 7]],
                ..RoutingInput::default()
            },
            &[outbound("ip"), outbound("domain")],
            &HashMap::new(),
        )
        .expect("literal IP target must remain eligible for IP rules");

    assert_eq!(matched.outbound_tag, "ip");
}

#[test]
fn unknown_domain_strategy_defaults_to_as_is() {
    let state = strategy_state("unknown-future-value", domain_and_ip_rules());

    assert!(
        state
            .route(
                &resolved_domain_input("other.example"),
                &[outbound("ip"), outbound("domain")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn failed_strategy_merge_preserves_previous_strategy() {
    let mut state = strategy_state("IPOnDemand", domain_and_ip_rules());
    let error = state
        .merge_with_domain_strategy(
            vec![RuleConfig {
                domain: vec!["regexp:(invalid".into()],
                outbound_tag: Some("domain".into()),
                ..RuleConfig::default()
            }],
            Vec::new(),
            false,
            Some(DomainStrategy::AsIs),
        )
        .expect_err("invalid strategy update must fail atomically");
    assert!(error.contains("invalid regexp routing rule"));

    let matched = state
        .route(
            &resolved_domain_input("example.com"),
            &[outbound("ip"), outbound("domain")],
            &HashMap::new(),
        )
        .expect("previous IPOnDemand strategy must survive failure");
    assert_eq!(matched.outbound_tag, "ip");
}

#[test]
fn process_condition_matches_xray_name_path_folder_and_self_forms() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                process: vec!["curl.exe".into()],
                outbound_tag: Some("name".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                process: vec!["/usr/bin/special".into()],
                outbound_tag: Some("path".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                process: vec!["/opt/apps/".into()],
                outbound_tag: Some("folder".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                process: vec!["self/".into()],
                outbound_tag: Some("self".into()),
                ..RuleConfig::default()
            },
        ],
        vec![],
    )
    .expect("process routing rules should compile");
    assert!(state.requires_process_lookup());
    let outbounds = [
        outbound("name"),
        outbound("path"),
        outbound("folder"),
        outbound("self"),
    ];

    let cases = [
        (
            RoutingInput {
                process_name: "curl".into(),
                ..RoutingInput::default()
            },
            "name",
        ),
        (
            RoutingInput {
                process_path: "/usr/bin/special".into(),
                ..RoutingInput::default()
            },
            "path",
        ),
        (
            RoutingInput {
                process_path: "/opt/apps/client".into(),
                ..RoutingInput::default()
            },
            "folder",
        ),
        (
            RoutingInput {
                process_id: std::process::id(),
                ..RoutingInput::default()
            },
            "self",
        ),
    ];
    for (input, expected) in cases {
        let matched = state
            .route(&input, &outbounds, &HashMap::new())
            .expect("process condition should match");
        assert_eq!(matched.outbound_tag, expected);
    }

    assert!(
        state
            .route(&RoutingInput::default(), &outbounds, &HashMap::new(),)
            .is_none(),
        "configured process rules must reject missing process metadata"
    );
}

#[test]
fn routing_without_process_rules_skips_process_lookup() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("routing state should compile");

    assert!(!state.requires_process_lookup());
}

#[test]
fn matched_rule_fires_webhook_with_headers_and_user_deduplication() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind routing webhook listener");
    listener
        .set_nonblocking(true)
        .expect("set webhook listener nonblocking");
    let address = listener.local_addr().expect("webhook listener address");
    let (request_tx, request_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .expect("set webhook read timeout");
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        let read = stream.read(&mut chunk).unwrap_or_default();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        let Some(header_end) = request
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .map(|index| index + 4)
                        else {
                            continue;
                        };
                        let headers =
                            String::from_utf8_lossy(&request[..header_end]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                line.split_once(':').and_then(|(name, value)| {
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                            })
                            .unwrap_or_default();
                        if request.len() >= header_end + content_length {
                            break;
                        }
                    }
                    let _ = stream.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    let _ = request_tx.send(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["webhook-in".into()],
            outbound_tag: Some("direct".into()),
            webhook: Some(crate::config::rule::WebhookRuleConfig {
                url: format!("http://{address}/route"),
                deduplication: 60,
                headers: HashMap::from([("X-Route-Key".into(), "secret".into())]),
            }),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("webhook routing rule should compile");
    let input = RoutingInput {
        inbound_tag: "webhook-in".into(),
        network: 2,
        source_ips: vec![vec![127, 0, 0, 1]],
        source_port: 12345,
        target_domain: "example.com".into(),
        target_port: 443,
        protocol: "tls".into(),
        user: "alice@example.com".into(),
        ..RoutingInput::default()
    };
    let outbounds = [outbound("direct")];

    for _ in 0..2 {
        let matched = state
            .route(&input, &outbounds, &HashMap::new())
            .expect("webhook rule should match");
        assert_eq!(matched.outbound_tag, "direct");
    }

    let request = request_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("webhook request missing");
    let request_text = String::from_utf8_lossy(&request);
    assert!(request_text.starts_with("POST /route HTTP/1.1"));
    assert!(
        request_text
            .to_ascii_lowercase()
            .contains("x-route-key: secret")
    );
    let body_offset = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("webhook header terminator")
        + 4;
    let body: serde_json::Value = serde_json::from_slice(&request[body_offset..])
        .expect("decode webhook body");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["inboundTag"], "webhook-in");
    assert_eq!(body["outboundTag"], "direct");
    assert_eq!(body["destination"], "example.com:443");
    assert!(
        request_rx
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "duplicate user webhook should be suppressed"
    );
    server.join().expect("webhook server thread");
}

#[test]
fn invalid_webhook_url_is_rejected_during_rule_compile() {
    let error = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["webhook-in".into()],
            outbound_tag: Some("direct".into()),
            webhook: Some(crate::config::rule::WebhookRuleConfig {
                url: "unix:///tmp/router.sock".into(),
                ..Default::default()
            }),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect_err("unsupported webhook scheme must fail at compile time");

    assert!(error.contains("webhook URL scheme unix is not supported"));
}

#[test]
fn user_condition_supports_exact_and_regexp_values() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            user: vec![
                "exact@example.com".into(),
                r"regexp:^team-[0-9]+@example\.com$".into(),
            ],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("user routing rule should compile");
    let outbounds = [outbound("direct")];

    for user in ["exact@example.com", "team-42@example.com"] {
        assert!(
            state
                .route(
                    &RoutingInput {
                        user: user.into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            "user {user} should match"
        );
    }
    assert!(
        state
            .route(
                &RoutingInput {
                    user: "other@example.com".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn user_regexp_is_case_sensitive() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            user: vec![r"regexp:^Admin@Example\.Com$".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("case-sensitive user regexp should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    user: "Admin@Example.Com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
    assert!(
        state
            .route(
                &RoutingInput {
                    user: "admin@example.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn invalid_user_regexp_is_ignored_instead_of_rejecting_rule() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            user: vec!["regexp:(invalid".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("invalid user regexp should be ignored like xray-core");

    assert!(
        state
            .route(
                &RoutingInput {
                    user: "anything".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none(),
        "rule with only invalid user regexp must never match"
    );
}

#[test]
fn configured_user_condition_rejects_empty_user() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            user: vec!["exact@example.com".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("user routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput::default(),
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn internationalized_domain_rule_is_normalized_to_punycode() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["domain:bücher.example".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("internationalized domain routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "shop.xn--bcher-kva.example".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn non_regexp_domain_rule_rejects_non_ldh_characters_transactionally() {
    let mut state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![RuleConfig {
                domain: vec!["domain:_service.example".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect_err("non-LDH domain rule must be rejected");
    assert!(error.contains("does not conform to LDH subset"));

    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn regexp_domain_rule_may_use_non_ldh_characters() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec![r"regexp:^_service\.example$".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("regexp domain rule should not use LDH validation");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "_service.example".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn dotless_domain_rule_matches_only_single_label_domains() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["dotless:".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("dotless routing rule should compile");
    let outbounds = [outbound("direct")];

    for (domain, expected) in [
        ("localhost", true),
        ("printer-01", true),
        ("example.com", false),
    ] {
        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_domain: domain.into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            expected,
            "domain {domain}"
        );
    }
}

#[test]
fn dotless_substring_rule_and_invalid_dot_follow_xray_semantics() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["dotless:print".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("dotless substring routing rule should compile");
    let outbounds = [outbound("direct")];

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "office-printer".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_some()
    );
    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "print.example".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_none()
    );

    let error = RoutingState::from_parts(
        vec![RuleConfig {
            domain: vec!["dotless:bad.value".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect_err("dotless substring containing a dot must fail");
    assert!(error.contains("should not contain a dot"));
}

#[test]
fn protocol_condition_uses_xray_prefix_matching() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            protocol: vec!["tls".into(), "http".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("protocol routing rule should compile");
    let outbounds = [outbound("direct")];

    for protocol in ["tls", "tls.http/1.1", "http2"] {
        assert!(
            state
                .route(
                    &RoutingInput {
                        protocol: protocol.into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            "protocol {protocol} should match by prefix"
        );
    }
    assert!(
        state
            .route(
                &RoutingInput {
                    protocol: "quic".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn configured_protocol_condition_rejects_empty_protocol() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            protocol: vec!["tls".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("protocol routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput::default(),
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn attribute_condition_uses_case_insensitive_keys_and_regexp_values() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            attrs: HashMap::from([
                ("Host".into(), r"^api[0-9]+\.example\.com$".into()),
                ("User-Agent".into(), r"^chimera/".into()),
            ]),
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("attribute routing rule should compile");

    let matched = state.route(
        &RoutingInput {
            attributes: HashMap::from([
                ("HOST".into(), "api42.example.com".into()),
                ("user-agent".into(), "chimera/1.0".into()),
            ]),
            ..RoutingInput::default()
        },
        &[outbound("direct")],
        &HashMap::new(),
    );
    assert!(matched.is_some());

    assert!(
        state
            .route(
                &RoutingInput {
                    attributes: HashMap::from([
                        ("host".into(), "api42.example.com".into()),
                        ("user-agent".into(), "other/1.0".into()),
                    ]),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none(),
        "all configured attribute regexps must match"
    );
}

#[test]
fn configured_attribute_condition_rejects_missing_attributes() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            attrs: HashMap::from([("host".into(), ".+".into())]),
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("attribute routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput::default(),
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn invalid_attribute_regexp_rejects_rule_transactionally() {
    let mut state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![RuleConfig {
                attrs: HashMap::from([("host".into(), "(invalid".into())]),
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect_err("invalid attribute regexp must reject rule");
    assert!(error.contains("invalid routing attribute regexp"));

    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some(),
        "failed attribute update must preserve existing state"
    );
}

#[test]
fn multiple_geoip_reverse_prefixes_follow_xray_xor_semantics() {
    let outbounds = [outbound("direct")];
    for (rule, inside, outside) in [
        ("!!geoip:TEST", true, false),
        ("!geoip:!TEST", true, false),
        ("!!!geoip:TEST", false, true),
    ] {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                ip: vec![rule.into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("multi-reverse geoip routing rule should compile");

        for (ip, expected) in [
            (vec![203, 0, 113, 42], inside),
            (vec![192, 0, 2, 42], outside),
        ] {
            assert_eq!(
                state
                    .route(
                        &RoutingInput {
                            target_ips: vec![ip],
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                expected,
                "rule {rule}"
            );
        }
    }
}

#[test]
fn default_ext_aliases_expand_preloaded_geodata() {
    let geoip = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            ip: vec!["ext:geoip.dat:TEST".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("default ext geoip alias should compile");
    assert!(
        geoip
            .route(
                &RoutingInput {
                    target_ips: vec![vec![203, 0, 113, 42]],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );

    for rule in [
        "ext:geosite.dat:TEST@ads",
        "ext-domain:geosite.dat:TEST@ads",
        "ext-site:geosite.dat:TEST@ads",
    ] {
        let geosite = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                domain: vec![rule.into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("default ext geosite alias should compile");
        assert!(
            geosite
                .route(
                    &RoutingInput {
                        target_domain: "sub.example.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "rule {rule}"
        );
    }
}

#[test]
fn external_geodata_syntax_and_path_errors_are_transactional() {
    let invalid_rules = [
        "ext:missing-separator",
        "ext::TEST",
        "ext:../custom.dat:TEST",
        "ext:/tmp/custom.dat:TEST",
    ];
    for rule in invalid_rules {
        let mut state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("existing routing state should build");

        state
            .merge(
                vec![RuleConfig {
                    ip: vec![rule.into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("invalid external geoip rule must fail");
        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "rule {rule} must not mutate previous state"
        );
    }
}

#[test]
fn geosite_empty_attribute_syntax_is_rejected_transactionally() {
    for rule in ["geosite:TEST@", "geosite:TEST@@ads"] {
        let mut state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    domain: vec![rule.into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("empty geosite attr must fail");
        assert!(error.contains("empty attr"));
        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }
}

#[test]
fn geoip_reference_expands_into_cidr_matchers() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            ip: vec!["geoip:test".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("geoip routing rule should compile");
    let outbounds = [outbound("direct")];

    for (ip, expected) in
        [(vec![203, 0, 113, 42], true), (vec![192, 0, 2, 42], false)]
    {
        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![ip],
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            expected
        );
    }
}

#[test]
fn reversed_geoip_reference_excludes_the_named_set() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            ip: vec!["geoip:!TEST".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("reverse geoip routing rule should compile");
    let outbounds = [outbound("direct")];

    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![203, 0, 113, 42]],
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_none()
    );
    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![192, 0, 2, 42]],
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn geosite_reference_expands_domain_types_and_attribute_filters() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            domain: vec!["geosite:test@ads".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("geosite routing rule should compile");
    let outbounds = [outbound("direct")];

    for (domain, expected) in [
        ("sub.example.com", true),
        ("api42.example", true),
        ("only.example", false),
        ("other.example", false),
    ] {
        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_domain: domain.into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            expected,
            "domain {domain}"
        );
    }
}

#[test]
fn malformed_geosite_entries_are_ignored_individually() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            domain: vec!["geosite:mixed".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("mixed geosite routing rule should compile");
    let outbounds = [outbound("direct")];

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "valid.example".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .is_some()
    );
    for domain in ["unknown.example", "bad_name.example", "other.example"] {
        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: domain.into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none(),
            "invalid geosite item must not match {domain}"
        );
    }
}

#[test]
fn all_invalid_geosite_entry_remains_a_non_matching_condition() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            domain: vec!["geosite:all_invalid".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("all-invalid geosite routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "anything.example".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn empty_geoip_entry_remains_a_non_matching_condition() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            ip: vec!["geoip:empty".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("empty geoip routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![203, 0, 113, 42]],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none(),
        "an empty geoip set must not remove the IP condition"
    );
}

#[test]
fn empty_geosite_attribute_filter_remains_a_non_matching_condition() {
    let state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            domain: vec!["geosite:test@missing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("empty geosite filter should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_domain: "example.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none(),
        "an empty geosite filter must not remove the domain condition"
    );
}

#[test]
fn missing_geodata_code_rejects_update_transactionally() {
    let mut state = RoutingState::from_parts_with_geodata(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
        test_geodata(),
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![RuleConfig {
                domain: vec!["geosite:missing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect_err("missing geosite code must reject update");
    assert!(error.contains("xray geosite entry not found: MISSING"));
    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some(),
        "failed geodata update must preserve previous routing state"
    );
}

#[test]
fn cidr_conditions_match_source_target_and_local_addresses() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            source_ip: vec!["10.0.0.0/8".into()],
            ip: vec!["203.0.113.0/24".into()],
            local_ip: vec!["192.0.2.10/32".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("CIDR routing rule should compile");
    let input = RoutingInput {
        source_ips: vec![vec![198, 51, 100, 1], vec![10, 9, 8, 7]],
        target_ips: vec![vec![203, 0, 113, 42]],
        local_ips: vec![vec![192, 0, 2, 10]],
        ..RoutingInput::default()
    };

    assert!(
        state
            .route(&input, &[outbound("direct")], &HashMap::new())
            .is_some(),
        "each CIDR category should accept any matching candidate"
    );

    let mut wrong_local = input;
    wrong_local.local_ips = vec![vec![192, 0, 2, 11]];
    assert!(
        state
            .route(&wrong_local, &[outbound("direct")], &HashMap::new(),)
            .is_none(),
        "source, target, and local CIDR categories are combined with AND"
    );
}

#[test]
fn ipv6_cidr_matches_prefix_boundary() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["2001:db8:abcd:12::/64".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("IPv6 CIDR routing rule should compile");

    let matching: std::net::Ipv6Addr =
        "2001:db8:abcd:12::99".parse().expect("matching IPv6");
    let outside: std::net::Ipv6Addr =
        "2001:db8:abcd:13::1".parse().expect("outside IPv6");
    for (address, expected) in [(matching, true), (outside, false)] {
        let matched = state.route(
            &RoutingInput {
                target_ips: vec![address.octets().to_vec()],
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        );
        assert_eq!(matched.is_some(), expected, "address {address}");
    }
}

#[test]
fn malformed_ip_candidates_do_not_match_cidr_rules() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["0.0.0.0/0".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("catch-all CIDR routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![], vec![127, 0, 0]],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none()
    );
}

#[test]
fn reverse_cidr_matches_addresses_outside_the_excluded_set() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["!8.8.8.8/32".into(), "!91.108.0.0/16".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("reverse CIDR routing rule should compile");
    let outbounds = [outbound("direct")];

    for (ip, expected) in [
        (vec![8, 8, 8, 8], false),
        (vec![91, 108, 4, 1], false),
        (vec![1, 1, 1, 1], true),
    ] {
        let matched = state.route(
            &RoutingInput {
                target_ips: vec![ip],
                ..RoutingInput::default()
            },
            &outbounds,
            &HashMap::new(),
        );
        assert_eq!(matched.is_some(), expected);
    }
}

#[test]
fn reverse_cidr_only_applies_to_configured_address_family() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["!8.8.8.8/32".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("IPv4 reverse CIDR routing rule should compile");
    let ipv6: std::net::Ipv6Addr = "2001:db8::1".parse().expect("test IPv6 address");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![ipv6.octets().to_vec()],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_none(),
        "IPv4-only reverse set must not match IPv6"
    );
}

#[test]
fn positive_and_reverse_cidr_groups_are_combined_with_or() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["203.0.113.0/24".into(), "!10.0.0.0/8".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("mixed CIDR routing rule should compile");
    let outbounds = [outbound("direct")];

    for (ip, expected) in [
        (vec![203, 0, 113, 9], true),
        (vec![192, 0, 2, 9], true),
        (vec![10, 1, 2, 3], false),
    ] {
        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![ip],
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some(),
            expected
        );
    }
}

#[test]
fn reverse_cidr_uses_any_match_across_resolved_addresses() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            ip: vec!["!10.0.0.0/8".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("reverse CIDR routing rule should compile");

    assert!(
        state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![10, 1, 2, 3], vec![192, 0, 2, 9]],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some(),
        "one allowed resolved address should satisfy AnyMatch"
    );
}

#[test]
fn invalid_cidr_update_is_rejected_transactionally() {
    let mut state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![RuleConfig {
                ip: vec!["192.0.2.0/33".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect_err("invalid CIDR prefix must reject update");
    assert!(error.contains("prefix 33 exceeds 32"));
    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .is_some()
    );
}

#[test]
fn port_conditions_use_closed_intervals_and_reject_unknown_zero() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            source_port: PortListConfig(vec![PortRangeConfig {
                from: 1000,
                to: 2000,
            }]),
            port: PortListConfig(vec![PortRangeConfig { from: 443, to: 443 }]),
            local_port: PortListConfig(vec![PortRangeConfig {
                from: 1080,
                to: 1081,
            }]),
            vless_route: PortListConfig(vec![PortRangeConfig { from: 7, to: 9 }]),
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("port routing rule should compile");
    let outbounds = [outbound("direct")];

    for source_port in [1000, 2000] {
        for local_port in [1080, 1081] {
            for vless_route in [7, 9] {
                assert!(
                    state
                        .route(
                            &RoutingInput {
                                source_port,
                                target_port: 443,
                                local_port,
                                vless_route,
                                ..RoutingInput::default()
                            },
                            &outbounds,
                            &HashMap::new(),
                        )
                        .is_some()
                );
            }
        }
    }
    for input in [
        RoutingInput {
            source_port: 0,
            target_port: 443,
            local_port: 1080,
            vless_route: 7,
            ..RoutingInput::default()
        },
        RoutingInput {
            source_port: 1000,
            target_port: 444,
            local_port: 1080,
            vless_route: 7,
            ..RoutingInput::default()
        },
    ] {
        assert!(state.route(&input, &outbounds, &HashMap::new()).is_none());
    }
}

#[test]
fn port_conditions_match_zero_and_wrap_test_route_values() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                port: PortListConfig(vec![PortRangeConfig { from: 0, to: 0 }]),
                outbound_tag: Some("zero".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                port: PortListConfig(vec![PortRangeConfig { from: 1, to: 1 }]),
                outbound_tag: Some("one".into()),
                ..RuleConfig::default()
            },
        ],
        vec![],
    )
    .expect("zero-port routing rules should compile");
    let outbounds = [outbound("zero"), outbound("one")];

    assert_eq!(
        state
            .route(
                &RoutingInput {
                    target_port: 65_536,
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .expect("65536 should wrap to port zero")
            .outbound_tag,
        "zero"
    );
    assert_eq!(
        state
            .route(
                &RoutingInput {
                    target_port: 65_537,
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .expect("65537 should wrap to port one")
            .outbound_tag,
        "one"
    );
}

#[test]
fn network_condition_matches_xray_network_enum_values() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            network: NetworkListConfig(vec!["TCP".into(), "udp".into()]),
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("network routing rule should compile");
    let outbounds = [outbound("direct")];

    for network in [2, 3] {
        assert!(
            state
                .route(
                    &RoutingInput {
                        network,
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some()
        );
    }
    for network in [0, 1, 4, 99] {
        assert!(
            state
                .route(
                    &RoutingInput {
                        network,
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none()
        );
    }
}

#[test]
fn xray_alias_fields_override_legacy_routing_fields() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                domain: vec!["regexp:(ignored-invalid".into()],
                domains: vec!["full:new.example".into()],
                outbound_tag: Some("domain".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                source: vec!["invalid-ignored-source".into()],
                source_ip: vec!["192.0.2.7".into()],
                outbound_tag: Some("source".into()),
                ..RuleConfig::default()
            },
        ],
        vec![],
    )
    .expect("Xray alias precedence should ignore shadowed values");
    let outbounds = [outbound("domain"), outbound("source")];

    let domain_match = state
        .route(
            &RoutingInput {
                target_domain: "new.example".into(),
                ..RoutingInput::default()
            },
            &outbounds,
            &HashMap::new(),
        )
        .expect("domains should override domain");
    assert_eq!(domain_match.outbound_tag, "domain");

    let source_match = state
        .route(
            &RoutingInput {
                source_ips: vec![vec![192, 0, 2, 7]],
                ..RoutingInput::default()
            },
            &outbounds,
            &HashMap::new(),
        )
        .expect("sourceIP should override source");
    assert_eq!(source_match.outbound_tag, "source");
}

#[test]
fn routing_rule_without_effective_fields_is_rejected() {
    let error = RoutingState::from_parts(
        vec![RuleConfig {
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect_err("unconditional Xray field rules must be rejected");

    assert_eq!(error, "routing rule has no effective fields");
}

#[test]
fn routing_balancer_requires_an_outbound_selector() {
    let error = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("empty".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "empty".into(),
            outbound_selector: vec!["".into(), "   ".into()],
            strategy: Default::default(),
            fallback_tag: Some("direct".into()),
        }],
    )
    .expect_err("Xray balancers require at least one selector");

    assert_eq!(
        error,
        "routing balancer empty requires at least one outbound selector"
    );
}

#[test]
fn matched_rule_with_missing_outbound_does_not_fall_through() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("missing".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            },
        ],
        vec![],
    )
    .expect("missing outbound routing state should compile");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        )
        .expect("first matched rule should be returned");
    assert_eq!(matched.outbound_tag, "missing");
}

#[test]
fn failed_replace_merge_preserves_existing_routes() {
    let mut state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![RuleConfig {
                domain: vec!["regexp:(invalid".into()],
                outbound_tag: Some("blocked".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect_err("invalid replacement must fail atomically");
    assert!(error.contains("invalid regexp routing rule"));

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "existing".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct"), outbound("blocked")],
            &HashMap::new(),
        )
        .expect("existing route must survive failed replacement");
    assert_eq!(matched.outbound_tag, "direct");
}

#[test]
fn failed_append_merge_does_not_keep_partial_rules_or_balancers() {
    let mut state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["existing".into()],
            outbound_tag: Some("direct".into()),
            rule_tag: Some("existing-rule".into()),
            ..RuleConfig::default()
        }],
        vec![],
    )
    .expect("existing routing state should build");

    let error = state
        .merge(
            vec![
                RuleConfig {
                    inbound_tag: vec!["partial".into()],
                    outbound_tag: Some("blocked".into()),
                    rule_tag: Some("partial-rule".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    inbound_tag: vec!["duplicate".into()],
                    outbound_tag: Some("blocked".into()),
                    rule_tag: Some("existing-rule".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![BalancerConfig {
                tag: "partial-balancer".into(),
                outbound_selector: vec!["blocked".into()],
                strategy: Default::default(),
                fallback_tag: None,
            }],
            true,
        )
        .expect_err("invalid append must fail atomically");
    assert!(error.contains("duplicate routing ruleTag"));

    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "partial".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("blocked")],
                &HashMap::new(),
            )
            .is_none(),
        "partial rule must not survive failed append"
    );
    assert!(
        state
            .balancer_targets("partial-balancer", &[outbound("blocked")])
            .is_empty(),
        "partial balancer must not survive failed append"
    );
    assert!(
        state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("blocked")],
                &HashMap::new(),
            )
            .is_some(),
        "existing rule must survive failed append"
    );
}

#[test]
fn empty_balancer_does_not_fall_through_to_later_rule() {
    let state = RoutingState::from_parts(
        vec![
            RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("empty".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            },
        ],
        vec![BalancerConfig {
            tag: "empty".into(),
            outbound_selector: vec!["missing-prefix".into()],
            strategy: Default::default(),
            fallback_tag: None,
        }],
    )
    .expect("empty balancer routing state should compile");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        )
        .expect("matched empty balancer should return an error route");

    assert_eq!(matched.outbound_tag, "");
    assert_eq!(matched.outbound_group_tags, vec!["empty"]);
    assert_eq!(
        matched.resolution_error.as_deref(),
        Some("routing balancer empty has no available outbound")
    );
}

#[test]
fn balancer_fallback_is_used_when_selectors_match_nothing() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("auto".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "auto".into(),
            outbound_selector: vec!["missing-prefix".into()],
            strategy: Default::default(),
            fallback_tag: Some("direct".into()),
        }],
    )
    .expect("fallback balancer routing state should compile");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        )
        .expect("fallback balancer should resolve");

    assert_eq!(matched.outbound_tag, "direct");
    assert_eq!(matched.outbound_group_tags, vec!["auto"]);
    assert_eq!(matched.resolution_error, None);
}

#[test]
fn round_robin_balancer_rotates_in_candidate_order() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("round".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "round".into(),
            outbound_selector: vec!["direct".into(), "backup".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "roundRobin".into(),
                settings: None,
            },
            fallback_tag: None,
        }],
    )
    .expect("round-robin routing state should build");
    let input = RoutingInput {
        inbound_tag: "test".into(),
        ..RoutingInput::default()
    };
    let outbounds = [outbound("direct"), outbound("backup")];

    let selected = (0..5)
        .map(|_| {
            state
                .route(&input, &outbounds, &HashMap::new())
                .expect("round-robin route should match")
                .outbound_tag
        })
        .collect::<Vec<_>>();

    assert_eq!(
        selected,
        vec!["backup", "direct", "backup", "direct", "backup"]
    );
}

#[test]
fn random_and_round_robin_fallback_filter_observed_dead_candidates() {
    for strategy in ["random", "roundRobin"] {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("auto".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "auto".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: strategy.into(),
                    settings: None,
                },
                fallback_tag: Some("fallback".into()),
            }],
        )
        .expect("fallback-aware balancer should build");
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: false,
                ..OutboundObservation::default()
            },
        );
        let input = RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        };
        let outbounds =
            [outbound("direct"), outbound("backup"), outbound("fallback")];

        for _ in 0..4 {
            let selected = state
                .route(&input, &outbounds, &HashMap::new())
                .expect("unobserved candidate should remain available");
            assert_eq!(selected.outbound_tag, "backup");
        }

        state.record_observation(
            "backup",
            OutboundObservation {
                alive: false,
                ..OutboundObservation::default()
            },
        );
        let fallback = state
            .route(&input, &outbounds, &HashMap::new())
            .expect("all dead candidates should use fallback");
        assert_eq!(fallback.outbound_tag, "fallback");
        assert_eq!(
            state.balancer_principle_targets("auto", &outbounds),
            vec!["backup", "direct"],
            "principle targets should remain selector candidates"
        );
    }
}

#[test]
fn random_without_fallback_does_not_filter_dead_candidates() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("random".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "random".into(),
            outbound_selector: vec!["direct".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "random".into(),
                settings: None,
            },
            fallback_tag: None,
        }],
    )
    .expect("random balancer should build");
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: false,
            ..OutboundObservation::default()
        },
    );

    let selected = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        )
        .expect("random without fallback should ignore observation state");
    assert_eq!(selected.outbound_tag, "direct");
}

#[test]
fn least_ping_balancer_selects_lowest_alive_observation() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("latency".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "latency".into(),
            outbound_selector: vec!["direct".into(), "backup".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "leastPing".into(),
                settings: None,
            },
            fallback_tag: Some("fallback".into()),
        }],
    )
    .expect("leastPing routing state should build");
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: true,
            delay_ms: 80,
            ..OutboundObservation::default()
        },
    );
    state.record_observation(
        "backup",
        OutboundObservation {
            alive: true,
            delay_ms: 15,
            ..OutboundObservation::default()
        },
    );
    let input = RoutingInput {
        inbound_tag: "test".into(),
        ..RoutingInput::default()
    };
    let outbounds = [outbound("direct"), outbound("backup"), outbound("fallback")];

    let selected = state
        .route(&input, &outbounds, &HashMap::new())
        .expect("leastPing route should resolve");
    assert_eq!(selected.outbound_tag, "backup");

    state.record_observation(
        "direct",
        OutboundObservation {
            alive: false,
            delay_ms: 1,
            ..OutboundObservation::default()
        },
    );
    state.record_observation(
        "backup",
        OutboundObservation {
            alive: false,
            delay_ms: 1,
            ..OutboundObservation::default()
        },
    );
    let fallback = state
        .route(&input, &outbounds, &HashMap::new())
        .expect("leastPing fallback should resolve");
    assert_eq!(fallback.outbound_tag, "fallback");
    assert_eq!(
        state.balancer_principle_targets("latency", &outbounds),
        vec![String::new()],
        "leastPing principle target must not apply fallbackTag"
    );
}

#[test]
fn observation_store_shards_writes_and_reconstructs_full_snapshot() {
    let store = Arc::new(ObservationStore::default());
    let writers = (0..8)
        .map(|writer| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for index in 0..32 {
                    store.record(
                        format!("node-{writer}-{index}"),
                        OutboundObservation {
                            alive: true,
                            delay_ms: i64::from(writer * 32 + index),
                            ..OutboundObservation::default()
                        },
                    );
                }
            })
        })
        .collect::<Vec<_>>();
    for writer in writers {
        writer.join().expect("observation writer should finish");
    }

    let snapshot = store.snapshot_all();
    assert_eq!(snapshot.len(), 256);
    assert_eq!(snapshot["node-3-7"].delay_ms, 103);
}

#[test]
fn observation_target_snapshot_reuses_arc_values() {
    let store = ObservationStore::default();
    store.record(
        "direct".into(),
        OutboundObservation {
            alive: true,
            delay_ms: 12,
            ..OutboundObservation::default()
        },
    );
    store.record(
        "unrelated".into(),
        OutboundObservation {
            alive: true,
            delay_ms: 99,
            ..OutboundObservation::default()
        },
    );
    let direct = store.get("direct").expect("direct observation");
    let targets = BalancerTargetSet::new(vec!["direct".into(), "missing".into()]);

    let snapshot = store.snapshot_for(&targets);

    assert_eq!(snapshot.len(), 2);
    assert!(Arc::ptr_eq(
        &direct,
        snapshot[0].as_ref().expect("direct target snapshot")
    ));
    assert!(snapshot[1].is_none());
}

#[test]
fn observation_merge_preserves_only_missing_liveness_history() {
    let previous = OutboundObservation {
        alive: true,
        delay_ms: 20,
        last_seen_time: 100,
        last_try_time: 100,
        health_all: 10,
        health_fail: 2,
        health_deviation_ms: 4,
        health_average_ms: 18,
        health_max_ms: 30,
        health_min_ms: 10,
        ..OutboundObservation::default()
    };
    let incoming = OutboundObservation {
        alive: false,
        delay_ms: 50,
        last_try_time: 101,
        last_error_reason: "connection refused".into(),
        ..OutboundObservation::default()
    };

    let merged = merge_outbound_observation(Some(&previous), incoming);
    assert!(!merged.alive);
    assert_eq!(merged.delay_ms, 50);
    assert_eq!(merged.last_seen_time, 100);
    assert_eq!(merged.last_try_time, 101);
    assert_eq!(merged.health_all, 10);
    assert_eq!(merged.health_fail, 2);
    assert_eq!(merged.health_deviation_ms, 4);
    assert_eq!(merged.health_average_ms, 18);
    assert_eq!(merged.health_max_ms, 30);
    assert_eq!(merged.health_min_ms, 10);
    assert_eq!(merged.last_error_reason, "connection refused");
}

#[test]
fn observation_merge_keeps_explicit_new_health_window() {
    let previous = OutboundObservation {
        last_seen_time: 100,
        health_all: 10,
        health_fail: 2,
        ..OutboundObservation::default()
    };
    let incoming = OutboundObservation {
        last_seen_time: 200,
        health_all: 3,
        health_fail: 1,
        health_average_ms: 9,
        ..OutboundObservation::default()
    };

    let merged = merge_outbound_observation(Some(&previous), incoming.clone());
    assert_eq!(merged, incoming);
}

#[test]
fn connection_observation_preserves_active_health_window() {
    let state = RoutingState::default();
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: true,
            delay_ms: 20,
            last_seen_time: 100,
            last_try_time: 100,
            health_all: 10,
            health_fail: 2,
            health_deviation_ms: 4,
            health_average_ms: 18,
            health_max_ms: 30,
            health_min_ms: 10,
            ..OutboundObservation::default()
        },
    );
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: false,
            delay_ms: 50,
            last_error_reason: "connection refused".into(),
            last_try_time: 101,
            ..OutboundObservation::default()
        },
    );

    let status = &state.observations()["direct"];
    assert!(!status.alive);
    assert_eq!(status.delay_ms, 50);
    assert_eq!(status.last_seen_time, 100);
    assert_eq!(status.last_try_time, 101);
    assert_eq!(status.health_all, 10);
    assert_eq!(status.health_fail, 2);
    assert_eq!(status.health_average_ms, 18);
    assert_eq!(status.health_deviation_ms, 4);
}

#[test]
fn routing_replace_preserves_outbound_observations() {
    let mut state = RoutingState::default();
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: true,
            delay_ms: 12,
            ..OutboundObservation::default()
        },
    );
    state
        .merge(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            false,
        )
        .expect("routing replacement should compile");

    assert_eq!(state.observations()["direct"].delay_ms, 12);
}

#[test]
fn least_load_balancer_applies_health_filters_costs_and_baselines() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("load".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "load".into(),
            outbound_selector: vec![
                "fast".into(),
                "premium".into(),
                "flaky".into(),
                "slow".into(),
            ],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "leastLoad".into(),
                settings: Some(serde_json::json!({
                    "costs": [{"match": "premium", "value": 4}],
                    "baselines": ["20ms"],
                    "expected": 2,
                    "maxRTT": "100ms",
                    "tolerance": 0.5
                })),
            },
            fallback_tag: Some("fallback".into()),
        }],
    )
    .expect("leastLoad routing state should build");
    for (tag, status) in [
        (
            "fast",
            OutboundObservation {
                alive: true,
                delay_ms: 12,
                health_all: 10,
                health_fail: 1,
                health_average_ms: 12,
                health_deviation_ms: 10,
                ..OutboundObservation::default()
            },
        ),
        (
            "premium",
            OutboundObservation {
                alive: true,
                delay_ms: 8,
                health_all: 10,
                health_average_ms: 8,
                health_deviation_ms: 6,
                ..OutboundObservation::default()
            },
        ),
        (
            "flaky",
            OutboundObservation {
                alive: true,
                delay_ms: 4,
                health_all: 10,
                health_fail: 8,
                health_average_ms: 4,
                health_deviation_ms: 4,
                ..OutboundObservation::default()
            },
        ),
        (
            "slow",
            OutboundObservation {
                alive: true,
                delay_ms: 150,
                ..OutboundObservation::default()
            },
        ),
    ] {
        state.record_observation(tag, status);
    }
    let outbounds = [
        outbound("fast"),
        outbound("premium"),
        outbound("flaky"),
        outbound("slow"),
        outbound("fallback"),
    ];

    assert_eq!(
        state.balancer_principle_targets("load", &outbounds),
        vec!["fast", "premium"]
    );
}

#[test]
fn least_load_filters_failed_node_even_with_zero_tolerance() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("load".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "load".into(),
            outbound_selector: vec!["direct".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "leastLoad".into(),
                settings: Some(serde_json::json!({
                    "expected": 1,
                    "tolerance": 0
                })),
            },
            fallback_tag: Some("fallback".into()),
        }],
    )
    .expect("leastLoad failed-node state should build");
    state.record_observation(
        "direct",
        OutboundObservation {
            alive: false,
            delay_ms: LEAST_PING_MAX_DELAY_MS,
            health_all: 3,
            health_fail: 3,
            ..OutboundObservation::default()
        },
    );

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct"), outbound("fallback")],
            &HashMap::new(),
        )
        .expect("failed measured node should use fallback");
    assert_eq!(matched.outbound_tag, "fallback");
}

#[test]
fn least_load_balancer_uses_fallback_when_no_node_is_qualified() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("load".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "load".into(),
            outbound_selector: vec!["direct".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "leastLoad".into(),
                settings: Some(serde_json::json!({"expected": 1})),
            },
            fallback_tag: Some("fallback".into()),
        }],
    )
    .expect("leastLoad fallback state should build");
    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct"), outbound("fallback")],
            &HashMap::new(),
        )
        .expect("leastLoad fallback should route");

    assert_eq!(matched.outbound_tag, "fallback");
    assert!(
        state
            .balancer_principle_targets(
                "load",
                &[outbound("direct"), outbound("fallback")],
            )
            .is_empty(),
        "leastLoad principle targets must not apply fallbackTag"
    );
}

#[test]
fn least_load_ignores_invalid_or_empty_cost_matchers() {
    for cost in [
        serde_json::json!({"regexp": true, "match": "("}),
        serde_json::json!({"match": ""}),
    ] {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("load".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "load".into(),
                outbound_selector: vec!["direct".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastLoad".into(),
                    settings: Some(serde_json::json!({
                        "costs": [cost],
                        "expected": 1
                    })),
                },
                fallback_tag: None,
            }],
        )
        .expect("Xray ignores unusable leastLoad cost matchers");
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: true,
                delay_ms: 10,
                health_all: 1,
                health_average_ms: 10,
                health_deviation_ms: 10,
                ..OutboundObservation::default()
            },
        );
        assert_eq!(
            state.balancer_principle_targets("load", &[outbound("direct")],),
            vec!["direct"]
        );
    }
}

#[test]
fn least_load_rejects_invalid_duration() {
    let error = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            balancer_tag: Some("load".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "load".into(),
            outbound_selector: vec!["direct".into()],
            strategy: crate::config::rule::BalancerStrategyConfig {
                kind: "leastLoad".into(),
                settings: Some(serde_json::json!({
                    "maxRTT": "five parsecs"
                })),
            },
            fallback_tag: None,
        }],
    )
    .expect_err("invalid leastLoad duration must fail");
    assert!(error.contains("invalid routing duration"));
}

#[test]
fn routing_state_resolves_balancer_override() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            balancer_tag: Some("auto".into()),
            inbound_tag: vec!["test".into()],
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "auto".into(),
            outbound_selector: vec!["direct".into(), "backup".into()],
            strategy: Default::default(),
            fallback_tag: None,
        }],
    )
    .expect("routing state should build");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct"), outbound("backup")],
            &HashMap::from([("auto".into(), "backup".into())]),
        )
        .expect("balancer rule should match");
    assert_eq!(matched.outbound_tag, "backup");
    assert_eq!(matched.outbound_group_tags, vec!["auto".to_string()]);
}

#[test]
fn outbound_tag_takes_priority_when_balancer_tag_is_also_present() {
    let state = RoutingState::from_parts(
        vec![RuleConfig {
            inbound_tag: vec!["test".into()],
            outbound_tag: Some("direct".into()),
            balancer_tag: Some("auto".into()),
            ..RuleConfig::default()
        }],
        vec![BalancerConfig {
            tag: "auto".into(),
            outbound_selector: vec!["backup".into()],
            strategy: Default::default(),
            fallback_tag: None,
        }],
    )
    .expect("Xray gives outboundTag priority over balancerTag");

    let matched = state
        .route(
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            &[outbound("direct"), outbound("backup")],
            &HashMap::new(),
        )
        .expect("routing rule should match");
    assert_eq!(matched.outbound_tag, "direct");
    assert!(matched.outbound_group_tags.is_empty());
}
