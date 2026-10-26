use std::fmt::Write as _;

use serde::Deserialize;
use serde_path_to_error::{Path, Segment};

pub(crate) fn json(error: &serde_json::Error, field_path: Option<String>) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "invalid value",
        serde_json::error::Category::Eof => "unexpected end of input",
        serde_json::error::Category::Io => "input error",
    };

    format!(
        "{category}{} at line {}, column {}",
        field_path_suffix(field_path),
        error.line(),
        error.column()
    )
}

pub(crate) fn json5(error: &json5::Error, field_path: Option<String>) -> String {
    let category = error
        .code()
        .map(|code| format!("syntax error ({code:?})"))
        .unwrap_or_else(|| "invalid value".to_string());

    match error.position() {
        Some(position) => format!(
            "{category}{} at line {}, column {}",
            field_path_suffix(field_path),
            position.line + 1,
            position.column + 1
        ),
        None => format!("{category}{}", field_path_suffix(field_path)),
    }
}

pub(crate) fn json_field_path<'de, T>(input: &'de str) -> Option<String>
where
    T: Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let error = serde_path_to_error::deserialize::<_, T>(&mut deserializer).err()?;
    safe_field_path(error.path())
}

pub(crate) fn json5_field_path<'de, T>(input: &'de str) -> Option<String>
where
    T: Deserialize<'de>,
{
    let mut deserializer = json5::Deserializer::from_str(input);
    let error = serde_path_to_error::deserialize::<_, T>(&mut deserializer).err()?;
    safe_field_path(error.path())
}

pub(crate) fn yaml_field_path<'de, T>(input: &'de str) -> Option<String>
where
    T: Deserialize<'de>,
{
    let deserializer = serde_yaml::Deserializer::from_str(input);
    let error = serde_path_to_error::deserialize::<_, T>(deserializer).err()?;
    safe_field_path(error.path())
}

// Rust field names used by the config deserializers. Accept both the source
// spelling and its serde camelCase spelling so useful diagnostics remain
// available as the typed config structs grow. Arbitrary map keys are still
// masked below, regardless of whether their spelling matches this list.
const CONFIG_STRUCT_FIELDS: &[&str] = &[
    // Generated from the config deserialization structs in def.rs, mod.rs,
    // rule/mod.rs, and LogConfig.
    "accept_proxy_protocol",
    "access",
    "address",
    "addresses",
    "allocate",
    "alpn",
    "api",
    "attrs",
    "auth",
    "authority",
    "auto_outbounds_interface",
    "auto_system_routing_table",
    "balancer_tag",
    "balancers",
    "bbr_profile",
    "brutal_down",
    "brutal_up",
    "buffer_size",
    "build_chain",
    "burst_observatory",
    "certificate",
    "certificate_file",
    "certificates",
    "cfg",
    "cipher_suites",
    "client_ip",
    "congestion",
    "connection_idle",
    "connectivity",
    "content",
    "custom_sockopt",
    "cwd",
    "cwnd_multiplier",
    "deduplication",
    "desc",
    "dest",
    "destination",
    "dir",
    "disable_cache",
    "disable_fallback",
    "disable_fallback_if_match",
    "disable_path_mtu_discovery",
    "disable_system_root",
    "dns",
    "dns_log",
    "domain",
    "domain_strategy",
    "domains",
    "down",
    "downlink_capacity",
    "downlink_only",
    "download_settings",
    "ed",
    "email",
    "enable_concurrency",
    "enable_parallel_query",
    "enable_session_resumption",
    "error",
    "expected_ips",
    "expected_ips_prefer",
    "extra",
    "fallback_tag",
    "final_mask",
    "final_query",
    "fingerprint",
    "flow",
    "from",
    "gateway",
    "grace_period_seconds",
    "grpc_settings",
    "handshake",
    "header",
    "headers",
    "health_check_timeout",
    "heartbeat_period",
    "host",
    "hosts",
    "http_method",
    "httpupgrade_settings",
    "hysteria_settings",
    "id",
    "idle_timeout",
    "ignore_client_bandwidth",
    "inbound_tag",
    "inbounds",
    "init_connection_receive_window",
    "init_stream_receive_window",
    "initial_windows_size",
    "inner",
    "insecure",
    "interface",
    "interval",
    "ip",
    "ipv6_address",
    "kcp_settings",
    "keep_alive_period",
    "key",
    "key_file",
    "kind",
    "legacy_reverse_configured",
    "level",
    "levels",
    "listen",
    "local_ip",
    "local_port",
    "log",
    "loglevel",
    "mark",
    "masquerade",
    "max_client_ver",
    "max_connection_receive_window",
    "max_idle_timeout",
    "max_incoming_streams",
    "max_sending_window",
    "max_stream_receive_window",
    "max_tcp_connections",
    "max_time_diff",
    "max_udp_sessions",
    "max_version",
    "mcp",
    "metrics",
    "min_client_ver",
    "min_version",
    "mode",
    "mtu",
    "multi_mode",
    "name",
    "network",
    "no_grpc_header",
    "no_sse_header",
    "observatory",
    "ocsp_stapling",
    "one_time_loading",
    "opt",
    "outbound_selector",
    "outbound_tag",
    "outbounds",
    "override_error_target",
    "password",
    "path",
    "permit_without_stream",
    "ping_config",
    "policy",
    "port",
    "ports",
    "private_key",
    "probe_interval",
    "probe_url",
    "process",
    "protocol",
    "proxied_domain",
    "public_key",
    "query_strategy",
    "quic_params",
    "reality_settings",
    "receive_original_dest_address",
    "reject_unknown_sni",
    "response_code",
    "rewrite_host",
    "route_from",
    "route_input_interface",
    "route_rule_priority",
    "route_table",
    "routes",
    "routing",
    "rule",
    "rule_tag",
    "rules",
    "sampling",
    "sc_max_buffered_posts",
    "sc_max_each_post_bytes",
    "sc_min_posts_interval_ms",
    "sc_stream_up_server_secs",
    "security",
    "seed",
    "seq_key",
    "seq_placement",
    "serve_expired_ttl",
    "serve_stale",
    "server_max_header_bytes",
    "server_name",
    "server_names",
    "servers",
    "service_name",
    "services",
    "session_id_length",
    "session_id_table",
    "session_key",
    "session_placement",
    "settings",
    "short_ids",
    "show",
    "shutdown",
    "skip_fallback",
    "sniffing",
    "sockopt",
    "source",
    "source_ip",
    "source_port",
    "spider_x",
    "stats",
    "stats_inbound_downlink",
    "stats_inbound_uplink",
    "stats_outbound_downlink",
    "stats_outbound_uplink",
    "stats_user_downlink",
    "stats_user_online",
    "stats_user_uplink",
    "status_code",
    "strategy",
    "stream_settings",
    "subject_selector",
    "system",
    "tag",
    "tcp",
    "tcp_brutal_cwnd_gain",
    "tcp_brutal_rate",
    "tcp_congestion",
    "tcp_fast_open",
    "tcp_keep_alive_idle",
    "tcp_keep_alive_interval",
    "tcp_max_seg",
    "tcp_mptcp",
    "tcp_user_timeout",
    "tcp_window_clamp",
    "timeout",
    "timeout_ms",
    "tls_settings",
    "to",
    "tproxy",
    "transport",
    "trusted_x_forwarded_for",
    "tti",
    "tun_gateway",
    "udp",
    "udp_hop",
    "udp_idle_timeout",
    "unexpected_ips",
    "unexpected_ips_prefer",
    "up",
    "update_interval_ms",
    "uplink_capacity",
    "uplink_chunk_size",
    "uplink_data_key",
    "uplink_data_placement",
    "uplink_http_method",
    "uplink_only",
    "url",
    "usage",
    "use_system_hosts",
    "user",
    "user_domain_access",
    "user_level",
    "v6only",
    "value",
    "value_type",
    "version",
    "vless_route",
    "webhook",
    "ws_settings",
    "x_padding_bytes",
    "x_padding_header",
    "x_padding_key",
    "x_padding_method",
    "x_padding_obfs_mode",
    "x_padding_placement",
    "xhttp_settings",
    "xmux",
    "xver",
];

fn safe_field_path(path: &Path) -> Option<String> {
    const STATIC_FIELDS: &[&str] = &[
        "inbounds",
        "outbounds",
        "log",
        "stats",
        "metrics",
        "api",
        "policy",
        "routing",
        "dns",
        "userDomainAccess",
        "user_domain_access",
        "observatory",
        "burstObservatory",
        "shutdown",
        "tunGateway",
        "mcp",
        "reverse",
        "allocate",
        "listen",
        "port",
        "protocol",
        "settings",
        "sniffing",
        "streamSettings",
        "stream_settings",
        "tag",
        "network",
        "security",
        "tlsSettings",
        "tls_settings",
        "xhttpSettings",
        "xhttp_settings",
        "wsSettings",
        "ws_settings",
        "httpupgradeSettings",
        "httpupgrade_settings",
        "grpcSettings",
        "grpc_settings",
        "kcpSettings",
        "kcp_settings",
        "hysteriaSettings",
        "hysteria_settings",
        "finalmask",
        "finalMask",
        "final_mask",
        "tcp",
        "udp",
        "ports",
        "realitySettings",
        "reality_settings",
        "sockopt",
        "clients",
        "users",
        "email",
        "id",
        "level",
        "method",
        "password",
        "alterId",
        "alter_id",
        "flow",
        "decryption",
        "encryption",
        "address",
        "serverName",
        "serverNames",
        "shortId",
        "shortIds",
        "privateKey",
        "publicKey",
        "fingerprint",
        "verify",
        "headers",
        "header",
        "hosts",
        "servers",
        "clientIp",
        "clientIP",
        "queryStrategy",
        "disableCache",
        "serveStale",
        "serveExpiredTtl",
        "disableFallback",
        "disableFallbackIfMatch",
        "enableParallelQuery",
        "useSystemHosts",
        "permitWithoutStream",
        "initialWindowsSize",
        "levels",
        "system",
        "handshake",
        "connIdle",
        "connectionIdle",
        "uplinkOnly",
        "downlinkOnly",
        "statsUserUplink",
        "statsUserDownlink",
        "statsUserOnline",
        "bufferSize",
        "statsInboundUplink",
        "statsInboundDownlink",
        "statsOutboundUplink",
        "statsOutboundDownlink",
        "rules",
        "domainStrategy",
        "domainMatcher",
        "balancers",
        "attrs",
        "ruleTag",
        "inboundTag",
        "outboundTag",
        "balancerTag",
        "domain",
        "domains",
        "ip",
        "sourceIp",
        "source",
        "localIp",
        "localPort",
        "process",
        "webhook",
        "url",
        "deduplication",
        "connectivity",
        "destination",
        "interval",
        "samplingCount",
        "timeout",
        "httpMethod",
        "subjectSelector",
        "probeURL",
        "probeUrl",
        "probeInterval",
        "probe_interval",
        "enableConcurrency",
        "pingConfig",
        "gracePeriodSeconds",
        "mtu",
        "routes",
        "routeFrom",
        "routeInputInterface",
        "routeTable",
        "routeRulePriority",
        "userLevel",
        "maxTcpConnections",
        "maxUdpSessions",
        "services",
        "path",
        "extra",
        "downloadSettings",
        "download_settings",
        "xmux",
        "updateIntervalMs",
        "type",
        "name",
        "value",
        // Explicit Serde spellings and aliases whose acronyms do not follow
        // the ordinary snake_case-to-camelCase conversion.
        "noGRPCHeader",
        "noSSEHeader",
        "uplinkHTTPMethod",
        "sessionIDPlacement",
        "sessionPlacement",
        "sessionIDKey",
        "sessionKey",
        "sessionIDTable",
        "sessionIDLength",
        "disablePathMTUDiscovery",
        "maxTimediff",
        "minClient",
        "maxClient",
        "target",
        "cipher_suite",
        "selector",
    ];
    const DYNAMIC_VALUE_FIELDS: &[&str] = &[
        "attrs",
        "headers",
        "hosts",
        "levels",
        "settings",
        "userDomainAccess",
        "user_domain_access",
        "servers",
        "allocate",
        "sniffing",
        "probeInterval",
        "probe_interval",
        "interval",
        "timeout",
        "header",
        "extra",
        "downloadSettings",
        "download_settings",
        "xmux",
        "tcp",
        "udp",
        "ports",
        "streamSettings",
        "stream_settings",
    ];

    let mut result = String::new();
    let mut path_fields = Vec::new();
    let mut inside_dynamic_value = false;
    for segment in path {
        match segment {
            Segment::Map { key } => {
                let safe_key = if inside_dynamic_value
                    || !is_static_field(key, STATIC_FIELDS)
                {
                    "<key>"
                } else {
                    key.as_str()
                };
                if !result.is_empty() {
                    result.push('.');
                }
                result.push_str(safe_key);
                if !inside_dynamic_value
                    && DYNAMIC_VALUE_FIELDS.contains(&key.as_str())
                    && is_dynamic_value_field(&path_fields, key)
                {
                    inside_dynamic_value = true;
                }
                path_fields.push(key);
            }
            Segment::Seq { index } => {
                let _ = write!(result, "[{index}]");
                path_fields.push("[]");
            }
            Segment::Enum { .. } => {
                if !result.is_empty() {
                    result.push('.');
                }
                result.push_str("<variant>");
                path_fields.push("<variant>");
            }
            Segment::Unknown => path_fields.push("<unknown>"),
        }
    }

    (!result.is_empty() && result != ".").then_some(result)
}

fn is_dynamic_value_field(path: &[&str], field: &str) -> bool {
    match field {
        "streamSettings" | "stream_settings" => path.contains(&"outbounds"),
        _ => true,
    }
}

fn is_static_field(field: &str, static_fields: &[&str]) -> bool {
    static_fields.contains(&field)
        || CONFIG_STRUCT_FIELDS
            .iter()
            .any(|known| *known == field || snake_to_camel_matches(known, field))
}

fn snake_to_camel_matches(snake: &str, candidate: &str) -> bool {
    let mut candidate = candidate.chars();
    let mut uppercase_next = false;

    for character in snake.chars() {
        if character == '_' {
            uppercase_next = true;
            continue;
        }

        let Some(candidate_character) = candidate.next() else {
            return false;
        };
        let expected = if uppercase_next {
            uppercase_next = false;
            character.to_ascii_uppercase()
        } else {
            character
        };

        if candidate_character != expected {
            return false;
        }
    }

    candidate.next().is_none()
}

pub(crate) fn yaml(error: &serde_yaml::Error, field_path: Option<String>) -> String {
    match error.location() {
        Some(location) => format!(
            "invalid value{} at line {}, column {}",
            field_path_suffix(field_path),
            location.line(),
            location.column()
        ),
        None => format!("invalid value{}", field_path_suffix(field_path)),
    }
}

fn field_path_suffix(field_path: Option<String>) -> String {
    field_path
        .map(|path| format!(" at field path `{path}`"))
        .unwrap_or_default()
}
