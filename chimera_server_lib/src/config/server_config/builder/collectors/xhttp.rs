use serde::Deserialize;

use crate::{
    Error,
    config::{XhttpRange, XhttpSettings},
};

use super::{
    super::super::types::{
        RangeConfig, XhttpDataPlacement, XhttpMode, XhttpPaddingMethod,
        XhttpPaddingPlacement, XhttpPlacement, XhttpServerConfig,
    },
    normalize_path,
};

pub(in crate::config::server_config::builder) fn collect_xhttp_settings(
    raw: XhttpSettings,
) -> Result<XhttpServerConfig, Error> {
    let raw = apply_xhttp_extra(raw)?;
    let mode = parse_xhttp_mode(raw.mode.as_deref())?;
    validate_xhttp_client_fields(&raw, mode)?;
    validate_xhttp_session_id_generator(&raw)?;
    let uplink_http_method =
        normalize_xhttp_uplink_method(raw.uplink_http_method.as_deref(), mode)?;
    let min_posts_interval_ms =
        normalize_xhttp_min_posts_interval_ms(raw.sc_min_posts_interval_ms.clone());
    let session_placement =
        parse_xhttp_placement(raw.session_placement.as_deref(), "sessionPlacement")?;
    let seq_placement =
        parse_xhttp_placement(raw.seq_placement.as_deref(), "seqPlacement")?;
    let session_key = normalize_xhttp_meta_key(
        raw.session_key.as_deref(),
        session_placement,
        "X-Session",
        "x_session",
    );
    let seq_key = normalize_xhttp_meta_key(
        raw.seq_key.as_deref(),
        seq_placement,
        "X-Seq",
        "x_seq",
    );
    let uplink_data_placement =
        parse_xhttp_data_placement(raw.uplink_data_placement.as_deref(), mode)?;
    let uplink_data_key = normalize_xhttp_data_key(
        raw.uplink_data_key.as_deref(),
        uplink_data_placement,
    );
    if raw
        .headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("host"))
    {
        return Err(Error::InvalidConfig(
            "xhttpSettings.headers cannot contain host; use xhttpSettings.host instead"
                .into(),
        ));
    }
    if raw.x_padding_bytes.as_ref().is_some_and(|range| {
        (range.from != 0 || range.to != 0) && (range.from <= 0 || range.to <= 0)
    }) {
        return Err(Error::InvalidConfig(
            "xhttpSettings.xPaddingBytes cannot be disabled".into(),
        ));
    }
    // Current Xray only requires a trailing slash when session or sequence
    // metadata is encoded in the path. Preserve file-like paths otherwise.
    let normalized_path = normalize_path(
        raw.path,
        session_placement == XhttpPlacement::Path
            || seq_placement == XhttpPlacement::Path,
    );
    let (min_padding, max_padding) = clamp_xhttp_range(
        raw.x_padding_bytes.unwrap_or(XhttpRange {
            from: 100,
            to: 1000,
        }),
        100,
        1000,
    );
    let padding_obfs_mode = raw.x_padding_obfs_mode.unwrap_or(false);
    let padding_key = raw
        .x_padding_key
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "x_padding".to_string());
    let padding_header = raw
        .x_padding_header
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "X-Padding".to_string());
    let padding_placement =
        parse_xhttp_padding_placement(raw.x_padding_placement.as_deref())?;
    let padding_method =
        parse_xhttp_padding_method(raw.x_padding_method.as_deref())?;
    if matches!(
        padding_placement,
        XhttpPaddingPlacement::Header | XhttpPaddingPlacement::QueryInHeader
    ) && http::header::HeaderName::from_bytes(padding_header.as_bytes()).is_err()
    {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttpSettings.xPaddingHeader: {padding_header}"
        )));
    }
    let server_max_header_bytes = match raw.server_max_header_bytes.unwrap_or(0) {
        value if value < 0 => {
            return Err(Error::InvalidConfig(
                "xhttpSettings.serverMaxHeaderBytes cannot be negative".into(),
            ));
        }
        0 => 8192,
        value => value as usize,
    };
    let max_each_post_bytes = match raw.sc_max_each_post_bytes {
        None => 1_000_000,
        Some(range) if range.to == 0 => 1_000_000,
        Some(range) => i64::from(range.to),
    };
    let stream_up_server_secs =
        normalize_xhttp_stream_up_server_secs(raw.sc_stream_up_server_secs);

    Ok(XhttpServerConfig {
        mode,
        host: raw.host.map(|h| h.to_ascii_lowercase()),
        path: normalized_path,
        trusted_x_forwarded_for: Vec::new(),
        min_padding,
        max_padding,
        max_each_post_bytes,
        max_buffered_posts: match raw.sc_max_buffered_posts.unwrap_or(0) {
            value if value < 0 => {
                return Err(Error::InvalidConfig(
                    "xhttpSettings.scMaxBufferedPosts cannot be negative".into(),
                ));
            }
            0 => 30,
            value => value as usize,
        },
        session_ttl_secs: 30,
        stream_up_server_secs,
        server_max_header_bytes,
        padding_obfs_mode,
        padding_key,
        padding_header,
        padding_placement,
        padding_method,
        no_grpc_header: raw.no_grpc_header.unwrap_or(false),
        no_sse_header: raw.no_sse_header.unwrap_or(false),
        uplink_http_method,
        min_posts_interval_ms,
        session_placement,
        session_key,
        seq_placement,
        seq_key,
        uplink_data_placement,
        uplink_data_key,
        xray_congestion: None,
        xray_brutal_up: None,
        xray_max_idle_timeout_secs: None,
        xray_max_incoming_streams: None,
        xray_init_stream_receive_window: None,
        xray_max_stream_receive_window: None,
        xray_init_connection_receive_window: None,
        xray_max_connection_receive_window: None,
        xray_disable_path_mtu_discovery: None,
    })
}

fn validate_xhttp_session_id_generator(raw: &XhttpSettings) -> Result<(), Error> {
    let Some(table) = raw
        .session_id_table
        .as_deref()
        .filter(|table| !table.is_empty())
    else {
        return Ok(());
    };
    let table = match table {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        table => table,
    };
    let length = raw.session_id_length.clone().unwrap_or_default();
    if length.from <= 0 {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDLength.from must be greater than 0".into(),
        ));
    }
    if !table.is_ascii() {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDTable must contain only ASCII characters".into(),
        ));
    }

    const MIN_SESSION_ID_ROOM: u128 = 1_u128 << 31;
    let base = table.len() as u128;
    let mut room = 0_u128;
    for length in length.from..=length.to {
        let mut term = 1_u128;
        for _ in 0..length {
            term = term.saturating_mul(base).min(MIN_SESSION_ID_ROOM);
            if term == MIN_SESSION_ID_ROOM {
                break;
            }
        }
        room = room.saturating_add(term).min(MIN_SESSION_ID_ROOM);
        if room == MIN_SESSION_ID_ROOM {
            break;
        }
    }
    if room < MIN_SESSION_ID_ROOM {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDTable or sessionIDLength is too small".into(),
        ));
    }
    Ok(())
}

fn apply_xhttp_extra(mut raw: XhttpSettings) -> Result<XhttpSettings, Error> {
    let Some(extra_value) = raw.extra.take() else {
        return Ok(raw);
    };

    let outer_host = raw.host.take();
    let outer_path = raw.path.take();
    let outer_mode = raw.mode.take();
    let mut extra =
        serde_json::from_value::<XhttpSettings>(extra_value).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to parse xhttpSettings.extra: {error}"
            ))
        })?;
    extra.host = outer_host;
    extra.path = outer_path;
    extra.mode = outer_mode;
    extra.extra = None;
    Ok(extra)
}

fn validate_xhttp_client_fields(
    raw: &XhttpSettings,
    mode: XhttpMode,
) -> Result<(), Error> {
    if raw.download_settings.is_some() && mode == XhttpMode::StreamOne {
        return Err(Error::InvalidConfig(
            "xhttpSettings.downloadSettings cannot be used with mode=stream-one"
                .into(),
        ));
    }

    if let Some(value) = raw.xmux.as_ref() {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct XmuxInput {
            #[serde(default)]
            max_concurrency: Option<XhttpRange>,
            #[serde(default)]
            max_connections: Option<XhttpRange>,
        }

        let xmux =
            serde_json::from_value::<XmuxInput>(value.clone()).map_err(|error| {
                Error::InvalidConfig(format!("invalid xhttpSettings.xmux: {error}"))
            })?;
        if xmux
            .max_connections
            .as_ref()
            .is_some_and(|range| range.to > 0)
            && xmux
                .max_concurrency
                .as_ref()
                .is_some_and(|range| range.to > 0)
        {
            return Err(Error::InvalidConfig(
                "xhttpSettings.xmux.maxConnections cannot be specified together with maxConcurrency"
                    .into(),
            ));
        }
    }

    Ok(())
}

fn parse_xhttp_data_placement(
    placement: Option<&str>,
    mode: XhttpMode,
) -> Result<XhttpDataPlacement, Error> {
    let placement = match placement.unwrap_or("") {
        "" | "auto" => XhttpDataPlacement::Auto,
        "body" => XhttpDataPlacement::Body,
        "header" => XhttpDataPlacement::Header,
        "cookie" => XhttpDataPlacement::Cookie,
        unsupported => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttpSettings.uplinkDataPlacement: {unsupported}"
            )));
        }
    };
    if matches!(
        placement,
        XhttpDataPlacement::Header | XhttpDataPlacement::Cookie
    ) && mode != XhttpMode::PacketUp
    {
        let value = match placement {
            XhttpDataPlacement::Header => "header",
            XhttpDataPlacement::Cookie => "cookie",
            _ => unreachable!(),
        };
        return Err(Error::InvalidConfig(format!(
            "xhttpSettings.uplinkDataPlacement={value} requires mode=packet-up"
        )));
    }
    Ok(placement)
}

fn normalize_xhttp_data_key(
    key: Option<&str>,
    placement: XhttpDataPlacement,
) -> String {
    let key = key.unwrap_or("");
    if !key.is_empty() {
        return key.to_string();
    }
    match placement {
        XhttpDataPlacement::Body => String::new(),
        XhttpDataPlacement::Cookie => "x_data".to_string(),
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header => {
            "X-Data".to_string()
        }
    }
}

fn parse_xhttp_padding_placement(
    placement: Option<&str>,
) -> Result<XhttpPaddingPlacement, Error> {
    match placement.unwrap_or("queryInHeader") {
        "cookie" => Ok(XhttpPaddingPlacement::Cookie),
        "header" => Ok(XhttpPaddingPlacement::Header),
        "query" => Ok(XhttpPaddingPlacement::Query),
        "" | "queryInHeader" => Ok(XhttpPaddingPlacement::QueryInHeader),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.xPaddingPlacement: {unsupported}"
        ))),
    }
}

fn parse_xhttp_padding_method(
    method: Option<&str>,
) -> Result<XhttpPaddingMethod, Error> {
    match method.unwrap_or("repeat-x") {
        "" | "repeat-x" => Ok(XhttpPaddingMethod::RepeatX),
        "tokenish" => Ok(XhttpPaddingMethod::Tokenish),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.xPaddingMethod: {unsupported}"
        ))),
    }
}

pub(super) fn parse_xhttp_placement(
    placement: Option<&str>,
    field: &str,
) -> Result<XhttpPlacement, Error> {
    match placement.unwrap_or("path") {
        "" | "path" => Ok(XhttpPlacement::Path),
        "query" => Ok(XhttpPlacement::Query),
        "header" => Ok(XhttpPlacement::Header),
        "cookie" => Ok(XhttpPlacement::Cookie),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.{field}: {unsupported}"
        ))),
    }
}

fn normalize_xhttp_meta_key(
    key: Option<&str>,
    placement: XhttpPlacement,
    default_header: &str,
    default_query_cookie: &str,
) -> String {
    let key = key.unwrap_or("");
    if !key.is_empty() {
        return key.to_string();
    }
    match placement {
        XhttpPlacement::Path => String::new(),
        XhttpPlacement::Header => default_header.to_string(),
        XhttpPlacement::Query | XhttpPlacement::Cookie => {
            default_query_cookie.to_string()
        }
    }
}

fn normalize_xhttp_uplink_method(
    method: Option<&str>,
    mode: XhttpMode,
) -> Result<String, Error> {
    let method = method.unwrap_or("");
    let method = if method.is_empty() {
        "POST".to_string()
    } else {
        // Xray v26.2.6 applies strings.ToUpper without trimming or validating
        // the value as an HTTP token. Preserve that exact config semantics;
        // odd values simply never match a real request method at runtime.
        method.to_ascii_uppercase()
    };
    if method == "GET" && mode != XhttpMode::PacketUp {
        return Err(Error::InvalidConfig(
            "xhttpSettings.uplinkHTTPMethod=GET requires mode=packet-up".into(),
        ));
    }
    Ok(method)
}

fn parse_xhttp_mode(mode: Option<&str>) -> Result<XhttpMode, Error> {
    match mode.unwrap_or("auto") {
        "" | "auto" => Ok(XhttpMode::Auto),
        "packet-up" => Ok(XhttpMode::PacketUp),
        "stream-up" => Ok(XhttpMode::StreamUp),
        "stream-one" => Ok(XhttpMode::StreamOne),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.mode: {unsupported}"
        ))),
    }
}

fn clamp_xhttp_range(
    range: XhttpRange,
    default_from: i32,
    default_to: i32,
) -> (usize, usize) {
    RangeConfig {
        from: range.from,
        to: range.to,
    }
    .clamp_with_defaults(default_from, default_to)
}

fn normalize_xhttp_min_posts_interval_ms(
    range: Option<XhttpRange>,
) -> (usize, usize) {
    let range = range.unwrap_or(XhttpRange { from: 30, to: 30 });
    if range.to == 0 {
        return (30, 30);
    }
    if range.to < 0 {
        // Xray v26.2.6 preserves negative sentinels here. Its client-side
        // scheduler only sleeps when From > 0, so represent that disabled
        // state explicitly in the unsigned server config.
        return (0, 0);
    }
    (range.from.max(0) as usize, range.to as usize)
}

fn normalize_xhttp_stream_up_server_secs(
    range: Option<XhttpRange>,
) -> (usize, usize) {
    let range = range.unwrap_or(XhttpRange { from: 20, to: 80 });
    if range.to == 0 {
        return (20, 80);
    }
    if range.to < 0 {
        // Xray v26.2.6 preserves a negative range here and then gates the
        // stream-up padding writer on To > 0. Represent that disabled state
        // explicitly because the runtime duration type is unsigned.
        return (0, 0);
    }
    (range.from.max(0) as usize, range.to as usize)
}
