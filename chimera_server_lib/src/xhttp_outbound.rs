use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    HeaderMap, Method, Request, Uri,
    body::Frame,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderName,
        HeaderValue, REFERER, TRANSFER_ENCODING,
    },
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rand::RngExt;
use serde::Deserialize;
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    },
    sync::Mutex,
    time::sleep,
};
use tokio_util::io::ReaderStream;
use tracing::debug;

use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
};

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
const DEFAULT_PADDING_FROM: usize = 100;
const DEFAULT_PADDING_TO: usize = 1000;
const DEFAULT_MAX_EACH_POST_BYTES: usize = 1_000_000;
const DEFAULT_MIN_POST_INTERVAL: Duration = Duration::from_millis(30);
const DEFAULT_UPLINK_CHUNK_SIZE: usize = DEFAULT_MAX_EACH_POST_BYTES;

type XhttpOutboundBody = UnsyncBoxBody<Bytes, std::io::Error>;
type XhttpH2Sender = hyper::client::conn::http2::SendRequest<XhttpOutboundBody>;
type XhttpH3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type XhttpH3SendStream =
    h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type XhttpH3RecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

#[async_trait]
pub(crate) trait XhttpStreamDialer: Send + Sync {
    async fn dial(&self) -> std::io::Result<Box<dyn AsyncStream>>;
}

#[async_trait]
pub(crate) trait XhttpDownlinkConnector: Send + Sync {
    async fn open_downlink(&self, session_id: &str)
    -> std::io::Result<DuplexStream>;
}

#[async_trait]
pub(crate) trait XhttpH3Dialer: Send + Sync {
    async fn dial_h3(
        &self,
        keep_alive: Option<Duration>,
    ) -> std::io::Result<(Arc<quinn::Endpoint>, quinn::Connection)>;
}

const DEFAULT_H2_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(45);
const DEFAULT_H3_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Default)]
struct XhttpXmuxConfig {
    max_concurrency: (u64, u64),
    max_connections: (u64, u64),
    c_max_reuse_times: (u64, u64),
    h_max_request_times: (u64, u64),
    h_max_reusable_secs: (u64, u64),
    h_keep_alive_period: i64,
}

#[derive(Debug, Clone, Copy)]
struct XhttpXmuxRuntimeConfig {
    max_concurrency: u32,
    max_connections: usize,
    c_max_reuse_times: (u64, u64),
    h_max_request_times: (u64, u64),
    h_max_reusable_secs: (u64, u64),
    h_keep_alive_period: i64,
}

struct XhttpXmuxManager {
    config: XhttpXmuxRuntimeConfig,
    h2_connections: Mutex<Vec<XhttpH2XmuxEntry>>,
    h3_connections: Mutex<Vec<XhttpH3XmuxEntry>>,
}

impl fmt::Debug for XhttpXmuxManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XhttpXmuxManager")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

struct XhttpXmuxConnectionState {
    active_tunnels: AtomicU32,
    remaining_uses: AtomicI64,
    remaining_requests: AtomicI64,
    reusable_until: Option<Instant>,
    closed: AtomicBool,
}

impl XhttpXmuxConnectionState {
    fn new(config: XhttpXmuxRuntimeConfig) -> Self {
        let reuse_times = random_u64(config.c_max_reuse_times);
        let request_times = random_u64(config.h_max_request_times);
        let reusable_secs = random_u64(config.h_max_reusable_secs);
        Self {
            active_tunnels: AtomicU32::new(0),
            remaining_uses: AtomicI64::new(xmux_limit(reuse_times)),
            remaining_requests: AtomicI64::new(xmux_limit(request_times)),
            reusable_until: (reusable_secs > 0)
                .then(|| Instant::now() + Duration::from_secs(reusable_secs)),
            closed: AtomicBool::new(false),
        }
    }

    fn is_expired(&self) -> bool {
        self.reusable_until
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn can_select(&self, max_concurrency: u32) -> bool {
        !self.closed.load(Ordering::Acquire)
            && !self.is_expired()
            && self.remaining_uses.load(Ordering::Acquire) != 0
            && self.remaining_requests.load(Ordering::Acquire) != 0
            && (max_concurrency == 0
                || self.active_tunnels.load(Ordering::Acquire) < max_concurrency)
    }

    fn claim_selection(&self, track_tunnel: bool) -> bool {
        let remaining = self.remaining_uses.load(Ordering::Acquire);
        if remaining == 0 {
            return false;
        }
        if remaining > 0 {
            self.remaining_uses.fetch_sub(1, Ordering::AcqRel);
        }
        if track_tunnel {
            self.active_tunnels.fetch_add(1, Ordering::AcqRel);
        }
        true
    }

    fn release_tunnel(&self) {
        self.active_tunnels.fetch_sub(1, Ordering::AcqRel);
    }

    fn record_request(&self) {
        let mut remaining = self.remaining_requests.load(Ordering::Acquire);
        while remaining > 0 {
            match self.remaining_requests.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(current) => remaining = current,
            }
        }
    }

    fn should_rotate_requests(&self) -> bool {
        self.closed.load(Ordering::Acquire)
            || self.is_expired()
            || self.remaining_requests.load(Ordering::Acquire) == 0
    }

    fn keep_in_pool(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && !self.is_expired()
            && self.remaining_uses.load(Ordering::Acquire) != 0
            && self.remaining_requests.load(Ordering::Acquire) != 0
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

fn xmux_limit(value: u64) -> i64 {
    if value == 0 {
        -1
    } else {
        value.min(i64::MAX as u64) as i64
    }
}

struct XhttpXmuxLease {
    state: Arc<XhttpXmuxConnectionState>,
}

impl Drop for XhttpXmuxLease {
    fn drop(&mut self) {
        self.state.release_tunnel();
    }
}

#[derive(Clone)]
struct XhttpH2XmuxEntry {
    sender: XhttpH2Sender,
    state: Arc<XhttpXmuxConnectionState>,
}

struct XhttpH2XmuxSelection {
    sender: XhttpH2Sender,
    state: Arc<XhttpXmuxConnectionState>,
    lease: Option<XhttpXmuxLease>,
}

#[derive(Clone)]
struct XhttpH2PoolContext {
    manager: Arc<XhttpXmuxManager>,
    dialer: Arc<dyn XhttpStreamDialer>,
    state: Arc<XhttpXmuxConnectionState>,
}

#[derive(Clone)]
struct XhttpH3XmuxEntry {
    endpoint: Arc<quinn::Endpoint>,
    sender: XhttpH3Sender,
    state: Arc<XhttpXmuxConnectionState>,
}

struct XhttpH3XmuxSelection {
    endpoint: Arc<quinn::Endpoint>,
    sender: XhttpH3Sender,
    state: Arc<XhttpXmuxConnectionState>,
    lease: Option<XhttpXmuxLease>,
}

#[derive(Clone)]
struct XhttpH3PoolContext {
    manager: Arc<XhttpXmuxManager>,
    dialer: Arc<dyn XhttpH3Dialer>,
    state: Arc<XhttpXmuxConnectionState>,
}

impl XhttpXmuxManager {
    fn new(config: XhttpXmuxConfig) -> Self {
        Self {
            config: XhttpXmuxRuntimeConfig {
                max_concurrency: random_u64(config.max_concurrency)
                    .min(u32::MAX as u64) as u32,
                max_connections: random_u64(config.max_connections)
                    .min(usize::MAX as u64)
                    as usize,
                c_max_reuse_times: config.c_max_reuse_times,
                h_max_request_times: config.h_max_request_times,
                h_max_reusable_secs: config.h_max_reusable_secs,
                h_keep_alive_period: config.h_keep_alive_period,
            },
            h2_connections: Mutex::new(Vec::new()),
            h3_connections: Mutex::new(Vec::new()),
        }
    }

    fn h2_keep_alive_period(&self) -> Option<Duration> {
        xmux_keep_alive_period(
            self.config.h_keep_alive_period,
            DEFAULT_H2_KEEP_ALIVE_PERIOD,
        )
    }

    fn h3_keep_alive_period(&self) -> Option<Duration> {
        xmux_keep_alive_period(
            self.config.h_keep_alive_period,
            DEFAULT_H3_KEEP_ALIVE_PERIOD,
        )
    }

    async fn select_h2(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        track_tunnel: bool,
    ) -> std::io::Result<XhttpH2XmuxSelection> {
        let mut connections = self.h2_connections.lock().await;
        connections.retain(|entry| entry.state.keep_in_pool());
        let mut selected = None;
        let fill_connections = self.config.max_connections > 0
            && connections.len() < self.config.max_connections;
        if !connections.is_empty() && !fill_connections {
            let candidates = connections
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    entry
                        .state
                        .can_select(self.config.max_concurrency)
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                selected =
                    Some(candidates[rand::rng().random_range(0..candidates.len())]);
            }
        }
        let index = match selected {
            Some(index) => index,
            None => {
                let transport = dialer.dial().await?;
                let mut builder =
                    hyper::client::conn::http2::Builder::new(TokioExecutor::new());
                if let Some(period) = self.h2_keep_alive_period() {
                    builder.timer(TokioTimer::new());
                    builder.keep_alive_interval(Some(period));
                    builder.keep_alive_timeout(Duration::from_secs(20));
                    builder.keep_alive_while_idle(true);
                }
                let (sender, connection) = builder
                    .handshake::<_, XhttpOutboundBody>(TokioIo::new(transport))
                    .await
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!("XHTTP H2 handshake failed: {error}"),
                        )
                    })?;
                let state = Arc::new(XhttpXmuxConnectionState::new(self.config));
                let driver_state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(error) = connection.await {
                        debug!("XHTTP H2 connection ended: {error}");
                    }
                    driver_state.mark_closed();
                });
                connections.push(XhttpH2XmuxEntry { sender, state });
                connections.len() - 1
            }
        };
        let entry = connections[index].clone();
        if !entry.state.claim_selection(track_tunnel) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "XHTTP H2 xmux connection became unavailable",
            ));
        }
        let lease = track_tunnel.then(|| XhttpXmuxLease {
            state: Arc::clone(&entry.state),
        });
        Ok(XhttpH2XmuxSelection {
            sender: entry.sender,
            state: entry.state,
            lease,
        })
    }

    async fn select_h3(
        &self,
        dialer: Arc<dyn XhttpH3Dialer>,
        track_tunnel: bool,
        max_field_section_size: usize,
    ) -> std::io::Result<XhttpH3XmuxSelection> {
        let mut connections = self.h3_connections.lock().await;
        connections.retain(|entry| entry.state.keep_in_pool());
        let mut selected = None;
        let fill_connections = self.config.max_connections > 0
            && connections.len() < self.config.max_connections;
        if !connections.is_empty() && !fill_connections {
            let candidates = connections
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    entry
                        .state
                        .can_select(self.config.max_concurrency)
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                selected =
                    Some(candidates[rand::rng().random_range(0..candidates.len())]);
            }
        }
        let index = match selected {
            Some(index) => index,
            None => {
                let (endpoint, connection) =
                    dialer.dial_h3(self.h3_keep_alive_period()).await?;
                let h3_transport = h3_quinn::Connection::new(connection);
                let mut builder = h3::client::builder();
                builder.max_field_section_size(
                    max_field_section_size.min(u64::MAX as usize) as u64,
                );
                let (mut driver, sender) =
                    builder.build(h3_transport).await.map_err(h3_io_error)?;
                let state = Arc::new(XhttpXmuxConnectionState::new(self.config));
                let driver_state = Arc::clone(&state);
                let driver_endpoint = Arc::clone(&endpoint);
                tokio::spawn(async move {
                    let error =
                        futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
                    debug!("XHTTP H3 connection ended: {error}");
                    driver_state.mark_closed();
                    drop(driver_endpoint);
                });
                connections.push(XhttpH3XmuxEntry {
                    endpoint,
                    sender,
                    state,
                });
                connections.len() - 1
            }
        };
        let entry = connections[index].clone();
        if !entry.state.claim_selection(track_tunnel) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "XHTTP H3 xmux connection became unavailable",
            ));
        }
        let lease = track_tunnel.then(|| XhttpXmuxLease {
            state: Arc::clone(&entry.state),
        });
        Ok(XhttpH3XmuxSelection {
            endpoint: entry.endpoint,
            sender: entry.sender,
            state: entry.state,
            lease,
        })
    }
}

fn xmux_keep_alive_period(raw: i64, default: Duration) -> Option<Duration> {
    match raw {
        value if value < 0 => None,
        0 => Some(default),
        value => Some(Duration::from_secs(value as u64)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XhttpHttpVersion {
    Http1,
    Http2,
    Http3,
}

impl XhttpHttpVersion {
    pub(crate) const fn required_alpn(self) -> &'static [u8] {
        match self {
            Self::Http1 => b"http/1.1",
            Self::Http2 => b"h2",
            Self::Http3 => b"h3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpClientMode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UplinkDataPlacement {
    Body,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaddingPlacement {
    Query,
    Header,
    QueryInHeader,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaddingMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone)]
pub(crate) struct XhttpClientConfig {
    authority: String,
    http_version: XhttpHttpVersion,
    path_and_query: String,
    mode: XhttpClientMode,
    method: Method,
    headers: HeaderMap,
    no_grpc_header: bool,
    padding_from: usize,
    padding_to: usize,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: PaddingPlacement,
    padding_method: PaddingMethod,
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    uplink_data_placement: UplinkDataPlacement,
    uplink_data_key: String,
    max_each_post_bytes: (usize, usize),
    min_post_interval_ms: (u64, u64),
    uplink_chunk_size: (usize, usize),
    session_id_table: Option<String>,
    session_id_length: Option<(usize, usize)>,
    server_max_header_bytes: usize,
    xmux: Arc<XhttpXmuxManager>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiteralXhttpClientSettings {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    x_padding_bytes: Option<serde_json::Value>,
    #[serde(default, rename = "noGRPCHeader")]
    no_grpc_header: bool,
    #[serde(default, rename = "noSSEHeader")]
    _no_sse_header: bool,
    #[serde(default)]
    sc_max_each_post_bytes: Option<serde_json::Value>,
    #[serde(default)]
    sc_min_posts_interval_ms: Option<serde_json::Value>,
    #[serde(default)]
    sc_max_buffered_posts: Option<i64>,
    #[serde(default)]
    sc_stream_up_server_secs: Option<serde_json::Value>,
    #[serde(default)]
    xmux: Option<serde_json::Value>,
    #[serde(default)]
    download_settings: Option<serde_json::Value>,
    #[serde(default)]
    x_padding_obfs_mode: bool,
    #[serde(default)]
    x_padding_key: Option<String>,
    #[serde(default)]
    x_padding_header: Option<String>,
    #[serde(default)]
    x_padding_placement: Option<String>,
    #[serde(default)]
    x_padding_method: Option<String>,
    #[serde(default, rename = "uplinkHTTPMethod")]
    uplink_http_method: Option<String>,
    #[serde(default, rename = "sessionIDPlacement", alias = "sessionPlacement")]
    session_placement: Option<String>,
    #[serde(default, rename = "sessionIDKey", alias = "sessionKey")]
    session_key: Option<String>,
    #[serde(default)]
    seq_placement: Option<String>,
    #[serde(default)]
    seq_key: Option<String>,
    #[serde(default)]
    uplink_data_placement: Option<String>,
    #[serde(default)]
    uplink_data_key: Option<String>,
    #[serde(default)]
    uplink_chunk_size: Option<serde_json::Value>,
    #[serde(default)]
    server_max_header_bytes: Option<i32>,
    #[serde(default, rename = "sessionIDTable")]
    session_id_table: Option<String>,
    #[serde(default, rename = "sessionIDLength")]
    session_id_length: Option<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiteralXhttpXmuxSettings {
    #[serde(default)]
    max_concurrency: Option<serde_json::Value>,
    #[serde(default)]
    max_connections: Option<serde_json::Value>,
    #[serde(default)]
    c_max_reuse_times: Option<serde_json::Value>,
    #[serde(default)]
    h_max_request_times: Option<serde_json::Value>,
    #[serde(default)]
    h_max_reusable_secs: Option<serde_json::Value>,
    #[serde(default)]
    h_keep_alive_period: Option<i64>,
}

impl XhttpClientConfig {
    pub(crate) fn configure_http_version(
        &mut self,
        version: XhttpHttpVersion,
        outbound_tag: &str,
    ) -> Result<(), String> {
        if version == XhttpHttpVersion::Http1
            && matches!(
                self.mode,
                XhttpClientMode::StreamOne | XhttpClientMode::StreamUp
            )
        {
            return Err(format!(
                "XHTTP outbound {outbound_tag} requires packet-up or auto over HTTP/1.1 because Go HTTP/1.x servers cannot reliably read a streaming request body after flushing the response"
            ));
        }
        self.http_version = version;
        Ok(())
    }

    pub(crate) const fn mode_is_stream_one(&self) -> bool {
        matches!(self.mode, XhttpClientMode::StreamOne)
    }

    pub(crate) const fn required_alpn(&self) -> &'static [u8] {
        self.http_version.required_alpn()
    }

    pub(crate) const fn uses_http1(&self) -> bool {
        matches!(self.http_version, XhttpHttpVersion::Http1)
    }

    pub(crate) const fn uses_http3(&self) -> bool {
        matches!(self.http_version, XhttpHttpVersion::Http3)
    }

    pub(crate) fn compile(
        server: &NetLocation,
        raw: serde_json::Value,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        let settings = serde_json::from_value::<LiteralXhttpClientSettings>(raw)
            .map_err(|error| {
                format!("invalid XHTTP outbound {outbound_tag} settings: {error}")
            })?;
        let mode = parse_mode(settings.mode.as_deref(), outbound_tag)?;
        if settings.download_settings.is_some() {
            return Err(format!(
                "XHTTP outbound {outbound_tag} downloadSettings must be compiled by the transport layer"
            ));
        }
        let xmux = parse_xmux_config(settings.xmux.as_ref(), outbound_tag)?;
        let padding_placement = parse_padding_placement(
            settings.x_padding_placement.as_deref(),
            outbound_tag,
        )?;
        let padding_method = parse_padding_method(
            settings.x_padding_method.as_deref(),
            outbound_tag,
        )?;
        let padding_key = settings
            .x_padding_key
            .unwrap_or_else(|| "x_padding".to_string());
        let padding_header = settings
            .x_padding_header
            .unwrap_or_else(|| "X-Padding".to_string());
        validate_padding_config(
            settings.x_padding_obfs_mode,
            padding_placement,
            &padding_key,
            &padding_header,
            outbound_tag,
        )?;
        let session_placement = parse_placement(
            settings.session_placement.as_deref(),
            Placement::Path,
            "sessionIDPlacement",
            outbound_tag,
        )?;
        let seq_placement = parse_placement(
            settings.seq_placement.as_deref(),
            Placement::Path,
            "seqPlacement",
            outbound_tag,
        )?;
        let uplink_data_placement = parse_uplink_data_placement(
            settings.uplink_data_placement.as_deref(),
            outbound_tag,
        )?;
        let session_key = settings.session_key.unwrap_or_else(|| {
            default_meta_key(session_placement, "X-Session", "x_session")
        });
        let seq_key = settings
            .seq_key
            .unwrap_or_else(|| default_meta_key(seq_placement, "X-Seq", "x_seq"));
        let uplink_data_key = settings
            .uplink_data_key
            .unwrap_or_else(|| "X-Data".to_string());
        validate_meta_key(
            session_placement,
            &session_key,
            "sessionIDKey",
            outbound_tag,
        )?;
        validate_meta_key(seq_placement, &seq_key, "seqKey", outbound_tag)?;
        validate_uplink_data_key(
            uplink_data_placement,
            &uplink_data_key,
            outbound_tag,
        )?;

        let authority = settings
            .host
            .filter(|host| !host.trim().is_empty())
            .unwrap_or_else(|| server.to_string());
        let path_and_query = normalize_path(settings.path.as_deref());
        let method = settings
            .uplink_http_method
            .as_deref()
            .unwrap_or("POST")
            .parse::<Method>()
            .map_err(|error| {
                format!(
                    "XHTTP outbound {outbound_tag} has invalid uplinkHTTPMethod: {error}"
                )
            })?;
        let mut headers = HeaderMap::new();
        for (name, value) in settings.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                format!(
                    "XHTTP outbound {outbound_tag} has invalid header name: {error}"
                )
            })?;
            let value = HeaderValue::from_str(&value).map_err(|error| {
                format!(
                    "XHTTP outbound {outbound_tag} has invalid header value: {error}"
                )
            })?;
            headers.append(name, value);
        }
        let (padding_from, padding_to) =
            parse_padding_range(settings.x_padding_bytes.as_ref(), outbound_tag)?;
        let max_each_post_bytes = parse_usize_range(
            settings.sc_max_each_post_bytes.as_ref(),
            (DEFAULT_MAX_EACH_POST_BYTES, DEFAULT_MAX_EACH_POST_BYTES),
            "scMaxEachPostBytes",
            outbound_tag,
        )?;
        if max_each_post_bytes.0 == 0 {
            return Err(format!(
                "XHTTP outbound {outbound_tag} requires scMaxEachPostBytes > 0"
            ));
        }
        let min_post_interval = parse_u64_range(
            settings.sc_min_posts_interval_ms.as_ref(),
            (
                DEFAULT_MIN_POST_INTERVAL.as_millis() as u64,
                DEFAULT_MIN_POST_INTERVAL.as_millis() as u64,
            ),
            "scMinPostsIntervalMs",
            outbound_tag,
        )?;
        let default_chunk = match uplink_data_placement {
            UplinkDataPlacement::Body => max_each_post_bytes,
            UplinkDataPlacement::Header => (3_000, 4_000),
            UplinkDataPlacement::Cookie => (2_048, 3_072),
        };
        let mut uplink_chunk_size = parse_usize_range(
            settings.uplink_chunk_size.as_ref(),
            default_chunk,
            "uplinkChunkSize",
            outbound_tag,
        )?;
        uplink_chunk_size.0 = uplink_chunk_size.0.max(64);
        uplink_chunk_size.1 = uplink_chunk_size.1.max(uplink_chunk_size.0);
        let session_id_length = settings
            .session_id_length
            .as_ref()
            .map(|value| {
                parse_usize_range(
                    Some(value),
                    (0, 0),
                    "sessionIDLength",
                    outbound_tag,
                )
            })
            .transpose()?;
        if let Some(value) = settings.sc_max_buffered_posts
            && value <= 0
        {
            return Err(format!(
                "XHTTP outbound {outbound_tag} requires scMaxBufferedPosts > 0"
            ));
        }
        let server_max_header_bytes = settings
            .server_max_header_bytes
            .map_or(8192usize, |value| value.max(1) as usize);
        let _ = settings.sc_stream_up_server_secs;

        Ok(Self {
            authority,
            http_version: XhttpHttpVersion::Http2,
            path_and_query,
            mode,
            method,
            headers,
            no_grpc_header: settings.no_grpc_header,
            padding_from,
            padding_to,
            padding_obfs_mode: settings.x_padding_obfs_mode,
            padding_key,
            padding_header,
            padding_placement,
            padding_method,
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            uplink_data_placement,
            uplink_data_key,
            max_each_post_bytes,
            min_post_interval_ms: min_post_interval,
            uplink_chunk_size,
            session_id_table: settings.session_id_table,
            session_id_length,
            server_max_header_bytes,
            xmux: Arc::new(XhttpXmuxManager::new(xmux)),
        })
    }

    pub(crate) async fn connect_h2_with_dialer(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        secure: bool,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        if self.http_version != XhttpHttpVersion::Http2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H2 dialer provided for a non-H2 configuration",
            ));
        }
        let selection = self.xmux.select_h2(Arc::clone(&dialer), true).await?;
        let context = XhttpH2PoolContext {
            manager: Arc::clone(&self.xmux),
            dialer,
            state: Arc::clone(&selection.state),
        };
        let stream = self
            .connect_h2_sender(
                selection.sender,
                if secure { "https" } else { "http" },
                reality,
                downlink,
                Some(context),
            )
            .await?;
        let lease = selection.lease.ok_or_else(|| {
            std::io::Error::other(
                "XHTTP H2 xmux selection did not return a tunnel lease",
            )
        })?;
        Ok(Box::new(XhttpXmuxLeasedStream {
            inner: stream,
            _lease: lease,
        }))
    }

    pub(crate) async fn connect(
        &self,
        transport: Box<dyn AsyncStream>,
        secure: bool,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let scheme = if secure { "https" } else { "http" };
        if self.http_version == XhttpHttpVersion::Http1 {
            return self.connect_http1_stream_one(transport, scheme).await;
        }
        if self.http_version == XhttpHttpVersion::Http3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP HTTP/3 requires a QUIC connection",
            ));
        }

        let io = TokioIo::new(transport);
        let (sender, connection) = hyper::client::conn::http2::handshake::<
            _,
            _,
            XhttpOutboundBody,
        >(TokioExecutor::new(), io)
        .await
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("XHTTP H2 handshake failed: {error}"),
            )
        })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                debug!("XHTTP H2 connection ended: {error}");
            }
        });

        self.connect_h2_sender(sender, scheme, reality, downlink, None)
            .await
    }

    async fn connect_h2_sender(
        &self,
        sender: XhttpH2Sender,
        scheme: &str,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
        pool: Option<XhttpH2PoolContext>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let mode = match self.mode {
            XhttpClientMode::Auto if reality && downlink.is_some() => {
                XhttpClientMode::StreamUp
            }
            XhttpClientMode::Auto if reality => XhttpClientMode::StreamOne,
            XhttpClientMode::Auto => XhttpClientMode::PacketUp,
            mode => mode,
        };
        match mode {
            XhttpClientMode::StreamOne => {
                if downlink.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "XHTTP downloadSettings cannot be used with stream-one",
                    ));
                }
                if let Some(pool) = &pool {
                    pool.state.record_request();
                }
                self.connect_stream_one(sender, scheme).await
            }
            XhttpClientMode::StreamUp => {
                if let Some(pool) = &pool {
                    if downlink.is_none() {
                        pool.state.record_request();
                    }
                    pool.state.record_request();
                }
                self.connect_stream_up(sender, scheme, downlink).await
            }
            XhttpClientMode::PacketUp => {
                if let Some(pool) = &pool
                    && downlink.is_none()
                {
                    pool.state.record_request();
                }
                self.connect_packet_up(sender, scheme, downlink, pool).await
            }
            XhttpClientMode::Auto => unreachable!("XHTTP auto mode was resolved"),
        }
    }

    pub(crate) async fn open_http1_downlink(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        secure: bool,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        let scheme = if secure { "https" } else { "http" };
        self.open_http1_download(dialer, scheme, session_id).await
    }

    pub(crate) async fn open_h2_downlink(
        &self,
        transport: Box<dyn AsyncStream>,
        secure: bool,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        let io = TokioIo::new(transport);
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<
            _,
            _,
            XhttpOutboundBody,
        >(TokioExecutor::new(), io)
        .await
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("XHTTP H2 downlink handshake failed: {error}"),
            )
        })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                debug!("XHTTP H2 downlink connection ended: {error}");
            }
        });
        let scheme = if secure { "https" } else { "http" };
        let request = self.build_stream_request(
            scheme,
            Some(session_id),
            Method::GET,
            empty_body(),
            false,
        )?;
        let response = send_checked_request(&mut sender, request).await?;
        Ok(response_body_reader(response.into_body()))
    }

    pub(crate) async fn open_h2_downlink_with_dialer(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        secure: bool,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        if self.http_version != XhttpHttpVersion::Http2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H2 downlink dialer provided for a non-H2 configuration",
            ));
        }
        let selection = self.xmux.select_h2(dialer, true).await?;
        selection.state.record_request();
        let mut sender = selection.sender;
        let scheme = if secure { "https" } else { "http" };
        let request = self.build_stream_request(
            scheme,
            Some(session_id),
            Method::GET,
            empty_body(),
            false,
        )?;
        let response = send_checked_request(&mut sender, request).await?;
        let lease = selection.lease.ok_or_else(|| {
            std::io::Error::other(
                "XHTTP H2 downlink xmux selection did not return a tunnel lease",
            )
        })?;
        Ok(response_body_reader_with_lease(response.into_body(), lease))
    }

    pub(crate) async fn connect_http1_with_dialer(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        secure: bool,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        if self.http_version != XhttpHttpVersion::Http1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP HTTP/1.1 dialer provided for a non-H1 configuration",
            ));
        }
        let mode = match self.mode {
            XhttpClientMode::Auto if reality && downlink.is_some() => {
                XhttpClientMode::StreamUp
            }
            XhttpClientMode::Auto if reality => XhttpClientMode::StreamOne,
            XhttpClientMode::Auto => XhttpClientMode::PacketUp,
            mode => mode,
        };
        let scheme = if secure { "https" } else { "http" };
        match mode {
            XhttpClientMode::PacketUp => {
                self.connect_http1_packet_up(dialer, scheme, downlink).await
            }
            XhttpClientMode::StreamUp | XhttpClientMode::StreamOne => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "XHTTP HTTP/1.1 supports only packet-up because streaming request bodies are half-duplex on Go HTTP/1.x servers",
                ))
            }
            XhttpClientMode::Auto => unreachable!("XHTTP auto mode was resolved"),
        }
    }

    async fn connect_http1_packet_up(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        scheme: &str,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let reader = if let Some(downlink) = downlink {
            downlink.open_downlink(&session_id).await?
        } else {
            self.open_http1_download(dialer.clone(), scheme, &session_id)
                .await?
        };
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        let config = self.clone();
        let scheme = scheme.to_string();
        tokio::spawn(async move {
            if let Err(error) = config
                .run_http1_packet_uploader(
                    upload_reader,
                    dialer,
                    &scheme,
                    &session_id,
                )
                .await
            {
                debug!("XHTTP H1 packet uploader ended: {error}");
            }
        });
        Ok(Box::new(XhttpClientStream {
            reader,
            writer: upload_writer,
            _h3_endpoint: None,
            _h3_sender: None,
        }))
    }

    async fn connect_http1_stream_up(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        scheme: &str,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let reader = self
            .open_http1_download(dialer.clone(), scheme, &session_id)
            .await?;
        let mut upload_transport = dialer.dial().await?;
        let request = self.build_stream_request(
            scheme,
            Some(&session_id),
            self.method.clone(),
            empty_body(),
            true,
        )?;
        let request_head = serialize_http1_request_head(&request, &self.authority)?;
        upload_transport.write_all(&request_head).await?;
        upload_transport.flush().await?;
        let upload_stream = XhttpHttp1Stream::new(upload_transport);
        let (mut response_reader, mut request_writer) =
            tokio::io::split(upload_stream);
        tokio::spawn(async move {
            let mut discarded = [0u8; 8192];
            let mut total = 0usize;
            loop {
                match response_reader.read(&mut discarded).await {
                    Ok(0) => {
                        debug!(total, "XHTTP H1 stream-up response ended");
                        return;
                    }
                    Ok(length) => {
                        total += length;
                        debug!(length, total, "XHTTP H1 stream-up response data");
                    }
                    Err(error) => {
                        debug!(total, "XHTTP H1 stream-up response failed: {error}");
                        return;
                    }
                }
            }
        });
        let (upload_writer, mut upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(async move {
            let mut buffer = [0u8; 16 * 1024];
            let mut total = 0usize;
            loop {
                match upload_reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(length) => {
                        if let Err(error) =
                            request_writer.write_all(&buffer[..length]).await
                        {
                            debug!(
                                total,
                                "XHTTP H1 stream uploader failed: {error}"
                            );
                            return;
                        }
                        if let Err(error) = request_writer.flush().await {
                            debug!(
                                total,
                                "XHTTP H1 stream uploader flush failed: {error}"
                            );
                            return;
                        }
                        total += length;
                        debug!(length, total, "XHTTP H1 stream upload data");
                    }
                    Err(error) => {
                        debug!(total, "XHTTP H1 upload pipe failed: {error}");
                        return;
                    }
                }
            }
            debug!(total, "XHTTP H1 stream upload ended");
            let _ = request_writer.shutdown().await;
        });
        Ok(Box::new(XhttpClientStream {
            reader,
            writer: upload_writer,
            _h3_endpoint: None,
            _h3_sender: None,
        }))
    }

    async fn open_http1_download(
        &self,
        dialer: Arc<dyn XhttpStreamDialer>,
        scheme: &str,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        let mut transport = dialer.dial().await?;
        let request = self.build_stream_request(
            scheme,
            Some(session_id),
            Method::GET,
            empty_body(),
            false,
        )?;
        let request_head =
            serialize_http1_fixed_request(&request, &self.authority, &[])?;
        transport.write_all(&request_head).await?;
        transport.flush().await?;
        let mut response = XhttpHttp1Stream::new(transport);
        let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(async move {
            let mut buffer = [0u8; 16 * 1024];
            let mut total = 0usize;
            loop {
                match response.read(&mut buffer).await {
                    Ok(0) => {
                        debug!(total, "XHTTP H1 stream-down ended");
                        break;
                    }
                    Ok(length) => {
                        if let Err(error) = writer.write_all(&buffer[..length]).await
                        {
                            debug!(
                                total,
                                "XHTTP H1 stream-down pipe failed: {error}"
                            );
                            break;
                        }
                        total += length;
                        debug!(length, total, "XHTTP H1 stream-down data");
                    }
                    Err(error) => {
                        debug!(total, "XHTTP H1 stream-down failed: {error}");
                        break;
                    }
                }
            }
            let _ = writer.shutdown().await;
        });
        Ok(reader)
    }

    async fn run_http1_packet_uploader(
        &self,
        mut upload_reader: DuplexStream,
        dialer: Arc<dyn XhttpStreamDialer>,
        scheme: &str,
        session_id: &str,
    ) -> std::io::Result<()> {
        let mut seq = 0u64;
        let mut last_post = None;
        loop {
            let max_upload_size = random_usize(self.max_each_post_bytes);
            let mut payload = vec![0u8; max_upload_size];
            let length = upload_reader.read(&mut payload).await?;
            if length == 0 {
                return Ok(());
            }
            payload.truncate(length);
            if let Some(last_post) = last_post {
                let interval =
                    Duration::from_millis(random_u64(self.min_post_interval_ms));
                let elapsed = tokio::time::Instant::now().duration_since(last_post);
                if elapsed < interval {
                    sleep(interval - elapsed).await;
                }
            }
            let (request, body) =
                self.build_http1_packet_request(scheme, session_id, seq, &payload)?;
            let encoded =
                serialize_http1_fixed_request(&request, &self.authority, body)?;
            let mut transport = dialer.dial().await?;
            transport.write_all(&encoded).await?;
            transport.flush().await?;
            let mut response = XhttpHttp1Stream::new(transport);
            let mut discarded = Vec::new();
            response.read_to_end(&mut discarded).await?;
            last_post = Some(tokio::time::Instant::now());
            seq = seq.checked_add(1).ok_or_else(|| {
                std::io::Error::other("XHTTP packet sequence exhausted")
            })?;
        }
    }

    fn build_http1_packet_request<'a>(
        &self,
        scheme: &str,
        session_id: &str,
        seq: u64,
        payload: &'a [u8],
    ) -> std::io::Result<(Request<XhttpOutboundBody>, &'a [u8])> {
        let mut request = self.build_base_request(
            scheme,
            Some(session_id),
            Some(&seq.to_string()),
            self.method.clone(),
            empty_body(),
        )?;
        let body = match self.uplink_data_placement {
            UplinkDataPlacement::Body => payload,
            UplinkDataPlacement::Header => {
                self.apply_payload_headers(request.headers_mut(), payload)?;
                &[]
            }
            UplinkDataPlacement::Cookie => {
                self.apply_payload_cookies(request.headers_mut(), payload)?;
                &[]
            }
        };
        Ok((request, body))
    }

    pub(crate) async fn open_h3_downlink(
        &self,
        endpoint: Arc<quinn::Endpoint>,
        connection: quinn::Connection,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        let h3_transport = h3_quinn::Connection::new(connection);
        let mut builder = h3::client::builder();
        builder.max_field_section_size(
            self.server_max_header_bytes.min(u64::MAX as usize) as u64,
        );
        let (mut driver, mut sender) =
            builder.build(h3_transport).await.map_err(h3_io_error)?;
        let driver_endpoint = endpoint.clone();
        tokio::spawn(async move {
            let error = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("XHTTP H3 downlink connection ended: {error}");
            drop(driver_endpoint);
        });
        let request = self.build_h3_stream_request(
            "https",
            Some(session_id),
            Method::GET,
            false,
        )?;
        let mut stream = sender.send_request(request).await.map_err(h3_io_error)?;
        stream.finish().await.map_err(h3_io_error)?;
        let (_, recv_stream) = stream.split();
        let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(async move {
            copy_h3_response(recv_stream, &mut writer).await;
            let _ = writer.shutdown().await;
            drop(sender);
            drop(endpoint);
        });
        Ok(reader)
    }

    pub(crate) async fn open_h3_downlink_with_dialer(
        &self,
        dialer: Arc<dyn XhttpH3Dialer>,
        session_id: &str,
    ) -> std::io::Result<DuplexStream> {
        if self.http_version != XhttpHttpVersion::Http3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H3 downlink dialer provided for a non-H3 configuration",
            ));
        }
        let selection = self
            .xmux
            .select_h3(dialer, true, self.server_max_header_bytes)
            .await?;
        selection.state.record_request();
        let mut sender = selection.sender;
        let endpoint = selection.endpoint;
        let request = self.build_h3_stream_request(
            "https",
            Some(session_id),
            Method::GET,
            false,
        )?;
        let mut stream = sender.send_request(request).await.map_err(h3_io_error)?;
        stream.finish().await.map_err(h3_io_error)?;
        let (_, recv_stream) = stream.split();
        let lease = selection.lease.ok_or_else(|| {
            std::io::Error::other(
                "XHTTP H3 downlink xmux selection did not return a tunnel lease",
            )
        })?;
        let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(async move {
            copy_h3_response(recv_stream, &mut writer).await;
            let _ = writer.shutdown().await;
            drop(sender);
            drop(endpoint);
            drop(lease);
        });
        Ok(reader)
    }

    pub(crate) async fn connect_h3_with_dialer(
        &self,
        dialer: Arc<dyn XhttpH3Dialer>,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        if self.http_version != XhttpHttpVersion::Http3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H3 dialer provided for a non-H3 configuration",
            ));
        }
        let selection = self
            .xmux
            .select_h3(Arc::clone(&dialer), true, self.server_max_header_bytes)
            .await?;
        let context = XhttpH3PoolContext {
            manager: Arc::clone(&self.xmux),
            dialer,
            state: Arc::clone(&selection.state),
        };
        let stream = self
            .connect_h3_sender(
                selection.sender,
                selection.endpoint,
                reality,
                downlink,
                Some(context),
            )
            .await?;
        let lease = selection.lease.ok_or_else(|| {
            std::io::Error::other(
                "XHTTP H3 xmux selection did not return a tunnel lease",
            )
        })?;
        Ok(Box::new(XhttpXmuxLeasedStream {
            inner: stream,
            _lease: lease,
        }))
    }

    pub(crate) async fn connect_h3(
        &self,
        endpoint: Arc<quinn::Endpoint>,
        connection: quinn::Connection,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        if self.http_version != XhttpHttpVersion::Http3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP QUIC connection provided for a non-H3 configuration",
            ));
        }
        let h3_transport = h3_quinn::Connection::new(connection);
        let mut builder = h3::client::builder();
        builder.max_field_section_size(
            self.server_max_header_bytes.min(u64::MAX as usize) as u64,
        );
        let (mut driver, sender) =
            builder.build(h3_transport).await.map_err(h3_io_error)?;
        let driver_endpoint = endpoint.clone();
        tokio::spawn(async move {
            let error = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("XHTTP H3 connection ended: {error}");
            drop(driver_endpoint);
        });

        self.connect_h3_sender(sender, endpoint, reality, downlink, None)
            .await
    }

    async fn connect_h3_sender(
        &self,
        sender: XhttpH3Sender,
        endpoint: Arc<quinn::Endpoint>,
        reality: bool,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
        pool: Option<XhttpH3PoolContext>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let mode = match self.mode {
            XhttpClientMode::Auto if reality && downlink.is_some() => {
                XhttpClientMode::StreamUp
            }
            XhttpClientMode::Auto if reality => XhttpClientMode::StreamOne,
            XhttpClientMode::Auto => XhttpClientMode::PacketUp,
            mode => mode,
        };
        match mode {
            XhttpClientMode::StreamOne => {
                if downlink.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "XHTTP downloadSettings cannot be used with stream-one",
                    ));
                }
                if let Some(pool) = &pool {
                    pool.state.record_request();
                }
                self.connect_h3_stream_one(sender, endpoint).await
            }
            XhttpClientMode::StreamUp => {
                if let Some(pool) = &pool {
                    if downlink.is_none() {
                        pool.state.record_request();
                    }
                    pool.state.record_request();
                }
                self.connect_h3_stream_up(sender, endpoint, downlink).await
            }
            XhttpClientMode::PacketUp => {
                if let Some(pool) = &pool
                    && downlink.is_none()
                {
                    pool.state.record_request();
                }
                self.connect_h3_packet_up(sender, endpoint, downlink, pool)
                    .await
            }
            XhttpClientMode::Auto => unreachable!("XHTTP auto mode was resolved"),
        }
    }

    async fn connect_h3_stream_one(
        &self,
        mut sender: XhttpH3Sender,
        endpoint: Arc<quinn::Endpoint>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let request =
            self.build_h3_stream_request("https", None, self.method.clone(), true)?;
        let stream = sender.send_request(request).await.map_err(h3_io_error)?;
        let (send_stream, recv_stream) = stream.split();
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(run_h3_stream_upload(upload_reader, send_stream));
        Ok(Box::new(XhttpClientStream {
            reader: h3_response_body_reader(recv_stream),
            writer: upload_writer,
            _h3_endpoint: Some(endpoint),
            _h3_sender: Some(sender),
        }))
    }

    async fn connect_h3_stream_up(
        &self,
        mut sender: XhttpH3Sender,
        endpoint: Arc<quinn::Endpoint>,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let down_reader = if let Some(downlink) = downlink {
            downlink.open_downlink(&session_id).await?
        } else {
            let down_request = self.build_h3_stream_request(
                "https",
                Some(&session_id),
                Method::GET,
                false,
            )?;
            let mut down_stream = sender
                .send_request(down_request)
                .await
                .map_err(h3_io_error)?;
            down_stream.finish().await.map_err(h3_io_error)?;
            let (_, down_recv) = down_stream.split();
            h3_response_body_reader(down_recv)
        };

        let up_request = self.build_h3_stream_request(
            "https",
            Some(&session_id),
            self.method.clone(),
            true,
        )?;
        let up_stream =
            sender.send_request(up_request).await.map_err(h3_io_error)?;
        let (up_send, up_recv) = up_stream.split();
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        tokio::spawn(run_h3_stream_upload(upload_reader, up_send));
        tokio::spawn(drain_h3_response(up_recv));

        Ok(Box::new(XhttpClientStream {
            reader: down_reader,
            writer: upload_writer,
            _h3_endpoint: Some(endpoint),
            _h3_sender: Some(sender),
        }))
    }

    async fn connect_h3_packet_up(
        &self,
        mut sender: XhttpH3Sender,
        endpoint: Arc<quinn::Endpoint>,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
        pool: Option<XhttpH3PoolContext>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let down_reader = if let Some(downlink) = downlink {
            downlink.open_downlink(&session_id).await?
        } else {
            let down_request = self.build_h3_stream_request(
                "https",
                Some(&session_id),
                Method::GET,
                false,
            )?;
            let mut down_stream = sender
                .send_request(down_request)
                .await
                .map_err(h3_io_error)?;
            down_stream.finish().await.map_err(h3_io_error)?;
            let (_, down_recv) = down_stream.split();
            h3_response_body_reader(down_recv)
        };

        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        let config = self.clone();
        let sender_guard = sender.clone();
        tokio::spawn(async move {
            if let Err(error) = config
                .run_h3_packet_uploader(upload_reader, sender, &session_id, pool)
                .await
            {
                debug!("XHTTP H3 packet uploader ended: {error}");
            }
        });
        Ok(Box::new(XhttpClientStream {
            reader: down_reader,
            writer: upload_writer,
            _h3_endpoint: Some(endpoint),
            _h3_sender: Some(sender_guard),
        }))
    }

    async fn run_h3_packet_uploader(
        &self,
        mut upload_reader: DuplexStream,
        mut sender: XhttpH3Sender,
        session_id: &str,
        mut pool: Option<XhttpH3PoolContext>,
    ) -> std::io::Result<()> {
        let mut seq = 0u64;
        let mut last_post = None;
        loop {
            let max_upload_size = random_usize(self.max_each_post_bytes);
            let mut payload = vec![0u8; max_upload_size];
            let length = upload_reader.read(&mut payload).await?;
            if length == 0 {
                return Ok(());
            }
            payload.truncate(length);
            if let Some(last_post) = last_post {
                let interval =
                    Duration::from_millis(random_u64(self.min_post_interval_ms));
                let elapsed = tokio::time::Instant::now().duration_since(last_post);
                if elapsed < interval {
                    sleep(interval - elapsed).await;
                }
            }
            if let Some(context) = &mut pool {
                if context.state.should_rotate_requests() {
                    let selection = context
                        .manager
                        .select_h3(
                            Arc::clone(&context.dialer),
                            false,
                            self.server_max_header_bytes,
                        )
                        .await?;
                    sender = selection.sender;
                    context.state = selection.state;
                }
                context.state.record_request();
            }
            let payload = Bytes::from(payload);
            let request = self.build_h3_packet_request(session_id, seq, &payload)?;
            let mut stream =
                sender.send_request(request).await.map_err(h3_io_error)?;
            if self.uplink_data_placement == UplinkDataPlacement::Body {
                stream.send_data(payload).await.map_err(h3_io_error)?;
            }
            stream.finish().await.map_err(h3_io_error)?;
            let response = stream.recv_response().await.map_err(h3_io_error)?;
            if !response.status().is_success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("XHTTP H3 server returned status {}", response.status()),
                ));
            }
            while stream.recv_data().await.map_err(h3_io_error)?.is_some() {}
            last_post = Some(tokio::time::Instant::now());
            seq = seq.checked_add(1).ok_or_else(|| {
                std::io::Error::other("XHTTP packet sequence exhausted")
            })?;
        }
    }

    fn build_h3_stream_request(
        &self,
        scheme: &str,
        session_id: Option<&str>,
        method: Method,
        has_body: bool,
    ) -> std::io::Result<Request<()>> {
        let request = self.build_stream_request(
            scheme,
            session_id,
            method,
            empty_body(),
            has_body,
        )?;
        let (parts, _) = request.into_parts();
        Ok(Request::from_parts(parts, ()))
    }

    fn build_h3_packet_request(
        &self,
        session_id: &str,
        seq: u64,
        payload: &[u8],
    ) -> std::io::Result<Request<()>> {
        let mut request = self.build_base_request(
            "https",
            Some(session_id),
            Some(&seq.to_string()),
            self.method.clone(),
            empty_body(),
        )?;
        match self.uplink_data_placement {
            UplinkDataPlacement::Body => {}
            UplinkDataPlacement::Header => {
                self.apply_payload_headers(request.headers_mut(), payload)?
            }
            UplinkDataPlacement::Cookie => {
                self.apply_payload_cookies(request.headers_mut(), payload)?
            }
        }
        let (parts, _) = request.into_parts();
        Ok(Request::from_parts(parts, ()))
    }

    async fn connect_http1_stream_one(
        &self,
        mut transport: Box<dyn AsyncStream>,
        scheme: &str,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let request = self.build_stream_request(
            scheme,
            None,
            self.method.clone(),
            empty_body(),
            true,
        )?;
        let request_head = serialize_http1_request_head(&request, &self.authority)?;
        transport.write_all(&request_head).await?;
        transport.flush().await?;
        Ok(Box::new(XhttpHttp1Stream::new(transport)))
    }

    async fn connect_stream_one(
        &self,
        mut sender: XhttpH2Sender,
        scheme: &str,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        let request = self.build_stream_request(
            scheme,
            None,
            self.method.clone(),
            stream_body(upload_reader),
            true,
        )?;
        let response = send_checked_request(&mut sender, request).await?;
        Ok(Box::new(XhttpClientStream {
            reader: response_body_reader(response.into_body()),
            writer: upload_writer,
            _h3_endpoint: None,
            _h3_sender: None,
        }))
    }

    async fn connect_stream_up(
        &self,
        mut sender: XhttpH2Sender,
        scheme: &str,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let down_reader = if let Some(downlink) = downlink {
            downlink.open_downlink(&session_id).await?
        } else {
            let down_request = self.build_stream_request(
                scheme,
                Some(&session_id),
                Method::GET,
                empty_body(),
                false,
            )?;
            let down_response =
                send_checked_request(&mut sender, down_request).await?;
            response_body_reader(down_response.into_body())
        };
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        let up_request = self.build_stream_request(
            scheme,
            Some(&session_id),
            self.method.clone(),
            stream_body(upload_reader),
            true,
        )?;
        let up_response = send_checked_request(&mut sender, up_request).await?;
        tokio::spawn(drain_response_body(up_response.into_body()));
        Ok(Box::new(XhttpClientStream {
            reader: down_reader,
            writer: upload_writer,
            _h3_endpoint: None,
            _h3_sender: None,
        }))
    }

    async fn connect_packet_up(
        &self,
        mut sender: XhttpH2Sender,
        scheme: &str,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
        pool: Option<XhttpH2PoolContext>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let session_id = self.generate_session_id();
        let down_reader = if let Some(downlink) = downlink {
            downlink.open_downlink(&session_id).await?
        } else {
            let down_request = self.build_stream_request(
                scheme,
                Some(&session_id),
                Method::GET,
                empty_body(),
                false,
            )?;
            let down_response =
                send_checked_request(&mut sender, down_request).await?;
            response_body_reader(down_response.into_body())
        };
        let (upload_writer, upload_reader) = duplex(XHTTP_PIPE_CAPACITY);
        let config = self.clone();
        let scheme = scheme.to_string();
        tokio::spawn(async move {
            if let Err(error) = config
                .run_packet_uploader(
                    upload_reader,
                    sender,
                    &scheme,
                    &session_id,
                    pool,
                )
                .await
            {
                debug!("XHTTP packet uploader ended: {error}");
            }
        });
        Ok(Box::new(XhttpClientStream {
            reader: down_reader,
            writer: upload_writer,
            _h3_endpoint: None,
            _h3_sender: None,
        }))
    }

    async fn run_packet_uploader(
        &self,
        mut upload_reader: DuplexStream,
        mut sender: XhttpH2Sender,
        scheme: &str,
        session_id: &str,
        mut pool: Option<XhttpH2PoolContext>,
    ) -> std::io::Result<()> {
        let mut seq = 0u64;
        let mut last_post = None;
        loop {
            let max_upload_size = random_usize(self.max_each_post_bytes);
            let mut payload = vec![0u8; max_upload_size];
            let length = upload_reader.read(&mut payload).await?;
            if length == 0 {
                return Ok(());
            }
            payload.truncate(length);
            if let Some(last_post) = last_post {
                let interval =
                    Duration::from_millis(random_u64(self.min_post_interval_ms));
                let elapsed = tokio::time::Instant::now().duration_since(last_post);
                if elapsed < interval {
                    sleep(interval - elapsed).await;
                }
            }
            if let Some(context) = &mut pool {
                if context.state.should_rotate_requests() {
                    let selection = context
                        .manager
                        .select_h2(Arc::clone(&context.dialer), false)
                        .await?;
                    sender = selection.sender;
                    context.state = selection.state;
                }
                context.state.record_request();
            }
            let request = self.build_packet_request(
                scheme,
                session_id,
                seq,
                Bytes::from(payload),
            )?;
            let response = send_checked_request(&mut sender, request).await?;
            drain_response_body(response.into_body()).await;
            last_post = Some(tokio::time::Instant::now());
            seq = seq.checked_add(1).ok_or_else(|| {
                std::io::Error::other("XHTTP packet sequence exhausted")
            })?;
        }
    }

    fn build_stream_request(
        &self,
        scheme: &str,
        session_id: Option<&str>,
        method: Method,
        body: XhttpOutboundBody,
        has_body: bool,
    ) -> std::io::Result<Request<XhttpOutboundBody>> {
        let mut request =
            self.build_base_request(scheme, session_id, None, method, body)?;
        if has_body && !self.no_grpc_header {
            request
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        }
        Ok(request)
    }

    fn build_packet_request(
        &self,
        scheme: &str,
        session_id: &str,
        seq: u64,
        payload: Bytes,
    ) -> std::io::Result<Request<XhttpOutboundBody>> {
        let body = match self.uplink_data_placement {
            UplinkDataPlacement::Body => full_body(payload.clone()),
            UplinkDataPlacement::Header | UplinkDataPlacement::Cookie => {
                empty_body()
            }
        };
        let mut request = self.build_base_request(
            scheme,
            Some(session_id),
            Some(&seq.to_string()),
            self.method.clone(),
            body,
        )?;
        match self.uplink_data_placement {
            UplinkDataPlacement::Body => {}
            UplinkDataPlacement::Header => {
                self.apply_payload_headers(request.headers_mut(), &payload)?
            }
            UplinkDataPlacement::Cookie => {
                self.apply_payload_cookies(request.headers_mut(), &payload)?
            }
        }
        Ok(request)
    }

    fn build_base_request(
        &self,
        scheme: &str,
        session_id: Option<&str>,
        seq: Option<&str>,
        method: Method,
        body: XhttpOutboundBody,
    ) -> std::io::Result<Request<XhttpOutboundBody>> {
        let (uri_string, headers) = self.request_target(scheme, session_id, seq)?;
        let uri = uri_string.parse::<Uri>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid XHTTP request URI: {error}"),
            )
        })?;
        let mut request = Request::new(body);
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        *request.headers_mut() = headers;
        self.apply_padding(&mut request, &uri_string)?;
        Ok(request)
    }

    fn request_target(
        &self,
        scheme: &str,
        session_id: Option<&str>,
        seq: Option<&str>,
    ) -> std::io::Result<(String, HeaderMap)> {
        let (base_path, base_query) = self
            .path_and_query
            .split_once('?')
            .map_or((self.path_and_query.as_str(), None), |(path, query)| {
                (path, Some(query))
            });
        let mut path = base_path.to_string();
        let mut query = base_query.map(ToOwned::to_owned);
        let mut headers = self.headers.clone();
        let mut cookies = Vec::new();
        if let Some(session_id) = session_id {
            apply_meta(
                session_id,
                self.session_placement,
                &self.session_key,
                &mut path,
                &mut query,
                &mut headers,
                &mut cookies,
            )?;
        }
        if let Some(seq) = seq {
            apply_meta(
                seq,
                self.seq_placement,
                &self.seq_key,
                &mut path,
                &mut query,
                &mut headers,
                &mut cookies,
            )?;
        }
        apply_cookies(&mut headers, cookies)?;
        let path_and_query = query
            .filter(|query| !query.is_empty())
            .map_or(path.clone(), |query| format!("{path}?{query}"));
        Ok((
            format!("{scheme}://{}{path_and_query}", self.authority),
            headers,
        ))
    }

    fn apply_padding(
        &self,
        request: &mut Request<XhttpOutboundBody>,
        raw_url: &str,
    ) -> std::io::Result<()> {
        let target_length = random_usize((self.padding_from, self.padding_to));
        let padding = if self.padding_obfs_mode {
            generate_client_padding(self.padding_method, target_length)
        } else {
            "X".repeat(target_length)
        };
        if !self.padding_obfs_mode {
            let referer = set_url_query(raw_url, "x_padding", &padding, false);
            request.headers_mut().insert(
                REFERER,
                HeaderValue::from_str(&referer).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid XHTTP Referer header: {error}"),
                    )
                })?,
            );
            return Ok(());
        }

        match self.padding_placement {
            PaddingPlacement::Query => {
                let updated = set_url_query(
                    &request.uri().to_string(),
                    &self.padding_key,
                    &padding,
                    true,
                );
                *request.uri_mut() = updated.parse::<Uri>().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid XHTTP padded URI: {error}"),
                    )
                })?;
            }
            PaddingPlacement::Header => {
                let name = HeaderName::from_bytes(self.padding_header.as_bytes())
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid XHTTP padding header: {error}"),
                        )
                    })?;
                let value = HeaderValue::from_str(&padding).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid XHTTP padding header value: {error}"),
                    )
                })?;
                request.headers_mut().insert(name, value);
            }
            PaddingPlacement::QueryInHeader => {
                let name = HeaderName::from_bytes(self.padding_header.as_bytes())
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid XHTTP padding header: {error}"),
                        )
                    })?;
                let value =
                    set_url_query(raw_url, &self.padding_key, &padding, false);
                request.headers_mut().insert(
                    name,
                    HeaderValue::from_str(&value).map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "invalid XHTTP query-in-header padding: {error}"
                            ),
                        )
                    })?,
                );
            }
            PaddingPlacement::Cookie => {
                apply_cookies(
                    request.headers_mut(),
                    vec![format!("{}={padding}", self.padding_key)],
                )?;
            }
        }
        Ok(())
    }

    fn apply_payload_headers(
        &self,
        headers: &mut HeaderMap,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let length_name = HeaderName::from_bytes(
            format!("{}-Length", self.uplink_data_key).as_bytes(),
        )
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid XHTTP payload length header: {error}"),
            )
        })?;
        let length_value = HeaderValue::from_str(&encoded.len().to_string())
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP payload length value: {error}"),
                )
            })?;
        headers.insert(length_name, length_value);
        for (index, chunk) in
            split_encoded(&encoded, self.uplink_chunk_size).enumerate()
        {
            let name = HeaderName::from_bytes(
                format!("{}-{index}", self.uplink_data_key).as_bytes(),
            )
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP payload header: {error}"),
                )
            })?;
            let value = HeaderValue::from_str(chunk).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP payload header value: {error}"),
                )
            })?;
            headers.insert(name, value);
        }
        Ok(())
    }

    fn apply_payload_cookies(
        &self,
        headers: &mut HeaderMap,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let cookies = split_encoded(&encoded, self.uplink_chunk_size)
            .enumerate()
            .map(|(index, chunk)| {
                format!("{}_{index}={chunk}", self.uplink_data_key)
            })
            .collect::<Vec<_>>();
        apply_cookies(headers, cookies)
    }

    fn generate_session_id(&self) -> String {
        let Some(length_range) = self.session_id_length else {
            return uuid::Uuid::new_v4().to_string();
        };
        let Some(table) = self.session_id_table.as_deref() else {
            return uuid::Uuid::new_v4().to_string();
        };
        let table = predefined_session_table(table).unwrap_or(table);
        if table.is_empty() {
            return uuid::Uuid::new_v4().to_string();
        }
        let bytes = table.as_bytes();
        let length = random_usize(length_range);
        if length == 0 {
            return uuid::Uuid::new_v4().to_string();
        }
        let mut id = String::with_capacity(length);
        let mut rng = rand::rng();
        for _ in 0..length {
            id.push(bytes[rng.random_range(0..bytes.len())] as char);
        }
        id
    }
}

fn parse_mode(
    mode: Option<&str>,
    outbound_tag: &str,
) -> Result<XhttpClientMode, String> {
    match mode
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "auto" => Ok(XhttpClientMode::Auto),
        "stream-one" | "streamone" => Ok(XhttpClientMode::StreamOne),
        "stream-up" | "streamup" => Ok(XhttpClientMode::StreamUp),
        "packet-up" | "packetup" => Ok(XhttpClientMode::PacketUp),
        other => Err(format!(
            "XHTTP outbound {outbound_tag} uses unsupported mode {other}"
        )),
    }
}

fn parse_placement(
    placement: Option<&str>,
    default: Placement,
    field: &str,
    outbound_tag: &str,
) -> Result<Placement, String> {
    match placement
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" => Ok(default),
        "path" => Ok(Placement::Path),
        "query" => Ok(Placement::Query),
        "header" => Ok(Placement::Header),
        "cookie" => Ok(Placement::Cookie),
        other => Err(format!(
            "XHTTP outbound {outbound_tag} has unsupported {field} {other}"
        )),
    }
}

fn parse_padding_placement(
    placement: Option<&str>,
    outbound_tag: &str,
) -> Result<PaddingPlacement, String> {
    match placement
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "queryinheader" | "query-in-header" => {
            Ok(PaddingPlacement::QueryInHeader)
        }
        "query" => Ok(PaddingPlacement::Query),
        "header" => Ok(PaddingPlacement::Header),
        "cookie" => Ok(PaddingPlacement::Cookie),
        other => Err(format!(
            "XHTTP outbound {outbound_tag} has unsupported xPaddingPlacement {other}"
        )),
    }
}

fn parse_padding_method(
    method: Option<&str>,
    outbound_tag: &str,
) -> Result<PaddingMethod, String> {
    match method
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "repeat-x" | "repeatx" => Ok(PaddingMethod::RepeatX),
        "tokenish" => Ok(PaddingMethod::Tokenish),
        other => Err(format!(
            "XHTTP outbound {outbound_tag} has unsupported xPaddingMethod {other}"
        )),
    }
}

fn validate_padding_config(
    obfs_mode: bool,
    placement: PaddingPlacement,
    key: &str,
    header: &str,
    outbound_tag: &str,
) -> Result<(), String> {
    if !obfs_mode {
        return Ok(());
    }
    if key.trim().is_empty() {
        return Err(format!(
            "XHTTP outbound {outbound_tag} requires non-empty xPaddingKey"
        ));
    }
    if matches!(
        placement,
        PaddingPlacement::Header | PaddingPlacement::QueryInHeader
    ) {
        if header.trim().is_empty() {
            return Err(format!(
                "XHTTP outbound {outbound_tag} requires non-empty xPaddingHeader"
            ));
        }
        HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            format!(
                "XHTTP outbound {outbound_tag} has invalid xPaddingHeader: {error}"
            )
        })?;
    }
    if placement == PaddingPlacement::Cookie
        && (key.bytes().any(|byte| {
            byte <= 0x20
                || byte >= 0x7f
                || matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        }))
    {
        return Err(format!(
            "XHTTP outbound {outbound_tag} has invalid cookie xPaddingKey"
        ));
    }
    Ok(())
}

fn parse_uplink_data_placement(
    placement: Option<&str>,
    outbound_tag: &str,
) -> Result<UplinkDataPlacement, String> {
    match placement
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "auto" | "body" => Ok(UplinkDataPlacement::Body),
        "header" => Ok(UplinkDataPlacement::Header),
        "cookie" => Ok(UplinkDataPlacement::Cookie),
        other => Err(format!(
            "XHTTP outbound {outbound_tag} has unsupported uplinkDataPlacement {other}"
        )),
    }
}

fn default_meta_key(
    placement: Placement,
    header_key: &str,
    other_key: &str,
) -> String {
    match placement {
        Placement::Header => header_key.to_string(),
        Placement::Query | Placement::Cookie => other_key.to_string(),
        Placement::Path => String::new(),
    }
}

fn validate_meta_key(
    placement: Placement,
    key: &str,
    field: &str,
    outbound_tag: &str,
) -> Result<(), String> {
    if placement != Placement::Path && key.trim().is_empty() {
        return Err(format!(
            "XHTTP outbound {outbound_tag} requires non-empty {field}"
        ));
    }
    if placement == Placement::Header {
        HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
            format!("XHTTP outbound {outbound_tag} has invalid {field}: {error}")
        })?;
    }
    Ok(())
}

fn validate_uplink_data_key(
    placement: UplinkDataPlacement,
    key: &str,
    outbound_tag: &str,
) -> Result<(), String> {
    if placement != UplinkDataPlacement::Body && key.trim().is_empty() {
        return Err(format!(
            "XHTTP outbound {outbound_tag} requires non-empty uplinkDataKey"
        ));
    }
    Ok(())
}

fn parse_xmux_config(
    value: Option<&serde_json::Value>,
    outbound_tag: &str,
) -> Result<XhttpXmuxConfig, String> {
    let Some(value) = value else {
        return Ok(XhttpXmuxConfig::default());
    };
    let settings = serde_json::from_value::<LiteralXhttpXmuxSettings>(value.clone())
        .map_err(|error| {
            format!("invalid XHTTP outbound {outbound_tag} xmux: {error}")
        })?;
    Ok(XhttpXmuxConfig {
        max_concurrency: parse_u64_range(
            settings.max_concurrency.as_ref(),
            (0, 0),
            "xmux.maxConcurrency",
            outbound_tag,
        )?,
        max_connections: parse_u64_range(
            settings.max_connections.as_ref(),
            (0, 0),
            "xmux.maxConnections",
            outbound_tag,
        )?,
        c_max_reuse_times: parse_u64_range(
            settings.c_max_reuse_times.as_ref(),
            (0, 0),
            "xmux.cMaxReuseTimes",
            outbound_tag,
        )?,
        h_max_request_times: parse_u64_range(
            settings.h_max_request_times.as_ref(),
            (0, 0),
            "xmux.hMaxRequestTimes",
            outbound_tag,
        )?,
        h_max_reusable_secs: parse_u64_range(
            settings.h_max_reusable_secs.as_ref(),
            (0, 0),
            "xmux.hMaxReusableSecs",
            outbound_tag,
        )?,
        h_keep_alive_period: settings.h_keep_alive_period.unwrap_or(0),
    })
}

fn parse_usize_range(
    value: Option<&serde_json::Value>,
    default: (usize, usize),
    field: &str,
    outbound_tag: &str,
) -> Result<(usize, usize), String> {
    let (from, to) = parse_u64_range(
        value,
        (default.0 as u64, default.1 as u64),
        field,
        outbound_tag,
    )?;
    Ok((
        usize::try_from(from).map_err(|_| {
            format!("XHTTP outbound {outbound_tag} {field} is too large")
        })?,
        usize::try_from(to).map_err(|_| {
            format!("XHTTP outbound {outbound_tag} {field} is too large")
        })?,
    ))
}

fn parse_u64_range(
    value: Option<&serde_json::Value>,
    default: (u64, u64),
    field: &str,
    outbound_tag: &str,
) -> Result<(u64, u64), String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parse_number = |text: &str| {
        text.trim().parse::<u64>().map_err(|_| {
            format!("XHTTP outbound {outbound_tag} has invalid {field}")
        })
    };
    let range = match value {
        serde_json::Value::Number(number) => {
            let value = number.as_u64().ok_or_else(|| {
                format!("XHTTP outbound {outbound_tag} has invalid {field}")
            })?;
            (value, value)
        }
        serde_json::Value::String(text) => {
            if let Some((from, to)) = text.split_once('-') {
                (parse_number(from)?, parse_number(to)?)
            } else {
                let value = parse_number(text)?;
                (value, value)
            }
        }
        serde_json::Value::Object(object) => {
            let from = object
                .get("from")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(default.0);
            let to = object
                .get("to")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(from);
            (from, to)
        }
        _ => {
            return Err(format!(
                "XHTTP outbound {outbound_tag} has invalid {field}"
            ));
        }
    };
    if range.1 < range.0 {
        return Err(format!(
            "XHTTP outbound {outbound_tag} requires {field}.from <= to"
        ));
    }
    Ok(range)
}

fn empty_body() -> XhttpOutboundBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn full_body(payload: Bytes) -> XhttpOutboundBody {
    Full::new(payload)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn stream_body(reader: DuplexStream) -> XhttpOutboundBody {
    let stream = ReaderStream::new(reader).map(|result| result.map(Frame::data));
    StreamBody::new(stream).boxed_unsync()
}

async fn send_checked_request(
    sender: &mut XhttpH2Sender,
    request: Request<XhttpOutboundBody>,
) -> std::io::Result<hyper::Response<hyper::body::Incoming>> {
    let response = sender.send_request(request).await.map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            format!("XHTTP request failed: {error}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("XHTTP server returned status {}", response.status()),
        ));
    }
    Ok(response)
}

async fn drain_response_body(mut body: hyper::body::Incoming) {
    while let Some(frame) = body.frame().await {
        if let Err(error) = frame {
            debug!("XHTTP response body drain failed: {error}");
            break;
        }
    }
}

fn response_body_reader(body: hyper::body::Incoming) -> DuplexStream {
    let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
    tokio::spawn(async move {
        copy_response_body(body, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    reader
}

fn response_body_reader_with_lease(
    body: hyper::body::Incoming,
    lease: XhttpXmuxLease,
) -> DuplexStream {
    let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
    tokio::spawn(async move {
        copy_response_body(body, &mut writer).await;
        let _ = writer.shutdown().await;
        drop(lease);
    });
    reader
}

async fn copy_response_body(
    mut body: hyper::body::Incoming,
    writer: &mut DuplexStream,
) {
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                debug!("XHTTP response body failed: {error}");
                break;
            }
        };
        if let Ok(data) = frame.into_data()
            && writer.write_all(&data).await.is_err()
        {
            break;
        }
    }
}

fn h3_io_error(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(format!("XHTTP H3 error: {error}"))
}

async fn run_h3_stream_upload(
    mut reader: DuplexStream,
    mut stream: XhttpH3SendStream,
) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => {
                if let Err(error) = stream
                    .send_data(Bytes::copy_from_slice(&buffer[..length]))
                    .await
                {
                    debug!("XHTTP H3 stream upload failed: {error}");
                    return;
                }
            }
            Err(error) => {
                debug!("XHTTP H3 upload pipe failed: {error}");
                return;
            }
        }
    }
    if let Err(error) = stream.finish().await {
        debug!("XHTTP H3 stream finish failed: {error}");
    }
}

fn h3_response_body_reader(stream: XhttpH3RecvStream) -> DuplexStream {
    let (mut writer, reader) = duplex(XHTTP_PIPE_CAPACITY);
    tokio::spawn(async move {
        copy_h3_response(stream, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    reader
}

async fn copy_h3_response(mut stream: XhttpH3RecvStream, writer: &mut DuplexStream) {
    let response = match stream.recv_response().await {
        Ok(response) => response,
        Err(error) => {
            debug!("XHTTP H3 response header failed: {error}");
            return;
        }
    };
    if !response.status().is_success() {
        debug!("XHTTP H3 server returned status {}", response.status());
        return;
    }
    loop {
        match stream.recv_data().await {
            Ok(Some(mut data)) => {
                let bytes = data.copy_to_bytes(data.remaining());
                if writer.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(error) => {
                debug!("XHTTP H3 response body failed: {error}");
                return;
            }
        }
    }
}

async fn drain_h3_response(mut stream: XhttpH3RecvStream) {
    let response = match stream.recv_response().await {
        Ok(response) => response,
        Err(error) => {
            debug!("XHTTP H3 upload response failed: {error}");
            return;
        }
    };
    if !response.status().is_success() {
        debug!("XHTTP H3 upload returned status {}", response.status());
    }
    loop {
        match stream.recv_data().await {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(error) => {
                debug!("XHTTP H3 upload response body failed: {error}");
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_meta(
    value: &str,
    placement: Placement,
    key: &str,
    path: &mut String,
    query: &mut Option<String>,
    headers: &mut HeaderMap,
    cookies: &mut Vec<String>,
) -> std::io::Result<()> {
    match placement {
        Placement::Path => append_path_value(path, value),
        Placement::Query => append_query_value(query, key, value),
        Placement::Header => {
            let name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP metadata header: {error}"),
                )
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid XHTTP metadata value: {error}"),
                )
            })?;
            headers.insert(name, value);
        }
        Placement::Cookie => cookies.push(format!("{key}={value}")),
    }
    Ok(())
}

fn append_path_value(path: &mut String, value: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(value);
}

fn append_query_value(query: &mut Option<String>, key: &str, value: &str) {
    let query = query.get_or_insert_with(String::new);
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(key);
    query.push('=');
    query.push_str(value);
}

fn apply_cookies(
    headers: &mut HeaderMap,
    mut cookies: Vec<String>,
) -> std::io::Result<()> {
    if cookies.is_empty() {
        return Ok(());
    }
    if let Some(existing) = headers.remove(COOKIE) {
        let existing = existing.to_str().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid XHTTP Cookie header: {error}"),
            )
        })?;
        if !existing.trim().is_empty() {
            cookies.insert(0, existing.to_string());
        }
    }
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookies.join("; ")).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid XHTTP Cookie header: {error}"),
            )
        })?,
    );
    Ok(())
}

struct EncodedChunks<'a> {
    remaining: &'a str,
    range: (usize, usize),
}

impl<'a> Iterator for EncodedChunks<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let length = random_usize(self.range).min(self.remaining.len()).max(1);
        let (chunk, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Some(chunk)
    }
}

fn split_encoded(encoded: &str, range: (usize, usize)) -> EncodedChunks<'_> {
    EncodedChunks {
        remaining: encoded,
        range,
    }
}

fn predefined_session_table(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        }
        "base64raw" => {
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        }
        "base64url" => {
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        }
        "base62" => {
            Some("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        }
        "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
        "hex" => Some("0123456789abcdef"),
        "number" => Some("0123456789"),
        _ => None,
    }
}

fn random_usize(range: (usize, usize)) -> usize {
    if range.0 == range.1 {
        range.0
    } else {
        rand::rng().random_range(range.0..=range.1)
    }
}

fn random_u64(range: (u64, u64)) -> u64 {
    if range.0 == range.1 {
        range.0
    } else {
        rand::rng().random_range(range.0..=range.1)
    }
}

fn normalize_path(path: Option<&str>) -> String {
    let configured = path.unwrap_or("/").trim();
    let (raw_path, query) = configured
        .split_once('?')
        .map_or((configured, None), |(path, query)| (path, Some(query)));
    let mut normalized = if raw_path.is_empty() {
        "/".to_string()
    } else if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    if let Some(query) = query
        && !query.is_empty()
    {
        normalized.push('?');
        normalized.push_str(query);
    }
    normalized
}

fn parse_padding_range(
    value: Option<&serde_json::Value>,
    outbound_tag: &str,
) -> Result<(usize, usize), String> {
    let Some(value) = value else {
        return Ok((DEFAULT_PADDING_FROM, DEFAULT_PADDING_TO));
    };
    let parse_i64 = |value: &serde_json::Value| value.as_i64();
    let (from, to) = match value {
        serde_json::Value::Number(number) => {
            let value = number.as_i64().ok_or_else(|| {
                format!("XHTTP outbound {outbound_tag} has invalid xPaddingBytes")
            })?;
            (value, value)
        }
        serde_json::Value::String(text) => {
            let text = text.trim();
            if let Some((from, to)) = text.split_once('-') {
                let from = from.trim().parse::<i64>().map_err(|_| {
                    format!(
                        "XHTTP outbound {outbound_tag} has invalid xPaddingBytes"
                    )
                })?;
                let to = to.trim().parse::<i64>().map_err(|_| {
                    format!(
                        "XHTTP outbound {outbound_tag} has invalid xPaddingBytes"
                    )
                })?;
                (from, to)
            } else {
                let value = text.parse::<i64>().map_err(|_| {
                    format!(
                        "XHTTP outbound {outbound_tag} has invalid xPaddingBytes"
                    )
                })?;
                (value, value)
            }
        }
        serde_json::Value::Object(object) => {
            let from = object
                .get("from")
                .and_then(parse_i64)
                .unwrap_or(DEFAULT_PADDING_FROM as i64);
            let to = object.get("to").and_then(parse_i64).unwrap_or(from);
            (from, to)
        }
        _ => {
            return Err(format!(
                "XHTTP outbound {outbound_tag} has invalid xPaddingBytes"
            ));
        }
    };
    if from <= 0 || to < from {
        return Err(format!(
            "XHTTP outbound {outbound_tag} requires 0 < xPaddingBytes.from <= to"
        ));
    }
    let from = usize::try_from(from).map_err(|_| {
        format!("XHTTP outbound {outbound_tag} xPaddingBytes is too large")
    })?;
    let to = usize::try_from(to).map_err(|_| {
        format!("XHTTP outbound {outbound_tag} xPaddingBytes is too large")
    })?;
    Ok((from, to))
}

const CLIENT_HPACK_ASCII_CODE_LENGTHS: [u8; 128] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10,
    10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13,
    19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5,
    6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
];

fn client_hpack_huffman_encoded_len(value: &str) -> usize {
    let bits = value.bytes().fold(0usize, |sum, byte| {
        sum + CLIENT_HPACK_ASCII_CODE_LENGTHS
            .get(byte as usize)
            .copied()
            .unwrap_or(30) as usize
    });
    bits.div_ceil(8)
}

fn generate_client_padding(method: PaddingMethod, target_length: usize) -> String {
    if target_length == 0 {
        return String::new();
    }
    if method == PaddingMethod::RepeatX {
        return "X".repeat(target_length);
    }

    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let initial_length = (target_length * 5).div_ceil(4).max(1);
    let mut value = String::with_capacity(initial_length + 8);
    let mut rng = rand::rng();
    for _ in 0..initial_length {
        value.push(BASE62[rng.random_range(0..BASE62.len())] as char);
    }

    let mut adjust = 'X';
    for _ in 0..150 {
        let encoded_length = client_hpack_huffman_encoded_len(&value);
        if encoded_length.abs_diff(target_length) <= 2 {
            return value;
        }
        if encoded_length < target_length {
            value.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else if value.len() > 1 {
            value.pop();
        } else {
            break;
        }
    }
    value
}

fn set_url_query(
    url: &str,
    key: &str,
    value: &str,
    preserve_existing: bool,
) -> String {
    let (without_fragment, fragment) = url
        .split_once('#')
        .map_or((url, None), |(base, fragment)| (base, Some(fragment)));
    let (base, existing_query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(base, query)| {
            (base, Some(query))
        });
    let mut pairs = Vec::new();
    if preserve_existing {
        for pair in existing_query.unwrap_or_default().split('&') {
            if pair.is_empty() {
                continue;
            }
            let pair_key = pair.split_once('=').map_or(pair, |(key, _)| key);
            if pair_key != key {
                pairs.push(pair.to_string());
            }
        }
    }
    pairs.push(format!("{key}={value}"));
    let mut result = format!("{base}?{}", pairs.join("&"));
    if let Some(fragment) = fragment {
        result.push('#');
        result.push_str(fragment);
    }
    result
}

fn append_query_parameter(url: &str, key: &str, value: &str) -> String {
    set_url_query(url, key, value, true)
}

fn serialize_http1_fixed_request<B>(
    request: &Request<B>,
    authority: &str,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let mut output = Vec::with_capacity(1024 + body.len());
    output.extend_from_slice(request.method().as_str().as_bytes());
    output.push(b' ');
    output.extend_from_slice(path.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(authority.as_bytes());
    output.extend_from_slice(b"\r\n");
    for (name, value) in request.headers() {
        if name == HOST
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
            || name == CONNECTION
        {
            continue;
        }
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    output.extend_from_slice(body);
    Ok(output)
}

fn serialize_http1_request_head<B>(
    request: &Request<B>,
    authority: &str,
) -> std::io::Result<Vec<u8>> {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let mut output = Vec::with_capacity(1024);
    output.extend_from_slice(request.method().as_str().as_bytes());
    output.push(b' ');
    output.extend_from_slice(path.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(authority.as_bytes());
    output.extend_from_slice(b"\r\n");
    for (name, value) in request.headers() {
        if name == HOST
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
            || name == CONNECTION
        {
            continue;
        }
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(
        b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
    );
    Ok(output)
}

#[derive(Debug)]
enum Http1BodyMode {
    Headers,
    Chunked {
        remaining: Option<usize>,
        reading_trailers: bool,
    },
    ContentLength {
        remaining: usize,
    },
    UntilEof,
    Finished,
}

struct XhttpHttp1Stream {
    inner: Box<dyn AsyncStream>,
    write_pending: Vec<u8>,
    write_offset: usize,
    write_payload_len: Option<usize>,
    shutdown_frame_started: bool,
    shutdown_complete: bool,
    raw_read: Vec<u8>,
    decoded_read: Vec<u8>,
    decoded_offset: usize,
    body_mode: Http1BodyMode,
}

impl XhttpHttp1Stream {
    fn new(inner: Box<dyn AsyncStream>) -> Self {
        Self {
            inner,
            write_pending: Vec::new(),
            write_offset: 0,
            write_payload_len: None,
            shutdown_frame_started: false,
            shutdown_complete: false,
            raw_read: Vec::new(),
            decoded_read: Vec::new(),
            decoded_offset: 0,
            body_mode: Http1BodyMode::Headers,
        }
    }

    fn poll_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.write_offset < self.write_pending.len() {
            match Pin::new(&mut *self.inner)
                .poll_write(cx, &self.write_pending[self.write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "XHTTP H1 tunnel wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_pending.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_chunk(&mut self, payload: &[u8]) {
        let prefix = format!("{:X}\r\n", payload.len());
        self.write_pending.reserve(prefix.len() + payload.len() + 2);
        self.write_pending.extend_from_slice(prefix.as_bytes());
        self.write_pending.extend_from_slice(payload);
        self.write_pending.extend_from_slice(b"\r\n");
        self.write_offset = 0;
        self.write_payload_len = Some(payload.len());
    }

    fn copy_decoded(&mut self, buffer: &mut ReadBuf<'_>) -> bool {
        if self.decoded_offset >= self.decoded_read.len() {
            self.decoded_read.clear();
            self.decoded_offset = 0;
            return false;
        }
        let available = &self.decoded_read[self.decoded_offset..];
        let length = available.len().min(buffer.remaining());
        buffer.put_slice(&available[..length]);
        self.decoded_offset += length;
        if self.decoded_offset == self.decoded_read.len() {
            self.decoded_read.clear();
            self.decoded_offset = 0;
        }
        length > 0
    }

    fn process_read_buffer(&mut self) -> std::io::Result<bool> {
        let mode = std::mem::replace(&mut self.body_mode, Http1BodyMode::Finished);
        match mode {
            Http1BodyMode::Headers => {
                let Some(end) = find_bytes(&self.raw_read, b"\r\n\r\n") else {
                    self.body_mode = Http1BodyMode::Headers;
                    return Ok(false);
                };
                let header_end = end + 4;
                let header =
                    std::str::from_utf8(&self.raw_read[..end]).map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid XHTTP H1 response header: {error}"),
                        )
                    })?;
                let mut lines = header.split("\r\n");
                let status_line = lines.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "missing XHTTP H1 response status",
                    )
                })?;
                let status = status_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<u16>().ok())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid XHTTP H1 response status",
                        )
                    })?;
                if !(200..300).contains(&status) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("XHTTP H1 server returned status {status}"),
                    ));
                }
                let mut chunked = false;
                let mut content_length = None;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    if name.trim().eq_ignore_ascii_case("transfer-encoding")
                        && value
                            .split(',')
                            .any(|item| item.trim().eq_ignore_ascii_case("chunked"))
                    {
                        chunked = true;
                    }
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse::<usize>().ok();
                    }
                }
                self.raw_read.drain(..header_end);
                self.body_mode = if chunked {
                    Http1BodyMode::Chunked {
                        remaining: None,
                        reading_trailers: false,
                    }
                } else if let Some(remaining) = content_length {
                    Http1BodyMode::ContentLength { remaining }
                } else {
                    Http1BodyMode::UntilEof
                };
                Ok(true)
            }
            Http1BodyMode::Chunked {
                mut remaining,
                mut reading_trailers,
            } => {
                if reading_trailers {
                    if self.raw_read.starts_with(b"\r\n") {
                        self.raw_read.drain(..2);
                        self.body_mode = Http1BodyMode::Finished;
                        return Ok(true);
                    }
                    if let Some(end) = find_bytes(&self.raw_read, b"\r\n\r\n") {
                        self.raw_read.drain(..end + 4);
                        self.body_mode = Http1BodyMode::Finished;
                        return Ok(true);
                    }
                    self.body_mode = Http1BodyMode::Chunked {
                        remaining,
                        reading_trailers,
                    };
                    return Ok(false);
                }
                if let Some(left) = remaining {
                    if left == 0 {
                        if self.raw_read.len() < 2 {
                            self.body_mode = Http1BodyMode::Chunked {
                                remaining: Some(0),
                                reading_trailers,
                            };
                            return Ok(false);
                        }
                        if &self.raw_read[..2] != b"\r\n" {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid XHTTP H1 chunk terminator",
                            ));
                        }
                        self.raw_read.drain(..2);
                        remaining = None;
                        self.body_mode = Http1BodyMode::Chunked {
                            remaining,
                            reading_trailers,
                        };
                        return Ok(true);
                    }
                    if self.raw_read.is_empty() {
                        self.body_mode = Http1BodyMode::Chunked {
                            remaining,
                            reading_trailers,
                        };
                        return Ok(false);
                    }
                    let length = left.min(self.raw_read.len());
                    self.decoded_read
                        .extend_from_slice(&self.raw_read[..length]);
                    self.raw_read.drain(..length);
                    remaining = Some(left - length);
                    self.body_mode = Http1BodyMode::Chunked {
                        remaining,
                        reading_trailers,
                    };
                    return Ok(true);
                }
                let Some(end) = find_bytes(&self.raw_read, b"\r\n") else {
                    self.body_mode = Http1BodyMode::Chunked {
                        remaining,
                        reading_trailers,
                    };
                    return Ok(false);
                };
                let line =
                    std::str::from_utf8(&self.raw_read[..end]).map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid XHTTP H1 chunk size: {error}"),
                        )
                    })?;
                let size = usize::from_str_radix(
                    line.split(';').next().unwrap_or_default().trim(),
                    16,
                )
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid XHTTP H1 chunk size: {error}"),
                    )
                })?;
                self.raw_read.drain(..end + 2);
                if size == 0 {
                    reading_trailers = true;
                } else {
                    remaining = Some(size);
                }
                self.body_mode = Http1BodyMode::Chunked {
                    remaining,
                    reading_trailers,
                };
                Ok(true)
            }
            Http1BodyMode::ContentLength { mut remaining } => {
                if remaining == 0 {
                    self.body_mode = Http1BodyMode::Finished;
                    return Ok(true);
                }
                if self.raw_read.is_empty() {
                    self.body_mode = Http1BodyMode::ContentLength { remaining };
                    return Ok(false);
                }
                let length = remaining.min(self.raw_read.len());
                self.decoded_read
                    .extend_from_slice(&self.raw_read[..length]);
                self.raw_read.drain(..length);
                remaining -= length;
                self.body_mode = if remaining == 0 {
                    Http1BodyMode::Finished
                } else {
                    Http1BodyMode::ContentLength { remaining }
                };
                Ok(true)
            }
            Http1BodyMode::UntilEof => {
                if self.raw_read.is_empty() {
                    self.body_mode = Http1BodyMode::UntilEof;
                    return Ok(false);
                }
                self.decoded_read.extend_from_slice(&self.raw_read);
                self.raw_read.clear();
                self.body_mode = Http1BodyMode::UntilEof;
                Ok(true)
            }
            Http1BodyMode::Finished => {
                self.body_mode = Http1BodyMode::Finished;
                Ok(false)
            }
        }
    }

    fn handle_read_eof(&mut self) -> std::io::Result<()> {
        match self.body_mode {
            Http1BodyMode::UntilEof | Http1BodyMode::Finished => {
                self.body_mode = Http1BodyMode::Finished;
                Ok(())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "XHTTP H1 response ended before framing completed",
            )),
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl AsyncRead for XhttpHttp1Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.copy_decoded(buffer) {
                return Poll::Ready(Ok(()));
            }
            if matches!(this.body_mode, Http1BodyMode::Finished) {
                return Poll::Ready(Ok(()));
            }
            match this.process_read_buffer() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            let mut temporary = [0u8; 8192];
            let mut read_buffer = ReadBuf::new(&mut temporary);
            match Pin::new(&mut *this.inner).poll_read(cx, &mut read_buffer) {
                Poll::Ready(Ok(())) if read_buffer.filled().is_empty() => {
                    if let Err(error) = this.handle_read_eof() {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(())) => {
                    this.raw_read.extend_from_slice(read_buffer.filled());
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for XhttpHttp1Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_frame_started {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "XHTTP H1 request body is closed",
            )));
        }
        if this.write_payload_len.is_none() {
            if buffer.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.queue_chunk(buffer);
        }
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {
                let length = this.write_payload_len.take().unwrap_or_default();
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {
                this.write_payload_len = None;
                Pin::new(&mut *this.inner).poll_flush(cx)
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => this.write_payload_len = None,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if !this.shutdown_frame_started {
            this.shutdown_frame_started = true;
            this.write_pending.extend_from_slice(b"0\r\n\r\n");
            this.write_offset = 0;
        }
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut *this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown_complete = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncPing for XhttpHttp1Stream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for XhttpHttp1Stream {}

struct XhttpClientStream {
    reader: DuplexStream,
    writer: DuplexStream,
    _h3_endpoint: Option<Arc<quinn::Endpoint>>,
    _h3_sender: Option<XhttpH3Sender>,
}

impl AsyncRead for XhttpClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buffer)
    }
}

impl AsyncWrite for XhttpClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpClientStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for XhttpClientStream {}

struct XhttpXmuxLeasedStream {
    inner: Box<dyn AsyncStream>,
    _lease: XhttpXmuxLease,
}

impl AsyncRead for XhttpXmuxLeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for XhttpXmuxLeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpXmuxLeasedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut *self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for XhttpXmuxLeasedStream {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct TestAsyncStream(DuplexStream);

    impl AsyncRead for TestAsyncStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestAsyncStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestAsyncStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestAsyncStream {}

    #[derive(Clone)]
    struct CountingH2Dialer {
        connections: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl XhttpStreamDialer for CountingH2Dialer {
        async fn dial(&self) -> std::io::Result<Box<dyn AsyncStream>> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            let (client, server) = duplex(64 * 1024);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|_request| async {
                    Ok::<_, Infallible>(http::Response::new(Empty::<Bytes>::new()))
                });
                let _ =
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(server), service)
                        .await;
            });
            Ok(Box::new(TestAsyncStream(client)))
        }
    }

    #[test]
    fn normalized_path_matches_xray_path_placement_defaults() {
        assert_eq!(normalize_path(Some("xhttp")), "/xhttp/");
        assert_eq!(normalize_path(Some("/xhttp?matrix=1")), "/xhttp/?matrix=1");
        assert_eq!(normalize_path(Some("/xhttp")), "/xhttp/");
    }

    #[test]
    fn padding_range_accepts_xray_forms() {
        for (value, expected) in [
            (serde_json::json!(100), (100, 100)),
            (serde_json::json!("100-200"), (100, 200)),
            (serde_json::json!({"from": 100, "to": 200}), (100, 200)),
        ] {
            assert_eq!(parse_padding_range(Some(&value), "test").unwrap(), expected);
        }
    }

    #[test]
    fn query_padding_preserves_existing_query_and_fragment() {
        assert_eq!(
            append_query_parameter(
                "https://example.test/x?existing=1#fragment",
                "x_padding",
                "XX",
            ),
            "https://example.test/x?existing=1&x_padding=XX#fragment"
        );
    }

    #[test]
    fn compile_accepts_supported_modes_xmux_and_rejects_nested_download_settings() {
        let server = NetLocation::from_str("127.0.0.1:443", None).unwrap();
        for (mode, expected) in [
            ("auto", XhttpClientMode::Auto),
            ("stream-one", XhttpClientMode::StreamOne),
            ("stream-up", XhttpClientMode::StreamUp),
            ("packet-up", XhttpClientMode::PacketUp),
        ] {
            let config = XhttpClientConfig::compile(
                &server,
                serde_json::json!({"mode": mode}),
                "proxy",
            )
            .expect("supported XHTTP mode should compile");
            assert_eq!(config.mode, expected);
        }

        for placement in ["query", "header", "queryInHeader", "cookie"] {
            for method in ["repeat-x", "tokenish"] {
                let config = XhttpClientConfig::compile(
                    &server,
                    serde_json::json!({
                        "mode": "stream-one",
                        "xPaddingObfsMode": true,
                        "xPaddingPlacement": placement,
                        "xPaddingMethod": method
                    }),
                    "proxy",
                )
                .expect("supported padding obfs should compile");
                assert!(config.padding_obfs_mode);
            }
        }

        let xmux = XhttpClientConfig::compile(
            &server,
            serde_json::json!({
                "mode": "stream-one",
                "xmux": {
                    "maxConcurrency": 4,
                    "maxConnections": "2-3",
                    "cMaxReuseTimes": {"from": 5, "to": 6},
                    "hMaxRequestTimes": 7,
                    "hMaxReusableSecs": 8,
                    "hKeepAlivePeriod": -1
                }
            }),
            "proxy",
        )
        .expect("xmux settings should compile");
        assert_eq!(xmux.xmux.config.max_concurrency, 4);
        assert!((2..=3).contains(&xmux.xmux.config.max_connections));
        assert_eq!(xmux.xmux.config.c_max_reuse_times, (5, 6));
        assert_eq!(xmux.xmux.config.h_max_request_times, (7, 7));
        assert_eq!(xmux.xmux.config.h_max_reusable_secs, (8, 8));
        assert_eq!(xmux.xmux.h2_keep_alive_period(), None);

        assert!(
            XhttpClientConfig::compile(
                &server,
                serde_json::json!({
                    "mode": "stream-one",
                    "downloadSettings": {"address": "127.0.0.1"}
                }),
                "proxy",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn xmux_enforces_concurrency_request_and_lifetime_rotation() {
        let connections = Arc::new(AtomicUsize::new(0));
        let dialer: Arc<dyn XhttpStreamDialer> = Arc::new(CountingH2Dialer {
            connections: Arc::clone(&connections),
        });
        let concurrency = XhttpXmuxManager::new(XhttpXmuxConfig {
            max_concurrency: (1, 1),
            ..XhttpXmuxConfig::default()
        });
        let first = concurrency
            .select_h2(Arc::clone(&dialer), true)
            .await
            .unwrap();
        let second = concurrency
            .select_h2(Arc::clone(&dialer), true)
            .await
            .unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop(first);
        drop(second);

        connections.store(0, Ordering::SeqCst);
        let request_limit = XhttpXmuxManager::new(XhttpXmuxConfig {
            h_max_request_times: (1, 1),
            ..XhttpXmuxConfig::default()
        });
        let first = request_limit
            .select_h2(Arc::clone(&dialer), true)
            .await
            .unwrap();
        first.state.record_request();
        drop(first);
        let second = request_limit
            .select_h2(Arc::clone(&dialer), true)
            .await
            .unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop(second);

        connections.store(0, Ordering::SeqCst);
        let lifetime = XhttpXmuxManager::new(XhttpXmuxConfig {
            h_max_reusable_secs: (1, 1),
            ..XhttpXmuxConfig::default()
        });
        let first = lifetime.select_h2(Arc::clone(&dialer), true).await.unwrap();
        drop(first);
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let second = lifetime.select_h2(dialer, true).await.unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop(second);
    }

    #[test]
    fn tokenish_padding_tracks_hpack_target() {
        for target in [1, 64, 100, 128, 1000] {
            let padding = generate_client_padding(PaddingMethod::Tokenish, target);
            assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            assert!(
                client_hpack_huffman_encoded_len(&padding).abs_diff(target) <= 2,
                "target={target}, actual={}, raw={}",
                client_hpack_huffman_encoded_len(&padding),
                padding.len()
            );
        }
    }

    #[test]
    fn obfs_padding_uses_configured_placement() {
        let server = NetLocation::from_str("127.0.0.1:443", None).unwrap();
        for (placement, expected_uri, expected_header, expected_cookie) in [
            ("query", true, None, false),
            ("header", false, Some("X-Test-Padding"), false),
            ("queryInHeader", false, Some("X-Test-Padding"), false),
            ("cookie", false, None, true),
        ] {
            let config = XhttpClientConfig::compile(
                &server,
                serde_json::json!({
                    "host": "localhost",
                    "path": "/xhttp?existing=1",
                    "mode": "stream-one",
                    "xPaddingBytes": 100,
                    "xPaddingObfsMode": true,
                    "xPaddingPlacement": placement,
                    "xPaddingKey": "test_padding",
                    "xPaddingHeader": "X-Test-Padding"
                }),
                "proxy",
            )
            .unwrap();
            let request = config
                .build_stream_request(
                    "https",
                    None,
                    Method::POST,
                    empty_body(),
                    true,
                )
                .unwrap();
            assert_eq!(
                request
                    .uri()
                    .query()
                    .unwrap_or_default()
                    .contains("test_padding="),
                expected_uri
            );
            assert_eq!(
                request.headers().contains_key("X-Test-Padding"),
                expected_header.is_some()
            );
            assert_eq!(request.headers().contains_key(COOKIE), expected_cookie);
            assert!(!request.headers().contains_key(REFERER));
            if placement == "queryInHeader" {
                let value = request.headers()["X-Test-Padding"].to_str().unwrap();
                assert!(value.contains("?test_padding="));
                assert!(!value.contains("existing=1"));
            }
        }
    }

    #[tokio::test]
    async fn http1_raw_stream_request_uses_origin_form_and_host_header() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream},
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("POST /xhttp/ HTTP/1.1\r\n"),
                "{request}"
            );
            assert!(request.to_ascii_lowercase().contains("host: localhost"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("transfer-encoding: chunked")
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let server_location =
            NetLocation::from_str(&format!("127.0.0.1:{}", address.port()), None)
                .unwrap();
        let mut config = XhttpClientConfig::compile(
            &server_location,
            serde_json::json!({
                "host": "localhost",
                "path": "/xhttp",
                "mode": "stream-one",
                "xPaddingBytes": 100
            }),
            "proxy",
        )
        .unwrap();
        config.http_version = XhttpHttpVersion::Http1;
        let transport = TcpStream::connect(address).await.unwrap();
        let mut stream = config
            .connect_http1_stream_one(Box::new(transport), "http")
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http1_chunk_writer_preserves_multiple_large_chunks() {
        use tokio::{
            io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
            net::{TcpListener, TcpStream},
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = [26usize, 16 * 1024, 16 * 1024, 16 * 1024, 16 * 1024];
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut header_line = String::new();
            loop {
                header_line.clear();
                reader.read_line(&mut header_line).await.unwrap();
                if header_line == "\r\n" {
                    break;
                }
            }
            for expected_length in expected {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let length = usize::from_str_radix(line.trim(), 16).unwrap();
                assert_eq!(length, expected_length);
                let mut payload = vec![0u8; length];
                reader.read_exact(&mut payload).await.unwrap();
                assert!(payload.iter().all(|byte| *byte == expected_length as u8));
                let mut terminator = [0u8; 2];
                reader.read_exact(&mut terminator).await.unwrap();
                assert_eq!(&terminator, b"\r\n");
            }
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let transport = TcpStream::connect(address).await.unwrap();
        let mut stream = XhttpHttp1Stream::new(Box::new(transport));
        stream
            .inner
            .write_all(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for length in expected {
            stream.write_all(&vec![length as u8; length]).await.unwrap();
            stream.flush().await.unwrap();
        }
        server.await.unwrap();
    }

    #[test]
    fn success_status_is_required() {
        assert!(hyper::StatusCode::OK.is_success());
        assert!(!hyper::StatusCode::BAD_REQUEST.is_success());
    }
}
