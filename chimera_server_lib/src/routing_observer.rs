use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{Client, Method, Url, redirect::Policy};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{debug, warn};

use crate::{
    address::{Address, NetLocation},
    config::def::{BurstObservatoryConfig, ObservatoryConfig},
    outbound::{connect_tcp_via_outbound, reqwest_proxy_for_outbound},
    resolver::{NativeResolver, Resolver},
    routing_state::OutboundObservation,
    runtime::{OutboundSummary, RuntimeState},
};

const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";
const DEFAULT_BURST_PROBE_URL: &str =
    "https://connectivitycheck.gstatic.com/generate_204";
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_BURST_INTERVAL: Duration = Duration::from_secs(60);
const MIN_BURST_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_HEALTH_WINDOW: usize = 10;
const FAILED_DELAY_MS: i64 = 99_999_999;

#[derive(Debug, Clone)]
struct ActiveObserverConfig {
    selectors: Vec<String>,
    probe_url: Url,
    connectivity_url: Option<Url>,
    interval: Duration,
    timeout: Duration,
    method: Method,
    concurrent: bool,
    sampling_count: usize,
    consume_body: bool,
}

#[derive(Debug, Clone)]
struct ProbeResult {
    alive: bool,
    delay_ms: i64,
    error: String,
}

#[derive(Debug, Clone)]
struct ProbeSample {
    recorded_at: Instant,
    alive: bool,
    delay_ms: i64,
}

#[derive(Debug, Default)]
struct ProbeWindow {
    samples: VecDeque<ProbeSample>,
    last_seen_time: i64,
}

pub(crate) fn validate_observatory_config(
    config: Option<&ObservatoryConfig>,
    burst: Option<&BurstObservatoryConfig>,
) -> Result<(), String> {
    let _ = resolve_observer_config(config, burst)?;
    Ok(())
}

pub(crate) fn start_observer(
    runtime: RuntimeState,
    config: Option<ObservatoryConfig>,
    burst: Option<BurstObservatoryConfig>,
) -> Result<Option<JoinHandle<()>>, String> {
    let Some(config) = resolve_observer_config(config.as_ref(), burst.as_ref())?
    else {
        return Ok(None);
    };
    if config.selectors.is_empty() {
        return Ok(None);
    }
    Ok(Some(tokio::spawn(async move {
        run_observer(runtime, config).await;
    })))
}

async fn run_observer(runtime: RuntimeState, config: ActiveObserverConfig) {
    let client = match Client::builder()
        .timeout(config.timeout)
        .redirect(Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!("failed to build routing observer client: {error}");
            return;
        }
    };
    let mut windows = HashMap::<String, ProbeWindow>::new();
    loop {
        let mut outbounds = selected_outbounds(&runtime, &config.selectors);
        if config.concurrent {
            let probes = outbounds.drain(..).map(|outbound| {
                probe_outbound(&runtime, client.clone(), config.clone(), outbound)
            });
            let results = futures::future::join_all(probes).await;
            for (tag, result) in results {
                if let Some(result) = result {
                    apply_probe_result(
                        &runtime,
                        &mut windows,
                        tag,
                        result,
                        config.sampling_count,
                        config.health_validity(),
                    );
                }
            }
            sleep(config.interval).await;
        } else {
            outbounds.sort_by(|left, right| left.tag.cmp(&right.tag));
            if outbounds.is_empty() {
                sleep(config.interval).await;
                continue;
            }
            for outbound in outbounds {
                let (tag, result) = probe_outbound(
                    &runtime,
                    client.clone(),
                    config.clone(),
                    outbound,
                )
                .await;
                if let Some(result) = result {
                    apply_probe_result(
                        &runtime,
                        &mut windows,
                        tag,
                        result,
                        config.sampling_count,
                        config.health_validity(),
                    );
                }
                sleep(config.interval).await;
            }
        }
    }
}

async fn probe_once(
    runtime: &RuntimeState,
    config: &ActiveObserverConfig,
    windows: &mut HashMap<String, ProbeWindow>,
) -> usize {
    let client = match Client::builder()
        .timeout(config.timeout)
        .redirect(Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!("failed to build routing observer client: {error}");
            return 0;
        }
    };
    let outbounds = selected_outbounds(runtime, &config.selectors);
    let count = outbounds.len();
    if config.concurrent {
        let results =
            futures::future::join_all(outbounds.into_iter().map(|outbound| {
                probe_outbound(runtime, client.clone(), config.clone(), outbound)
            }))
            .await;
        for (tag, result) in results {
            if let Some(result) = result {
                apply_probe_result(
                    runtime,
                    windows,
                    tag,
                    result,
                    config.sampling_count,
                    config.health_validity(),
                );
            }
        }
    } else {
        for outbound in outbounds {
            let (tag, result) =
                probe_outbound(runtime, client.clone(), config.clone(), outbound)
                    .await;
            if let Some(result) = result {
                apply_probe_result(
                    runtime,
                    windows,
                    tag,
                    result,
                    config.sampling_count,
                    config.health_validity(),
                );
            }
        }
    }
    count
}

fn selected_outbounds(
    runtime: &RuntimeState,
    selectors: &[String],
) -> Vec<OutboundSummary> {
    runtime
        .outbounds()
        .into_iter()
        .filter(|outbound| {
            selectors
                .iter()
                .any(|selector| outbound.tag.starts_with(selector))
        })
        .collect()
}

async fn probe_outbound(
    runtime: &RuntimeState,
    direct_client: Client,
    config: ActiveObserverConfig,
    outbound: OutboundSummary,
) -> (String, Option<ProbeResult>) {
    if outbound.protocol.trim().eq_ignore_ascii_case("blackhole") {
        return (
            outbound.tag,
            Some(ProbeResult {
                alive: false,
                delay_ms: FAILED_DELAY_MS,
                error: "blackhole outbound cannot relay observatory probes".into(),
            }),
        );
    }

    if matches!(
        outbound.protocol.trim().to_ascii_lowercase().as_str(),
        "vless" | "trojan"
    ) {
        let started = Instant::now();
        let result = match timeout(
            config.timeout,
            probe_tagged_http(runtime, &config, &outbound),
        )
        .await
        {
            Ok(Ok(())) => Some(ProbeResult {
                alive: true,
                delay_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                error: String::new(),
            }),
            Ok(Err(error)) => {
                if connectivity_is_unavailable(&direct_client, &config).await {
                    debug!(
                        outbound = %outbound.tag,
                        "routing observatory skipped sample because connectivity check failed"
                    );
                    None
                } else {
                    Some(ProbeResult {
                        alive: false,
                        delay_ms: FAILED_DELAY_MS,
                        error: error.to_string(),
                    })
                }
            }
            Err(_) => Some(ProbeResult {
                alive: false,
                delay_ms: FAILED_DELAY_MS,
                error: "tagged observatory probe timed out".into(),
            }),
        };
        return (outbound.tag, result);
    }

    let probe_client = match reqwest_proxy_for_outbound(&outbound) {
        Ok(None) => direct_client.clone(),
        Ok(Some(proxy)) => match Client::builder()
            .timeout(config.timeout)
            .redirect(Policy::none())
            .proxy(proxy)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                return (
                    outbound.tag,
                    Some(ProbeResult {
                        alive: false,
                        delay_ms: FAILED_DELAY_MS,
                        error: error.to_string(),
                    }),
                );
            }
        },
        Err(error) => {
            return (
                outbound.tag,
                Some(ProbeResult {
                    alive: false,
                    delay_ms: FAILED_DELAY_MS,
                    error: error.to_string(),
                }),
            );
        }
    };

    let started = Instant::now();
    let request =
        probe_client.request(config.method.clone(), config.probe_url.clone());
    let result = match request.send().await {
        Ok(response) => {
            if config.consume_body
                && let Err(error) = response.bytes().await
            {
                Some(ProbeResult {
                    alive: false,
                    delay_ms: FAILED_DELAY_MS,
                    error: error.to_string(),
                })
            } else {
                Some(ProbeResult {
                    alive: true,
                    delay_ms: started.elapsed().as_millis().min(i64::MAX as u128)
                        as i64,
                    error: String::new(),
                })
            }
        }
        Err(error) => {
            // Match Xray Burst: connectivity is checked directly, not through
            // the failed tagged outbound.
            if connectivity_is_unavailable(&direct_client, &config).await {
                debug!(
                    outbound = %outbound.tag,
                    "routing observatory skipped sample because connectivity check failed"
                );
                None
            } else {
                Some(ProbeResult {
                    alive: false,
                    delay_ms: FAILED_DELAY_MS,
                    error: error.to_string(),
                })
            }
        }
    };
    (outbound.tag, result)
}

async fn probe_tagged_http(
    runtime: &RuntimeState,
    config: &ActiveObserverConfig,
    outbound: &OutboundSummary,
) -> std::io::Result<()> {
    let host = config.probe_url.host_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "observatory probe URL has no host",
        )
    })?;
    let port = config.probe_url.port_or_known_default().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "observatory probe URL has no known port",
        )
    })?;
    let target = NetLocation::new(Address::from(host)?, port);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let connection =
        connect_tcp_via_outbound(&resolver, &target, runtime, outbound).await?;
    let path = probe_request_target(&config.probe_url);
    let host_header = probe_host_header(&config.probe_url, host, port);

    match config.probe_url.scheme() {
        "http" => {
            probe_http1_io(
                connection.stream,
                &config.method,
                &path,
                &host_header,
                config.consume_body,
            )
            .await
        }
        "https" => {
            let native = rustls_native_certs::load_native_certs();
            let mut roots = rustls::RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no native CA certificates were available for observatory TLS",
                ));
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut client_config =
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector =
                tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let server_name = rustls::pki_types::ServerName::try_from(
                host.to_owned(),
            )
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid observatory TLS server name {host}: {error}"),
                )
            })?;
            let tls = connector.connect(server_name, connection.stream).await?;
            probe_http1_io(
                tls,
                &config.method,
                &path,
                &host_header,
                config.consume_body,
            )
            .await
        }
        scheme => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported observatory probe URL scheme {scheme}"),
        )),
    }
}

fn probe_request_target(url: &Url) -> String {
    let mut target = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn probe_host_header(url: &Url, host: &str, port: u16) -> String {
    let default_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => port,
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

async fn probe_http1_io<S>(
    mut io: S,
    method: &Method,
    path: &str,
    host: &str,
    consume_body: bool,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
        method.as_str(),
        path,
        host
    );
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut response = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = io.read(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "observatory HTTP probe ended before response headers",
            ));
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(index) =
            response.windows(4).position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if response.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "observatory HTTP response headers exceed 64 KiB",
            ));
        }
    };
    if !response.starts_with(b"HTTP/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "observatory probe received a non-HTTP response",
        ));
    }
    if consume_body {
        let _ = header_end;
        loop {
            let read = io.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
        }
    }
    Ok(())
}

async fn connectivity_is_unavailable(
    client: &Client,
    config: &ActiveObserverConfig,
) -> bool {
    let Some(connectivity_url) = config.connectivity_url.as_ref() else {
        return false;
    };
    client
        .request(config.method.clone(), connectivity_url.clone())
        .send()
        .await
        .is_err()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProbeHealthSummary {
    all: i64,
    fail: i64,
    deviation_ms: i64,
    average_ms: i64,
    max_ms: i64,
    min_ms: i64,
}

fn advance_probe_window(
    mut window: ProbeWindow,
    result: &ProbeResult,
    now: i64,
    recorded_at: Instant,
    sampling_count: usize,
    validity: Duration,
) -> ProbeWindow {
    if result.alive {
        window.last_seen_time = now;
    }
    window.samples.push_back(ProbeSample {
        recorded_at,
        alive: result.alive,
        delay_ms: result.delay_ms,
    });
    while window.samples.len() > sampling_count.max(1) {
        window.samples.pop_front();
    }
    while window.samples.front().is_some_and(|sample| {
        recorded_at.duration_since(sample.recorded_at) > validity
    }) {
        window.samples.pop_front();
    }
    window
}

fn summarize_probe_window(window: &ProbeWindow) -> ProbeHealthSummary {
    let all = window.samples.len() as i64;
    let fail = window.samples.iter().filter(|sample| !sample.alive).count() as i64;
    let successful = window
        .samples
        .iter()
        .filter(|sample| sample.alive)
        .map(|sample| sample.delay_ms)
        .collect::<Vec<_>>();
    let average_ms = if successful.is_empty() {
        0
    } else {
        successful.iter().sum::<i64>() / successful.len() as i64
    };
    let deviation_ms = match successful.len() {
        0 => 0,
        1 => average_ms / 2,
        count => {
            let variance = successful
                .iter()
                .map(|delay| {
                    let delta = *delay as f64 - average_ms as f64;
                    delta * delta
                })
                .sum::<f64>()
                / count as f64;
            variance.sqrt().round() as i64
        }
    };

    ProbeHealthSummary {
        all,
        fail,
        deviation_ms,
        average_ms,
        max_ms: successful.iter().copied().max().unwrap_or_default(),
        min_ms: successful.iter().copied().min().unwrap_or_default(),
    }
}

fn build_probe_observation(
    result: ProbeResult,
    now: i64,
    last_seen_time: i64,
    health: ProbeHealthSummary,
) -> OutboundObservation {
    OutboundObservation {
        alive: result.alive,
        delay_ms: result.delay_ms,
        last_error_reason: result.error,
        last_seen_time,
        last_try_time: now,
        health_all: health.all,
        health_fail: health.fail,
        health_deviation_ms: health.deviation_ms,
        health_average_ms: health.average_ms,
        health_max_ms: health.max_ms,
        health_min_ms: health.min_ms,
    }
}

fn apply_probe_result(
    runtime: &RuntimeState,
    windows: &mut HashMap<String, ProbeWindow>,
    tag: String,
    result: ProbeResult,
    sampling_count: usize,
    validity: Duration,
) {
    let now = unix_time_secs();
    let (observation, next_window) = if sampling_count == 0 {
        let previous_last_seen = runtime
            .outbound_observation(&tag)
            .map_or(0, |status| status.last_seen_time);
        let last_seen_time = if result.alive {
            now
        } else {
            previous_last_seen
        };
        (
            build_probe_observation(
                result,
                now,
                last_seen_time,
                ProbeHealthSummary::default(),
            ),
            None,
        )
    } else {
        let window = windows.remove(&tag).unwrap_or_default();
        let window = advance_probe_window(
            window,
            &result,
            now,
            Instant::now(),
            sampling_count,
            validity,
        );
        let health = summarize_probe_window(&window);
        let mut observation =
            build_probe_observation(result, now, window.last_seen_time, health);
        observation.alive = health.all != health.fail;
        observation.delay_ms = health.average_ms;
        observation.last_error_reason.clear();
        observation.last_seen_time = 0;
        observation.last_try_time = 0;
        (observation, Some(window))
    };

    if let Some(window) = next_window {
        windows.insert(tag.clone(), window);
    }
    let alive = observation.alive;
    let delay_ms = observation.delay_ms;
    runtime.record_outbound_observation(tag.clone(), observation);
    debug!(
        outbound = %tag,
        alive,
        delay_ms,
        "routing observatory probe completed"
    );
}

impl ActiveObserverConfig {
    fn health_validity(&self) -> Duration {
        if self.sampling_count == 0 {
            return Duration::ZERO;
        }
        let samples = self.sampling_count.min(u32::MAX as usize) as u32;
        self.interval
            .checked_mul(samples)
            .and_then(|duration| duration.checked_mul(2))
            .unwrap_or(Duration::MAX)
    }
}

fn resolve_observer_config(
    config: Option<&ObservatoryConfig>,
    burst: Option<&BurstObservatoryConfig>,
) -> Result<Option<ActiveObserverConfig>, String> {
    match (config, burst) {
        (Some(config), Some(_)) => ActiveObserverConfig::try_from(config).map(Some),
        (Some(config), None) => ActiveObserverConfig::try_from(config).map(Some),
        (None, Some(config)) => ActiveObserverConfig::try_from(config).map(Some),
        (None, None) => Ok(None),
    }
}

impl TryFrom<&ObservatoryConfig> for ActiveObserverConfig {
    type Error = String;

    fn try_from(config: &ObservatoryConfig) -> Result<Self, Self::Error> {
        let selectors = normalize_selectors(&config.subject_selector);
        let probe_url = parse_http_url(
            if config.probe_url.trim().is_empty() {
                DEFAULT_PROBE_URL
            } else {
                config.probe_url.trim()
            },
            "observatory probeURL",
        )?;
        let interval = config
            .probe_interval
            .as_ref()
            .map(parse_duration)
            .transpose()?
            .filter(|interval| !interval.is_zero())
            .unwrap_or(DEFAULT_PROBE_INTERVAL);
        Ok(Self {
            selectors,
            probe_url,
            connectivity_url: None,
            interval,
            timeout: DEFAULT_PROBE_TIMEOUT,
            method: Method::GET,
            concurrent: config.enable_concurrency,
            sampling_count: 0,
            consume_body: false,
        })
    }
}

impl TryFrom<&BurstObservatoryConfig> for ActiveObserverConfig {
    type Error = String;

    fn try_from(config: &BurstObservatoryConfig) -> Result<Self, Self::Error> {
        let ping = config.ping_config.as_ref().ok_or_else(|| {
            "burstObservatory requires a valid pingConfig".to_string()
        })?;
        let probe_url = parse_http_url(
            if ping.destination.trim().is_empty() {
                DEFAULT_BURST_PROBE_URL
            } else {
                ping.destination.trim()
            },
            "burstObservatory pingConfig.destination",
        )?;
        let connectivity_url = (!ping.connectivity.trim().is_empty())
            .then(|| {
                parse_http_url(
                    ping.connectivity.trim(),
                    "burstObservatory pingConfig.connectivity",
                )
            })
            .transpose()?;
        let interval = ping
            .interval
            .as_ref()
            .map(parse_duration)
            .transpose()?
            .filter(|interval| !interval.is_zero())
            .unwrap_or(DEFAULT_BURST_INTERVAL)
            .max(MIN_BURST_INTERVAL);
        let timeout = ping
            .timeout
            .as_ref()
            .map(parse_duration)
            .transpose()?
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(DEFAULT_PROBE_TIMEOUT);
        let method = Method::from_bytes(if ping.http_method.trim().is_empty() {
            b"HEAD"
        } else {
            ping.http_method.trim().as_bytes()
        })
        .map_err(|error| {
            format!(
                "invalid burstObservatory pingConfig.httpMethod {}: {error}",
                ping.http_method
            )
        })?;
        Ok(Self {
            selectors: normalize_selectors(&config.subject_selector),
            probe_url,
            connectivity_url,
            interval,
            timeout,
            consume_body: method == Method::GET,
            method,
            concurrent: true,
            sampling_count: ping
                .sampling
                .filter(|sampling| *sampling > 0)
                .unwrap_or(DEFAULT_HEALTH_WINDOW),
        })
    }
}

fn normalize_selectors(selectors: &[String]) -> Vec<String> {
    selectors
        .iter()
        .map(|selector| selector.trim())
        .filter(|selector| !selector.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_http_url(value: &str, field: &str) -> Result<Url, String> {
    let url =
        Url::parse(value).map_err(|error| format!("invalid {field}: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{field} scheme {} is not supported", url.scheme()));
    }
    Ok(url)
}

fn parse_duration(value: &serde_json::Value) -> Result<Duration, String> {
    if let Some(milliseconds) = value.as_u64() {
        return Ok(Duration::from_millis(milliseconds));
    }
    let Some(value) = value.as_str() else {
        return Err("observatory probeInterval must be a duration string".into());
    };
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let amount = value[..split].parse::<f64>().map_err(|error| {
        format!("invalid observatory probeInterval {value}: {error}")
    })?;
    let seconds = match value[split..].trim().to_ascii_lowercase().as_str() {
        "ns" => amount / 1_000_000_000.0,
        "us" | "µs" => amount / 1_000_000.0,
        "ms" => amount / 1_000.0,
        "s" | "" => amount,
        "m" => amount * 60.0,
        "h" => amount * 3_600.0,
        unit => {
            return Err(format!(
                "unsupported observatory probeInterval unit {unit}"
            ));
        }
    };
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("observatory probeInterval must be positive".into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "ws", feature = "httpupgrade", feature = "reality"))]
    use crate::async_stream::AsyncStream;
    #[cfg(feature = "grpc_transport")]
    use crate::beginning::grpc_transport::{
        decode_grpc_message_payloads, encode_grpc_message,
    };
    #[cfg(feature = "ws")]
    use crate::handler::ws::WebsocketStream;
    use crate::{
        config::{
            def::OutboundItem,
            rule::{BalancerConfig, BalancerStrategyConfig, RuleConfig},
        },
        outbound::compile_static_outbound,
        routing_state::{RoutingInput, RoutingState},
    };
    #[cfg(feature = "ws")]
    use base64::Engine as _;
    #[cfg(feature = "grpc_transport")]
    use bytes::BytesMut;
    #[cfg(feature = "grpc_transport")]
    use http_body_util::{BodyExt as _, StreamBody};
    #[cfg(feature = "grpc_transport")]
    use hyper::{
        Method as HyperMethod, Request, Response, body::Frame, header,
        server::conn::http2, service::service_fn,
    };
    #[cfg(feature = "grpc_transport")]
    use hyper_util::rt::{TokioExecutor, TokioIo};
    #[cfg(feature = "grpc_transport")]
    use std::convert::Infallible;

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }
    }

    async fn start_fake_socks_probe_server(
        response_delay: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake SOCKS probe server");
        let address = listener.local_addr().expect("fake SOCKS probe address");
        let task = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept SOCKS probe");
            let mut greeting = [0u8; 3];
            stream
                .read_exact(&mut greeting)
                .await
                .expect("read SOCKS greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream
                .write_all(&[0x05, 0x00])
                .await
                .expect("write SOCKS method");
            let mut header = [0u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read SOCKS CONNECT");
            assert_eq!(header, [0x05, 0x01, 0x00, 0x03]);
            let length =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; length];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read probe domain");
            let port = stream.read_u16().await.expect("read probe port");
            assert_eq!(domain, b"probe.example");
            assert_eq!(port, 80);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("write SOCKS CONNECT response");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await.expect("read HTTP probe");
            tokio::time::sleep(response_delay).await;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write HTTP probe response");
        });
        (address, task)
    }

    fn static_socks_outbound(
        tag: &str,
        address: std::net::SocketAddr,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port()
            }
        }))
        .expect("parse fake SOCKS outbound");
        compile_static_outbound(&item).expect("compile fake SOCKS outbound")
    }

    #[cfg(feature = "trojan")]
    fn static_trojan_outbound(
        tag: &str,
        address: std::net::SocketAddr,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            }
        }))
        .expect("parse fake Trojan outbound");
        compile_static_outbound(&item).expect("compile fake Trojan outbound")
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    fn static_trojan_websocket_outbound(
        tag: &str,
        address: std::net::SocketAddr,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "host": "ws.example.test",
                    "path": "/trojan"
                }
            }
        }))
        .expect("parse fake Trojan WebSocket outbound");
        compile_static_outbound(&item)
            .expect("compile fake Trojan WebSocket outbound")
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    fn static_trojan_httpupgrade_outbound(
        tag: &str,
        address: std::net::SocketAddr,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "none",
                "httpUpgradeSettings": {
                    "host": "upgrade.example.test",
                    "path": "/trojan"
                }
            }
        }))
        .expect("parse fake Trojan HTTPUpgrade outbound");
        compile_static_outbound(&item)
            .expect("compile fake Trojan HTTPUpgrade outbound")
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    fn static_trojan_grpc_outbound_with_mode(
        tag: &str,
        address: std::net::SocketAddr,
        multi_mode: bool,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService",
                    "multiMode": multi_mode
                }
            }
        }))
        .expect("parse fake Trojan gRPC outbound");
        compile_static_outbound(&item).expect("compile fake Trojan gRPC outbound")
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    fn static_trojan_grpc_outbound(
        tag: &str,
        address: std::net::SocketAddr,
    ) -> OutboundSummary {
        static_trojan_grpc_outbound_with_mode(tag, address, false)
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    async fn serve_fake_trojan_grpc_probe<IO>(
        stream: IO,
        response_delay: Duration,
        multi_mode: bool,
    ) where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(
            move |request: Request<hyper::body::Incoming>| async move {
                assert_eq!(request.method(), HyperMethod::POST);
                assert_eq!(
                    request.uri().path(),
                    if multi_mode {
                        "/GunService/TunMulti"
                    } else {
                        "/GunService/Tun"
                    }
                );
                assert_eq!(
                    request
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/grpc")
                );
                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<Frame<bytes::Bytes>, Infallible>,
                >(4);
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut encoded = BytesMut::new();
                    let mut decoded = Vec::new();
                    let digest = aws_lc_rs::digest::digest(
                        &aws_lc_rs::digest::SHA224,
                        b"secret",
                    );
                    let expected_hash = digest
                        .as_ref()
                        .iter()
                        .flat_map(|byte| format!("{byte:02x}").into_bytes())
                        .collect::<Vec<_>>();

                    loop {
                        let frame = body
                            .frame()
                            .await
                            .expect("gRPC probe request body must continue")
                            .expect("read gRPC probe request frame");
                        if let Some(data) = frame.data_ref() {
                            encoded.extend_from_slice(data);
                            while let Some(payloads) = decode_grpc_message_payloads(
                                &mut encoded,
                                multi_mode,
                            )
                            .expect("decode gRPC probe Hunk")
                            {
                                for payload in payloads {
                                    decoded.extend_from_slice(&payload);
                                }
                            }
                        }

                        if decoded.len() < 56 + 2 + 1 + 1 + 1 + 13 + 2 + 2 {
                            continue;
                        }
                        assert_eq!(&decoded[..56], expected_hash.as_slice());
                        assert_eq!(&decoded[56..58], b"\r\n");
                        assert_eq!(decoded[58], 0x01);
                        assert_eq!(decoded[59], 0x03);
                        let domain_len = decoded[60] as usize;
                        let domain_start = 61;
                        let domain_end = domain_start + domain_len;
                        if decoded.len() < domain_end + 4 {
                            continue;
                        }
                        assert_eq!(
                            &decoded[domain_start..domain_end],
                            b"probe.example"
                        );
                        let port = u16::from_be_bytes([
                            decoded[domain_end],
                            decoded[domain_end + 1],
                        ]);
                        assert_eq!(port, 80);
                        assert_eq!(
                            &decoded[domain_end + 2..domain_end + 4],
                            b"\r\n"
                        );
                        let http_start = domain_end + 4;
                        let Some(http_end) = decoded[http_start..]
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .map(|index| http_start + index + 4)
                        else {
                            continue;
                        };
                        let http_request =
                            String::from_utf8_lossy(&decoded[http_start..http_end]);
                        assert!(
                            http_request.starts_with("GET /generate_204 HTTP/1.1")
                        );
                        assert!(
                            http_request
                                .to_ascii_lowercase()
                                .contains("host: probe.example")
                        );
                        tokio::time::sleep(response_delay).await;
                        tx.send(Ok(Frame::data(encode_grpc_message(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        multi_mode,
                    ))))
                    .await
                    .expect("send gRPC probe response Hunk");
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            "grpc-status",
                            hyper::header::HeaderValue::from_static("0"),
                        );
                        tx.send(Ok(Frame::trailers(trailers)))
                            .await
                            .expect("send gRPC probe success trailers");
                        break;
                    }
                });
                let response_stream =
                    futures::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|frame| (frame, rx))
                    });
                let response = Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/grpc")
                    .body(StreamBody::new(response_stream))
                    .expect("build fake gRPC probe response");
                Ok::<_, Infallible>(response)
            },
        );
        http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve fake Trojan gRPC probe connection");
    }

    async fn start_fake_trojan_grpc_probe_server_with_mode(
        response_delay: Duration,
        multi_mode: bool,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC probe server");
        let address = listener
            .local_addr()
            .expect("fake Trojan gRPC probe address");
        let task = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept Trojan gRPC probe");
            serve_fake_trojan_grpc_probe(stream, response_delay, multi_mode).await;
        });
        (address, task)
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    async fn start_fake_trojan_grpc_probe_server(
        response_delay: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        start_fake_trojan_grpc_probe_server_with_mode(response_delay, false).await
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    async fn accept_test_reality_probe_stream(
        mut stream: tokio::net::TcpStream,
        config: crate::reality::RealityServerConfig,
    ) -> crate::reality::RealityTlsStream<
        Box<dyn AsyncStream>,
        crate::reality::RealityServerConnection,
    > {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut record_header = [0u8; 5];
        stream
            .read_exact(&mut record_header)
            .await
            .expect("read observatory REALITY ClientHello header");
        assert_eq!(record_header[0], 0x16);
        let record_len =
            u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut client_hello = Vec::with_capacity(5 + record_len);
        client_hello.extend_from_slice(&record_header);
        client_hello.resize(5 + record_len, 0);
        stream
            .read_exact(&mut client_hello[5..])
            .await
            .expect("read observatory REALITY ClientHello payload");

        let mut session = crate::reality::RealityServerConnection::new(config)
            .expect("build observatory REALITY server session");
        session
            .validate_client_hello(&client_hello)
            .expect("validate observatory REALITY ClientHello");
        session
            .build_server_response(Vec::new())
            .expect("build observatory REALITY response");
        let mut response = Vec::new();
        while session.wants_write() {
            session
                .write_tls(&mut response)
                .expect("serialize observatory REALITY response");
        }
        stream
            .write_all(&response)
            .await
            .expect("write observatory REALITY response");
        stream
            .flush()
            .await
            .expect("flush observatory REALITY response");

        while session.is_handshaking() {
            let mut buffer = [0u8; 4096];
            let read = stream
                .read(&mut buffer)
                .await
                .expect("read observatory REALITY client Finished");
            assert!(read > 0, "REALITY probe closed during handshake");
            session
                .read_tls(&mut std::io::Cursor::new(&buffer[..read]))
                .expect("feed observatory REALITY client handshake");
            session
                .process_new_packets()
                .expect("process observatory REALITY client handshake");
            if session.wants_write() {
                let mut pending = Vec::new();
                while session.wants_write() {
                    session
                        .write_tls(&mut pending)
                        .expect("serialize pending observatory REALITY data");
                }
                stream
                    .write_all(&pending)
                    .await
                    .expect("write pending observatory REALITY data");
                stream
                    .flush()
                    .await
                    .expect("flush pending observatory REALITY data");
            }
        }
        crate::reality::RealityTlsStream::new(
            Box::new(stream) as Box<dyn AsyncStream>,
            session,
        )
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    async fn start_fake_trojan_reality_probe_server(
        tag: &str,
        response_delay: Duration,
    ) -> (OutboundSummary, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (private_key_b64, public_key_b64) = crate::reality::generate_keypair()
            .expect("generate observatory REALITY keypair");
        let private_key = crate::reality::decode_private_key(&private_key_b64)
            .expect("decode observatory REALITY private key");
        let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan REALITY probe server");
        let address = listener
            .local_addr()
            .expect("fake Trojan REALITY probe address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan REALITY probe");
            let mut stream = accept_test_reality_probe_stream(
                stream,
                crate::reality::RealityServerConfig {
                    private_key,
                    short_ids: vec![short_id],
                    dest: crate::address::NetLocation::new(
                        crate::address::Address::Hostname(
                            "reality.example.test".to_string(),
                        ),
                        443,
                    ),
                    server_names: vec!["reality.example.test".to_string()],
                    max_time_diff: Some(60_000),
                    min_client_version: Some([26, 3, 27]),
                    max_client_version: None,
                    cipher_suites: Vec::new(),
                },
            )
            .await;

            let mut hash = [0u8; 56];
            stream
                .read_exact(&mut hash)
                .await
                .expect("read REALITY Trojan hash");
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
            let expected = digest
                .as_ref()
                .iter()
                .flat_map(|byte| format!("{byte:02x}").into_bytes())
                .collect::<Vec<_>>();
            assert_eq!(hash.as_slice(), expected.as_slice());
            let mut crlf = [0u8; 2];
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read REALITY Trojan auth CRLF");
            assert_eq!(crlf, *b"\r\n");
            assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
            assert_eq!(stream.read_u8().await.expect("read Trojan ATYP"), 0x03);
            let length =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; length];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read REALITY probe domain");
            assert_eq!(domain, b"probe.example");
            assert_eq!(stream.read_u16().await.expect("read probe port"), 80);
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read REALITY Trojan request CRLF");
            assert_eq!(crlf, *b"\r\n");
            let mut request = [0u8; 2048];
            let read = stream
                .read(&mut request)
                .await
                .expect("read REALITY HTTP probe");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("host: probe.example"));
            tokio::time::sleep(response_delay).await;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write REALITY HTTP probe response");
            stream
                .flush()
                .await
                .expect("flush REALITY HTTP probe response");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "reality.example.test",
                    "publicKey": public_key_b64,
                    "shortId": "0011223344556677",
                    "spiderX": "/"
                }
            }
        }))
        .expect("parse fake Trojan REALITY outbound");
        (
            compile_static_outbound(&item)
                .expect("compile fake Trojan REALITY outbound"),
            task,
        )
    }

    #[cfg(all(feature = "trojan", feature = "reality", feature = "grpc_transport"))]
    async fn start_fake_trojan_grpc_reality_probe_server(
        tag: &str,
        response_delay: Duration,
    ) -> (OutboundSummary, tokio::task::JoinHandle<()>) {
        let (private_key_b64, public_key_b64) = crate::reality::generate_keypair()
            .expect("generate gRPC REALITY observatory keypair");
        let private_key = crate::reality::decode_private_key(&private_key_b64)
            .expect("decode gRPC REALITY observatory private key");
        let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC REALITY probe server");
        let address = listener
            .local_addr()
            .expect("fake Trojan gRPC REALITY probe address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan gRPC REALITY probe");
            let stream = accept_test_reality_probe_stream(
                stream,
                crate::reality::RealityServerConfig {
                    private_key,
                    short_ids: vec![short_id],
                    dest: crate::address::NetLocation::new(
                        crate::address::Address::Hostname(
                            "reality.example.test".to_string(),
                        ),
                        443,
                    ),
                    server_names: vec!["reality.example.test".to_string()],
                    max_time_diff: Some(60_000),
                    min_client_version: Some([26, 3, 27]),
                    max_client_version: None,
                    cipher_suites: Vec::new(),
                },
            )
            .await;
            serve_fake_trojan_grpc_probe(stream, response_delay, false).await;
        });
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": address.ip().to_string(),
                "port": address.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "reality.example.test",
                    "publicKey": public_key_b64,
                    "shortId": "0011223344556677",
                    "spiderX": "/"
                },
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService"
                }
            }
        }))
        .expect("parse fake Trojan gRPC REALITY outbound");
        (
            compile_static_outbound(&item)
                .expect("compile fake Trojan gRPC REALITY outbound"),
            task,
        )
    }

    #[cfg(feature = "trojan")]
    async fn start_fake_trojan_probe_server(
        response_delay: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan probe server");
        let address = listener.local_addr().expect("fake Trojan probe address");
        let task = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept Trojan probe");
            let mut hash = [0u8; 56];
            stream
                .read_exact(&mut hash)
                .await
                .expect("read Trojan hash");
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
            let expected = digest
                .as_ref()
                .iter()
                .flat_map(|byte| format!("{byte:02x}").into_bytes())
                .collect::<Vec<_>>();
            assert_eq!(hash.as_slice(), expected.as_slice());
            let mut crlf = [0u8; 2];
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read Trojan CRLF");
            assert_eq!(crlf, *b"\r\n");
            assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
            assert_eq!(stream.read_u8().await.expect("read Trojan ATYP"), 0x03);
            let length =
                stream.read_u8().await.expect("read Trojan domain length") as usize;
            let mut domain = vec![0u8; length];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read probe domain");
            let port = stream.read_u16().await.expect("read probe port");
            assert_eq!(domain, b"probe.example");
            assert_eq!(port, 80);
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read request CRLF");
            assert_eq!(crlf, *b"\r\n");
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).await.expect("read HTTP probe");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("host: probe.example"));
            tokio::time::sleep(response_delay).await;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write HTTP probe response");
        });
        (address, task)
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    async fn serve_trojan_httpupgrade_probe(
        mut stream: Box<dyn AsyncStream>,
        response_delay: Duration,
        expected_host: &str,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut upgrade = Vec::new();
        loop {
            if upgrade.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(upgrade.len() < 64 * 1024, "HTTPUpgrade request too large");
            let mut chunk = [0u8; 2048];
            let read = stream
                .read(&mut chunk)
                .await
                .expect("read HTTPUpgrade request");
            assert!(read > 0, "HTTPUpgrade probe closed during upgrade");
            upgrade.extend_from_slice(&chunk[..read]);
        }
        let header_end = upgrade
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTPUpgrade header terminator")
            + 4;
        assert_eq!(
            upgrade.len(),
            header_end,
            "Trojan probe must wait for HTTPUpgrade 101 before sending data"
        );
        let request =
            std::str::from_utf8(&upgrade).expect("ASCII HTTPUpgrade request");
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next(), Some("GET /trojan HTTP/1.1"));
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) =
                line.split_once(':').expect("valid HTTPUpgrade header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        assert_eq!(
            headers.get("upgrade").map(String::as_str),
            Some("websocket")
        );
        assert_eq!(
            headers.get("connection").map(String::as_str),
            Some("Upgrade")
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("write HTTPUpgrade 101");
        stream.flush().await.expect("flush HTTPUpgrade 101");

        let mut hash = [0u8; 56];
        stream
            .read_exact(&mut hash)
            .await
            .expect("read Trojan hash after HTTPUpgrade");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(hash.as_slice(), expected.as_slice());
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.expect("read auth CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
        assert_eq!(stream.read_u8().await.expect("read Trojan ATYP"), 0x03);
        let length = stream.read_u8().await.expect("read domain length") as usize;
        let mut domain = vec![0u8; length];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read probe domain");
        assert_eq!(domain, b"probe.example");
        assert_eq!(stream.read_u16().await.expect("read probe port"), 80);
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read request CRLF");
        assert_eq!(crlf, *b"\r\n");
        let mut request = [0u8; 2048];
        let read = stream.read(&mut request).await.expect("read HTTP probe");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
        assert!(request.to_ascii_lowercase().contains("host: probe.example"));
        tokio::time::sleep(response_delay).await;
        stream
            .write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write HTTP probe response");
        stream.flush().await.expect("flush HTTP probe response");
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    async fn start_fake_trojan_httpupgrade_probe_server(
        response_delay: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan HTTPUpgrade probe server");
        let address = listener
            .local_addr()
            .expect("fake Trojan HTTPUpgrade probe address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan HTTPUpgrade probe");
            serve_trojan_httpupgrade_probe(
                Box::new(stream),
                response_delay,
                "upgrade.example.test",
            )
            .await;
        });
        (address, task)
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    async fn serve_trojan_websocket_probe(
        mut stream: Box<dyn AsyncStream>,
        response_delay: Duration,
        expected_host: &str,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut upgrade = Vec::new();
        loop {
            if upgrade.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(upgrade.len() < 64 * 1024, "WebSocket upgrade too large");
            let mut chunk = [0u8; 2048];
            let read = stream
                .read(&mut chunk)
                .await
                .expect("read WebSocket upgrade");
            assert!(read > 0, "WebSocket probe closed during upgrade");
            upgrade.extend_from_slice(&chunk[..read]);
        }
        let header_end = upgrade
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("WebSocket header terminator")
            + 4;
        assert_eq!(
            upgrade.len(),
            header_end,
            "Trojan probe must wait for WebSocket 101 before sending data"
        );
        let request =
            std::str::from_utf8(&upgrade).expect("ASCII WebSocket upgrade");
        let mut lines = request.split("\r\n");
        assert_eq!(lines.next(), Some("GET /trojan HTTP/1.1"));
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) =
                line.split_once(':').expect("valid WebSocket header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        assert_eq!(
            headers.get("upgrade").map(String::as_str),
            Some("websocket")
        );
        assert!(
            headers
                .get("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
        );
        let key = headers
            .get("sec-websocket-key")
            .expect("WebSocket key header");
        const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut accept_input = key.as_bytes().to_vec();
        accept_input.extend_from_slice(WS_GUID);
        let digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            &accept_input,
        );
        let accept =
            base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write WebSocket 101");
        stream.flush().await.expect("flush WebSocket 101");

        let mut stream = WebsocketStream::new(stream, false, &[]);
        let mut hash = [0u8; 56];
        stream
            .read_exact(&mut hash)
            .await
            .expect("read framed Trojan hash");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(hash.as_slice(), expected.as_slice());
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.expect("read auth CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
        assert_eq!(stream.read_u8().await.expect("read Trojan ATYP"), 0x03);
        let length = stream.read_u8().await.expect("read domain length") as usize;
        let mut domain = vec![0u8; length];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read probe domain");
        assert_eq!(domain, b"probe.example");
        assert_eq!(stream.read_u16().await.expect("read probe port"), 80);
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read request CRLF");
        assert_eq!(crlf, *b"\r\n");
        let mut request = [0u8; 2048];
        let read = stream.read(&mut request).await.expect("read HTTP probe");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
        assert!(request.to_ascii_lowercase().contains("host: probe.example"));
        tokio::time::sleep(response_delay).await;
        stream
            .write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write framed HTTP probe response");
        stream
            .flush()
            .await
            .expect("flush framed HTTP probe response");
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    async fn start_fake_trojan_websocket_probe_server(
        response_delay: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan WebSocket probe server");
        let address = listener
            .local_addr()
            .expect("fake Trojan WebSocket probe address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan WebSocket probe");
            serve_trojan_websocket_probe(
                Box::new(stream),
                response_delay,
                "ws.example.test",
            )
            .await;
        });
        (address, task)
    }

    #[test]
    fn parses_observatory_duration_and_defaults() {
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["direct".into()],
            probe_interval: Some(serde_json::json!("250ms")),
            ..ObservatoryConfig::default()
        })
        .expect("parse observatory config");
        assert_eq!(config.interval, Duration::from_millis(250));
        assert_eq!(config.probe_url.as_str(), DEFAULT_PROBE_URL);
        assert_eq!(config.method, Method::GET);
        assert_eq!(config.timeout, DEFAULT_PROBE_TIMEOUT);
        assert_eq!(config.sampling_count, 0);
        assert!(!config.consume_body);
    }

    #[test]
    fn explicit_zero_observatory_values_use_xray_defaults() {
        let standard = ActiveObserverConfig::try_from(&ObservatoryConfig {
            probe_interval: Some(serde_json::json!(0)),
            ..ObservatoryConfig::default()
        })
        .expect("zero standard interval should use default");
        assert_eq!(standard.interval, DEFAULT_PROBE_INTERVAL);

        let burst = ActiveObserverConfig::try_from(&BurstObservatoryConfig {
            ping_config: Some(crate::config::def::HealthPingConfig {
                interval: Some(serde_json::json!(0)),
                sampling: Some(0),
                timeout: Some(serde_json::json!(0)),
                ..Default::default()
            }),
            ..BurstObservatoryConfig::default()
        })
        .expect("zero burst settings should use defaults");
        assert_eq!(burst.interval, DEFAULT_BURST_INTERVAL);
        assert_eq!(burst.timeout, DEFAULT_PROBE_TIMEOUT);
        assert_eq!(burst.sampling_count, DEFAULT_HEALTH_WINDOW);
    }

    #[test]
    fn parses_burst_observatory_defaults_and_limits() {
        let config = ActiveObserverConfig::try_from(&BurstObservatoryConfig {
            subject_selector: vec![" direct ".into()],
            ping_config: Some(crate::config::def::HealthPingConfig {
                interval: Some(serde_json::json!("1s")),
                sampling: Some(4),
                timeout: Some(serde_json::json!("2s")),
                connectivity: "https://connectivity.example/generate_204".into(),
                ..Default::default()
            }),
        })
        .expect("parse burst observatory config");

        assert_eq!(config.selectors, vec!["direct"]);
        assert_eq!(config.probe_url.as_str(), DEFAULT_BURST_PROBE_URL);
        assert_eq!(config.interval, MIN_BURST_INTERVAL);
        assert_eq!(config.timeout, Duration::from_secs(2));
        assert_eq!(config.method, Method::HEAD);
        assert_eq!(config.sampling_count, 4);
        assert!(!config.consume_body);
        assert_eq!(
            config.connectivity_url.as_ref().map(Url::as_str),
            Some("https://connectivity.example/generate_204")
        );
    }

    #[test]
    fn standard_observatory_takes_precedence_and_burst_requires_ping_config() {
        let standard = ObservatoryConfig {
            subject_selector: vec!["standard".into()],
            ..ObservatoryConfig::default()
        };
        let burst = BurstObservatoryConfig::default();
        let selected = resolve_observer_config(Some(&standard), Some(&burst))
            .expect("standard observatory should take precedence")
            .expect("observer config missing");
        assert_eq!(selected.selectors, vec!["standard"]);
        assert_eq!(selected.method, Method::GET);

        let missing = ActiveObserverConfig::try_from(&burst)
            .expect_err("burst observatory requires pingConfig");
        assert!(missing.contains("requires a valid pingConfig"));
    }

    #[tokio::test]
    async fn probes_selected_freedom_and_blackhole_outbounds() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observatory test server");
        let address = listener.local_addr().expect("observatory server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.expect("read probe");
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write probe response");
        });
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("block", "blackhole"),
                outbound("ignored", "freedom"),
            ],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["direct".into(), "block".into()],
            probe_url: format!("http://{address}/generate_204"),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build observatory test config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        server.await.expect("observatory server task");
        let observations = runtime.outbound_observations();
        assert!(observations["direct"].alive);
        assert_eq!(observations["direct"].health_all, 0);
        assert!(!observations["block"].alive);
        assert_eq!(observations["block"].health_all, 0);
        assert_eq!(observations["block"].health_fail, 0);
        assert!(!observations.contains_key("ignored"));
    }

    #[tokio::test]
    async fn observatory_probe_uses_configured_socks_outbound() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake SOCKS observatory server");
        let proxy_addr = listener.local_addr().expect("fake SOCKS address");
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept SOCKS probe");
            let mut greeting = [0u8; 3];
            stream
                .read_exact(&mut greeting)
                .await
                .expect("read SOCKS greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream
                .write_all(&[0x05, 0x00])
                .await
                .expect("write SOCKS method");

            let mut header = [0u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read SOCKS CONNECT");
            assert_eq!(header, [0x05, 0x01, 0x00, 0x03]);
            let length =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await.expect("read domain");
            let port = stream.read_u16().await.expect("read destination port");
            assert_eq!(domain, b"probe.example");
            assert_eq!(port, 80);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("write SOCKS CONNECT response");

            let mut request = vec![0u8; 2048];
            let read = stream.read(&mut request).await.expect("read HTTP probe");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("host: probe.example"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write HTTP probe response");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "tag": "proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": proxy_addr.port()
            }
        }))
        .expect("parse observatory SOCKS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![compile_static_outbound(&item).expect("compile SOCKS outbound")],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build SOCKS observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server.await.expect("fake SOCKS observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("SOCKS observatory result");
        assert!(
            observation.alive,
            "SOCKS probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "tls"))]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_tls_outbound() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan TLS observatory certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("select TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("build Trojan TLS observatory server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan TLS observatory server");
        let proxy_addr = listener.local_addr().expect("fake Trojan TLS address");
        let server = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept Trojan TLS probe");
            let mut stream =
                acceptor.accept(stream).await.expect("accept Trojan TLS");
            let mut hash = [0u8; 56];
            stream
                .read_exact(&mut hash)
                .await
                .expect("read Trojan hash");
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
            let expected = digest
                .as_ref()
                .iter()
                .flat_map(|byte| format!("{byte:02x}").into_bytes())
                .collect::<Vec<_>>();
            assert_eq!(hash.as_slice(), expected.as_slice());
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await.expect("read auth CRLF");
            assert_eq!(crlf, *b"\r\n");
            assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
            assert_eq!(stream.read_u8().await.expect("read Trojan ATYP"), 0x03);
            let length =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; length];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read probe domain");
            let port = stream.read_u16().await.expect("read probe port");
            assert_eq!(domain, b"probe.example");
            assert_eq!(port, 80);
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read request CRLF");
            assert_eq!(crlf, *b"\r\n");
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).await.expect("read HTTP probe");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /generate_204 HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write TLS probe response");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": proxy_addr.ip().to_string(),
                "port": proxy_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                }
            }
        }))
        .expect("parse observatory Trojan TLS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item).expect("compile Trojan TLS outbound"),
            ],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan TLS observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server.await.expect("fake Trojan TLS observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan TLS observatory result");
        assert!(
            observation.alive,
            "Trojan TLS probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_grpc_outbound() {
        let (proxy_addr, server) =
            start_fake_trojan_grpc_probe_server(Duration::from_millis(1)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![static_trojan_grpc_outbound("proxy", proxy_addr)],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan gRPC observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server.await.expect("fake Trojan gRPC observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan gRPC observatory result");
        assert!(
            observation.alive,
            "Trojan gRPC probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn least_ping_uses_real_trojan_grpc_observatory_rtt() {
        let (fast_addr, fast_server) =
            start_fake_trojan_grpc_probe_server(Duration::from_millis(5)).await;
        let (slow_addr, slow_server) =
            start_fake_trojan_grpc_probe_server(Duration::from_millis(120)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_trojan_grpc_outbound("trojan-grpc-fast", fast_addr),
                static_trojan_grpc_outbound("trojan-grpc-slow", slow_addr),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-grpc-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan gRPC leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-grpc-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan gRPC leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server.await.expect("fast Trojan gRPC probe task");
        slow_server.await.expect("slow Trojan gRPC probe task");
        let fast = runtime
            .outbound_observation("trojan-grpc-fast")
            .expect("fast Trojan gRPC observation");
        let slow = runtime
            .outbound_observation("trojan-grpc-slow")
            .expect("slow Trojan gRPC observation");
        assert!(fast.alive && slow.alive);
        assert!(
            fast.delay_ms < slow.delay_ms,
            "expected fast Trojan gRPC RTT < slow RTT: {fast:?} vs {slow:?}"
        );
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan gRPC leastPing routing should not fail")
            .expect("Trojan gRPC leastPing route should select an outbound");
        assert_eq!(selected.tag, "trojan-grpc-fast");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn observatory_probe_and_least_ping_use_trojan_grpc_multi_outbound() {
        let (fast_addr, fast_server) =
            start_fake_trojan_grpc_probe_server_with_mode(
                Duration::from_millis(5),
                true,
            )
            .await;
        let (slow_addr, slow_server) =
            start_fake_trojan_grpc_probe_server_with_mode(
                Duration::from_millis(120),
                true,
            )
            .await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_trojan_grpc_outbound_with_mode(
                    "trojan-grpc-multi-fast",
                    fast_addr,
                    true,
                ),
                static_trojan_grpc_outbound_with_mode(
                    "trojan-grpc-multi-slow",
                    slow_addr,
                    true,
                ),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-grpc-multi-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan gRPC TunMulti leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-grpc-multi-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan gRPC TunMulti observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server
            .await
            .expect("fast Trojan gRPC TunMulti probe task");
        slow_server
            .await
            .expect("slow Trojan gRPC TunMulti probe task");
        let fast = runtime
            .outbound_observation("trojan-grpc-multi-fast")
            .expect("fast Trojan gRPC TunMulti observation");
        let slow = runtime
            .outbound_observation("trojan-grpc-multi-slow")
            .expect("slow Trojan gRPC TunMulti observation");
        assert!(fast.alive && slow.alive);
        assert!(fast.delay_ms < slow.delay_ms);
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan gRPC TunMulti leastPing routing should not fail")
            .expect("Trojan gRPC TunMulti leastPing should select an outbound");
        assert_eq!(selected.tag, "trojan-grpc-multi-fast");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "reality"))]
    #[tokio::test]
    async fn observatory_and_least_ping_use_trojan_grpc_reality_outbound() {
        let (fast_outbound, fast_server) =
            start_fake_trojan_grpc_reality_probe_server(
                "trojan-grpc-reality-fast",
                Duration::from_millis(5),
            )
            .await;
        let (slow_outbound, slow_server) =
            start_fake_trojan_grpc_reality_probe_server(
                "trojan-grpc-reality-slow",
                Duration::from_millis(120),
            )
            .await;
        let runtime =
            RuntimeState::new(Vec::new(), vec![fast_outbound, slow_outbound]);
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-grpc-reality-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan gRPC REALITY leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-grpc-reality-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan gRPC REALITY observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server
            .await
            .expect("fast Trojan gRPC REALITY probe task");
        slow_server
            .await
            .expect("slow Trojan gRPC REALITY probe task");
        let fast = runtime
            .outbound_observation("trojan-grpc-reality-fast")
            .expect("fast Trojan gRPC REALITY observation");
        let slow = runtime
            .outbound_observation("trojan-grpc-reality-slow")
            .expect("slow Trojan gRPC REALITY observation");
        assert!(fast.alive && slow.alive);
        assert!(fast.delay_ms < slow.delay_ms);
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan gRPC REALITY leastPing routing should not fail")
            .expect("Trojan gRPC REALITY leastPing should select an outbound");
        assert_eq!(selected.tag, "trojan-grpc-reality-fast");
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_httpupgrade_outbound() {
        let (proxy_addr, server) =
            start_fake_trojan_httpupgrade_probe_server(Duration::from_millis(1))
                .await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![static_trojan_httpupgrade_outbound("proxy", proxy_addr)],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan HTTPUpgrade observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server
            .await
            .expect("fake Trojan HTTPUpgrade observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan HTTPUpgrade observatory result");
        assert!(
            observation.alive,
            "Trojan HTTPUpgrade probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    #[tokio::test]
    async fn least_ping_uses_real_trojan_httpupgrade_observatory_rtt() {
        let (fast_addr, fast_server) =
            start_fake_trojan_httpupgrade_probe_server(Duration::from_millis(5))
                .await;
        let (slow_addr, slow_server) =
            start_fake_trojan_httpupgrade_probe_server(Duration::from_millis(120))
                .await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_trojan_httpupgrade_outbound("trojan-hu-fast", fast_addr),
                static_trojan_httpupgrade_outbound("trojan-hu-slow", slow_addr),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-hu-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan HTTPUpgrade leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-hu-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan HTTPUpgrade leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server
            .await
            .expect("fast Trojan HTTPUpgrade probe task");
        slow_server
            .await
            .expect("slow Trojan HTTPUpgrade probe task");
        let fast = runtime.outbound_observation("trojan-hu-fast").unwrap();
        let slow = runtime.outbound_observation("trojan-hu-slow").unwrap();
        assert!(fast.alive && slow.alive);
        assert!(fast.delay_ms < slow.delay_ms);
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan HTTPUpgrade leastPing routing should not fail")
            .expect("Trojan HTTPUpgrade leastPing route should select an outbound");
        assert_eq!(selected.tag, "trojan-hu-fast");
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_reality_outbound() {
        let (outbound, server) = start_fake_trojan_reality_probe_server(
            "proxy",
            Duration::from_millis(1),
        )
        .await;
        let runtime = RuntimeState::new(Vec::new(), vec![outbound]);
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan REALITY observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server.await.expect("fake Trojan REALITY observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan REALITY observatory result");
        assert!(
            observation.alive,
            "Trojan REALITY probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    #[tokio::test]
    async fn least_ping_uses_real_trojan_reality_observatory_rtt() {
        let (fast_outbound, fast_server) = start_fake_trojan_reality_probe_server(
            "trojan-reality-fast",
            Duration::from_millis(5),
        )
        .await;
        let (slow_outbound, slow_server) = start_fake_trojan_reality_probe_server(
            "trojan-reality-slow",
            Duration::from_millis(120),
        )
        .await;
        let runtime =
            RuntimeState::new(Vec::new(), vec![fast_outbound, slow_outbound]);
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-reality-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan REALITY leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-reality-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan REALITY leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server.await.expect("fast Trojan REALITY probe task");
        slow_server.await.expect("slow Trojan REALITY probe task");
        let fast = runtime
            .outbound_observation("trojan-reality-fast")
            .expect("fast Trojan REALITY observation");
        let slow = runtime
            .outbound_observation("trojan-reality-slow")
            .expect("slow Trojan REALITY observation");
        assert!(fast.alive && slow.alive);
        assert!(
            fast.delay_ms < slow.delay_ms,
            "expected fast Trojan REALITY RTT < slow RTT: {fast:?} vs {slow:?}"
        );
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan REALITY leastPing routing should not fail")
            .expect("Trojan REALITY leastPing route should select an outbound");
        assert_eq!(selected.tag, "trojan-reality-fast");
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_websocket_outbound() {
        let (proxy_addr, server) =
            start_fake_trojan_websocket_probe_server(Duration::from_millis(1)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![static_trojan_websocket_outbound("proxy", proxy_addr)],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan WebSocket observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server
            .await
            .expect("fake Trojan WebSocket observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan WebSocket observatory result");
        assert!(
            observation.alive,
            "Trojan WebSocket probe should be alive: {observation:?}"
        );
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    #[tokio::test]
    async fn least_ping_uses_real_trojan_websocket_observatory_rtt() {
        let (fast_addr, fast_server) =
            start_fake_trojan_websocket_probe_server(Duration::from_millis(5)).await;
        let (slow_addr, slow_server) =
            start_fake_trojan_websocket_probe_server(Duration::from_millis(120))
                .await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_trojan_websocket_outbound("trojan-ws-fast", fast_addr),
                static_trojan_websocket_outbound("trojan-ws-slow", slow_addr),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-ws-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan WebSocket leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-ws-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan WebSocket leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server.await.expect("fast Trojan WebSocket probe task");
        slow_server.await.expect("slow Trojan WebSocket probe task");
        let fast = runtime.outbound_observation("trojan-ws-fast").unwrap();
        let slow = runtime.outbound_observation("trojan-ws-slow").unwrap();
        assert!(fast.alive && slow.alive);
        assert!(
            fast.delay_ms < slow.delay_ms,
            "expected fast Trojan WebSocket RTT < slow RTT: {fast:?} vs {slow:?}"
        );
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan WebSocket leastPing routing should not fail")
            .expect("Trojan WebSocket leastPing route should select an outbound");
        assert_eq!(selected.tag, "trojan-ws-fast");
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn observatory_probe_uses_configured_trojan_outbound() {
        let (proxy_addr, server) =
            start_fake_trojan_probe_server(Duration::from_millis(1)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![static_trojan_outbound("proxy", proxy_addr)],
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        server.await.expect("fake Trojan observatory task");
        let observation = runtime
            .outbound_observation("proxy")
            .expect("Trojan observatory result");
        assert!(
            observation.alive,
            "Trojan probe should be alive: {observation:?}"
        );
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn least_ping_uses_real_trojan_observatory_rtt() {
        let (fast_addr, fast_server) =
            start_fake_trojan_probe_server(Duration::from_millis(5)).await;
        let (slow_addr, slow_server) =
            start_fake_trojan_probe_server(Duration::from_millis(120)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_trojan_outbound("trojan-fast", fast_addr),
                static_trojan_outbound("trojan-slow", slow_addr),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["trojan-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile Trojan leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["trojan-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: true,
            ..ObservatoryConfig::default()
        })
        .expect("build Trojan leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server.await.expect("fast Trojan probe task");
        slow_server.await.expect("slow Trojan probe task");
        let fast = runtime.outbound_observation("trojan-fast").unwrap();
        let slow = runtime.outbound_observation("trojan-slow").unwrap();
        assert!(fast.alive && slow.alive);
        assert!(
            fast.delay_ms < slow.delay_ms,
            "expected fast Trojan RTT < slow Trojan RTT: {fast:?} vs {slow:?}"
        );
        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("Trojan leastPing routing should not fail")
            .expect("Trojan leastPing route should select an outbound");
        assert_eq!(selected.tag, "trojan-fast");
    }

    #[tokio::test]
    async fn least_ping_uses_real_socks_observatory_rtt() {
        let (fast_addr, fast_server) =
            start_fake_socks_probe_server(Duration::from_millis(5)).await;
        let (slow_addr, slow_server) =
            start_fake_socks_probe_server(Duration::from_millis(750)).await;
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                static_socks_outbound("proxy-fast", fast_addr),
                static_socks_outbound("proxy-slow", slow_addr),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["proxy-".into()],
                    strategy: BalancerStrategyConfig {
                        kind: "leastPing".into(),
                        settings: None,
                    },
                    fallback_tag: None,
                }],
            )
            .expect("compile leastPing routing"),
        );
        let config = ActiveObserverConfig::try_from(&ObservatoryConfig {
            subject_selector: vec!["proxy-".into()],
            probe_url: "http://probe.example/generate_204".into(),
            enable_concurrency: false,
            ..ObservatoryConfig::default()
        })
        .expect("build leastPing observatory config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 2);
        fast_server.await.expect("fast SOCKS probe task");
        slow_server.await.expect("slow SOCKS probe task");
        let fast = runtime.outbound_observation("proxy-fast").unwrap();
        let slow = runtime.outbound_observation("proxy-slow").unwrap();
        assert!(fast.alive && slow.alive);
        assert!(
            fast.delay_ms < slow.delay_ms,
            "expected fast SOCKS RTT < slow SOCKS RTT: {fast:?} vs {slow:?}"
        );

        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "edge".into(),
                ..RoutingInput::default()
            })
            .expect("leastPing routing should not fail")
            .expect("leastPing route should select an outbound");
        assert_eq!(selected.tag, "proxy-fast");
    }

    #[tokio::test]
    async fn rolling_health_window_is_bounded() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let mut windows = HashMap::new();
        for delay in 1..=15 {
            apply_probe_result(
                &runtime,
                &mut windows,
                "direct".into(),
                ProbeResult {
                    alive: delay % 4 != 0,
                    delay_ms: delay,
                    error: String::new(),
                },
                DEFAULT_HEALTH_WINDOW,
                Duration::MAX,
            );
        }
        let status = runtime.outbound_observations().remove("direct").unwrap();
        assert_eq!(status.health_all, 10);
        assert_eq!(status.health_fail, 2);
        assert!(status.alive);
        assert_eq!(status.delay_ms, status.health_average_ms);
        assert_eq!(status.delay_ms, 10);
        assert_eq!(status.last_seen_time, 0);
        assert_eq!(status.last_try_time, 0);
    }

    #[tokio::test]
    async fn burst_liveness_uses_health_window_not_latest_sample() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let mut windows = HashMap::new();
        for result in [
            ProbeResult {
                alive: true,
                delay_ms: 20,
                error: String::new(),
            },
            ProbeResult {
                alive: true,
                delay_ms: 40,
                error: String::new(),
            },
            ProbeResult {
                alive: false,
                delay_ms: FAILED_DELAY_MS,
                error: "timeout".into(),
            },
        ] {
            apply_probe_result(
                &runtime,
                &mut windows,
                "direct".into(),
                result,
                10,
                Duration::MAX,
            );
        }

        let status = runtime.outbound_observations().remove("direct").unwrap();
        assert!(status.alive);
        assert_eq!(status.delay_ms, 30);
        assert_eq!(status.health_all, 3);
        assert_eq!(status.health_fail, 1);
        assert!(status.last_error_reason.is_empty());
    }

    #[tokio::test]
    async fn single_successful_burst_sample_uses_half_rtt_deviation() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let mut windows = HashMap::new();

        apply_probe_result(
            &runtime,
            &mut windows,
            "direct".into(),
            ProbeResult {
                alive: true,
                delay_ms: 20,
                error: String::new(),
            },
            10,
            Duration::MAX,
        );

        let status = runtime.outbound_observations().remove("direct").unwrap();
        assert_eq!(status.health_all, 1);
        assert_eq!(status.health_average_ms, 20);
        assert_eq!(status.health_deviation_ms, 10);
    }

    #[tokio::test]
    async fn all_failed_burst_samples_report_zero_rtt_statistics() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let mut windows = HashMap::new();
        for _ in 0..3 {
            apply_probe_result(
                &runtime,
                &mut windows,
                "direct".into(),
                ProbeResult {
                    alive: false,
                    delay_ms: FAILED_DELAY_MS,
                    error: "timeout".into(),
                },
                10,
                Duration::MAX,
            );
        }

        let status = runtime.outbound_observations().remove("direct").unwrap();
        assert_eq!(status.health_all, 3);
        assert_eq!(status.health_fail, 3);
        assert_eq!(status.health_average_ms, 0);
        assert_eq!(status.health_deviation_ms, 0);
        assert_eq!(status.health_max_ms, 0);
        assert_eq!(status.health_min_ms, 0);
    }

    #[tokio::test]
    async fn expired_burst_samples_are_removed_before_statistics() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let mut windows = HashMap::from([(
            "direct".to_string(),
            ProbeWindow {
                samples: VecDeque::from([ProbeSample {
                    recorded_at: Instant::now()
                        .checked_sub(Duration::from_secs(2))
                        .expect("old sample timestamp"),
                    alive: false,
                    delay_ms: FAILED_DELAY_MS,
                }]),
                last_seen_time: 0,
            },
        )]);

        apply_probe_result(
            &runtime,
            &mut windows,
            "direct".into(),
            ProbeResult {
                alive: true,
                delay_ms: 12,
                error: String::new(),
            },
            10,
            Duration::from_millis(100),
        );

        let status = runtime.outbound_observations().remove("direct").unwrap();
        assert_eq!(status.health_all, 1);
        assert_eq!(status.health_fail, 0);
        assert_eq!(status.health_average_ms, 12);
        assert_eq!(status.health_deviation_ms, 6);
    }

    #[tokio::test]
    async fn burst_get_probe_consumes_body_and_uses_sampling_count() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind burst probe server");
        let address = listener.local_addr().expect("burst probe address");
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept burst probe");
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.expect("read burst probe");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("write burst response");
            String::from_utf8_lossy(&request[..read]).into_owned()
        });
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let config = ActiveObserverConfig::try_from(&BurstObservatoryConfig {
            subject_selector: vec!["direct".into()],
            ping_config: Some(crate::config::def::HealthPingConfig {
                destination: format!("http://{address}/probe"),
                http_method: "GET".into(),
                sampling: Some(2),
                ..Default::default()
            }),
        })
        .expect("build burst GET config");
        let mut windows = HashMap::new();

        probe_once(&runtime, &config, &mut windows).await;
        let request = server.await.expect("burst probe server task");
        assert!(request.starts_with("GET /probe HTTP/1.1"));
        let observation = runtime.outbound_observations().remove("direct").unwrap();
        assert!(observation.alive);
        assert_eq!(observation.health_all, 1);
    }

    #[tokio::test]
    async fn failed_connectivity_check_skips_observation_sample() {
        let reserve = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve unavailable probe port");
        let address = reserve.local_addr().expect("unavailable probe address");
        drop(reserve);
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let config = ActiveObserverConfig::try_from(&BurstObservatoryConfig {
            subject_selector: vec!["direct".into()],
            ping_config: Some(crate::config::def::HealthPingConfig {
                destination: format!("http://{address}/probe"),
                connectivity: format!("http://{address}/connectivity"),
                timeout: Some(serde_json::json!("100ms")),
                ..Default::default()
            }),
        })
        .expect("build connectivity skip config");
        let mut windows = HashMap::new();

        assert_eq!(probe_once(&runtime, &config, &mut windows).await, 1);
        assert!(runtime.outbound_observations().is_empty());
        assert!(windows.is_empty());
    }
}
