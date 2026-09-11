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

mod config;

use config::{ActiveObserverConfig, resolve_observer_config};
#[cfg(test)]
use config::{
    DEFAULT_BURST_INTERVAL, DEFAULT_BURST_PROBE_URL, DEFAULT_HEALTH_WINDOW,
    DEFAULT_PROBE_INTERVAL, DEFAULT_PROBE_TIMEOUT, DEFAULT_PROBE_URL,
    MIN_BURST_INTERVAL,
};

const FAILED_DELAY_MS: i64 = 99_999_999;

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
    let connection = connect_tcp_via_outbound(
        &resolver,
        &target,
        &runtime.data_plane(),
        outbound,
    )
    .await?;
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

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests;
