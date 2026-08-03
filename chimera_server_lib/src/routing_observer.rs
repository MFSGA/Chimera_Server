use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{Client, Method, Url, redirect::Policy};
use tokio::{task::JoinHandle, time::sleep};
use tracing::{debug, warn};

use crate::{
    config::def::{BurstObservatoryConfig, ObservatoryConfig},
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
                probe_outbound(client.clone(), config.clone(), outbound)
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
                let (tag, result) =
                    probe_outbound(client.clone(), config.clone(), outbound).await;
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
                probe_outbound(client.clone(), config.clone(), outbound)
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
                probe_outbound(client.clone(), config.clone(), outbound).await;
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
    client: Client,
    config: ActiveObserverConfig,
    outbound: OutboundSummary,
) -> (String, Option<ProbeResult>) {
    let result = match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => {
            let started = Instant::now();
            let request =
                client.request(config.method.clone(), config.probe_url.clone());
            match request.send().await {
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
                            delay_ms: started
                                .elapsed()
                                .as_millis()
                                .min(i64::MAX as u128)
                                as i64,
                            error: String::new(),
                        })
                    }
                }
                Err(error) => {
                    if connectivity_is_unavailable(&client, &config).await {
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
            }
        }
        "blackhole" => Some(ProbeResult {
            alive: false,
            delay_ms: FAILED_DELAY_MS,
            error: "blackhole outbound cannot relay observatory probes".into(),
        }),
        protocol => Some(ProbeResult {
            alive: false,
            delay_ms: FAILED_DELAY_MS,
            error: format!(
                "observatory probe for outbound protocol {protocol} is not supported"
            ),
        }),
    };
    (outbound.tag, result)
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

fn apply_probe_result(
    runtime: &RuntimeState,
    windows: &mut HashMap<String, ProbeWindow>,
    tag: String,
    result: ProbeResult,
    sampling_count: usize,
    validity: Duration,
) {
    let now = unix_time_secs();
    if sampling_count == 0 {
        let last_seen_time = if result.alive {
            now
        } else {
            runtime
                .outbound_observations()
                .get(&tag)
                .map_or(0, |status| status.last_seen_time)
        };
        runtime.record_outbound_observation(
            tag.clone(),
            OutboundObservation {
                alive: result.alive,
                delay_ms: result.delay_ms,
                last_error_reason: result.error,
                last_seen_time,
                last_try_time: now,
                ..OutboundObservation::default()
            },
        );
        debug!(
            outbound = %tag,
            alive = result.alive,
            delay_ms = result.delay_ms,
            "routing observatory probe completed"
        );
        return;
    }
    let window = windows.entry(tag.clone()).or_default();
    if result.alive {
        window.last_seen_time = now;
    }
    let recorded_at = Instant::now();
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
    let all = window.samples.len() as i64;
    let fail = window.samples.iter().filter(|sample| !sample.alive).count() as i64;
    let successful = window
        .samples
        .iter()
        .filter(|sample| sample.alive)
        .map(|sample| sample.delay_ms)
        .collect::<Vec<_>>();
    let average = if successful.is_empty() {
        0
    } else {
        successful.iter().sum::<i64>() / successful.len() as i64
    };
    let deviation = if successful.is_empty() {
        0
    } else if successful.len() == 1 {
        average / 2
    } else {
        let variance = successful
            .iter()
            .map(|delay| {
                let delta = *delay as f64 - average as f64;
                delta * delta
            })
            .sum::<f64>()
            / successful.len() as f64;
        variance.sqrt().round() as i64
    };
    let maximum = successful.iter().copied().max().unwrap_or_default();
    let minimum = successful.iter().copied().min().unwrap_or_default();
    runtime.record_outbound_observation(
        tag.clone(),
        OutboundObservation {
            alive: result.alive,
            delay_ms: result.delay_ms,
            last_error_reason: result.error,
            last_seen_time: window.last_seen_time,
            last_try_time: now,
            health_all: all,
            health_fail: fail,
            health_deviation_ms: deviation,
            health_average_ms: average,
            health_max_ms: maximum,
            health_min_ms: minimum,
        },
    );
    debug!(
        outbound = %tag,
        alive = result.alive,
        delay_ms = result.delay_ms,
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

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
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
        assert_eq!(status.delay_ms, 15);
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
