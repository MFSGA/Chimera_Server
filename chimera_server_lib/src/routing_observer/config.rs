use std::time::Duration;

use reqwest::{Method, Url};

use crate::config::def::{BurstObservatoryConfig, ObservatoryConfig};

pub(super) const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";
pub(super) const DEFAULT_BURST_PROBE_URL: &str =
    "https://connectivitycheck.gstatic.com/generate_204";
pub(super) const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
pub(super) const DEFAULT_BURST_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const MIN_BURST_INTERVAL: Duration = Duration::from_secs(10);
pub(super) const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const DEFAULT_HEALTH_WINDOW: usize = 10;

#[derive(Debug, Clone)]
pub(super) struct ActiveObserverConfig {
    pub(super) selectors: Vec<String>,
    pub(super) probe_url: Url,
    pub(super) connectivity_url: Option<Url>,
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) method: Method,
    pub(super) concurrent: bool,
    pub(super) sampling_count: usize,
    pub(super) consume_body: bool,
}

impl ActiveObserverConfig {
    pub(super) fn health_validity(&self) -> Duration {
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

pub(super) fn resolve_observer_config(
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
