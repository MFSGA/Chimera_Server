use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rand::RngExt;
use regex::Regex;

use crate::{config::rule::BalancerConfig, runtime::OutboundSummary};

use super::{OutboundObservation, merge_outbound_observation};

pub(super) const LEAST_PING_MAX_DELAY_MS: i64 = 99_999_999;
const OBSERVATION_SHARD_COUNT: usize = 16;

pub(super) type ObservationSnapshot = Vec<Option<Arc<OutboundObservation>>>;

#[derive(Debug)]
pub(super) struct ObservationStore {
    shards:
        [RwLock<HashMap<String, Arc<OutboundObservation>>>; OBSERVATION_SHARD_COUNT],
}

impl Default for ObservationStore {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
        }
    }
}

impl ObservationStore {
    pub(super) fn record(&self, tag: String, observation: OutboundObservation) {
        let shard = observation_shard_index(&tag);
        if let Ok(mut observations) = self.shards[shard].write() {
            let observation = merge_outbound_observation(
                observations.get(&tag).map(AsRef::as_ref),
                observation,
            );
            observations.insert(tag, Arc::new(observation));
        }
    }

    pub(super) fn get(&self, tag: &str) -> Option<Arc<OutboundObservation>> {
        self.shards[observation_shard_index(tag)]
            .read()
            .ok()?
            .get(tag)
            .cloned()
    }

    pub(super) fn remove(&self, tag: &str) -> Option<OutboundObservation> {
        self.shards[observation_shard_index(tag)]
            .write()
            .ok()?
            .remove(tag)
            .map(|observation| observation.as_ref().clone())
    }

    pub(super) fn snapshot_all(&self) -> HashMap<String, OutboundObservation> {
        let mut snapshot = HashMap::new();
        for shard in &self.shards {
            let Ok(observations) = shard.read() else {
                continue;
            };
            snapshot.extend(observations.iter().map(|(tag, observation)| {
                (tag.clone(), observation.as_ref().clone())
            }));
        }
        snapshot
    }

    pub(super) fn snapshot_for(
        &self,
        targets: &BalancerTargetSet,
    ) -> ObservationSnapshot {
        let mut snapshot = vec![None; targets.tags.len()];
        for (shard_index, indices) in targets.indices_by_shard.iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let Ok(observations) = self.shards[shard_index].read() else {
                continue;
            };
            for &index in indices {
                snapshot[index] = observations.get(&targets.tags[index]).cloned();
            }
        }
        snapshot
    }
}

pub(super) fn observation_shard_index(tag: &str) -> usize {
    let hash = tag
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
    hash as usize % OBSERVATION_SHARD_COUNT
}

#[derive(Debug, Clone)]
pub(crate) struct BalancerTargetSet {
    pub(super) tags: Arc<[String]>,
    pub(super) indices_by_shard: Arc<[Vec<usize>]>,
}

impl AsRef<[String]> for BalancerTargetSet {
    fn as_ref(&self) -> &[String] {
        self.tags.as_ref()
    }
}

impl BalancerTargetSet {
    pub(super) fn new(tags: Vec<String>) -> Self {
        let mut indices_by_shard = vec![Vec::new(); OBSERVATION_SHARD_COUNT];
        for (index, tag) in tags.iter().enumerate() {
            indices_by_shard[observation_shard_index(tag)].push(index);
        }
        Self {
            tags: Arc::from(tags),
            indices_by_shard: Arc::from(indices_by_shard),
        }
    }
}

pub(crate) type BalancerTargetMap = HashMap<String, BalancerTargetSet>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoutingRuleSummary {
    pub outbound_tag: String,
    pub rule_tag: String,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledBalancer {
    pub(super) outbound_selector: Vec<String>,
    fallback_tag: Option<String>,
    strategy: BalancerStrategy,
}

#[derive(Debug, Clone)]
enum BalancerStrategy {
    Random,
    RoundRobin(Arc<AtomicU64>),
    LeastPing,
    LeastLoad(LeastLoadConfig),
}

#[derive(Debug, Clone, Default)]
struct LeastLoadConfig {
    costs: Vec<StrategyWeight>,
    baselines_ms: Vec<f64>,
    expected: usize,
    max_rtt_ms: Option<f64>,
    tolerance: f64,
}

#[derive(Debug, Clone)]
struct StrategyWeight {
    matcher: WeightMatcher,
    value: f64,
}

#[derive(Debug, Clone)]
enum WeightMatcher {
    Never,
    Substring(String),
    Regexp(Regex),
}

#[derive(Debug, Clone)]
struct LeastLoadNode {
    tag: String,
    all: i64,
    fail: i64,
    average_ms: f64,
    deviation_cost_ms: f64,
}

impl TryFrom<BalancerConfig> for CompiledBalancer {
    type Error = String;

    fn try_from(mut config: BalancerConfig) -> Result<Self, Self::Error> {
        if config.tag.trim().is_empty() {
            return Err("routing balancer tag is required".into());
        }
        config
            .outbound_selector
            .retain(|selector| !selector.trim().is_empty());
        if config.outbound_selector.is_empty() {
            return Err(format!(
                "routing balancer {} requires at least one outbound selector",
                config.tag
            ));
        }
        let strategy_name = config.strategy.kind.trim().to_ascii_lowercase();
        let strategy = match strategy_name.as_str() {
            "" | "random" => BalancerStrategy::Random,
            "roundrobin" => {
                BalancerStrategy::RoundRobin(Arc::new(AtomicU64::new(0)))
            }
            "leastping" => BalancerStrategy::LeastPing,
            "leastload" => BalancerStrategy::LeastLoad(
                LeastLoadConfig::from_settings(config.strategy.settings)?,
            ),
            strategy => {
                return Err(format!(
                    "routing balancer {} uses unknown strategy {strategy}",
                    config.tag
                ));
            }
        };
        Ok(Self {
            outbound_selector: config.outbound_selector,
            fallback_tag: config.fallback_tag,
            strategy,
        })
    }
}

impl CompiledBalancer {
    pub(super) fn needs_observations(&self) -> bool {
        self.fallback_tag.is_some()
            || matches!(
                self.strategy,
                BalancerStrategy::LeastPing | BalancerStrategy::LeastLoad(_)
            )
    }

    pub(super) fn pick(
        &self,
        targets: &[String],
        outbounds: &[OutboundSummary],
        observations: Option<&[Option<Arc<OutboundObservation>>]>,
    ) -> Option<String> {
        let candidates = if self.fallback_tag.is_some() {
            targets
                .iter()
                .zip(observations.unwrap_or_default())
                .filter(|(_, status)| {
                    status.as_deref().is_none_or(|status| status.alive)
                })
                .map(|(tag, _)| tag.clone())
                .collect::<Vec<_>>()
        } else {
            targets.to_vec()
        };
        let selected = match &self.strategy {
            BalancerStrategy::Random if !candidates.is_empty() => candidates
                .get(rand::rng().random_range(0..candidates.len()))
                .cloned(),
            BalancerStrategy::RoundRobin(index) if !candidates.is_empty() => {
                candidates
                    .get(
                        index.fetch_add(1, Ordering::Relaxed) as usize
                            % candidates.len(),
                    )
                    .cloned()
            }
            BalancerStrategy::LeastPing => {
                let target =
                    least_ping_target(targets, observations.unwrap_or_default());
                (!target.is_empty()).then_some(target)
            }
            BalancerStrategy::LeastLoad(settings) => {
                let selected =
                    settings.select(targets, observations.unwrap_or_default());
                (!selected.is_empty()).then(|| {
                    selected[rand::rng().random_range(0..selected.len())].clone()
                })
            }
            _ => None,
        };
        selected.or_else(|| {
            self.fallback_tag.as_ref().and_then(|fallback| {
                outbounds
                    .iter()
                    .any(|outbound| outbound.tag == *fallback)
                    .then(|| fallback.clone())
            })
        })
    }

    pub(super) fn principle_targets(
        &self,
        targets: &[String],
        _outbounds: &[OutboundSummary],
        observations: Option<&[Option<Arc<OutboundObservation>>]>,
    ) -> Vec<String> {
        match &self.strategy {
            BalancerStrategy::LeastPing => {
                vec![least_ping_target(targets, observations.unwrap_or_default())]
            }
            BalancerStrategy::LeastLoad(settings) => {
                settings.select(targets, observations.unwrap_or_default())
            }
            _ => targets.to_vec(),
        }
    }
}

fn least_ping_target(
    targets: &[String],
    observations: &[Option<Arc<OutboundObservation>>],
) -> String {
    targets
        .iter()
        .zip(observations)
        .filter_map(|(tag, status)| {
            status
                .as_deref()
                .filter(|status| {
                    status.alive && status.delay_ms < LEAST_PING_MAX_DELAY_MS
                })
                .map(|status| (status.delay_ms, tag))
        })
        .min_by_key(|(delay, _)| *delay)
        .map(|(_, tag)| tag.clone())
        .unwrap_or_default()
}

impl LeastLoadConfig {
    fn from_settings(settings: Option<serde_json::Value>) -> Result<Self, String> {
        let Some(settings) = settings else {
            return Ok(Self::default());
        };
        let object = settings.as_object().ok_or_else(|| {
            "routing leastLoad strategy settings must be an object".to_string()
        })?;
        let expected = object
            .get("expected")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_default()
            .max(0) as usize;
        let max_rtt_ms = object
            .get("maxRTT")
            .map(parse_duration_millis)
            .transpose()?
            .filter(|value| *value > 0.0);
        let tolerance = object
            .get("tolerance")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_default()
            .clamp(0.0, 1.0);
        let mut baselines_ms = match object.get("baselines") {
            None => Vec::new(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(parse_duration_millis)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err("routing leastLoad baselines must be an array".into());
            }
        };
        baselines_ms.retain(|value| *value > 0.0);
        let costs = match object.get("costs") {
            None => Vec::new(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(StrategyWeight::from_json)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err("routing leastLoad costs must be an array".into());
            }
        };
        Ok(Self {
            costs,
            baselines_ms,
            expected,
            max_rtt_ms,
            tolerance,
        })
    }

    fn select(
        &self,
        targets: &[String],
        observations: &[Option<Arc<OutboundObservation>>],
    ) -> Vec<String> {
        let mut nodes = targets
            .iter()
            .zip(observations)
            .filter_map(|(tag, status)| {
                let status = status.as_deref()?;
                if !status.alive {
                    return None;
                }
                if self
                    .max_rtt_ms
                    .is_some_and(|maximum| status.delay_ms as f64 >= maximum)
                {
                    return None;
                }
                if status.health_all > 0
                    && self.tolerance > 0.0
                    && status.health_fail as f64 / status.health_all as f64
                        > self.tolerance
                {
                    return None;
                }
                let (all, fail, average_ms, deviation_ms) = if status.health_all > 0
                {
                    (
                        status.health_all,
                        status.health_fail,
                        status.health_average_ms as f64,
                        status.health_deviation_ms as f64,
                    )
                } else {
                    (1, 1, status.delay_ms as f64, status.delay_ms as f64)
                };
                Some(LeastLoadNode {
                    tag: tag.clone(),
                    all,
                    fail,
                    average_ms,
                    deviation_cost_ms: self.apply_cost(tag, deviation_ms),
                })
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| {
            left.deviation_cost_ms
                .total_cmp(&right.deviation_cost_ms)
                .then_with(|| left.average_ms.total_cmp(&right.average_ms))
                .then_with(|| left.fail.cmp(&right.fail))
                .then_with(|| right.all.cmp(&left.all))
                .then_with(|| left.tag.cmp(&right.tag))
        });
        if nodes.is_empty() {
            return Vec::new();
        }
        if self.expected > nodes.len() {
            return nodes.into_iter().map(|node| node.tag).collect();
        }
        let expected = self.expected.max(1);
        let count = if self.baselines_ms.is_empty() {
            expected
        } else {
            let mut count = 0;
            for baseline in &self.baselines_ms {
                for (index, node) in nodes.iter().enumerate().skip(count) {
                    if node.deviation_cost_ms >= *baseline {
                        break;
                    }
                    count = index + 1;
                }
                if count >= expected {
                    break;
                }
            }
            if self.expected > 0 && count < expected {
                expected
            } else {
                count
            }
        };
        let count = count.min(nodes.len());
        nodes.into_iter().take(count).map(|node| node.tag).collect()
    }

    fn apply_cost(&self, tag: &str, value: f64) -> f64 {
        let cost = self
            .costs
            .iter()
            .find_map(|weight| weight.matches(tag))
            .unwrap_or(1.0)
            .max(f64::EPSILON);
        value * cost.sqrt()
    }
}

impl StrategyWeight {
    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value.as_object().ok_or_else(|| {
            "routing leastLoad cost entry must be an object".to_string()
        })?;
        let pattern = object
            .get("match")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let matcher = if pattern.is_empty() {
            WeightMatcher::Never
        } else if object
            .get("regexp")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Regex::new(&pattern)
                .map(WeightMatcher::Regexp)
                .unwrap_or(WeightMatcher::Never)
        } else {
            WeightMatcher::Substring(pattern)
        };
        Ok(Self {
            matcher,
            value: object
                .get("value")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default(),
        })
    }

    fn matches(&self, tag: &str) -> Option<f64> {
        let matched = match &self.matcher {
            WeightMatcher::Never => None,
            WeightMatcher::Substring(pattern) => {
                tag.contains(pattern).then_some(pattern.as_str())
            }
            WeightMatcher::Regexp(pattern) => {
                pattern.find(tag).map(|value| value.as_str())
            }
        }?;
        if self.value > 0.0 {
            return Some(self.value);
        }
        first_number(matched).or(Some(1.0))
    }
}

fn first_number(value: &str) -> Option<f64> {
    let start = value.find(|character: char| character.is_ascii_digit())?;
    let number = value[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>();
    number.parse().ok()
}

fn parse_duration_millis(value: &serde_json::Value) -> Result<f64, String> {
    if let Some(value) = value.as_f64() {
        return Ok(value.max(0.0));
    }
    let Some(value) = value.as_str() else {
        return Err("routing duration must be a number or string".into());
    };
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let amount = value[..split]
        .parse::<f64>()
        .map_err(|error| format!("invalid routing duration {value}: {error}"))?;
    let multiplier = match value[split..].trim().to_ascii_lowercase().as_str() {
        "" | "ms" => 1.0,
        "ns" => 0.000_001,
        "us" | "µs" => 0.001,
        "s" => 1_000.0,
        "m" => 60_000.0,
        "h" => 3_600_000.0,
        unit => return Err(format!("unsupported routing duration unit {unit}")),
    };
    Ok((amount * multiplier).max(0.0))
}
