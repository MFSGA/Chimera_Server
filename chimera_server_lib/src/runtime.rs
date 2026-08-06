use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

#[cfg(feature = "user_domain_access")]
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "user_domain_access", unix))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(feature = "user_domain_access")]
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(feature = "user_domain_access")]
use uuid::Uuid;

use tokio::{
    sync::broadcast,
    task::{AbortHandle, JoinHandle},
};

#[cfg(feature = "user_domain_access")]
use crate::user_domain_access::{
    AccessAction, AccessDecision, AccessDecisionReason, EnforcementMode,
    UserDomainAccessConfig, UserDomainAccessPolicy,
    UserDomainAccessSignatureVerifier,
};
use crate::{
    config::{def::PolicyConfig, server_config::ServerConfig},
    outbound_registry::{OutboundConnectorKind, OutboundRegistry},
    resolver::{NativeResolver, Resolver},
    routing_state::{
        OutboundObservation, RouteMatch, RoutingEvent, RoutingInput, RoutingState,
    },
};

#[derive(Debug, Clone)]
pub struct OutboundSummary {
    pub tag: String,
    pub protocol: String,
    pub settings: Option<serde_json::Value>,
    pub stream_settings: Option<crate::config::def::OutboundStreamSettings>,
    pub proxy_settings_type: Option<String>,
    pub proxy_settings_value: Option<Vec<u8>>,
}

impl OutboundSummary {
    fn normalize(mut self) -> Result<Self, String> {
        self.tag = self.tag.trim().to_string();
        if self.tag.is_empty() {
            return Err("outbound tag must not be empty".into());
        }
        self.protocol = self.protocol.trim().to_ascii_lowercase();
        if self.protocol.is_empty() {
            return Err(format!("outbound {} protocol must not be empty", self.tag));
        }
        Ok(self)
    }

    fn normalize_lenient(mut self) -> Self {
        self.tag = self.tag.trim().to_string();
        self.protocol = self.protocol.trim().to_ascii_lowercase();
        self
    }
}

#[derive(Debug, Clone, Default)]
struct OutboundRuntimeState {
    summaries: Vec<OutboundSummary>,
    registry: OutboundRegistry,
}

impl OutboundRuntimeState {
    fn from_outbounds_lenient(summaries: Vec<OutboundSummary>) -> Self {
        let summaries = summaries
            .into_iter()
            .map(OutboundSummary::normalize_lenient)
            .collect::<Vec<_>>();
        let registry = OutboundRegistry::from_outbounds_lenient(&summaries);
        Self {
            summaries,
            registry,
        }
    }
}

#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_HISTORY_LIMIT: usize = 5;
#[cfg(feature = "user_domain_access")]
pub(crate) const fn user_domain_access_history_limit() -> usize {
    USER_DOMAIN_ACCESS_HISTORY_LIMIT
}
#[cfg(feature = "user_domain_access")]
static USER_DOMAIN_ACCESS_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_STORE_FORMAT_VERSION: u32 = 1;
#[cfg(feature = "user_domain_access")]
pub(crate) const USER_DOMAIN_ACCESS_STORE_MAX_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_TIMEOUT_MILLIS: u64 = 5;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_MIN_TIMEOUT_MILLIS: u64 = 1;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_MAX_TIMEOUT_MILLIS: u64 = 100;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_MAX_BYTES: usize = 65_536;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_MIN_BYTES: usize = 1_024;
#[cfg(feature = "user_domain_access")]
const USER_DOMAIN_ACCESS_TLS_PROBE_MAX_BYTES: usize = 262_144;

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDomainAccessRevisionInfo {
    pub version: u64,
    pub generated_at: Option<Arc<str>>,
    pub source_backend_version: Option<Arc<str>>,
    pub target_node_uuid: Option<Arc<str>>,
    pub checksum: Option<Arc<str>>,
    pub signature_algorithm: Option<Arc<str>>,
    pub signing_key_id: Option<Arc<str>>,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedUserDomainAccessStore {
    pub config: UserDomainAccessConfig,
    pub highest_seen_version: u64,
    pub history: Vec<UserDomainAccessConfig>,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserDomainAccessStoreEnvelope {
    format_version: u32,
    highest_seen_version: u64,
    current: UserDomainAccessConfig,
    #[serde(default)]
    history: Vec<UserDomainAccessConfig>,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredUserDomainAccess {
    Envelope(UserDomainAccessStoreEnvelope),
    Legacy(UserDomainAccessConfig),
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone)]
struct UserDomainAccessRevision {
    info: UserDomainAccessRevisionInfo,
    policy: Arc<UserDomainAccessPolicy>,
    config: Option<Arc<UserDomainAccessConfig>>,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDomainAccessTlsProbeConfig {
    pub timeout: Duration,
    pub max_bytes: usize,
}

#[cfg(feature = "user_domain_access")]
impl Default for UserDomainAccessTlsProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(
                USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_TIMEOUT_MILLIS,
            ),
            max_bytes: USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_MAX_BYTES,
        }
    }
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserDomainAccessStats {
    pub evaluations: u64,
    pub allowed: u64,
    pub rejected: u64,
    pub matched_rule: u64,
    pub no_user_policy: u64,
    pub unknown_target: u64,
    pub allow_all_default: u64,
    pub allowlist_miss: u64,
    pub denylist_miss: u64,
    pub enforced_rejections: u64,
    pub shadow_rejections: u64,
    pub disabled_bypasses: u64,
    pub tls_probe_attempts: u64,
    pub tls_sni_found: u64,
    pub tls_ech_detected: u64,
    pub tls_not_tls: u64,
    pub tls_incomplete: u64,
    pub tls_malformed: u64,
    pub tls_no_server_name: u64,
    pub tls_timeouts: u64,
    pub tls_captured_bytes: u64,
    pub apply_succeeded: u64,
    pub apply_failed: u64,
    pub rollback_succeeded: u64,
    pub rollback_failed: u64,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserDomainAccessTlsProbeOutcome {
    ServerName,
    EncryptedClientHello,
    NotTls,
    Incomplete,
    Malformed,
    NoServerName,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Default)]
struct UserDomainAccessMetrics {
    evaluations: AtomicU64,
    allowed: AtomicU64,
    rejected: AtomicU64,
    matched_rule: AtomicU64,
    no_user_policy: AtomicU64,
    unknown_target: AtomicU64,
    allow_all_default: AtomicU64,
    allowlist_miss: AtomicU64,
    denylist_miss: AtomicU64,
    enforced_rejections: AtomicU64,
    shadow_rejections: AtomicU64,
    disabled_bypasses: AtomicU64,
    tls_probe_attempts: AtomicU64,
    tls_sni_found: AtomicU64,
    tls_ech_detected: AtomicU64,
    tls_not_tls: AtomicU64,
    tls_incomplete: AtomicU64,
    tls_malformed: AtomicU64,
    tls_no_server_name: AtomicU64,
    tls_timeouts: AtomicU64,
    tls_captured_bytes: AtomicU64,
    apply_succeeded: AtomicU64,
    apply_failed: AtomicU64,
    rollback_succeeded: AtomicU64,
    rollback_failed: AtomicU64,
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug, Default)]
struct UserDomainAccessRuntimeState {
    current: Option<UserDomainAccessRevision>,
    history: VecDeque<UserDomainAccessRevision>,
    highest_seen_version: u64,
    store_path: Option<PathBuf>,
    expected_target_node_uuid: Option<Uuid>,
    signature_verifier: UserDomainAccessSignatureVerifier,
    tls_probe: UserDomainAccessTlsProbeConfig,
}

#[derive(Clone)]
struct ResolverRuntimeState {
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for ResolverRuntimeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolverRuntimeState")
            .field("resolver", &"dyn Resolver")
            .finish()
    }
}

const DEFAULT_POLICY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
struct PolicyRuntimeState {
    handshake_timeouts: HashMap<u32, Duration>,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inbounds: Arc<RwLock<Vec<ServerConfig>>>,
    outbounds: Arc<RwLock<OutboundRuntimeState>>,
    inbound_tasks: Arc<RwLock<HashMap<String, Vec<AbortHandle>>>>,
    routing: Arc<RwLock<RoutingState>>,
    balancer_overrides: Arc<RwLock<HashMap<String, String>>>,
    resolver: Arc<RwLock<ResolverRuntimeState>>,
    policy: Arc<RwLock<PolicyRuntimeState>>,
    routing_events: broadcast::Sender<RoutingEvent>,
    #[cfg(feature = "user_domain_access")]
    user_domain_access: Arc<RwLock<UserDomainAccessRuntimeState>>,
    #[cfg(feature = "user_domain_access")]
    user_domain_access_metrics: Arc<UserDomainAccessMetrics>,
}

impl RuntimeState {
    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        let (routing_events, _) = broadcast::channel(256);
        Self {
            inbounds: Arc::new(RwLock::new(inbounds)),
            outbounds: Arc::new(RwLock::new(
                OutboundRuntimeState::from_outbounds_lenient(outbounds),
            )),
            inbound_tasks: Arc::new(RwLock::new(HashMap::new())),
            routing: Arc::new(RwLock::new(RoutingState::default())),
            balancer_overrides: Arc::new(RwLock::new(HashMap::new())),
            resolver: Arc::new(RwLock::new(ResolverRuntimeState {
                resolver: Arc::new(NativeResolver::new()),
            })),
            policy: Arc::new(RwLock::new(PolicyRuntimeState::default())),
            routing_events,
            #[cfg(feature = "user_domain_access")]
            user_domain_access: Arc::new(RwLock::new(
                UserDomainAccessRuntimeState::default(),
            )),
            #[cfg(feature = "user_domain_access")]
            user_domain_access_metrics: Arc::new(UserDomainAccessMetrics::default()),
        }
    }

    pub fn compile_outbounds(
        outbounds: Vec<OutboundSummary>,
    ) -> Result<Vec<OutboundSummary>, String> {
        let outbounds = outbounds
            .into_iter()
            .map(OutboundSummary::normalize)
            .collect::<Result<Vec<_>, _>>()?;
        OutboundRegistry::validate_strict(&outbounds)?;
        Ok(outbounds)
    }

    pub fn try_new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Result<Self, String> {
        Ok(Self::new(inbounds, Self::compile_outbounds(outbounds)?))
    }

    pub fn resolver(&self) -> Arc<dyn Resolver> {
        self.resolver
            .read()
            .expect("runtime resolver lock poisoned")
            .resolver
            .clone()
    }

    pub fn replace_resolver(&self, resolver: Arc<dyn Resolver>) {
        self.resolver
            .write()
            .expect("runtime resolver lock poisoned")
            .resolver = resolver;
    }

    pub fn configure_policy(
        &self,
        policy: Option<&PolicyConfig>,
    ) -> Result<(), String> {
        let mut handshake_timeouts = HashMap::new();
        if let Some(policy) = policy {
            for (raw_level, level_policy) in &policy.levels {
                let level = raw_level.parse::<u32>().map_err(|error| {
                    format!(
                        "policy level {raw_level:?} must be an unsigned integer: {error}"
                    )
                })?;
                if let Some(seconds) = level_policy.handshake {
                    handshake_timeouts
                        .insert(level, Duration::from_secs(u64::from(seconds)));
                }
            }
        }
        self.policy
            .write()
            .expect("runtime policy lock poisoned")
            .handshake_timeouts = handshake_timeouts;
        Ok(())
    }

    pub fn policy_handshake_timeout(&self, level: u32) -> Duration {
        self.policy
            .read()
            .expect("runtime policy lock poisoned")
            .handshake_timeouts
            .get(&level)
            .copied()
            .unwrap_or(DEFAULT_POLICY_HANDSHAKE_TIMEOUT)
    }

    pub fn inbounds(&self) -> Vec<ServerConfig> {
        self.inbounds
            .read()
            .expect("runtime inbounds lock poisoned")
            .clone()
    }

    pub fn inbound_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.inbounds
            .read()
            .expect("runtime inbounds lock poisoned")
            .iter()
            .find(|cfg| cfg.tag == tag)
            .cloned()
    }

    pub fn with_inbound_mut<R, F>(&self, tag: &str, mutator: F) -> Option<R>
    where
        F: FnOnce(&mut ServerConfig) -> R,
    {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        let inbound = guard.iter_mut().find(|cfg| cfg.tag == tag)?;
        Some(mutator(inbound))
    }

    pub fn remove_inbound(&self, tag: &str) -> Option<ServerConfig> {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        let index = guard.iter().position(|cfg| cfg.tag == tag)?;
        Some(guard.remove(index))
    }

    pub fn add_inbound(&self, inbound: ServerConfig) -> Result<(), String> {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        if guard.iter().any(|cfg| cfg.tag == inbound.tag) {
            return Err(format!("inbound {} already exists", inbound.tag));
        }
        guard.push(inbound);
        Ok(())
    }

    pub fn register_inbound_tasks(&self, tag: &str, handles: &[JoinHandle<()>]) {
        let abort_handles = handles
            .iter()
            .map(JoinHandle::abort_handle)
            .collect::<Vec<_>>();
        self.inbound_tasks
            .write()
            .expect("runtime inbound tasks lock poisoned")
            .insert(tag.to_string(), abort_handles);
    }

    pub fn abort_inbound_tasks(&self, tag: &str) -> bool {
        let Some(handles) = self
            .inbound_tasks
            .write()
            .expect("runtime inbound tasks lock poisoned")
            .remove(tag)
        else {
            return false;
        };

        for handle in handles {
            handle.abort();
        }

        true
    }

    pub fn outbounds(&self) -> Vec<OutboundSummary> {
        self.outbounds
            .read()
            .expect("runtime outbounds lock poisoned")
            .summaries
            .clone()
    }

    pub(crate) fn outbound_connector(
        &self,
        tag: &str,
    ) -> Option<Arc<OutboundConnectorKind>> {
        self.outbounds
            .read()
            .expect("runtime outbounds lock poisoned")
            .registry
            .get(tag)
    }

    pub fn select_outbound(&self, input: &RoutingInput) -> Option<OutboundSummary> {
        self.select_outbound_checked(input).ok().flatten()
    }

    pub(crate) fn select_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        let outbounds = self.outbounds();
        let overrides = self.balancer_overrides();
        let Some(route) = self.routing().route(input, &outbounds, &overrides) else {
            let selected = outbounds.first().cloned();
            if let Some(outbound) = selected.as_ref() {
                self.publish_routing_event(RoutingEvent {
                    input: input.clone(),
                    route: RouteMatch {
                        outbound_tag: outbound.tag.clone(),
                        outbound_group_tags: Vec::new(),
                        rule_tag: String::new(),
                        resolution_error: None,
                    },
                });
            }
            return Ok(selected);
        };
        if let Some(error) = route.resolution_error.clone() {
            return Err(error);
        }
        let selected = outbounds
            .iter()
            .find(|outbound| outbound.tag == route.outbound_tag)
            .cloned()
            .ok_or_else(|| {
                format!("routing selected missing outbound {}", route.outbound_tag)
            })?;
        self.publish_routing_event(RoutingEvent {
            input: input.clone(),
            route,
        });
        Ok(Some(selected))
    }

    pub(crate) fn subscribe_routing_events(
        &self,
    ) -> broadcast::Receiver<RoutingEvent> {
        self.routing_events.subscribe()
    }

    pub(crate) fn publish_routing_event(&self, event: RoutingEvent) {
        let _ = self.routing_events.send(event);
    }

    pub(crate) fn balancer_overrides(&self) -> HashMap<String, String> {
        self.balancer_overrides
            .read()
            .expect("runtime balancer overrides lock poisoned")
            .clone()
    }

    pub(crate) fn balancer_override(&self, tag: &str) -> Option<String> {
        self.balancer_overrides
            .read()
            .expect("runtime balancer overrides lock poisoned")
            .get(tag)
            .cloned()
    }

    pub(crate) fn set_balancer_override(
        &self,
        balancer_tag: impl Into<String>,
        outbound_tag: impl Into<String>,
    ) {
        self.balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned")
            .insert(balancer_tag.into(), outbound_tag.into());
    }

    pub(crate) fn remove_balancer_override(&self, tag: &str) -> bool {
        self.balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned")
            .remove(tag)
            .is_some()
    }

    pub fn remove_outbound(&self, tag: &str) -> Option<OutboundSummary> {
        let mut guard = self
            .outbounds
            .write()
            .expect("runtime outbounds lock poisoned");
        let index = guard.summaries.iter().position(|cfg| cfg.tag == tag)?;
        let outbound = guard.summaries.remove(index);
        guard.registry.remove(tag);
        Some(outbound)
    }

    pub fn add_outbound(&self, outbound: OutboundSummary) -> Result<(), String> {
        let outbound = outbound.normalize()?;
        let mut guard = self
            .outbounds
            .write()
            .expect("runtime outbounds lock poisoned");
        if guard.summaries.iter().any(|cfg| cfg.tag == outbound.tag) {
            return Err(format!("outbound {} already exists", outbound.tag));
        }
        guard.registry.insert_strict(&outbound)?;
        guard.summaries.push(outbound);
        Ok(())
    }

    pub fn routing(&self) -> RoutingState {
        self.routing
            .read()
            .expect("runtime routing lock poisoned")
            .clone()
    }

    pub fn replace_routing(&self, mut routing: RoutingState) {
        let mut current =
            self.routing.write().expect("runtime routing lock poisoned");
        routing.inherit_observations_from(&current);
        *current = routing;
    }

    pub(crate) fn record_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.routing().record_observation(tag, observation);
    }

    pub(crate) fn outbound_observations(
        &self,
    ) -> HashMap<String, OutboundObservation> {
        self.routing().observations()
    }

    pub fn with_routing_mut<R, F>(&self, mutator: F) -> R
    where
        F: FnOnce(&mut RoutingState) -> R,
    {
        let mut guard = self.routing.write().expect("runtime routing lock poisoned");
        mutator(&mut guard)
    }

    /// Returns the active compiled user-domain access policy, if configured.
    #[cfg(feature = "user_domain_access")]
    pub fn user_domain_access(&self) -> Option<Arc<UserDomainAccessPolicy>> {
        self.user_domain_access
            .read()
            .expect("runtime user-domain access lock poisoned")
            .current
            .as_ref()
            .map(|revision| Arc::clone(&revision.policy))
    }

    /// Records one low-cardinality access decision without locking the data path.
    #[cfg(feature = "user_domain_access")]
    pub(crate) fn record_user_domain_access_decision(
        &self,
        decision: &AccessDecision,
        enforcement_mode: EnforcementMode,
    ) {
        self.user_domain_access_metrics
            .record(decision, enforcement_mode);
    }

    #[cfg(feature = "user_domain_access")]
    pub(crate) fn record_user_domain_access_disabled_bypass(&self) {
        self.user_domain_access_metrics
            .disabled_bypasses
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "user_domain_access")]
    pub(crate) fn record_user_domain_access_tls_probe(
        &self,
        outcome: UserDomainAccessTlsProbeOutcome,
        captured_bytes: usize,
        timed_out: bool,
    ) {
        self.user_domain_access_metrics.record_tls_probe(
            outcome,
            captured_bytes,
            timed_out,
        );
    }

    #[cfg(feature = "user_domain_access")]
    pub(crate) fn record_user_domain_access_apply(&self, succeeded: bool) {
        self.user_domain_access_metrics.record_apply(succeeded);
    }

    #[cfg(feature = "user_domain_access")]
    pub(crate) fn record_user_domain_access_rollback(&self, succeeded: bool) {
        self.user_domain_access_metrics.record_rollback(succeeded);
    }

    /// Returns a cumulative low-cardinality access decision snapshot.
    #[cfg(feature = "user_domain_access")]
    pub fn user_domain_access_stats(&self) -> UserDomainAccessStats {
        self.user_domain_access_metrics.snapshot()
    }

    /// Returns the effective node-local TLS ClientHello probe settings.
    #[cfg(feature = "user_domain_access")]
    pub fn user_domain_access_tls_probe_config(
        &self,
    ) -> UserDomainAccessTlsProbeConfig {
        self.user_domain_access
            .read()
            .expect("runtime user-domain access lock poisoned")
            .tls_probe
    }

    /// Returns metadata for the active user-domain access revision.
    #[cfg(feature = "user_domain_access")]
    pub fn user_domain_access_revision(
        &self,
    ) -> Option<UserDomainAccessRevisionInfo> {
        self.user_domain_access
            .read()
            .expect("runtime user-domain access lock poisoned")
            .current
            .as_ref()
            .map(|revision| revision.info.clone())
    }

    /// Configures the atomic persistence target used by installs and rollbacks.
    #[cfg(feature = "user_domain_access")]
    pub fn configure_user_domain_access_store(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<(), String> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err("user-domain access store path must not be empty".into());
        }
        self.user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned")
            .store_path = Some(path);
        Ok(())
    }

    /// Configures the node UUID that incoming policy publications must target.
    #[cfg(feature = "user_domain_access")]
    pub fn configure_user_domain_access_target_node(
        &self,
        node_uuid: &str,
    ) -> Result<(), String> {
        let node_uuid = Uuid::parse_str(node_uuid.trim()).map_err(|error| {
            format!("invalid user-domain access node UUID {node_uuid}: {error}")
        })?;
        self.user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned")
            .expected_target_node_uuid = Some(node_uuid);
        Ok(())
    }

    /// Configures node-local trusted signing keys before policy installation.
    #[cfg(feature = "user_domain_access")]
    pub fn configure_user_domain_access_signature_verifier(
        &self,
        verifier: UserDomainAccessSignatureVerifier,
    ) -> Result<(), String> {
        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        if state.current.is_some() || !state.history.is_empty() {
            return Err(
                "user-domain access signature verifier must be configured before policy installation"
                    .into(),
            );
        }
        state.signature_verifier = verifier;
        Ok(())
    }

    /// Configures bounded TLS ClientHello probing before policy installation.
    #[cfg(feature = "user_domain_access")]
    pub fn configure_user_domain_access_tls_probe(
        &self,
        timeout_millis: Option<u64>,
        max_bytes: Option<usize>,
    ) -> Result<(), String> {
        let timeout_millis = timeout_millis
            .unwrap_or(USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_TIMEOUT_MILLIS);
        if !(USER_DOMAIN_ACCESS_TLS_PROBE_MIN_TIMEOUT_MILLIS
            ..=USER_DOMAIN_ACCESS_TLS_PROBE_MAX_TIMEOUT_MILLIS)
            .contains(&timeout_millis)
        {
            return Err(format!(
                "user-domain access TLS probe timeout must be between {} and {} milliseconds",
                USER_DOMAIN_ACCESS_TLS_PROBE_MIN_TIMEOUT_MILLIS,
                USER_DOMAIN_ACCESS_TLS_PROBE_MAX_TIMEOUT_MILLIS
            ));
        }
        let max_bytes =
            max_bytes.unwrap_or(USER_DOMAIN_ACCESS_TLS_PROBE_DEFAULT_MAX_BYTES);
        if !(USER_DOMAIN_ACCESS_TLS_PROBE_MIN_BYTES
            ..=USER_DOMAIN_ACCESS_TLS_PROBE_MAX_BYTES)
            .contains(&max_bytes)
        {
            return Err(format!(
                "user-domain access TLS probe max bytes must be between {} and {}",
                USER_DOMAIN_ACCESS_TLS_PROBE_MIN_BYTES,
                USER_DOMAIN_ACCESS_TLS_PROBE_MAX_BYTES
            ));
        }

        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        if state.current.is_some() || !state.history.is_empty() {
            return Err(
                "user-domain access TLS probe must be configured before policy installation"
                    .into(),
            );
        }
        state.tls_probe = UserDomainAccessTlsProbeConfig {
            timeout: Duration::from_millis(timeout_millis),
            max_bytes,
        };
        Ok(())
    }

    /// Restores persisted replay protection and rollback history before installing the current revision.
    #[cfg(feature = "user_domain_access")]
    pub(crate) fn restore_user_domain_access_persisted_state(
        &self,
        highest_seen_version: u64,
        history: Vec<UserDomainAccessConfig>,
    ) -> Result<(), String> {
        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        if state.current.is_some() || !state.history.is_empty() {
            return Err(
                "user-domain access persisted state must be restored before current policy installation"
                    .into(),
            );
        }
        if history.len() > USER_DOMAIN_ACCESS_HISTORY_LIMIT {
            return Err(format!(
                "cannot restore {} user-domain access history revisions; maximum is {}",
                history.len(),
                USER_DOMAIN_ACCESS_HISTORY_LIMIT
            ));
        }
        let mut versions = std::collections::HashSet::new();
        let mut restored = VecDeque::with_capacity(history.len());
        for config in history {
            let info = revision_info_from_config(&config);
            if !versions.insert(info.version) {
                return Err(format!(
                    "cannot restore duplicate user-domain access history version {}",
                    info.version
                ));
            }
            if info.version > highest_seen_version {
                return Err(format!(
                    "retained user-domain access version {} exceeds highestSeenVersion {}",
                    info.version, highest_seen_version
                ));
            }
            validate_user_domain_access_target(
                &info,
                state.expected_target_node_uuid,
            )?;
            state
                .signature_verifier
                .verify(&config)
                .map_err(|error| error.to_string())?;
            let policy = Arc::new(
                UserDomainAccessPolicy::compile(config.clone())
                    .map_err(|error| error.to_string())?,
            );
            restored.push_back(UserDomainAccessRevision {
                info,
                policy,
                config: Some(Arc::new(config)),
            });
        }
        state.highest_seen_version =
            state.highest_seen_version.max(highest_seen_version);
        state.history = restored;
        Ok(())
    }

    /// Compiles and atomically installs a strictly newer policy revision.
    /// Invalid or stale revisions leave the active policy unchanged.
    #[cfg(feature = "user_domain_access")]
    pub fn install_user_domain_access(
        &self,
        config: UserDomainAccessConfig,
    ) -> Result<UserDomainAccessRevisionInfo, String> {
        let signature_verifier = self
            .user_domain_access
            .read()
            .expect("runtime user-domain access lock poisoned")
            .signature_verifier
            .clone();
        signature_verifier
            .verify(&config)
            .map_err(|error| error.to_string())?;
        let info = revision_info_from_config(&config);
        let policy = Arc::new(
            UserDomainAccessPolicy::compile(config.clone())
                .map_err(|error| error.to_string())?,
        );
        let config = Arc::new(config);
        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        validate_user_domain_access_target(&info, state.expected_target_node_uuid)?;
        if state.current.is_some() && info.version <= state.highest_seen_version {
            return Err(format!(
                "user-domain access version {} is not newer than highest installed version {}",
                info.version, state.highest_seen_version
            ));
        }
        if let Some(path) = state.store_path.as_deref() {
            let mut history = Vec::with_capacity(USER_DOMAIN_ACCESS_HISTORY_LIMIT);
            if let Some(current) = state.current.as_ref() {
                append_persisted_history_config(&mut history, current, info.version);
            }
            for revision in &state.history {
                append_persisted_history_config(
                    &mut history,
                    revision,
                    info.version,
                );
                if history.len() == USER_DOMAIN_ACCESS_HISTORY_LIMIT {
                    break;
                }
            }
            persist_user_domain_access_config(
                path,
                &config,
                state.highest_seen_version.max(info.version),
                &history,
            )?;
        }
        install_user_domain_revision(
            &mut state,
            UserDomainAccessRevision {
                info: info.clone(),
                policy,
                config: Some(config),
            },
        );
        Ok(info)
    }

    /// Installs the startup policy without requiring a positive version.
    #[cfg(feature = "user_domain_access")]
    pub fn replace_user_domain_access(
        &self,
        policy: Option<UserDomainAccessPolicy>,
    ) {
        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        let store_path = state.store_path.take();
        let expected_target_node_uuid = state.expected_target_node_uuid.take();
        let signature_verifier = state.signature_verifier.clone();
        let tls_probe = state.tls_probe;
        *state = UserDomainAccessRuntimeState::default();
        state.store_path = store_path;
        state.expected_target_node_uuid = expected_target_node_uuid;
        state.signature_verifier = signature_verifier;
        state.tls_probe = tls_probe;
        if let Some(policy) = policy {
            state.current = Some(UserDomainAccessRevision {
                info: UserDomainAccessRevisionInfo {
                    version: 0,
                    generated_at: None,
                    source_backend_version: None,
                    target_node_uuid: None,
                    checksum: None,
                    signature_algorithm: None,
                    signing_key_id: None,
                },
                policy: Arc::new(policy),
                config: None,
            });
        }
    }

    /// Atomically rolls back to a retained revision while preserving replay protection.
    #[cfg(feature = "user_domain_access")]
    pub fn rollback_user_domain_access(
        &self,
        version: u64,
    ) -> Result<UserDomainAccessRevisionInfo, String> {
        let mut state = self
            .user_domain_access
            .write()
            .expect("runtime user-domain access lock poisoned");
        if state
            .current
            .as_ref()
            .is_some_and(|revision| revision.info.version == version)
        {
            return state
                .current
                .as_ref()
                .map(|revision| revision.info.clone())
                .ok_or_else(|| "user-domain access policy is not installed".into());
        }
        let Some(index) = state
            .history
            .iter()
            .position(|revision| revision.info.version == version)
        else {
            return Err(format!(
                "user-domain access version {version} is not retained"
            ));
        };
        let revision = state
            .history
            .get(index)
            .cloned()
            .expect("retained revision index must exist");
        if let Some(path) = state.store_path.as_deref() {
            let config = revision.config.as_deref().ok_or_else(|| {
                "retained user-domain access revision has no persisted config"
                    .to_string()
            })?;
            let mut history = Vec::with_capacity(USER_DOMAIN_ACCESS_HISTORY_LIMIT);
            if let Some(current) = state.current.as_ref() {
                append_persisted_history_config(
                    &mut history,
                    current,
                    revision.info.version,
                );
            }
            for (history_index, retained) in state.history.iter().enumerate() {
                if history_index == index {
                    continue;
                }
                append_persisted_history_config(
                    &mut history,
                    retained,
                    revision.info.version,
                );
                if history.len() == USER_DOMAIN_ACCESS_HISTORY_LIMIT {
                    break;
                }
            }
            persist_user_domain_access_config(
                path,
                config,
                state.highest_seen_version,
                &history,
            )?;
        }
        let revision = state
            .history
            .remove(index)
            .expect("retained revision index must exist");
        if let Some(current) = state.current.take() {
            push_user_domain_history(&mut state.history, current);
        }
        let info = revision.info.clone();
        state.current = Some(revision);
        Ok(info)
    }
}

#[cfg(feature = "user_domain_access")]
fn validate_user_domain_access_target(
    info: &UserDomainAccessRevisionInfo,
    expected_target_node_uuid: Option<Uuid>,
) -> Result<(), String> {
    let Some(expected_node_uuid) = expected_target_node_uuid else {
        return Ok(());
    };
    let actual_node_uuid = info.target_node_uuid.as_deref().ok_or_else(|| {
        format!(
            "user-domain access revision {} is missing targetNodeUuid; expected {}",
            info.version, expected_node_uuid
        )
    })?;
    let actual_node_uuid = Uuid::parse_str(actual_node_uuid).map_err(|error| {
        format!(
            "invalid user-domain access targetNodeUuid {actual_node_uuid}: {error}"
        )
    })?;
    if actual_node_uuid != expected_node_uuid {
        return Err(format!(
            "user-domain access revision {} targets node {}, expected {}",
            info.version, actual_node_uuid, expected_node_uuid
        ));
    }
    Ok(())
}

#[cfg(feature = "user_domain_access")]
fn append_persisted_history_config(
    history: &mut Vec<UserDomainAccessConfig>,
    revision: &UserDomainAccessRevision,
    current_version: u64,
) {
    let Some(config) = revision.config.as_deref() else {
        return;
    };
    if config.version == current_version
        || history
            .iter()
            .any(|existing| existing.version == config.version)
    {
        return;
    }
    history.push(config.clone());
}

#[cfg(feature = "user_domain_access")]
impl UserDomainAccessMetrics {
    fn record(&self, decision: &AccessDecision, enforcement_mode: EnforcementMode) {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        match decision.action {
            AccessAction::Allow => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            AccessAction::Reject => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                match enforcement_mode {
                    EnforcementMode::Enforce => {
                        self.enforced_rejections.fetch_add(1, Ordering::Relaxed);
                    }
                    EnforcementMode::Shadow => {
                        self.shadow_rejections.fetch_add(1, Ordering::Relaxed);
                    }
                    EnforcementMode::Disabled => {}
                }
            }
        }
        let counter = match decision.reason {
            AccessDecisionReason::MatchedRule => &self.matched_rule,
            AccessDecisionReason::NoUserPolicy => &self.no_user_policy,
            AccessDecisionReason::UnknownTarget => &self.unknown_target,
            AccessDecisionReason::AllowAllDefault => &self.allow_all_default,
            AccessDecisionReason::AllowlistMiss => &self.allowlist_miss,
            AccessDecisionReason::DenylistMiss => &self.denylist_miss,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_tls_probe(
        &self,
        outcome: UserDomainAccessTlsProbeOutcome,
        captured_bytes: usize,
        timed_out: bool,
    ) {
        self.tls_probe_attempts.fetch_add(1, Ordering::Relaxed);
        self.tls_captured_bytes
            .fetch_add(captured_bytes as u64, Ordering::Relaxed);
        if timed_out {
            self.tls_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        let counter = match outcome {
            UserDomainAccessTlsProbeOutcome::ServerName => &self.tls_sni_found,
            UserDomainAccessTlsProbeOutcome::EncryptedClientHello => {
                &self.tls_ech_detected
            }
            UserDomainAccessTlsProbeOutcome::NotTls => &self.tls_not_tls,
            UserDomainAccessTlsProbeOutcome::Incomplete => &self.tls_incomplete,
            UserDomainAccessTlsProbeOutcome::Malformed => &self.tls_malformed,
            UserDomainAccessTlsProbeOutcome::NoServerName => {
                &self.tls_no_server_name
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_apply(&self, succeeded: bool) {
        let counter = if succeeded {
            &self.apply_succeeded
        } else {
            &self.apply_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rollback(&self, succeeded: bool) {
        let counter = if succeeded {
            &self.rollback_succeeded
        } else {
            &self.rollback_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UserDomainAccessStats {
        UserDomainAccessStats {
            evaluations: self.evaluations.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            matched_rule: self.matched_rule.load(Ordering::Relaxed),
            no_user_policy: self.no_user_policy.load(Ordering::Relaxed),
            unknown_target: self.unknown_target.load(Ordering::Relaxed),
            allow_all_default: self.allow_all_default.load(Ordering::Relaxed),
            allowlist_miss: self.allowlist_miss.load(Ordering::Relaxed),
            denylist_miss: self.denylist_miss.load(Ordering::Relaxed),
            enforced_rejections: self.enforced_rejections.load(Ordering::Relaxed),
            shadow_rejections: self.shadow_rejections.load(Ordering::Relaxed),
            disabled_bypasses: self.disabled_bypasses.load(Ordering::Relaxed),
            tls_probe_attempts: self.tls_probe_attempts.load(Ordering::Relaxed),
            tls_sni_found: self.tls_sni_found.load(Ordering::Relaxed),
            tls_ech_detected: self.tls_ech_detected.load(Ordering::Relaxed),
            tls_not_tls: self.tls_not_tls.load(Ordering::Relaxed),
            tls_incomplete: self.tls_incomplete.load(Ordering::Relaxed),
            tls_malformed: self.tls_malformed.load(Ordering::Relaxed),
            tls_no_server_name: self.tls_no_server_name.load(Ordering::Relaxed),
            tls_timeouts: self.tls_timeouts.load(Ordering::Relaxed),
            tls_captured_bytes: self.tls_captured_bytes.load(Ordering::Relaxed),
            apply_succeeded: self.apply_succeeded.load(Ordering::Relaxed),
            apply_failed: self.apply_failed.load(Ordering::Relaxed),
            rollback_succeeded: self.rollback_succeeded.load(Ordering::Relaxed),
            rollback_failed: self.rollback_failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "user_domain_access")]
fn validate_user_domain_access_store_file_type(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "user-domain access store {} must not be a symbolic link",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "user-domain access store {} must be a regular file",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(feature = "user_domain_access")]
fn validate_user_domain_access_store_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    validate_user_domain_access_store_file_type(path, metadata)?;
    if metadata.len() > USER_DOMAIN_ACCESS_STORE_MAX_BYTES {
        return Err(format!(
            "user-domain access store {} exceeds maximum size of {} bytes",
            path.display(),
            USER_DOMAIN_ACCESS_STORE_MAX_BYTES
        ));
    }
    Ok(())
}

#[cfg(feature = "user_domain_access")]
pub(crate) fn load_user_domain_access_store(
    path: &Path,
) -> Result<Option<LoadedUserDomainAccessStore>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect user-domain access store {}: {error}",
                path.display()
            ));
        }
    };
    validate_user_domain_access_store_metadata(path, &metadata)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        format!(
            "failed to open user-domain access store {}: {error}",
            path.display()
        )
    })?;
    validate_user_domain_access_store_metadata(
        path,
        &file.metadata().map_err(|error| {
            format!(
                "failed to inspect opened user-domain access store {}: {error}",
                path.display()
            )
        })?,
    )?;
    let mut content = String::new();
    Read::by_ref(&mut file)
        .take(USER_DOMAIN_ACCESS_STORE_MAX_BYTES + 1)
        .read_to_string(&mut content)
        .map_err(|error| {
            format!(
                "failed to read user-domain access store {}: {error}",
                path.display()
            )
        })?;
    if content.len() as u64 > USER_DOMAIN_ACCESS_STORE_MAX_BYTES {
        return Err(format!(
            "user-domain access store {} exceeds maximum size of {} bytes",
            path.display(),
            USER_DOMAIN_ACCESS_STORE_MAX_BYTES
        ));
    }
    let stored = serde_json::from_str::<StoredUserDomainAccess>(&content).map_err(
        |error| {
            format!(
                "failed to parse user-domain access store {}: {error}",
                path.display()
            )
        },
    )?;
    let loaded = match stored {
        StoredUserDomainAccess::Legacy(config) => LoadedUserDomainAccessStore {
            highest_seen_version: config.version,
            config,
            history: Vec::new(),
        },
        StoredUserDomainAccess::Envelope(envelope) => {
            if envelope.format_version != USER_DOMAIN_ACCESS_STORE_FORMAT_VERSION {
                return Err(format!(
                    "unsupported user-domain access store format version {} in {}; expected {}",
                    envelope.format_version,
                    path.display(),
                    USER_DOMAIN_ACCESS_STORE_FORMAT_VERSION
                ));
            }
            if envelope.highest_seen_version < envelope.current.version {
                return Err(format!(
                    "user-domain access store {} has highestSeenVersion {} below current version {}",
                    path.display(),
                    envelope.highest_seen_version,
                    envelope.current.version
                ));
            }
            let mut versions = std::collections::HashSet::new();
            versions.insert(envelope.current.version);
            for revision in &envelope.history {
                if revision.version > envelope.highest_seen_version {
                    return Err(format!(
                        "user-domain access store {} retains version {} above highestSeenVersion {}",
                        path.display(),
                        revision.version,
                        envelope.highest_seen_version
                    ));
                }
                if !versions.insert(revision.version) {
                    return Err(format!(
                        "user-domain access store {} contains duplicate version {}",
                        path.display(),
                        revision.version
                    ));
                }
            }
            if envelope.history.len() > USER_DOMAIN_ACCESS_HISTORY_LIMIT {
                return Err(format!(
                    "user-domain access store {} retains {} history revisions; maximum is {}",
                    path.display(),
                    envelope.history.len(),
                    USER_DOMAIN_ACCESS_HISTORY_LIMIT
                ));
            }
            LoadedUserDomainAccessStore {
                config: envelope.current,
                highest_seen_version: envelope.highest_seen_version,
                history: envelope.history,
            }
        }
    };
    Ok(Some(loaded))
}

#[cfg(feature = "user_domain_access")]
fn persist_user_domain_access_config(
    path: &Path,
    config: &UserDomainAccessConfig,
    highest_seen_version: u64,
    history: &[UserDomainAccessConfig],
) -> Result<(), String> {
    if highest_seen_version < config.version {
        return Err(format!(
            "cannot persist user-domain access version {} with highestSeenVersion {}",
            config.version, highest_seen_version
        ));
    }
    if history.len() > USER_DOMAIN_ACCESS_HISTORY_LIMIT {
        return Err(format!(
            "cannot persist {} user-domain access history revisions; maximum is {}",
            history.len(),
            USER_DOMAIN_ACCESS_HISTORY_LIMIT
        ));
    }
    let envelope = UserDomainAccessStoreEnvelope {
        format_version: USER_DOMAIN_ACCESS_STORE_FORMAT_VERSION,
        highest_seen_version,
        current: config.clone(),
        history: history.to_vec(),
    };
    let mut serialized = serde_json::to_vec_pretty(&envelope).map_err(|error| {
        format!(
            "failed to serialize user-domain access store {}: {error}",
            path.display()
        )
    })?;
    serialized.push(b'\n');
    if serialized.len() as u64 > USER_DOMAIN_ACCESS_STORE_MAX_BYTES {
        return Err(format!(
            "user-domain access store {} would exceed maximum size of {} bytes",
            path.display(),
            USER_DOMAIN_ACCESS_STORE_MAX_BYTES
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_user_domain_access_store_file_type(path, &metadata)?;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create user-domain access store directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let directory = parent.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            format!(
                "user-domain access store path {} has no valid file name",
                path.display()
            )
        })?;
    let counter = USER_DOMAIN_ACCESS_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary =
        directory.join(format!(".{file_name}.tmp-{}-{counter}", std::process::id()));

    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&temporary).map_err(|error| {
            format!(
                "failed to create user-domain access temporary store {}: {error}",
                temporary.display()
            )
        })?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&serialized).map_err(|error| {
            format!(
                "failed to write user-domain access store {}: {error}",
                temporary.display()
            )
        })?;
        writer.flush().map_err(|error| {
            format!(
                "failed to flush user-domain access store {}: {error}",
                temporary.display()
            )
        })?;
        writer.get_ref().sync_all().map_err(|error| {
            format!(
                "failed to sync user-domain access store {}: {error}",
                temporary.display()
            )
        })?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "failed to atomically replace user-domain access store {}: {error}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "failed to sync user-domain access store directory {}: {error}",
                    directory.display()
                )
            })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(feature = "user_domain_access")]
fn revision_info_from_config(
    config: &UserDomainAccessConfig,
) -> UserDomainAccessRevisionInfo {
    UserDomainAccessRevisionInfo {
        version: config.version,
        generated_at: config.generated_at.as_deref().map(Arc::from),
        source_backend_version: config
            .source_backend_version
            .as_deref()
            .map(Arc::from),
        target_node_uuid: config.target_node_uuid.as_deref().map(Arc::from),
        checksum: config.checksum.as_deref().map(Arc::from),
        signature_algorithm: config
            .signature_algorithm
            .map(|_| Arc::<str>::from("ed25519")),
        signing_key_id: config.signing_key_id.as_deref().map(Arc::from),
    }
}

#[cfg(feature = "user_domain_access")]
fn install_user_domain_revision(
    state: &mut UserDomainAccessRuntimeState,
    revision: UserDomainAccessRevision,
) {
    state.highest_seen_version =
        state.highest_seen_version.max(revision.info.version);
    if let Some(current) = state.current.take() {
        push_user_domain_history(&mut state.history, current);
    }
    state.current = Some(revision);
}

#[cfg(feature = "user_domain_access")]
fn push_user_domain_history(
    history: &mut VecDeque<UserDomainAccessRevision>,
    revision: UserDomainAccessRevision,
) {
    history.retain(|existing| existing.info.version != revision.info.version);
    history.push_front(revision);
    history.truncate(USER_DOMAIN_ACCESS_HISTORY_LIMIT);
}
