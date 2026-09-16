use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;
const MAX_USERS: usize = 100_000;
const MAX_RULES_PER_USER: usize = 1_000;
const MAX_TOTAL_RULES: usize = 1_000_000;
const UNKNOWN_TARGET_AUDIT_DEDUP_WINDOW: Duration = Duration::from_secs(1);
const MAX_UNKNOWN_TARGET_AUDIT_KEYS: usize = 4_096;
const MAX_UNSUPPORTED_PROTOCOL_AUDIT_KEYS: usize = 128;
const MAX_AUDIT_EVENTS: usize = 1_024;
const MAX_AUDIT_FIELD_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserDomainAccessError {
    Invalid,
    FailedPrecondition,
    NotFound,
}

impl UserDomainAccessError {
    pub(crate) fn message(self, message: String) -> UserDomainAccessFailure {
        UserDomainAccessFailure {
            kind: self,
            message,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UserDomainAccessFailure {
    pub(crate) kind: UserDomainAccessError,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserDomainAccessPublication {
    pub(crate) version: u64,
    pub(crate) generated_at: String,
    pub(crate) source_backend_version: String,
    pub(crate) target_node_uuid: String,
    pub(crate) checksum: String,
    pub(crate) default_action: UserDomainAccessAction,
    #[serde(default)]
    pub(crate) enforcement_mode: UserDomainEnforcementMode,
    pub(crate) users: Vec<UserDomainAccessPublicationUser>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserDomainAccessPublicationUser {
    pub(crate) user_uuid: String,
    pub(crate) protocol_identity: UserDomainAccessProtocolIdentity,
    pub(crate) mode: UserDomainAccessMode,
    pub(crate) unknown_target_action: UserDomainAccessAction,
    pub(crate) rules: Vec<UserDomainAccessRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserDomainAccessProtocolIdentity {
    pub(crate) vless_uuid: String,
    pub(crate) vmess_uuid: String,
    pub(crate) tuic_uuid: String,
    pub(crate) hysteria2_password: String,
    pub(crate) trojan_password: String,
    pub(crate) http_username: String,
    pub(crate) socks_username: String,
    /// Xray's Shadowsocks inbound exposes the authenticated `MemoryUser.Email`.
    #[serde(default)]
    pub(crate) shadowsocks_email: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserDomainAccessRule {
    #[serde(default)]
    pub(crate) id: Option<String>,
    pub(crate) domain: String,
    #[serde(rename = "match")]
    pub(crate) match_kind: UserDomainAccessMatch,
    pub(crate) action: UserDomainAccessAction,
    #[serde(default)]
    pub(crate) priority: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UserDomainAccessAction {
    Allow,
    Reject,
}

impl UserDomainAccessAction {
    fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Controls whether a rejected policy decision affects outbound traffic.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserDomainEnforcementMode {
    #[default]
    Enforce,
    Shadow,
    Disabled,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserDomainAccessMode {
    AllowAll,
    Allowlist,
    Denylist,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UserDomainAccessMatch {
    Exact,
    Suffix,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UserDomainAccessRevision {
    pub(crate) version: u64,
    pub(crate) generated_at: String,
    pub(crate) source_backend_version: String,
    pub(crate) target_node_uuid: String,
    pub(crate) checksum: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UserDomainAccessDecisionStats {
    pub(crate) evaluations: u64,
    pub(crate) allowed: u64,
    pub(crate) rejected: u64,
    pub(crate) matched_rule: u64,
    pub(crate) no_user_policy: u64,
    pub(crate) unknown_target: u64,
    pub(crate) allow_all_default: u64,
    pub(crate) allowlist_miss: u64,
    pub(crate) denylist_miss: u64,
    pub(crate) dns_failures: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UserDomainAccessStatus {
    pub(crate) revision: Option<UserDomainAccessRevision>,
    pub(crate) stats: UserDomainAccessDecisionStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserDomainAccessAuditEvent {
    pub(crate) observed_at_unix_ms: u64,
    pub(crate) decision: String,
    pub(crate) reason: String,
    pub(crate) inbound_tag: String,
    pub(crate) protocol: String,
    pub(crate) network: String,
    pub(crate) target: String,
    pub(crate) routing_user: String,
    pub(crate) identity_count: u64,
}

/// Safe, non-authoritative context used only for user-domain audit logs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UserDomainAccessAuditContext<'a> {
    pub(crate) inbound_tag: &'a str,
    pub(crate) protocol: &'a str,
    pub(crate) network: &'a str,
    pub(crate) target: &'a str,
    pub(crate) routing_user: &'a str,
}

#[derive(Debug, Clone, Copy)]
enum DecisionReason {
    NoUserPolicy,
    UnknownTarget,
    MatchedRule,
    AllowAllDefault,
    AllowlistMiss,
    DenylistMiss,
}

#[derive(Debug, Clone)]
struct ActiveUserDomainAccessPublication {
    publication: Arc<UserDomainAccessPublication>,
    activation: Arc<()>,
}

impl ActiveUserDomainAccessPublication {
    fn new(publication: Arc<UserDomainAccessPublication>) -> Self {
        Self {
            publication,
            activation: Arc::new(()),
        }
    }

    fn same_activation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.activation, &other.activation)
    }
}

#[derive(Debug, Clone, Default)]
struct UserDomainAccessInner {
    active: Option<ActiveUserDomainAccessPublication>,
    revisions: BTreeMap<u64, Arc<UserDomainAccessPublication>>,
    highest_version: u64,
    stats: UserDomainAccessDecisionStats,
    unknown_target_audit: HashMap<String, Instant>,
    unsupported_protocol_audit: HashSet<String>,
    audit_events: VecDeque<UserDomainAccessAuditEvent>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UserDomainAccessStore {
    inner: Arc<RwLock<UserDomainAccessInner>>,
}

impl UserDomainAccessStore {
    pub(crate) fn apply(
        &self,
        publication: UserDomainAccessPublication,
    ) -> Result<UserDomainAccessRevision, UserDomainAccessFailure> {
        let legacy_reject_users = publication
            .users
            .iter()
            .filter(|user| {
                matches!(user.unknown_target_action, UserDomainAccessAction::Reject)
            })
            .count();
        if legacy_reject_users > 0 {
            tracing::warn!(
                event = "user_domain_access_unknown_target_action_ignored",
                legacy_reject_users,
                "unknown targets are always allowed and audited; the legacy reject action is ignored"
            );
        }
        let revision = revision_of(&publication);
        let publication = Arc::new(publication);
        let mut inner = self
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        if publication.version == 0 {
            return Err(UserDomainAccessError::Invalid.message(
                "user-domain access version must be greater than zero".to_string(),
            ));
        }
        if publication.version <= inner.highest_version {
            return Err(UserDomainAccessError::FailedPrecondition.message(format!(
                "user-domain access version {} is not greater than the highest accepted version {}",
                publication.version, inner.highest_version
            )));
        }

        inner.highest_version = publication.version;
        inner
            .revisions
            .insert(publication.version, Arc::clone(&publication));
        inner.active = Some(ActiveUserDomainAccessPublication::new(publication));
        inner.stats = UserDomainAccessDecisionStats::default();
        inner.unknown_target_audit.clear();
        inner.unsupported_protocol_audit.clear();
        inner.audit_events.clear();
        Ok(revision)
    }

    pub(crate) fn rollback(
        &self,
        version: u64,
    ) -> Result<UserDomainAccessRevision, UserDomainAccessFailure> {
        let mut inner = self
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        let publication =
            inner.revisions.get(&version).cloned().ok_or_else(|| {
                UserDomainAccessError::NotFound.message(format!(
                "user-domain access version {version} is not available for rollback"
            ))
            })?;
        let revision = revision_of(&publication);
        inner.active = Some(ActiveUserDomainAccessPublication::new(publication));
        inner.stats = UserDomainAccessDecisionStats::default();
        inner.unknown_target_audit.clear();
        inner.unsupported_protocol_audit.clear();
        inner.audit_events.clear();
        Ok(revision)
    }

    pub(crate) fn status(&self) -> UserDomainAccessStatus {
        let inner = self.inner.read().expect("user-domain access lock poisoned");
        UserDomainAccessStatus {
            revision: inner
                .active
                .as_ref()
                .map(|active| revision_of(&active.publication)),
            stats: inner.stats.clone(),
        }
    }

    pub(crate) fn record_dns_failure(&self) {
        let mut inner = self
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        bump(&mut inner.stats.dns_failures);
    }

    pub(crate) fn audit_events(
        &self,
        limit: usize,
    ) -> Vec<UserDomainAccessAuditEvent> {
        let inner = self.inner.read().expect("user-domain access lock poisoned");
        inner
            .audit_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Applies the active policy to a resolved target domain before an
    /// outbound connection is established. An empty or invalid target domain
    /// represents an IP-only or otherwise unknown target and is always
    /// allowed; the decision is recorded for auditing.
    pub(crate) fn allows(&self, identity: &str, target_domain: &str) -> bool {
        self.allows_identity_iter(std::iter::once(identity), target_domain, None)
    }

    pub(crate) fn allows_with_context(
        &self,
        identity: &str,
        target_domain: &str,
        audit_context: UserDomainAccessAuditContext<'_>,
    ) -> bool {
        self.allows_identity_iter(
            std::iter::once(identity),
            target_domain,
            Some(audit_context),
        )
    }

    pub(crate) fn allows_with_identities(
        &self,
        identities: &[String],
        target_domain: &str,
    ) -> bool {
        self.allows_identity_iter(
            identities.iter().map(String::as_str),
            target_domain,
            None,
        )
    }

    pub(crate) fn allows_with_identities_and_context(
        &self,
        identities: &[String],
        target_domain: &str,
        audit_context: UserDomainAccessAuditContext<'_>,
    ) -> bool {
        self.allows_identity_iter(
            identities.iter().map(String::as_str),
            target_domain,
            Some(audit_context),
        )
    }

    fn allows_identity_iter<'a, 'b, I>(
        &self,
        identities: I,
        target_domain: &'b str,
        audit_context: Option<UserDomainAccessAuditContext<'b>>,
    ) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        let active = {
            let inner = self.inner.read().expect("user-domain access lock poisoned");
            let Some(active) = inner.active.clone() else {
                return true;
            };
            if active.publication.enforcement_mode
                == UserDomainEnforcementMode::Disabled
            {
                return true;
            }
            active
        };

        let identities = identities.into_iter().collect::<Vec<_>>();
        let enforcement_mode = active.publication.enforcement_mode;
        let (allowed, reason) = evaluate_public_with_identities(
            &active.publication,
            identities.iter().copied(),
            target_domain,
        );

        let mut inner = self
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        let active_is_current = inner
            .active
            .as_ref()
            .is_some_and(|current| current.same_activation(&active));
        let should_log_unknown_target = if active_is_current {
            record_decision_stats(&mut inner.stats, allowed, reason);
            matches!(reason, DecisionReason::UnknownTarget)
                && should_emit_unknown_target_audit(
                    &mut inner,
                    target_domain,
                    audit_context,
                    Instant::now(),
                )
        } else {
            false
        };
        let unsupported_protocol = audit_context.filter(|context| {
            !context.protocol.trim().is_empty()
                && !is_user_domain_protocol_supported(context.protocol)
        });
        let should_warn_unsupported_protocol = active_is_current
            && unsupported_protocol.is_some_and(|context| {
                should_emit_unsupported_protocol_audit(&mut inner, context)
            });
        let audit_event = should_log_unknown_target.then(|| {
            let routing_user = audit_context
                .map(|context| safe_routing_user_summary(context.routing_user))
                .unwrap_or_else(|| "unavailable".to_string());
            let event = UserDomainAccessAuditEvent {
                observed_at_unix_ms: unix_timestamp_ms(),
                decision: "allow".to_string(),
                reason: "domain_not_available".to_string(),
                inbound_tag: audit_context
                    .map_or("", |context| context.inbound_tag)
                    .to_string(),
                protocol: audit_context
                    .map_or("", |context| context.protocol)
                    .to_string(),
                network: audit_context
                    .map_or("", |context| context.network)
                    .to_string(),
                target: audit_context
                    .map_or(target_domain, |context| context.target)
                    .to_string(),
                routing_user,
                identity_count: identities.len() as u64,
            };
            limit_audit_event_fields(event)
        });
        if let Some(event) = audit_event.as_ref() {
            if inner.audit_events.len() >= MAX_AUDIT_EVENTS {
                inner.audit_events.pop_front();
            }
            inner.audit_events.push_back(event.clone());
        }
        drop(inner);

        if let Some(event) = audit_event {
            tracing::info!(
                event = "user_domain_access_unknown_target",
                decision = %event.decision,
                reason = %event.reason,
                inbound_tag = %event.inbound_tag,
                protocol = %event.protocol,
                network = %event.network,
                target = %event.target,
                routing_user = %event.routing_user,
                enforcement_mode = ?enforcement_mode,
                identity_count = event.identity_count,
                "user-domain access policy allowed a target without a usable domain"
            );
        }
        if should_warn_unsupported_protocol
            && let Some(context) = unsupported_protocol
        {
            tracing::warn!(
                event = "user_domain_access_unsupported_protocol",
                inbound_tag = %context.inbound_tag,
                protocol = %context.protocol,
                network = %context.network,
                "user-domain access is not a verified capability for this inbound protocol; protocol-specific support remains pending"
            );
        }

        if enforcement_mode == UserDomainEnforcementMode::Shadow {
            true
        } else {
            allowed
        }
    }
}

impl UserDomainAccessPublicationUser {
    fn matches_identity(&self, identity: &str) -> bool {
        if identity.is_empty() {
            return false;
        }
        [
            self.user_uuid.as_str(),
            self.protocol_identity.vless_uuid.as_str(),
            self.protocol_identity.vmess_uuid.as_str(),
            self.protocol_identity.tuic_uuid.as_str(),
            self.protocol_identity.hysteria2_password.as_str(),
            self.protocol_identity.trojan_password.as_str(),
            self.protocol_identity.http_username.as_str(),
            self.protocol_identity.socks_username.as_str(),
            self.protocol_identity.shadowsocks_email.as_str(),
        ]
        .iter()
        .any(|candidate| !candidate.is_empty() && *candidate == identity)
    }
}

fn is_user_domain_protocol_supported(protocol: &str) -> bool {
    ["vless", "xhttp", "hysteria2", "socks", "socks5", "trojan"]
        .iter()
        .any(|supported| protocol.trim().eq_ignore_ascii_case(supported))
}

impl UserDomainAccessRule {
    fn matches(&self, target_domain: &str) -> bool {
        match self.match_kind {
            UserDomainAccessMatch::Exact => target_domain == self.domain,
            UserDomainAccessMatch::Suffix => {
                target_domain == self.domain
                    || target_domain.ends_with(&format!(".{}", self.domain))
            }
        }
    }
}

fn evaluate_publication(
    publication: &UserDomainAccessPublication,
    identity: &str,
    target_domain: &str,
) -> (bool, DecisionReason) {
    evaluate_public_with_identities(
        publication,
        std::iter::once(identity),
        target_domain,
    )
}

fn evaluate_public_with_identities<'a, I>(
    publication: &UserDomainAccessPublication,
    identities: I,
    target_domain: &str,
) -> (bool, DecisionReason)
where
    I: IntoIterator<Item = &'a str>,
{
    let Some(target_domain) = normalize_domain_for_match(target_domain) else {
        return (true, DecisionReason::UnknownTarget);
    };

    let identities = identities.into_iter().collect::<Vec<_>>();
    let Some(user) = publication.users.iter().find(|user| {
        identities
            .iter()
            .any(|identity| user.matches_identity(identity))
    }) else {
        return (
            publication.default_action.is_allowed(),
            DecisionReason::NoUserPolicy,
        );
    };

    let matching_rule = user
        .rules
        .iter()
        .filter(|rule| rule.matches(&target_domain))
        .max_by_key(|rule| rule.priority.unwrap_or_default());
    match (user.mode, matching_rule) {
        (_, Some(rule)) => (rule.action.is_allowed(), DecisionReason::MatchedRule),
        (UserDomainAccessMode::AllowAll, None) => {
            (true, DecisionReason::AllowAllDefault)
        }
        (UserDomainAccessMode::Allowlist, None) => {
            (false, DecisionReason::AllowlistMiss)
        }
        (UserDomainAccessMode::Denylist, None) => {
            (true, DecisionReason::DenylistMiss)
        }
    }
}

pub(crate) fn parse_publication(
    json_config: &str,
) -> Result<UserDomainAccessPublication, UserDomainAccessFailure> {
    if json_config.len() > MAX_POLICY_BYTES {
        return Err(UserDomainAccessError::Invalid.message(format!(
            "user-domain access policy exceeds {MAX_POLICY_BYTES} bytes"
        )));
    }

    let mut value: Value = serde_json::from_str(json_config).map_err(|error| {
        UserDomainAccessError::Invalid
            .message(format!("invalid user-domain access policy JSON: {error}"))
    })?;
    let supplied_checksum = value
        .as_object_mut()
        .and_then(|object| object.remove("checksum"))
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            UserDomainAccessError::Invalid.message(
                "user-domain access policy checksum is required".to_string(),
            )
        })?;
    let expected_checksum = checksum_for_value(&value).map_err(|error| {
        UserDomainAccessError::Invalid.message(format!(
            "unable to calculate user-domain access policy checksum: {error}"
        ))
    })?;
    if supplied_checksum != expected_checksum {
        return Err(UserDomainAccessError::Invalid.message(format!(
            "user-domain access policy checksum mismatch: expected {expected_checksum}"
        )));
    }
    value["checksum"] = Value::String(supplied_checksum.clone());

    let mut publication: UserDomainAccessPublication = serde_json::from_value(value)
        .map_err(|error| {
            UserDomainAccessError::Invalid.message(format!(
                "invalid user-domain access policy structure: {error}"
            ))
        })?;
    publication.checksum = supplied_checksum;
    validate_publication(&mut publication)?;
    Ok(publication)
}

fn validate_publication(
    publication: &mut UserDomainAccessPublication,
) -> Result<(), UserDomainAccessFailure> {
    if publication.version == 0 {
        return Err(UserDomainAccessError::Invalid.message(
            "user-domain access version must be greater than zero".to_string(),
        ));
    }
    if publication.generated_at.trim().is_empty()
        || publication.source_backend_version.trim().is_empty()
        || publication.target_node_uuid.trim().is_empty()
    {
        return Err(UserDomainAccessError::Invalid.message(
            "generatedAt, sourceBackendVersion and targetNodeUuid must not be empty"
                .to_string(),
        ));
    }
    if publication.users.len() > MAX_USERS {
        return Err(UserDomainAccessError::Invalid.message(format!(
            "user-domain access policy contains more than {MAX_USERS} users"
        )));
    }
    validate_policy_scale(publication.users.iter().map(|user| user.rules.len()))?;
    if let Some(local_node_uuid) = configured_node_uuid()
        && publication.target_node_uuid != local_node_uuid
    {
        return Err(UserDomainAccessError::FailedPrecondition.message(format!(
            "user-domain access policy targets node {}, but this node is {}",
            publication.target_node_uuid, local_node_uuid
        )));
    }

    let mut user_ids = HashSet::new();
    for user in &mut publication.users {
        if user.user_uuid.trim().is_empty()
            || !user_ids.insert(user.user_uuid.clone())
        {
            return Err(UserDomainAccessError::Invalid.message(
                "user-domain access user_uuid values must be non-empty and unique"
                    .to_string(),
            ));
        }
        if user.rules.len() > MAX_RULES_PER_USER {
            return Err(UserDomainAccessError::Invalid.message(format!(
                "rules must contain at most {MAX_RULES_PER_USER} entries"
            )));
        }
        if matches!(user.mode, UserDomainAccessMode::Allowlist)
            && user.rules.is_empty()
        {
            return Err(UserDomainAccessError::Invalid.message(
                "allowlist policy requires at least one rule".to_string(),
            ));
        }

        let mut rule_ids = HashSet::new();
        let mut semantic_rules = HashSet::new();
        for rule in &mut user.rules {
            rule.domain = normalize_domain(&rule.domain).map_err(|message| {
                UserDomainAccessError::Invalid.message(format!(
                    "invalid user-domain access rule domain: {message}"
                ))
            })?;
            if let Some(id) = &rule.id
                && (id.is_empty()
                    || id.len() > 128
                    || !id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'.' | b':' | b'-')
                    })
                    || !rule_ids.insert(id.clone()))
            {
                return Err(UserDomainAccessError::Invalid.message(
                    "user-domain access rule id is invalid or duplicated"
                        .to_string(),
                ));
            }
            let semantic = (
                rule.domain.clone(),
                rule.match_kind,
                rule.action,
                rule.priority.unwrap_or_default(),
            );
            if !semantic_rules.insert(semantic) {
                return Err(UserDomainAccessError::Invalid.message(format!(
                    "duplicate user-domain access rule for {}",
                    rule.domain
                )));
            }
        }
    }
    Ok(())
}

fn validate_policy_scale<I>(rule_counts: I) -> Result<(), UserDomainAccessFailure>
where
    I: IntoIterator<Item = usize>,
{
    let mut total_rules = 0usize;
    for rule_count in rule_counts {
        if rule_count > MAX_RULES_PER_USER {
            return Err(UserDomainAccessError::Invalid.message(format!(
                "rules must contain at most {MAX_RULES_PER_USER} entries"
            )));
        }
        total_rules = total_rules.checked_add(rule_count).ok_or_else(|| {
            UserDomainAccessError::Invalid.message(format!(
                "user-domain access policy contains more than {MAX_TOTAL_RULES} rules"
            ))
        })?;
        if total_rules > MAX_TOTAL_RULES {
            return Err(UserDomainAccessError::Invalid.message(format!(
                "user-domain access policy contains more than {MAX_TOTAL_RULES} rules"
            )));
        }
    }
    Ok(())
}

fn configured_node_uuid() -> Option<String> {
    ["CHIMERA_NODE_UUID", "RNODE_NODE_UUID", "NODE_UUID"]
        .iter()
        .filter_map(|name| env::var(name).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn normalize_domain(value: &str) -> Result<String, String> {
    let trimmed = value.trim().strip_suffix('.').unwrap_or(value.trim());
    if trimmed.is_empty() || trimmed.parse::<std::net::IpAddr>().is_ok() {
        return Err("domain must be a non-empty hostname".to_string());
    }
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|_| "domain is not a valid DNS name".to_string())?
        .to_ascii_lowercase();
    if ascii.len() > 253 {
        return Err("domain is longer than 253 bytes".to_string());
    }
    for label in ascii.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            })
        {
            return Err("domain contains an invalid DNS label".to_string());
        }
    }
    Ok(ascii)
}

fn normalize_domain_for_match(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        normalize_domain(value).ok()
    }
}

fn safe_routing_user_summary(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "none".to_string();
    }
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{digest:x}")
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn limit_audit_event_fields(
    mut event: UserDomainAccessAuditEvent,
) -> UserDomainAccessAuditEvent {
    event.inbound_tag = truncate_audit_field(&event.inbound_tag);
    event.protocol = truncate_audit_field(&event.protocol);
    event.network = truncate_audit_field(&event.network);
    event.target = truncate_audit_field(&event.target);
    event.routing_user = truncate_audit_field(&event.routing_user);
    event
}

fn truncate_audit_field(value: &str) -> String {
    value.chars().take(MAX_AUDIT_FIELD_LENGTH).collect()
}

fn should_emit_unknown_target_audit(
    inner: &mut UserDomainAccessInner,
    target_domain: &str,
    audit_context: Option<UserDomainAccessAuditContext<'_>>,
    now: Instant,
) -> bool {
    inner.unknown_target_audit.retain(|_, last_seen| {
        now.duration_since(*last_seen) < UNKNOWN_TARGET_AUDIT_DEDUP_WINDOW
    });
    let key = unknown_target_audit_key(target_domain, audit_context);
    if let Some(last_seen) = inner.unknown_target_audit.get_mut(&key) {
        if now.duration_since(*last_seen) < UNKNOWN_TARGET_AUDIT_DEDUP_WINDOW {
            return false;
        }
        *last_seen = now;
        return true;
    }
    if inner.unknown_target_audit.len() >= MAX_UNKNOWN_TARGET_AUDIT_KEYS {
        return false;
    }
    inner.unknown_target_audit.insert(key, now);
    true
}

fn should_emit_unsupported_protocol_audit(
    inner: &mut UserDomainAccessInner,
    context: UserDomainAccessAuditContext<'_>,
) -> bool {
    let key = format!(
        "{}\0{}",
        context.inbound_tag,
        context.protocol.trim().to_ascii_lowercase()
    );
    if !inner.unsupported_protocol_audit.insert(key) {
        return false;
    }
    if inner.unsupported_protocol_audit.len() > MAX_UNSUPPORTED_PROTOCOL_AUDIT_KEYS
        && let Some(key) = inner.unsupported_protocol_audit.iter().next().cloned()
    {
        inner.unsupported_protocol_audit.remove(&key);
    }
    true
}

fn unknown_target_audit_key(
    target_domain: &str,
    audit_context: Option<UserDomainAccessAuditContext<'_>>,
) -> String {
    let mut key = String::new();
    if let Some(context) = audit_context {
        key.push_str(context.inbound_tag);
        key.push('\0');
        key.push_str(context.protocol);
        key.push('\0');
        key.push_str(context.network);
        key.push('\0');
        key.push_str(context.target);
        key.push('\0');
        key.push_str(context.routing_user);
    } else {
        key.push_str(target_domain);
    }
    let digest = Sha256::digest(key.as_bytes());
    format!("{digest:x}")
}

fn revision_of(
    publication: &UserDomainAccessPublication,
) -> UserDomainAccessRevision {
    UserDomainAccessRevision {
        version: publication.version,
        generated_at: publication.generated_at.clone(),
        source_backend_version: publication.source_backend_version.clone(),
        target_node_uuid: publication.target_node_uuid.clone(),
        checksum: publication.checksum.clone(),
    }
}

fn checksum_for_value(value: &Value) -> Result<String, serde_json::Error> {
    let canonical = canonical_json(value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{digest:x}"))
}

fn canonical_json(value: &Value) -> Result<String, serde_json::Error> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical_json(&values[key])?
                    ))
                })
                .collect::<Result<Vec<_>, serde_json::Error>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn bump(value: &mut u64) {
    *value = value.saturating_add(1);
}

fn record_decision_stats(
    stats: &mut UserDomainAccessDecisionStats,
    allowed: bool,
    reason: DecisionReason,
) {
    bump(&mut stats.evaluations);
    match reason {
        DecisionReason::NoUserPolicy => bump(&mut stats.no_user_policy),
        DecisionReason::UnknownTarget => bump(&mut stats.unknown_target),
        DecisionReason::MatchedRule => bump(&mut stats.matched_rule),
        DecisionReason::AllowAllDefault => bump(&mut stats.allow_all_default),
        DecisionReason::AllowlistMiss => bump(&mut stats.allowlist_miss),
        DecisionReason::DenylistMiss => bump(&mut stats.denylist_miss),
    }
    if allowed {
        bump(&mut stats.allowed);
    } else {
        bump(&mut stats.rejected);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;

    use super::*;

    fn publication_json(version: u64, checksum: Option<&str>) -> String {
        let mut value = serde_json::json!({
            "version": version,
            "generatedAt": "2026-01-01T00:00:00.000Z",
            "sourceBackendVersion": "test+commit",
            "targetNodeUuid": "node-1",
            "defaultAction": "allow",
            "users": [{
                "userUuid": "user-1",
                "protocolIdentity": {
                    "vlessUuid": "vless-1",
                    "vmessUuid": "",
                    "tuicUuid": "",
                    "hysteria2Password": "",
                    "trojanPassword": "",
                    "httpUsername": "",
                    "socksUsername": ""
                },
                "mode": "allowlist",
                "unknownTargetAction": "reject",
                "rules": [{
                    "domain": "Example.COM.",
                    "match": "suffix",
                    "action": "allow",
                    "priority": 10
                }]
            }]
        });
        if let Some(checksum) = checksum {
            value["checksum"] = Value::String(checksum.to_string());
        }
        value.to_string()
    }

    fn signed_publication(version: u64) -> String {
        let mut value: Value =
            serde_json::from_str(&publication_json(version, None)).unwrap();
        let checksum = checksum_for_value(&value).unwrap();
        value["checksum"] = Value::String(checksum);
        value.to_string()
    }

    #[test]
    fn checksum_and_domain_normalization_are_verified() {
        let policy = parse_publication(&signed_publication(1)).unwrap();
        assert_eq!(policy.users[0].rules[0].domain, "example.com");
        assert!(
            parse_publication(&publication_json(1, Some("sha256:bad"))).is_err()
        );
    }

    #[test]
    fn apply_is_monotonic_and_rollback_does_not_lower_highest_version() {
        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();
        store
            .apply(parse_publication(&signed_publication(2)).unwrap())
            .unwrap();
        assert!(matches!(
            store.apply(parse_publication(&signed_publication(2)).unwrap()),
            Err(UserDomainAccessFailure {
                kind: UserDomainAccessError::FailedPrecondition,
                ..
            })
        ));
        store.rollback(1).unwrap();
        assert_eq!(store.status().revision.unwrap().version, 1);
        assert!(matches!(
            store.apply(parse_publication(&signed_publication(1)).unwrap()),
            Err(UserDomainAccessFailure {
                kind: UserDomainAccessError::FailedPrecondition,
                ..
            })
        ));
    }

    #[test]
    fn policy_modes_and_rule_actions_are_enforced() {
        let store = UserDomainAccessStore::default();
        let mut value: Value =
            serde_json::from_str(&publication_json(1, None)).unwrap();
        value["users"][0]["rules"][0]["action"] =
            Value::String("reject".to_string());
        value["checksum"] = Value::String(checksum_for_value(&value).unwrap());
        store
            .apply(parse_publication(&value.to_string()).unwrap())
            .unwrap();

        assert!(!store.allows("vless-1", "api.example.com"));
        assert!(!store.allows("vless-1", "other.example"));
        assert!(store.allows("unknown-user", "other.example"));
        let stats = store.status().stats;
        assert_eq!(stats.evaluations, 3);
        assert_eq!(stats.rejected, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.matched_rule, 1);
        assert_eq!(stats.allowlist_miss, 1);
        assert_eq!(stats.no_user_policy, 1);
    }

    #[test]
    fn unknown_targets_are_always_allowed_and_recorded() {
        let store = UserDomainAccessStore::default();
        let mut value: Value =
            serde_json::from_str(&publication_json(1, None)).unwrap();
        value["defaultAction"] = Value::String("reject".to_string());
        value["checksum"] = Value::String(checksum_for_value(&value).unwrap());
        store
            .apply(parse_publication(&value.to_string()).unwrap())
            .unwrap();

        assert!(store.allows("vless-1", ""));
        assert!(store.allows("unknown-user", "203.0.113.10"));

        let stats = store.status().stats;
        assert_eq!(stats.evaluations, 2);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.rejected, 0);
        assert_eq!(stats.unknown_target, 2);
        assert_eq!(stats.no_user_policy, 0);

        let events = store.audit_events(10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision, "allow");
        assert_eq!(events[0].reason, "domain_not_available");
        assert_eq!(events[0].routing_user, "unavailable");
    }

    #[test]
    fn audit_events_keep_safe_context_and_return_newest_first() {
        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();
        let context = UserDomainAccessAuditContext {
            inbound_tag: "vless-in",
            protocol: "vless",
            network: "tcp",
            target: "203.0.113.10:443",
            routing_user: "alice@example.com",
        };

        assert!(store.allows_with_context("vless-1", "", context));
        assert_eq!(store.audit_events(1).len(), 1);
        let event = &store.audit_events(1)[0];
        assert_eq!(event.target, "203.0.113.10:443");
        assert_eq!(
            event.routing_user,
            safe_routing_user_summary("alice@example.com")
        );
        assert!(!event.routing_user.contains("alice@example.com"));
    }

    #[test]
    fn unknown_target_audit_is_deduplicated_within_the_window() {
        let mut inner = UserDomainAccessInner::default();
        let context = UserDomainAccessAuditContext {
            inbound_tag: "vless-in",
            protocol: "vless",
            network: "tcp",
            target: "203.0.113.10:443",
            routing_user: "alice@example.com",
        };
        let start = Instant::now();

        assert!(should_emit_unknown_target_audit(
            &mut inner,
            "",
            Some(context),
            start,
        ));
        assert!(!should_emit_unknown_target_audit(
            &mut inner,
            "",
            Some(context),
            start + Duration::from_millis(500),
        ));
        assert!(should_emit_unknown_target_audit(
            &mut inner,
            "",
            Some(context),
            start + UNKNOWN_TARGET_AUDIT_DEDUP_WINDOW,
        ));
    }

    #[test]
    fn unsupported_protocol_diagnostic_is_explicit_and_deduplicated() {
        let mut inner = UserDomainAccessInner::default();
        let context = UserDomainAccessAuditContext {
            inbound_tag: "vmess-in",
            protocol: "vmess",
            network: "tcp",
            target: "blocked.example",
            routing_user: "user@example.com",
        };

        assert!(!is_user_domain_protocol_supported(context.protocol));
        assert!(should_emit_unsupported_protocol_audit(&mut inner, context));
        assert!(!should_emit_unsupported_protocol_audit(&mut inner, context));
        assert_eq!(inner.unsupported_protocol_audit.len(), 1);

        assert!(is_user_domain_protocol_supported("VLESS"));
        assert!(is_user_domain_protocol_supported("xhttp"));
        assert!(is_user_domain_protocol_supported("socks5"));
        assert!(!is_user_domain_protocol_supported("tuic"));

        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();
        assert!(store.allows_with_context("vless-1", "api.example.com", context));
    }

    #[test]
    fn audit_user_summary_does_not_expose_the_routing_user() {
        let summary = safe_routing_user_summary("alice@example.com");

        assert!(!summary.contains("alice@example.com"));
        assert!(summary.starts_with("sha256:"));
        assert_eq!(summary, safe_routing_user_summary("alice@example.com"));
    }

    #[test]
    fn policy_matches_any_authenticated_protocol_identity() {
        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();

        let identities = vec!["user-label".to_string(), "vless-1".to_string()];
        assert!(store.allows_with_identities(&identities, "api.example.com"));
    }

    #[test]
    fn policy_matches_shadowsocks_email_identity() {
        let mut value: Value =
            serde_json::from_str(&publication_json(1, None)).unwrap();
        value["defaultAction"] = Value::String("reject".to_string());
        value["users"][0]["protocolIdentity"]["shadowsocksEmail"] =
            Value::String("ss-user@example.com".to_string());
        value["checksum"] = Value::String(checksum_for_value(&value).unwrap());

        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&value.to_string()).unwrap())
            .unwrap();

        assert!(store.allows("ss-user@example.com", "api.example.com"));
        assert!(!store.allows("other@example.com", "api.example.com"));
    }

    #[test]
    fn shadow_records_rejections_without_blocking_and_disabled_skips_evaluation() {
        let mut shadow_value: Value =
            serde_json::from_str(&publication_json(1, None)).unwrap();
        shadow_value["enforcementMode"] = Value::String("shadow".to_string());
        shadow_value["users"][0]["rules"][0]["action"] =
            Value::String("reject".to_string());
        shadow_value["checksum"] =
            Value::String(checksum_for_value(&shadow_value).unwrap());

        let shadow = UserDomainAccessStore::default();
        shadow
            .apply(parse_publication(&shadow_value.to_string()).unwrap())
            .unwrap();

        assert!(shadow.allows("vless-1", "api.example.com"));
        let shadow_stats = shadow.status().stats;
        assert_eq!(shadow_stats.evaluations, 1);
        assert_eq!(shadow_stats.rejected, 1);

        let mut disabled_value = shadow_value;
        disabled_value["version"] = Value::from(2);
        disabled_value["enforcementMode"] = Value::String("disabled".to_string());
        disabled_value
            .as_object_mut()
            .expect("publication should be an object")
            .remove("checksum");
        disabled_value["checksum"] =
            Value::String(checksum_for_value(&disabled_value).unwrap());

        let disabled = UserDomainAccessStore::default();
        disabled
            .apply(parse_publication(&disabled_value.to_string()).unwrap())
            .unwrap();

        assert!(disabled.allows("vless-1", "api.example.com"));
        assert_eq!(disabled.status().stats.evaluations, 0);
    }

    #[test]
    fn stale_policy_decision_does_not_update_new_activation_stats() {
        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();

        let stale = store
            .inner
            .read()
            .expect("user-domain access lock poisoned")
            .active
            .clone()
            .expect("active policy");
        let (allowed, reason) =
            evaluate_publication(&stale.publication, "vless-1", "api.example.com");

        store
            .apply(parse_publication(&signed_publication(2)).unwrap())
            .unwrap();
        let mut inner = store
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        if inner
            .active
            .as_ref()
            .is_some_and(|current| current.same_activation(&stale))
        {
            record_decision_stats(&mut inner.stats, allowed, reason);
        }
        assert_eq!(inner.stats.evaluations, 0);
    }

    #[test]
    fn rollback_creates_a_fresh_policy_activation() {
        let store = UserDomainAccessStore::default();
        store
            .apply(parse_publication(&signed_publication(1)).unwrap())
            .unwrap();
        let original = store
            .inner
            .read()
            .expect("user-domain access lock poisoned")
            .active
            .clone()
            .expect("active policy");
        store
            .apply(parse_publication(&signed_publication(2)).unwrap())
            .unwrap();
        store.rollback(1).unwrap();
        let rolled_back = store
            .inner
            .read()
            .expect("user-domain access lock poisoned")
            .active
            .clone()
            .expect("rolled back policy");

        assert!(Arc::ptr_eq(&original.publication, &rolled_back.publication));
        assert!(!original.same_activation(&rolled_back));
    }

    #[test]
    fn concurrent_same_version_activation_has_one_winner() {
        let store = Arc::new(UserDomainAccessStore::default());
        let publication = parse_publication(&signed_publication(7)).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let first_store = Arc::clone(&store);
        let first_barrier = Arc::clone(&barrier);
        let first_publication = publication.clone();
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.apply(first_publication)
        });

        let second_store = Arc::clone(&store);
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_store.apply(publication)
        });

        barrier.wait();
        let first = first.join().expect("first concurrent apply task");
        let second = second.join().expect("second concurrent apply task");
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);

        let failure = if first.is_err() {
            first.err()
        } else {
            second.err()
        }
        .expect("one concurrent apply must fail");
        assert_eq!(failure.kind, UserDomainAccessError::FailedPrecondition);
        assert_eq!(store.status().revision.expect("active revision").version, 7);
    }

    #[test]
    fn policy_total_rule_limit_is_checked_before_compilation() {
        validate_policy_scale(std::iter::repeat_n(
            MAX_RULES_PER_USER,
            MAX_TOTAL_RULES / MAX_RULES_PER_USER,
        ))
        .expect("maximum total rule count should be accepted");

        assert!(matches!(
            validate_policy_scale(std::iter::repeat_n(
                MAX_RULES_PER_USER,
                MAX_TOTAL_RULES / MAX_RULES_PER_USER + 1,
            )),
            Err(UserDomainAccessFailure {
                kind: UserDomainAccessError::Invalid,
                ..
            })
        ));
    }
}
