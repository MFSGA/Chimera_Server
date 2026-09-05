use std::{
    collections::{BTreeMap, HashSet},
    env,
    sync::{Arc, RwLock},
};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;
const MAX_USERS: usize = 100_000;
const MAX_RULES_PER_USER: usize = 1_000;
const MAX_TOTAL_RULES: usize = 1_000_000;

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
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UserDomainAccessStatus {
    pub(crate) revision: Option<UserDomainAccessRevision>,
    pub(crate) stats: UserDomainAccessDecisionStats,
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

    /// Applies the active policy to a resolved target domain before an
    /// outbound connection is established. An empty target domain represents
    /// an IP-only or otherwise unknown target and follows the configured
    /// unknown-target action.
    pub(crate) fn allows(&self, identity: &str, target_domain: &str) -> bool {
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

        let enforcement_mode = active.publication.enforcement_mode;
        let (allowed, reason) =
            evaluate_publication(&active.publication, identity, target_domain);

        let mut inner = self
            .inner
            .write()
            .expect("user-domain access lock poisoned");
        if inner
            .active
            .as_ref()
            .is_some_and(|current| current.same_activation(&active))
        {
            record_decision_stats(&mut inner.stats, allowed, reason);
        }
        drop(inner);

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
        ]
        .iter()
        .any(|candidate| !candidate.is_empty() && *candidate == identity)
    }
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
    let Some(user) = publication
        .users
        .iter()
        .find(|user| user.matches_identity(identity))
    else {
        return (
            publication.default_action.is_allowed(),
            DecisionReason::NoUserPolicy,
        );
    };

    let Some(target_domain) = normalize_domain_for_match(target_domain) else {
        return (
            user.unknown_target_action.is_allowed(),
            DecisionReason::UnknownTarget,
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
