use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};

use aws_lc_rs::digest::{SHA224, SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;
const DEFAULT_RULE_PRIORITY: u32 = 100;

/// Stable backend user identifier used by the access policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(Uuid);

impl UserId {
    /// Returns the underlying UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for UserId {
    type Err = AccessPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        Uuid::parse_str(trimmed).map(Self).map_err(|source| {
            AccessPolicyError::InvalidUserUuid {
                value: value.to_string(),
                source,
            }
        })
    }
}

/// Final action selected by the user-domain access policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    #[default]
    Allow,
    Reject,
}

/// Default behavior for a user's policy when no domain rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserPolicyMode {
    AllowAll,
    Allowlist,
    Denylist,
}

/// Supported domain matching behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatchKind {
    Exact,
    Suffix,
}

/// Literal configuration for all user-domain access policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserDomainAccessConfig {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub source_backend_version: Option<String>,
    #[serde(default)]
    pub target_node_uuid: Option<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub default_action: AccessAction,
    #[serde(default)]
    pub users: Vec<UserDomainPolicyConfig>,
}

/// Literal configuration for one backend user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserDomainPolicyConfig {
    pub user_uuid: String,
    #[serde(default)]
    pub protocol_identity: ProtocolIdentityConfig,
    pub mode: UserPolicyMode,
    pub unknown_target_action: AccessAction,
    #[serde(default)]
    pub rules: Vec<UserDomainRuleConfig>,
}

/// Optional mapping from protocol credentials to a stable backend user UUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolIdentityConfig {
    #[serde(default)]
    pub vless_uuid: Option<String>,
    #[serde(default)]
    pub vmess_uuid: Option<String>,
    #[serde(default)]
    pub tuic_uuid: Option<String>,
    #[serde(default)]
    pub hysteria2_password: Option<String>,
    #[serde(default)]
    pub trojan_password: Option<String>,
    #[serde(default)]
    pub http_username: Option<String>,
    #[serde(default)]
    pub socks_username: Option<String>,
}

/// Literal configuration for one exact or suffix rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserDomainRuleConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub domain: String,
    #[serde(rename = "match")]
    pub match_kind: DomainMatchKind,
    pub action: AccessAction,
    #[serde(default = "default_rule_priority")]
    pub priority: u32,
}

const fn default_rule_priority() -> u32 {
    DEFAULT_RULE_PRIORITY
}

/// A validated, lower-case ASCII domain name without a trailing root dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedDomain(String);

impl NormalizedDomain {
    /// Parses and validates a DNS domain, including IDNA conversion.
    pub fn parse(value: &str) -> Result<Self, AccessPolicyError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: "domain is empty".into(),
            });
        }

        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty() || value.ends_with('.') {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: "domain has an invalid trailing dot".into(),
            });
        }
        if IpAddr::from_str(value).is_ok() {
            return Err(AccessPolicyError::DomainIsIpAddress(value.to_string()));
        }

        let ascii = idna::domain_to_ascii(value).map_err(|source| {
            AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: source.to_string(),
            }
        })?;
        let ascii = ascii.to_ascii_lowercase();
        validate_ascii_domain(&ascii)?;
        Ok(Self(ascii))
    }

    /// Returns the normalized ASCII domain.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn label_count(&self) -> usize {
        self.0.bytes().filter(|byte| *byte == b'.').count() + 1
    }

    fn is_suffix_of(&self, target: &NormalizedDomain) -> bool {
        if self == target {
            return true;
        }
        let Some(prefix) = target.0.strip_suffix(&self.0) else {
            return false;
        };
        prefix.ends_with('.')
    }
}

impl fmt::Display for NormalizedDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn validate_ascii_domain(value: &str) -> Result<(), AccessPolicyError> {
    if value.len() > MAX_DOMAIN_LENGTH {
        return Err(AccessPolicyError::InvalidDomain {
            value: value.to_string(),
            reason: format!("domain exceeds {MAX_DOMAIN_LENGTH} bytes"),
        });
    }

    for label in value.split('.') {
        if label.is_empty() {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: "domain contains an empty label".into(),
            });
        }
        if label.len() > MAX_LABEL_LENGTH {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: format!("domain label exceeds {MAX_LABEL_LENGTH} bytes"),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: "domain label starts or ends with '-'".into(),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AccessPolicyError::InvalidDomain {
                value: value.to_string(),
                reason: "domain does not conform to the LDH subset".into(),
            });
        }
    }

    Ok(())
}

/// Target metadata available to the access policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTarget {
    Domain(NormalizedDomain),
    IpAddress(IpAddr),
    Unknown,
}

impl AccessTarget {
    /// Classifies an optional target host as domain, IP address, or unknown.
    pub fn classify(value: Option<&str>) -> Result<Self, AccessPolicyError> {
        let Some(value) = value else {
            return Ok(Self::Unknown);
        };
        let value = value.trim();
        if value.is_empty() {
            return Ok(Self::Unknown);
        }
        if let Ok(address) = IpAddr::from_str(value) {
            return Ok(Self::IpAddress(address));
        }
        NormalizedDomain::parse(value).map(Self::Domain)
    }

    /// Returns the low-cardinality target class used in decisions and metrics.
    pub const fn class(&self) -> TargetClass {
        match self {
            Self::Domain(_) => TargetClass::Domain,
            Self::IpAddress(_) => TargetClass::IpAddress,
            Self::Unknown => TargetClass::Unknown,
        }
    }
}

/// Low-cardinality classification of the evaluated target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    Domain,
    IpAddress,
    Unknown,
}

/// Structured explanation for an access decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecisionReason {
    MatchedRule,
    NoUserPolicy,
    UnknownTarget,
    AllowAllDefault,
    AllowlistMiss,
    DenylistMiss,
}

/// Result returned for every user-target policy lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub action: AccessAction,
    pub matched_rule_id: Option<Arc<str>>,
    pub user_uuid: Option<UserId>,
    pub reason: AccessDecisionReason,
    pub target_class: TargetClass,
}

/// Validated in-memory user-domain policy optimized for per-connection lookup.
#[derive(Debug, Clone)]
pub struct UserDomainAccessPolicy {
    default_action: AccessAction,
    users: HashMap<UserId, CompiledUserPolicy>,
    vless_identities: HashMap<Uuid, UserId>,
    vmess_identities: HashMap<Uuid, UserId>,
    tuic_identities: HashMap<Uuid, UserId>,
    hysteria2_identities: HashMap<String, UserId>,
    trojan_identities: HashMap<Box<[u8]>, UserId>,
    http_identities: HashMap<String, UserId>,
    socks_identities: HashMap<String, UserId>,
}

#[derive(Debug, Clone)]
struct CompiledUserPolicy {
    mode: UserPolicyMode,
    unknown_target_action: AccessAction,
    exact_rules: HashMap<NormalizedDomain, Vec<CompiledRule>>,
    suffix_rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: Arc<str>,
    domain: NormalizedDomain,
    action: AccessAction,
    priority: u32,
    order: usize,
}

impl UserDomainAccessPolicy {
    /// Compiles and validates literal policy configuration.
    pub fn compile(
        config: UserDomainAccessConfig,
    ) -> Result<Self, AccessPolicyError> {
        validate_publication_metadata(&config)?;
        let mut users = HashMap::with_capacity(config.users.len());
        let mut vless_identities = HashMap::with_capacity(config.users.len());
        let mut vmess_identities = HashMap::with_capacity(config.users.len());
        let mut tuic_identities = HashMap::with_capacity(config.users.len());
        let mut hysteria2_identities = HashMap::with_capacity(config.users.len());
        let mut trojan_identities = HashMap::with_capacity(config.users.len());
        let mut http_identities = HashMap::with_capacity(config.users.len());
        let mut socks_identities = HashMap::with_capacity(config.users.len());
        for user in config.users {
            let user_id = UserId::from_str(&user.user_uuid)?;
            if users.contains_key(&user_id) {
                return Err(AccessPolicyError::DuplicateUser(user_id));
            }
            let vless_uuid = user
                .protocol_identity
                .vless_uuid
                .as_deref()
                .unwrap_or(&user.user_uuid)
                .trim();
            let vless_uuid = Uuid::parse_str(vless_uuid).map_err(|source| {
                AccessPolicyError::InvalidProtocolIdentity {
                    protocol: "vless",
                    value: vless_uuid.to_string(),
                    source,
                }
            })?;
            if let Some(existing_user) = vless_identities.insert(vless_uuid, user_id)
            {
                return Err(AccessPolicyError::DuplicateProtocolIdentity {
                    protocol: "vless",
                    value: vless_uuid.to_string(),
                    first_user_uuid: existing_user,
                    second_user_uuid: user_id,
                });
            }
            if let Some(vmess_uuid) = user.protocol_identity.vmess_uuid.as_deref() {
                let vmess_uuid =
                    Uuid::parse_str(vmess_uuid.trim()).map_err(|source| {
                        AccessPolicyError::InvalidProtocolIdentity {
                            protocol: "vmess",
                            value: vmess_uuid.to_string(),
                            source,
                        }
                    })?;
                if let Some(existing_user) =
                    vmess_identities.insert(vmess_uuid, user_id)
                {
                    return Err(AccessPolicyError::DuplicateProtocolIdentity {
                        protocol: "vmess",
                        value: vmess_uuid.to_string(),
                        first_user_uuid: existing_user,
                        second_user_uuid: user_id,
                    });
                }
            }
            if let Some(tuic_uuid) = user.protocol_identity.tuic_uuid.as_deref() {
                let tuic_uuid =
                    Uuid::parse_str(tuic_uuid.trim()).map_err(|source| {
                        AccessPolicyError::InvalidProtocolIdentity {
                            protocol: "tuic",
                            value: tuic_uuid.to_string(),
                            source,
                        }
                    })?;
                if let Some(existing_user) =
                    tuic_identities.insert(tuic_uuid, user_id)
                {
                    return Err(AccessPolicyError::DuplicateProtocolIdentity {
                        protocol: "tuic",
                        value: tuic_uuid.to_string(),
                        first_user_uuid: existing_user,
                        second_user_uuid: user_id,
                    });
                }
            }
            if let Some(password) =
                user.protocol_identity.hysteria2_password.as_deref()
            {
                if password.is_empty() {
                    return Err(AccessPolicyError::InvalidHysteria2Identity);
                }
                let identity = hysteria2_password_identity(password);
                if let Some(existing_user) =
                    hysteria2_identities.insert(identity, user_id)
                {
                    return Err(AccessPolicyError::DuplicateHysteria2Identity {
                        first_user_uuid: existing_user,
                        second_user_uuid: user_id,
                    });
                }
            }
            if let Some(password) = user.protocol_identity.trojan_password.as_deref()
            {
                if password.is_empty() {
                    return Err(AccessPolicyError::InvalidTrojanIdentity);
                }
                let password_hash = trojan_password_hash(password);
                if let Some(existing_user) =
                    trojan_identities.insert(password_hash, user_id)
                {
                    return Err(AccessPolicyError::DuplicateTrojanIdentity {
                        first_user_uuid: existing_user,
                        second_user_uuid: user_id,
                    });
                }
            }
            if let Some(username) = user.protocol_identity.http_username.as_deref() {
                insert_named_identity(
                    "HTTP",
                    username,
                    user_id,
                    &mut http_identities,
                )?;
            }
            if let Some(username) = user.protocol_identity.socks_username.as_deref()
            {
                insert_named_identity(
                    "SOCKS",
                    username,
                    user_id,
                    &mut socks_identities,
                )?;
            }
            let compiled = CompiledUserPolicy::compile(user_id, user)?;
            users.insert(user_id, compiled);
        }
        Ok(Self {
            default_action: config.default_action,
            users,
            vless_identities,
            vmess_identities,
            tuic_identities,
            hysteria2_identities,
            trojan_identities,
            http_identities,
            socks_identities,
        })
    }

    /// Evaluates one user and target without scanning policies for other users.
    pub fn decide(
        &self,
        user_uuid: UserId,
        target: &AccessTarget,
    ) -> AccessDecision {
        self.decide_optional(Some(user_uuid), target)
    }

    /// Evaluates a target even when a protocol identity has no backend mapping.
    pub fn decide_optional(
        &self,
        user_uuid: Option<UserId>,
        target: &AccessTarget,
    ) -> AccessDecision {
        let target_class = target.class();
        let Some(user_uuid) = user_uuid else {
            return AccessDecision {
                action: self.default_action,
                matched_rule_id: None,
                user_uuid: None,
                reason: AccessDecisionReason::NoUserPolicy,
                target_class,
            };
        };
        let Some(policy) = self.users.get(&user_uuid) else {
            return AccessDecision {
                action: self.default_action,
                matched_rule_id: None,
                user_uuid: Some(user_uuid),
                reason: AccessDecisionReason::NoUserPolicy,
                target_class,
            };
        };

        match target {
            AccessTarget::Domain(domain) => policy.decide_domain(user_uuid, domain),
            AccessTarget::IpAddress(_) | AccessTarget::Unknown => AccessDecision {
                action: policy.unknown_target_action,
                matched_rule_id: None,
                user_uuid: Some(user_uuid),
                reason: AccessDecisionReason::UnknownTarget,
                target_class,
            },
        }
    }

    /// Resolves an authenticated VLESS UUID to the stable backend user UUID.
    pub fn resolve_vless_identity(
        &self,
        value: &str,
    ) -> Result<UserId, AccessPolicyError> {
        let value = value.trim();
        let uuid = Uuid::parse_str(value).map_err(|source| {
            AccessPolicyError::InvalidProtocolIdentity {
                protocol: "vless",
                value: value.to_string(),
                source,
            }
        })?;
        Ok(self
            .vless_identities
            .get(&uuid)
            .copied()
            .unwrap_or(UserId(uuid)))
    }

    /// Resolves an authenticated VMess UUID to the stable backend user UUID.
    pub fn resolve_vmess_identity(
        &self,
        value: &str,
    ) -> Result<UserId, AccessPolicyError> {
        let value = value.trim();
        let uuid = Uuid::parse_str(value).map_err(|source| {
            AccessPolicyError::InvalidProtocolIdentity {
                protocol: "vmess",
                value: value.to_string(),
                source,
            }
        })?;
        Ok(self
            .vmess_identities
            .get(&uuid)
            .copied()
            .unwrap_or(UserId(uuid)))
    }

    /// Resolves an authenticated TUIC UUID to the stable backend user UUID.
    pub fn resolve_tuic_identity(
        &self,
        value: &str,
    ) -> Result<UserId, AccessPolicyError> {
        let value = value.trim();
        let uuid = Uuid::parse_str(value).map_err(|source| {
            AccessPolicyError::InvalidProtocolIdentity {
                protocol: "tuic",
                value: value.to_string(),
                source,
            }
        })?;
        Ok(self
            .tuic_identities
            .get(&uuid)
            .copied()
            .unwrap_or(UserId(uuid)))
    }

    /// Resolves an authenticated Hysteria2 password identity to a backend user UUID.
    pub fn resolve_hysteria2_identity(&self, identity: &str) -> Option<UserId> {
        self.hysteria2_identities.get(identity).copied()
    }

    /// Resolves an authenticated Trojan password hash to a backend user UUID.
    pub fn resolve_trojan_identity(&self, password_hash: &[u8]) -> Option<UserId> {
        self.trojan_identities.get(password_hash).copied()
    }

    /// Resolves an authenticated HTTP proxy username to a backend user UUID.
    pub fn resolve_http_identity(&self, username: &str) -> Option<UserId> {
        self.http_identities.get(username).copied()
    }

    /// Resolves an authenticated SOCKS username to a backend user UUID.
    pub fn resolve_socks_identity(&self, username: &str) -> Option<UserId> {
        self.socks_identities.get(username).copied()
    }

    /// Returns whether this policy contains a user-specific entry.
    pub fn contains_user(&self, user_uuid: UserId) -> bool {
        self.users.contains_key(&user_uuid)
    }
}

impl TryFrom<UserDomainAccessConfig> for UserDomainAccessPolicy {
    type Error = AccessPolicyError;

    fn try_from(config: UserDomainAccessConfig) -> Result<Self, Self::Error> {
        Self::compile(config)
    }
}

impl CompiledUserPolicy {
    fn compile(
        user_id: UserId,
        config: UserDomainPolicyConfig,
    ) -> Result<Self, AccessPolicyError> {
        if config.mode == UserPolicyMode::Allowlist && config.rules.is_empty() {
            return Err(AccessPolicyError::EmptyAllowlist(user_id));
        }

        let mut rule_ids = HashSet::with_capacity(config.rules.len());
        let mut semantic_rules = HashSet::with_capacity(config.rules.len());
        let mut exact_rules = HashMap::<NormalizedDomain, Vec<CompiledRule>>::new();
        let mut suffix_rules = Vec::new();

        for (order, rule) in config.rules.into_iter().enumerate() {
            let id = normalize_rule_id(rule.id.as_deref(), order)?;
            if !rule_ids.insert(id.clone()) {
                return Err(AccessPolicyError::DuplicateRuleId {
                    user_uuid: user_id,
                    rule_id: id,
                });
            }

            let domain = NormalizedDomain::parse(&rule.domain)?;
            let semantic_key =
                (rule.match_kind, domain.clone(), rule.action, rule.priority);
            if !semantic_rules.insert(semantic_key) {
                return Err(AccessPolicyError::DuplicateRule {
                    user_uuid: user_id,
                    domain,
                    match_kind: rule.match_kind,
                });
            }

            let compiled = CompiledRule {
                id: Arc::from(id),
                domain: domain.clone(),
                action: rule.action,
                priority: rule.priority,
                order,
            };
            match rule.match_kind {
                DomainMatchKind::Exact => {
                    exact_rules.entry(domain).or_default().push(compiled);
                }
                DomainMatchKind::Suffix => suffix_rules.push(compiled),
            }
        }

        for rules in exact_rules.values_mut() {
            rules.sort_by(compare_rule_priority);
        }
        suffix_rules.sort_by(compare_suffix_rules);

        Ok(Self {
            mode: config.mode,
            unknown_target_action: config.unknown_target_action,
            exact_rules,
            suffix_rules,
        })
    }

    fn decide_domain(
        &self,
        user_uuid: UserId,
        domain: &NormalizedDomain,
    ) -> AccessDecision {
        if let Some(rule) =
            self.exact_rules.get(domain).and_then(|rules| rules.first())
        {
            return matched_rule_decision(user_uuid, rule);
        }
        if let Some(rule) = self
            .suffix_rules
            .iter()
            .find(|rule| rule.domain.is_suffix_of(domain))
        {
            return matched_rule_decision(user_uuid, rule);
        }

        let (action, reason) = match self.mode {
            UserPolicyMode::AllowAll => {
                (AccessAction::Allow, AccessDecisionReason::AllowAllDefault)
            }
            UserPolicyMode::Allowlist => {
                (AccessAction::Reject, AccessDecisionReason::AllowlistMiss)
            }
            UserPolicyMode::Denylist => {
                (AccessAction::Allow, AccessDecisionReason::DenylistMiss)
            }
        };
        AccessDecision {
            action,
            matched_rule_id: None,
            user_uuid: Some(user_uuid),
            reason,
            target_class: TargetClass::Domain,
        }
    }
}

fn insert_named_identity(
    protocol: &'static str,
    username: &str,
    user_id: UserId,
    identities: &mut HashMap<String, UserId>,
) -> Result<(), AccessPolicyError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AccessPolicyError::InvalidNamedIdentity { protocol });
    }
    if let Some(existing_user) = identities.insert(username.to_string(), user_id) {
        return Err(AccessPolicyError::DuplicateNamedIdentity {
            protocol,
            username: username.to_string(),
            first_user_uuid: existing_user,
            second_user_uuid: user_id,
        });
    }
    Ok(())
}

fn validate_publication_metadata(
    config: &UserDomainAccessConfig,
) -> Result<(), AccessPolicyError> {
    if let Some(value) = config.generated_at.as_deref() {
        let value = value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err(AccessPolicyError::InvalidPublicationMetadata {
                field: "generatedAt",
                reason: "value must contain 1 to 256 bytes".into(),
            });
        }
    }
    if let Some(value) = config.source_backend_version.as_deref() {
        let value = value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err(AccessPolicyError::InvalidPublicationMetadata {
                field: "sourceBackendVersion",
                reason: "value must contain 1 to 256 bytes".into(),
            });
        }
    }
    if let Some(value) = config.target_node_uuid.as_deref() {
        Uuid::parse_str(value.trim()).map_err(|source| {
            AccessPolicyError::InvalidTargetNodeUuid {
                value: value.to_string(),
                source,
            }
        })?;
    }
    if let Some(actual) = config.checksum.as_deref() {
        let expected = user_domain_access_checksum(config)?;
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(AccessPolicyError::ChecksumMismatch {
                expected,
                actual: actual.to_string(),
            });
        }
    }
    Ok(())
}

/// Computes the canonical SHA-256 checksum used by policy publications.
pub fn user_domain_access_checksum(
    config: &UserDomainAccessConfig,
) -> Result<String, AccessPolicyError> {
    let mut value = serde_json::to_value(config).map_err(|error| {
        AccessPolicyError::ChecksumSerialization(error.to_string())
    })?;
    if let serde_json::Value::Object(object) = &mut value {
        object.remove("checksum");
    }
    let mut canonical = Vec::new();
    write_canonical_json(&value, &mut canonical)?;
    let checksum = digest(&SHA256, &canonical);
    Ok(format!("sha256:{}", encode_lower_hex(checksum.as_ref())))
}

fn write_canonical_json(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), AccessPolicyError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(value) => {
            output.extend_from_slice(value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            serde_json::to_writer(output, value).map_err(|error| {
                AccessPolicyError::ChecksumSerialization(error.to_string())
            })?;
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| {
                    AccessPolicyError::ChecksumSerialization(error.to_string())
                })?;
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

/// Returns a non-secret stable identity for an authenticated Hysteria2 password.
pub(crate) fn hysteria2_password_identity(password: &str) -> String {
    let checksum = digest(&SHA256, password.as_bytes());
    format!("sha256:{}", encode_lower_hex(checksum.as_ref()))
}

fn trojan_password_hash(password: &str) -> Box<[u8]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest(&SHA224, password.as_bytes());
    let mut result = Vec::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref().iter().copied() {
        result.push(HEX[(byte >> 4) as usize]);
        result.push(HEX[(byte & 0x0f) as usize]);
    }
    result.into_boxed_slice()
}

fn normalize_rule_id(
    value: Option<&str>,
    order: usize,
) -> Result<String, AccessPolicyError> {
    let id = match value {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Err(AccessPolicyError::InvalidRuleId {
                    rule_id: String::new(),
                    reason: "rule ID is empty".into(),
                });
            }
            value.to_string()
        }
        None => format!("rule-{}", order + 1),
    };
    if id.len() > 128 {
        return Err(AccessPolicyError::InvalidRuleId {
            rule_id: id,
            reason: "rule ID exceeds 128 bytes".into(),
        });
    }
    if !id.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
    }) {
        return Err(AccessPolicyError::InvalidRuleId {
            rule_id: id,
            reason: "rule ID contains unsupported characters".into(),
        });
    }
    Ok(id)
}

fn compare_rule_priority(left: &CompiledRule, right: &CompiledRule) -> Ordering {
    left.priority
        .cmp(&right.priority)
        .then_with(|| left.order.cmp(&right.order))
}

fn compare_suffix_rules(left: &CompiledRule, right: &CompiledRule) -> Ordering {
    right
        .domain
        .label_count()
        .cmp(&left.domain.label_count())
        .then_with(|| right.domain.as_str().len().cmp(&left.domain.as_str().len()))
        .then_with(|| compare_rule_priority(left, right))
}

fn matched_rule_decision(user_uuid: UserId, rule: &CompiledRule) -> AccessDecision {
    AccessDecision {
        action: rule.action,
        matched_rule_id: Some(Arc::clone(&rule.id)),
        user_uuid: Some(user_uuid),
        reason: AccessDecisionReason::MatchedRule,
        target_class: TargetClass::Domain,
    }
}

/// Validation error produced while compiling a user-domain access policy.
#[derive(Debug, Error)]
pub enum AccessPolicyError {
    #[error("invalid backend user UUID {value}: {source}")]
    InvalidUserUuid {
        value: String,
        #[source]
        source: uuid::Error,
    },
    #[error("invalid {protocol} protocol identity {value}: {source}")]
    InvalidProtocolIdentity {
        protocol: &'static str,
        value: String,
        #[source]
        source: uuid::Error,
    },
    #[error(
        "duplicate {protocol} protocol identity {value} for users {first_user_uuid} and {second_user_uuid}"
    )]
    DuplicateProtocolIdentity {
        protocol: &'static str,
        value: String,
        first_user_uuid: UserId,
        second_user_uuid: UserId,
    },
    #[error("duplicate user-domain policy for {0}")]
    DuplicateUser(UserId),
    #[error("invalid publication metadata {field}: {reason}")]
    InvalidPublicationMetadata { field: &'static str, reason: String },
    #[error("invalid target node UUID {value}: {source}")]
    InvalidTargetNodeUuid {
        value: String,
        #[source]
        source: uuid::Error,
    },
    #[error("failed to canonicalize policy for checksum: {0}")]
    ChecksumSerialization(String),
    #[error(
        "user-domain access checksum mismatch: expected {expected}, got {actual}"
    )]
    ChecksumMismatch { expected: String, actual: String },
    #[error("Hysteria2 protocol identity password must not be empty")]
    InvalidHysteria2Identity,
    #[error(
        "duplicate Hysteria2 protocol identity for users {first_user_uuid} and {second_user_uuid}"
    )]
    DuplicateHysteria2Identity {
        first_user_uuid: UserId,
        second_user_uuid: UserId,
    },
    #[error("Trojan protocol identity password must not be empty")]
    InvalidTrojanIdentity,
    #[error("{protocol} protocol identity username must not be empty")]
    InvalidNamedIdentity { protocol: &'static str },
    #[error(
        "duplicate Trojan protocol identity for users {first_user_uuid} and {second_user_uuid}"
    )]
    DuplicateTrojanIdentity {
        first_user_uuid: UserId,
        second_user_uuid: UserId,
    },
    #[error(
        "duplicate {protocol} protocol identity {username} for users {first_user_uuid} and {second_user_uuid}"
    )]
    DuplicateNamedIdentity {
        protocol: &'static str,
        username: String,
        first_user_uuid: UserId,
        second_user_uuid: UserId,
    },
    #[error("allowlist for {0} must contain at least one rule")]
    EmptyAllowlist(UserId),
    #[error("invalid domain {value}: {reason}")]
    InvalidDomain { value: String, reason: String },
    #[error("domain rule must not use an IP address: {0}")]
    DomainIsIpAddress(String),
    #[error("invalid rule ID {rule_id}: {reason}")]
    InvalidRuleId { rule_id: String, reason: String },
    #[error("duplicate rule ID {rule_id} for user {user_uuid}")]
    DuplicateRuleId { user_uuid: UserId, rule_id: String },
    #[error(
        "duplicate {match_kind:?} rule for domain {domain} and user {user_uuid}"
    )]
    DuplicateRule {
        user_uuid: UserId,
        domain: NormalizedDomain,
        match_kind: DomainMatchKind,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_A: &str = "11111111-1111-4111-8111-111111111111";
    const USER_B: &str = "22222222-2222-4222-8222-222222222222";

    fn user(value: &str) -> UserId {
        UserId::from_str(value).unwrap()
    }

    fn domain(value: &str) -> AccessTarget {
        AccessTarget::classify(Some(value)).unwrap()
    }

    fn policy(config: serde_json::Value) -> UserDomainAccessPolicy {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(config).unwrap();
        UserDomainAccessPolicy::compile(config).unwrap()
    }

    #[test]
    fn normalizes_case_trailing_dot_and_idna() {
        assert_eq!(
            NormalizedDomain::parse("BÜCHER.Example.").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn rejects_ip_and_invalid_domain_rules() {
        assert!(matches!(
            NormalizedDomain::parse("192.0.2.1"),
            Err(AccessPolicyError::DomainIsIpAddress(_))
        ));
        assert!(matches!(
            NormalizedDomain::parse("bad_domain.example"),
            Err(AccessPolicyError::InvalidDomain { .. })
        ));
        assert!(matches!(
            NormalizedDomain::parse("bad..example"),
            Err(AccessPolicyError::InvalidDomain { .. })
        ));
    }

    #[test]
    fn suffix_matching_respects_dns_label_boundaries() {
        let policy = policy(serde_json::json!({
            "defaultAction": "allow",
            "users": [{
                "userUuid": USER_A,
                "mode": "allowlist",
                "unknownTargetAction": "reject",
                "rules": [{
                    "id": "allow-example",
                    "domain": "example.com",
                    "match": "suffix",
                    "action": "allow"
                }]
            }]
        }));

        for allowed in ["example.com", "api.example.com", "A.B.EXAMPLE.COM."] {
            assert_eq!(
                policy.decide(user(USER_A), &domain(allowed)).action,
                AccessAction::Allow
            );
        }
        assert_eq!(
            policy
                .decide(user(USER_A), &domain("badexample.com"))
                .action,
            AccessAction::Reject
        );
    }

    #[test]
    fn exact_rules_take_precedence_over_suffix_rules() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "mode": "allowlist",
                "unknownTargetAction": "reject",
                "rules": [
                    {
                        "id": "allow-example",
                        "domain": "example.com",
                        "match": "suffix",
                        "action": "allow",
                        "priority": 1
                    },
                    {
                        "id": "reject-api",
                        "domain": "api.example.com",
                        "match": "exact",
                        "action": "reject",
                        "priority": 500
                    }
                ]
            }]
        }));

        let decision = policy.decide(user(USER_A), &domain("api.example.com"));
        assert_eq!(decision.action, AccessAction::Reject);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("reject-api"));
    }

    #[test]
    fn longer_suffix_then_priority_determine_the_match() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "mode": "allowlist",
                "unknownTargetAction": "reject",
                "rules": [
                    {
                        "id": "allow-parent",
                        "domain": "example.com",
                        "match": "suffix",
                        "action": "allow",
                        "priority": 1
                    },
                    {
                        "id": "reject-api-late",
                        "domain": "api.example.com",
                        "match": "suffix",
                        "action": "reject",
                        "priority": 50
                    },
                    {
                        "id": "allow-api-first",
                        "domain": "api.example.com",
                        "match": "suffix",
                        "action": "allow",
                        "priority": 10
                    }
                ]
            }]
        }));

        let decision = policy.decide(user(USER_A), &domain("v1.api.example.com"));
        assert_eq!(decision.action, AccessAction::Allow);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("allow-api-first"));
    }

    #[test]
    fn policy_modes_have_deterministic_domain_defaults() {
        let policy = policy(serde_json::json!({
            "users": [
                {
                    "userUuid": USER_A,
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": "allowed.example",
                        "match": "exact",
                        "action": "allow"
                    }]
                },
                {
                    "userUuid": USER_B,
                    "mode": "denylist",
                    "unknownTargetAction": "allow",
                    "rules": [{
                        "domain": "blocked.example",
                        "match": "exact",
                        "action": "reject"
                    }]
                }
            ]
        }));

        let allowlist_miss = policy.decide(user(USER_A), &domain("other.example"));
        assert_eq!(allowlist_miss.action, AccessAction::Reject);
        assert_eq!(allowlist_miss.reason, AccessDecisionReason::AllowlistMiss);

        let denylist_miss = policy.decide(user(USER_B), &domain("other.example"));
        assert_eq!(denylist_miss.action, AccessAction::Allow);
        assert_eq!(denylist_miss.reason, AccessDecisionReason::DenylistMiss);
    }

    #[test]
    fn unknown_targets_use_the_user_specific_action() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "mode": "allowlist",
                "unknownTargetAction": "reject",
                "rules": [{
                    "domain": "allowed.example",
                    "match": "exact",
                    "action": "allow"
                }]
            }]
        }));

        for target in [
            AccessTarget::Unknown,
            AccessTarget::IpAddress("192.0.2.1".parse().unwrap()),
        ] {
            let decision = policy.decide(user(USER_A), &target);
            assert_eq!(decision.action, AccessAction::Reject);
            assert_eq!(decision.reason, AccessDecisionReason::UnknownTarget);
        }
    }

    #[test]
    fn users_without_a_policy_use_the_global_default() {
        let policy = policy(serde_json::json!({
            "defaultAction": "reject",
            "users": []
        }));
        let decision = policy.decide(user(USER_A), &domain("example.com"));
        assert_eq!(decision.action, AccessAction::Reject);
        assert_eq!(decision.reason, AccessDecisionReason::NoUserPolicy);
    }

    #[test]
    fn rejects_duplicate_users_empty_allowlists_and_duplicate_rules() {
        let duplicate_user =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [
                    {
                        "userUuid": USER_A,
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    },
                    {
                        "userUuid": USER_A,
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    }
                ]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(duplicate_user),
            Err(AccessPolicyError::DuplicateUser(_))
        ));

        let empty_allowlist =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [{
                    "userUuid": USER_A,
                    "mode": "allowlist",
                    "unknownTargetAction": "reject"
                }]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(empty_allowlist),
            Err(AccessPolicyError::EmptyAllowlist(_))
        ));

        let duplicate_rules =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [{
                    "userUuid": USER_A,
                    "mode": "denylist",
                    "unknownTargetAction": "allow",
                    "rules": [
                        {
                            "id": "first",
                            "domain": "example.com",
                            "match": "suffix",
                            "action": "reject"
                        },
                        {
                            "id": "second",
                            "domain": "EXAMPLE.COM.",
                            "match": "suffix",
                            "action": "reject"
                        }
                    ]
                }]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(duplicate_rules),
            Err(AccessPolicyError::DuplicateRule { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_and_invalid_rule_ids() {
        let duplicate_ids =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [{
                    "userUuid": USER_A,
                    "mode": "denylist",
                    "unknownTargetAction": "allow",
                    "rules": [
                        {
                            "id": "same",
                            "domain": "one.example",
                            "match": "exact",
                            "action": "reject"
                        },
                        {
                            "id": "same",
                            "domain": "two.example",
                            "match": "exact",
                            "action": "reject"
                        }
                    ]
                }]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(duplicate_ids),
            Err(AccessPolicyError::DuplicateRuleId { .. })
        ));

        for invalid_rule_id in ["contains spaces", ""] {
            let invalid_id = serde_json::from_value::<UserDomainAccessConfig>(
                serde_json::json!({
                    "users": [{
                        "userUuid": USER_A,
                        "mode": "denylist",
                        "unknownTargetAction": "allow",
                        "rules": [{
                            "id": invalid_rule_id,
                            "domain": "one.example",
                            "match": "exact",
                            "action": "reject"
                        }]
                    }]
                }),
            )
            .unwrap();
            assert!(matches!(
                UserDomainAccessPolicy::compile(invalid_id),
                Err(AccessPolicyError::InvalidRuleId { .. })
            ));
        }
    }

    #[test]
    fn resolves_explicit_vless_identity_to_backend_user() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "protocolIdentity": {
                    "vlessUuid": USER_B
                },
                "mode": "allow_all",
                "unknownTargetAction": "allow"
            }]
        }));

        assert_eq!(policy.resolve_vless_identity(USER_B).unwrap(), user(USER_A));
        assert_eq!(policy.resolve_vless_identity(USER_A).unwrap(), user(USER_A));
    }

    #[test]
    fn resolves_hysteria2_identity_without_exposing_plaintext() {
        let password = "hysteria-secret";
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "protocolIdentity": {
                    "hysteria2Password": password
                },
                "mode": "allow_all",
                "unknownTargetAction": "allow"
            }]
        }));
        let identity = hysteria2_password_identity(password);
        assert!(identity.starts_with("sha256:"));
        assert!(!identity.contains(password));
        assert_eq!(
            policy.resolve_hysteria2_identity(&identity),
            Some(user(USER_A))
        );
        assert_eq!(policy.resolve_hysteria2_identity(password), None);
    }

    #[test]
    fn resolves_trojan_identity_without_exposing_plaintext() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "protocolIdentity": {
                    "trojanPassword": "correct horse battery staple"
                },
                "mode": "allow_all",
                "unknownTargetAction": "allow"
            }]
        }));
        let password_hash = trojan_password_hash("correct horse battery staple");
        assert_eq!(
            policy.resolve_trojan_identity(&password_hash),
            Some(user(USER_A))
        );
        assert_eq!(
            policy.resolve_trojan_identity(&trojan_password_hash("other")),
            None
        );
    }

    #[test]
    fn rejects_duplicate_trojan_identity_mappings() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [
                    {
                        "userUuid": USER_A,
                        "protocolIdentity": { "trojanPassword": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    },
                    {
                        "userUuid": USER_B,
                        "protocolIdentity": { "trojanPassword": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    }
                ]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(config),
            Err(AccessPolicyError::DuplicateTrojanIdentity { .. })
        ));
    }

    #[test]
    fn resolves_http_username_to_backend_user() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "protocolIdentity": {
                    "httpUsername": "autumn"
                },
                "mode": "allow_all",
                "unknownTargetAction": "allow"
            }]
        }));
        assert_eq!(policy.resolve_http_identity("autumn"), Some(user(USER_A)));
        assert_eq!(policy.resolve_http_identity("Autumn"), None);
    }

    #[test]
    fn rejects_duplicate_http_identity_mappings() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [
                    {
                        "userUuid": USER_A,
                        "protocolIdentity": { "httpUsername": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    },
                    {
                        "userUuid": USER_B,
                        "protocolIdentity": { "httpUsername": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    }
                ]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(config),
            Err(AccessPolicyError::DuplicateNamedIdentity {
                protocol: "HTTP",
                ..
            })
        ));
    }

    #[test]
    fn resolves_vmess_tuic_and_socks_identities() {
        let policy = policy(serde_json::json!({
            "users": [{
                "userUuid": USER_A,
                "protocolIdentity": {
                    "vmessUuid": USER_B,
                    "tuicUuid": "33333333-3333-4333-8333-333333333333",
                    "socksUsername": "autumn"
                },
                "mode": "allow_all",
                "unknownTargetAction": "allow"
            }]
        }));
        assert_eq!(policy.resolve_vmess_identity(USER_B).unwrap(), user(USER_A));
        assert_eq!(policy.resolve_vmess_identity(USER_A).unwrap(), user(USER_A));
        assert_eq!(
            policy
                .resolve_tuic_identity("33333333-3333-4333-8333-333333333333")
                .unwrap(),
            user(USER_A)
        );
        assert_eq!(policy.resolve_socks_identity("autumn"), Some(user(USER_A)));
        assert_eq!(policy.resolve_socks_identity("Autumn"), None);
    }

    #[test]
    fn rejects_duplicate_socks_identity_mappings() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [
                    {
                        "userUuid": USER_A,
                        "protocolIdentity": { "socksUsername": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    },
                    {
                        "userUuid": USER_B,
                        "protocolIdentity": { "socksUsername": "shared" },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    }
                ]
            }))
            .unwrap();
        assert!(matches!(
            UserDomainAccessPolicy::compile(config),
            Err(AccessPolicyError::DuplicateNamedIdentity {
                protocol: "SOCKS",
                ..
            })
        ));
    }

    #[test]
    fn canonical_checksum_detects_policy_tampering() {
        let mut config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "version": 9,
                "generatedAt": "2026-08-04T03:00:00Z",
                "targetNodeUuid": USER_B,
                "defaultAction": "reject",
                "users": [{
                    "userUuid": USER_A,
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": "allowed.example",
                        "match": "exact",
                        "action": "allow"
                    }]
                }]
            }))
            .unwrap();
        let checksum = user_domain_access_checksum(&config).unwrap();
        assert!(checksum.starts_with("sha256:"));
        assert_eq!(checksum.len(), "sha256:".len() + 64);
        config.checksum = Some(checksum);
        UserDomainAccessPolicy::compile(config.clone())
            .expect("matching checksum should compile");

        config.users[0].rules[0].domain = "tampered.example".into();
        assert!(matches!(
            UserDomainAccessPolicy::compile(config),
            Err(AccessPolicyError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn backend_canonical_checksum_fixture_matches_rust() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "version": 42,
                "generatedAt": "2026-08-04T00:00:00.000Z",
                "sourceBackendVersion": "backend-42",
                "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "defaultAction": "reject",
                "users": [{
                    "userUuid": "11111111-1111-4111-8111-111111111111",
                    "protocolIdentity": {
                        "vlessUuid": "22222222-2222-4222-8222-222222222222",
                        "vmessUuid": "22222222-2222-4222-8222-222222222222",
                        "tuicUuid": "22222222-2222-4222-8222-222222222222",
                        "hysteria2Password": "secret",
                        "trojanPassword": "secret",
                        "httpUsername": "autumn",
                        "socksUsername": "autumn"
                    },
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "id": "allow-api",
                        "domain": "api.example.com",
                        "match": "exact",
                        "action": "allow",
                        "priority": 10
                    }]
                }]
            }))
            .expect("backend checksum fixture should parse");
        assert_eq!(
            user_domain_access_checksum(&config).unwrap(),
            "sha256:0fba1228972c108b986d2affbad95cadc18b39074520ce534459d7614c709fc5"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_users_do_not_share_policy_state() {
        let policy = Arc::new(policy(serde_json::json!({
            "defaultAction": "reject",
            "users": [
                {
                    "userUuid": USER_A,
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": "a.example",
                        "match": "suffix",
                        "action": "allow"
                    }]
                },
                {
                    "userUuid": USER_B,
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": "b.example",
                        "match": "suffix",
                        "action": "allow"
                    }]
                }
            ]
        })));
        let mut tasks = Vec::new();
        for index in 0..64 {
            let policy = Arc::clone(&policy);
            tasks.push(tokio::spawn(async move {
                let (user_uuid, allowed, blocked) = if index % 2 == 0 {
                    (USER_A, "api.a.example", "api.b.example")
                } else {
                    (USER_B, "api.b.example", "api.a.example")
                };
                let user = policy.resolve_vless_identity(user_uuid).unwrap();
                for _ in 0..100 {
                    assert_eq!(
                        policy.decide(user, &domain(allowed)).action,
                        AccessAction::Allow
                    );
                    assert_eq!(
                        policy.decide(user, &domain(blocked)).action,
                        AccessAction::Reject
                    );
                }
            }));
        }
        for task in tasks {
            task.await.expect("policy task must not panic");
        }
    }

    #[test]
    fn rejects_duplicate_vless_identity_mappings() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "users": [
                    {
                        "userUuid": USER_A,
                        "protocolIdentity": { "vlessUuid": USER_A },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    },
                    {
                        "userUuid": USER_B,
                        "protocolIdentity": { "vlessUuid": USER_A },
                        "mode": "allow_all",
                        "unknownTargetAction": "allow"
                    }
                ]
            }))
            .unwrap();

        assert!(matches!(
            UserDomainAccessPolicy::compile(config),
            Err(AccessPolicyError::DuplicateProtocolIdentity { .. })
        ));
    }
}
