use std::{
    fmt::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand, ValueEnum};
use rand::{TryRng, rngs::SysRng};
use serde_json::{Value, json};
use tonic::{Request, client::Grpc, codegen::http::uri::PathAndQuery};
use x25519_dalek::{PublicKey, StaticSecret};

const APPLY_POLICY_PATH: &str =
    "/chimera.app.userdomain.command.UserDomainAccessService/ApplyPolicy";
const ROLLBACK_POLICY_PATH: &str =
    "/chimera.app.userdomain.command.UserDomainAccessService/RollbackPolicy";
const GET_POLICY_STATUS_PATH: &str =
    "/chimera.app.userdomain.command.UserDomainAccessService/GetPolicyStatus";

#[derive(Parser)]
#[command(name = "chimera-cli", about = "Utility helpers for Chimera Server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate x25519 keypairs in the same style as xray-core
    X25519 {
        /// Number of keypairs to generate
        #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=8))]
        count: u32,

        /// Output format for the keys
        #[arg(short, long, value_enum, default_value_t = KeyFormat::Base64)]
        format: KeyFormat,
    },
    /// Manage user-domain access policy revisions over Chimera gRPC
    UserDomainAccess {
        /// Chimera gRPC endpoint, for example http://127.0.0.1:8080
        #[arg(long)]
        endpoint: String,

        #[command(subcommand)]
        command: UserDomainCommand,
    },
}

#[derive(Subcommand)]
enum UserDomainCommand {
    /// Validate and atomically apply a policy JSON file
    Apply {
        /// Path to a complete userDomainAccess JSON object
        file: PathBuf,
    },
    /// Return the active revision and cumulative decision counters
    Status,
    /// Roll back to a retained policy version
    Rollback {
        /// Retained policy version to activate
        version: u64,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum KeyFormat {
    Base64,
    Hex,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::X25519 { count, format } => {
            for i in 0..count {
                if i > 0 {
                    println!();
                }
                let (private, public) = generate_keypair(format);
                println!("Private key ({format}): {private}");
                println!("Public key  ({format}): {public}");
            }
        }
        Command::UserDomainAccess { endpoint, command } => {
            run_user_domain_command(&endpoint, command).await?;
        }
    }

    Ok(())
}

async fn run_user_domain_command(
    endpoint: &str,
    command: UserDomainCommand,
) -> Result<()> {
    match command {
        UserDomainCommand::Apply { file } => {
            let json_config = tokio::fs::read_to_string(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let parsed: Value = serde_json::from_str(&json_config)
                .with_context(|| format!("{} is not valid JSON", file.display()))?;
            if !parsed.is_object() {
                return Err(anyhow!("policy JSON root must be an object"));
            }
            let response: ApplyPolicyResponse = unary(
                endpoint,
                APPLY_POLICY_PATH,
                ApplyPolicyRequest { json_config },
            )
            .await?;
            print_revision(response.revision.as_ref())?;
        }
        UserDomainCommand::Status => {
            let response: GetPolicyStatusResponse =
                unary(endpoint, GET_POLICY_STATUS_PATH, GetPolicyStatusRequest {})
                    .await?;
            let output = json!({
                "revision": response.revision.as_ref().map(revision_json),
                "stats": response.stats.as_ref().map(stats_json),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        UserDomainCommand::Rollback { version } => {
            let response: RollbackPolicyResponse = unary(
                endpoint,
                ROLLBACK_POLICY_PATH,
                RollbackPolicyRequest { version },
            )
            .await?;
            print_revision(response.revision.as_ref())?;
        }
    }
    Ok(())
}

async fn unary<Req, Resp>(
    endpoint: &str,
    path: &'static str,
    request: Req,
) -> Result<Resp>
where
    Req: prost::Message + Default + Send + Sync + 'static,
    Resp: prost::Message + Default + Send + Sync + 'static,
{
    let endpoint = normalize_endpoint(endpoint);
    let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .with_context(|| format!("invalid gRPC endpoint {endpoint}"))?
        .connect()
        .await
        .with_context(|| format!("failed to connect to {endpoint}"))?;
    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|error| anyhow!("gRPC service is not ready: {error}"))?;
    let codec = tonic_prost::ProstCodec::<Req, Resp>::default();
    let response = grpc
        .unary(
            Request::new(request),
            PathAndQuery::from_static(path),
            codec,
        )
        .await
        .with_context(|| format!("gRPC request {path} failed"))?;
    Ok(response.into_inner())
}

fn normalize_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

fn print_revision(revision: Option<&RevisionInfo>) -> Result<()> {
    let output = json!({ "revision": revision.map(revision_json) });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn revision_json(revision: &RevisionInfo) -> Value {
    json!({
        "version": revision.version,
        "generatedAt": revision.generated_at,
        "sourceBackendVersion": revision.source_backend_version,
        "targetNodeUuid": revision.target_node_uuid,
        "checksum": revision.checksum,
    })
}

fn stats_json(stats: &DecisionStats) -> Value {
    json!({
        "evaluations": stats.evaluations,
        "allowed": stats.allowed,
        "rejected": stats.rejected,
        "matchedRule": stats.matched_rule,
        "noUserPolicy": stats.no_user_policy,
        "unknownTarget": stats.unknown_target,
        "allowAllDefault": stats.allow_all_default,
        "allowlistMiss": stats.allowlist_miss,
        "denylistMiss": stats.denylist_miss,
        "enforcedRejections": stats.enforced_rejections,
        "shadowRejections": stats.shadow_rejections,
        "disabledBypasses": stats.disabled_bypasses,
        "tlsProbeAttempts": stats.tls_probe_attempts,
        "tlsSniFound": stats.tls_sni_found,
        "tlsEchDetected": stats.tls_ech_detected,
        "tlsNotTls": stats.tls_not_tls,
        "tlsIncomplete": stats.tls_incomplete,
        "tlsMalformed": stats.tls_malformed,
        "tlsNoServerName": stats.tls_no_server_name,
        "tlsTimeouts": stats.tls_timeouts,
        "tlsCapturedBytes": stats.tls_captured_bytes,
        "applySucceeded": stats.apply_succeeded,
        "applyFailed": stats.apply_failed,
        "rollbackSucceeded": stats.rollback_succeeded,
        "rollbackFailed": stats.rollback_failed,
    })
}

fn generate_keypair(format: KeyFormat) -> (String, String) {
    let mut secret_bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut secret_bytes)
        .expect("SysRng failure");
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    (
        encode_key(secret.as_bytes(), format),
        encode_key(public.as_bytes(), format),
    )
}

fn encode_key(bytes: &[u8], format: KeyFormat) -> String {
    match format {
        KeyFormat::Base64 => STANDARD.encode(bytes),
        KeyFormat::Hex => {
            let mut encoded = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(encoded, "{:02x}", byte);
            }
            encoded
        }
    }
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFormat::Base64 => write!(f, "base64"),
            KeyFormat::Hex => write!(f, "hex"),
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct RevisionInfo {
    #[prost(uint64, tag = "1")]
    version: u64,
    #[prost(string, tag = "2")]
    generated_at: String,
    #[prost(string, tag = "3")]
    target_node_uuid: String,
    #[prost(string, tag = "4")]
    checksum: String,
    #[prost(string, tag = "5")]
    source_backend_version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct DecisionStats {
    #[prost(uint64, tag = "1")]
    evaluations: u64,
    #[prost(uint64, tag = "2")]
    allowed: u64,
    #[prost(uint64, tag = "3")]
    rejected: u64,
    #[prost(uint64, tag = "4")]
    matched_rule: u64,
    #[prost(uint64, tag = "5")]
    no_user_policy: u64,
    #[prost(uint64, tag = "6")]
    unknown_target: u64,
    #[prost(uint64, tag = "7")]
    allow_all_default: u64,
    #[prost(uint64, tag = "8")]
    allowlist_miss: u64,
    #[prost(uint64, tag = "9")]
    denylist_miss: u64,
    #[prost(uint64, tag = "10")]
    enforced_rejections: u64,
    #[prost(uint64, tag = "11")]
    shadow_rejections: u64,
    #[prost(uint64, tag = "12")]
    disabled_bypasses: u64,
    #[prost(uint64, tag = "13")]
    tls_probe_attempts: u64,
    #[prost(uint64, tag = "14")]
    tls_sni_found: u64,
    #[prost(uint64, tag = "15")]
    tls_ech_detected: u64,
    #[prost(uint64, tag = "16")]
    tls_not_tls: u64,
    #[prost(uint64, tag = "17")]
    tls_incomplete: u64,
    #[prost(uint64, tag = "18")]
    tls_malformed: u64,
    #[prost(uint64, tag = "19")]
    tls_no_server_name: u64,
    #[prost(uint64, tag = "20")]
    tls_timeouts: u64,
    #[prost(uint64, tag = "21")]
    tls_captured_bytes: u64,
    #[prost(uint64, tag = "22")]
    apply_succeeded: u64,
    #[prost(uint64, tag = "23")]
    apply_failed: u64,
    #[prost(uint64, tag = "24")]
    rollback_succeeded: u64,
    #[prost(uint64, tag = "25")]
    rollback_failed: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ApplyPolicyRequest {
    #[prost(string, tag = "1")]
    json_config: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ApplyPolicyResponse {
    #[prost(message, optional, tag = "1")]
    revision: Option<RevisionInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RollbackPolicyRequest {
    #[prost(uint64, tag = "1")]
    version: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RollbackPolicyResponse {
    #[prost(message, optional, tag = "1")]
    revision: Option<RevisionInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetPolicyStatusRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct GetPolicyStatusResponse {
    #[prost(message, optional, tag = "1")]
    revision: Option<RevisionInfo>,
    #[prost(message, optional, tag = "2")]
    stats: Option<DecisionStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_without_scheme_uses_plain_http() {
        assert_eq!(
            normalize_endpoint("127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_endpoint("https://node.example:443"),
            "https://node.example:443"
        );
    }

    #[test]
    fn revision_json_uses_publication_field_names() {
        let revision = RevisionInfo {
            version: 7,
            generated_at: "2026-08-04T00:00:00Z".into(),
            target_node_uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            checksum: "sha256:test".into(),
            source_backend_version: "backend-42".into(),
        };
        let value = revision_json(&revision);
        assert_eq!(value["version"], 7);
        assert_eq!(value["sourceBackendVersion"], "backend-42");
    }
}
