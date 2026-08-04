use tonic::{Request, Response, Status};

use crate::{
    runtime::{RuntimeState, UserDomainAccessRevisionInfo, UserDomainAccessStats},
    user_domain_access::UserDomainAccessConfig,
};

use super::proto;

pub(super) struct UserDomainAccessServiceImpl {
    runtime: RuntimeState,
}

impl UserDomainAccessServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl proto::chimera::app::userdomain::command::user_domain_access_service_server::UserDomainAccessService
    for UserDomainAccessServiceImpl
{
    async fn apply_policy(
        &self,
        request: Request<proto::chimera::app::userdomain::command::ApplyPolicyRequest>,
    ) -> Result<
        Response<proto::chimera::app::userdomain::command::ApplyPolicyResponse>,
        Status,
    > {
        let json_config = request.into_inner().json_config;
        let result = async {
            if json_config.trim().is_empty() {
                return Err(Status::invalid_argument("json_config is required"));
            }
            let config = serde_json::from_str::<UserDomainAccessConfig>(&json_config)
                .map_err(|error| {
                    Status::invalid_argument(format!(
                        "invalid user-domain access JSON: {error}"
                    ))
                })?;
            let runtime = self.runtime.clone();
            tokio::task::spawn_blocking(move || {
                runtime.install_user_domain_access(config)
            })
            .await
            .map_err(|error| {
                Status::internal(format!(
                    "user-domain access install task failed: {error}"
                ))
            })?
            .map_err(map_install_error)
        }
        .await;
        self.runtime
            .record_user_domain_access_apply(result.is_ok());
        let revision = result?;
        tracing::info!(
            version = revision.version,
            generated_at = revision.generated_at.as_deref().unwrap_or("none"),
            source_backend_version = revision
                .source_backend_version
                .as_deref()
                .unwrap_or("none"),
            target_node_uuid = revision
                .target_node_uuid
                .as_deref()
                .unwrap_or("none"),
            checksum = revision.checksum.as_deref().unwrap_or("none"),
            "user-domain access policy revision applied"
        );
        Ok(Response::new(
            proto::chimera::app::userdomain::command::ApplyPolicyResponse {
                revision: Some(revision_to_proto(revision)),
            },
        ))
    }

    async fn rollback_policy(
        &self,
        request: Request<proto::chimera::app::userdomain::command::RollbackPolicyRequest>,
    ) -> Result<
        Response<proto::chimera::app::userdomain::command::RollbackPolicyResponse>,
        Status,
    > {
        let version = request.into_inner().version;
        let runtime = self.runtime.clone();
        let result = tokio::task::spawn_blocking(move || {
            runtime.rollback_user_domain_access(version)
        })
        .await
        .map_err(|error| {
            Status::internal(format!(
                "user-domain access rollback task failed: {error}"
            ))
        })
        .and_then(|result| result.map_err(Status::failed_precondition));
        self.runtime
            .record_user_domain_access_rollback(result.is_ok());
        let revision = result?;
        tracing::warn!(
            version = revision.version,
            "user-domain access policy rolled back"
        );
        Ok(Response::new(
            proto::chimera::app::userdomain::command::RollbackPolicyResponse {
                revision: Some(revision_to_proto(revision)),
            },
        ))
    }

    async fn get_policy_status(
        &self,
        _request: Request<
            proto::chimera::app::userdomain::command::GetPolicyStatusRequest,
        >,
    ) -> Result<
        Response<proto::chimera::app::userdomain::command::GetPolicyStatusResponse>,
        Status,
    > {
        Ok(Response::new(
            proto::chimera::app::userdomain::command::GetPolicyStatusResponse {
                revision: self
                    .runtime
                    .user_domain_access_revision()
                    .map(revision_to_proto),
                stats: Some(stats_to_proto(
                    self.runtime.user_domain_access_stats(),
                )),
            },
        ))
    }
}

fn map_install_error(error: String) -> Status {
    if error.contains("not newer than highest installed version") {
        Status::failed_precondition(error)
    } else {
        Status::invalid_argument(error)
    }
}

fn revision_to_proto(
    revision: UserDomainAccessRevisionInfo,
) -> proto::chimera::app::userdomain::command::RevisionInfo {
    proto::chimera::app::userdomain::command::RevisionInfo {
        version: revision.version,
        generated_at: revision
            .generated_at
            .as_deref()
            .unwrap_or_default()
            .to_string(),
        target_node_uuid: revision
            .target_node_uuid
            .as_deref()
            .unwrap_or_default()
            .to_string(),
        checksum: revision.checksum.as_deref().unwrap_or_default().to_string(),
        source_backend_version: revision
            .source_backend_version
            .as_deref()
            .unwrap_or_default()
            .to_string(),
    }
}

fn stats_to_proto(
    stats: UserDomainAccessStats,
) -> proto::chimera::app::userdomain::command::DecisionStats {
    proto::chimera::app::userdomain::command::DecisionStats {
        evaluations: stats.evaluations,
        allowed: stats.allowed,
        rejected: stats.rejected,
        matched_rule: stats.matched_rule,
        no_user_policy: stats.no_user_policy,
        unknown_target: stats.unknown_target,
        allow_all_default: stats.allow_all_default,
        allowlist_miss: stats.allowlist_miss,
        denylist_miss: stats.denylist_miss,
        enforced_rejections: stats.enforced_rejections,
        shadow_rejections: stats.shadow_rejections,
        disabled_bypasses: stats.disabled_bypasses,
        tls_probe_attempts: stats.tls_probe_attempts,
        tls_sni_found: stats.tls_sni_found,
        tls_ech_detected: stats.tls_ech_detected,
        tls_not_tls: stats.tls_not_tls,
        tls_incomplete: stats.tls_incomplete,
        tls_malformed: stats.tls_malformed,
        tls_no_server_name: stats.tls_no_server_name,
        tls_timeouts: stats.tls_timeouts,
        tls_captured_bytes: stats.tls_captured_bytes,
        apply_succeeded: stats.apply_succeeded,
        apply_failed: stats.apply_failed,
        rollback_succeeded: stats.rollback_succeeded,
        rollback_failed: stats.rollback_failed,
    }
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> proto::chimera::app::userdomain::command::user_domain_access_service_server::UserDomainAccessServiceServer<
    UserDomainAccessServiceImpl,
>{
    proto::chimera::app::userdomain::command::user_domain_access_service_server::UserDomainAccessServiceServer::new(
        UserDomainAccessServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::proto::chimera::app::userdomain::command::user_domain_access_service_server::UserDomainAccessService;
    use super::*;
    use crate::user_domain_access::user_domain_access_checksum;

    fn temporary_store_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "chimera-grpc-user-domain-access-{}-{nonce}.json",
            std::process::id()
        ))
    }

    fn json(version: u64, domain: &str) -> String {
        let mut config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "version": version,
                "generatedAt": format!("revision-{version}"),
                "sourceBackendVersion": format!("backend-{version}"),
                "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "defaultAction": "reject",
                "users": [{
                    "userUuid": "11111111-1111-4111-8111-111111111111",
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": domain,
                        "match": "exact",
                        "action": "allow"
                    }]
                }]
            }))
            .expect("policy config should parse");
        config.checksum = Some(
            user_domain_access_checksum(&config)
                .expect("policy checksum should compute"),
        );
        serde_json::to_string(&config).expect("policy config should serialize")
    }

    #[tokio::test]
    async fn applies_reports_and_rolls_back_policy_revisions() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let service = UserDomainAccessServiceImpl::new(runtime.clone());

        service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: json(1, "one.example"),
                },
            ))
            .await
            .expect("version 1 apply should succeed");
        service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: json(2, "two.example"),
                },
            ))
            .await
            .expect("version 2 apply should succeed");

        let status = service
            .get_policy_status(Request::new(
                proto::chimera::app::userdomain::command::GetPolicyStatusRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.revision.expect("revision missing").version, 2);
        let stats = status.stats.expect("stats missing");
        assert_eq!(stats.apply_succeeded, 2);
        assert_eq!(stats.apply_failed, 0);

        let rollback = service
            .rollback_policy(Request::new(
                proto::chimera::app::userdomain::command::RollbackPolicyRequest {
                    version: 1,
                },
            ))
            .await
            .expect("rollback should succeed")
            .into_inner();
        assert_eq!(rollback.revision.expect("revision missing").version, 1);

        let replay = service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: json(2, "replayed.example"),
                },
            ))
            .await
            .expect_err("replayed version must fail");
        assert_eq!(replay.code(), tonic::Code::FailedPrecondition);

        let missing = service
            .rollback_policy(Request::new(
                proto::chimera::app::userdomain::command::RollbackPolicyRequest {
                    version: 999,
                },
            ))
            .await
            .expect_err("missing rollback version must fail");
        assert_eq!(missing.code(), tonic::Code::FailedPrecondition);

        let status = service
            .get_policy_status(Request::new(
                proto::chimera::app::userdomain::command::GetPolicyStatusRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let stats = status.stats.expect("stats missing");
        assert_eq!(stats.apply_succeeded, 2);
        assert_eq!(stats.apply_failed, 1);
        assert_eq!(stats.rollback_succeeded, 1);
        assert_eq!(stats.rollback_failed, 1);
    }

    #[tokio::test]
    async fn persisted_history_remains_rollback_capable_after_restart() {
        let store = temporary_store_path();
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime
            .configure_user_domain_access_store(store.clone())
            .expect("store should configure");
        let service = UserDomainAccessServiceImpl::new(runtime);

        for (version, domain) in [(1, "one.example"), (2, "two.example")] {
            service
                .apply_policy(Request::new(
                    proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                        json_config: json(version, domain),
                    },
                ))
                .await
                .expect("policy apply should succeed");
        }
        service
            .rollback_policy(Request::new(
                proto::chimera::app::userdomain::command::RollbackPolicyRequest {
                    version: 1,
                },
            ))
            .await
            .expect("initial rollback should succeed");

        let persisted = crate::runtime::load_user_domain_access_store(&store)
            .expect("store should load")
            .expect("store should exist");
        let restarted = RuntimeState::new(Vec::new(), Vec::new());
        restarted
            .configure_user_domain_access_store(store.clone())
            .expect("store should configure after restart");
        restarted
            .restore_user_domain_access_persisted_state(
                persisted.highest_seen_version,
                persisted.history,
            )
            .expect("history should restore");
        restarted
            .install_user_domain_access(persisted.config)
            .expect("current revision should restore");
        let restarted_service = UserDomainAccessServiceImpl::new(restarted);

        let rollback = restarted_service
            .rollback_policy(Request::new(
                proto::chimera::app::userdomain::command::RollbackPolicyRequest {
                    version: 2,
                },
            ))
            .await
            .expect("persisted history rollback should succeed")
            .into_inner();
        assert_eq!(rollback.revision.expect("revision missing").version, 2);

        let replay = restarted_service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: json(2, "replayed.example"),
                },
            ))
            .await
            .expect_err("restored highest version should reject replay");
        assert_eq!(replay.code(), tonic::Code::FailedPrecondition);

        fs::remove_file(store).expect("temporary store should be removed");
    }

    #[tokio::test]
    async fn invalid_apply_preserves_current_revision() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let service = UserDomainAccessServiceImpl::new(runtime);
        service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: json(5, "stable.example"),
                },
            ))
            .await
            .unwrap();

        let mut invalid: serde_json::Value =
            serde_json::from_str(&json(6, "invalid.example")).unwrap();
        invalid["users"][0]["rules"] = serde_json::json!([]);
        let error = service
            .apply_policy(Request::new(
                proto::chimera::app::userdomain::command::ApplyPolicyRequest {
                    json_config: invalid.to_string(),
                },
            ))
            .await
            .expect_err("invalid revision must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let status = service
            .get_policy_status(Request::new(
                proto::chimera::app::userdomain::command::GetPolicyStatusRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.revision.expect("revision missing").version, 5);
        let stats = status.stats.expect("stats missing");
        assert_eq!(stats.apply_succeeded, 1);
        assert_eq!(stats.apply_failed, 1);
    }
}
