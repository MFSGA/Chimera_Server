use tonic::{Request, Response, Status};

use crate::{
    runtime::RuntimeState,
    user_domain::{
        UserDomainAccessAuditEvent, UserDomainAccessError, UserDomainAccessFailure,
        UserDomainAccessRevision, UserDomainAccessStatus,
    },
};

use super::proto::chimera::app::user_domain_access;

const DEFAULT_AUDIT_EVENT_LIMIT: usize = 100;
const MAX_AUDIT_EVENT_LIMIT: usize = 1_000;

pub(super) struct UserDomainAccessServiceImpl {
    runtime: RuntimeState,
}

impl UserDomainAccessServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl user_domain_access::user_domain_access_service_server::UserDomainAccessService
    for UserDomainAccessServiceImpl
{
    async fn apply_policy(
        &self,
        request: Request<user_domain_access::ApplyPolicyRequest>,
    ) -> Result<Response<user_domain_access::ApplyPolicyResponse>, Status> {
        let json_config = request.into_inner().json_config;
        if json_config.trim().is_empty() {
            return Err(Status::invalid_argument("json_config is required"));
        }
        let runtime = self.runtime.clone();
        let revision = tokio::task::spawn_blocking(move || {
            runtime.apply_user_domain_policy(&json_config)
        })
        .await
        .map_err(|error| {
            Status::internal(format!(
                "user-domain access policy task failed: {error}"
            ))
        })?
        .map_err(status_from_failure)?;
        Ok(Response::new(user_domain_access::ApplyPolicyResponse {
            revision: Some(revision_info(&revision)),
        }))
    }

    async fn rollback_policy(
        &self,
        request: Request<user_domain_access::RollbackPolicyRequest>,
    ) -> Result<Response<user_domain_access::RollbackPolicyResponse>, Status> {
        let version = request.into_inner().version;
        let runtime = self.runtime.clone();
        let revision = tokio::task::spawn_blocking(move || {
            runtime.rollback_user_domain_policy(version)
        })
        .await
        .map_err(|error| {
            Status::internal(format!(
                "user-domain access rollback task failed: {error}"
            ))
        })?
        .map_err(status_from_failure)?;
        Ok(Response::new(user_domain_access::RollbackPolicyResponse {
            revision: Some(revision_info(&revision)),
        }))
    }

    async fn get_policy_status(
        &self,
        _request: Request<user_domain_access::GetPolicyStatusRequest>,
    ) -> Result<Response<user_domain_access::GetPolicyStatusResponse>, Status> {
        let status = self.runtime.user_domain_policy_status();
        Ok(Response::new(user_domain_access::GetPolicyStatusResponse {
            revision: status.revision.as_ref().map(revision_info),
            stats: Some(decision_stats(&status)),
        }))
    }

    async fn get_audit_events(
        &self,
        request: Request<user_domain_access::GetAuditEventsRequest>,
    ) -> Result<Response<user_domain_access::GetAuditEventsResponse>, Status> {
        let requested = request.into_inner().limit as usize;
        let limit = if requested == 0 {
            DEFAULT_AUDIT_EVENT_LIMIT
        } else {
            requested.min(MAX_AUDIT_EVENT_LIMIT)
        };
        let events = self
            .runtime
            .user_domain_audit_events(limit)
            .iter()
            .map(audit_event)
            .collect();
        Ok(Response::new(user_domain_access::GetAuditEventsResponse {
            events,
        }))
    }
}

fn revision_info(
    revision: &UserDomainAccessRevision,
) -> user_domain_access::RevisionInfo {
    user_domain_access::RevisionInfo {
        version: revision.version,
        generated_at: revision.generated_at.clone(),
        target_node_uuid: revision.target_node_uuid.clone(),
        checksum: revision.checksum.clone(),
        source_backend_version: revision.source_backend_version.clone(),
    }
}

fn decision_stats(
    status: &UserDomainAccessStatus,
) -> user_domain_access::DecisionStats {
    let stats = &status.stats;
    user_domain_access::DecisionStats {
        evaluations: stats.evaluations,
        allowed: stats.allowed,
        rejected: stats.rejected,
        matched_rule: stats.matched_rule,
        no_user_policy: stats.no_user_policy,
        unknown_target: stats.unknown_target,
        allow_all_default: stats.allow_all_default,
        allowlist_miss: stats.allowlist_miss,
        denylist_miss: stats.denylist_miss,
        dns_failures: stats.dns_failures,
    }
}

fn audit_event(
    event: &UserDomainAccessAuditEvent,
) -> user_domain_access::AuditEvent {
    user_domain_access::AuditEvent {
        observed_at_unix_ms: event.observed_at_unix_ms,
        decision: event.decision.clone(),
        reason: event.reason.clone(),
        inbound_tag: event.inbound_tag.clone(),
        protocol: event.protocol.clone(),
        network: event.network.clone(),
        target: event.target.clone(),
        routing_user: event.routing_user.clone(),
        identity_count: event.identity_count,
    }
}

fn status_from_failure(failure: UserDomainAccessFailure) -> Status {
    let code = match failure.kind {
        UserDomainAccessError::Invalid => tonic::Code::InvalidArgument,
        UserDomainAccessError::FailedPrecondition => tonic::Code::FailedPrecondition,
        UserDomainAccessError::NotFound => tonic::Code::NotFound,
    };
    Status::new(code, failure.message)
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> user_domain_access::user_domain_access_service_server::UserDomainAccessServiceServer<
    UserDomainAccessServiceImpl,
>{
    user_domain_access::user_domain_access_service_server::UserDomainAccessServiceServer::new(
        UserDomainAccessServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeState;
    use tonic::Code;

    use user_domain_access::user_domain_access_service_server::UserDomainAccessService;

    fn signed_policy() -> String {
        "{\"version\":1,\"generatedAt\":\"2026-01-01T00:00:00.000Z\",\"sourceBackendVersion\":\"test\",\"targetNodeUuid\":\"node-1\",\"defaultAction\":\"reject\",\"users\":[],\"checksum\":\"sha256:5dbfd6c39173b845c52cf308e01156f5fbd6011600118d0fc6adc410217b871a\"}".to_string()
    }

    #[tokio::test]
    async fn user_domain_access_service_applies_reports_and_rolls_back() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let service = UserDomainAccessServiceImpl::new(runtime);

        let applied = service
            .apply_policy(Request::new(user_domain_access::ApplyPolicyRequest {
                json_config: signed_policy(),
            }))
            .await
            .expect("policy should be applied")
            .into_inner();
        let applied_revision =
            applied.revision.expect("revision should be returned");
        assert_eq!(applied_revision.version, 1);
        assert_eq!(applied_revision.target_node_uuid, "node-1");

        let status = service
            .get_policy_status(Request::new(
                user_domain_access::GetPolicyStatusRequest {},
            ))
            .await
            .expect("policy status should be available")
            .into_inner();
        assert_eq!(status.revision.expect("active revision").version, 1);
        assert_eq!(status.stats.expect("decision stats").evaluations, 0);

        let events = service
            .get_audit_events(Request::new(
                user_domain_access::GetAuditEventsRequest { limit: 10 },
            ))
            .await
            .expect("audit events should be available")
            .into_inner();
        assert!(events.events.is_empty());

        let rolled_back = service
            .rollback_policy(Request::new(
                user_domain_access::RollbackPolicyRequest { version: 1 },
            ))
            .await
            .expect("stored policy should be rollbackable")
            .into_inner();
        assert_eq!(rolled_back.revision.expect("rollback revision").version, 1);

        let empty = service
            .apply_policy(Request::new(user_domain_access::ApplyPolicyRequest {
                json_config: " ".into(),
            }))
            .await
            .expect_err("empty policy must be rejected");
        assert_eq!(empty.code(), Code::InvalidArgument);
    }
}
