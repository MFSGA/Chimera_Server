use tonic::{Request, Response, Status};

use crate::{
    runtime::RuntimeState,
    user_domain::{
        UserDomainAccessError, UserDomainAccessFailure, UserDomainAccessRevision,
        UserDomainAccessStatus,
    },
};

use super::proto::chimera::app::user_domain_access;

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
