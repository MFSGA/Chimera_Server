use tonic::{Request, Response, Status};

#[cfg(test)]
use crate::beginning::start_servers;
#[cfg(feature = "reality")]
use crate::config::server_config::RealityTransportConfig;
#[cfg(feature = "tls")]
use crate::config::server_config::TlsServerConfig;
#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "ws")]
use crate::config::server_config::ws::WebsocketServerConfig;
#[cfg(feature = "tls")]
use crate::config::server_config::{TlsCertificateConfig, TlsCertificateUsage};
#[cfg(feature = "vmess")]
use crate::config::server_config::{VmessUser, normalize_vmess_user_id};
#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;
use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig, SocksUser},
    },
    inbound::{
        AddInboundError, AlterInboundError, InboundManager, RemoveInboundError,
    },
    runtime::{OutboundSummary, RuntimeState},
    traffic::register_identity,
};
#[cfg(feature = "hysteria")]
use crate::{
    config::server_config::Hysteria2Client,
    handler::hysteria2::connection::HysteriaUserStore,
};
#[cfg(feature = "shadowsocks")]
use crate::{
    config::server_config::ShadowsocksUser,
    handler::shadowsocks::{ShadowsocksUserStore, ShadowsocksUserStoreError},
};
#[cfg(feature = "trojan")]
use crate::{
    config::server_config::TrojanUser,
    handler::trojan::{TrojanUserStore, TrojanUserStoreError},
};
use prost::Message;

use super::proto;

mod inbound_adapter;
mod outbound_adapter;
mod user_management;
mod wire;

use wire::*;

#[derive(Clone)]
pub(super) struct HandlerServiceImpl {
    runtime: RuntimeState,
    inbound_manager: std::sync::Arc<InboundManager>,
    outbound_mutation_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
enum AlterInboundOperation {
    Noop,
    AddUser(proto::xray::app::proxyman::command::AddUserOperation),
    RemoveUser(proto::xray::app::proxyman::command::RemoveUserOperation),
}

impl HandlerServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        let inbound_manager = runtime.inbound_manager();
        Self {
            runtime,
            inbound_manager,
            outbound_mutation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn map_alter_inbound_error(error: AlterInboundError<Status>) -> Status {
        match error {
            AlterInboundError::NotFound => Status::unknown("inbound not found"),
            AlterInboundError::Update(error) => error,
            AlterInboundError::State(error) => Status::internal(error),
            AlterInboundError::Restart {
                start_error,
                rollback_error: None,
            } => Status::unknown(format!(
                "failed to restart inbound handler: {start_error}; previous inbound restored"
            )),
            AlterInboundError::Restart {
                start_error,
                rollback_error: Some(rollback_error),
            } => Status::unknown(format!(
                "failed to restart inbound handler: {start_error}; rollback failed: {rollback_error}"
            )),
        }
    }

    fn build_user(&self, email: String) -> proto::xray::common::protocol::User {
        proto::xray::common::protocol::User {
            level: 0,
            email,
            account: None,
        }
    }
}

#[tonic::async_trait]
impl proto::xray::app::proxyman::command::handler_service_server::HandlerService
    for HandlerServiceImpl
{
    async fn add_inbound(
        &self,
        request: Request<proto::xray::app::proxyman::command::AddInboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AddInboundResponse>,
        Status,
    > {
        let request = request.into_inner();
        let inbound = request
            .inbound
            .ok_or_else(|| Status::invalid_argument("inbound is required"))?;
        let inbound = self.parse_add_inbound(inbound)?;
        self.inbound_manager
            .add_started(self.runtime.clone(), inbound)
            .await
            .map_err(|error| match error {
                AddInboundError::AlreadyExists(error) => {
                    Status::unknown(format!("existing tag: {error}"))
                }
                AddInboundError::Start(error) => Status::unknown(format!(
                    "failed to start inbound handler: {error}"
                )),
                AddInboundError::State(error) => Status::internal(error),
            })?;

        Ok(Response::new(
            proto::xray::app::proxyman::command::AddInboundResponse {},
        ))
    }

    async fn remove_inbound(
        &self,
        request: Request<proto::xray::app::proxyman::command::RemoveInboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::RemoveInboundResponse>,
        Status,
    > {
        let request = request.into_inner();
        self.inbound_manager
            .remove_started(&request.tag)
            .await
            .map_err(|error| match error {
                RemoveInboundError::NotFound => Status::unknown("inbound not found"),
            })?;
        Ok(Response::new(
            proto::xray::app::proxyman::command::RemoveInboundResponse {},
        ))
    }

    async fn alter_inbound(
        &self,
        request: Request<proto::xray::app::proxyman::command::AlterInboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AlterInboundResponse>,
        Status,
    > {
        let request = request.into_inner();
        let operation = self.parse_alter_inbound_operation(request.operation)?;
        if request.tag.is_empty() {
            return Err(Status::unknown("inbound not found"));
        }
        if matches!(&operation, AlterInboundOperation::Noop) {
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        #[cfg(feature = "shadowsocks")]
        if self.runtime.shadowsocks_user_store(&request.tag).is_some() {
            let config_operation = operation.clone();
            self.runtime
                .alter_shadowsocks_users(
                    &request.tag,
                    |current| {
                        let mut updated = Self::detached_inbound(current);
                        self.apply_alter_inbound_operation(
                            &mut updated,
                            config_operation,
                        )?;
                        Ok::<ServerConfig, Status>(updated)
                    },
                    |store| {
                        self.apply_shadowsocks_runtime_operation(store, operation)
                    },
                )
                .await
                .map_err(Self::map_alter_inbound_error)?;
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        #[cfg(feature = "hysteria")]
        if self.runtime.hysteria_user_store(&request.tag).is_some() {
            let config_operation = operation.clone();
            self.runtime
                .alter_hysteria_users(
                    &request.tag,
                    |current| {
                        let mut updated = Self::detached_inbound(current);
                        self.apply_alter_inbound_operation(
                            &mut updated,
                            config_operation,
                        )?;
                        Ok::<ServerConfig, Status>(updated)
                    },
                    |store| self.apply_hysteria_runtime_operation(store, operation),
                )
                .await
                .map_err(Self::map_alter_inbound_error)?;
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        #[cfg(feature = "trojan")]
        if self.runtime.trojan_user_store(&request.tag).is_some() {
            let config_operation = operation.clone();
            self.runtime
                .alter_trojan_users(
                    &request.tag,
                    |current| {
                        let mut updated = Self::detached_inbound(current);
                        self.apply_alter_inbound_operation(
                            &mut updated,
                            config_operation,
                        )?;
                        Ok::<ServerConfig, Status>(updated)
                    },
                    |store| self.apply_trojan_runtime_operation(store, operation),
                )
                .await
                .map_err(Self::map_alter_inbound_error)?;
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        #[cfg(feature = "vmess")]
        if self.runtime.vmess_user_store(&request.tag).is_some() {
            let config_operation = operation.clone();
            self.runtime
                .alter_vmess_users(
                    &request.tag,
                    |current| {
                        let mut updated = Self::detached_inbound(current);
                        self.apply_alter_inbound_operation(
                            &mut updated,
                            config_operation,
                        )?;
                        Ok::<ServerConfig, Status>(updated)
                    },
                    |users| self.apply_vmess_runtime_operation(users, operation),
                )
                .await
                .map_err(Self::map_alter_inbound_error)?;
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        #[cfg(feature = "vless")]
        let alter_result = {
            let config_operation = operation.clone();
            self.runtime
                .alter_inbound_users(
                    &request.tag,
                    |current| {
                        let mut updated = Self::detached_inbound(current);
                        self.apply_alter_inbound_operation(
                            &mut updated,
                            config_operation,
                        )?;
                        Ok::<ServerConfig, Status>(updated)
                    },
                    |users| self.apply_vless_runtime_operation(users, operation),
                )
                .await
        };
        #[cfg(not(feature = "vless"))]
        let alter_result = self
            .inbound_manager
            .alter_started(self.runtime.clone(), &request.tag, |current| {
                let mut updated = Self::detached_inbound(current);
                self.apply_alter_inbound_operation(&mut updated, operation)?;
                Ok::<ServerConfig, Status>(updated)
            })
            .await;

        alter_result.map_err(Self::map_alter_inbound_error)?;

        Ok(Response::new(
            proto::xray::app::proxyman::command::AlterInboundResponse {},
        ))
    }

    async fn list_inbounds(
        &self,
        request: Request<proto::xray::app::proxyman::command::ListInboundsRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::ListInboundsResponse>,
        Status,
    > {
        let request = request.into_inner();
        let mut inbounds = Vec::new();
        for inbound in self.runtime.inbounds() {
            let mut config = self.encode_inbound_config(&inbound);
            if request.is_only_tags {
                config.receiver_settings = None;
                config.proxy_settings = None;
            }
            inbounds.push(config);
        }
        Ok(Response::new(
            proto::xray::app::proxyman::command::ListInboundsResponse { inbounds },
        ))
    }

    async fn get_inbound_users(
        &self,
        request: Request<proto::xray::app::proxyman::command::GetInboundUserRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::GetInboundUserResponse>,
        Status,
    > {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;

        let users = self
            .get_user_manager_users(&inbound.protocol)
            .ok_or_else(|| Status::unknown(ERR_PROXY_NOT_USER_MANAGER))?;
        let case_insensitive = Self::shadowsocks_user_manager(&inbound.protocol);
        let users =
            Self::select_user_manager_users(users, &request.email, case_insensitive);

        Ok(Response::new(
            proto::xray::app::proxyman::command::GetInboundUserResponse { users },
        ))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<proto::xray::app::proxyman::command::GetInboundUserRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::GetInboundUsersCountResponse>,
        Status,
    > {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;
        let count = self
            .get_user_manager_identities(&inbound.protocol)
            .ok_or_else(|| Status::unknown(ERR_PROXY_NOT_USER_MANAGER))?
            .len() as i64;
        Ok(Response::new(
            proto::xray::app::proxyman::command::GetInboundUsersCountResponse {
                count,
            },
        ))
    }

    async fn add_outbound(
        &self,
        request: Request<proto::xray::app::proxyman::command::AddOutboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AddOutboundResponse>,
        Status,
    > {
        let _mutation_guard = self.outbound_mutation_lock.lock().await;
        let request = request.into_inner();
        let outbound = request
            .outbound
            .ok_or_else(|| Status::invalid_argument("outbound is required"))?;
        let outbound = self.parse_add_outbound(outbound)?;
        self.runtime.add_outbound(outbound).map_err(|error| {
            Status::already_exists(format!("existing tag: {error}"))
        })?;
        Ok(Response::new(
            proto::xray::app::proxyman::command::AddOutboundResponse {},
        ))
    }

    async fn remove_outbound(
        &self,
        request: Request<proto::xray::app::proxyman::command::RemoveOutboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::RemoveOutboundResponse>,
        Status,
    > {
        let _mutation_guard = self.outbound_mutation_lock.lock().await;
        let request = request.into_inner();
        let Some(_) = self.runtime.remove_outbound(&request.tag) else {
            return Err(Status::not_found("outbound not found"));
        };
        Ok(Response::new(
            proto::xray::app::proxyman::command::RemoveOutboundResponse {},
        ))
    }

    async fn alter_outbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::AlterOutboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AlterOutboundResponse>,
        Status,
    > {
        Err(Status::unimplemented("AlterOutbound is not supported"))
    }

    async fn list_outbounds(
        &self,
        _request: Request<proto::xray::app::proxyman::command::ListOutboundsRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::ListOutboundsResponse>,
        Status,
    > {
        let outbounds = self
            .runtime
            .outbounds()
            .iter()
            .map(|outbound| self.encode_outbound_config(outbound))
            .collect();
        Ok(Response::new(
            proto::xray::app::proxyman::command::ListOutboundsResponse { outbounds },
        ))
    }
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> proto::xray::app::proxyman::command::handler_service_server::HandlerServiceServer<
    HandlerServiceImpl,
>{
    proto::xray::app::proxyman::command::handler_service_server::HandlerServiceServer::new(
        HandlerServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests;
