use tonic::{Request, Response, Status};

use crate::{config::server_config::ServerProxyConfig, runtime::RuntimeState};

use super::proto;

#[derive(Clone)]
pub(super) struct HandlerServiceImpl {
    runtime: RuntimeState,
}

impl HandlerServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }

    fn collect_identities(&self, protocol: &ServerProxyConfig) -> Vec<String> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { user_label, .. } => vec![user_label.clone()],
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                users.iter().filter_map(|user| user.email.clone()).collect()
            }
            ServerProxyConfig::Socks { accounts } => accounts
                .iter()
                .map(|account| account.username.clone())
                .collect(),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => config
                .clients
                .iter()
                .filter_map(|client| client.email.clone())
                .collect(),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => vec![config.uuid.clone()],
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut identities = Vec::new();
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        identities.extend(self.collect_identities(&target.protocol));
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            identities.extend(self.collect_identities(&target.protocol));
                        }
                    }
                }
                identities
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => self.collect_identities(&tls.inner),
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => self.collect_identities(&reality.inner),
            ServerProxyConfig::Xhttp { .. } => Vec::new(),
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
        _request: Request<proto::xray::app::proxyman::command::AddInboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::AddInboundResponse>, Status> {
        Err(Status::unimplemented("AddInbound is not supported"))
    }

    async fn remove_inbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::RemoveInboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::RemoveInboundResponse>, Status> {
        Err(Status::unimplemented("RemoveInbound is not supported"))
    }

    async fn alter_inbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::AlterInboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::AlterInboundResponse>, Status> {
        Err(Status::unimplemented("AlterInbound is not supported"))
    }

    async fn list_inbounds(
        &self,
        request: Request<proto::xray::app::proxyman::command::ListInboundsRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::ListInboundsResponse>, Status> {
        let request = request.into_inner();
        let mut inbounds = Vec::new();
        for inbound in self.runtime.inbounds() {
            let mut config = proto::xray::core::InboundHandlerConfig {
                tag: inbound.tag.clone(),
                receiver_settings: None,
                proxy_settings: None,
            };
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
    ) -> Result<Response<proto::xray::app::proxyman::command::GetInboundUserResponse>, Status> {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;

        let mut users = self
            .collect_identities(&inbound.protocol)
            .into_iter()
            .map(|email| self.build_user(email))
            .collect::<Vec<_>>();

        if !request.email.is_empty() {
            users.retain(|user| user.email == request.email);
        }

        Ok(Response::new(
            proto::xray::app::proxyman::command::GetInboundUserResponse { users },
        ))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<proto::xray::app::proxyman::command::GetInboundUserRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::GetInboundUsersCountResponse>, Status>
    {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;
        let count = self.collect_identities(&inbound.protocol).len() as i64;
        Ok(Response::new(
            proto::xray::app::proxyman::command::GetInboundUsersCountResponse { count },
        ))
    }

    async fn add_outbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::AddOutboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::AddOutboundResponse>, Status> {
        Err(Status::unimplemented("AddOutbound is not supported"))
    }

    async fn remove_outbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::RemoveOutboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::RemoveOutboundResponse>, Status> {
        Err(Status::unimplemented("RemoveOutbound is not supported"))
    }

    async fn alter_outbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::AlterOutboundRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::AlterOutboundResponse>, Status> {
        Err(Status::unimplemented("AlterOutbound is not supported"))
    }

    async fn list_outbounds(
        &self,
        _request: Request<proto::xray::app::proxyman::command::ListOutboundsRequest>,
    ) -> Result<Response<proto::xray::app::proxyman::command::ListOutboundsResponse>, Status> {
        let outbounds = self
            .runtime
            .outbounds()
            .iter()
            .map(|outbound| proto::xray::core::OutboundHandlerConfig {
                tag: outbound.tag.clone(),
                sender_settings: None,
                proxy_settings: None,
                expire: 0,
                comment: String::new(),
            })
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
> {
    proto::xray::app::proxyman::command::handler_service_server::HandlerServiceServer::new(
        HandlerServiceImpl::new(runtime),
    )
}
