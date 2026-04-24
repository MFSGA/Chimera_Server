use tonic::{Request, Response, Status};

#[cfg(feature = "trojan")]
use crate::config::server_config::TrojanUser;
use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig, SocksUser},
    },
    runtime::{OutboundSummary, RuntimeState},
};
use prost::Message;

use super::proto;

const TYPE_ADD_USER_OPERATION: &str = "xray.app.proxyman.command.AddUserOperation";
const TYPE_REMOVE_USER_OPERATION: &str =
    "xray.app.proxyman.command.RemoveUserOperation";
const TYPE_ADD_USER_OPERATION_V2RAY: &str =
    "v2ray.core.app.proxyman.command.AddUserOperation";
const TYPE_REMOVE_USER_OPERATION_V2RAY: &str =
    "v2ray.core.app.proxyman.command.RemoveUserOperation";
const ERR_PROXY_NOT_USER_MANAGER: &str =
    "app/proxyman/command: proxy is not a UserManager";
const TYPE_APP_RECEIVER_CONFIG: &str = "xray.app.proxyman.ReceiverConfig";
const TYPE_APP_RECEIVER_CONFIG_V2RAY: &str =
    "v2ray.core.app.proxyman.ReceiverConfig";
const TYPE_PROXY_SOCKS_SERVER_CONFIG: &str = "xray.proxy.socks.ServerConfig";
const TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ServerConfig";
const TYPE_PROXY_FREEDOM_CONFIG: &str = "xray.proxy.freedom.Config";
const TYPE_PROXY_FREEDOM_CONFIG_V2RAY: &str = "v2ray.core.proxy.freedom.Config";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.trojan.Account";

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    password: String,
}

#[derive(Clone, PartialEq, Message)]
struct PortRangePayload {
    #[prost(uint32, tag = "1")]
    from: u32,
    #[prost(uint32, tag = "2")]
    to: u32,
}

#[derive(Clone, PartialEq, Message)]
struct PortListPayload {
    #[prost(message, repeated, tag = "1")]
    range: Vec<PortRangePayload>,
}

#[derive(Clone, PartialEq, Message)]
struct IpOrDomainPayload {
    #[prost(oneof = "ip_or_domain_payload::Address", tags = "1, 2")]
    address: Option<ip_or_domain_payload::Address>,
}

mod ip_or_domain_payload {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ReceiverConfigPayload {
    #[prost(message, optional, tag = "1")]
    port_list: Option<PortListPayload>,
    #[prost(message, optional, tag = "2")]
    listen: Option<IpOrDomainPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct SocksServerConfigPayload {
    #[prost(int32, tag = "1")]
    auth_type: i32,
    #[prost(map = "string, string", tag = "2")]
    accounts: std::collections::HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
struct FreedomConfigPayload {}

#[derive(Clone)]
pub(super) struct HandlerServiceImpl {
    runtime: RuntimeState,
}

enum AlterInboundOperation {
    Noop,
    AddUser(proto::xray::app::proxyman::command::AddUserOperation),
    RemoveUser(proto::xray::app::proxyman::command::RemoveUserOperation),
}

impl HandlerServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }

    fn parse_alter_inbound_operation(
        &self,
        operation: Option<proto::xray::common::serial::TypedMessage>,
    ) -> Result<AlterInboundOperation, Status> {
        let Some(operation) = operation else {
            // Keep compatibility with existing clients that send an empty operation.
            return Ok(AlterInboundOperation::Noop);
        };

        let op_type = operation.r#type.trim_start_matches('.');
        match op_type {
            TYPE_ADD_USER_OPERATION | TYPE_ADD_USER_OPERATION_V2RAY => {
                let decoded =
                    proto::xray::app::proxyman::command::AddUserOperation::decode(
                        operation.value.as_slice(),
                    )
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid AddUserOperation payload: {err}"
                        ))
                    })?;
                Ok(AlterInboundOperation::AddUser(decoded))
            }
            TYPE_REMOVE_USER_OPERATION | TYPE_REMOVE_USER_OPERATION_V2RAY => {
                let decoded = proto::xray::app::proxyman::command::RemoveUserOperation::decode(
                    operation.value.as_slice(),
                )
                .map_err(|err| {
                    Status::invalid_argument(format!("invalid RemoveUserOperation payload: {err}"))
                })?;
                Ok(AlterInboundOperation::RemoveUser(decoded))
            }
            other => Err(Status::invalid_argument(format!(
                "unsupported inbound operation type: {other}"
            ))),
        }
    }

    fn parse_typed_message_type(
        typed_message: &proto::xray::common::serial::TypedMessage,
    ) -> &str {
        typed_message.r#type.trim_start_matches('.')
    }

    fn decode_typed_message<T: Message + Default>(
        &self,
        typed_message: &proto::xray::common::serial::TypedMessage,
        accepted_types: &[&str],
        label: &str,
    ) -> Result<T, Status> {
        let message_type = Self::parse_typed_message_type(typed_message);
        if !accepted_types
            .iter()
            .any(|candidate| *candidate == message_type)
        {
            return Err(Status::invalid_argument(format!(
                "unsupported {label} type: {message_type}"
            )));
        }
        T::decode(typed_message.value.as_slice()).map_err(|err| {
            Status::invalid_argument(format!("invalid {label} payload: {err}"))
        })
    }

    fn parse_address(
        &self,
        value: Option<IpOrDomainPayload>,
    ) -> Result<Address, Status> {
        match value.and_then(|item| item.address) {
            Some(ip_or_domain_payload::Address::Ip(bytes)) => match bytes.as_slice()
            {
                [a, b, c, d] => {
                    Ok(Address::Ipv4(std::net::Ipv4Addr::new(*a, *b, *c, *d)))
                }
                [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => {
                    Ok(Address::Ipv6(std::net::Ipv6Addr::from([
                        *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o,
                        *p,
                    ])))
                }
                _ => {
                    Err(Status::invalid_argument("listen ip must be 4 or 16 bytes"))
                }
            },
            Some(ip_or_domain_payload::Address::Domain(domain)) => {
                if domain.trim().is_empty() {
                    Err(Status::invalid_argument("listen domain is required"))
                } else {
                    Ok(Address::Hostname(domain))
                }
            }
            None => Ok(Address::UNSPECIFIED),
        }
    }

    fn parse_listen_port(
        &self,
        receiver: &ReceiverConfigPayload,
    ) -> Result<u16, Status> {
        let port_list = receiver.port_list.as_ref().ok_or_else(|| {
            Status::invalid_argument("ReceiverConfig.port_list is required")
        })?;
        let range = port_list.range.first().ok_or_else(|| {
            Status::invalid_argument("ReceiverConfig.port_list.range is required")
        })?;
        if range.from == 0 || range.to == 0 {
            return Err(Status::invalid_argument("receiver port must be non-zero"));
        }
        if range.from != range.to {
            return Err(Status::invalid_argument(
                "port ranges are not supported for AddInbound",
            ));
        }
        u16::try_from(range.from)
            .map_err(|_| Status::invalid_argument("receiver port must fit in u16"))
    }

    fn parse_add_inbound(
        &self,
        inbound: proto::xray::core::InboundHandlerConfig,
    ) -> Result<ServerConfig, Status> {
        if inbound.tag.trim().is_empty() {
            return Err(Status::invalid_argument("inbound tag is required"));
        }
        let receiver_settings =
            inbound.receiver_settings.as_ref().ok_or_else(|| {
                Status::invalid_argument("inbound.receiver_settings is required")
            })?;
        let receiver = self.decode_typed_message::<ReceiverConfigPayload>(
            receiver_settings,
            &[TYPE_APP_RECEIVER_CONFIG, TYPE_APP_RECEIVER_CONFIG_V2RAY],
            "receiver settings",
        )?;
        let port = self.parse_listen_port(&receiver)?;
        let address = self.parse_address(receiver.listen)?;

        let proxy_settings = inbound.proxy_settings.as_ref().ok_or_else(|| {
            Status::invalid_argument("inbound.proxy_settings is required")
        })?;
        let socks = self.decode_typed_message::<SocksServerConfigPayload>(
            proxy_settings,
            &[
                TYPE_PROXY_SOCKS_SERVER_CONFIG,
                TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY,
            ],
            "inbound proxy settings",
        )?;

        let accounts = socks
            .accounts
            .into_iter()
            .map(|(username, password)| SocksUser { username, password })
            .collect();

        Ok(ServerConfig {
            tag: inbound.tag,
            bind_location: BindLocation::Address(NetLocation::new(address, port)),
            protocol: ServerProxyConfig::Socks { accounts },
            transport: Transport::Tcp,
            quic_settings: None,
        })
    }

    fn parse_add_outbound(
        &self,
        outbound: proto::xray::core::OutboundHandlerConfig,
    ) -> Result<OutboundSummary, Status> {
        if outbound.tag.trim().is_empty() {
            return Err(Status::invalid_argument("outbound tag is required"));
        }
        let proxy_settings = outbound.proxy_settings.as_ref().ok_or_else(|| {
            Status::invalid_argument("outbound.proxy_settings is required")
        })?;
        let _ = self.decode_typed_message::<FreedomConfigPayload>(
            proxy_settings,
            &[TYPE_PROXY_FREEDOM_CONFIG, TYPE_PROXY_FREEDOM_CONFIG_V2RAY],
            "outbound proxy settings",
        )?;
        Ok(OutboundSummary {
            tag: outbound.tag,
            protocol: "freedom".to_string(),
        })
    }

    #[cfg(feature = "trojan")]
    fn parse_trojan_password(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<String, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for trojan",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        if account_type != TYPE_PROXY_TROJAN_ACCOUNT
            && account_type != TYPE_PROXY_TROJAN_ACCOUNT_V2RAY
        {
            return Err(Status::invalid_argument(format!(
                "unsupported trojan account type: {account_type}"
            )));
        }

        let payload = TrojanAccountPayload::decode(account.value.as_slice())
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid trojan account payload: {err}"
                ))
            })?;
        let password = payload.password.trim();
        if password.is_empty() {
            return Err(Status::invalid_argument(
                "trojan account password is required",
            ));
        }
        Ok(password.to_string())
    }

    fn apply_add_user_to_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        user: &proto::xray::common::protocol::User,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                let password = self.parse_trojan_password(user)?;
                let email = user.email.trim();
                if email.is_empty() {
                    if users.iter().any(|existing| existing.password == password) {
                        return Ok(true);
                    }
                    users.push(TrojanUser {
                        password,
                        email: None,
                    });
                    return Ok(true);
                }

                if let Some(existing) = users
                    .iter_mut()
                    .find(|existing| existing.email.as_deref() == Some(email))
                {
                    existing.password = password;
                } else {
                    users.push(TrojanUser {
                        password,
                        email: Some(email.to_string()),
                    });
                }
                Ok(true)
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
                crate::util::option::OneOrSome::One(target) => {
                    self.apply_add_user_to_protocol(&mut target.protocol, user)
                }
                crate::util::option::OneOrSome::Some(target_list) => {
                    let mut handled = false;
                    for target in target_list.iter_mut() {
                        handled |= self.apply_add_user_to_protocol(
                            &mut target.protocol,
                            user,
                        )?;
                    }
                    Ok(handled)
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.apply_add_user_to_protocol(tls.inner.as_mut(), user)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.apply_add_user_to_protocol(reality.inner.as_mut(), user)
            }
            _ => Ok(false),
        }
    }

    fn apply_add_user_operation(
        &self,
        protocol: &mut ServerProxyConfig,
        operation: proto::xray::app::proxyman::command::AddUserOperation,
    ) -> Result<(), Status> {
        let user = operation.user.ok_or_else(|| {
            Status::invalid_argument("AddUserOperation.user is required")
        })?;
        if self.apply_add_user_to_protocol(protocol, &user)? {
            return Ok(());
        }

        Err(Status::unknown(ERR_PROXY_NOT_USER_MANAGER))
    }

    fn apply_remove_user_from_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        email: &str,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                users.retain(|user| user.email.as_deref() != Some(email));
                Ok(true)
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
                crate::util::option::OneOrSome::One(target) => {
                    self.apply_remove_user_from_protocol(&mut target.protocol, email)
                }
                crate::util::option::OneOrSome::Some(target_list) => {
                    let mut handled = false;
                    for target in target_list.iter_mut() {
                        handled |= self.apply_remove_user_from_protocol(
                            &mut target.protocol,
                            email,
                        )?;
                    }
                    Ok(handled)
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.apply_remove_user_from_protocol(tls.inner.as_mut(), email)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.apply_remove_user_from_protocol(reality.inner.as_mut(), email)
            }
            _ => Ok(false),
        }
    }

    fn apply_remove_user_operation(
        &self,
        protocol: &mut ServerProxyConfig,
        operation: proto::xray::app::proxyman::command::RemoveUserOperation,
    ) -> Result<(), Status> {
        let email = operation.email.trim();
        if email.is_empty() {
            return Err(Status::invalid_argument(
                "RemoveUserOperation.email is required",
            ));
        }

        if self.apply_remove_user_from_protocol(protocol, email)? {
            Ok(())
        } else {
            Err(Status::unknown(ERR_PROXY_NOT_USER_MANAGER))
        }
    }

    fn apply_alter_inbound_operation(
        &self,
        inbound: &mut crate::config::server_config::ServerConfig,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(op) => {
                self.apply_add_user_operation(&mut inbound.protocol, op)
            }
            AlterInboundOperation::RemoveUser(op) => {
                self.apply_remove_user_operation(&mut inbound.protocol, op)
            }
        }
    }

    fn get_user_manager_identities(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<String>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { user_label, .. } => {
                Some(vec![user_label.clone()])
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                Some(users.iter().filter_map(|user| user.email.clone()).collect())
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter_map(|client| client.email.clone())
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => Some(vec![config.uuid.clone()]),
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut identities = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_identities(&target.protocol)
                        {
                            identities.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_identities(&target.protocol)
                            {
                                identities.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(identities)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.get_user_manager_identities(&tls.inner)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_identities(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_identities(inner)
            }
            ServerProxyConfig::Socks { .. } => None,
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
        self.runtime
            .add_inbound(inbound)
            .map_err(Status::already_exists)?;
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
        let Some(_) = self.runtime.remove_inbound(&request.tag) else {
            return Err(Status::not_found("inbound not found"));
        };
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
        let result = self.runtime.with_inbound_mut(&request.tag, |inbound| {
            self.apply_alter_inbound_operation(inbound, operation)
        });

        let Some(result) = result else {
            return Err(Status::not_found("inbound not found"));
        };
        result?;
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
    ) -> Result<
        Response<proto::xray::app::proxyman::command::GetInboundUserResponse>,
        Status,
    > {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;

        let mut users = self
            .get_user_manager_identities(&inbound.protocol)
            .ok_or_else(|| Status::unknown(ERR_PROXY_NOT_USER_MANAGER))?
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
        let request = request.into_inner();
        let outbound = request
            .outbound
            .ok_or_else(|| Status::invalid_argument("outbound is required"))?;
        let outbound = self.parse_add_outbound(outbound)?;
        self.runtime
            .add_outbound(outbound)
            .map_err(Status::already_exists)?;
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
>{
    proto::xray::app::proxyman::command::handler_service_server::HandlerServiceServer::new(
        HandlerServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests {
    use super::proto::xray::app::proxyman::command::handler_service_server::HandlerService;
    use super::*;
    #[cfg(feature = "trojan")]
    use crate::config::server_config::TrojanUser;
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            server_config::{ServerConfig, SocksUser},
        },
        runtime::OutboundSummary,
    };
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tonic::{Code, Request};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        runtime: RuntimeState,
        inbound_tag: String,
        users: Vec<String>,
        outbound_tag: String,
    }

    fn unique_tag(prefix: &str) -> String {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    fn build_fixture() -> Fixture {
        let inbound_tag = unique_tag("inbound");
        let outbound_tag = unique_tag("outbound");

        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1080,
        ));
        let protocol = ServerProxyConfig::Socks {
            accounts: vec![SocksUser {
                username: unique_tag("user-a"),
                password: "pass-a".to_string(),
            }],
        };
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location,
            protocol,
            transport: Transport::Tcp,
            quic_settings: None,
        };

        let outbound = OutboundSummary {
            tag: outbound_tag.clone(),
            protocol: "freedom".to_string(),
        };

        let runtime = RuntimeState::new(vec![inbound], vec![outbound]);
        Fixture {
            runtime,
            inbound_tag,
            users: Vec::new(),
            outbound_tag,
        }
    }

    fn localhost_ip_payload() -> IpOrDomainPayload {
        IpOrDomainPayload {
            address: Some(ip_or_domain_payload::Address::Ip(
                Ipv4Addr::LOCALHOST.octets().to_vec(),
            )),
        }
    }

    fn build_add_inbound_request(
        tag: &str,
        port: u16,
    ) -> proto::xray::app::proxyman::command::AddInboundRequest {
        let mut accounts = std::collections::HashMap::new();
        accounts.insert(unique_tag("user"), "pass".to_string());
        proto::xray::app::proxyman::command::AddInboundRequest {
            inbound: Some(proto::xray::core::InboundHandlerConfig {
                tag: tag.to_string(),
                receiver_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_APP_RECEIVER_CONFIG.to_string(),
                    value: ReceiverConfigPayload {
                        port_list: Some(PortListPayload {
                            range: vec![PortRangePayload {
                                from: port as u32,
                                to: port as u32,
                            }],
                        }),
                        listen: Some(localhost_ip_payload()),
                    }
                    .encode_to_vec(),
                }),
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_SOCKS_SERVER_CONFIG.to_string(),
                    value: SocksServerConfigPayload {
                        auth_type: 1,
                        accounts,
                    }
                    .encode_to_vec(),
                }),
            }),
        }
    }

    fn build_add_outbound_request(
        tag: &str,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        proto::xray::app::proxyman::command::AddOutboundRequest {
            outbound: Some(proto::xray::core::OutboundHandlerConfig {
                tag: tag.to_string(),
                sender_settings: None,
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_FREEDOM_CONFIG.to_string(),
                    value: FreedomConfigPayload {}.encode_to_vec(),
                }),
                expire: 0,
                comment: String::new(),
            }),
        }
    }

    #[tokio::test]
    async fn handler_lists_inbounds() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        let response = service
            .list_inbounds(Request::new(
                proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: false,
                },
            ))
            .await
            .expect("list_inbounds failed")
            .into_inner();
        assert_eq!(response.inbounds.len(), 1);
        assert_eq!(response.inbounds[0].tag, fixture.inbound_tag);
    }

    #[tokio::test]
    async fn handler_lists_outbounds() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        let response = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .expect("list_outbounds failed")
            .into_inner();
        assert_eq!(response.outbounds.len(), 1);
        assert_eq!(response.outbounds[0].tag, fixture.outbound_tag);
    }

    #[tokio::test]
    async fn handler_methods_without_support_return_errors() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        let err = service
            .add_inbound(Request::new(
                proto::xray::app::proxyman::command::AddInboundRequest::default(),
            ))
            .await
            .expect_err("expected add_inbound to validate request");
        assert_eq!(err.code(), Code::InvalidArgument);

        let err = service
            .remove_inbound(Request::new(
                proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: "missing-inbound".to_string(),
                },
            ))
            .await
            .expect_err("expected remove_inbound to report not found");
        assert_eq!(err.code(), Code::NotFound);

        let err = service
            .add_outbound(Request::new(
                proto::xray::app::proxyman::command::AddOutboundRequest::default(),
            ))
            .await
            .expect_err("expected add_outbound to validate request");
        assert_eq!(err.code(), Code::InvalidArgument);

        let err = service
            .remove_outbound(Request::new(
                proto::xray::app::proxyman::command::RemoveOutboundRequest {
                    tag: "missing-outbound".to_string(),
                },
            ))
            .await
            .expect_err("expected remove_outbound to report not found");
        assert_eq!(err.code(), Code::NotFound);

        let err = service
            .alter_outbound(Request::new(
                proto::xray::app::proxyman::command::AlterOutboundRequest::default(),
            ))
            .await
            .expect_err("expected alter_outbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect_err("expected socks inbound to not be a user manager");
        assert_eq!(err.code(), Code::Unknown);
        assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);

        let err = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect_err("expected socks inbound count to not be a user manager");
        assert_eq!(err.code(), Code::Unknown);
        assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);
    }

    #[tokio::test]
    async fn handler_adds_inbound_and_outbound() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let added_inbound = unique_tag("added-inbound");
        let added_outbound = unique_tag("added-outbound");

        service
            .add_inbound(Request::new(build_add_inbound_request(
                &added_inbound,
                2081,
            )))
            .await
            .expect("add_inbound should succeed");
        assert!(fixture.runtime.inbound_by_tag(&added_inbound).is_some());

        let inbounds = service
            .list_inbounds(Request::new(
                proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: true,
                },
            ))
            .await
            .expect("list_inbounds after add failed")
            .into_inner();
        assert!(
            inbounds
                .inbounds
                .iter()
                .any(|item| item.tag == added_inbound)
        );

        service
            .add_outbound(Request::new(build_add_outbound_request(&added_outbound)))
            .await
            .expect("add_outbound should succeed");

        let outbounds = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .expect("list_outbounds after add failed")
            .into_inner();
        assert!(
            outbounds
                .outbounds
                .iter()
                .any(|item| item.tag == added_outbound)
        );
    }

    #[tokio::test]
    async fn handler_removes_inbound_and_outbound() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        service
            .remove_inbound(Request::new(
                proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: fixture.inbound_tag.clone(),
                },
            ))
            .await
            .expect("remove_inbound failed");
        assert!(
            fixture
                .runtime
                .inbound_by_tag(&fixture.inbound_tag)
                .is_none()
        );
        let inbounds = service
            .list_inbounds(Request::new(
                proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: true,
                },
            ))
            .await
            .expect("list_inbounds after remove failed")
            .into_inner();
        assert!(inbounds.inbounds.is_empty());

        service
            .remove_outbound(Request::new(
                proto::xray::app::proxyman::command::RemoveOutboundRequest {
                    tag: fixture.outbound_tag.clone(),
                },
            ))
            .await
            .expect("remove_outbound failed");
        let outbounds = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .expect("list_outbounds after remove failed")
            .into_inner();
        assert!(outbounds.outbounds.is_empty());
    }

    #[tokio::test]
    async fn handler_alter_inbound_rejects_non_user_manager_inbound() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: unique_tag("email"),
                account: None,
            }),
        };

        let err = service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: fixture.inbound_tag,
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_ADD_USER_OPERATION.to_string(),
                        value: add_operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect_err("expected non-user-manager inbound to reject alter");
        assert_eq!(err.code(), Code::Unknown);
        assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_trojan_users() {
        let inbound_tag = unique_tag("trojan-inbound");
        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1091,
        ));
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location,
            protocol: ServerProxyConfig::Trojan {
                users: vec![TrojanUser {
                    password: "initial-password".to_string(),
                    email: Some("initial-user".to_string()),
                }],
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);

        let email = unique_tag("trojan-user");
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: email.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                    value: TrojanAccountPayload {
                        password: "added-password".to_string(),
                    }
                    .encode_to_vec(),
                }),
            }),
        };
        service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: inbound_tag.clone(),
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_ADD_USER_OPERATION.to_string(),
                        value: add_operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect("trojan add user should succeed");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("trojan get users after add failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        assert!(users_after_add.iter().any(|candidate| candidate == &email));

        let count_after_add = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("trojan get users count after add failed")
            .into_inner();
        assert_eq!(count_after_add.count, 2);

        let remove_operation =
            proto::xray::app::proxyman::command::RemoveUserOperation {
                email: email.clone(),
            };
        service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: inbound_tag.clone(),
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                        value: remove_operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect("trojan remove user should succeed");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .expect("trojan get users after remove failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        assert!(
            !users_after_remove
                .iter()
                .any(|candidate| candidate == &email)
        );
    }

    #[tokio::test]
    async fn handler_alter_inbound_rejects_unknown_operation_type() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);

        let err = service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: fixture.inbound_tag,
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: "xray.app.proxyman.command.UnknownOperation"
                            .to_string(),
                        value: vec![1, 2, 3],
                    }),
                },
            ))
            .await
            .expect_err("expected invalid argument for unknown operation");
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}
