use tonic::{Request, Response, Status};

#[cfg(feature = "trojan")]
use crate::config::server_config::TrojanUser;
use crate::{
    config::server_config::{ServerProxyConfig, SocksUser},
    runtime::RuntimeState,
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
const TYPE_PROXY_SOCKS_ACCOUNT: &str = "xray.proxy.socks.Account";
const TYPE_PROXY_SOCKS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.socks.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.trojan.Account";

#[derive(Clone, PartialEq, Message)]
struct SocksAccountPayload {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    password: String,
}

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

    fn parse_socks_credentials(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<(String, String), Status> {
        let fallback_username = user.email.trim().to_string();
        let Some(account) = user.account.as_ref() else {
            if fallback_username.is_empty() {
                return Err(Status::invalid_argument(
                    "AddUserOperation.user.email is required when account is missing",
                ));
            }
            return Ok((fallback_username, String::new()));
        };

        let account_type = Self::parse_typed_message_type(account);
        if account_type != TYPE_PROXY_SOCKS_ACCOUNT
            && account_type != TYPE_PROXY_SOCKS_ACCOUNT_V2RAY
        {
            return Err(Status::invalid_argument(format!(
                "unsupported socks account type: {account_type}"
            )));
        }

        let payload = SocksAccountPayload::decode(account.value.as_slice())
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid socks account payload: {err}"
                ))
            })?;
        let username = if payload.username.trim().is_empty() {
            fallback_username
        } else {
            payload.username.trim().to_string()
        };
        if username.is_empty() {
            return Err(Status::invalid_argument(
                "AddUserOperation.user.email or socks account username is required",
            ));
        }

        Ok((username, payload.password))
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
            ServerProxyConfig::Socks { accounts } => {
                let (username, password) = self.parse_socks_credentials(user)?;
                if let Some(existing) = accounts
                    .iter_mut()
                    .find(|account| account.username == username)
                {
                    existing.password = password;
                } else {
                    accounts.push(SocksUser { username, password });
                }
                Ok(true)
            }
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

        Err(Status::failed_precondition(
            "proxy is not a UserManager for AddUserOperation",
        ))
    }

    fn apply_remove_user_from_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        email: &str,
    ) -> Result<bool, Status> {
        match protocol {
            ServerProxyConfig::Socks { accounts } => {
                accounts.retain(|account| account.username != email);
                Ok(true)
            }
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
            Err(Status::failed_precondition(
                "proxy is not a UserManager for RemoveUserOperation",
            ))
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
                            identities
                                .extend(self.collect_identities(&target.protocol));
                        }
                    }
                }
                identities
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => self.collect_identities(&tls.inner),
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.collect_identities(&reality.inner)
            }
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
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AddInboundResponse>,
        Status,
    > {
        Err(Status::unimplemented("AddInbound is not supported"))
    }

    async fn remove_inbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::RemoveInboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::RemoveInboundResponse>,
        Status,
    > {
        Err(Status::unimplemented("RemoveInbound is not supported"))
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
    ) -> Result<
        Response<proto::xray::app::proxyman::command::GetInboundUsersCountResponse>,
        Status,
    > {
        let request = request.into_inner();
        let inbound = self
            .runtime
            .inbound_by_tag(&request.tag)
            .ok_or_else(|| Status::not_found("inbound not found"))?;
        let count = self.collect_identities(&inbound.protocol).len() as i64;
        Ok(Response::new(
            proto::xray::app::proxyman::command::GetInboundUsersCountResponse {
                count,
            },
        ))
    }

    async fn add_outbound(
        &self,
        _request: Request<proto::xray::app::proxyman::command::AddOutboundRequest>,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::AddOutboundResponse>,
        Status,
    > {
        Err(Status::unimplemented("AddOutbound is not supported"))
    }

    async fn remove_outbound(
        &self,
        _request: Request<
            proto::xray::app::proxyman::command::RemoveOutboundRequest,
        >,
    ) -> Result<
        Response<proto::xray::app::proxyman::command::RemoveOutboundResponse>,
        Status,
    > {
        Err(Status::unimplemented("RemoveOutbound is not supported"))
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
        let user_a = unique_tag("user-a");
        let user_b = unique_tag("user-b");
        let outbound_tag = unique_tag("outbound");

        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1080,
        ));
        let protocol = ServerProxyConfig::Socks {
            accounts: vec![
                SocksUser {
                    username: user_a.clone(),
                    password: "pass-a".to_string(),
                },
                SocksUser {
                    username: user_b.clone(),
                    password: "pass-b".to_string(),
                },
            ],
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
            users: vec![user_a, user_b],
            outbound_tag,
        }
    }

    #[tokio::test]
    async fn handler_lists_inbounds_and_users() {
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

        let response = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("get_inbound_users failed")
            .into_inner();
        let mut emails = response
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        emails.sort();
        let mut expected = fixture.users.clone();
        expected.sort();
        assert_eq!(emails, expected);

        let response = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: fixture.users[0].clone(),
                },
            ))
            .await
            .expect("get_inbound_users filtered failed")
            .into_inner();
        assert_eq!(response.users.len(), 1);
        assert_eq!(response.users[0].email, fixture.users[0]);
    }

    #[tokio::test]
    async fn handler_counts_users_and_outbounds() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        let response = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("get_inbound_users_count failed")
            .into_inner();
        assert_eq!(response.count, fixture.users.len() as i64);

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
    async fn handler_unimplemented_methods_return_errors() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);

        let err = service
            .add_inbound(Request::new(
                proto::xray::app::proxyman::command::AddInboundRequest::default(),
            ))
            .await
            .expect_err("expected add_inbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .remove_inbound(Request::new(
                proto::xray::app::proxyman::command::RemoveInboundRequest::default(),
            ))
            .await
            .expect_err("expected remove_inbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .add_outbound(Request::new(
                proto::xray::app::proxyman::command::AddOutboundRequest::default(),
            ))
            .await
            .expect_err("expected add_outbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .remove_outbound(Request::new(
                proto::xray::app::proxyman::command::RemoveOutboundRequest::default(
                ),
            ))
            .await
            .expect_err("expected remove_outbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .alter_outbound(Request::new(
                proto::xray::app::proxyman::command::AlterOutboundRequest::default(),
            ))
            .await
            .expect_err("expected alter_outbound to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_socks_users() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let user = unique_tag("added-user");

        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: user.clone(),
                account: None,
            }),
        };
        let add_request = proto::xray::app::proxyman::command::AlterInboundRequest {
            tag: fixture.inbound_tag.clone(),
            operation: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_ADD_USER_OPERATION.to_string(),
                value: add_operation.encode_to_vec(),
            }),
        };
        service
            .alter_inbound(Request::new(add_request))
            .await
            .expect("alter_inbound add user failed");

        let users = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("get_inbound_users after add failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        assert!(users.iter().any(|email| email == &user));

        let remove_operation =
            proto::xray::app::proxyman::command::RemoveUserOperation {
                email: user.clone(),
            };
        let remove_request =
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: fixture.inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            };
        service
            .alter_inbound(Request::new(remove_request))
            .await
            .expect("alter_inbound remove user failed");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("get_inbound_users after remove failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        assert!(!users_after_remove.iter().any(|email| email == &user));
    }

    #[tokio::test]
    async fn handler_alter_inbound_updates_socks_password_from_account_payload() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let username = fixture.users[0].clone();
        let new_password = unique_tag("new-password");
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: unique_tag("email"),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
                    value: SocksAccountPayload {
                        username: username.clone(),
                        password: new_password.clone(),
                    }
                    .encode_to_vec(),
                }),
            }),
        };
        service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: fixture.inbound_tag.clone(),
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_ADD_USER_OPERATION.to_string(),
                        value: add_operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect("alter_inbound update socks password failed");

        let inbound = fixture
            .runtime
            .inbound_by_tag(&fixture.inbound_tag)
            .expect("inbound should exist");
        match inbound.protocol {
            ServerProxyConfig::Socks { accounts } => {
                let updated = accounts
                    .into_iter()
                    .find(|account| account.username == username)
                    .expect("updated socks account should exist");
                assert_eq!(updated.password, new_password);
            }
            other => panic!("unexpected protocol after update: {other}"),
        }
    }

    #[tokio::test]
    async fn handler_alter_inbound_rejects_invalid_socks_account_type() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: unique_tag("user"),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: "xray.proxy.vless.Account".to_string(),
                    value: vec![1, 2, 3],
                }),
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
            .expect_err(
                "expected invalid argument for unsupported socks account type",
            );
        assert_eq!(err.code(), Code::InvalidArgument);
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
