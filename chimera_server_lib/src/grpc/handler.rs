use tonic::{Request, Response, Status};

#[cfg(feature = "hysteria")]
use crate::config::server_config::Hysteria2Client;
#[cfg(feature = "reality")]
use crate::config::server_config::RealityTransportConfig;
#[cfg(feature = "tls")]
use crate::config::server_config::TlsServerConfig;
#[cfg(feature = "trojan")]
use crate::config::server_config::TrojanUser;
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
    beginning::start_servers,
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig, SocksUser},
    },
    runtime::{OutboundSummary, RuntimeState},
    traffic::register_identity,
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
const TYPE_PROXY_DOKODEMO_CONFIG: &str = "xray.proxy.dokodemo.Config";
#[cfg(feature = "hysteria")]
const TYPE_PROXY_HYSTERIA_ACCOUNT: &str = "xray.proxy.hysteria.account.Account";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_INBOUND_CONFIG: &str = "xray.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.vless.Account";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_INBOUND_CONFIG: &str = "xray.proxy.vmess.inbound.Config";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vmess.inbound.Config";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_ACCOUNT: &str = "xray.proxy.vmess.Account";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.vmess.Account";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_ACCOUNT: &str = "xray.proxy.shadowsocks.Account";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.shadowsocks.Account";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT: &str =
    "xray.proxy.shadowsocks_2022.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG: &str = "xray.proxy.trojan.ServerConfig";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ServerConfig";
const TYPE_PROXY_FREEDOM_CONFIG: &str = "xray.proxy.freedom.Config";
const TYPE_PROXY_FREEDOM_CONFIG_V2RAY: &str = "v2ray.core.proxy.freedom.Config";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG: &str = "xray.proxy.socks.ClientConfig";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ClientConfig";
const TYPE_PROXY_BLACKHOLE_CONFIG: &str = "xray.proxy.blackhole.Config";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.trojan.Account";
#[cfg(feature = "ws")]
const TYPE_TRANSPORT_WEBSOCKET_CONFIG: &str =
    "xray.transport.internet.websocket.Config";
#[cfg(feature = "ws")]
const TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.websocket.Config";
#[cfg(feature = "tls")]
const TYPE_TRANSPORT_TLS_CONFIG: &str = "xray.transport.internet.tls.Config";
#[cfg(feature = "tls")]
const TYPE_TRANSPORT_TLS_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.tls.Config";
#[cfg(feature = "reality")]
const TYPE_TRANSPORT_REALITY_CONFIG: &str = "xray.transport.internet.reality.Config";

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    password: String,
}

#[cfg(feature = "hysteria")]
#[derive(Clone, PartialEq, Message)]
struct HysteriaAccountPayload {
    #[prost(string, tag = "1")]
    auth: String,
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
    #[prost(message, optional, tag = "3")]
    stream_settings: Option<StreamConfigPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct SocksServerConfigPayload {
    #[prost(int32, tag = "1")]
    auth_type: i32,
    #[prost(map = "string, string", tag = "2")]
    accounts: std::collections::HashMap<String, String>,
    #[prost(message, optional, tag = "3")]
    address: Option<IpOrDomainPayload>,
    #[prost(bool, tag = "4")]
    udp_enabled: bool,
    #[prost(uint32, tag = "6")]
    user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
struct DokodemoConfigPayload {
    #[prost(message, optional, tag = "1")]
    address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    port: u32,
    #[prost(map = "string, string", tag = "3")]
    port_map: std::collections::HashMap<String, String>,
    #[prost(enumeration = "proto::xray::common::net::Network", repeated, tag = "7")]
    networks: Vec<i32>,
    #[prost(bool, tag = "5")]
    follow_redirect: bool,
    #[prost(uint32, tag = "6")]
    user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
struct FreedomConfigPayload {}

#[derive(Clone, PartialEq, Message)]
struct SocksClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    server: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct SocksServerEndpointPayload {
    #[prost(message, optional, tag = "1")]
    address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    port: u32,
    #[prost(message, optional, tag = "3")]
    user: Option<proto::xray::common::protocol::User>,
}

#[derive(Clone, PartialEq, Message)]
struct BlackholeConfigPayload {}

#[derive(Clone, PartialEq, Message)]
struct StreamConfigPayload {
    #[prost(string, tag = "5")]
    protocol_name: String,
    #[prost(message, repeated, tag = "2")]
    transport_settings: Vec<TransportConfigPayload>,
    #[prost(string, tag = "3")]
    security_type: String,
    #[prost(message, repeated, tag = "4")]
    security_settings: Vec<proto::xray::common::serial::TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
struct TransportConfigPayload {
    #[prost(message, optional, tag = "2")]
    settings: Option<proto::xray::common::serial::TypedMessage>,
    #[prost(string, tag = "3")]
    protocol_name: String,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessInboundConfigPayload {
    #[prost(message, repeated, tag = "1")]
    clients: Vec<proto::xray::common::protocol::User>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessAccountPayload {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    flow: String,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
struct VmessInboundConfigPayload {
    #[prost(message, repeated, tag = "1")]
    users: Vec<proto::xray::common::protocol::User>,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
struct VmessSecurityConfigPayload {
    #[prost(int32, tag = "1")]
    r#type: i32,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
struct VmessAccountPayload {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(message, optional, tag = "3")]
    security_settings: Option<VmessSecurityConfigPayload>,
    #[prost(string, tag = "4")]
    tests_enabled: String,
}

#[cfg(feature = "shadowsocks")]
#[derive(Clone, PartialEq, Message)]
struct ShadowsocksAccountPayload {
    #[prost(string, tag = "1")]
    password: String,
    #[prost(int32, tag = "2")]
    cipher_type: i32,
    #[prost(bool, tag = "3")]
    iv_check: bool,
}

#[cfg(feature = "shadowsocks")]
#[derive(Clone, PartialEq, Message)]
struct Shadowsocks2022AccountPayload {
    #[prost(string, tag = "1")]
    key: String,
}

#[cfg(feature = "vless")]
fn validate_vless_flow(flow: &str) -> Result<(), Status> {
    match flow {
        "" | "xtls-rprx-vision" => Ok(()),
        unsupported => Err(Status::invalid_argument(format!(
            "vless clients.flow doesn't support {unsupported}"
        ))),
    }
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanServerConfigPayload {
    #[prost(message, repeated, tag = "1")]
    users: Vec<proto::xray::common::protocol::User>,
    #[prost(message, repeated, tag = "2")]
    fallbacks: Vec<TrojanFallbackPayload>,
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanFallbackPayload {
    #[prost(string, tag = "5")]
    dest: String,
}

#[cfg(feature = "ws")]
#[derive(Clone, PartialEq, Message)]
struct WebsocketConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(map = "string, string", tag = "3")]
    header: std::collections::HashMap<String, String>,
    #[prost(bool, tag = "4")]
    accept_proxy_protocol: bool,
    #[prost(uint32, tag = "6")]
    heartbeat_period: u32,
}

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
struct TlsConfigPayload {
    #[prost(message, repeated, tag = "2")]
    certificate: Vec<TlsCertificatePayload>,
    #[prost(string, repeated, tag = "4")]
    next_protocol: Vec<String>,
}

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
struct TlsCertificatePayload {
    #[prost(bytes = "vec", tag = "1")]
    certificate: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    key: Vec<u8>,
    #[prost(string, tag = "5")]
    certificate_path: String,
    #[prost(string, tag = "6")]
    key_path: String,
}

#[cfg(feature = "reality")]
#[derive(Clone, PartialEq, Message)]
struct RealityConfigPayload {
    #[prost(string, tag = "2")]
    dest: String,
    #[prost(string, repeated, tag = "5")]
    server_names: Vec<String>,
    #[prost(bytes = "vec", tag = "6")]
    private_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    min_client_ver: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    max_client_ver: Vec<u8>,
    #[prost(uint64, tag = "9")]
    max_time_diff: u64,
    #[prost(bytes = "vec", repeated, tag = "10")]
    short_ids: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub(super) struct HandlerServiceImpl {
    runtime: RuntimeState,
    mutation_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

enum AlterInboundOperation {
    Noop,
    AddUser(proto::xray::app::proxyman::command::AddUserOperation),
    RemoveUser(proto::xray::app::proxyman::command::RemoveUserOperation),
}

impl HandlerServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self {
            runtime,
            mutation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
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
        if !accepted_types.contains(&message_type) {
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
        let mut protocol = self.parse_add_inbound_protocol(proxy_settings)?;
        if let Some(stream_settings) = receiver.stream_settings {
            protocol =
                self.apply_add_inbound_stream_settings(protocol, stream_settings)?;
        }

        Ok(ServerConfig {
            tag: inbound.tag,
            bind_location: BindLocation::Address(NetLocation::new(address, port)),
            protocol,
            transport: Transport::Tcp,
            quic_settings: None,
        })
    }

    fn parse_add_inbound_protocol(
        &self,
        proxy_settings: &proto::xray::common::serial::TypedMessage,
    ) -> Result<ServerProxyConfig, Status> {
        match Self::parse_typed_message_type(proxy_settings) {
            TYPE_PROXY_SOCKS_SERVER_CONFIG
            | TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY => {
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
                    .collect::<Vec<_>>();
                let accounts =
                    crate::config::server_config::SocksUserStore::with_auth_required(
                        accounts,
                        socks.auth_type == 1,
                    );
                let udp_response_ip = match socks.address {
                    Some(address) => {
                        Some(self.parse_address(Some(address))?.to_string())
                    }
                    None => None,
                };

                Ok(ServerProxyConfig::Socks {
                    accounts,
                    udp_enabled: socks.udp_enabled,
                    udp_response_ip,
                    user_level: socks.user_level,
                })
            }
            #[cfg(feature = "vless")]
            TYPE_PROXY_VLESS_INBOUND_CONFIG
            | TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VlessInboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VLESS_INBOUND_CONFIG,
                            TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_vless_inbound_config(config)
            }
            #[cfg(feature = "vmess")]
            TYPE_PROXY_VMESS_INBOUND_CONFIG
            | TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VmessInboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VMESS_INBOUND_CONFIG,
                            TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_vmess_inbound_config(config)
            }
            #[cfg(feature = "trojan")]
            TYPE_PROXY_TROJAN_SERVER_CONFIG
            | TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<TrojanServerConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_TROJAN_SERVER_CONFIG,
                            TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_trojan_inbound_config(config)
            }
            other => Err(Status::invalid_argument(format!(
                "unsupported inbound proxy settings type: {other}"
            ))),
        }
    }

    #[cfg(feature = "vless")]
    fn parse_vless_inbound_config(
        &self,
        config: VlessInboundConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        if config.clients.is_empty() {
            return Err(Status::invalid_argument(
                "vless AddInbound requires at least one client",
            ));
        }
        let users = config
            .clients
            .iter()
            .map(|client| self.parse_vless_user(client))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ServerProxyConfig::Vless {
            users,
            fallbacks: Vec::new(),
        })
    }

    #[cfg(feature = "vless")]
    fn parse_vless_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<VlessUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument("vless client account is required")
        })?;
        let account = self.decode_typed_message::<VlessAccountPayload>(
            account,
            &[TYPE_PROXY_VLESS_ACCOUNT, TYPE_PROXY_VLESS_ACCOUNT_V2RAY],
            "vless account",
        )?;
        let user_id = account.id.trim();
        if user_id.is_empty() {
            return Err(Status::invalid_argument("vless client id is required"));
        }
        validate_vless_flow(&account.flow)?;
        Ok(VlessUser {
            user_id: user_id.to_string(),
            user_label: if user.email.trim().is_empty() {
                user_id.to_string()
            } else {
                user.email.clone()
            },
            flow: account.flow,
        })
    }

    #[cfg(feature = "vmess")]
    fn parse_vmess_inbound_config(
        &self,
        config: VmessInboundConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        if config.users.is_empty() {
            return Err(Status::invalid_argument(
                "vmess AddInbound requires at least one user",
            ));
        }
        let users = config
            .users
            .iter()
            .map(|user| self.parse_vmess_user(user))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ServerProxyConfig::Vmess { users })
    }

    #[cfg(feature = "vmess")]
    fn parse_vmess_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<VmessUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument("vmess client account is required")
        })?;
        let account = self.decode_typed_message::<VmessAccountPayload>(
            account,
            &[TYPE_PROXY_VMESS_ACCOUNT, TYPE_PROXY_VMESS_ACCOUNT_V2RAY],
            "vmess account",
        )?;
        let user_id = normalize_vmess_user_id(&account.id)
            .map_err(Status::invalid_argument)?;
        let cipher = match account
            .security_settings
            .as_ref()
            .map(|security| security.r#type)
            .unwrap_or(2)
        {
            3 => "aes-128-gcm",
            4 => "chacha20-poly1305",
            _ => "auto",
        }
        .to_string();
        Ok(VmessUser {
            user_label: if user.email.trim().is_empty() {
                user_id.clone()
            } else {
                user.email.clone()
            },
            user_id,
            cipher,
        })
    }

    #[cfg(feature = "shadowsocks")]
    fn parse_shadowsocks_user(
        &self,
        protocol: &ServerProxyConfig,
        user: &proto::xray::common::protocol::User,
    ) -> Result<crate::config::server_config::ShadowsocksUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for shadowsocks",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        let (method, password) = match protocol {
            ServerProxyConfig::Shadowsocks { users, identity } => {
                if let Some(identity) = identity {
                    if account_type != TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT {
                        return Err(Status::invalid_argument(
                            "shadowsocks 2022 inbound requires a shadowsocks_2022 account",
                        ));
                    }
                    let payload = Shadowsocks2022AccountPayload::decode(
                        account.value.as_slice(),
                    )
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid shadowsocks 2022 account payload: {err}"
                        ))
                    })?;
                    (identity.method.clone(), payload.key)
                } else {
                    if account_type != TYPE_PROXY_SHADOWSOCKS_ACCOUNT
                        && account_type != TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY
                    {
                        return Err(Status::invalid_argument(
                            "legacy shadowsocks inbound requires a shadowsocks account",
                        ));
                    }
                    let payload =
                        ShadowsocksAccountPayload::decode(account.value.as_slice())
                            .map_err(|err| {
                                Status::invalid_argument(format!(
                                    "invalid shadowsocks account payload: {err}"
                                ))
                            })?;
                    let method = users
                        .first()
                        .map(|user| user.method.clone())
                        .filter(|method| !method.is_empty())
                        .ok_or_else(|| {
                            Status::failed_precondition(
                                "legacy shadowsocks inbound has no cipher method",
                            )
                        })?;
                    (method, payload.password)
                }
            }
            _ => {
                return Err(Status::invalid_argument(
                    "shadowsocks account used with a non-shadowsocks inbound",
                ));
            }
        };

        let parsed = crate::config::server_config::ShadowsocksUser {
            method,
            password,
            email: user.email.clone(),
        };
        crate::handler::shadowsocks::validate_user(&parsed).map_err(|err| {
            Status::invalid_argument(format!("invalid shadowsocks user: {err}"))
        })?;
        Ok(parsed)
    }

    #[cfg(feature = "shadowsocks")]
    fn shadowsocks_cipher_type(method: &str) -> Result<i32, Status> {
        match method {
            "aes-128-gcm" => Ok(5),
            "aes-256-gcm" => Ok(6),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(7),
            "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Ok(8),
            other => Err(Status::failed_precondition(format!(
                "unsupported legacy shadowsocks cipher {other}"
            ))),
        }
    }

    #[cfg(feature = "trojan")]
    fn parse_trojan_inbound_config(
        &self,
        config: TrojanServerConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        let mut users = Vec::with_capacity(config.users.len());
        for user in &config.users {
            let password = self.parse_trojan_password(user)?;
            users.push(TrojanUser {
                password,
                email: (!user.email.trim().is_empty()).then(|| user.email.clone()),
            });
        }

        let mut fallbacks = Vec::with_capacity(config.fallbacks.len());
        for fallback in config.fallbacks {
            let dest = fallback.dest.trim();
            if dest.is_empty() {
                return Err(Status::invalid_argument(
                    "trojan fallback dest cannot be empty",
                ));
            }
            if !dest.contains(':') {
                return Err(Status::invalid_argument(
                    "trojan fallback dest must be host:port",
                ));
            }
            let dest = NetLocation::from_str(dest, None).map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid trojan fallback dest {dest}: {err}"
                ))
            })?;
            fallbacks.push(crate::config::server_config::TrojanFallback {
                name: String::new(),
                alpn: String::new(),
                path: String::new(),
                dest,
                xver: 0,
            });
        }

        Ok(ServerProxyConfig::Trojan { users, fallbacks })
    }

    fn apply_add_inbound_stream_settings(
        &self,
        mut protocol: ServerProxyConfig,
        stream_settings: StreamConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        let network = stream_settings.protocol_name.trim().to_ascii_lowercase();
        match network.as_str() {
            "" | "tcp" => {}
            #[cfg(feature = "ws")]
            "ws" | "websocket" => {
                let transport = stream_settings
                    .transport_settings
                    .iter()
                    .find_map(|item| {
                        let name = item.protocol_name.trim().to_ascii_lowercase();
                        (name == "ws" || name == "websocket")
                            .then_some(item.settings.as_ref())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "websocket transport settings are required",
                        )
                    })?;
                let websocket = self
                    .decode_typed_message::<WebsocketConfigPayload>(
                        transport,
                        &[
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY,
                        ],
                        "websocket transport settings",
                    )?;
                let matching_headers = (!websocket.host.is_empty()).then(|| {
                    std::collections::HashMap::from([(
                        "host".to_string(),
                        websocket.host.clone(),
                    )])
                });
                protocol = ServerProxyConfig::Websocket {
                    targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                        matching_path: Some(if websocket.path.is_empty() {
                            "/".to_string()
                        } else if websocket.path.starts_with('/') {
                            websocket.path
                        } else {
                            format!("/{}", websocket.path)
                        }),
                        matching_headers,
                        xray_mismatch_404: true,
                        trusted_x_forwarded_for: Vec::new(),
                        accept_proxy_protocol: websocket.accept_proxy_protocol,
                        heartbeat_period: websocket.heartbeat_period,
                        protocol,
                    })),
                };
            }
            "xhttp" => {
                return Err(Status::invalid_argument(
                    "xhttp AddInbound is not supported yet",
                ));
            }
            unsupported => {
                return Err(Status::invalid_argument(format!(
                    "unsupported inbound network for AddInbound: {unsupported}"
                )));
            }
        }

        let security = stream_settings.security_type.trim().to_ascii_lowercase();
        match security.as_str() {
            "" | "none" => Ok(protocol),
            #[cfg(feature = "tls")]
            "tls" | TYPE_TRANSPORT_TLS_CONFIG | TYPE_TRANSPORT_TLS_CONFIG_V2RAY => {
                let security = stream_settings
                    .security_settings
                    .iter()
                    .find(|item| {
                        matches!(
                            Self::parse_typed_message_type(item),
                            TYPE_TRANSPORT_TLS_CONFIG
                                | TYPE_TRANSPORT_TLS_CONFIG_V2RAY
                        )
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "tls security settings are required",
                        )
                    })?;
                let tls = self.decode_typed_message::<TlsConfigPayload>(
                    security,
                    &[TYPE_TRANSPORT_TLS_CONFIG, TYPE_TRANSPORT_TLS_CONFIG_V2RAY],
                    "tls security settings",
                )?;
                let certificate = tls.certificate.first().ok_or_else(|| {
                    Status::invalid_argument(
                        "tls AddInbound requires at least one certificate",
                    )
                })?;
                let certificate_path = certificate.certificate_path.trim();
                let private_key_path = certificate.key_path.trim();
                if certificate_path.is_empty() || private_key_path.is_empty() {
                    return Err(Status::invalid_argument(
                        "tls AddInbound currently requires certificate_path and key_path",
                    ));
                }
                Ok(ServerProxyConfig::Tls(TlsServerConfig {
                    certificates: vec![TlsCertificateConfig {
                        certificate_path: Some(certificate_path.to_string()),
                        certificate_pem: certificate.certificate.clone(),
                        key_path: Some(private_key_path.to_string()),
                        key_pem: Some(certificate.key.clone()),
                        usage: TlsCertificateUsage::Encipherment,
                    }],
                    alpn_protocols: tls.next_protocol,
                    enable_session_resumption: false,
                    reject_unknown_sni: false,
                    min_version: None,
                    max_version: None,
                    server_name: None,
                    inner: Box::new(protocol),
                }))
            }
            #[cfg(feature = "reality")]
            "reality" | TYPE_TRANSPORT_REALITY_CONFIG => {
                let security = stream_settings
                    .security_settings
                    .iter()
                    .find(|item| {
                        Self::parse_typed_message_type(item)
                            == TYPE_TRANSPORT_REALITY_CONFIG
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "reality security settings are required",
                        )
                    })?;
                let reality = self.decode_typed_message::<RealityConfigPayload>(
                    security,
                    &[TYPE_TRANSPORT_REALITY_CONFIG],
                    "reality security settings",
                )?;
                let dest = NetLocation::from_str(reality.dest.trim(), Some(443))
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid reality.dest value: {} ({err})",
                            reality.dest
                        ))
                    })?;
                if !matches!(dest.address(), Address::Hostname(_)) {
                    return Err(Status::invalid_argument(
                        "reality.dest must be a hostname",
                    ));
                }
                let private_key: [u8; 32] =
                    reality.private_key.as_slice().try_into().map_err(|_| {
                        Status::invalid_argument(
                            "reality private_key must be exactly 32 bytes",
                        )
                    })?;
                let short_ids = reality
                    .short_ids
                    .into_iter()
                    .map(|short_id| {
                        short_id.as_slice().try_into().map_err(|_| {
                            Status::invalid_argument(
                                "reality short_ids entries must be exactly 8 bytes",
                            )
                        })
                    })
                    .collect::<Result<Vec<[u8; 8]>, Status>>()?;
                let min_client_version = self.parse_reality_version(
                    &reality.min_client_ver,
                    "min_client_ver",
                )?;
                let max_client_version = self.parse_reality_version(
                    &reality.max_client_ver,
                    "max_client_ver",
                )?;
                let mut server_names = reality.server_names;
                if server_names.is_empty()
                    && let Some(hostname) = dest.address().hostname()
                {
                    server_names.push(hostname.to_string());
                }
                Ok(ServerProxyConfig::Reality(RealityTransportConfig {
                    dest,
                    private_key,
                    short_ids,
                    cipher_suites: Vec::new(),
                    max_time_diff: (reality.max_time_diff > 0)
                        .then_some(reality.max_time_diff),
                    min_client_version,
                    max_client_version,
                    server_names,
                    inner: Box::new(protocol),
                }))
            }
            unsupported => Err(Status::invalid_argument(format!(
                "unsupported inbound security for AddInbound: {unsupported}"
            ))),
        }
    }

    #[cfg(feature = "reality")]
    fn parse_reality_version(
        &self,
        bytes: &[u8],
        field: &str,
    ) -> Result<Option<[u8; 3]>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let version = bytes.try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "reality {field} must be exactly 3 bytes"
            ))
        })?;
        Ok(Some(version))
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
        if matches!(
            Self::parse_typed_message_type(proxy_settings),
            "xray.proxy.socks.ClientConfig" | "v2ray.core.proxy.socks.ClientConfig"
        ) {
            return Err(Status::unimplemented(
                "socks outbound is parsed but its data-plane connector is not implemented",
            ));
        }
        let protocol = match Self::parse_typed_message_type(proxy_settings) {
            TYPE_PROXY_FREEDOM_CONFIG | TYPE_PROXY_FREEDOM_CONFIG_V2RAY => {
                let _ = self.decode_typed_message::<FreedomConfigPayload>(
                    proxy_settings,
                    &[TYPE_PROXY_FREEDOM_CONFIG, TYPE_PROXY_FREEDOM_CONFIG_V2RAY],
                    "outbound proxy settings",
                )?;
                "freedom"
            }
            TYPE_PROXY_SOCKS_CLIENT_CONFIG
            | TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY => {
                let config = self.decode_typed_message::<SocksClientConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG,
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY,
                    ],
                    "socks outbound proxy settings",
                )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument(
                        "socks outbound requires a server endpoint",
                    )
                })?;
                let _ = self.parse_address(server.address)?;
                if !(1..=u32::from(u16::MAX)).contains(&server.port) {
                    return Err(Status::invalid_argument(
                        "socks outbound server port must be between 1 and 65535",
                    ));
                }
                "socks"
            }
            TYPE_PROXY_BLACKHOLE_CONFIG => {
                let _ = self.decode_typed_message::<BlackholeConfigPayload>(
                    proxy_settings,
                    &[TYPE_PROXY_BLACKHOLE_CONFIG],
                    "outbound proxy settings",
                )?;
                "blackhole"
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported outbound proxy settings type: {other}"
                )));
            }
        };
        Ok(OutboundSummary {
            tag: outbound.tag,
            protocol: protocol.to_string(),
            proxy_settings_type: Some(proxy_settings.r#type.clone()),
            proxy_settings_value: Some(proxy_settings.value.clone()),
        })
    }

    fn typed_message<T: Message>(
        message_type: &str,
        payload: T,
    ) -> proto::xray::common::serial::TypedMessage {
        proto::xray::common::serial::TypedMessage {
            r#type: message_type.to_string(),
            value: payload.encode_to_vec(),
        }
    }

    fn encode_address(address: &Address) -> Option<IpOrDomainPayload> {
        let address = match address {
            Address::Ipv4(addr) => {
                Some(ip_or_domain_payload::Address::Ip(addr.octets().to_vec()))
            }
            Address::Ipv6(addr) => {
                Some(ip_or_domain_payload::Address::Ip(addr.octets().to_vec()))
            }
            Address::Hostname(hostname) if !hostname.is_empty() => {
                Some(ip_or_domain_payload::Address::Domain(hostname.clone()))
            }
            Address::Hostname(_) => None,
        }?;
        Some(IpOrDomainPayload {
            address: Some(address),
        })
    }

    fn encode_receiver_settings(
        &self,
        inbound: &ServerConfig,
        stream_settings: Option<StreamConfigPayload>,
    ) -> proto::xray::common::serial::TypedMessage {
        let (address, port) = match &inbound.bind_location {
            BindLocation::Address(location) => location.components(),
        };
        Self::typed_message(
            TYPE_APP_RECEIVER_CONFIG,
            ReceiverConfigPayload {
                port_list: Some(PortListPayload {
                    range: vec![PortRangePayload {
                        from: u32::from(port),
                        to: u32::from(port),
                    }],
                }),
                listen: Self::encode_address(address),
                stream_settings,
            },
        )
    }

    fn encode_user_manager_protocol(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<proto::xray::common::serial::TypedMessage> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                let clients = users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.user_label.clone(),
                        account: Some(Self::typed_message(
                            TYPE_PROXY_VLESS_ACCOUNT,
                            VlessAccountPayload {
                                id: user.user_id.clone(),
                                flow: user.flow.clone(),
                            },
                        )),
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_VLESS_INBOUND_CONFIG,
                    VlessInboundConfigPayload { clients },
                ))
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                let users = users
                    .iter()
                    .map(|user| {
                        let security_type = match user.cipher.as_str() {
                            "aes-128-gcm" => 3,
                            "chacha20-poly1305" | "chacha20-ietf-poly1305" => 4,
                            _ => 2,
                        };
                        proto::xray::common::protocol::User {
                            level: 0,
                            email: user.user_label.clone(),
                            account: Some(Self::typed_message(
                                TYPE_PROXY_VMESS_ACCOUNT,
                                VmessAccountPayload {
                                    id: user.user_id.clone(),
                                    security_settings: Some(
                                        VmessSecurityConfigPayload {
                                            r#type: security_type,
                                        },
                                    ),
                                    tests_enabled: String::new(),
                                },
                            )),
                        }
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_VMESS_INBOUND_CONFIG,
                    VmessInboundConfigPayload { users },
                ))
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, fallbacks } => {
                let users = users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.email.clone().unwrap_or_default(),
                        account: Some(Self::typed_message(
                            TYPE_PROXY_TROJAN_ACCOUNT,
                            TrojanAccountPayload {
                                password: user.password.clone(),
                            },
                        )),
                    })
                    .collect();
                let fallbacks = fallbacks
                    .iter()
                    .map(|fallback| TrojanFallbackPayload {
                        dest: fallback.dest.to_string(),
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_TROJAN_SERVER_CONFIG,
                    TrojanServerConfigPayload { users, fallbacks },
                ))
            }
            ServerProxyConfig::Socks {
                accounts,
                udp_enabled,
                udp_response_ip,
                user_level,
            } => {
                let auth_type = i32::from(accounts.auth_required());
                let account_map = accounts
                    .snapshot()
                    .iter()
                    .map(|account| {
                        (account.username.clone(), account.password.clone())
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_SOCKS_SERVER_CONFIG,
                    SocksServerConfigPayload {
                        auth_type,
                        accounts: account_map,
                        address: udp_response_ip.as_deref().and_then(|address| {
                            Address::from(address)
                                .ok()
                                .and_then(|address| Self::encode_address(&address))
                        }),
                        udp_enabled: *udp_enabled,
                        user_level: *user_level,
                    },
                ))
            }
            ServerProxyConfig::DokodemoDoor { config } => {
                let (address, port) = config.target.components();
                Some(Self::typed_message(
                    TYPE_PROXY_DOKODEMO_CONFIG,
                    DokodemoConfigPayload {
                        address: Self::encode_address(address),
                        port: u32::from(port),
                        port_map: std::collections::HashMap::new(),
                        networks: vec![
                            proto::xray::common::net::Network::Tcp as i32,
                        ],
                        follow_redirect: config.follow_redirect,
                        user_level: 0,
                    },
                ))
            }
            _ => None,
        }
    }

    fn encode_inbound_config(
        &self,
        inbound: &ServerConfig,
    ) -> proto::xray::core::InboundHandlerConfig {
        let (stream_settings, proxy_settings) =
            self.encode_inbound_protocol_layers(&inbound.protocol);
        proto::xray::core::InboundHandlerConfig {
            tag: inbound.tag.clone(),
            receiver_settings: Some(
                self.encode_receiver_settings(inbound, stream_settings),
            ),
            proxy_settings,
        }
    }

    fn encode_inbound_protocol_layers(
        &self,
        protocol: &ServerProxyConfig,
    ) -> (
        Option<StreamConfigPayload>,
        Option<proto::xray::common::serial::TypedMessage>,
    ) {
        match protocol {
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let target = match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => target,
                    crate::util::option::OneOrSome::Some(targets) => {
                        let Some(target) = targets.first() else {
                            return (None, None);
                        };
                        target
                    }
                };
                let mut headers =
                    target.matching_headers.clone().unwrap_or_default();
                let host = headers
                    .remove("Host")
                    .or_else(|| headers.remove("host"))
                    .unwrap_or_default();
                let websocket = Self::typed_message(
                    TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                    WebsocketConfigPayload {
                        host,
                        path: target.matching_path.clone().unwrap_or_default(),
                        header: headers,
                        accept_proxy_protocol: target.accept_proxy_protocol,
                        heartbeat_period: target.heartbeat_period,
                    },
                );
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&target.protocol);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "websocket".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                    });
                settings.protocol_name = "websocket".to_string();
                settings.transport_settings.push(TransportConfigPayload {
                    settings: Some(websocket),
                    protocol_name: "websocket".to_string(),
                });
                (stream_settings, proxy_settings)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&tls.inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "tcp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                    });
                settings.security_type = "tls".to_string();
                settings.security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_TLS_CONFIG,
                    TlsConfigPayload {
                        certificate: tls
                            .certificates
                            .iter()
                            .map(|certificate| TlsCertificatePayload {
                                certificate: certificate.certificate_pem.clone(),
                                key: certificate.key_pem.clone().unwrap_or_default(),
                                certificate_path: certificate
                                    .certificate_path
                                    .clone()
                                    .unwrap_or_default(),
                                key_path: certificate
                                    .key_path
                                    .clone()
                                    .unwrap_or_default(),
                            })
                            .collect(),
                        next_protocol: tls.alpn_protocols.clone(),
                    },
                ));
                (stream_settings, proxy_settings)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&reality.inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "tcp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                    });
                settings.security_type = "reality".to_string();
                settings.security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_REALITY_CONFIG,
                    RealityConfigPayload {
                        dest: reality.dest.to_string(),
                        server_names: reality.server_names.clone(),
                        private_key: reality.private_key.to_vec(),
                        min_client_ver: reality
                            .min_client_version
                            .map(|version| version.to_vec())
                            .unwrap_or_default(),
                        max_client_ver: reality
                            .max_client_version
                            .map(|version| version.to_vec())
                            .unwrap_or_default(),
                        max_time_diff: reality.max_time_diff.unwrap_or_default(),
                        short_ids: reality
                            .short_ids
                            .iter()
                            .map(|short_id| short_id.to_vec())
                            .collect(),
                    },
                ));
                (stream_settings, proxy_settings)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                    });
                settings.protocol_name = "xhttp".to_string();
                (stream_settings, proxy_settings)
            }
            protocol => (None, self.encode_user_manager_protocol(protocol)),
        }
    }

    fn encode_outbound_config(
        &self,
        outbound: &OutboundSummary,
    ) -> proto::xray::core::OutboundHandlerConfig {
        let proxy_settings = match (
            outbound.proxy_settings_type.as_ref(),
            outbound.proxy_settings_value.as_ref(),
        ) {
            (Some(r#type), Some(value)) => {
                Some(proto::xray::common::serial::TypedMessage {
                    r#type: r#type.clone(),
                    value: value.clone(),
                })
            }
            _ => match outbound.protocol.as_str() {
                "freedom" => Some(Self::typed_message(
                    TYPE_PROXY_FREEDOM_CONFIG,
                    FreedomConfigPayload {},
                )),
                "blackhole" => Some(Self::typed_message(
                    TYPE_PROXY_BLACKHOLE_CONFIG,
                    BlackholeConfigPayload {},
                )),
                _ => None,
            },
        };
        proto::xray::core::OutboundHandlerConfig {
            tag: outbound.tag.clone(),
            sender_settings: None,
            proxy_settings,
            expire: 0,
            comment: String::new(),
        }
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

    #[cfg(feature = "hysteria")]
    fn parse_hysteria_client(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<Hysteria2Client, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for hysteria",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        if account_type != TYPE_PROXY_HYSTERIA_ACCOUNT {
            return Err(Status::invalid_argument(format!(
                "unsupported hysteria account type: {account_type}"
            )));
        }

        let payload = HysteriaAccountPayload::decode(account.value.as_slice())
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid hysteria account payload: {err}"
                ))
            })?;
        let auth = payload.auth.as_str();

        Ok(Hysteria2Client {
            password: auth.to_string(),
            email: if user.email.is_empty() {
                None
            } else {
                Some(user.email.clone())
            },
            level: user.level,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        })
    }

    fn apply_add_user_to_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        user: &proto::xray::common::protocol::User,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                let user = self.parse_vless_user(user)?;
                if users
                    .iter()
                    .any(|existing| existing.user_label == user.user_label)
                {
                    return Err(Status::already_exists(format!(
                        "VLESS user {} already exists",
                        user.user_label
                    )));
                }
                users.push(user);
                Ok(true)
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                let parsed = self.parse_vmess_user(user)?;
                let email = user.email.trim();
                if !email.is_empty()
                    && users.iter().any(|existing| {
                        existing.user_label.eq_ignore_ascii_case(email)
                    })
                {
                    return Err(Status::already_exists(format!(
                        "VMess user {email} already exists"
                    )));
                }
                users.push(parsed);
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

                if users
                    .iter()
                    .any(|existing| existing.email.as_deref() == Some(email))
                {
                    return Err(Status::already_exists(format!(
                        "Trojan user {email} already exists"
                    )));
                }
                users.push(TrojanUser {
                    password,
                    email: Some(email.to_string()),
                });
                Ok(true)
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                let client = self.parse_hysteria_client(user)?;
                // Xray's Hysteria validator is keyed by raw auth, not email.
                // Re-adding the same auth replaces that entry, while multiple
                // auth values with the same email are allowed to coexist. Move
                // replacements to the end so UUID masked-ID lookup remains
                // last-write-wins like Xray's secondary ID map.
                config.clients.retain(|existing| {
                    existing.xray_transport_auth_fallback
                        || existing.password != client.password
                });
                config.clients.push(client);
                Ok(true)
            }
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, identity } => {
                let current = ServerProxyConfig::Shadowsocks {
                    users: users.clone(),
                    identity: identity.clone(),
                };
                let parsed = self.parse_shadowsocks_user(&current, user)?;
                if identity.is_some() {
                    if users.iter().any(|existing| existing.email == parsed.email) {
                        return Err(Status::already_exists(format!(
                            "Shadowsocks user {} already exists",
                            parsed.email
                        )));
                    }
                } else {
                    users.retain(|existing| existing.email != parsed.email);
                }
                users.push(parsed);
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
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.apply_add_user_to_protocol(inner.as_mut(), user)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.apply_add_user_to_protocol(config.inner.as_mut(), user)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.apply_add_user_to_protocol(config.inner.as_mut(), user)
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
            register_identity(user.email.clone());
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
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                let before = users.len();
                users.retain(|user| user.user_label != email);
                if before == users.len() {
                    return Err(Status::not_found(format!(
                        "VLESS user {email} not found"
                    )));
                }
                Ok(before != users.len())
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                let before = users.len();
                users.retain(|user| !user.user_label.eq_ignore_ascii_case(email));
                if before == users.len() {
                    return Err(Status::not_found(format!(
                        "VMess user {email} not found"
                    )));
                }
                Ok(true)
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                let before = users.len();
                users.retain(|user| user.email.as_deref() != Some(email));
                if before == users.len() {
                    return Err(Status::not_found(format!(
                        "Trojan user {email} not found"
                    )));
                }
                Ok(true)
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                if let Some(index) = config
                    .clients
                    .iter()
                    .position(|client| client.email.as_deref() == Some(email))
                {
                    // Xray DelByEmail resolves one matching user and deletes only
                    // that user's auth key; duplicate emails are not bulk-removed.
                    config.clients.remove(index);
                }
                // Xray's Hysteria DelByEmail is idempotent and returns nil even
                // when no matching email exists. `true` means this protocol did
                // handle the user-manager operation, not that a user was found.
                Ok(true)
            }
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, .. } => {
                let before = users.len();
                users.retain(|user| user.email != email);
                if before == users.len() {
                    return Err(Status::not_found(format!(
                        "Shadowsocks user {email} not found"
                    )));
                }
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
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.apply_remove_user_from_protocol(inner.as_mut(), email)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.apply_remove_user_from_protocol(config.inner.as_mut(), email)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.apply_remove_user_from_protocol(config.inner.as_mut(), email)
            }
            _ => Ok(false),
        }
    }

    fn detached_inbound(inbound: &ServerConfig) -> ServerConfig {
        inbound.clone()
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
            ServerProxyConfig::Vless { users, .. } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
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
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| client.email.clone().unwrap_or_default())
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
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, .. } => {
                Some(users.iter().map(|user| user.email.clone()).collect())
            }
            ServerProxyConfig::DokodemoDoor { .. } => None,
        }
    }

    fn select_user_manager_users(
        users: Vec<proto::xray::common::protocol::User>,
        email: &str,
    ) -> Vec<proto::xray::common::protocol::User> {
        if email.is_empty() {
            users
        } else {
            users
                .into_iter()
                .find(|user| user.email == email)
                .into_iter()
                .collect()
        }
    }

    fn get_user_manager_users(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<proto::xray::common::protocol::User>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => Some(
                users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.user_label.clone(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                            value: VlessAccountPayload {
                                id: user.user_id.clone(),
                                flow: user.flow.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => Some(
                users
                    .iter()
                    .map(|user| {
                        let security_type = match user.cipher.as_str() {
                            "aes-128-gcm" => 3,
                            "chacha20-poly1305" | "chacha20-ietf-poly1305" => 4,
                            _ => 2,
                        };
                        proto::xray::common::protocol::User {
                            level: 0,
                            email: user.user_label.clone(),
                            account: Some(
                                proto::xray::common::serial::TypedMessage {
                                    r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                                    value: VmessAccountPayload {
                                        id: user.user_id.clone(),
                                        security_settings: Some(
                                            VmessSecurityConfigPayload {
                                                r#type: security_type,
                                            },
                                        ),
                                        tests_enabled: String::new(),
                                    }
                                    .encode_to_vec(),
                                },
                            ),
                        }
                    })
                    .collect(),
            ),
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => Some(
                users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                            value: TrojanAccountPayload {
                                password: user.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| proto::xray::common::protocol::User {
                        level: client.level,
                        email: client.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                            value: HysteriaAccountPayload {
                                auth: client.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => {
                Some(vec![self.build_user(config.uuid.clone())])
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut users = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_users(&target.protocol)
                        {
                            users.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_users(&target.protocol)
                            {
                                users.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(users)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => self.get_user_manager_users(&tls.inner),
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_users(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_users(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_users(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_users(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, identity } => Some(
                users
                    .iter()
                    .map(|user| {
                        let account = if identity.is_some() {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT,
                                Shadowsocks2022AccountPayload {
                                    key: user.password.clone(),
                                },
                            )
                        } else {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                                ShadowsocksAccountPayload {
                                    password: user.password.clone(),
                                    cipher_type: Self::shadowsocks_cipher_type(
                                        &user.method,
                                    )
                                    .unwrap_or_default(),
                                    iv_check: false,
                                },
                            )
                        };
                        proto::xray::common::protocol::User {
                            level: 0,
                            email: user.email.clone(),
                            account: Some(account),
                        }
                    })
                    .collect(),
            ),
            ServerProxyConfig::DokodemoDoor { .. } => None,
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
        let _mutation_guard = self.mutation_lock.lock().await;
        let request = request.into_inner();
        let inbound = request
            .inbound
            .ok_or_else(|| Status::invalid_argument("inbound is required"))?;
        let inbound = self.parse_add_inbound(inbound)?;
        let inbound_tag = inbound.tag.clone();
        self.runtime.add_inbound(inbound.clone()).map_err(|error| {
            Status::already_exists(format!("existing tag: {error}"))
        })?;

        let handles = match start_servers(inbound, self.runtime.clone()).await {
            Ok(handles) => handles,
            Err(err) => {
                self.runtime.remove_inbound(&inbound_tag);
                return Err(Status::unknown(format!(
                    "failed to start inbound handler: {err}"
                )));
            }
        };
        self.runtime.register_inbound_tasks(&inbound_tag, handles);

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
        let _mutation_guard = self.mutation_lock.lock().await;
        let request = request.into_inner();
        let Some(_) = self.runtime.remove_inbound(&request.tag) else {
            return Err(Status::not_found("inbound not found"));
        };
        self.runtime.stop_inbound_tasks(&request.tag).await;
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
        let _mutation_guard = self.mutation_lock.lock().await;
        let request = request.into_inner();
        let operation = self.parse_alter_inbound_operation(request.operation)?;
        if matches!(&operation, AlterInboundOperation::Noop) {
            return Ok(Response::new(
                proto::xray::app::proxyman::command::AlterInboundResponse {},
            ));
        }

        let Some(current) = self.runtime.inbound_by_tag(&request.tag) else {
            return Err(Status::not_found("inbound not found"));
        };
        let original = Self::detached_inbound(&current);
        let mut updated = Self::detached_inbound(&current);
        self.apply_alter_inbound_operation(&mut updated, operation)?;
        self.runtime
            .with_inbound_mut(&request.tag, |inbound| *inbound = updated.clone())
            .ok_or_else(|| Status::not_found("inbound not found"))?;

        if self.runtime.stop_inbound_tasks(&request.tag).await {
            match start_servers(updated, self.runtime.clone()).await {
                Ok(handles) => {
                    self.runtime.register_inbound_tasks(&request.tag, handles);
                }
                Err(start_error) => {
                    self.runtime
                        .with_inbound_mut(&request.tag, |inbound| {
                            *inbound = original.clone()
                        })
                        .ok_or_else(|| Status::not_found("inbound not found"))?;
                    tokio::task::yield_now().await;
                    let rollback =
                        start_servers(original, self.runtime.clone()).await;
                    return match rollback {
                        Ok(handles) => {
                            self.runtime
                                .register_inbound_tasks(&request.tag, handles);
                            Err(Status::unknown(format!(
                                "failed to restart inbound handler: {start_error}; previous inbound restored"
                            )))
                        }
                        Err(rollback_error) => Err(Status::unknown(format!(
                            "failed to restart inbound handler: {start_error}; rollback failed: {rollback_error}"
                        ))),
                    };
                }
            }
        }

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
        let users = Self::select_user_manager_users(users, &request.email);

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
        let _mutation_guard = self.mutation_lock.lock().await;
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
        let _mutation_guard = self.mutation_lock.lock().await;
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
mod tests {
    use super::proto::xray::app::proxyman::command::handler_service_server::HandlerService;
    use super::*;
    #[cfg(feature = "trojan")]
    use crate::config::server_config::TrojanUser;
    #[cfg(feature = "vless")]
    use crate::config::server_config::VlessUser;
    #[cfg(feature = "hysteria")]
    use crate::config::server_config::{
        Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig,
    };
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            server_config::{ServerConfig, SocksUser, XhttpServerConfig},
        },
        runtime::OutboundSummary,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{
        net::{Ipv4Addr, SocketAddrV4, TcpListener},
        time::Duration,
    };
    use tonic::{Code, Request};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        runtime: RuntimeState,
        inbound_tag: String,
        outbound_tag: String,
    }

    fn unique_tag(prefix: &str) -> String {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    fn free_localhost_port() -> u16 {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral port")
            .local_addr()
            .expect("read local addr")
            .port()
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
            }]
            .into(),
            udp_enabled: false,
            udp_response_ip: None,
            user_level: 0,
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
            proxy_settings_type: None,
            proxy_settings_value: None,
        };

        let runtime = RuntimeState::new(vec![inbound], vec![outbound]);
        Fixture {
            runtime,
            inbound_tag,
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
                        stream_settings: None,
                    }
                    .encode_to_vec(),
                }),
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_SOCKS_SERVER_CONFIG.to_string(),
                    value: SocksServerConfigPayload {
                        auth_type: 1,
                        accounts,
                        address: None,
                        udp_enabled: false,
                        user_level: 0,
                    }
                    .encode_to_vec(),
                }),
            }),
        }
    }

    fn build_receiver_settings(
        port: u16,
        stream_settings: Option<StreamConfigPayload>,
    ) -> proto::xray::common::serial::TypedMessage {
        proto::xray::common::serial::TypedMessage {
            r#type: TYPE_APP_RECEIVER_CONFIG.to_string(),
            value: ReceiverConfigPayload {
                port_list: Some(PortListPayload {
                    range: vec![PortRangePayload {
                        from: port as u32,
                        to: port as u32,
                    }],
                }),
                listen: Some(localhost_ip_payload()),
                stream_settings,
            }
            .encode_to_vec(),
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

    #[test]
    fn handler_rejects_socks_outbound_until_connector_exists() {
        let service =
            HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
        let error = service
            .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
                tag: "socks-outbound".to_string(),
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: "xray.proxy.socks.ClientConfig".to_string(),
                    value: Vec::new(),
                }),
                ..proto::xray::core::OutboundHandlerConfig::default()
            })
            .expect_err("SOCKS outbound must not be advertised as executable yet");

        assert_eq!(error.code(), Code::Unimplemented);
        assert_eq!(
            error.message(),
            "socks outbound is parsed but its data-plane connector is not implemented"
        );
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_alter_inbound_rolls_back_config_when_restart_fails() {
        let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();
        let inbound_tag = unique_tag("rollback-inbound");
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Vless {
                users: Vec::new(),
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let placeholder_task = tokio::spawn(std::future::pending::<()>());
        runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
        let service = HandlerServiceImpl::new(runtime.clone());
        let added_email = unique_tag("failed-user");
        let operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: added_email,
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: VlessAccountPayload {
                        id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                        flow: String::new(),
                    }
                    .encode_to_vec(),
                }),
            }),
        };

        let error = service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: inbound_tag.clone(),
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_ADD_USER_OPERATION.to_string(),
                        value: operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect_err("occupied listener should fail both restart attempts");

        assert_eq!(error.code(), Code::Unknown);
        assert!(error.message().contains("rollback failed"));
        let restored = runtime.inbound_by_tag(&inbound_tag).unwrap();
        let ServerProxyConfig::Vless { users, .. } = restored.protocol else {
            panic!("expected vless inbound");
        };
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn handler_empty_alter_keeps_registered_listener() {
        let fixture = build_fixture();
        let placeholder_task = tokio::spawn(std::future::pending::<()>());
        fixture
            .runtime
            .register_inbound_tasks(&fixture.inbound_tag, vec![placeholder_task]);
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: fixture.inbound_tag.clone(),
                    operation: None,
                },
            ))
            .await
            .expect("empty operation should be idempotent");

        assert!(
            fixture
                .runtime
                .stop_inbound_tasks(&fixture.inbound_tag)
                .await
        );
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_alter_inbound_reaches_xhttp_inner_users() {
        let inbound_tag = unique_tag("xhttp-vless-inbound");
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                free_localhost_port(),
            )),
            protocol: ServerProxyConfig::Xhttp {
                config: XhttpServerConfig {
                    mode: crate::config::server_config::XhttpMode::Auto,
                    host: None,
                    path: "/control".to_string(),
                    trusted_x_forwarded_for: Vec::new(),
                    min_padding: 0,
                    max_padding: 0,
                    max_each_post_bytes: 1_000_000,
                    max_buffered_posts: 30,
                    session_ttl_secs: 30,
                    stream_up_server_secs: (20, 80),
                    server_max_header_bytes: 8192,
                    padding_obfs_mode: false,
                    padding_key: "x_padding".into(),
                    padding_header: "X-Padding".into(),
                    padding_placement:
                        crate::config::server_config::XhttpPaddingPlacement::QueryInHeader,
                    padding_method:
                        crate::config::server_config::XhttpPaddingMethod::RepeatX,
                    no_grpc_header: false,
                    no_sse_header: false,
                    uplink_http_method: "POST".into(),
                    min_posts_interval_ms: (30, 30),
                    session_placement:
                        crate::config::server_config::XhttpPlacement::Path,
                    session_key: String::new(),
                    seq_placement:
                        crate::config::server_config::XhttpPlacement::Path,
                    seq_key: String::new(),
                    uplink_data_placement:
                        crate::config::server_config::XhttpDataPlacement::Auto,
                    uplink_data_key: "X-Data".into(),
                    xray_max_idle_timeout_secs: None,
                    xray_max_incoming_streams: None,
                    xray_init_stream_receive_window: None,
                    xray_max_stream_receive_window: None,
                    xray_init_connection_receive_window: None,
                    xray_max_connection_receive_window: None,
                    xray_disable_path_mtu_discovery: None,
                },
                inner: Box::new(ServerProxyConfig::Vless {
                    users: Vec::new(),
                    fallbacks: Vec::new(),
                }),
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);
        let email = unique_tag("xhttp-user");
        let operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: email.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: VlessAccountPayload {
                        id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                        flow: String::new(),
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
                        value: operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect("xhttp add user should reach inner protocol");
        let users = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .users;

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, email);
    }

    #[test]
    fn handler_preserves_xray_socks_grpc_fields() {
        let service =
            HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
        let parsed = service
            .parse_add_inbound_protocol(&HandlerServiceImpl::typed_message(
                TYPE_PROXY_SOCKS_SERVER_CONFIG,
                SocksServerConfigPayload {
                    auth_type: 2,
                    accounts: std::collections::HashMap::from([(
                        "alice".to_string(),
                        "secret".to_string(),
                    )]),
                    address: Some(localhost_ip_payload()),
                    udp_enabled: true,
                    user_level: 7,
                },
            ))
            .expect("SOCKS server config should parse");
        let ServerProxyConfig::Socks {
            accounts,
            udp_enabled,
            udp_response_ip,
            user_level,
        } = &parsed
        else {
            panic!("expected SOCKS inbound config");
        };
        assert!(!accounts.auth_required());
        assert_eq!(accounts.snapshot()[0].username, "alice");
        assert!(*udp_enabled);
        assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(*user_level, 7);

        let (_, encoded) = service.encode_inbound_protocol_layers(&parsed);
        let encoded = encoded.expect("SOCKS settings should encode");
        let socks = SocksServerConfigPayload::decode(encoded.value.as_slice())
            .expect("decode SOCKS settings");
        assert_eq!(socks.auth_type, 0);
        assert_eq!(
            socks.accounts.get("alice").map(String::as_str),
            Some("secret")
        );
        assert_eq!(socks.address, Some(localhost_ip_payload()));
        assert!(socks.udp_enabled);
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
        let inbound = &response.inbounds[0];
        assert_eq!(inbound.tag, fixture.inbound_tag);

        let receiver_settings = inbound
            .receiver_settings
            .as_ref()
            .expect("receiver settings should be echoed");
        assert_eq!(receiver_settings.r#type, TYPE_APP_RECEIVER_CONFIG);
        let receiver =
            ReceiverConfigPayload::decode(receiver_settings.value.as_slice())
                .expect("decode receiver settings");
        let ports = receiver.port_list.expect("receiver ports");
        assert_eq!(ports.range.len(), 1);
        assert_eq!(ports.range[0].from, 1080);
        assert_eq!(ports.range[0].to, 1080);
        assert_eq!(receiver.listen, Some(localhost_ip_payload()));

        let proxy_settings = inbound
            .proxy_settings
            .as_ref()
            .expect("proxy settings should be echoed");
        assert_eq!(proxy_settings.r#type, TYPE_PROXY_SOCKS_SERVER_CONFIG);
        let socks =
            SocksServerConfigPayload::decode(proxy_settings.value.as_slice())
                .expect("decode socks settings");
        assert_eq!(socks.auth_type, 1);
        assert_eq!(socks.accounts.len(), 1);
        assert!(socks.accounts.values().any(|password| password == "pass-a"));
    }

    #[tokio::test]
    async fn handler_lists_inbounds_only_tags_omits_settings() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());

        let response = service
            .list_inbounds(Request::new(
                proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: true,
                },
            ))
            .await
            .expect("list_inbounds failed")
            .into_inner();
        assert_eq!(response.inbounds.len(), 1);
        let inbound = &response.inbounds[0];
        assert_eq!(inbound.tag, fixture.inbound_tag);
        assert!(inbound.receiver_settings.is_none());
        assert!(inbound.proxy_settings.is_none());
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
        let outbound = &response.outbounds[0];
        assert_eq!(outbound.tag, fixture.outbound_tag);
        assert!(outbound.sender_settings.is_none());
        let proxy_settings = outbound
            .proxy_settings
            .as_ref()
            .expect("proxy settings should be echoed");
        assert_eq!(proxy_settings.r#type, TYPE_PROXY_FREEDOM_CONFIG);
        FreedomConfigPayload::decode(proxy_settings.value.as_slice())
            .expect("decode freedom settings");
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
            .expect_err("SOCKS should not expose Xray UserManager");
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
            .expect_err("SOCKS should not expose Xray UserManager count");
        assert_eq!(err.code(), Code::Unknown);
        assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);
    }

    #[tokio::test]
    async fn handler_adds_inbound_and_outbound() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let added_inbound = unique_tag("added-inbound");
        let added_outbound = unique_tag("added-outbound");
        let added_inbound_port = free_localhost_port();

        service
            .add_inbound(Request::new(build_add_inbound_request(
                &added_inbound,
                added_inbound_port,
            )))
            .await
            .expect("add_inbound should succeed");
        assert!(fixture.runtime.inbound_by_tag(&added_inbound).is_some());

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stream = tokio::net::TcpStream::connect(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            added_inbound_port,
        ))
        .await
        .expect("added inbound listener should accept connections");
        drop(stream);

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

        service
            .remove_inbound(Request::new(
                proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: added_inbound.clone(),
                },
            ))
            .await
            .expect("remove_inbound after add failed");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = tokio::net::TcpStream::connect(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            added_inbound_port,
        ))
        .await
        .expect_err("removed inbound listener should stop accepting connections");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
        ));
    }

    #[cfg(all(feature = "vless", feature = "ws", feature = "tls"))]
    #[test]
    fn handler_parse_add_inbound_supports_vless_websocket_tls() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "vless-user@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                    flow: String::new(),
                }
                .encode_to_vec(),
            }),
        };
        let inbound = proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("vless"),
            receiver_settings: Some(build_receiver_settings(
                2080,
                Some(StreamConfigPayload {
                    protocol_name: "websocket".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "websocket".to_string(),
                        settings: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
                            value: WebsocketConfigPayload {
                                host: "example.com".to_string(),
                                path: "/ws".to_string(),
                                header: std::collections::HashMap::from([(
                                    "X-Test".to_string(),
                                    "ignored-inbound".to_string(),
                                )]),
                                accept_proxy_protocol: false,
                                heartbeat_period: 0,
                            }
                            .encode_to_vec(),
                        }),
                    }],
                    security_type: "tls".to_string(),
                    security_settings: vec![
                        proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                            value: TlsConfigPayload {
                                certificate: vec![TlsCertificatePayload {
                                    certificate: Vec::new(),
                                    key: Vec::new(),
                                    certificate_path: "/tmp/test-cert.pem"
                                        .to_string(),
                                    key_path: "/tmp/test-key.pem".to_string(),
                                }],
                                next_protocol: vec![
                                    "h2".to_string(),
                                    "http/1.1".to_string(),
                                ],
                            }
                            .encode_to_vec(),
                        },
                    ],
                }),
            )),
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_INBOUND_CONFIG.to_string(),
                value: VlessInboundConfigPayload {
                    clients: vec![user],
                }
                .encode_to_vec(),
            }),
        };

        let parsed = service
            .parse_add_inbound(inbound)
            .expect("vless websocket tls inbound should parse");
        assert_eq!(parsed.transport, Transport::Tcp);
        match parsed.protocol {
            ServerProxyConfig::Tls(tls) => {
                assert_eq!(tls.certificates.len(), 1);
                let certificate = &tls.certificates[0];
                assert_eq!(
                    certificate.certificate_path.as_deref(),
                    Some("/tmp/test-cert.pem")
                );
                assert_eq!(
                    certificate.key_path.as_deref(),
                    Some("/tmp/test-key.pem")
                );
                assert_eq!(tls.alpn_protocols, vec!["h2", "http/1.1"]);
                match tls.inner.as_ref() {
                    ServerProxyConfig::Websocket { targets } => match targets
                        .as_ref()
                    {
                        OneOrSome::One(target) => {
                            assert_eq!(target.matching_path.as_deref(), Some("/ws"));
                            let matching_headers = target
                                .matching_headers
                                .as_ref()
                                .expect("websocket host should be preserved");
                            assert_eq!(
                                matching_headers.get("host").map(String::as_str),
                                Some("example.com")
                            );
                            assert!(!matching_headers.contains_key("X-Test"));
                            assert!(!matching_headers.contains_key("x-test"));
                            match &target.protocol {
                                ServerProxyConfig::Vless { users, .. } => {
                                    assert_eq!(users.len(), 1);
                                    assert_eq!(
                                        users[0].user_id,
                                        "5df5643d-4e28-4399-bb9e-22014a2d3246"
                                    );
                                    assert_eq!(
                                        users[0].user_label,
                                        "vless-user@example.com"
                                    );
                                }
                                other => {
                                    panic!("unexpected inner protocol: {other:?}")
                                }
                            }
                        }
                        other => {
                            panic!("unexpected websocket target layout: {other:?}")
                        }
                    },
                    other => panic!("unexpected tls inner protocol: {other:?}"),
                }
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn handler_parse_add_inbound_supports_vmess() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "vmess-user@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                value: VmessAccountPayload {
                    id: "test-vmess-user".to_string(),
                    security_settings: Some(VmessSecurityConfigPayload {
                        r#type: 3,
                    }),
                    tests_enabled: String::new(),
                }
                .encode_to_vec(),
            }),
        };
        let inbound = proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("vmess"),
            receiver_settings: Some(build_receiver_settings(2444, None)),
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VMESS_INBOUND_CONFIG.to_string(),
                value: VmessInboundConfigPayload { users: vec![user] }
                    .encode_to_vec(),
            }),
        };

        let parsed = service
            .parse_add_inbound(inbound)
            .expect("vmess inbound should parse");
        match parsed.protocol {
            ServerProxyConfig::Vmess { users } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].user_label, "vmess-user@example.com");
                assert_eq!(users[0].user_id, "321d83eb-74db-554a-a630-0ad214dc332b");
                assert_eq!(users[0].cipher, "aes-128-gcm");
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    #[test]
    fn handler_parse_add_inbound_supports_trojan_reality() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "trojan-user@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                value: TrojanAccountPayload {
                    password: "secret-password".to_string(),
                }
                .encode_to_vec(),
            }),
        };
        let inbound = proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("trojan"),
            receiver_settings: Some(build_receiver_settings(
                2443,
                Some(StreamConfigPayload {
                    protocol_name: "tcp".to_string(),
                    transport_settings: Vec::new(),
                    security_type: "reality".to_string(),
                    security_settings: vec![
                        proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                            value: RealityConfigPayload {
                                dest: "www.example.com:443".to_string(),
                                server_names: vec!["www.example.com".to_string()],
                                private_key: vec![7; 32],
                                min_client_ver: vec![1, 8, 0],
                                max_client_ver: vec![1, 8, 9],
                                max_time_diff: 30,
                                short_ids: vec![vec![1, 2, 3, 4, 5, 6, 7, 8]],
                            }
                            .encode_to_vec(),
                        },
                    ],
                }),
            )),
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_TROJAN_SERVER_CONFIG.to_string(),
                value: TrojanServerConfigPayload {
                    users: vec![user],
                    fallbacks: vec![TrojanFallbackPayload {
                        dest: "fallback.example.com:8443".to_string(),
                    }],
                }
                .encode_to_vec(),
            }),
        };

        let parsed = service
            .parse_add_inbound(inbound)
            .expect("trojan reality inbound should parse");
        match parsed.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.dest.to_string(), "www.example.com:443");
                assert_eq!(reality.short_ids.len(), 1);
                assert_eq!(reality.max_time_diff, Some(30));
                assert_eq!(reality.min_client_version, Some([1, 8, 0]));
                assert_eq!(reality.max_client_version, Some([1, 8, 9]));
                match reality.inner.as_ref() {
                    ServerProxyConfig::Trojan { users, fallbacks } => {
                        assert_eq!(users.len(), 1);
                        assert_eq!(
                            users[0].email.as_deref(),
                            Some("trojan-user@example.com")
                        );
                        assert_eq!(users[0].password, "secret-password");
                        assert_eq!(fallbacks.len(), 1);
                        assert_eq!(
                            fallbacks[0].dest.to_string(),
                            "fallback.example.com:8443"
                        );
                    }
                    other => panic!("unexpected reality inner protocol: {other:?}"),
                }
            }
            other => panic!("unexpected protocol: {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_vmess_users() {
        let inbound_tag = unique_tag("vmess-inbound");
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                free_localhost_port(),
            )),
            protocol: ServerProxyConfig::Vmess {
                users: vec![VmessUser {
                    user_id: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
                    user_label: "first-vmess@example.com".to_string(),
                    cipher: "aes-128-gcm".to_string(),
                }],
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);

        let initial_users = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vmess get users failed")
            .into_inner()
            .users;
        assert_eq!(initial_users.len(), 1);
        let initial_account = initial_users[0]
            .account
            .as_ref()
            .expect("VMess users must include account payload");
        assert_eq!(initial_account.r#type, TYPE_PROXY_VMESS_ACCOUNT);
        let initial_account =
            VmessAccountPayload::decode(initial_account.value.as_slice())
                .expect("decode VMess account");
        assert_eq!(initial_account.id, "3ac9b383-75a1-431c-8184-106c80eb2273");
        assert_eq!(
            initial_account
                .security_settings
                .map(|security| security.r#type),
            Some(3)
        );

        let email = unique_tag("vmess-user");
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: email.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                    value: VmessAccountPayload {
                        id: "short-id".to_string(),
                        security_settings: Some(VmessSecurityConfigPayload {
                            r#type: 4,
                        }),
                        tests_enabled: String::new(),
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
            .expect("vmess add user should succeed");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: email.clone(),
                },
            ))
            .await
            .expect("vmess get added user failed")
            .into_inner()
            .users;
        assert_eq!(users_after_add.len(), 1);
        let account = users_after_add[0]
            .account
            .as_ref()
            .expect("added VMess user must include account");
        let account = VmessAccountPayload::decode(account.value.as_slice())
            .expect("decode added VMess account");
        assert_eq!(account.id, "bcd643ce-d9c8-50bb-b026-89d256010162");
        assert_eq!(
            account.security_settings.map(|security| security.r#type),
            Some(4)
        );

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
            .expect("vmess remove user should succeed");

        let count_after_remove = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .expect("vmess get users count after remove failed")
            .into_inner();
        assert_eq!(count_after_remove.count, 1);
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_vless_users() {
        let inbound_tag = unique_tag("vless-inbound");
        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1092,
        ));
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location,
            protocol: ServerProxyConfig::Vless {
                users: vec![
                    VlessUser {
                        user_id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                        user_label: "first-user@example.com".to_string(),
                        flow: String::new(),
                    },
                    VlessUser {
                        user_id: "4571894c-7ece-4b27-a734-746330d1a984".to_string(),
                        user_label: "second-user@example.com".to_string(),
                        flow: "xtls-rprx-vision".to_string(),
                    },
                ],
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);

        let initial_users = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| {
                let account = user.account.as_ref().map(|account| {
                    VlessAccountPayload::decode(account.value.as_slice())
                        .expect("decode vless account from initial users")
                });
                (user.email, account)
            })
            .collect::<Vec<_>>();
        assert_eq!(initial_users.len(), 2);
        assert!(
            initial_users
                .iter()
                .any(|(email, _)| email == "first-user@example.com")
        );
        assert!(
            initial_users
                .iter()
                .any(|(email, _)| email == "second-user@example.com")
        );
        assert!(initial_users.iter().any(|(email, account)| {
            email == "first-user@example.com"
                && account
                    .as_ref()
                    .is_some_and(|account| account.flow.is_empty())
        }));
        assert!(initial_users.iter().any(|(email, account)| {
            email == "second-user@example.com"
                && account
                    .as_ref()
                    .is_some_and(|account| account.flow == "xtls-rprx-vision")
        }));

        let initial_count = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users count failed")
            .into_inner();
        assert_eq!(initial_count.count, 2);

        let email = unique_tag("vless-user");
        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: email.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: VlessAccountPayload {
                        id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                        flow: String::new(),
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
            .expect("vless add user should succeed");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users after add failed")
            .into_inner()
            .users
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(users_after_add.len(), 3);
        let added_user = users_after_add
            .iter()
            .find(|user| user.email == email)
            .expect("added vless user should be returned");
        let account = added_user
            .account
            .as_ref()
            .expect("returned vless user should include account");
        assert_eq!(account.r#type, TYPE_PROXY_VLESS_ACCOUNT);

        let count_after_add = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users count after add failed")
            .into_inner();
        assert_eq!(count_after_add.count, 3);

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
            .expect("vless remove user should succeed");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users after remove failed")
            .into_inner()
            .users
            .into_iter()
            .map(|user| user.email)
            .collect::<Vec<_>>();
        assert_eq!(users_after_remove.len(), 2);
        assert!(
            !users_after_remove
                .iter()
                .any(|candidate| candidate == &email)
        );

        let count_after_remove = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .expect("vless get users count after remove failed")
            .into_inner();
        assert_eq!(count_after_remove.count, 2);
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_node_style_flow_on_empty_vless_inbound() {
        let inbound_tag = unique_tag("debug-vless");
        let username = unique_tag("debug-user");
        let user_id = "218b98f5-df92-43f9-8880-3be70912d79c".to_string();
        let inbound_port = free_localhost_port();

        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                inbound_port,
            )),
            protocol: ServerProxyConfig::Vless {
                users: vec![],
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound.clone()], Vec::new());
        let handles = start_servers(inbound, runtime.clone())
            .await
            .expect("start empty vless inbound");
        runtime.register_inbound_tasks(&inbound_tag, handles);
        let service = HandlerServiceImpl::new(runtime.clone());

        let users_before_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users before add failed")
            .into_inner()
            .users;
        assert!(users_before_add.is_empty());

        let count_before_add = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users count before add failed")
            .into_inner();
        assert_eq!(count_before_add.count, 0);

        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: username.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: VlessAccountPayload {
                        id: user_id.clone(),
                        flow: String::new(),
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
            .expect("node-style add user should succeed");
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, inbound_port))
            .await
            .expect("vless listener should remain available after adding a user");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users after add failed")
            .into_inner()
            .users;
        assert_eq!(users_after_add.len(), 1);
        assert_eq!(users_after_add[0].email, username);
        let account_after_add = users_after_add[0]
            .account
            .as_ref()
            .expect("node-style returned user should include account");
        assert_eq!(account_after_add.r#type, TYPE_PROXY_VLESS_ACCOUNT);
        let decoded_account =
            VlessAccountPayload::decode(account_after_add.value.as_slice())
                .expect("decode vless account from node-style response");
        assert_eq!(decoded_account.id, user_id);
        assert_eq!(decoded_account.flow, "");

        let count_after_add = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users count after add failed")
            .into_inner();
        assert_eq!(count_after_add.count, 1);

        let remove_operation =
            proto::xray::app::proxyman::command::RemoveUserOperation {
                email: users_after_add[0].email.clone(),
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
            .expect("node-style remove user should succeed");
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, inbound_port))
            .await
            .expect("vless listener should remain available after removing a user");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users after remove failed")
            .into_inner()
            .users;
        assert!(users_after_remove.is_empty());

        let count_after_remove = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users count after remove failed")
            .into_inner();
        assert_eq!(count_after_remove.count, 0);
        runtime.stop_inbound_tasks(&inbound_tag).await;
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
    async fn handler_alter_inbound_rejects_socks_user_manager_operations() {
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
            .expect_err("SOCKS should not expose Xray UserManager mutations");
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

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria_user_reads_include_empty_email_and_select_one_duplicate() {
        let service =
            HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
        let config: Hysteria2ServerConfig =
            serde_json::from_value(serde_json::json!({
                "clients": [
                    {
                        "password": "transport-fallback",
                        "email": null,
                        "xray_transport_auth_fallback": true
                    },
                    {"password": "empty-email-auth", "email": null, "level": 7},
                    {"password": "auth-a", "email": "shared@example.com", "level": 3},
                    {"password": "auth-b", "email": "shared@example.com", "level": 4}
                ],
                "xrayCompat": true
            }))
            .expect("valid Hysteria2 user-manager config");
        let protocol = ServerProxyConfig::Hysteria2 { config };

        let users = service
            .get_user_manager_users(&protocol)
            .expect("Hysteria2 should expose a user manager");
        assert_eq!(users.len(), 3, "transport fallback must stay hidden");
        assert!(
            users
                .iter()
                .any(|user| user.email.is_empty() && user.level == 7),
            "Xray GetUsers includes empty-email validators and preserves level"
        );
        assert_eq!(
            users
                .iter()
                .filter(|user| user.email == "shared@example.com")
                .count(),
            2,
            "duplicate emails remain distinct auth-keyed users"
        );

        let identities = service
            .get_user_manager_identities(&protocol)
            .expect("Hysteria2 should expose a user count");
        assert_eq!(identities.len(), 3);
        assert!(identities.iter().any(String::is_empty));

        let selected = HandlerServiceImpl::select_user_manager_users(
            users,
            "shared@example.com",
        );
        assert_eq!(
            selected.len(),
            1,
            "Xray email-specific GetInboundUsers returns one GetUser result"
        );
        assert!(matches!(selected[0].level, 3 | 4));

        let dynamic = service
            .parse_hysteria_client(&proto::xray::common::protocol::User {
                level: 9,
                email: String::new(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                    value: HysteriaAccountPayload {
                        auth: String::new(),
                    }
                    .encode_to_vec(),
                }),
            })
            .expect("Xray Hysteria AddUser permits empty email/auth fields");
        assert_eq!(dynamic.password, "");
        assert_eq!(dynamic.email, None);
        assert_eq!(dynamic.level, 9);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria_user_mutations_match_xray_auth_key_semantics() {
        let service =
            HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
        let mut protocol = ServerProxyConfig::Hysteria2 {
            config: Hysteria2ServerConfig {
                clients: vec![Hysteria2Client {
                    password: "transport-fallback".to_string(),
                    email: None,
                    level: 0,
                    xray_uuid_route: false,
                    xray_transport_auth_fallback: true,
                }],
                bandwidth: Hysteria2BandwidthConfig::default(),
                ignore_client_bandwidth: false,
                udp_enabled: true,
                xray_compat: true,
                xray_masquerade_string: None,
                xray_masquerade_file: None,
                xray_masquerade_proxy: None,
                xray_congestion: None,
                xray_bbr_profile: None,
                xray_brutal_up: None,
                xray_brutal_down: None,
                xray_max_idle_timeout_secs: None,
                xray_keep_alive_period_secs: None,
                xray_udp_idle_timeout_secs: None,
                xray_max_incoming_streams: None,
                xray_init_stream_receive_window: None,
                xray_max_stream_receive_window: None,
                xray_init_connection_receive_window: None,
                xray_max_connection_receive_window: None,
                xray_disable_path_mtu_discovery: None,
            },
        };
        let user = |email: &str, auth: &str| proto::xray::common::protocol::User {
            level: 0,
            email: email.to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                value: HysteriaAccountPayload {
                    auth: auth.to_string(),
                }
                .encode_to_vec(),
            }),
        };

        service
            .apply_add_user_to_protocol(
                &mut protocol,
                &user("shared@example.com", "auth-a"),
            )
            .expect("add first duplicate-email user");
        service
            .apply_add_user_to_protocol(
                &mut protocol,
                &user("shared@example.com", "auth-b"),
            )
            .expect("add second duplicate-email user");

        let ServerProxyConfig::Hysteria2 { config } = &protocol else {
            unreachable!("test protocol is hysteria2");
        };
        assert_eq!(
            config
                .clients
                .iter()
                .filter(
                    |client| client.email.as_deref() == Some("shared@example.com")
                )
                .count(),
            2,
            "Xray allows different auth keys to share one email"
        );
        assert!(
            config
                .clients
                .iter()
                .any(|client| client.xray_transport_auth_fallback),
            "dynamic user updates must preserve transport fallback"
        );

        assert!(
            service
                .apply_remove_user_from_protocol(&mut protocol, "shared@example.com")
                .expect("remove one duplicate-email user")
        );
        let ServerProxyConfig::Hysteria2 { config } = &protocol else {
            unreachable!("test protocol is hysteria2");
        };
        assert_eq!(
            config
                .clients
                .iter()
                .filter(
                    |client| client.email.as_deref() == Some("shared@example.com")
                )
                .count(),
            1,
            "Xray DelByEmail removes one matching auth entry, not all"
        );

        service
            .apply_add_user_to_protocol(
                &mut protocol,
                &user("replacement@example.com", "auth-b"),
            )
            .expect("replace existing auth key");
        let ServerProxyConfig::Hysteria2 { config } = &protocol else {
            unreachable!("test protocol is hysteria2");
        };
        assert_eq!(
            config
                .clients
                .iter()
                .filter(|client| !client.xray_transport_auth_fallback)
                .count(),
            1,
            "re-adding the same auth must replace its prior validator entry"
        );
        let auth_b = config
            .clients
            .iter()
            .find(|client| {
                client.password == "auth-b" && !client.xray_transport_auth_fallback
            })
            .expect("replacement auth should remain");
        assert_eq!(auth_b.email.as_deref(), Some("replacement@example.com"));
        assert!(
            service
                .apply_remove_user_from_protocol(
                    &mut protocol,
                    "missing@example.com"
                )
                .expect("missing Hysteria user removal should remain idempotent"),
            "Xray treats a Hysteria remove miss as a handled no-op"
        );
    }

    #[cfg(feature = "hysteria")]
    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_hysteria_users() {
        let inbound_tag = unique_tag("hysteria-inbound");
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                1093,
            )),
            protocol: ServerProxyConfig::Hysteria2 {
                config: Hysteria2ServerConfig {
                    clients: vec![Hysteria2Client {
                        password: "initial-auth".to_string(),
                        email: Some("initial-user".to_string()),
                        level: 0,
                        xray_uuid_route: true,
                        xray_transport_auth_fallback: false,
                    }],
                    bandwidth: Hysteria2BandwidthConfig::default(),
                    ignore_client_bandwidth: false,
                    udp_enabled: true,
                    xray_compat: false,
                    xray_masquerade_string: None,
                    xray_masquerade_file: None,
                    xray_masquerade_proxy: None,
                    xray_congestion: None,
                    xray_bbr_profile: None,
                    xray_brutal_up: None,
                    xray_brutal_down: None,
                    xray_max_idle_timeout_secs: None,
                    xray_keep_alive_period_secs: None,
                    xray_udp_idle_timeout_secs: None,
                    xray_max_incoming_streams: None,
                    xray_init_stream_receive_window: None,
                    xray_max_stream_receive_window: None,
                    xray_init_connection_receive_window: None,
                    xray_max_connection_receive_window: None,
                    xray_disable_path_mtu_discovery: None,
                },
            },
            transport: Transport::Quic,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime.clone());
        let email = unique_tag("hysteria-user");
        let auth = " added-auth ";

        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: email.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                    value: HysteriaAccountPayload {
                        auth: auth.to_string(),
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
            .expect("hysteria add user should succeed");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag.clone(),
                    email: email.clone(),
                },
            ))
            .await
            .expect("hysteria get users after add failed")
            .into_inner()
            .users;
        assert_eq!(users_after_add.len(), 1);
        let account = users_after_add[0]
            .account
            .as_ref()
            .expect("hysteria user should include an account");
        assert_eq!(account.r#type, TYPE_PROXY_HYSTERIA_ACCOUNT);
        let account = HysteriaAccountPayload::decode(account.value.as_slice())
            .expect("decode hysteria account");
        assert_eq!(account.auth, auth);
        let updated = runtime
            .inbound_by_tag(&inbound_tag)
            .expect("updated hysteria inbound should remain registered");
        let ServerProxyConfig::Hysteria2 { config } = updated.protocol else {
            panic!("expected hysteria2 inbound");
        };
        let added_client = config
            .clients
            .iter()
            .find(|client| client.email.as_deref() == Some(email.as_str()))
            .expect("added hysteria user should be in runtime config");
        assert!(!added_client.xray_transport_auth_fallback);

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
            .expect("hysteria remove user should succeed");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: inbound_tag,
                    email,
                },
            ))
            .await
            .expect("hysteria get users after remove failed")
            .into_inner()
            .users;
        assert!(users_after_remove.is_empty());
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
