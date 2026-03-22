use tonic::{Request, Response, Status};

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
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_INBOUND_CONFIG: &str = "xray.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.vless.Account";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG: &str = "xray.proxy.trojan.ServerConfig";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ServerConfig";
const TYPE_PROXY_FREEDOM_CONFIG: &str = "xray.proxy.freedom.Config";
const TYPE_PROXY_FREEDOM_CONFIG_V2RAY: &str = "v2ray.core.proxy.freedom.Config";
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
}

#[derive(Clone, PartialEq, Message)]
struct FreedomConfigPayload {}

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
                    .collect();

                Ok(ServerProxyConfig::Socks { accounts })
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
        Ok(ServerProxyConfig::Vless { users })
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
            fallbacks.push(crate::config::server_config::TrojanFallback { dest });
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
                let mut headers = websocket.header;
                if !websocket.host.trim().is_empty() {
                    headers
                        .entry("Host".to_string())
                        .or_insert(websocket.host.clone());
                }
                protocol = ServerProxyConfig::Websocket {
                    targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                        matching_path: (!websocket.path.is_empty())
                            .then_some(websocket.path),
                        matching_headers: (!headers.is_empty()).then_some(headers),
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
                if server_names.is_empty() {
                    if let Some(hostname) = dest.address().hostname() {
                        server_names.push(hostname.to_string());
                    }
                }
                Ok(ServerProxyConfig::Reality(RealityTransportConfig {
                    dest,
                    private_key,
                    short_ids,
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
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users } => {
                let user = self.parse_vless_user(user)?;
                if let Some(existing) = users
                    .iter_mut()
                    .find(|existing| existing.user_label == user.user_label)
                {
                    existing.user_id = user.user_id;
                } else {
                    users.push(user);
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

        Err(Status::unknown(ERR_PROXY_NOT_USER_MANAGER))
    }

    fn apply_remove_user_from_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        email: &str,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users } => {
                let before = users.len();
                users.retain(|user| user.user_label != email);
                Ok(before != users.len())
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
            ServerProxyConfig::Vless { users } => {
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
            ServerProxyConfig::DokodemoDoor { .. } => None,
        }
    }

    fn get_user_manager_users(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<proto::xray::common::protocol::User>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users } => Some(
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
                    .filter_map(|client| client.email.clone())
                    .map(|email| self.build_user(email))
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
            ServerProxyConfig::Socks { .. } => None,
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
        let request = request.into_inner();
        let inbound = request
            .inbound
            .ok_or_else(|| Status::invalid_argument("inbound is required"))?;
        let inbound = self.parse_add_inbound(inbound)?;
        let inbound_tag = inbound.tag.clone();
        self.runtime
            .add_inbound(inbound.clone())
            .map_err(Status::already_exists)?;

        let handles = start_servers(inbound).await.map_err(|err| {
            Status::unknown(format!("failed to start inbound handler: {err}"))
        })?;
        self.runtime.register_inbound_tasks(&inbound_tag, &handles);

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
        self.runtime.abort_inbound_tasks(&request.tag);
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
            .get_user_manager_users(&inbound.protocol)
            .ok_or_else(|| Status::unknown(ERR_PROXY_NOT_USER_MANAGER))?
            .into_iter()
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
    #[cfg(feature = "vless")]
    use crate::config::server_config::VlessUser;
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            server_config::{ServerConfig, SocksUser},
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
        users: Vec<String>,
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
                        stream_settings: None,
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
                    id: "11111111-1111-1111-1111-111111111111".to_string(),
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
                                header: Default::default(),
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
                            assert_eq!(
                                target
                                    .matching_headers
                                    .as_ref()
                                    .and_then(|headers| headers.get("Host"))
                                    .map(String::as_str),
                                Some("example.com")
                            );
                            match &target.protocol {
                                ServerProxyConfig::Vless { users } => {
                                    assert_eq!(users.len(), 1);
                                    assert_eq!(
                                        users[0].user_id,
                                        "11111111-1111-1111-1111-111111111111"
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
                        user_id: "11111111-1111-1111-1111-111111111111".to_string(),
                        user_label: "first-user@example.com".to_string(),
                        flow: String::new(),
                    },
                    VlessUser {
                        user_id: "22222222-2222-2222-2222-222222222222".to_string(),
                        user_label: "second-user@example.com".to_string(),
                        flow: "xtls-rprx-vision".to_string(),
                    },
                ],
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
            .into_iter()
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
                        id: "33333333-3333-3333-3333-333333333333".to_string(),
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
        let user_id = "33333333-3333-4333-8333-333333333333".to_string();

        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                12080,
            )),
            protocol: ServerProxyConfig::Vless { users: vec![] },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);

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
                    tag: inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .expect("empty vless get users count after remove failed")
            .into_inner();
        assert_eq!(count_after_remove.count, 0);
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
