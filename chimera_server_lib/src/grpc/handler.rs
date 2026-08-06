use tonic::{Request, Response, Status};

#[cfg(feature = "grpc_transport")]
use crate::config::def::OutboundGrpcSettings;
#[cfg(feature = "httpupgrade")]
use crate::config::def::OutboundHttpUpgradeSettings;
#[cfg(feature = "reality")]
use crate::config::def::OutboundRealitySettings;
#[cfg(feature = "ws")]
use crate::config::def::OutboundWebsocketSettings;
#[cfg(feature = "tls")]
use crate::config::def::{OutboundTlsCertificate, OutboundTlsSettings};
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
use crate::handler::vmess::client::format_vmess_user_id;
#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;
use crate::{
    address::{Address, BindLocation, NetLocation},
    beginning::start_servers,
    config::def::OutboundStreamSettings,
    config::{
        Transport,
        server_config::{
            ServerConfig, ServerProxyConfig, SocksUser,
            collect_xhttp_settings_from_json,
        },
    },
    outbound_registry::OutboundConnectorKind,
    runtime::{OutboundSummary, RuntimeState},
};
#[cfg(feature = "reality")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
const TYPE_APP_SENDER_CONFIG: &str = "xray.app.proxyman.SenderConfig";
const TYPE_APP_SENDER_CONFIG_V2RAY: &str = "v2ray.core.app.proxyman.SenderConfig";
const TYPE_PROXY_HTTP_CLIENT_CONFIG: &str = "xray.proxy.http.ClientConfig";
const TYPE_PROXY_HTTP_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.http.ClientConfig";
const TYPE_PROXY_HTTP_ACCOUNT: &str = "xray.proxy.http.Account";
const TYPE_PROXY_HTTP_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.http.Account";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG: &str =
    "xray.proxy.shadowsocks.ClientConfig";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.shadowsocks.ClientConfig";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_ACCOUNT: &str = "xray.proxy.shadowsocks.Account";
#[cfg(feature = "shadowsocks")]
const TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.shadowsocks.Account";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG: &str = "xray.proxy.socks.ClientConfig";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ClientConfig";
const TYPE_PROXY_SOCKS_SERVER_CONFIG: &str = "xray.proxy.socks.ServerConfig";
const TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ServerConfig";
const TYPE_PROXY_SOCKS_ACCOUNT: &str = "xray.proxy.socks.Account";
const TYPE_PROXY_SOCKS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.socks.Account";
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
const TYPE_PROXY_VMESS_OUTBOUND_CONFIG: &str = "xray.proxy.vmess.outbound.Config";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_OUTBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vmess.outbound.Config";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_ACCOUNT: &str = "xray.proxy.vmess.Account";
#[cfg(feature = "vmess")]
const TYPE_PROXY_VMESS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.vmess.Account";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_OUTBOUND_CONFIG: &str = "xray.proxy.vless.outbound.Config";
#[cfg(feature = "vless")]
const TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.outbound.Config";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_CLIENT_CONFIG: &str = "xray.proxy.trojan.ClientConfig";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ClientConfig";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG: &str = "xray.proxy.trojan.ServerConfig";
#[cfg(feature = "trojan")]
const TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ServerConfig";
const TYPE_PROXY_FREEDOM_CONFIG: &str = "xray.proxy.freedom.Config";
const TYPE_PROXY_FREEDOM_CONFIG_V2RAY: &str = "v2ray.core.proxy.freedom.Config";
const TYPE_PROXY_BLACKHOLE_CONFIG: &str = "xray.proxy.blackhole.Config";
const TYPE_PROXY_BLACKHOLE_CONFIG_V2RAY: &str = "v2ray.core.proxy.blackhole.Config";
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
#[cfg(feature = "httpupgrade")]
const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG: &str =
    "xray.transport.internet.httpupgrade.Config";
#[cfg(feature = "httpupgrade")]
const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.httpupgrade.Config";
#[cfg(feature = "grpc_transport")]
const TYPE_TRANSPORT_GRPC_CONFIG: &str =
    "xray.transport.internet.grpc.encoding.Config";
#[cfg(feature = "grpc_transport")]
const TYPE_TRANSPORT_GRPC_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.grpc.encoding.Config";
const TYPE_TRANSPORT_SPLITHTTP_CONFIG: &str =
    "xray.transport.internet.splithttp.Config";
const TYPE_TRANSPORT_SPLITHTTP_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.splithttp.Config";
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

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    server: Option<TrojanServerEndpointPayload>,
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
struct TrojanServerEndpointPayload {
    #[prost(message, optional, tag = "1")]
    address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    port: u32,
    #[prost(message, optional, tag = "3")]
    user: Option<proto::xray::common::protocol::User>,
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
}

#[derive(Clone, PartialEq, Message)]
struct HttpAccountPayload {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

#[derive(Clone, PartialEq, Message)]
struct HttpClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    server: Option<SocksServerEndpointPayload>,
    #[prost(message, repeated, tag = "2")]
    header: Vec<HttpHeaderPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct HttpHeaderPayload {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(string, tag = "2")]
    value: String,
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
struct ShadowsocksClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    server: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct SocksAccountPayload {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

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

#[derive(Clone, PartialEq, Message)]
struct SenderConfigPayload {
    #[prost(message, optional, tag = "1")]
    via: Option<IpOrDomainPayload>,
    #[prost(message, optional, tag = "2")]
    stream_settings: Option<SenderStreamConfigPayload>,
    #[prost(message, optional, tag = "3")]
    proxy_settings: Option<SenderProxyConfigPayload>,
    #[prost(message, optional, tag = "4")]
    multiplex_settings: Option<SenderMultiplexingConfigPayload>,
    #[prost(string, tag = "5")]
    via_cidr: String,
    #[prost(int32, tag = "6")]
    target_strategy: i32,
}

#[derive(Clone, PartialEq, Message)]
struct SenderProxyConfigPayload {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(bool, tag = "2")]
    transport_layer_proxy: bool,
}

#[derive(Clone, PartialEq, Message)]
struct SenderMultiplexingConfigPayload {
    #[prost(bool, tag = "1")]
    enabled: bool,
    #[prost(int32, tag = "2")]
    concurrency: i32,
    #[prost(int32, tag = "3")]
    xudp_concurrency: i32,
    #[prost(string, tag = "4")]
    xudp_proxy_udp443: String,
}

#[derive(Clone, PartialEq, Message)]
struct SenderStreamConfigPayload {
    #[prost(message, repeated, tag = "2")]
    transport_settings: Vec<TransportConfigPayload>,
    #[prost(string, tag = "3")]
    security_type: String,
    #[prost(message, repeated, tag = "4")]
    security_settings: Vec<proto::xray::common::serial::TypedMessage>,
    #[prost(string, tag = "5")]
    protocol_name: String,
    #[prost(message, optional, tag = "6")]
    socket_settings: Option<OpaqueSenderMessage>,
    #[prost(message, optional, tag = "8")]
    address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "9")]
    port: u32,
    #[prost(message, repeated, tag = "10")]
    udp_masks: Vec<proto::xray::common::serial::TypedMessage>,
    #[prost(message, repeated, tag = "11")]
    tcp_masks: Vec<proto::xray::common::serial::TypedMessage>,
    #[prost(message, optional, tag = "12")]
    quic_params: Option<OpaqueSenderMessage>,
}

#[derive(Clone, PartialEq, Message)]
struct OpaqueSenderMessage {}

#[cfg(feature = "ws")]
#[derive(Clone, PartialEq, Message)]
struct OutboundWebsocketConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(map = "string, string", tag = "3")]
    header: std::collections::HashMap<String, String>,
    #[prost(bool, tag = "4")]
    accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    early_data: u32,
    #[prost(uint32, tag = "6")]
    heartbeat_period: u32,
}

#[cfg(feature = "httpupgrade")]
#[derive(Clone, PartialEq, Message)]
struct OutboundHttpUpgradeConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(map = "string, string", tag = "3")]
    header: std::collections::HashMap<String, String>,
    #[prost(bool, tag = "4")]
    accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    early_data: u32,
}

#[cfg(feature = "grpc_transport")]
#[derive(Clone, PartialEq, Message)]
struct OutboundGrpcConfigPayload {
    #[prost(string, tag = "1")]
    authority: String,
    #[prost(string, tag = "2")]
    service_name: String,
    #[prost(bool, tag = "3")]
    multi_mode: bool,
    #[prost(int32, tag = "4")]
    idle_timeout: i32,
    #[prost(int32, tag = "5")]
    health_check_timeout: i32,
    #[prost(bool, tag = "6")]
    permit_without_stream: bool,
    #[prost(int32, tag = "7")]
    initial_windows_size: i32,
    #[prost(string, tag = "8")]
    user_agent: String,
}

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
struct OutboundTlsConfigPayload {
    #[prost(message, repeated, tag = "2")]
    certificate: Vec<OutboundTlsCertificatePayload>,
    #[prost(string, tag = "3")]
    server_name: String,
    #[prost(string, repeated, tag = "4")]
    next_protocol: Vec<String>,
    #[prost(bool, tag = "5")]
    enable_session_resumption: bool,
    #[prost(bool, tag = "6")]
    disable_system_root: bool,
    #[prost(string, tag = "7")]
    min_version: String,
    #[prost(string, tag = "8")]
    max_version: String,
    #[prost(string, tag = "9")]
    cipher_suites: String,
    #[prost(string, tag = "11")]
    fingerprint: String,
    #[prost(bool, tag = "12")]
    reject_unknown_sni: bool,
    #[prost(string, tag = "15")]
    master_key_log: String,
    #[prost(string, repeated, tag = "16")]
    curve_preferences: Vec<String>,
    #[prost(string, repeated, tag = "17")]
    verify_peer_cert_by_name: Vec<String>,
    #[prost(bytes = "vec", tag = "18")]
    ech_server_keys: Vec<u8>,
    #[prost(string, tag = "19")]
    ech_config_list: String,
    #[prost(message, optional, tag = "21")]
    ech_socket_settings: Option<OpaqueSenderMessage>,
    #[prost(bytes = "vec", repeated, tag = "22")]
    pinned_peer_cert_sha256: Vec<Vec<u8>>,
}

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
struct OutboundTlsCertificatePayload {
    #[prost(bytes = "vec", tag = "1")]
    certificate: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    key: Vec<u8>,
    #[prost(int32, tag = "3")]
    usage: i32,
    #[prost(uint64, tag = "4")]
    ocsp_stapling: u64,
    #[prost(string, tag = "5")]
    certificate_path: String,
    #[prost(string, tag = "6")]
    key_path: String,
    #[prost(bool, tag = "7")]
    one_time_loading: bool,
    #[prost(bool, tag = "8")]
    build_chain: bool,
}

#[cfg(feature = "reality")]
#[derive(Clone, PartialEq, Message)]
struct OutboundRealityConfigPayload {
    #[prost(bool, tag = "1")]
    show: bool,
    #[prost(string, tag = "2")]
    dest: String,
    #[prost(string, tag = "3")]
    transport_type: String,
    #[prost(uint64, tag = "4")]
    xver: u64,
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
    #[prost(bytes = "vec", tag = "11")]
    mldsa65_seed: Vec<u8>,
    #[prost(message, optional, tag = "12")]
    limit_fallback_upload: Option<OpaqueSenderMessage>,
    #[prost(message, optional, tag = "13")]
    limit_fallback_download: Option<OpaqueSenderMessage>,
    #[prost(string, tag = "21")]
    fingerprint: String,
    #[prost(string, tag = "22")]
    server_name: String,
    #[prost(bytes = "vec", tag = "23")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "24")]
    short_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "25")]
    mldsa65_verify: Vec<u8>,
    #[prost(string, tag = "26")]
    spider_x: String,
    #[prost(int64, repeated, tag = "27")]
    spider_y: Vec<i64>,
    #[prost(string, tag = "31")]
    master_key_log: String,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessInboundConfigPayload {
    #[prost(message, repeated, tag = "1")]
    clients: Vec<proto::xray::common::protocol::User>,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
struct VmessSecurityConfigPayload {
    #[prost(int32, tag = "1")]
    security_type: i32,
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

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
struct VmessOutboundConfigPayload {
    #[prost(message, optional, tag = "1")]
    receiver: Option<SocksServerEndpointPayload>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessAccountPayload {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    flow: String,
    #[prost(string, tag = "3")]
    encryption: String,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessOutboundConfigPayload {
    #[prost(message, optional, tag = "1")]
    vnext: Option<VlessServerEndpointPayload>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
struct VlessServerEndpointPayload {
    #[prost(message, optional, tag = "1")]
    address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    port: u32,
    #[prost(message, optional, tag = "3")]
    user: Option<proto::xray::common::protocol::User>,
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

#[derive(Clone, PartialEq, Message)]
struct XhttpRangePayload {
    #[prost(int32, tag = "1")]
    from: i32,
    #[prost(int32, tag = "2")]
    to: i32,
}

#[derive(Clone, PartialEq, Message)]
struct XhttpXmuxPayload {
    #[prost(message, optional, tag = "1")]
    max_concurrency: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "2")]
    max_connections: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "3")]
    c_max_reuse_times: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "4")]
    h_max_request_times: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "5")]
    h_max_reusable_secs: Option<XhttpRangePayload>,
    #[prost(int64, tag = "6")]
    h_keep_alive_period: i64,
}

#[derive(Clone, PartialEq, Message)]
struct XhttpConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(string, tag = "3")]
    mode: String,
    #[prost(map = "string, string", tag = "4")]
    headers: std::collections::HashMap<String, String>,
    #[prost(message, optional, tag = "5")]
    x_padding_bytes: Option<XhttpRangePayload>,
    #[prost(bool, tag = "6")]
    no_grpc_header: bool,
    #[prost(bool, tag = "7")]
    no_sse_header: bool,
    #[prost(message, optional, tag = "8")]
    sc_max_each_post_bytes: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "9")]
    sc_min_posts_interval_ms: Option<XhttpRangePayload>,
    #[prost(int64, tag = "10")]
    sc_max_buffered_posts: i64,
    #[prost(message, optional, tag = "11")]
    sc_stream_up_server_secs: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "12")]
    xmux: Option<XhttpXmuxPayload>,
    #[prost(message, optional, tag = "13")]
    download_settings: Option<StreamConfigPayload>,
    #[prost(bool, tag = "14")]
    x_padding_obfs_mode: bool,
    #[prost(string, tag = "15")]
    x_padding_key: String,
    #[prost(string, tag = "16")]
    x_padding_header: String,
    #[prost(string, tag = "17")]
    x_padding_placement: String,
    #[prost(string, tag = "18")]
    x_padding_method: String,
    #[prost(string, tag = "19")]
    uplink_http_method: String,
    #[prost(string, tag = "20")]
    session_id_placement: String,
    #[prost(string, tag = "21")]
    session_id_key: String,
    #[prost(string, tag = "22")]
    seq_placement: String,
    #[prost(string, tag = "23")]
    seq_key: String,
    #[prost(string, tag = "24")]
    uplink_data_placement: String,
    #[prost(string, tag = "25")]
    uplink_data_key: String,
    #[prost(message, optional, tag = "26")]
    uplink_chunk_size: Option<XhttpRangePayload>,
    #[prost(int32, tag = "27")]
    server_max_header_bytes: i32,
    #[prost(string, tag = "28")]
    session_id_table: String,
    #[prost(message, optional, tag = "29")]
    session_id_length: Option<XhttpRangePayload>,
}

fn xhttp_range_json(range: Option<XhttpRangePayload>) -> serde_json::Value {
    range.map_or(
        serde_json::Value::Null,
        |range| serde_json::json!({"from": range.from, "to": range.to}),
    )
}

fn xhttp_xmux_json(xmux: Option<XhttpXmuxPayload>) -> serde_json::Value {
    xmux.map_or(serde_json::Value::Null, |xmux| {
        serde_json::json!({
            "maxConcurrency": xhttp_range_json(xmux.max_concurrency),
            "maxConnections": xhttp_range_json(xmux.max_connections),
            "cMaxReuseTimes": xhttp_range_json(xmux.c_max_reuse_times),
            "hMaxRequestTimes": xhttp_range_json(xmux.h_max_request_times),
            "hMaxReusableSecs": xhttp_range_json(xmux.h_max_reusable_secs),
            "hKeepAlivePeriod": xmux.h_keep_alive_period,
        })
    })
}

fn xhttp_config_json(config: XhttpConfigPayload) -> serde_json::Value {
    let sc_max_buffered_posts =
        (config.sc_max_buffered_posts != 0).then_some(config.sc_max_buffered_posts);
    let download_settings = config.download_settings.map(|_| serde_json::json!({}));
    serde_json::json!({
        "host": config.host,
        "path": config.path,
        "mode": config.mode,
        "headers": config.headers,
        "xPaddingBytes": xhttp_range_json(config.x_padding_bytes),
        "noGRPCHeader": config.no_grpc_header,
        "noSSEHeader": config.no_sse_header,
        "scMaxEachPostBytes": xhttp_range_json(config.sc_max_each_post_bytes),
        "scMinPostsIntervalMs": xhttp_range_json(config.sc_min_posts_interval_ms),
        "scMaxBufferedPosts": sc_max_buffered_posts,
        "scStreamUpServerSecs": xhttp_range_json(config.sc_stream_up_server_secs),
        "xmux": xhttp_xmux_json(config.xmux),
        "downloadSettings": download_settings,
        "xPaddingObfsMode": config.x_padding_obfs_mode,
        "xPaddingKey": config.x_padding_key,
        "xPaddingHeader": config.x_padding_header,
        "xPaddingPlacement": config.x_padding_placement,
        "xPaddingMethod": config.x_padding_method,
        "uplinkHTTPMethod": config.uplink_http_method,
        "sessionIDPlacement": config.session_id_placement,
        "sessionIDKey": config.session_id_key,
        "seqPlacement": config.seq_placement,
        "seqKey": config.seq_key,
        "uplinkDataPlacement": config.uplink_data_placement,
        "uplinkDataKey": config.uplink_data_key,
        "uplinkChunkSize": xhttp_range_json(config.uplink_chunk_size),
        "serverMaxHeaderBytes": config.server_max_header_bytes,
        "sessionIDTable": config.session_id_table,
        "sessionIDLength": xhttp_range_json(config.session_id_length),
    })
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
                        socks.auth_type != 0,
                    );

                Ok(ServerProxyConfig::Socks {
                    accounts,
                    udp_enabled: false,
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
            user_level: user.level,
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
            "xhttp" | "splithttp" => {
                let transport = stream_settings
                    .transport_settings
                    .iter()
                    .find_map(|item| {
                        let name = item.protocol_name.trim().to_ascii_lowercase();
                        (name == "xhttp" || name == "splithttp")
                            .then_some(item.settings.as_ref())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "xhttp transport settings are required",
                        )
                    })?;
                let xhttp = self.decode_typed_message::<XhttpConfigPayload>(
                    transport,
                    &[
                        TYPE_TRANSPORT_SPLITHTTP_CONFIG,
                        TYPE_TRANSPORT_SPLITHTTP_CONFIG_V2RAY,
                    ],
                    "xhttp transport settings",
                )?;
                let config =
                    collect_xhttp_settings_from_json(xhttp_config_json(xhttp))
                        .map_err(|error| {
                            Status::invalid_argument(format!(
                                "invalid xhttp transport settings: {error}"
                            ))
                        })?;
                protocol = ServerProxyConfig::Xhttp {
                    config,
                    inner: Box::new(protocol),
                };
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

    fn parse_outbound_sender_settings(
        &self,
        sender_settings: Option<&proto::xray::common::serial::TypedMessage>,
    ) -> Result<OutboundStreamSettings, Status> {
        let mut output = OutboundStreamSettings {
            network: "tcp".to_string(),
            security: Some("none".to_string()),
            ..OutboundStreamSettings::default()
        };
        let Some(sender_settings) = sender_settings else {
            return Ok(output);
        };
        let sender = self.decode_typed_message::<SenderConfigPayload>(
            sender_settings,
            &[TYPE_APP_SENDER_CONFIG, TYPE_APP_SENDER_CONFIG_V2RAY],
            "outbound sender settings",
        )?;
        if sender.via.is_some() {
            return Err(Status::invalid_argument(
                "outbound SenderConfig.via is not supported yet",
            ));
        }
        if sender.proxy_settings.is_some() {
            return Err(Status::invalid_argument(
                "outbound SenderConfig.proxy_settings is not supported yet",
            ));
        }
        if sender.multiplex_settings.is_some() {
            return Err(Status::invalid_argument(
                "outbound SenderConfig.multiplex_settings is not supported yet",
            ));
        }
        if !sender.via_cidr.trim().is_empty() {
            return Err(Status::invalid_argument(
                "outbound SenderConfig.via_cidr is not supported yet",
            ));
        }
        if sender.target_strategy != 0 {
            return Err(Status::invalid_argument(
                "outbound SenderConfig.target_strategy currently requires AsIs",
            ));
        }

        let stream = sender.stream_settings.unwrap_or_default();
        if stream.address.is_some()
            || stream.port != 0
            || stream.socket_settings.is_some()
            || stream.quic_params.is_some()
            || !stream.udp_masks.is_empty()
            || !stream.tcp_masks.is_empty()
        {
            return Err(Status::invalid_argument(
                "outbound SenderConfig stream address/port/socket/mask/quic fields are not supported yet",
            ));
        }

        output.network =
            match stream.protocol_name.trim().to_ascii_lowercase().as_str() {
                "" | "tcp" => {
                    if !stream.transport_settings.is_empty() {
                        return Err(Status::invalid_argument(
                            "outbound TCP transport settings are not supported yet",
                        ));
                    }
                    "tcp".to_string()
                }
                #[cfg(feature = "ws")]
                "ws" | "websocket" => {
                    let typed = self.single_sender_transport_setting(
                        &stream,
                        &["ws", "websocket"],
                        "websocket",
                    )?;
                    let settings = self
                        .decode_typed_message::<OutboundWebsocketConfigPayload>(
                            typed,
                            &[
                                TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                                TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY,
                            ],
                            "outbound websocket transport settings",
                        )?;
                    if settings.early_data != 0 {
                        return Err(Status::invalid_argument(
                            "outbound websocket early data is not supported yet",
                        ));
                    }
                    output.ws_settings = Some(OutboundWebsocketSettings {
                        host: (!settings.host.trim().is_empty())
                            .then_some(settings.host),
                        path: (!settings.path.trim().is_empty())
                            .then_some(settings.path),
                        headers: settings.header,
                        accept_proxy_protocol: settings.accept_proxy_protocol,
                        heartbeat_period: settings.heartbeat_period,
                    });
                    "ws".to_string()
                }
                #[cfg(feature = "httpupgrade")]
                "httpupgrade" => {
                    let typed = self.single_sender_transport_setting(
                        &stream,
                        &["httpupgrade"],
                        "httpupgrade",
                    )?;
                    let settings = self
                        .decode_typed_message::<OutboundHttpUpgradeConfigPayload>(
                            typed,
                            &[
                                TYPE_TRANSPORT_HTTPUPGRADE_CONFIG,
                                TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY,
                            ],
                            "outbound HTTP Upgrade transport settings",
                        )?;
                    if settings.early_data != 0 {
                        return Err(Status::invalid_argument(
                            "outbound HTTP Upgrade early data is not supported yet",
                        ));
                    }
                    output.httpupgrade_settings =
                        Some(OutboundHttpUpgradeSettings {
                            host: (!settings.host.trim().is_empty())
                                .then_some(settings.host),
                            path: (!settings.path.trim().is_empty())
                                .then_some(settings.path),
                            headers: settings.header,
                            accept_proxy_protocol: settings.accept_proxy_protocol,
                        });
                    "httpupgrade".to_string()
                }
                #[cfg(feature = "grpc_transport")]
                "grpc" => {
                    let typed = self.single_sender_transport_setting(
                        &stream,
                        &["grpc"],
                        "grpc",
                    )?;
                    let settings = self
                        .decode_typed_message::<OutboundGrpcConfigPayload>(
                            typed,
                            &[
                                TYPE_TRANSPORT_GRPC_CONFIG,
                                TYPE_TRANSPORT_GRPC_CONFIG_V2RAY,
                            ],
                            "outbound gRPC transport settings",
                        )?;
                    output.grpc_settings = Some(OutboundGrpcSettings {
                        authority: (!settings.authority.trim().is_empty())
                            .then_some(settings.authority),
                        service_name: (!settings.service_name.trim().is_empty())
                            .then_some(settings.service_name),
                        multi_mode: settings.multi_mode,
                        idle_timeout: u32::try_from(settings.idle_timeout).map_err(
                            |_| {
                                Status::invalid_argument(
                                    "gRPC idle_timeout must not be negative",
                                )
                            },
                        )?,
                        health_check_timeout: u32::try_from(
                            settings.health_check_timeout,
                        )
                        .map_err(|_| {
                            Status::invalid_argument(
                                "gRPC health_check_timeout must not be negative",
                            )
                        })?,
                        permit_without_stream: settings.permit_without_stream,
                        initial_windows_size: u32::try_from(
                            settings.initial_windows_size,
                        )
                        .map_err(|_| {
                            Status::invalid_argument(
                                "gRPC initial_windows_size must not be negative",
                            )
                        })?,
                        user_agent: (!settings.user_agent.trim().is_empty())
                            .then_some(settings.user_agent),
                    });
                    "grpc".to_string()
                }
                unsupported => {
                    return Err(Status::invalid_argument(format!(
                        "unsupported outbound sender network: {unsupported}"
                    )));
                }
            };

        output.security = Some(
            match stream.security_type.trim().to_ascii_lowercase().as_str() {
                "" | "none" => {
                    if !stream.security_settings.is_empty() {
                        return Err(Status::invalid_argument(
                            "outbound security settings require a supported security_type",
                        ));
                    }
                    "none".to_string()
                }
                #[cfg(feature = "tls")]
                "tls"
                | TYPE_TRANSPORT_TLS_CONFIG
                | TYPE_TRANSPORT_TLS_CONFIG_V2RAY => {
                    let typed = self.single_sender_security_setting(
                        &stream,
                        &[
                            TYPE_TRANSPORT_TLS_CONFIG,
                            TYPE_TRANSPORT_TLS_CONFIG_V2RAY,
                        ],
                        "tls",
                    )?;
                    output.tls_settings =
                        Some(self.parse_outbound_tls_settings(typed)?);
                    "tls".to_string()
                }
                #[cfg(feature = "reality")]
                "reality" | TYPE_TRANSPORT_REALITY_CONFIG => {
                    let typed = self.single_sender_security_setting(
                        &stream,
                        &[TYPE_TRANSPORT_REALITY_CONFIG],
                        "reality",
                    )?;
                    output.reality_settings =
                        Some(self.parse_outbound_reality_settings(typed)?);
                    "reality".to_string()
                }
                unsupported => {
                    return Err(Status::invalid_argument(format!(
                        "unsupported outbound sender security: {unsupported}"
                    )));
                }
            },
        );
        Ok(output)
    }

    fn single_sender_transport_setting<'a>(
        &self,
        stream: &'a SenderStreamConfigPayload,
        accepted_names: &[&str],
        label: &str,
    ) -> Result<&'a proto::xray::common::serial::TypedMessage, Status> {
        let mut selected = None;
        for transport in &stream.transport_settings {
            let name = transport.protocol_name.trim().to_ascii_lowercase();
            if !accepted_names.contains(&name.as_str()) {
                return Err(Status::invalid_argument(format!(
                    "unexpected outbound transport settings for {name}"
                )));
            }
            if selected.is_some() {
                return Err(Status::invalid_argument(format!(
                    "duplicate outbound {label} transport settings"
                )));
            }
            selected = transport.settings.as_ref();
        }
        selected.ok_or_else(|| {
            Status::invalid_argument(format!(
                "outbound {label} transport settings are required"
            ))
        })
    }

    fn single_sender_security_setting<'a>(
        &self,
        stream: &'a SenderStreamConfigPayload,
        accepted_types: &[&str],
        label: &str,
    ) -> Result<&'a proto::xray::common::serial::TypedMessage, Status> {
        let mut selected = None;
        for setting in &stream.security_settings {
            let setting_type = Self::parse_typed_message_type(setting);
            if !accepted_types.contains(&setting_type) {
                return Err(Status::invalid_argument(format!(
                    "unexpected outbound security settings type: {setting_type}"
                )));
            }
            if selected.is_some() {
                return Err(Status::invalid_argument(format!(
                    "duplicate outbound {label} security settings"
                )));
            }
            selected = Some(setting);
        }
        selected.ok_or_else(|| {
            Status::invalid_argument(format!(
                "outbound {label} security settings are required"
            ))
        })
    }

    #[cfg(feature = "tls")]
    fn parse_outbound_tls_settings(
        &self,
        typed: &proto::xray::common::serial::TypedMessage,
    ) -> Result<OutboundTlsSettings, Status> {
        let tls = self.decode_typed_message::<OutboundTlsConfigPayload>(
            typed,
            &[TYPE_TRANSPORT_TLS_CONFIG, TYPE_TRANSPORT_TLS_CONFIG_V2RAY],
            "outbound TLS security settings",
        )?;
        if !tls.cipher_suites.trim().is_empty()
            || tls.reject_unknown_sni
            || !tls.master_key_log.trim().is_empty()
            || !tls.curve_preferences.is_empty()
            || !tls.ech_server_keys.is_empty()
            || tls.ech_socket_settings.is_some()
        {
            return Err(Status::invalid_argument(
                "outbound TLS cipher suites, server-only SNI, key log, curves, and ECH socket settings are not supported yet",
            ));
        }
        if !tls.pinned_peer_cert_sha256.is_empty() {
            return Err(Status::invalid_argument(
                "outbound TLS pinned peer certificates are not supported yet",
            ));
        }
        if tls.verify_peer_cert_by_name.len() > 1 {
            return Err(Status::invalid_argument(
                "outbound TLS verify_peer_cert_by_name accepts at most one value",
            ));
        }

        let certificates = tls
            .certificate
            .into_iter()
            .map(|certificate| {
                if certificate.usage != 1 {
                    return Err(Status::invalid_argument(
                        "outbound TLS certificates must use AUTHORITY_VERIFY",
                    ));
                }
                if !certificate.key.is_empty()
                    || certificate.ocsp_stapling != 0
                    || !certificate.certificate_path.trim().is_empty()
                    || !certificate.key_path.trim().is_empty()
                    || certificate.one_time_loading
                    || certificate.build_chain
                {
                    return Err(Status::invalid_argument(
                        "outbound TLS client keys, file paths, OCSP, one-time loading, and build-chain are not supported yet",
                    ));
                }
                if certificate.certificate.is_empty() {
                    return Err(Status::invalid_argument(
                        "outbound TLS verify certificate must not be empty",
                    ));
                }
                let certificate = String::from_utf8(certificate.certificate)
                    .map_err(|_| Status::invalid_argument(
                        "outbound TLS dynamic certificates currently require PEM text",
                    ))?;
                Ok(OutboundTlsCertificate {
                    certificate_file: None,
                    certificate: vec![certificate],
                    key_file: None,
                    key: Vec::new(),
                    usage: Some("verify".to_string()),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(OutboundTlsSettings {
            allow_insecure: false,
            server_name: (!tls.server_name.trim().is_empty())
                .then_some(tls.server_name),
            alpn: tls.next_protocol,
            enable_session_resumption: tls.enable_session_resumption,
            disable_system_root: tls.disable_system_root,
            min_version: (!tls.min_version.trim().is_empty())
                .then_some(tls.min_version),
            max_version: (!tls.max_version.trim().is_empty())
                .then_some(tls.max_version),
            fingerprint: (!tls.fingerprint.trim().is_empty())
                .then_some(tls.fingerprint),
            pinned_peer_cert_sha256: None,
            verify_peer_cert_by_name: tls
                .verify_peer_cert_by_name
                .into_iter()
                .next(),
            ech_config_list: (!tls.ech_config_list.trim().is_empty())
                .then_some(tls.ech_config_list),
            certificates,
        })
    }

    #[cfg(feature = "reality")]
    fn parse_outbound_reality_settings(
        &self,
        typed: &proto::xray::common::serial::TypedMessage,
    ) -> Result<OutboundRealitySettings, Status> {
        let reality = self.decode_typed_message::<OutboundRealityConfigPayload>(
            typed,
            &[TYPE_TRANSPORT_REALITY_CONFIG],
            "outbound REALITY security settings",
        )?;
        if reality.show
            || !reality.dest.trim().is_empty()
            || !reality.transport_type.trim().is_empty()
            || reality.xver != 0
            || !reality.server_names.is_empty()
            || !reality.private_key.is_empty()
            || !reality.min_client_ver.is_empty()
            || !reality.max_client_ver.is_empty()
            || reality.max_time_diff != 0
            || !reality.short_ids.is_empty()
            || !reality.mldsa65_seed.is_empty()
            || reality.limit_fallback_upload.is_some()
            || reality.limit_fallback_download.is_some()
        {
            return Err(Status::invalid_argument(
                "outbound REALITY sender settings contain server-only fields",
            ));
        }
        if !reality.mldsa65_verify.is_empty()
            || !reality.spider_y.is_empty()
            || !reality.master_key_log.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "outbound REALITY ML-DSA, spiderY, and key-log fields are not supported yet",
            ));
        }
        if reality.public_key.len() != 32 {
            return Err(Status::invalid_argument(
                "outbound REALITY public_key must be exactly 32 bytes",
            ));
        }
        if reality.short_id.len() > 8 {
            return Err(Status::invalid_argument(
                "outbound REALITY short_id must be at most 8 bytes",
            ));
        }
        let short_id = reality
            .short_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(OutboundRealitySettings {
            server_name: (!reality.server_name.trim().is_empty())
                .then_some(reality.server_name),
            public_key: Some(URL_SAFE_NO_PAD.encode(reality.public_key)),
            short_id: (!short_id.is_empty()).then_some(short_id),
            cipher_suites: Vec::new(),
            fingerprint: (!reality.fingerprint.trim().is_empty())
                .then_some(reality.fingerprint),
            spider_x: (!reality.spider_x.trim().is_empty())
                .then_some(reality.spider_x),
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
        let mut literal_settings = None;
        let mut stream_settings = None;
        let protocol = match Self::parse_typed_message_type(proxy_settings) {
            TYPE_PROXY_FREEDOM_CONFIG | TYPE_PROXY_FREEDOM_CONFIG_V2RAY => {
                if outbound.sender_settings.is_some() {
                    return Err(Status::invalid_argument(
                        "freedom outbound sender_settings are not supported yet",
                    ));
                }
                let _ = self.decode_typed_message::<FreedomConfigPayload>(
                    proxy_settings,
                    &[TYPE_PROXY_FREEDOM_CONFIG, TYPE_PROXY_FREEDOM_CONFIG_V2RAY],
                    "outbound proxy settings",
                )?;
                "freedom"
            }
            TYPE_PROXY_BLACKHOLE_CONFIG | TYPE_PROXY_BLACKHOLE_CONFIG_V2RAY => {
                if outbound.sender_settings.is_some() {
                    return Err(Status::invalid_argument(
                        "blackhole outbound sender_settings are not supported yet",
                    ));
                }
                let _ = self.decode_typed_message::<BlackholeConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_BLACKHOLE_CONFIG,
                        TYPE_PROXY_BLACKHOLE_CONFIG_V2RAY,
                    ],
                    "outbound proxy settings",
                )?;
                "blackhole"
            }
            TYPE_PROXY_HTTP_CLIENT_CONFIG | TYPE_PROXY_HTTP_CLIENT_CONFIG_V2RAY => {
                let config = self.decode_typed_message::<HttpClientConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_HTTP_CLIENT_CONFIG,
                        TYPE_PROXY_HTTP_CLIENT_CONFIG_V2RAY,
                    ],
                    "outbound proxy settings",
                )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument("HTTP outbound server is required")
                })?;
                if server.address.is_none() {
                    return Err(Status::invalid_argument(
                        "HTTP outbound server address is required",
                    ));
                }
                let address = self.parse_address(server.address)?;
                let port = u16::try_from(server.port).map_err(|_| {
                    Status::invalid_argument(
                        "HTTP outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "HTTP outbound server port must not be zero",
                    ));
                }
                let users = if let Some(user) = server.user {
                    let account = user.account.as_ref().ok_or_else(|| {
                        Status::invalid_argument(
                            "HTTP outbound user account is required",
                        )
                    })?;
                    let account = self.decode_typed_message::<HttpAccountPayload>(
                        account,
                        &[TYPE_PROXY_HTTP_ACCOUNT, TYPE_PROXY_HTTP_ACCOUNT_V2RAY],
                        "HTTP outbound account",
                    )?;
                    vec![serde_json::json!({
                        "user": account.username,
                        "pass": account.password,
                        "level": user.level,
                        "email": user.email
                    })]
                } else {
                    Vec::new()
                };
                let mut headers = std::collections::HashMap::new();
                for header in config.header {
                    if headers.insert(header.key.clone(), header.value).is_some() {
                        return Err(Status::invalid_argument(format!(
                            "duplicate HTTP outbound header {}",
                            header.key
                        )));
                    }
                }
                literal_settings = Some(serde_json::json!({
                    "servers": [{
                        "address": address.to_string(),
                        "port": port,
                        "users": users
                    }],
                    "headers": headers
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "http"
            }
            #[cfg(feature = "shadowsocks")]
            TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG
            | TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<ShadowsocksClientConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG,
                            TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG_V2RAY,
                        ],
                        "outbound proxy settings",
                    )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument(
                        "Shadowsocks outbound server is required",
                    )
                })?;
                if server.address.is_none() {
                    return Err(Status::invalid_argument(
                        "Shadowsocks outbound server address is required",
                    ));
                }
                let address = self.parse_address(server.address)?;
                let port = u16::try_from(server.port).map_err(|_| {
                    Status::invalid_argument(
                        "Shadowsocks outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "Shadowsocks outbound server port must not be zero",
                    ));
                }
                let user = server.user.ok_or_else(|| {
                    Status::invalid_argument("Shadowsocks outbound user is required")
                })?;
                let account = user.account.as_ref().ok_or_else(|| {
                    Status::invalid_argument(
                        "Shadowsocks outbound user account is required",
                    )
                })?;
                let account = self
                    .decode_typed_message::<ShadowsocksAccountPayload>(
                        account,
                        &[
                            TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                            TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY,
                        ],
                        "Shadowsocks outbound account",
                    )?;
                if account.iv_check {
                    return Err(Status::invalid_argument(
                        "Shadowsocks outbound iv_check is not supported",
                    ));
                }
                let method = match account.cipher_type {
                    5 => "aes-128-gcm",
                    6 => "aes-256-gcm",
                    7 => "chacha20-ietf-poly1305",
                    8 => {
                        return Err(Status::invalid_argument(
                            "Shadowsocks XChaCha20-Poly1305 outbound is not supported",
                        ));
                    }
                    other => {
                        return Err(Status::invalid_argument(format!(
                            "unsupported Shadowsocks outbound cipher type: {other}"
                        )));
                    }
                };
                literal_settings = Some(serde_json::json!({
                    "servers": [{
                        "address": address.to_string(),
                        "port": port,
                        "method": method,
                        "password": account.password,
                        "level": user.level,
                        "email": user.email
                    }]
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "shadowsocks"
            }
            TYPE_PROXY_SOCKS_CLIENT_CONFIG
            | TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY => {
                let config = self.decode_typed_message::<SocksClientConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG,
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY,
                    ],
                    "outbound proxy settings",
                )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument("SOCKS outbound server is required")
                })?;
                if server.address.is_none() {
                    return Err(Status::invalid_argument(
                        "SOCKS outbound server address is required",
                    ));
                }
                let address = self.parse_address(server.address)?;
                let port = u16::try_from(server.port).map_err(|_| {
                    Status::invalid_argument(
                        "SOCKS outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "SOCKS outbound server port must not be zero",
                    ));
                }
                let users = if let Some(user) = server.user {
                    let account = user.account.as_ref().ok_or_else(|| {
                        Status::invalid_argument(
                            "SOCKS outbound user account is required",
                        )
                    })?;
                    let account = self.decode_typed_message::<SocksAccountPayload>(
                        account,
                        &[TYPE_PROXY_SOCKS_ACCOUNT, TYPE_PROXY_SOCKS_ACCOUNT_V2RAY],
                        "SOCKS outbound account",
                    )?;
                    vec![serde_json::json!({
                        "user": account.username,
                        "pass": account.password,
                        "level": user.level,
                        "email": user.email
                    })]
                } else {
                    Vec::new()
                };
                literal_settings = Some(serde_json::json!({
                    "servers": [{
                        "address": address.to_string(),
                        "port": port,
                        "users": users
                    }]
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "socks"
            }
            #[cfg(feature = "trojan")]
            TYPE_PROXY_TROJAN_CLIENT_CONFIG
            | TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<TrojanClientConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_TROJAN_CLIENT_CONFIG,
                            TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY,
                        ],
                        "outbound proxy settings",
                    )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument("Trojan outbound server is required")
                })?;
                if server.address.is_none() {
                    return Err(Status::invalid_argument(
                        "Trojan outbound server address is required",
                    ));
                }
                let address = self.parse_address(server.address)?;
                let port = u16::try_from(server.port).map_err(|_| {
                    Status::invalid_argument(
                        "Trojan outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "Trojan outbound server port must not be zero",
                    ));
                }
                let user = server.user.ok_or_else(|| {
                    Status::invalid_argument("Trojan outbound user is required")
                })?;
                let account = user.account.as_ref().ok_or_else(|| {
                    Status::invalid_argument(
                        "Trojan outbound user account is required",
                    )
                })?;
                let account = self.decode_typed_message::<TrojanAccountPayload>(
                    account,
                    &[TYPE_PROXY_TROJAN_ACCOUNT, TYPE_PROXY_TROJAN_ACCOUNT_V2RAY],
                    "Trojan outbound account",
                )?;
                literal_settings = Some(serde_json::json!({
                    "servers": [{
                        "address": address.to_string(),
                        "port": port,
                        "password": account.password,
                        "level": user.level,
                        "email": user.email
                    }]
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "trojan"
            }
            #[cfg(feature = "vmess")]
            TYPE_PROXY_VMESS_OUTBOUND_CONFIG
            | TYPE_PROXY_VMESS_OUTBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VmessOutboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VMESS_OUTBOUND_CONFIG,
                            TYPE_PROXY_VMESS_OUTBOUND_CONFIG_V2RAY,
                        ],
                        "outbound proxy settings",
                    )?;
                let receiver = config.receiver.ok_or_else(|| {
                    Status::invalid_argument("VMess outbound receiver is required")
                })?;
                if receiver.address.is_none() {
                    return Err(Status::invalid_argument(
                        "VMess outbound server address is required",
                    ));
                }
                let address = self.parse_address(receiver.address)?;
                let port = u16::try_from(receiver.port).map_err(|_| {
                    Status::invalid_argument(
                        "VMess outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "VMess outbound server port must not be zero",
                    ));
                }
                let user = receiver.user.ok_or_else(|| {
                    Status::invalid_argument("VMess outbound user is required")
                })?;
                let account = user.account.as_ref().ok_or_else(|| {
                    Status::invalid_argument(
                        "VMess outbound user account is required",
                    )
                })?;
                let account = self.decode_typed_message::<VmessAccountPayload>(
                    account,
                    &[TYPE_PROXY_VMESS_ACCOUNT, TYPE_PROXY_VMESS_ACCOUNT_V2RAY],
                    "VMess outbound account",
                )?;
                if !account.tests_enabled.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "VMess outbound experiments are not supported",
                    ));
                }
                let security_type = account
                    .security_settings
                    .as_ref()
                    .map(|settings| settings.security_type)
                    .unwrap_or_default();
                let security = match security_type {
                    0 => "none",
                    3 => "aes-128-gcm",
                    4 => "chacha20-poly1305",
                    2 => {
                        return Err(Status::invalid_argument(
                            "VMess outbound requires explicit security instead of auto",
                        ));
                    }
                    other => {
                        return Err(Status::invalid_argument(format!(
                            "unsupported VMess outbound security type: {other}"
                        )));
                    }
                };
                literal_settings = Some(serde_json::json!({
                    "vnext": [{
                        "address": address.to_string(),
                        "port": port,
                        "users": [{
                            "id": account.id,
                            "security": security,
                            "alterId": 0,
                            "experiments": account.tests_enabled,
                            "level": user.level,
                            "email": user.email
                        }]
                    }]
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "vmess"
            }
            #[cfg(feature = "vless")]
            TYPE_PROXY_VLESS_OUTBOUND_CONFIG
            | TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VlessOutboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VLESS_OUTBOUND_CONFIG,
                            TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY,
                        ],
                        "outbound proxy settings",
                    )?;
                let vnext = config.vnext.ok_or_else(|| {
                    Status::invalid_argument("VLESS outbound vnext is required")
                })?;
                if vnext.address.is_none() {
                    return Err(Status::invalid_argument(
                        "VLESS outbound server address is required",
                    ));
                }
                let address = self.parse_address(vnext.address)?;
                let port = u16::try_from(vnext.port).map_err(|_| {
                    Status::invalid_argument(
                        "VLESS outbound server port must fit in u16",
                    )
                })?;
                if port == 0 {
                    return Err(Status::invalid_argument(
                        "VLESS outbound server port must not be zero",
                    ));
                }
                let user = vnext.user.ok_or_else(|| {
                    Status::invalid_argument("VLESS outbound user is required")
                })?;
                let account = user.account.as_ref().ok_or_else(|| {
                    Status::invalid_argument(
                        "VLESS outbound user account is required",
                    )
                })?;
                let account = self.decode_typed_message::<VlessAccountPayload>(
                    account,
                    &[TYPE_PROXY_VLESS_ACCOUNT, TYPE_PROXY_VLESS_ACCOUNT_V2RAY],
                    "VLESS outbound account",
                )?;
                literal_settings = Some(serde_json::json!({
                    "vnext": [{
                        "address": address.to_string(),
                        "port": port,
                        "users": [{
                            "id": account.id,
                            "flow": account.flow,
                            "encryption": account.encryption
                        }]
                    }]
                }));
                stream_settings = Some(self.parse_outbound_sender_settings(
                    outbound.sender_settings.as_ref(),
                )?);
                "vless"
            }
            unsupported => {
                return Err(Status::invalid_argument(format!(
                    "unsupported outbound proxy settings type: {unsupported}"
                )));
            }
        };
        Ok(OutboundSummary {
            tag: outbound.tag,
            protocol: protocol.to_string(),
            settings: literal_settings,
            stream_settings,
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
                                encryption: String::new(),
                            },
                        )),
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_VLESS_INBOUND_CONFIG,
                    VlessInboundConfigPayload { clients },
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
            ServerProxyConfig::Socks { accounts, .. } => {
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

    fn encode_outbound_sender_settings(
        &self,
        stream: Option<&OutboundStreamSettings>,
    ) -> Option<proto::xray::common::serial::TypedMessage> {
        let stream = stream?;
        let network = stream.network.trim().to_ascii_lowercase();
        let mut transport_settings = Vec::new();
        match network.as_str() {
            "" | "tcp" => {}
            #[cfg(feature = "ws")]
            "ws" | "websocket" => {
                let settings = stream.ws_settings.as_ref()?;
                transport_settings.push(TransportConfigPayload {
                    protocol_name: "websocket".to_string(),
                    settings: Some(Self::typed_message(
                        TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                        OutboundWebsocketConfigPayload {
                            host: settings.host.clone().unwrap_or_default(),
                            path: settings.path.clone().unwrap_or_default(),
                            header: settings.headers.clone(),
                            accept_proxy_protocol: settings.accept_proxy_protocol,
                            early_data: 0,
                            heartbeat_period: settings.heartbeat_period,
                        },
                    )),
                });
            }
            #[cfg(feature = "httpupgrade")]
            "httpupgrade" => {
                let settings = stream.httpupgrade_settings.as_ref()?;
                transport_settings.push(TransportConfigPayload {
                    protocol_name: "httpupgrade".to_string(),
                    settings: Some(Self::typed_message(
                        TYPE_TRANSPORT_HTTPUPGRADE_CONFIG,
                        OutboundHttpUpgradeConfigPayload {
                            host: settings.host.clone().unwrap_or_default(),
                            path: settings.path.clone().unwrap_or_default(),
                            header: settings.headers.clone(),
                            accept_proxy_protocol: settings.accept_proxy_protocol,
                            early_data: 0,
                        },
                    )),
                });
            }
            #[cfg(feature = "grpc_transport")]
            "grpc" => {
                let settings = stream.grpc_settings.as_ref()?;
                transport_settings.push(TransportConfigPayload {
                    protocol_name: "grpc".to_string(),
                    settings: Some(Self::typed_message(
                        TYPE_TRANSPORT_GRPC_CONFIG,
                        OutboundGrpcConfigPayload {
                            authority: settings
                                .authority
                                .clone()
                                .unwrap_or_default(),
                            service_name: settings
                                .service_name
                                .clone()
                                .unwrap_or_default(),
                            multi_mode: settings.multi_mode,
                            idle_timeout: i32::try_from(settings.idle_timeout)
                                .ok()?,
                            health_check_timeout: i32::try_from(
                                settings.health_check_timeout,
                            )
                            .ok()?,
                            permit_without_stream: settings.permit_without_stream,
                            initial_windows_size: i32::try_from(
                                settings.initial_windows_size,
                            )
                            .ok()?,
                            user_agent: settings
                                .user_agent
                                .clone()
                                .unwrap_or_default(),
                        },
                    )),
                });
            }
            _ => return None,
        }

        let security_type = stream
            .security
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let mut security_settings = Vec::new();
        match security_type.as_str() {
            "" | "none" => {}
            #[cfg(feature = "tls")]
            "tls" => {
                let settings = stream.tls_settings.as_ref()?;
                security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_TLS_CONFIG,
                    OutboundTlsConfigPayload {
                        certificate: settings
                            .certificates
                            .iter()
                            .map(|certificate| OutboundTlsCertificatePayload {
                                certificate: certificate
                                    .certificate
                                    .join("\n")
                                    .into_bytes(),
                                key: Vec::new(),
                                usage: 1,
                                ocsp_stapling: 0,
                                certificate_path: String::new(),
                                key_path: String::new(),
                                one_time_loading: false,
                                build_chain: false,
                            })
                            .collect(),
                        server_name: settings
                            .server_name
                            .clone()
                            .unwrap_or_default(),
                        next_protocol: settings.alpn.clone(),
                        enable_session_resumption: settings
                            .enable_session_resumption,
                        disable_system_root: settings.disable_system_root,
                        min_version: settings
                            .min_version
                            .clone()
                            .unwrap_or_default(),
                        max_version: settings
                            .max_version
                            .clone()
                            .unwrap_or_default(),
                        cipher_suites: String::new(),
                        fingerprint: settings
                            .fingerprint
                            .clone()
                            .unwrap_or_default(),
                        reject_unknown_sni: false,
                        master_key_log: String::new(),
                        curve_preferences: Vec::new(),
                        verify_peer_cert_by_name: settings
                            .verify_peer_cert_by_name
                            .clone()
                            .into_iter()
                            .collect(),
                        ech_server_keys: Vec::new(),
                        ech_config_list: settings
                            .ech_config_list
                            .clone()
                            .unwrap_or_default(),
                        ech_socket_settings: None,
                        pinned_peer_cert_sha256: Vec::new(),
                    },
                ));
            }
            #[cfg(feature = "reality")]
            "reality" => {
                let settings = stream.reality_settings.as_ref()?;
                let public_key = URL_SAFE_NO_PAD
                    .decode(settings.public_key.as_deref()?)
                    .ok()?;
                let short_id = crate::reality::decode_short_id(
                    settings.short_id.as_deref().unwrap_or_default(),
                )
                .ok()?
                .to_vec();
                security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_REALITY_CONFIG,
                    OutboundRealityConfigPayload {
                        show: false,
                        dest: String::new(),
                        transport_type: String::new(),
                        xver: 0,
                        server_names: Vec::new(),
                        private_key: Vec::new(),
                        min_client_ver: Vec::new(),
                        max_client_ver: Vec::new(),
                        max_time_diff: 0,
                        short_ids: Vec::new(),
                        mldsa65_seed: Vec::new(),
                        limit_fallback_upload: None,
                        limit_fallback_download: None,
                        fingerprint: settings
                            .fingerprint
                            .clone()
                            .unwrap_or_default(),
                        server_name: settings
                            .server_name
                            .clone()
                            .unwrap_or_default(),
                        public_key,
                        short_id,
                        mldsa65_verify: Vec::new(),
                        spider_x: settings.spider_x.clone().unwrap_or_default(),
                        spider_y: Vec::new(),
                        master_key_log: String::new(),
                    },
                ));
            }
            _ => return None,
        }

        Some(Self::typed_message(
            TYPE_APP_SENDER_CONFIG,
            SenderConfigPayload {
                via: None,
                stream_settings: Some(SenderStreamConfigPayload {
                    transport_settings,
                    security_type,
                    security_settings,
                    protocol_name: if network.is_empty() {
                        "tcp".to_string()
                    } else {
                        network
                    },
                    socket_settings: None,
                    address: None,
                    port: 0,
                    udp_masks: Vec::new(),
                    tcp_masks: Vec::new(),
                    quic_params: None,
                }),
                proxy_settings: None,
                multiplex_settings: None,
                via_cidr: String::new(),
                target_strategy: 0,
            },
        ))
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
                "http" => self.runtime.outbound_connector(&outbound.tag).and_then(
                    |connector| match connector.as_ref() {
                        OutboundConnectorKind::HttpTcp(config) => {
                            let mut headers = config
                                .headers
                                .iter()
                                .map(|(key, value)| HttpHeaderPayload {
                                    key: key.clone(),
                                    value: value.clone(),
                                })
                                .collect::<Vec<_>>();
                            headers.sort_by(|left, right| left.key.cmp(&right.key));
                            Some(Self::typed_message(
                                TYPE_PROXY_HTTP_CLIENT_CONFIG,
                                HttpClientConfigPayload {
                                    server: Some(SocksServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: config.credentials.as_ref().map(
                                            |credentials| {
                                                proto::xray::common::protocol::User {
                                                    level: 0,
                                                    email: String::new(),
                                                    account: Some(
                                                        Self::typed_message(
                                                            TYPE_PROXY_HTTP_ACCOUNT,
                                                            HttpAccountPayload {
                                                                username:
                                                                    credentials
                                                                        .username
                                                                        .clone(),
                                                                password:
                                                                    credentials
                                                                        .password
                                                                        .clone(),
                                                            },
                                                        ),
                                                    ),
                                                }
                                            },
                                        ),
                                    }),
                                    header: headers,
                                },
                            ))
                        }
                        _ => None,
                    },
                ),
                #[cfg(feature = "shadowsocks")]
                "shadowsocks" => self
                    .runtime
                    .outbound_connector(&outbound.tag)
                    .and_then(|connector| match connector.as_ref() {
                        OutboundConnectorKind::ShadowsocksTcp(config) => {
                            let cipher_type = match config.method.as_ref() {
                                "aes-128-gcm" => 5,
                                "aes-256-gcm" => 6,
                                "chacha20-ietf-poly1305" => 7,
                                _ => return None,
                            };
                            Some(Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG,
                                ShadowsocksClientConfigPayload {
                                    server: Some(SocksServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: Some(
                                            proto::xray::common::protocol::User {
                                                level: 0,
                                                email: String::new(),
                                                account: Some(Self::typed_message(
                                                    TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                                                    ShadowsocksAccountPayload {
                                                        password: config
                                                            .password
                                                            .to_string(),
                                                        cipher_type,
                                                        iv_check: false,
                                                    },
                                                )),
                                            },
                                        ),
                                    }),
                                },
                            ))
                        }
                        _ => None,
                    }),
                "socks" => self.runtime.outbound_connector(&outbound.tag).and_then(
                    |connector| match connector.as_ref() {
                        OutboundConnectorKind::SocksTcp(config) => {
                            Some(Self::typed_message(
                                TYPE_PROXY_SOCKS_CLIENT_CONFIG,
                                SocksClientConfigPayload {
                                    server: Some(SocksServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: config.credentials.as_ref().map(
                                            |credentials| {
                                                proto::xray::common::protocol::User {
                                                    level: 0,
                                                    email: String::new(),
                                                    account: Some(
                                                        Self::typed_message(
                                                            TYPE_PROXY_SOCKS_ACCOUNT,
                                                            SocksAccountPayload {
                                                                username:
                                                                    credentials
                                                                        .username
                                                                        .clone(),
                                                                password:
                                                                    credentials
                                                                        .password
                                                                        .clone(),
                                                            },
                                                        ),
                                                    ),
                                                }
                                            },
                                        ),
                                    }),
                                },
                            ))
                        }
                        _ => None,
                    },
                ),
                #[cfg(feature = "trojan")]
                "trojan" => self.runtime.outbound_connector(&outbound.tag).and_then(
                    |connector| match connector.as_ref() {
                        OutboundConnectorKind::TrojanTcp(config) => {
                            Some(Self::typed_message(
                                TYPE_PROXY_TROJAN_CLIENT_CONFIG,
                                TrojanClientConfigPayload {
                                    server: Some(TrojanServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: Some(
                                            proto::xray::common::protocol::User {
                                                level: 0,
                                                email: String::new(),
                                                account: Some(Self::typed_message(
                                                    TYPE_PROXY_TROJAN_ACCOUNT,
                                                    TrojanAccountPayload {
                                                        password: config
                                                            .password
                                                            .to_string(),
                                                    },
                                                )),
                                            },
                                        ),
                                    }),
                                },
                            ))
                        }
                        _ => None,
                    },
                ),
                #[cfg(feature = "vmess")]
                "vmess" => self.runtime.outbound_connector(&outbound.tag).and_then(
                    |connector| match connector.as_ref() {
                        OutboundConnectorKind::VmessTcp(config) => {
                            let security_type = match config.security {
                                crate::handler::vmess::client::VmessDataSecurity::None => 0,
                                crate::handler::vmess::client::VmessDataSecurity::Aes128Gcm => 3,
                                crate::handler::vmess::client::VmessDataSecurity::ChaCha20Poly1305 => 4,
                            };
                            Some(Self::typed_message(
                                TYPE_PROXY_VMESS_OUTBOUND_CONFIG,
                                VmessOutboundConfigPayload {
                                    receiver: Some(SocksServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: Some(
                                            proto::xray::common::protocol::User {
                                                level: 0,
                                                email: String::new(),
                                                account: Some(Self::typed_message(
                                                    TYPE_PROXY_VMESS_ACCOUNT,
                                                    VmessAccountPayload {
                                                        id: format_vmess_user_id(
                                                            config.user_uuid,
                                                        ),
                                                        security_settings: Some(
                                                            VmessSecurityConfigPayload {
                                                                security_type,
                                                            },
                                                        ),
                                                        tests_enabled: String::new(),
                                                    },
                                                )),
                                            },
                                        ),
                                    }),
                                },
                            ))
                        }
                        _ => None,
                    },
                ),
                #[cfg(feature = "vless")]
                "vless" => self.runtime.outbound_connector(&outbound.tag).and_then(
                    |connector| match connector.as_ref() {
                        OutboundConnectorKind::VlessTcp(config) => {
                            Some(Self::typed_message(
                                TYPE_PROXY_VLESS_OUTBOUND_CONFIG,
                                VlessOutboundConfigPayload {
                                    vnext: Some(VlessServerEndpointPayload {
                                        address: Self::encode_address(
                                            config.server.address(),
                                        ),
                                        port: u32::from(config.server.port()),
                                        user: Some(
                                            proto::xray::common::protocol::User {
                                                level: 0,
                                                email: String::new(),
                                                account: Some(Self::typed_message(
                                                    TYPE_PROXY_VLESS_ACCOUNT,
                                                    VlessAccountPayload {
                                                        id: uuid::Uuid::from_bytes(
                                                            config.user_uuid,
                                                        )
                                                        .to_string(),
                                                        flow: String::new(),
                                                        encryption: "none".into(),
                                                    },
                                                )),
                                            },
                                        ),
                                    }),
                                },
                            ))
                        }
                        _ => None,
                    },
                ),
                _ => None,
            },
        };
        proto::xray::core::OutboundHandlerConfig {
            tag: outbound.tag.clone(),
            sender_settings: self
                .encode_outbound_sender_settings(outbound.stream_settings.as_ref()),
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

    fn parse_socks_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<SocksUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for socks",
            )
        })?;
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
            user.email.trim()
        } else {
            payload.username.trim()
        };
        if username.is_empty() {
            return Err(Status::invalid_argument(
                "socks account username is required",
            ));
        }
        let password = payload.password.trim();
        if password.is_empty() {
            return Err(Status::invalid_argument(
                "socks account password is required",
            ));
        }

        Ok(SocksUser {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    #[cfg(feature = "hysteria")]
    fn parse_hysteria_client(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<Hysteria2Client, Status> {
        let email = user.email.trim();
        if email.is_empty() {
            return Err(Status::invalid_argument(
                "hysteria account email is required",
            ));
        }
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
        let auth = payload.auth.trim();
        if auth.is_empty() {
            return Err(Status::invalid_argument(
                "hysteria account auth is required",
            ));
        }

        Ok(Hysteria2Client {
            password: auth.to_string(),
            email: Some(email.to_string()),
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
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                let client = self.parse_hysteria_client(user)?;
                if let Some(existing) = config
                    .clients
                    .iter_mut()
                    .find(|existing| existing.email == client.email)
                {
                    existing.password = client.password;
                } else {
                    config.clients.push(client);
                }
                Ok(true)
            }
            ServerProxyConfig::Socks { accounts, .. } => {
                accounts.upsert(self.parse_socks_user(user)?);
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
            ServerProxyConfig::Vless { users, .. } => {
                let before = users.len();
                users.retain(|user| user.user_label != email);
                Ok(before != users.len())
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                users.retain(|user| user.email.as_deref() != Some(email));
                Ok(true)
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                let before = config.clients.len();
                config
                    .clients
                    .retain(|client| client.email.as_deref() != Some(email));
                Ok(before != config.clients.len())
            }
            ServerProxyConfig::Socks { accounts, .. } => Ok(accounts.remove(email)),
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
            _ => Ok(false),
        }
    }

    fn detached_inbound(inbound: &ServerConfig) -> ServerConfig {
        let mut detached = inbound.clone();
        Self::detach_socks_user_stores(&mut detached.protocol);
        detached
    }

    fn detach_socks_user_stores(protocol: &mut ServerProxyConfig) {
        match protocol {
            ServerProxyConfig::Socks { accounts, .. } => {
                *accounts =
                    crate::config::server_config::SocksUserStore::with_auth_required(
                        accounts.snapshot(),
                        accounts.auth_required(),
                    );
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
                crate::util::option::OneOrSome::One(target) => {
                    Self::detach_socks_user_stores(&mut target.protocol);
                }
                crate::util::option::OneOrSome::Some(targets) => {
                    for target in targets {
                        Self::detach_socks_user_stores(&mut target.protocol);
                    }
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                Self::detach_socks_user_stores(tls.inner.as_mut());
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                Self::detach_socks_user_stores(reality.inner.as_mut());
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                Self::detach_socks_user_stores(inner.as_mut());
            }
            _ => {}
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
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            ServerProxyConfig::Socks { accounts, .. } => Some(
                accounts
                    .snapshot()
                    .iter()
                    .map(|account| account.username.clone())
                    .collect(),
            ),
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { .. } => None,
            ServerProxyConfig::DokodemoDoor { .. } => None,
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
                                encryption: String::new(),
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
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.user_label.clone(),
                        account: None,
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
                    .filter_map(|client| {
                        client.email.clone().map(|email| {
                            proto::xray::common::protocol::User {
                                level: 0,
                                email,
                                account: Some(
                                    proto::xray::common::serial::TypedMessage {
                                        r#type: TYPE_PROXY_HYSTERIA_ACCOUNT
                                            .to_string(),
                                        value: HysteriaAccountPayload {
                                            auth: client.password.clone(),
                                        }
                                        .encode_to_vec(),
                                    },
                                ),
                            }
                        })
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
            ServerProxyConfig::Socks { accounts, .. } => Some(
                accounts
                    .snapshot()
                    .iter()
                    .map(|account| proto::xray::common::protocol::User {
                        level: 0,
                        email: account.username.clone(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
                            value: SocksAccountPayload {
                                username: account.username.clone(),
                                password: account.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { .. } => None,
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
        self.runtime
            .add_inbound(inbound.clone())
            .map_err(Status::already_exists)?;

        let handles = match start_servers(inbound, self.runtime.clone()).await {
            Ok(handles) => handles,
            Err(err) => {
                self.runtime.remove_inbound(&inbound_tag);
                return Err(Status::unknown(format!(
                    "failed to start inbound handler: {err}"
                )));
            }
        };
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
        let _mutation_guard = self.mutation_lock.lock().await;
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

        if self.runtime.abort_inbound_tasks(&request.tag) {
            tokio::task::yield_now().await;
            match start_servers(updated, self.runtime.clone()).await {
                Ok(handles) => {
                    self.runtime.register_inbound_tasks(&request.tag, &handles);
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
                                .register_inbound_tasks(&request.tag, &handles);
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
        let _mutation_guard = self.mutation_lock.lock().await;
        let request = request.into_inner();
        let outbound = request
            .outbound
            .ok_or_else(|| Status::invalid_argument("outbound is required"))?;
        let outbound = self.parse_add_outbound(outbound)?;
        self.runtime.add_outbound(outbound).map_err(|error| {
            if error.contains("already exists") {
                Status::already_exists(error)
            } else {
                Status::invalid_argument(error)
            }
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
        outbound_registry::OutboundConnectorKind,
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
            settings: None,
            stream_settings: None,
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
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_FREEDOM_CONFIG,
            FreedomConfigPayload {}.encode_to_vec(),
        )
    }

    #[cfg(feature = "vmess")]
    fn build_add_vmess_outbound_request(
        tag: &str,
        security_type: i32,
        tests_enabled: &str,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "vmess-outbound@example.com".into(),
            account: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VMESS_ACCOUNT,
                VmessAccountPayload {
                    id: "3ac9b383-75a1-431c-8184-106c80eb2273".into(),
                    security_settings: Some(VmessSecurityConfigPayload {
                        security_type,
                    }),
                    tests_enabled: tests_enabled.to_string(),
                },
            )),
        };
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_VMESS_OUTBOUND_CONFIG,
            VmessOutboundConfigPayload {
                receiver: Some(SocksServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "vmess.example".into(),
                        )),
                    }),
                    port: 443,
                    user: Some(user),
                }),
            }
            .encode_to_vec(),
        )
    }

    #[cfg(feature = "vless")]
    fn build_add_vless_outbound_request(
        tag: &str,
        user_id: &str,
        flow: &str,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let account = proto::xray::common::protocol::User {
            level: 0,
            email: "outbound@example.com".into(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.into(),
                value: VlessAccountPayload {
                    id: user_id.into(),
                    flow: flow.into(),
                    encryption: "none".into(),
                }
                .encode_to_vec(),
            }),
        };
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_VLESS_OUTBOUND_CONFIG,
            VlessOutboundConfigPayload {
                vnext: Some(VlessServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "proxy.example".into(),
                        )),
                    }),
                    port: 443,
                    user: Some(account),
                }),
            }
            .encode_to_vec(),
        )
    }

    fn build_add_http_outbound_request(
        tag: &str,
        credentials: Option<(&str, &str)>,
        headers: Vec<(&str, &str)>,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let user = credentials.map(|(username, password)| {
            proto::xray::common::protocol::User {
                level: 0,
                email: "http-outbound@example.com".into(),
                account: Some(HandlerServiceImpl::typed_message(
                    TYPE_PROXY_HTTP_ACCOUNT,
                    HttpAccountPayload {
                        username: username.to_string(),
                        password: password.to_string(),
                    },
                )),
            }
        });
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_HTTP_CLIENT_CONFIG,
            HttpClientConfigPayload {
                server: Some(SocksServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "http.example".into(),
                        )),
                    }),
                    port: 8080,
                    user,
                }),
                header: headers
                    .into_iter()
                    .map(|(key, value)| HttpHeaderPayload {
                        key: key.to_string(),
                        value: value.to_string(),
                    })
                    .collect(),
            }
            .encode_to_vec(),
        )
    }

    #[cfg(feature = "shadowsocks")]
    fn build_add_shadowsocks_outbound_request(
        tag: &str,
        cipher_type: i32,
        password: &str,
        iv_check: bool,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "shadowsocks-outbound@example.com".into(),
            account: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                ShadowsocksAccountPayload {
                    password: password.to_string(),
                    cipher_type,
                    iv_check,
                },
            )),
        };
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG,
            ShadowsocksClientConfigPayload {
                server: Some(SocksServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "shadowsocks.example".into(),
                        )),
                    }),
                    port: 8388,
                    user: Some(user),
                }),
            }
            .encode_to_vec(),
        )
    }

    fn build_add_socks_outbound_request(
        tag: &str,
        credentials: Option<(&str, &str)>,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let user = credentials.map(|(username, password)| {
            proto::xray::common::protocol::User {
                level: 0,
                email: "socks-outbound@example.com".into(),
                account: Some(HandlerServiceImpl::typed_message(
                    TYPE_PROXY_SOCKS_ACCOUNT,
                    SocksAccountPayload {
                        username: username.to_string(),
                        password: password.to_string(),
                    },
                )),
            }
        });
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_SOCKS_CLIENT_CONFIG,
            SocksClientConfigPayload {
                server: Some(SocksServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "socks.example".into(),
                        )),
                    }),
                    port: 1080,
                    user,
                }),
            }
            .encode_to_vec(),
        )
    }

    #[cfg(feature = "trojan")]
    fn build_add_trojan_outbound_request(
        tag: &str,
        password: &str,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "trojan-outbound@example.com".into(),
            account: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_TROJAN_ACCOUNT,
                TrojanAccountPayload {
                    password: password.to_string(),
                },
            )),
        };
        build_typed_add_outbound_request(
            tag,
            TYPE_PROXY_TROJAN_CLIENT_CONFIG,
            TrojanClientConfigPayload {
                server: Some(TrojanServerEndpointPayload {
                    address: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Domain(
                            "trojan.example".into(),
                        )),
                    }),
                    port: 443,
                    user: Some(user),
                }),
            }
            .encode_to_vec(),
        )
    }

    #[cfg(feature = "vless")]
    fn build_sender_add_vless_outbound_request(
        tag: &str,
        user_id: &str,
        stream_settings: SenderStreamConfigPayload,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        let mut request = build_add_vless_outbound_request(tag, user_id, "");
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload {
                    stream_settings: Some(stream_settings),
                    ..SenderConfigPayload::default()
                },
            ));
        request
    }

    fn build_typed_add_outbound_request(
        tag: &str,
        message_type: &str,
        value: Vec<u8>,
    ) -> proto::xray::app::proxyman::command::AddOutboundRequest {
        proto::xray::app::proxyman::command::AddOutboundRequest {
            outbound: Some(proto::xray::core::OutboundHandlerConfig {
                tag: tag.to_string(),
                sender_settings: None,
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: message_type.to_string(),
                    value,
                }),
                expire: 0,
                comment: String::new(),
            }),
        }
    }

    fn build_socks_add_user_operation(
        username: &str,
    ) -> proto::xray::common::serial::TypedMessage {
        let operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: username.to_string(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
                    value: SocksAccountPayload {
                        username: username.to_string(),
                        password: "new-password".to_string(),
                    }
                    .encode_to_vec(),
                }),
            }),
        };
        proto::xray::common::serial::TypedMessage {
            r#type: TYPE_ADD_USER_OPERATION.to_string(),
            value: operation.encode_to_vec(),
        }
    }

    #[tokio::test]
    async fn handler_alter_inbound_rolls_back_config_when_restart_fails() {
        let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();
        let inbound_tag = unique_tag("rollback-inbound");
        let original_username = unique_tag("original-user");
        let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: vec![SocksUser {
                    username: original_username.clone(),
                    password: "original-password".to_string(),
                }]
                .into(),
                udp_enabled: false,
            },
            transport: Transport::Tcp,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let placeholder_task = tokio::spawn(std::future::pending::<()>());
        runtime.register_inbound_tasks(&inbound_tag, &[placeholder_task]);
        let service = HandlerServiceImpl::new(runtime.clone());
        let added_username = unique_tag("failed-user");

        let error = service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: inbound_tag.clone(),
                    operation: Some(build_socks_add_user_operation(&added_username)),
                },
            ))
            .await
            .expect_err("occupied listener should fail both restart attempts");

        assert_eq!(error.code(), Code::Unknown);
        assert!(error.message().contains("rollback failed"));
        let restored = runtime.inbound_by_tag(&inbound_tag).unwrap();
        let ServerProxyConfig::Socks { accounts, .. } = restored.protocol else {
            panic!("expected socks inbound");
        };
        let users = accounts.snapshot();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, original_username);
        assert!(!users.iter().any(|user| user.username == added_username));
    }

    #[tokio::test]
    async fn handler_empty_alter_keeps_registered_listener() {
        let fixture = build_fixture();
        let placeholder_task = tokio::spawn(std::future::pending::<()>());
        fixture
            .runtime
            .register_inbound_tasks(&fixture.inbound_tag, &[placeholder_task]);
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

        assert!(fixture.runtime.abort_inbound_tasks(&fixture.inbound_tag));
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
                        encryption: String::new(),
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
    async fn handler_installs_blackhole_and_rejects_unsupported_outbound_atomically()
    {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let blackhole_tag = unique_tag("blackhole");

        service
            .add_outbound(Request::new(build_typed_add_outbound_request(
                &format!(" {blackhole_tag} "),
                TYPE_PROXY_BLACKHOLE_CONFIG,
                BlackholeConfigPayload {}.encode_to_vec(),
            )))
            .await
            .expect("blackhole outbound should install");
        assert!(matches!(
            runtime.outbound_connector(&blackhole_tag).as_deref(),
            Some(OutboundConnectorKind::Blackhole)
        ));
        assert!(
            runtime
                .outbounds()
                .iter()
                .any(|outbound| outbound.tag == blackhole_tag)
        );

        let before = runtime.outbounds();
        let unsupported_tag = unique_tag("unsupported");
        let error = service
            .add_outbound(Request::new(build_typed_add_outbound_request(
                &unsupported_tag,
                "xray.proxy.wireguard.Config",
                Vec::new(),
            )))
            .await
            .expect_err("unsupported outbound should fail before installation");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(
            error
                .message()
                .contains("unsupported outbound proxy settings")
        );
        assert_eq!(runtime.outbounds().len(), before.len());
        assert!(runtime.outbound_connector(&unsupported_tag).is_none());
    }

    #[tokio::test]
    async fn handler_installs_http_outbound_and_preserves_headers() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let tag = unique_tag("http-auth");
        let mut request = build_add_http_outbound_request(
            &tag,
            Some(("alice", "secret")),
            vec![("X-Region", "edge"), ("X-Trace", "enabled")],
        );
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));

        service
            .add_outbound(Request::new(request))
            .await
            .expect("HTTP outbound should install");
        let connector = runtime.outbound_connector(&tag).unwrap();
        let OutboundConnectorKind::HttpTcp(config) = connector.as_ref() else {
            panic!("expected HTTP TCP connector");
        };
        assert_eq!(config.server.to_string(), "http.example:8080");
        assert_eq!(
            config.credentials,
            Some(crate::http_outbound::HttpProxyCredentials {
                username: "alice".into(),
                password: "secret".into(),
            })
        );
        assert_eq!(config.headers.get("X-Region"), Some(&"edge".to_string()));
        assert!(config.transport.is_tcp());

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let outbound = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .expect("listed HTTP outbound missing");
        assert_eq!(
            outbound.proxy_settings.as_ref().unwrap().r#type,
            TYPE_PROXY_HTTP_CLIENT_CONFIG
        );
        let config = HttpClientConfigPayload::decode(
            outbound.proxy_settings.as_ref().unwrap().value.as_slice(),
        )
        .unwrap();
        assert_eq!(
            config
                .header
                .iter()
                .map(|header| (header.key.as_str(), header.value.as_str()))
                .collect::<Vec<_>>(),
            vec![("X-Region", "edge"), ("X-Trace", "enabled")]
        );
        let account = config.server.unwrap().user.unwrap().account.unwrap();
        let account = HttpAccountPayload::decode(account.value.as_slice()).unwrap();
        assert_eq!(account.username, "alice");
        assert_eq!(account.password, "secret");
        assert!(outbound.sender_settings.is_some());

        let before = runtime.outbounds().len();
        let duplicate_tag = unique_tag("http-duplicate-header");
        let error = service
            .add_outbound(Request::new(build_add_http_outbound_request(
                &duplicate_tag,
                None,
                vec![("X-Test", "one"), ("X-Test", "two")],
            )))
            .await
            .expect_err("duplicate HTTP headers must fail atomically");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("duplicate HTTP outbound header"));
        assert_eq!(runtime.outbounds().len(), before);
        assert!(runtime.outbound_connector(&duplicate_tag).is_none());

        let reserved_tag = unique_tag("http-reserved-header");
        let error = service
            .add_outbound(Request::new(build_add_http_outbound_request(
                &reserved_tag,
                None,
                vec![("Proxy-Authorization", "override")],
            )))
            .await
            .expect_err("reserved HTTP headers must fail atomically");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("reserved"));
        assert!(runtime.outbound_connector(&reserved_tag).is_none());
    }

    #[cfg(feature = "vmess")]
    #[tokio::test]
    async fn handler_installs_vmess_and_rejects_auto_or_experiments() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let tag = unique_tag("vmess-aes");
        let mut request = build_add_vmess_outbound_request(&tag, 3, "");
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));

        service
            .add_outbound(Request::new(request))
            .await
            .expect("VMess outbound should install");
        let connector = runtime.outbound_connector(&tag).unwrap();
        let OutboundConnectorKind::VmessTcp(config) = connector.as_ref() else {
            panic!("expected VMess TCP connector");
        };
        assert_eq!(config.server.to_string(), "vmess.example:443");
        assert_eq!(
            config.security,
            crate::handler::vmess::client::VmessDataSecurity::Aes128Gcm
        );
        assert_eq!(
            format_vmess_user_id(config.user_uuid),
            "3ac9b383-75a1-431c-8184-106c80eb2273"
        );
        assert!(config.transport.is_tcp());

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let outbound = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .expect("listed VMess outbound missing");
        assert_eq!(
            outbound.proxy_settings.as_ref().unwrap().r#type,
            TYPE_PROXY_VMESS_OUTBOUND_CONFIG
        );
        let config = VmessOutboundConfigPayload::decode(
            outbound.proxy_settings.as_ref().unwrap().value.as_slice(),
        )
        .unwrap();
        let account = config.receiver.unwrap().user.unwrap().account.unwrap();
        let account = VmessAccountPayload::decode(account.value.as_slice()).unwrap();
        assert_eq!(account.id, "3ac9b383-75a1-431c-8184-106c80eb2273");
        assert_eq!(account.security_settings.unwrap().security_type, 3);
        assert!(account.tests_enabled.is_empty());
        assert!(outbound.sender_settings.is_some());

        for (suffix, security_type, tests_enabled, expected) in [
            ("auto", 2, "", "explicit security"),
            ("unknown", 99, "", "unsupported VMess outbound security"),
            (
                "experiments",
                3,
                "AuthenticatedLength",
                "experiments are not supported",
            ),
        ] {
            let rejected_tag = unique_tag(suffix);
            let before = runtime.outbounds().len();
            let error = service
                .add_outbound(Request::new(build_add_vmess_outbound_request(
                    &rejected_tag,
                    security_type,
                    tests_enabled,
                )))
                .await
                .expect_err("unsupported VMess variant must fail atomically");
            assert_eq!(error.code(), Code::InvalidArgument);
            assert!(
                error.message().contains(expected),
                "unexpected error: {error}"
            );
            assert_eq!(runtime.outbounds().len(), before);
            assert!(runtime.outbound_connector(&rejected_tag).is_none());
        }
    }

    #[cfg(feature = "shadowsocks")]
    #[tokio::test]
    async fn handler_installs_legacy_shadowsocks_and_rejects_newer_variants() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let tag = unique_tag("shadowsocks-aes");
        let mut request =
            build_add_shadowsocks_outbound_request(&tag, 5, "secret", false);
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));

        service
            .add_outbound(Request::new(request))
            .await
            .expect("legacy Shadowsocks outbound should install");
        let connector = runtime.outbound_connector(&tag).unwrap();
        let OutboundConnectorKind::ShadowsocksTcp(config) = connector.as_ref()
        else {
            panic!("expected Shadowsocks TCP connector");
        };
        assert_eq!(config.server.to_string(), "shadowsocks.example:8388");
        assert_eq!(config.method.as_ref(), "aes-128-gcm");
        assert_eq!(config.password.as_ref(), "secret");
        assert!(config.transport.is_tcp());

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let outbound = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .expect("listed Shadowsocks outbound missing");
        assert_eq!(
            outbound.proxy_settings.as_ref().unwrap().r#type,
            TYPE_PROXY_SHADOWSOCKS_CLIENT_CONFIG
        );
        let config = ShadowsocksClientConfigPayload::decode(
            outbound.proxy_settings.as_ref().unwrap().value.as_slice(),
        )
        .unwrap();
        let account = config.server.unwrap().user.unwrap().account.unwrap();
        let account =
            ShadowsocksAccountPayload::decode(account.value.as_slice()).unwrap();
        assert_eq!(account.password, "secret");
        assert_eq!(account.cipher_type, 5);
        assert!(!account.iv_check);
        assert!(outbound.sender_settings.is_some());

        for (suffix, cipher_type, iv_check, expected) in [
            ("xchacha", 8, false, "XChaCha20-Poly1305"),
            (
                "unknown",
                99,
                false,
                "unsupported Shadowsocks outbound cipher",
            ),
            ("iv-check", 5, true, "iv_check is not supported"),
        ] {
            let rejected_tag = unique_tag(suffix);
            let before = runtime.outbounds().len();
            let error = service
                .add_outbound(Request::new(build_add_shadowsocks_outbound_request(
                    &rejected_tag,
                    cipher_type,
                    "secret",
                    iv_check,
                )))
                .await
                .expect_err("unsupported Shadowsocks variant must fail atomically");
            assert_eq!(error.code(), Code::InvalidArgument);
            assert!(
                error.message().contains(expected),
                "unexpected error: {error}"
            );
            assert_eq!(runtime.outbounds().len(), before);
            assert!(runtime.outbound_connector(&rejected_tag).is_none());
        }
    }

    #[tokio::test]
    async fn handler_installs_socks_outbound_with_and_without_authentication() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());

        let no_auth_tag = unique_tag("socks-no-auth");
        service
            .add_outbound(Request::new(build_add_socks_outbound_request(
                &no_auth_tag,
                None,
            )))
            .await
            .expect("no-auth SOCKS outbound should install");
        let connector = runtime.outbound_connector(&no_auth_tag).unwrap();
        let OutboundConnectorKind::SocksTcp(config) = connector.as_ref() else {
            panic!("expected SOCKS TCP connector");
        };
        assert!(config.credentials.is_none());
        assert!(config.transport.is_tcp());

        let auth_tag = unique_tag("socks-auth");
        let mut request =
            build_add_socks_outbound_request(&auth_tag, Some(("alice", "secret")));
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));
        service
            .add_outbound(Request::new(request))
            .await
            .expect("authenticated SOCKS outbound should install");
        let connector = runtime.outbound_connector(&auth_tag).unwrap();
        let OutboundConnectorKind::SocksTcp(config) = connector.as_ref() else {
            panic!("expected authenticated SOCKS TCP connector");
        };
        assert_eq!(
            config.credentials,
            Some(crate::socks_outbound::Socks5Credentials {
                username: "alice".into(),
                password: "secret".into(),
            })
        );

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let outbound = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == auth_tag)
            .expect("listed authenticated SOCKS outbound missing");
        assert_eq!(
            outbound.proxy_settings.as_ref().unwrap().r#type,
            TYPE_PROXY_SOCKS_CLIENT_CONFIG
        );
        let config = SocksClientConfigPayload::decode(
            outbound.proxy_settings.as_ref().unwrap().value.as_slice(),
        )
        .unwrap();
        let user = config.server.unwrap().user.unwrap();
        let account =
            SocksAccountPayload::decode(user.account.unwrap().value.as_slice())
                .unwrap();
        assert_eq!(account.username, "alice");
        assert_eq!(account.password, "secret");
        assert!(outbound.sender_settings.is_some());

        let rejected_tag = unique_tag("socks-empty-user");
        let error = service
            .add_outbound(Request::new(build_add_socks_outbound_request(
                &rejected_tag,
                Some(("", "secret")),
            )))
            .await
            .expect_err("empty SOCKS username must fail atomically");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("username must not be empty"));
        assert!(runtime.outbound_connector(&rejected_tag).is_none());
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn handler_installs_trojan_outbound_and_lists_sender_settings() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let tag = unique_tag("trojan-outbound");

        let mut request = build_add_trojan_outbound_request(&tag, "secret");
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));
        service
            .add_outbound(Request::new(request))
            .await
            .expect("Trojan outbound should install");

        let connector = runtime
            .outbound_connector(&tag)
            .expect("Trojan connector should be registered");
        let OutboundConnectorKind::TrojanTcp(config) = connector.as_ref() else {
            panic!("expected Trojan TCP connector");
        };
        assert_eq!(config.server.to_string(), "trojan.example:443");
        assert_eq!(config.password.as_ref(), "secret");
        assert!(config.transport.is_tcp());

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let outbound = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .expect("listed Trojan outbound missing");
        assert_eq!(
            outbound.proxy_settings.as_ref().unwrap().r#type,
            TYPE_PROXY_TROJAN_CLIENT_CONFIG
        );
        let sender = outbound
            .sender_settings
            .as_ref()
            .expect("Trojan SenderConfig should be listed");
        let sender = SenderConfigPayload::decode(sender.value.as_slice()).unwrap();
        assert_eq!(sender.stream_settings.unwrap().protocol_name, "tcp");

        let rejected_tag = unique_tag("trojan-empty-password");
        let error = service
            .add_outbound(Request::new(build_add_trojan_outbound_request(
                &rejected_tag,
                "",
            )))
            .await
            .expect_err("empty Trojan password must fail atomically");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("password must not be empty"));
        assert!(runtime.outbound_connector(&rejected_tag).is_none());
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_installs_plain_vless_and_rejects_unsupported_variants_atomically()
     {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let tag = unique_tag("vless-outbound");

        service
            .add_outbound(Request::new(build_add_vless_outbound_request(
                &tag, user_id, "",
            )))
            .await
            .expect("plain VLESS outbound should install");
        let connector = runtime
            .outbound_connector(&tag)
            .expect("VLESS connector should be registered");
        let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
            panic!("expected a VLESS TCP connector");
        };
        assert_eq!(config.server.to_string(), "proxy.example:443");
        assert_eq!(
            config.user_uuid,
            uuid::Uuid::parse_str(user_id).unwrap().into_bytes()
        );
        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .expect("VLESS outbound should be listable")
            .into_inner();
        let listed = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == tag)
            .expect("listed VLESS outbound missing");
        let proxy_settings = listed
            .proxy_settings
            .as_ref()
            .expect("listed VLESS proxy settings missing");
        assert_eq!(proxy_settings.r#type, TYPE_PROXY_VLESS_OUTBOUND_CONFIG);
        let listed_config =
            VlessOutboundConfigPayload::decode(proxy_settings.value.as_slice())
                .expect("listed VLESS config should decode");
        let listed_account = listed_config
            .vnext
            .and_then(|server| server.user)
            .and_then(|user| user.account)
            .expect("listed VLESS account missing");
        let listed_account =
            VlessAccountPayload::decode(listed_account.value.as_slice())
                .expect("listed VLESS account should decode");
        assert_eq!(listed_account.id, user_id);
        assert_eq!(listed_account.encryption, "none");

        let before = runtime.outbounds().len();
        let invalid_flow_tag = unique_tag("vless-flow");
        let invalid_flow = service
            .add_outbound(Request::new(build_add_vless_outbound_request(
                &invalid_flow_tag,
                user_id,
                "xtls-rprx-vision",
            )))
            .await
            .expect_err("Vision is outside the plain VLESS outbound slice");
        assert_eq!(invalid_flow.code(), Code::InvalidArgument);
        assert!(invalid_flow.message().contains("does not support flow"));
        assert_eq!(runtime.outbounds().len(), before);
        assert!(runtime.outbound_connector(&invalid_flow_tag).is_none());

        let sender_tag = unique_tag("vless-sender");
        let mut request = build_add_vless_outbound_request(&sender_tag, user_id, "");
        request.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload::default(),
            ));
        service
            .add_outbound(Request::new(request))
            .await
            .expect("default SenderConfig should install as TCP/none");
        let connector = runtime
            .outbound_connector(&sender_tag)
            .expect("sender connector should be registered");
        let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
            panic!("expected VLESS connector");
        };
        assert!(config.transport.is_tcp());
        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        let listed_sender = listed
            .outbounds
            .iter()
            .find(|outbound| outbound.tag == sender_tag)
            .and_then(|outbound| outbound.sender_settings.as_ref())
            .expect("SenderConfig should be listed");
        let listed_sender =
            SenderConfigPayload::decode(listed_sender.value.as_slice())
                .expect("listed SenderConfig should decode");
        assert_eq!(
            listed_sender
                .stream_settings
                .expect("listed stream settings")
                .protocol_name,
            "tcp"
        );

        let rejected_tag = unique_tag("vless-mux");
        let mut rejected =
            build_add_vless_outbound_request(&rejected_tag, user_id, "");
        rejected.outbound.as_mut().unwrap().sender_settings =
            Some(HandlerServiceImpl::typed_message(
                TYPE_APP_SENDER_CONFIG,
                SenderConfigPayload {
                    multiplex_settings: Some(SenderMultiplexingConfigPayload {
                        enabled: true,
                        concurrency: 8,
                        xudp_concurrency: 0,
                        xudp_proxy_udp443: String::new(),
                    }),
                    ..SenderConfigPayload::default()
                },
            ));
        let sender_error = service
            .add_outbound(Request::new(rejected))
            .await
            .expect_err("unsupported mux must fail before installation");
        assert_eq!(sender_error.code(), Code::InvalidArgument);
        assert!(sender_error.message().contains("multiplex_settings"));
        assert!(runtime.outbound_connector(&rejected_tag).is_none());
    }

    #[cfg(all(
        feature = "vless",
        feature = "ws",
        feature = "httpupgrade",
        feature = "tls",
        feature = "reality",
        feature = "grpc_transport"
    ))]
    #[tokio::test]
    async fn handler_installs_dynamic_sender_transport_matrix_and_lists_it() {
        let fixture = build_fixture();
        let runtime = fixture.runtime.clone();
        let service = HandlerServiceImpl::new(runtime.clone());
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";

        let websocket_tag = unique_tag("dynamic-ws");
        service
            .add_outbound(Request::new(build_sender_add_vless_outbound_request(
                &websocket_tag,
                user_id,
                SenderStreamConfigPayload {
                    protocol_name: "websocket".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "websocket".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                            OutboundWebsocketConfigPayload {
                                host: "edge.example".to_string(),
                                path: "/ws".to_string(),
                                header: std::collections::HashMap::from([(
                                    "X-Test".to_string(),
                                    "dynamic".to_string(),
                                )]),
                                accept_proxy_protocol: false,
                                early_data: 0,
                                heartbeat_period: 0,
                            },
                        )),
                    }],
                    security_type: "none".to_string(),
                    ..SenderStreamConfigPayload::default()
                },
            )))
            .await
            .expect("dynamic WebSocket sender should install");
        let connector = runtime.outbound_connector(&websocket_tag).unwrap();
        let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
            panic!("expected VLESS WebSocket connector");
        };
        assert!(config.transport.is_websocket());

        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let httpupgrade_tag = unique_tag("dynamic-tls-httpupgrade");
        service
            .add_outbound(Request::new(build_sender_add_vless_outbound_request(
                &httpupgrade_tag,
                user_id,
                SenderStreamConfigPayload {
                    protocol_name: "httpupgrade".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "httpupgrade".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_HTTPUPGRADE_CONFIG,
                            OutboundHttpUpgradeConfigPayload {
                                host: "proxy.example".to_string(),
                                path: "/upgrade".to_string(),
                                header: std::collections::HashMap::new(),
                                accept_proxy_protocol: false,
                                early_data: 0,
                            },
                        )),
                    }],
                    security_type: "tls".to_string(),
                    security_settings: vec![HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_TLS_CONFIG,
                        OutboundTlsConfigPayload {
                            certificate: vec![OutboundTlsCertificatePayload {
                                certificate: generated.cert.pem().into_bytes(),
                                usage: 1,
                                ..OutboundTlsCertificatePayload::default()
                            }],
                            server_name: "proxy.example".to_string(),
                            disable_system_root: true,
                            ..OutboundTlsConfigPayload::default()
                        },
                    )],
                    ..SenderStreamConfigPayload::default()
                },
            )))
            .await
            .expect("dynamic TLS HTTP Upgrade sender should install");
        let connector = runtime.outbound_connector(&httpupgrade_tag).unwrap();
        let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
            panic!("expected VLESS HTTP Upgrade connector");
        };
        assert!(config.transport.is_tls());
        assert!(config.transport.is_httpupgrade());

        let (_, public_key) = crate::reality::generate_keypair().unwrap();
        let public_key = URL_SAFE_NO_PAD.decode(public_key).unwrap();
        let grpc_tag = unique_tag("dynamic-reality-grpc");
        service
            .add_outbound(Request::new(build_sender_add_vless_outbound_request(
                &grpc_tag,
                user_id,
                SenderStreamConfigPayload {
                    protocol_name: "grpc".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "grpc".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_GRPC_CONFIG,
                            OutboundGrpcConfigPayload {
                                authority: "grpc.example".to_string(),
                                service_name: "dynamic-grpc".to_string(),
                                user_agent: "chimera-dynamic-test".to_string(),
                                ..OutboundGrpcConfigPayload::default()
                            },
                        )),
                    }],
                    security_type: "reality".to_string(),
                    security_settings: vec![HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_REALITY_CONFIG,
                        OutboundRealityConfigPayload {
                            server_name: "cover.example".to_string(),
                            public_key,
                            short_id: vec![0x4a, 0xc9, 0x7a, 0xaf],
                            ..OutboundRealityConfigPayload::default()
                        },
                    )],
                    ..SenderStreamConfigPayload::default()
                },
            )))
            .await
            .expect("dynamic REALITY gRPC sender should install");
        let connector = runtime.outbound_connector(&grpc_tag).unwrap();
        let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
            panic!("expected VLESS gRPC connector");
        };
        assert!(config.transport.is_reality());
        assert!(config.transport.is_grpc());

        let listed = service
            .list_outbounds(Request::new(
                proto::xray::app::proxyman::command::ListOutboundsRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        for (tag, network, security) in [
            (&websocket_tag, "ws", "none"),
            (&httpupgrade_tag, "httpupgrade", "tls"),
            (&grpc_tag, "grpc", "reality"),
        ] {
            let sender = listed
                .outbounds
                .iter()
                .find(|outbound| outbound.tag == *tag)
                .and_then(|outbound| outbound.sender_settings.as_ref())
                .expect("dynamic SenderConfig should be listed");
            assert_eq!(sender.r#type, TYPE_APP_SENDER_CONFIG);
            let sender =
                SenderConfigPayload::decode(sender.value.as_slice()).unwrap();
            let stream = sender.stream_settings.unwrap();
            assert_eq!(stream.protocol_name, network);
            assert_eq!(stream.security_type, security);
        }

        let rejected_tag = unique_tag("dynamic-ws-ed");
        let error = service
            .add_outbound(Request::new(build_sender_add_vless_outbound_request(
                &rejected_tag,
                user_id,
                SenderStreamConfigPayload {
                    protocol_name: "websocket".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "websocket".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                            OutboundWebsocketConfigPayload {
                                early_data: 1,
                                ..OutboundWebsocketConfigPayload::default()
                            },
                        )),
                    }],
                    ..SenderStreamConfigPayload::default()
                },
            )))
            .await
            .expect_err("unsupported early data must fail atomically");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("early data"));
        assert!(runtime.outbound_connector(&rejected_tag).is_none());
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

        let users = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("expected socks inbound users to be returned")
            .into_inner();
        assert_eq!(users.users.len(), 1);
        assert!(users.users[0].email.starts_with("user-a-"));

        let users_count = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("expected socks inbound users count to be returned")
            .into_inner();
        assert_eq!(users_count.count, 1);
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

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn handler_adds_and_removes_xhttp_inbound() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let tag = unique_tag("dynamic-xhttp");
        let port = free_localhost_port();
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "dynamic-xhttp@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                    flow: String::new(),
                    encryption: String::new(),
                }
                .encode_to_vec(),
            }),
        };
        let request = proto::xray::app::proxyman::command::AddInboundRequest {
            inbound: Some(proto::xray::core::InboundHandlerConfig {
                tag: tag.clone(),
                receiver_settings: Some(build_receiver_settings(
                    port,
                    Some(StreamConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        transport_settings: vec![TransportConfigPayload {
                            protocol_name: "xhttp".to_string(),
                            settings: Some(
                                proto::xray::common::serial::TypedMessage {
                                    r#type: TYPE_TRANSPORT_SPLITHTTP_CONFIG
                                        .to_string(),
                                    value: XhttpConfigPayload {
                                        path: "/dynamic".to_string(),
                                        mode: "stream-one".to_string(),
                                        ..Default::default()
                                    }
                                    .encode_to_vec(),
                                },
                            ),
                        }],
                        security_type: String::new(),
                        security_settings: Vec::new(),
                    }),
                )),
                proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_INBOUND_CONFIG.to_string(),
                    value: VlessInboundConfigPayload {
                        clients: vec![user],
                    }
                    .encode_to_vec(),
                }),
            }),
        };

        service
            .add_inbound(Request::new(request))
            .await
            .expect("dynamic XHTTP AddInbound should start");
        assert!(fixture.runtime.inbound_by_tag(&tag).is_some());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let connection = tokio::net::TcpStream::connect(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))
        .await
        .expect("dynamic XHTTP listener should accept TCP connections");
        drop(connection);

        service
            .remove_inbound(Request::new(
                proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: tag.clone(),
                },
            ))
            .await
            .expect("dynamic XHTTP RemoveInbound should stop listener");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(fixture.runtime.inbound_by_tag(&tag).is_none());
        let error = tokio::net::TcpStream::connect(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))
        .await
        .expect_err("removed XHTTP listener should reject connections");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
        ));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn handler_parse_add_inbound_supports_vless_xhttp() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime);
        let user = proto::xray::common::protocol::User {
            level: 0,
            email: "xhttp-user@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                    flow: String::new(),
                    encryption: String::new(),
                }
                .encode_to_vec(),
            }),
        };
        let inbound = proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("vless-xhttp"),
            receiver_settings: Some(build_receiver_settings(
                2080,
                Some(StreamConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "splithttp".to_string(),
                        settings: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_TRANSPORT_SPLITHTTP_CONFIG.to_string(),
                            value: XhttpConfigPayload {
                                path: "/dynamic?ed=2048".to_string(),
                                mode: "packet-up".to_string(),
                                x_padding_obfs_mode: true,
                                x_padding_key: "pad".to_string(),
                                x_padding_header: "X-Dynamic-Pad".to_string(),
                                x_padding_placement: "header".to_string(),
                                x_padding_method: "tokenish".to_string(),
                                session_id_placement: "header".to_string(),
                                seq_placement: "query".to_string(),
                                uplink_data_placement: "cookie".to_string(),
                                server_max_header_bytes: 65_536,
                                session_id_table: "Base62".to_string(),
                                session_id_length: Some(XhttpRangePayload {
                                    from: 6,
                                    to: 8,
                                }),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        }),
                    }],
                    security_type: String::new(),
                    security_settings: Vec::new(),
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
            .expect("vless xhttp inbound should parse");
        match parsed.protocol {
            ServerProxyConfig::Xhttp { config, inner } => {
                assert_eq!(config.path, "/dynamic");
                assert_eq!(
                    config.mode,
                    crate::config::server_config::XhttpMode::PacketUp
                );
                assert!(config.padding_obfs_mode);
                assert_eq!(config.padding_key, "pad");
                assert_eq!(config.padding_header, "X-Dynamic-Pad");
                assert_eq!(config.server_max_header_bytes, 65_536);
                assert_eq!(
                    config.session_placement,
                    crate::config::server_config::XhttpPlacement::Header
                );
                assert_eq!(
                    config.seq_placement,
                    crate::config::server_config::XhttpPlacement::Query
                );
                assert_eq!(
                    config.uplink_data_placement,
                    crate::config::server_config::XhttpDataPlacement::Cookie
                );
                match inner.as_ref() {
                    ServerProxyConfig::Vless { users, .. } => {
                        assert_eq!(users.len(), 1);
                        assert_eq!(users[0].user_label, "xhttp-user@example.com");
                    }
                    other => panic!("unexpected XHTTP inner protocol: {other:?}"),
                }
            }
            other => panic!("unexpected dynamic inbound protocol: {other:?}"),
        }
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
                    encryption: String::new(),
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
                        user_id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                        user_label: "first-user@example.com".to_string(),
                        user_level: 0,
                        flow: String::new(),
                    },
                    VlessUser {
                        user_id: "4571894c-7ece-4b27-a734-746330d1a984".to_string(),
                        user_label: "second-user@example.com".to_string(),
                        user_level: 0,
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
                        encryption: String::new(),
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
        runtime.register_inbound_tasks(&inbound_tag, &handles);
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
                        encryption: String::new(),
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
        runtime.abort_inbound_tasks(&inbound_tag);
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
    async fn handler_alter_inbound_rejects_invalid_socks_user() {
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
            .expect_err("expected socks add user without account to fail");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "AddUserOperation.user.account is required for socks"
        );
    }

    #[tokio::test]
    async fn handler_alter_inbound_adds_and_removes_socks_users() {
        let fixture = build_fixture();
        let service = HandlerServiceImpl::new(fixture.runtime.clone());
        let username = unique_tag("socks-user");

        let initial_count = service
            .get_inbound_users_count(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("socks get users count failed")
            .into_inner();
        assert_eq!(initial_count.count, 1);

        let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: username.clone(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
                    value: SocksAccountPayload {
                        username: username.clone(),
                        password: "added-password".to_string(),
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
            .expect("socks add user should succeed");

        let users_after_add = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag.clone(),
                    email: String::new(),
                },
            ))
            .await
            .expect("socks get users after add failed")
            .into_inner()
            .users;
        assert_eq!(users_after_add.len(), 2);
        assert!(users_after_add.iter().any(|user| user.email == username));

        let remove_operation =
            proto::xray::app::proxyman::command::RemoveUserOperation {
                email: username.clone(),
            };
        service
            .alter_inbound(Request::new(
                proto::xray::app::proxyman::command::AlterInboundRequest {
                    tag: fixture.inbound_tag.clone(),
                    operation: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                        value: remove_operation.encode_to_vec(),
                    }),
                },
            ))
            .await
            .expect("socks remove user should succeed");

        let users_after_remove = service
            .get_inbound_users(Request::new(
                proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: fixture.inbound_tag,
                    email: String::new(),
                },
            ))
            .await
            .expect("socks get users after remove failed")
            .into_inner()
            .users;
        assert_eq!(users_after_remove.len(), 1);
        assert!(!users_after_remove.iter().any(|user| user.email == username));
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
                    }],
                    bandwidth: Hysteria2BandwidthConfig::default(),
                    ignore_client_bandwidth: false,
                },
            },
            transport: Transport::Quic,
            quic_settings: None,
        };
        let runtime = RuntimeState::new(vec![inbound], Vec::new());
        let service = HandlerServiceImpl::new(runtime);
        let email = unique_tag("hysteria-user");
        let auth = "added-auth";

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
