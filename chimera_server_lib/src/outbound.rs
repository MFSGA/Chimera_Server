use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "grpc_transport")]
use std::{
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use base64::Engine as _;
#[cfg(feature = "grpc_transport")]
use bytes::BytesMut;
#[cfg(feature = "grpc_transport")]
use futures::StreamExt as _;
#[cfg(feature = "grpc_transport")]
use http_body_util::{BodyExt as _, StreamBody};
#[cfg(feature = "grpc_transport")]
use hyper::{
    Method, Request, body::Frame, client::conn::http2 as client_http2, header,
};
#[cfg(feature = "grpc_transport")]
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use prost::Message;
#[cfg(feature = "ws")]
use rand::RngExt as _;
#[cfg(any(feature = "ws", feature = "grpc_transport"))]
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[cfg(feature = "grpc_transport")]
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    task::AbortHandle,
};
#[cfg(feature = "grpc_transport")]
use tokio_util::io::ReaderStream;
use tracing::warn;

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::def::OutboundItem,
    resolver::{Resolver, resolve_single_address},
    routing_process::enrich_routing_input,
    routing_state::{DomainStrategy, OutboundObservation, RoutingInput},
    runtime::{OutboundSummary, RuntimeState},
    util::socket::new_tcp_socket,
};

#[cfg(feature = "trojan")]
use crate::handler::trojan_udp::TrojanUdpStream;
#[cfg(feature = "ws")]
use crate::handler::ws::WebsocketStream;
#[cfg(feature = "reality")]
use crate::reality::{
    RealityClientConfig, RealityClientConnection, RealityTlsStream,
};
#[cfg(any(feature = "ws", feature = "httpupgrade"))]
use crate::util::prefixed_stream::PrefixedStream;
#[cfg(feature = "grpc_transport")]
use crate::{
    async_stream::AsyncPing,
    beginning::grpc_transport::{
        decode_grpc_message_payloads, encode_grpc_message, grpc_service_paths,
    },
};

const USER_DOMAIN_ACCESS_BLACKHOLE_TAG: &str = "user-domain-access";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG: &str = "xray.proxy.socks.ClientConfig";
const TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ClientConfig";
const TYPE_PROXY_SOCKS_ACCOUNT: &str = "xray.proxy.socks.Account";
const TYPE_PROXY_VLESS_CLIENT_CONFIG: &str = "xray.proxy.vless.outbound.Config";
const TYPE_PROXY_VLESS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.outbound.Config";
const TYPE_PROXY_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
const TYPE_PROXY_VLESS_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.vless.Account";
const TYPE_PROXY_TROJAN_CLIENT_CONFIG: &str = "xray.proxy.trojan.ClientConfig";
const TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ClientConfig";
const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str = "v2ray.core.proxy.trojan.Account";
const TYPE_APP_SENDER_CONFIG: &str = "xray.app.proxyman.SenderConfig";
const TYPE_APP_SENDER_CONFIG_V2RAY: &str = "v2ray.core.app.proxyman.SenderConfig";
const TYPE_TRANSPORT_TLS_CONFIG: &str = "xray.transport.internet.tls.Config";
const TYPE_TRANSPORT_TLS_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.tls.Config";
const TYPE_TRANSPORT_REALITY_CONFIG: &str = "xray.transport.internet.reality.Config";
const TYPE_TRANSPORT_WEBSOCKET_CONFIG: &str =
    "xray.transport.internet.websocket.Config";
const TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.websocket.Config";
const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG: &str =
    "xray.transport.internet.httpupgrade.Config";
const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.httpupgrade.Config";
#[cfg(feature = "grpc_transport")]
const TYPE_TRANSPORT_GRPC_CONFIG: &str =
    "xray.transport.internet.grpc.encoding.Config";
#[cfg(feature = "grpc_transport")]
const TYPE_TRANSPORT_GRPC_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.grpc.encoding.Config";

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
    user: Option<OutboundUserPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct IpOrDomainPayload {
    #[prost(oneof = "ip_or_domain_payload::Address", tags = "1, 2")]
    address: Option<ip_or_domain_payload::Address>,
}

mod ip_or_domain_payload {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct OutboundUserPayload {
    #[prost(uint32, tag = "1")]
    level: u32,
    #[prost(string, tag = "2")]
    email: String,
    #[prost(message, optional, tag = "3")]
    account: Option<TypedMessagePayload>,
}

#[derive(Clone, PartialEq, Message)]
struct TypedMessagePayload {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes, tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SocksAccountPayload {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

#[derive(Clone, PartialEq, Message)]
struct VlessClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    vnext: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct VlessAccountPayload {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    flow: String,
    #[prost(string, tag = "3")]
    encryption: String,
}

#[derive(Clone, PartialEq, Message)]
struct TrojanClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    server: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    password: String,
}

#[derive(Clone, PartialEq, Message)]
struct SenderConfigPayload {
    #[prost(message, optional, tag = "2")]
    stream_settings: Option<OutboundStreamConfigPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct OutboundStreamConfigPayload {
    #[prost(message, repeated, tag = "2")]
    transport_settings: Vec<OutboundTransportConfigPayload>,
    #[prost(string, tag = "5")]
    protocol_name: String,
    #[prost(string, tag = "3")]
    security_type: String,
    #[prost(message, repeated, tag = "4")]
    security_settings: Vec<TypedMessagePayload>,
}

#[derive(Clone, PartialEq, Message)]
struct OutboundTransportConfigPayload {
    #[prost(message, optional, tag = "2")]
    settings: Option<TypedMessagePayload>,
    #[prost(string, tag = "3")]
    protocol_name: String,
}

#[derive(Clone, PartialEq, Message)]
struct WebsocketConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(map = "string, string", tag = "3")]
    header: HashMap<String, String>,
    #[prost(bool, tag = "4")]
    accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    ed: u32,
    #[prost(uint32, tag = "6")]
    heartbeat_period: u32,
}

#[derive(Clone, PartialEq, Message)]
struct HttpUpgradeConfigPayload {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, tag = "2")]
    path: String,
    #[prost(map = "string, string", tag = "3")]
    header: HashMap<String, String>,
    #[prost(bool, tag = "4")]
    accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    ed: u32,
}

#[cfg(feature = "grpc_transport")]
#[derive(Clone, PartialEq, Message)]
struct GrpcConfigPayload {
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

#[derive(Clone, PartialEq, Message)]
struct RealityConfigPayload {
    #[prost(bool, tag = "1")]
    show: bool,
    #[prost(string, tag = "2")]
    dest: String,
    #[prost(string, tag = "3")]
    r#type: String,
    #[prost(uint64, tag = "4")]
    xver: u64,
    #[prost(string, repeated, tag = "5")]
    server_names: Vec<String>,
    #[prost(bytes, tag = "6")]
    private_key: Vec<u8>,
    #[prost(bytes, tag = "7")]
    min_client_ver: Vec<u8>,
    #[prost(bytes, tag = "8")]
    max_client_ver: Vec<u8>,
    #[prost(uint64, tag = "9")]
    max_time_diff: u64,
    #[prost(bytes, repeated, tag = "10")]
    short_ids: Vec<Vec<u8>>,
    #[prost(bytes, tag = "11")]
    mldsa65_seed: Vec<u8>,
    #[prost(string, tag = "21")]
    fingerprint: String,
    #[prost(string, tag = "22")]
    server_name: String,
    #[prost(bytes, tag = "23")]
    public_key: Vec<u8>,
    #[prost(bytes, tag = "24")]
    short_id: Vec<u8>,
    #[prost(bytes, tag = "25")]
    mldsa65_verify: Vec<u8>,
    #[prost(string, tag = "26")]
    spider_x: String,
    #[prost(int64, repeated, tag = "27")]
    spider_y: Vec<i64>,
    #[prost(string, tag = "31")]
    master_key_log: String,
}

#[derive(Clone, PartialEq, Message)]
struct TlsConfigPayload {
    #[prost(message, repeated, tag = "2")]
    certificate: Vec<TlsCertificatePayload>,
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
    #[prost(bytes, tag = "18")]
    ech_server_keys: Vec<u8>,
    #[prost(string, tag = "19")]
    ech_config_list: String,
    #[prost(bytes, repeated, tag = "22")]
    pinned_peer_cert_sha256: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct TlsCertificatePayload {
    #[prost(bytes, tag = "1")]
    certificate: Vec<u8>,
    #[prost(bytes, tag = "2")]
    key: Vec<u8>,
    #[prost(int32, tag = "3")]
    usage: i32,
    #[prost(string, tag = "5")]
    certificate_path: String,
    #[prost(string, tag = "6")]
    key_path: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticSocksClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    pass: String,
    #[serde(default)]
    servers: Vec<StaticSocksServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticSocksServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<StaticSocksUserConfig>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticSocksUserConfig {
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    pass: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticVlessClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    encryption: String,
    #[serde(default)]
    vnext: Vec<StaticVlessServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticVlessServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<StaticVlessUserConfig>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticVlessUserConfig {
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    id: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    encryption: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticTrojanClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    servers: Vec<StaticTrojanServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticTrojanServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    password: String,
    #[serde(default)]
    flow: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundStreamSettings {
    #[serde(default)]
    network: String,
    #[serde(default)]
    security: String,
    #[serde(default)]
    tls_settings: Option<StaticOutboundTlsSettings>,
    #[serde(default, alias = "wsSettings")]
    ws_settings: Option<StaticOutboundWebsocketSettings>,
    #[serde(default, alias = "httpUpgradeSettings")]
    http_upgrade_settings: Option<StaticOutboundHttpUpgradeSettings>,
    #[cfg(feature = "grpc_transport")]
    #[serde(default, alias = "grpcSettings")]
    grpc_settings: Option<StaticOutboundGrpcSettings>,
    #[serde(default, alias = "realitySettings")]
    reality_settings: Option<StaticOutboundRealitySettings>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundWebsocketSettings {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
    #[serde(default)]
    heartbeat_period: u32,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundHttpUpgradeSettings {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundGrpcSettings {
    #[serde(default)]
    authority: String,
    #[serde(default)]
    service_name: String,
    #[serde(default)]
    multi_mode: bool,
    #[serde(default, alias = "idle_timeout")]
    idle_timeout: i32,
    #[serde(default, alias = "health_check_timeout")]
    health_check_timeout: i32,
    #[serde(default, alias = "permit_without_stream")]
    permit_without_stream: bool,
    #[serde(default, alias = "initial_windows_size")]
    initial_windows_size: i32,
    #[serde(default, alias = "user_agent")]
    user_agent: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundRealitySettings {
    #[serde(default)]
    show: bool,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    short_id: String,
    #[serde(default)]
    mldsa65_verify: String,
    #[serde(default)]
    spider_x: String,
    #[serde(default)]
    master_key_log: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundTlsSettings {
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    certificates: Vec<StaticOutboundTlsCertificate>,
    #[serde(default)]
    enable_session_resumption: bool,
    #[serde(default)]
    disable_system_root: bool,
    #[serde(default)]
    min_version: String,
    #[serde(default)]
    max_version: String,
    #[serde(default)]
    cipher_suites: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    reject_unknown_sni: bool,
    #[serde(default)]
    master_key_log: String,
    #[serde(default)]
    curve_preferences: Vec<String>,
    #[serde(default)]
    verify_peer_cert_by_name: String,
    #[serde(default)]
    pinned_peer_cert_sha256: String,
    #[serde(default)]
    ech_server_keys: String,
    #[serde(default)]
    ech_config_list: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundTlsCertificate {
    #[serde(default)]
    certificate_file: String,
    #[serde(default)]
    certificate: Vec<String>,
    #[serde(default)]
    key_file: String,
    #[serde(default)]
    key: Vec<String>,
    #[serde(default)]
    usage: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksOutboundEndpoint {
    server: NetLocation,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VlessOutboundEndpoint {
    server: NetLocation,
    user_id: [u8; 16],
    flow: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrojanOutboundEndpoint {
    server: NetLocation,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum OutboundTransport {
    #[default]
    Raw,
    Tls(OutboundTlsClientSettings),
    Websocket {
        tls: Option<OutboundTlsClientSettings>,
        settings: OutboundWebsocketClientSettings,
    },
    HttpUpgrade {
        tls: Option<OutboundTlsClientSettings>,
        settings: OutboundHttpUpgradeClientSettings,
    },
    #[cfg(feature = "grpc_transport")]
    Grpc {
        tls: Option<OutboundTlsClientSettings>,
        reality: Option<OutboundRealityClientSettings>,
        settings: OutboundGrpcClientSettings,
    },
    Reality(OutboundRealityClientSettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundWebsocketClientSettings {
    host: String,
    path: String,
    headers: HashMap<String, String>,
    ed: u32,
    heartbeat_period: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundHttpUpgradeClientSettings {
    host: String,
    path: String,
    headers: HashMap<String, String>,
    ed: u32,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundGrpcClientSettings {
    authority: String,
    service_name: String,
    multi_mode: bool,
    idle_timeout: i32,
    health_check_timeout: i32,
    permit_without_stream: bool,
    initial_windows_size: i32,
    user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundTlsClientSettings {
    server_name: String,
    alpn: Vec<String>,
    disable_system_root: bool,
    custom_root_certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundRealityClientSettings {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
}

pub(crate) fn compile_static_outbound(
    item: &OutboundItem,
) -> Result<OutboundSummary, String> {
    let protocol = item.protocol.trim().to_ascii_lowercase();
    let sender_settings = match item
        .stream_settings
        .as_ref()
        .filter(|settings| !settings.is_null())
    {
        None => None,
        Some(settings) if protocol == "trojan" => {
            Some(encode_static_sender_settings(settings, &item.tag)?)
        }
        Some(_) if matches!(protocol.as_str(), "socks" | "vless") => {
            return Err(format!(
                "{} outbound {} streamSettings are not implemented yet; refusing to downgrade transport security",
                protocol, item.tag
            ));
        }
        Some(_) => None,
    };
    let (proxy_settings_type, proxy_settings_value) = match protocol.as_str() {
        "socks" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("socks outbound {} requires settings", item.tag)
            })?;
            let config: StaticSocksClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid socks outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_socks_config(config)?;
            (
                Some(TYPE_PROXY_SOCKS_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        "vless" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("vless outbound {} requires settings", item.tag)
            })?;
            let config: StaticVlessClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid vless outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_vless_config(config)?;
            (
                Some(TYPE_PROXY_VLESS_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        "trojan" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("trojan outbound {} requires settings", item.tag)
            })?;
            let config: StaticTrojanClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid trojan outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_trojan_config(config)?;
            (
                Some(TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        _ => (None, None),
    };
    Ok(OutboundSummary {
        tag: item.tag.clone(),
        protocol: item.protocol.clone(),
        proxy_settings_type,
        proxy_settings_value,
        sender_settings_type: sender_settings
            .as_ref()
            .map(|_| TYPE_APP_SENDER_CONFIG.to_string()),
        sender_settings_value: sender_settings
            .map(|settings| settings.encode_to_vec()),
    })
}

fn encode_static_sender_settings(
    value: &serde_json::Value,
    outbound_tag: &str,
) -> Result<SenderConfigPayload, String> {
    let settings: StaticOutboundStreamSettings =
        serde_json::from_value(value.clone()).map_err(|error| {
            format!("invalid outbound {outbound_tag} streamSettings: {error}")
        })?;
    let (protocol_name, transport_settings) = match settings
        .network
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "raw" | "tcp" => ("tcp".to_string(), Vec::new()),
        "ws" | "websocket" => {
            let websocket = encode_static_websocket_config(
                settings.ws_settings.unwrap_or_default(),
            )?;
            (
                "websocket".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "websocket".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
                        value: websocket.encode_to_vec(),
                    }),
                }],
            )
        }
        "httpupgrade" | "http-upgrade" => {
            let http_upgrade = encode_static_httpupgrade_config(
                settings.http_upgrade_settings.unwrap_or_default(),
            )?;
            (
                "httpupgrade".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "httpupgrade".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_HTTPUPGRADE_CONFIG.to_string(),
                        value: http_upgrade.encode_to_vec(),
                    }),
                }],
            )
        }
        #[cfg(feature = "grpc_transport")]
        "grpc" => {
            let grpc = encode_static_grpc_config(
                settings.grpc_settings.unwrap_or_default(),
            )?;
            (
                "grpc".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "grpc".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_GRPC_CONFIG.to_string(),
                        value: grpc.encode_to_vec(),
                    }),
                }],
            )
        }
        network => {
            return Err(format!(
                "outbound {outbound_tag} transport {network} is not implemented yet"
            ));
        }
    };
    let security = settings.security.trim().to_ascii_lowercase();
    let (security_type, security_settings) = match security.as_str() {
        "" | "none" => (String::new(), Vec::new()),
        "tls" => {
            let tls =
                encode_static_tls_config(settings.tls_settings.unwrap_or_default())?;
            (
                TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                vec![TypedMessagePayload {
                    r#type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                    value: tls.encode_to_vec(),
                }],
            )
        }
        "reality" => {
            let reality = encode_static_reality_config(
                settings.reality_settings.unwrap_or_default(),
            )?;
            (
                TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                vec![TypedMessagePayload {
                    r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                    value: reality.encode_to_vec(),
                }],
            )
        }
        security => {
            return Err(format!(
                "outbound {outbound_tag} security {security} is not implemented yet"
            ));
        }
    };
    Ok(SenderConfigPayload {
        stream_settings: Some(OutboundStreamConfigPayload {
            transport_settings,
            protocol_name,
            security_type,
            security_settings,
        }),
    })
}

fn encode_static_websocket_config(
    mut config: StaticOutboundWebsocketSettings,
) -> Result<WebsocketConfigPayload, String> {
    let mut host_header_key = None;
    for key in config.headers.keys() {
        if key.eq_ignore_ascii_case("host") {
            host_header_key = Some(key.clone());
            break;
        }
    }
    if let Some(key) = host_header_key {
        if config.host.is_empty()
            && let Some(host) = config.headers.get(&key)
        {
            config.host = host.clone();
        }
        config.headers.remove(&key);
    }

    let (path, ed) = normalize_websocket_path(&config.path)?;
    Ok(WebsocketConfigPayload {
        host: config.host,
        path,
        header: config.headers,
        accept_proxy_protocol: config.accept_proxy_protocol,
        ed,
        heartbeat_period: config.heartbeat_period,
    })
}

#[cfg(feature = "grpc_transport")]
fn encode_static_grpc_config(
    mut config: StaticOutboundGrpcSettings,
) -> Result<GrpcConfigPayload, String> {
    if config.idle_timeout <= 0 {
        config.idle_timeout = 0;
    }
    if config.health_check_timeout <= 0 {
        config.health_check_timeout = 0;
    }
    if config.initial_windows_size < 0 {
        config.initial_windows_size = 0;
    }
    Ok(GrpcConfigPayload {
        authority: config.authority,
        service_name: config.service_name,
        multi_mode: config.multi_mode,
        idle_timeout: config.idle_timeout,
        health_check_timeout: config.health_check_timeout,
        permit_without_stream: config.permit_without_stream,
        initial_windows_size: config.initial_windows_size,
        user_agent: config.user_agent,
    })
}

fn encode_static_httpupgrade_config(
    mut config: StaticOutboundHttpUpgradeSettings,
) -> Result<HttpUpgradeConfigPayload, String> {
    for key in config.headers.keys() {
        if key.eq_ignore_ascii_case("host") {
            return Err(
                "HTTPUpgrade outbound headers can't contain Host; use host instead"
                    .into(),
            );
        }
    }
    let (path, ed) = normalize_websocket_path(&config.path)?;
    Ok(HttpUpgradeConfigPayload {
        host: config.host,
        path,
        header: std::mem::take(&mut config.headers),
        accept_proxy_protocol: config.accept_proxy_protocol,
        ed,
    })
}

fn normalize_websocket_path(path: &str) -> Result<(String, u32), String> {
    let path = if path.is_empty() { "/" } else { path };
    let Some((base, query)) = path.split_once('?') else {
        return Ok((path.to_string(), 0));
    };
    let mut ed = 0u32;
    let mut kept = Vec::new();
    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=')
            && key == "ed"
        {
            ed = value.parse::<u32>().unwrap_or_default();
            continue;
        }
        if !part.is_empty() {
            kept.push(part);
        }
    }
    let normalized = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok((
        if normalized.is_empty() {
            "/".to_string()
        } else {
            normalized
        },
        ed,
    ))
}

fn encode_static_reality_config(
    config: StaticOutboundRealitySettings,
) -> Result<RealityConfigPayload, String> {
    let fingerprint = config.fingerprint.trim().to_ascii_lowercase();
    if !matches!(fingerprint.as_str(), "" | "chrome") {
        return Err(format!(
            "REALITY outbound fingerprint {} is not implemented; only chrome is supported",
            config.fingerprint
        ));
    }
    if !config.mldsa65_verify.trim().is_empty() {
        return Err(
            "REALITY outbound ML-DSA verification is not implemented yet".into(),
        );
    }
    if !config.master_key_log.trim().is_empty() {
        return Err("REALITY outbound masterKeyLog is not implemented yet".into());
    }
    if !config.spider_x.trim().is_empty() && config.spider_x.trim() != "/" {
        return Err(
            "REALITY outbound spiderX fallback crawling is not implemented; only '/' is accepted"
                .into(),
        );
    }
    let public_key_text = if config.public_key.trim().is_empty() {
        config.password.trim()
    } else {
        config.public_key.trim()
    };
    if public_key_text.is_empty() {
        return Err(
            "REALITY outbound requires publicKey (or legacy password)".into()
        );
    }
    let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(public_key_text)
        .map_err(|error| format!("invalid REALITY outbound publicKey: {error}"))?;
    let public_key: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        "invalid REALITY outbound publicKey: decoded key must contain exactly 32 bytes"
            .to_string()
    })?;
    let short_id_text = config.short_id.trim();
    if short_id_text.len() > 16 || !short_id_text.len().is_multiple_of(2) {
        return Err("invalid REALITY outbound shortId length".into());
    }
    let mut short_id = [0u8; 8];
    for (index, chunk) in short_id_text.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| "invalid REALITY outbound shortId".to_string())?;
        short_id[index] = u8::from_str_radix(text, 16)
            .map_err(|_| "invalid REALITY outbound shortId".to_string())?;
    }
    Ok(RealityConfigPayload {
        show: config.show,
        dest: String::new(),
        r#type: String::new(),
        xver: 0,
        server_names: Vec::new(),
        private_key: Vec::new(),
        min_client_ver: Vec::new(),
        max_client_ver: Vec::new(),
        max_time_diff: 0,
        short_ids: Vec::new(),
        mldsa65_seed: Vec::new(),
        fingerprint: if fingerprint.is_empty() {
            "chrome".to_string()
        } else {
            fingerprint
        },
        server_name: config.server_name,
        public_key: public_key.to_vec(),
        short_id: short_id.to_vec(),
        mldsa65_verify: Vec::new(),
        spider_x: if config.spider_x.trim().is_empty() {
            "/".to_string()
        } else {
            config.spider_x
        },
        spider_y: Vec::new(),
        master_key_log: String::new(),
    })
}

fn encode_static_tls_config(
    config: StaticOutboundTlsSettings,
) -> Result<TlsConfigPayload, String> {
    if config.allow_insecure {
        return Err(
            "TLS allowInsecure is removed by current Xray and is not accepted"
                .into(),
        );
    }
    let certificates = config
        .certificates
        .into_iter()
        .map(encode_static_tls_certificate)
        .collect::<Result<Vec<_>, _>>()?;
    if config.enable_session_resumption {
        return Err(
            "TLS enableSessionResumption is not implemented for outbound yet".into(),
        );
    }
    if !config.min_version.is_empty() || !config.max_version.is_empty() {
        return Err(
            "TLS minVersion/maxVersion are not implemented for outbound yet".into(),
        );
    }
    if !config.cipher_suites.is_empty() {
        return Err("TLS cipherSuites are not implemented for outbound yet".into());
    }
    if !config.fingerprint.is_empty() {
        return Err(
            "TLS fingerprint/uTLS is not implemented for outbound yet".into()
        );
    }
    if config.reject_unknown_sni {
        return Err(
            "TLS rejectUnknownSni is a server-side option and is not accepted here"
                .into(),
        );
    }
    if !config.master_key_log.is_empty()
        || !config.curve_preferences.is_empty()
        || !config.verify_peer_cert_by_name.is_empty()
        || !config.pinned_peer_cert_sha256.is_empty()
        || !config.ech_server_keys.is_empty()
        || !config.ech_config_list.is_empty()
    {
        return Err(
            "advanced TLS verification/fingerprint/ECH settings are not implemented for outbound yet"
                .into(),
        );
    }
    Ok(TlsConfigPayload {
        certificate: certificates,
        server_name: config.server_name,
        next_protocol: config.alpn,
        enable_session_resumption: false,
        disable_system_root: config.disable_system_root,
        min_version: String::new(),
        max_version: String::new(),
        cipher_suites: String::new(),
        fingerprint: String::new(),
        reject_unknown_sni: false,
        master_key_log: String::new(),
        curve_preferences: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        ech_server_keys: Vec::new(),
        ech_config_list: String::new(),
        pinned_peer_cert_sha256: Vec::new(),
    })
}

fn encode_static_tls_certificate(
    certificate: StaticOutboundTlsCertificate,
) -> Result<TlsCertificatePayload, String> {
    if !certificate.key_file.trim().is_empty() || !certificate.key.is_empty() {
        return Err(
            "TLS outbound client certificates are not implemented; only usage=verify trust roots are supported"
                .into(),
        );
    }
    let usage = certificate.usage.trim().to_ascii_lowercase();
    if usage != "verify" {
        return Err(format!(
            "TLS outbound certificate usage {} is not implemented; only verify is supported",
            if usage.is_empty() {
                "encipherment"
            } else {
                usage.as_str()
            }
        ));
    }
    let certificate_bytes = if !certificate.certificate_file.trim().is_empty() {
        std::fs::read(certificate.certificate_file.trim()).map_err(|error| {
            format!(
                "failed to read outbound TLS certificate {}: {error}",
                certificate.certificate_file
            )
        })?
    } else if !certificate.certificate.is_empty() {
        certificate.certificate.join("\n").into_bytes()
    } else {
        return Err("TLS outbound verify certificate requires certificate or certificateFile".into());
    };
    Ok(TlsCertificatePayload {
        certificate: certificate_bytes,
        key: Vec::new(),
        usage: 1,
        certificate_path: String::new(),
        key_path: String::new(),
    })
}

fn encode_static_socks_config(
    mut config: StaticSocksClientConfig,
) -> Result<SocksClientConfigPayload, String> {
    let (server, user) = if let Some(address) = config.address.take() {
        if config.port == 0 {
            return Err("SOCKS outbound port must be between 1 and 65535".into());
        }
        let user = (!config.user.is_empty()).then_some(StaticSocksUserConfig {
            level: config.level,
            email: config.email,
            user: config.user,
            pass: config.pass,
        });
        (
            StaticSocksServerConfig {
                address,
                port: config.port,
                users: Vec::new(),
            },
            user,
        )
    } else {
        if config.servers.len() != 1 {
            return Err(
                "SOCKS settings servers must contain exactly one endpoint".into()
            );
        }
        let mut server = config.servers.remove(0);
        if server.port == 0 {
            return Err("SOCKS outbound port must be between 1 and 65535".into());
        }
        if server.users.len() > 1 {
            return Err(
                "SOCKS outbound server users must contain at most one member".into(),
            );
        }
        let user = server.users.pop();
        (server, user)
    };

    let address = encode_ip_or_domain(&server.address)?;
    let user = user.map(encode_static_socks_user);
    Ok(SocksClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(address),
            port: u32::from(server.port),
            user,
        }),
    })
}

fn encode_static_vless_config(
    mut config: StaticVlessClientConfig,
) -> Result<VlessClientConfigPayload, String> {
    let (server, user) = if let Some(address) = config.address.take() {
        if config.port == 0 {
            return Err("VLESS outbound port must be between 1 and 65535".into());
        }
        (
            StaticVlessServerConfig {
                address,
                port: config.port,
                users: Vec::new(),
            },
            StaticVlessUserConfig {
                level: config.level,
                email: config.email,
                id: config.id,
                flow: config.flow,
                encryption: config.encryption,
            },
        )
    } else {
        if config.vnext.len() != 1 {
            return Err(
                "VLESS settings vnext must contain exactly one endpoint".into()
            );
        }
        let mut server = config.vnext.remove(0);
        if server.port == 0 {
            return Err("VLESS outbound port must be between 1 and 65535".into());
        }
        if server.users.len() != 1 {
            return Err(
                "VLESS outbound vnext users must contain exactly one member".into(),
            );
        }
        let user = server.users.remove(0);
        (server, user)
    };

    if !user.flow.trim().is_empty() {
        return Err(format!(
            "VLESS outbound flow {} is not implemented yet; only empty flow is supported",
            user.flow
        ));
    }
    if !user.encryption.trim().eq_ignore_ascii_case("none") {
        return Err(format!(
            "VLESS outbound encryption must be none, got {}",
            user.encryption
        ));
    }
    parse_xray_uuid(&user.id)?;

    let account = VlessAccountPayload {
        id: user.id,
        flow: user.flow,
        encryption: user.encryption,
    };
    Ok(VlessClientConfigPayload {
        vnext: Some(SocksServerEndpointPayload {
            address: Some(encode_ip_or_domain(&server.address)?),
            port: u32::from(server.port),
            user: Some(OutboundUserPayload {
                level: user.level,
                email: user.email,
                account: Some(TypedMessagePayload {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: account.encode_to_vec(),
                }),
            }),
        }),
    })
}

fn encode_static_trojan_config(
    mut config: StaticTrojanClientConfig,
) -> Result<TrojanClientConfigPayload, String> {
    let server = if let Some(address) = config.address.take() {
        StaticTrojanServerConfig {
            address,
            port: config.port,
            level: config.level,
            email: config.email,
            password: config.password,
            flow: config.flow,
        }
    } else {
        if config.servers.len() != 1 {
            return Err(
                "Trojan settings servers must contain exactly one endpoint".into()
            );
        }
        config.servers.remove(0)
    };
    if server.port == 0 {
        return Err("Trojan outbound port must be between 1 and 65535".into());
    }
    if server.password.is_empty() {
        return Err("Trojan outbound password is required".into());
    }
    if !server.flow.is_empty() {
        return Err(
            "Trojan outbound flow is removed by current Xray and must be empty"
                .into(),
        );
    }
    Ok(TrojanClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(encode_ip_or_domain(&server.address)?),
            port: u32::from(server.port),
            user: Some(OutboundUserPayload {
                level: server.level,
                email: server.email,
                account: Some(TypedMessagePayload {
                    r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                    value: TrojanAccountPayload {
                        password: server.password,
                    }
                    .encode_to_vec(),
                }),
            }),
        }),
    })
}

fn encode_ip_or_domain(value: &str) -> Result<IpOrDomainPayload, String> {
    let address = Address::from(value)
        .map_err(|error| format!("invalid outbound address {value}: {error}"))?;
    let address = match address {
        Address::Ipv4(ip) => ip_or_domain_payload::Address::Ip(ip.octets().to_vec()),
        Address::Ipv6(ip) => ip_or_domain_payload::Address::Ip(ip.octets().to_vec()),
        Address::Hostname(domain) => ip_or_domain_payload::Address::Domain(domain),
    };
    Ok(IpOrDomainPayload {
        address: Some(address),
    })
}

pub(crate) fn parse_xray_uuid(value: &str) -> Result<[u8; 16], String> {
    let text = value.as_bytes();
    if text.len() < 32 || text.len() > 36 {
        if text.is_empty() || text.len() > 30 {
            return Err(format!("invalid VLESS UUID: {value}"));
        }
        let mut input = [0u8; 16].to_vec();
        input.extend_from_slice(text);
        let digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            &input,
        );
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&digest.as_ref()[..16]);
        uuid[6] = (uuid[6] & 0x0f) | (5 << 4);
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        return Ok(uuid);
    }

    let mut uuid = [0u8; 16];
    let mut source = text;
    let mut offset = 0usize;
    for group_len in [8usize, 4, 4, 4, 12] {
        if source.first() == Some(&b'-') {
            source = &source[1..];
        }
        if source.len() < group_len {
            return Err(format!("invalid VLESS UUID: {value}"));
        }
        for pair in source[..group_len].as_chunks::<2>().0 {
            let encoded = std::str::from_utf8(pair)
                .map_err(|_| format!("invalid VLESS UUID: {value}"))?;
            uuid[offset] = u8::from_str_radix(encoded, 16)
                .map_err(|_| format!("invalid VLESS UUID: {value}"))?;
            offset += 1;
        }
        source = &source[group_len..];
    }
    Ok(uuid)
}

fn encode_static_socks_user(user: StaticSocksUserConfig) -> OutboundUserPayload {
    let account = SocksAccountPayload {
        username: user.user,
        password: user.pass,
    };
    OutboundUserPayload {
        level: user.level,
        email: user.email,
        account: Some(TypedMessagePayload {
            r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
            value: account.encode_to_vec(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
    Socks { outbound: OutboundSummary },
    Vless { outbound: OutboundSummary },
    Trojan { outbound: OutboundSummary },
}

pub(crate) struct TcpOutboundConnection {
    pub stream: Box<dyn AsyncStream>,
    pub outbound_tag: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InboundRoutingMetadata {
    pub local_addr: Option<SocketAddr>,
    pub vless_route: u32,
    pub sniffed_protocol: Option<String>,
    pub route_target_domain: Option<String>,
    pub attributes: HashMap<String, String>,
}

pub(crate) struct OutboundRoutingContext<'a> {
    pub inbound_tag: &'a str,
    pub user: &'a str,
    pub source_addr: SocketAddr,
    pub network: i32,
    pub network_name: &'a str,
    pub metadata: InboundRoutingMetadata,
}

impl<'a> OutboundRoutingContext<'a> {
    pub fn new(
        inbound_tag: &'a str,
        user: &'a str,
        source_addr: SocketAddr,
        network: i32,
        network_name: &'a str,
        metadata: InboundRoutingMetadata,
    ) -> Self {
        Self {
            inbound_tag,
            user,
            source_addr,
            network,
            network_name,
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpRoutePlan {
    Freedom {
        target_addr: SocketAddr,
        outbound_tag: Option<String>,
    },
    Socks {
        target: NetLocation,
        outbound: OutboundSummary,
    },
    Vless {
        target: NetLocation,
        outbound: OutboundSummary,
    },
    Trojan {
        target: NetLocation,
        outbound: OutboundSummary,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrojanCommand {
    Tcp,
    Udp,
}

impl TrojanCommand {
    fn byte(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x03,
        }
    }
}

#[derive(Debug)]
enum TcpProtocolHandshake {
    None,
    Socks {
        target: NetLocation,
        endpoint: SocksOutboundEndpoint,
    },
    Vless {
        target: NetLocation,
        endpoint: VlessOutboundEndpoint,
    },
    Trojan {
        target: NetLocation,
        endpoint: TrojanOutboundEndpoint,
    },
}

pub(crate) fn apply_routing_metadata(
    mut input: RoutingInput,
    metadata: InboundRoutingMetadata,
) -> RoutingInput {
    input.vless_route = metadata.vless_route;
    if let Some(local_addr) = metadata.local_addr {
        input.local_ips = vec![encode_ip(local_addr.ip())];
        input.local_port = local_addr.port() as u32;
    }
    if let Some(domain) = metadata.route_target_domain {
        input.target_domain = domain;
    }
    if let Some(protocol) = metadata.sniffed_protocol {
        input.protocol = protocol;
    }
    input.attributes = metadata.attributes;
    input
}

pub(crate) async fn connect_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    connect_tcp_outbound_with_vless_route(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        0,
    )
    .await
}

pub(crate) async fn connect_tcp_outbound_with_vless_route(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    vless_route: u32,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    connect_tcp_outbound_with_routing_metadata(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        InboundRoutingMetadata {
            vless_route,
            ..InboundRoutingMetadata::default()
        },
    )
    .await
}

pub(crate) async fn connect_tcp_outbound_with_routing_metadata(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    let Some(plan) = plan_tcp_route(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        routing_metadata,
    )
    .await?
    else {
        return Ok(None);
    };

    connect_planned_tcp_outbound(resolver, runtime, plan, true, TrojanCommand::Tcp)
        .await
        .map(Some)
}

async fn plan_tcp_route(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<TcpRoutePlan>> {
    let (action, target_addr) = select_direct_outbound_for_location(
        resolver,
        remote_location,
        runtime,
        OutboundRoutingContext::new(
            inbound_tag,
            user,
            source_addr,
            2,
            "tcp",
            routing_metadata,
        ),
    )
    .await?;
    match action {
        DirectOutboundAction::Blackhole { .. } => Ok(None),
        DirectOutboundAction::Freedom { tag } => Ok(Some(TcpRoutePlan::Freedom {
            target_addr: target_addr.ok_or_else(|| {
                std::io::Error::other("TCP freedom route did not resolve target")
            })?,
            outbound_tag: tag,
        })),
        DirectOutboundAction::Socks { outbound } => Ok(Some(TcpRoutePlan::Socks {
            target: remote_location.clone(),
            outbound,
        })),
        DirectOutboundAction::Vless { outbound } => Ok(Some(TcpRoutePlan::Vless {
            target: remote_location.clone(),
            outbound,
        })),
        DirectOutboundAction::Trojan { outbound } => {
            Ok(Some(TcpRoutePlan::Trojan {
                target: remote_location.clone(),
                outbound,
            }))
        }
    }
}

pub(crate) async fn select_direct_outbound_for_location(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    context: OutboundRoutingContext<'_>,
) -> std::io::Result<(DirectOutboundAction, Option<SocketAddr>)> {
    let mut route_input = apply_routing_metadata(
        unresolved_connection_routing_input(
            context.inbound_tag,
            context.user,
            context.network,
            context.source_addr,
            remote_location,
        ),
        context.metadata,
    );
    if !runtime
        .allows_user_domain_access(&route_input.user, &route_input.target_domain)
    {
        return Ok((
            DirectOutboundAction::Blackhole {
                tag: USER_DOMAIN_ACCESS_BLACKHOLE_TAG.to_string(),
            },
            None,
        ));
    }

    let routing_location =
        routing_resolution_location(&route_input, remote_location);
    let routing = runtime.routing();
    let domain_strategy = routing.domain_strategy();
    let mut resolved_for_routing = None;

    if routing.needs_target_ip_resolution(&route_input) {
        let addresses = resolve_all_addresses(resolver, &routing_location).await?;
        route_input.target_ips = encode_target_ips(&addresses);
        resolved_for_routing = Some(addresses);
    }
    route_input = enrich_route_input_if_needed(runtime, route_input).await;

    let selected = if domain_strategy == DomainStrategy::IpIfNonMatch
        && !route_input.target_domain.is_empty()
        && route_input.target_ips.is_empty()
    {
        match runtime
            .match_outbound_checked(&route_input)
            .map_err(invalid_routing_error)?
        {
            Some(outbound) => Some(outbound),
            None => {
                let addresses =
                    resolve_all_addresses(resolver, &routing_location).await?;
                route_input.target_ips = encode_target_ips(&addresses);
                resolved_for_routing = Some(addresses);
                route_input =
                    enrich_route_input_if_needed(runtime, route_input).await;
                runtime
                    .select_outbound_checked(&route_input)
                    .map_err(invalid_routing_error)?
            }
        }
    } else {
        runtime
            .select_outbound_checked(&route_input)
            .map_err(invalid_routing_error)?
    };

    let action = classify_selected_outbound(selected, context.network_name)?;
    match action {
        DirectOutboundAction::Blackhole { .. }
        | DirectOutboundAction::Socks { .. }
        | DirectOutboundAction::Vless { .. }
        | DirectOutboundAction::Trojan { .. } => Ok((action, None)),
        DirectOutboundAction::Freedom { .. } => {
            let target_addr = match remote_location.to_socket_addr_nonblocking() {
                Some(target_addr) => target_addr,
                None if routing_location == *remote_location => resolved_for_routing
                    .as_ref()
                    .and_then(|addresses| addresses.first().copied())
                    .unwrap_or(
                        resolve_single_address(resolver, remote_location).await?,
                    ),
                None => resolve_single_address(resolver, remote_location).await?,
            };
            Ok((action, Some(target_addr)))
        }
    }
}

fn invalid_routing_error(error: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
}

async fn resolve_all_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    let addresses = resolver.resolve_location(location).await?;
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("DNS lookup returned no addresses for {location}"),
        ));
    }
    Ok(addresses)
}

fn encode_target_ips(addresses: &[SocketAddr]) -> Vec<Vec<u8>> {
    addresses
        .iter()
        .map(|address| encode_ip(address.ip()))
        .collect()
}

fn routing_resolution_location(
    input: &RoutingInput,
    remote_location: &NetLocation,
) -> NetLocation {
    if remote_location.address().is_hostname()
        && !input.target_domain.is_empty()
        && remote_location.address().hostname() != Some(input.target_domain.as_str())
    {
        return NetLocation::new(
            Address::Hostname(input.target_domain.clone()),
            remote_location.port(),
        );
    }
    remote_location.clone()
}

async fn enrich_route_input_if_needed(
    runtime: &RuntimeState,
    mut input: RoutingInput,
) -> RoutingInput {
    if runtime.routing().needs_process_lookup(&input) {
        enrich_routing_input(&mut input).await;
    }
    input
}

async fn connect_planned_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    plan: TcpRoutePlan,
    record_observation: bool,
    trojan_command: TrojanCommand,
) -> std::io::Result<TcpOutboundConnection> {
    let (target_addr, outbound_tag, transport, transport_server, handshake) =
        match plan {
            TcpRoutePlan::Freedom {
                target_addr,
                outbound_tag,
            } => (
                target_addr,
                outbound_tag,
                OutboundTransport::Raw,
                None,
                TcpProtocolHandshake::None,
            ),
            TcpRoutePlan::Socks { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_socks_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Socks { target, endpoint },
                )
            }
            TcpRoutePlan::Vless { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_vless_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Vless { target, endpoint },
                )
            }
            TcpRoutePlan::Trojan { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_trojan_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Trojan { target, endpoint },
                )
            }
        };
    let record = |observation| {
        if record_observation {
            record_tcp_connect_observation(
                runtime,
                outbound_tag.as_deref(),
                observation,
            );
        }
    };
    let websocket_early_data = match (&transport, &handshake) {
        (
            OutboundTransport::Websocket { settings, .. },
            TcpProtocolHandshake::Trojan { target, endpoint },
        ) if settings.ed > 0 => {
            let request = build_trojan_request(endpoint, target, trojan_command)?;
            (request.len() <= settings.ed as usize).then_some(request)
        }
        _ => None,
    };
    let httpupgrade_early_data = match (&transport, &handshake) {
        (
            OutboundTransport::HttpUpgrade { settings, .. },
            TcpProtocolHandshake::Trojan { target, endpoint },
        ) if settings.ed > 0 => {
            Some(build_trojan_request(endpoint, target, trojan_command)?)
        }
        _ => None,
    };
    let handshake_sent_as_early_data =
        websocket_early_data.is_some() || httpupgrade_early_data.is_some();

    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let started = Instant::now();
    let attempted_at = unix_time_secs();
    let raw_stream = match tcp_socket.connect(target_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            record(tcp_connect_observation(
                false,
                elapsed_millis(started),
                attempted_at,
                error.to_string(),
            ));
            return Err(error);
        }
    };
    if let Err(error) = raw_stream.set_nodelay(true) {
        warn!("Failed to set TCP no-delay on client socket: {}", error);
    }

    let mut stream: Box<dyn AsyncStream> = match transport {
        OutboundTransport::Raw => Box::new(raw_stream),
        OutboundTransport::Tls(settings) => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other("TLS outbound is missing its server identity")
            })?;
            #[cfg(feature = "tls")]
            {
                match connect_tls_transport(raw_stream, &settings, server).await {
                    Ok(stream) => Box::new(stream),
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (raw_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TLS outbound requires the tls feature",
                ));
            }
        }
        OutboundTransport::Websocket { tls, settings } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "WebSocket outbound is missing its server identity",
                )
            })?;
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let base_stream: Box<dyn AsyncStream> = match tls {
                None => Box::new(raw_stream),
                Some(settings) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "WebSocket TLS outbound requires the tls feature",
                        ));
                    }
                }
            };
            #[cfg(feature = "ws")]
            {
                match connect_websocket_transport(
                    base_stream,
                    &settings,
                    server,
                    tls_server_name.as_deref(),
                    websocket_early_data.as_deref(),
                )
                .await
                {
                    Ok(stream) => Box::new(stream),
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "ws"))]
            {
                let _ = (base_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "WebSocket outbound requires the ws feature",
                ));
            }
        }
        OutboundTransport::HttpUpgrade { tls, settings } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "HTTPUpgrade outbound is missing its server identity",
                )
            })?;
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let base_stream: Box<dyn AsyncStream> = match tls {
                None => Box::new(raw_stream),
                Some(settings) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "HTTPUpgrade TLS outbound requires the tls feature",
                        ));
                    }
                }
            };
            #[cfg(feature = "httpupgrade")]
            {
                match connect_httpupgrade_transport(
                    base_stream,
                    &settings,
                    server,
                    tls_server_name.as_deref(),
                    httpupgrade_early_data.as_deref(),
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "httpupgrade"))]
            {
                let _ = (base_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "HTTPUpgrade outbound requires the httpupgrade feature",
                ));
            }
        }
        #[cfg(feature = "grpc_transport")]
        OutboundTransport::Grpc {
            tls,
            reality,
            settings,
        } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other("gRPC outbound is missing its server identity")
            })?;
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let reality_transport = reality.is_some();
            let base_stream: Box<dyn AsyncStream> = match (tls, reality) {
                (None, None) => Box::new(raw_stream),
                (Some(settings), None) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "gRPC TLS outbound requires the tls feature",
                        ));
                    }
                }
                (None, Some(settings)) => {
                    #[cfg(feature = "reality")]
                    {
                        match connect_reality_transport(
                            raw_stream, &settings, server,
                        ) {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "reality"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "gRPC REALITY outbound requires the reality feature",
                        ));
                    }
                }
                (Some(_), Some(_)) => {
                    unreachable!("one Xray stream has one security type")
                }
            };
            match connect_grpc_transport(
                base_stream,
                &settings,
                server,
                tls_server_name.as_deref(),
                reality_transport,
            )
            .await
            {
                Ok(stream) => Box::new(stream),
                Err(error) => {
                    record(tcp_connect_observation(
                        false,
                        elapsed_millis(started),
                        attempted_at,
                        error.to_string(),
                    ));
                    return Err(error);
                }
            }
        }
        OutboundTransport::Reality(settings) => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "REALITY outbound is missing its server identity",
                )
            })?;
            #[cfg(feature = "reality")]
            {
                connect_reality_transport(raw_stream, &settings, server)
                    .inspect_err(|error| {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                    })
                    .map(|stream| Box::new(stream) as Box<dyn AsyncStream>)?
            }
            #[cfg(not(feature = "reality"))]
            {
                let _ = (raw_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound requires the reality feature",
                ));
            }
        }
    };

    let handshake_result = match handshake {
        TcpProtocolHandshake::None => Ok(()),
        TcpProtocolHandshake::Socks { target, endpoint } => {
            socks5_connect(&mut *stream, &endpoint, &target).await
        }
        TcpProtocolHandshake::Vless { target, endpoint } => {
            vless_tcp_connect(&mut *stream, &endpoint, &target).await
        }
        TcpProtocolHandshake::Trojan { .. } if handshake_sent_as_early_data => {
            Ok(())
        }
        TcpProtocolHandshake::Trojan { target, endpoint } => {
            trojan_connect(&mut *stream, &endpoint, &target, trojan_command).await
        }
    };
    if let Err(error) = handshake_result {
        record(tcp_connect_observation(
            false,
            elapsed_millis(started),
            attempted_at,
            error.to_string(),
        ));
        return Err(error);
    }

    record(tcp_connect_observation(
        true,
        elapsed_millis(started),
        attempted_at,
        String::new(),
    ));
    Ok(TcpOutboundConnection {
        stream,
        outbound_tag,
    })
}

pub(crate) async fn connect_tcp_via_outbound(
    resolver: &Arc<dyn Resolver>,
    target: &NetLocation,
    runtime: &RuntimeState,
    outbound: &OutboundSummary,
) -> std::io::Result<TcpOutboundConnection> {
    let plan = match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => TcpRoutePlan::Freedom {
            target_addr: resolve_single_address(resolver, target).await?,
            outbound_tag: Some(outbound.tag.clone()),
        },
        "socks" => TcpRoutePlan::Socks {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "vless" => TcpRoutePlan::Vless {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "trojan" => TcpRoutePlan::Trojan {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "blackhole" => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("outbound {} is blackhole", outbound.tag),
            ));
        }
        protocol => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "outbound {} protocol {} has no TCP connector",
                    outbound.tag, protocol
                ),
            ));
        }
    };
    connect_planned_tcp_outbound(resolver, runtime, plan, false, TrojanCommand::Tcp)
        .await
}

#[cfg(feature = "trojan")]
pub(crate) async fn connect_trojan_udp_via_outbound(
    resolver: &Arc<dyn Resolver>,
    target: &NetLocation,
    runtime: &RuntimeState,
    outbound: &OutboundSummary,
) -> std::io::Result<TrojanUdpStream> {
    if !outbound.protocol.trim().eq_ignore_ascii_case("trojan") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "outbound {} protocol {} is not Trojan",
                outbound.tag, outbound.protocol
            ),
        ));
    }
    let connection = connect_planned_tcp_outbound(
        resolver,
        runtime,
        TcpRoutePlan::Trojan {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        true,
        TrojanCommand::Udp,
    )
    .await?;
    Ok(TrojanUdpStream::new(connection.stream))
}

pub(crate) fn reqwest_proxy_for_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<Option<reqwest::Proxy>> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(None),
        "socks" => {
            let endpoint = decode_socks_outbound(outbound)?;
            let (address, port) = endpoint.server.components();
            let host = match address {
                Address::Ipv4(ip) => ip.to_string(),
                Address::Ipv6(ip) => format!("[{ip}]"),
                Address::Hostname(domain) => domain.clone(),
            };
            let mut proxy = reqwest::Proxy::all(format!("socks5h://{host}:{port}"))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "invalid SOCKS proxy URL for {}: {error}",
                            outbound.tag
                        ),
                    )
                })?;
            if let Some(username) = endpoint.username.as_deref() {
                proxy = proxy.basic_auth(
                    username,
                    endpoint.password.as_deref().unwrap_or_default(),
                );
            }
            Ok(Some(proxy))
        }
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "outbound {} protocol {} cannot be used as an HTTP probe transport",
                outbound.tag, protocol
            ),
        )),
    }
}

fn decode_socks_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<SocksOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_SOCKS_CLIENT_CONFIG
        && message_type != TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "SOCKS outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = SocksClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid SOCKS outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.server.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} requires a server endpoint", outbound.tag),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SOCKS outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} has invalid server address", outbound.tag),
        )
    })?;
    let (username, password) = match server.user.and_then(|user| user.account) {
        Some(account) => {
            let account_type = account.r#type.trim_start_matches('.');
            if account_type != TYPE_PROXY_SOCKS_ACCOUNT
                && account_type != "v2ray.core.proxy.socks.Account"
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "SOCKS outbound {} has unsupported account type {}",
                        outbound.tag, account.r#type
                    ),
                ));
            }
            let account = SocksAccountPayload::decode(account.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "invalid SOCKS outbound {} account: {error}",
                            outbound.tag
                        ),
                    )
                })?;
            (Some(account.username), Some(account.password))
        }
        None => (None, None),
    };
    Ok(SocksOutboundEndpoint {
        server: NetLocation::new(address, port),
        username,
        password,
    })
}

fn decode_vless_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<VlessOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_VLESS_CLIENT_CONFIG
        && message_type != TYPE_PROXY_VLESS_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "VLESS outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = VlessClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid VLESS outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.vnext.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} requires a vnext endpoint", outbound.tag),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("VLESS outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} has invalid server address", outbound.tag),
        )
    })?;
    let account = server.user.and_then(|user| user.account).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} requires exactly one user", outbound.tag),
        )
    })?;
    let account_type = account.r#type.trim_start_matches('.');
    if account_type != TYPE_PROXY_VLESS_ACCOUNT
        && account_type != TYPE_PROXY_VLESS_ACCOUNT_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "VLESS outbound {} has unsupported account type {}",
                outbound.tag, account.r#type
            ),
        ));
    }
    let account =
        VlessAccountPayload::decode(account.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid VLESS outbound {} account: {error}", outbound.tag),
            )
        })?;
    if !account.flow.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "VLESS outbound {} flow {} is not implemented yet",
                outbound.tag, account.flow
            ),
        ));
    }
    if !account.encryption.trim().eq_ignore_ascii_case("none") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "VLESS outbound {} encryption {} is not implemented",
                outbound.tag, account.encryption
            ),
        ));
    }
    let user_id = parse_xray_uuid(&account.id).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
    })?;
    Ok(VlessOutboundEndpoint {
        server: NetLocation::new(address, port),
        user_id,
        flow: account.flow,
    })
}

fn decode_trojan_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<TrojanOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_TROJAN_CLIENT_CONFIG
        && message_type != TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = TrojanClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid Trojan outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.server.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} requires a server endpoint",
                outbound.tag
            ),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Trojan outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} has invalid server address",
                outbound.tag
            ),
        )
    })?;
    let account = server.user.and_then(|user| user.account).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} requires exactly one user", outbound.tag),
        )
    })?;
    let account_type = account.r#type.trim_start_matches('.');
    if account_type != TYPE_PROXY_TROJAN_ACCOUNT
        && account_type != TYPE_PROXY_TROJAN_ACCOUNT_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} has unsupported account type {}",
                outbound.tag, account.r#type
            ),
        ));
    }
    let account =
        TrojanAccountPayload::decode(account.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid Trojan outbound {} account: {error}", outbound.tag),
            )
        })?;
    if account.password.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} password is empty", outbound.tag),
        ));
    }
    Ok(TrojanOutboundEndpoint {
        server: NetLocation::new(address, port),
        password: account.password,
    })
}

fn decode_outbound_transport(
    outbound: &OutboundSummary,
) -> std::io::Result<OutboundTransport> {
    decode_sender_transport(
        outbound.sender_settings_type.as_deref(),
        outbound.sender_settings_value.as_deref(),
    )
}

pub(crate) fn validate_outbound_sender_settings(
    message_type: Option<&str>,
    value: Option<&[u8]>,
) -> std::io::Result<()> {
    decode_sender_transport(message_type, value).map(|_| ())
}

fn decode_sender_transport(
    message_type: Option<&str>,
    value: Option<&[u8]>,
) -> std::io::Result<OutboundTransport> {
    let Some(message_type) = message_type else {
        return Ok(OutboundTransport::Raw);
    };
    let message_type = message_type.trim_start_matches('.');
    if message_type != TYPE_APP_SENDER_CONFIG
        && message_type != TYPE_APP_SENDER_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported outbound sender settings type {message_type}"),
        ));
    }
    let value = value.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "outbound sender settings payload is empty",
        )
    })?;
    let sender = SenderConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid outbound sender settings: {error}"),
        )
    })?;
    let Some(stream) = sender.stream_settings else {
        return Ok(OutboundTransport::Raw);
    };
    let reality = decode_reality_security(&stream)?;
    let tls = if reality.is_none() {
        decode_tls_security(&stream)?
    } else {
        None
    };
    match stream.protocol_name.trim().to_ascii_lowercase().as_str() {
        "" | "raw" | "tcp" => Ok(match (tls, reality) {
            (Some(settings), None) => OutboundTransport::Tls(settings),
            (None, Some(settings)) => OutboundTransport::Reality(settings),
            (None, None) => OutboundTransport::Raw,
            (Some(_), Some(_)) => {
                unreachable!("one Xray stream has one security type")
            }
        }),
        "ws" | "websocket" => {
            if reality.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound with WebSocket transport is not implemented yet",
                ));
            }
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("http/1.1".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    matches!(
                        transport.protocol_name.trim().to_ascii_lowercase().as_str(),
                        "ws" | "websocket"
                    )
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "WebSocket outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "WebSocket outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_WEBSOCKET_CONFIG
                && settings_type != TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported WebSocket outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings = WebsocketConfigPayload::decode(settings.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid outbound WebSocket settings: {error}"),
                    )
                })?;
            Ok(OutboundTransport::Websocket {
                tls,
                settings: OutboundWebsocketClientSettings {
                    host: settings.host,
                    path: if settings.path.is_empty() {
                        "/".to_string()
                    } else {
                        settings.path
                    },
                    headers: settings.header,
                    ed: settings.ed,
                    heartbeat_period: settings.heartbeat_period,
                },
            })
        }
        "httpupgrade" | "http-upgrade" => {
            if reality.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound with HTTPUpgrade transport is not implemented yet",
                ));
            }
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("http/1.1".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    matches!(
                        transport.protocol_name.trim().to_ascii_lowercase().as_str(),
                        "httpupgrade" | "http-upgrade"
                    )
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "HTTPUpgrade outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPUpgrade outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_HTTPUPGRADE_CONFIG
                && settings_type != TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported HTTPUpgrade outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings =
                HttpUpgradeConfigPayload::decode(settings.value.as_slice())
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "invalid outbound HTTPUpgrade settings: {error}"
                            ),
                        )
                    })?;
            if settings
                .header
                .keys()
                .any(|name| name.eq_ignore_ascii_case("host"))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPUpgrade outbound headers can't contain Host; use host instead",
                ));
            }
            Ok(OutboundTransport::HttpUpgrade {
                tls,
                settings: OutboundHttpUpgradeClientSettings {
                    host: settings.host,
                    path: if settings.path.is_empty() {
                        "/".to_string()
                    } else {
                        settings.path
                    },
                    headers: settings.header,
                    ed: settings.ed,
                },
            })
        }
        #[cfg(feature = "grpc_transport")]
        "grpc" => {
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("h2".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    transport.protocol_name.trim().eq_ignore_ascii_case("grpc")
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "gRPC outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "gRPC outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_GRPC_CONFIG
                && settings_type != TYPE_TRANSPORT_GRPC_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported gRPC outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings = GrpcConfigPayload::decode(settings.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid outbound gRPC settings: {error}"),
                    )
                })?;
            Ok(OutboundTransport::Grpc {
                tls,
                reality,
                settings: OutboundGrpcClientSettings {
                    authority: settings.authority,
                    service_name: settings.service_name,
                    multi_mode: settings.multi_mode,
                    idle_timeout: settings.idle_timeout.max(0),
                    health_check_timeout: settings.health_check_timeout.max(0),
                    permit_without_stream: settings.permit_without_stream,
                    initial_windows_size: settings.initial_windows_size.max(0),
                    user_agent: settings.user_agent,
                },
            })
        }
        network => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("outbound transport {network} is not implemented yet"),
        )),
    }
}

fn decode_reality_security(
    stream: &OutboundStreamConfigPayload,
) -> std::io::Result<Option<OutboundRealityClientSettings>> {
    let security = stream.security_type.trim_start_matches('.');
    if security != TYPE_TRANSPORT_REALITY_CONFIG
        && !security.eq_ignore_ascii_case("reality")
    {
        return Ok(None);
    }
    let message = stream
        .security_settings
        .iter()
        .find(|message| {
            message.r#type.trim_start_matches('.') == TYPE_TRANSPORT_REALITY_CONFIG
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound is missing REALITY security settings",
            )
        })?;
    let reality =
        RealityConfigPayload::decode(message.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid outbound REALITY settings: {error}"),
            )
        })?;
    if !reality.dest.is_empty()
        || !reality.r#type.is_empty()
        || reality.xver != 0
        || !reality.server_names.is_empty()
        || !reality.private_key.is_empty()
        || !reality.min_client_ver.is_empty()
        || !reality.max_client_ver.is_empty()
        || reality.max_time_diff != 0
        || !reality.short_ids.is_empty()
        || !reality.mldsa65_seed.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound contains server-side settings",
        ));
    }
    if !matches!(
        reality.fingerprint.trim().to_ascii_lowercase().as_str(),
        "" | "chrome"
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "REALITY outbound fingerprint {} is not implemented; only chrome is supported",
                reality.fingerprint
            ),
        ));
    }
    if reality.public_key.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound publicKey must contain exactly 32 bytes",
        ));
    }
    if reality.short_id.len() != 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound shortId must contain exactly 8 bytes",
        ));
    }
    if !reality.mldsa65_verify.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound ML-DSA verification is not implemented yet",
        ));
    }
    if !reality.master_key_log.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound masterKeyLog is not implemented yet",
        ));
    }
    if !reality.spider_x.is_empty() && reality.spider_x != "/" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound spiderX fallback crawling is not implemented yet",
        ));
    }
    let public_key: [u8; 32] =
        reality.public_key.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound publicKey has invalid length",
            )
        })?;
    let short_id: [u8; 8] =
        reality.short_id.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound shortId has invalid length",
            )
        })?;
    Ok(Some(OutboundRealityClientSettings {
        public_key,
        short_id,
        server_name: reality.server_name,
    }))
}

fn decode_tls_security(
    stream: &OutboundStreamConfigPayload,
) -> std::io::Result<Option<OutboundTlsClientSettings>> {
    let security = stream.security_type.trim_start_matches('.');
    if security.is_empty() || security.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if security != TYPE_TRANSPORT_TLS_CONFIG
        && security != TYPE_TRANSPORT_TLS_CONFIG_V2RAY
        && !security.eq_ignore_ascii_case("tls")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("outbound security {security} is not implemented yet"),
        ));
    }
    let tls_message = stream
        .security_settings
        .iter()
        .find(|message| {
            let message_type = message.r#type.trim_start_matches('.');
            message_type == TYPE_TRANSPORT_TLS_CONFIG
                || message_type == TYPE_TRANSPORT_TLS_CONFIG_V2RAY
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS outbound is missing TLS security settings",
            )
        })?;
    let tls =
        TlsConfigPayload::decode(tls_message.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid outbound TLS settings: {error}"),
            )
        })?;
    let custom_root_certificates = validate_tls_payload(&tls)?;
    Ok(Some(OutboundTlsClientSettings {
        server_name: tls.server_name,
        alpn: tls.next_protocol,
        disable_system_root: tls.disable_system_root,
        custom_root_certificates,
    }))
}

fn validate_tls_payload(tls: &TlsConfigPayload) -> std::io::Result<Vec<Vec<u8>>> {
    let mut custom_root_certificates = Vec::new();
    for certificate in &tls.certificate {
        if certificate.usage != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TLS outbound certificates only support AUTHORITY_VERIFY usage",
            ));
        }
        if !certificate.key.is_empty() || !certificate.key_path.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TLS outbound client certificates are not implemented",
            ));
        }
        let bytes = if !certificate.certificate_path.trim().is_empty() {
            std::fs::read(certificate.certificate_path.trim()).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to read outbound TLS certificate {}: {error}",
                        certificate.certificate_path
                    ),
                )
            })?
        } else if !certificate.certificate.is_empty() {
            certificate.certificate.clone()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS outbound verify certificate is empty",
            ));
        };
        custom_root_certificates.push(bytes);
    }
    if tls.enable_session_resumption {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS enableSessionResumption is not implemented for outbound yet",
        ));
    }
    if !tls.min_version.is_empty() || !tls.max_version.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS minVersion/maxVersion are not implemented for outbound yet",
        ));
    }
    if !tls.cipher_suites.is_empty()
        || !tls.fingerprint.is_empty()
        || tls.reject_unknown_sni
        || !tls.master_key_log.is_empty()
        || !tls.curve_preferences.is_empty()
        || !tls.verify_peer_cert_by_name.is_empty()
        || !tls.ech_server_keys.is_empty()
        || !tls.ech_config_list.is_empty()
        || !tls.pinned_peer_cert_sha256.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "advanced TLS verification/fingerprint/ECH settings are not implemented for outbound yet",
        ));
    }
    Ok(custom_root_certificates)
}

fn decode_ip_or_domain(value: Option<&IpOrDomainPayload>) -> Option<Address> {
    match value?.address.as_ref()? {
        ip_or_domain_payload::Address::Ip(bytes) => match bytes.as_slice() {
            [a, b, c, d] => {
                Some(Address::Ipv4(std::net::Ipv4Addr::new(*a, *b, *c, *d)))
            }
            bytes if bytes.len() == 16 => {
                let bytes: [u8; 16] = bytes.try_into().ok()?;
                Some(Address::Ipv6(std::net::Ipv6Addr::from(bytes)))
            }
            _ => None,
        },
        ip_or_domain_payload::Address::Domain(domain) if !domain.is_empty() => {
            Some(Address::Hostname(domain.clone()))
        }
        ip_or_domain_payload::Address::Domain(_) => None,
    }
}

#[cfg(feature = "reality")]
fn connect_reality_transport(
    stream: tokio::net::TcpStream,
    settings: &OutboundRealityClientSettings,
    server: &NetLocation,
) -> std::io::Result<RealityTlsStream<tokio::net::TcpStream, RealityClientConnection>>
{
    let server_name = if settings.server_name.trim().is_empty() {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
        }
    } else {
        settings.server_name.trim().to_string()
    };
    let session = RealityClientConnection::new(RealityClientConfig {
        public_key: settings.public_key,
        short_id: settings.short_id,
        server_name,
        cipher_suites: Vec::new(),
    })?;
    Ok(RealityTlsStream::new(stream, session))
}

#[cfg(feature = "tls")]
async fn connect_tls_transport(
    stream: tokio::net::TcpStream,
    settings: &OutboundTlsClientSettings,
    server: &NetLocation,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut added_roots = 0usize;
    if !settings.disable_system_root {
        let native = rustls_native_certs::load_native_certs();
        let (added, _) = roots.add_parsable_certificates(native.certs);
        added_roots += added;
    }
    for certificate in &settings.custom_root_certificates {
        let mut cursor = std::io::Cursor::new(certificate.as_slice());
        let pem_certificates = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid outbound TLS CA certificate: {error}"),
                )
            })?;
        if pem_certificates.is_empty() {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid outbound TLS CA certificate: {error}"),
                    )
                })?;
            added_roots += 1;
        } else {
            for certificate in pem_certificates {
                roots.add(certificate).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid outbound TLS CA certificate: {error}"),
                    )
                })?;
                added_roots += 1;
            }
        }
    }
    if added_roots == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no CA certificates were available for outbound TLS",
        ));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = settings
        .alpn
        .iter()
        .filter(|protocol| !protocol.is_empty())
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = if settings.server_name.trim().is_empty() {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
        }
    } else {
        settings.server_name.trim().to_string()
    };
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid outbound TLS serverName {server_name}: {error}"),
        )
    })?;
    connector.connect(server_name, stream).await
}

#[cfg(feature = "grpc_transport")]
struct GrpcOutboundStream {
    inner: DuplexStream,
    shared_error: Arc<Mutex<Option<(std::io::ErrorKind, String)>>>,
    connection_abort: AbortHandle,
    response_abort: AbortHandle,
}

#[cfg(feature = "grpc_transport")]
impl Drop for GrpcOutboundStream {
    fn drop(&mut self) {
        self.response_abort.abort();
        self.connection_abort.abort();
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncRead for GrpcOutboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                match take_grpc_outbound_error(&self.shared_error) {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Ready(Ok(())),
                }
            }
            other => other,
        }
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncWrite for GrpcOutboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(error) = clone_grpc_outbound_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(error) = clone_grpc_outbound_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncPing for GrpcOutboundStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncStream for GrpcOutboundStream {}

#[cfg(feature = "grpc_transport")]
fn set_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
    kind: std::io::ErrorKind,
    message: String,
) {
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_none() {
        *guard = Some((kind, message));
    }
}

#[cfg(feature = "grpc_transport")]
fn clone_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
) -> Option<std::io::Error> {
    let guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard
        .as_ref()
        .map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
}

#[cfg(feature = "grpc_transport")]
fn take_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
) -> Option<std::io::Error> {
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard
        .take()
        .map(|(kind, message)| std::io::Error::new(kind, message))
}

#[cfg(feature = "grpc_transport")]
fn grpc_initial_stream_window(settings: &OutboundGrpcClientSettings) -> u32 {
    u32::try_from(settings.initial_windows_size)
        .ok()
        .filter(|size| *size >= 65_535)
        .unwrap_or(65_535)
}

#[cfg(feature = "grpc_transport")]
fn grpc_keepalive_params(
    settings: &OutboundGrpcClientSettings,
) -> Option<(Duration, Duration, bool)> {
    if settings.idle_timeout <= 0
        && settings.health_check_timeout <= 0
        && !settings.permit_without_stream
    {
        return None;
    }
    let interval_secs = u64::try_from(settings.idle_timeout.max(10)).unwrap_or(10);
    let timeout_secs = if settings.health_check_timeout > 0 {
        u64::try_from(settings.health_check_timeout).unwrap_or(20)
    } else {
        20
    };
    Some((
        Duration::from_secs(interval_secs),
        Duration::from_secs(timeout_secs),
        settings.permit_without_stream,
    ))
}

#[cfg(feature = "grpc_transport")]
async fn connect_grpc_transport(
    stream: Box<dyn AsyncStream>,
    settings: &OutboundGrpcClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    reality_transport: bool,
) -> std::io::Result<GrpcOutboundStream> {
    const PIPE_CAPACITY: usize = 64 * 1024;

    let authority = grpc_outbound_authority(
        settings,
        server,
        tls_server_name,
        reality_transport,
    );
    let (tun_path, tun_multi_path) = grpc_service_paths(&settings.service_name);
    let path = if settings.multi_mode {
        tun_multi_path
    } else {
        tun_path
    };
    let uri_text = match authority.as_deref() {
        Some(authority) => format!("http://{authority}{path}"),
        None => path,
    };
    let uri = uri_text.parse::<hyper::Uri>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid gRPC outbound authority/path: {error}"),
        )
    })?;

    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    builder.initial_stream_window_size(grpc_initial_stream_window(settings));
    builder.initial_connection_window_size(65_535);
    if let Some((interval, timeout, permit_without_stream)) =
        grpc_keepalive_params(settings)
    {
        builder.timer(TokioTimer::new());
        builder.keep_alive_interval(Some(interval));
        builder.keep_alive_timeout(timeout);
        builder.keep_alive_while_idle(permit_without_stream);
    }
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound HTTP/2 handshake failed: {error}"),
            )
        })?;

    let shared_error = Arc::new(Mutex::new(None));
    let connection_error = shared_error.clone();
    let connection_task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            set_grpc_outbound_error(
                &connection_error,
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound HTTP/2 connection failed: {error}"),
            );
        }
    });
    let connection_abort = connection_task.abort_handle();
    drop(connection_task);

    let (app_stream, transport_stream) = duplex(PIPE_CAPACITY);
    let (upload_read, mut download_write) = tokio::io::split(transport_stream);
    let multi_mode = settings.multi_mode;
    let body_stream = ReaderStream::new(upload_read).map(move |chunk| {
        chunk.map(|data| Frame::data(encode_grpc_message(&data, multi_mode)))
    });
    let body = StreamBody::new(body_stream);
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers");
    if !settings.user_agent.trim().is_empty() {
        request = request.header(header::USER_AGENT, settings.user_agent.trim());
    }
    let request = match request.body(body) {
        Ok(request) => request,
        Err(error) => {
            connection_abort.abort();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to build gRPC outbound request: {error}"),
            ));
        }
    };

    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            connection_abort.abort();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound request failed: {error}"),
            ));
        }
    };
    if response.status() != hyper::StatusCode::OK {
        connection_abort.abort();
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("gRPC outbound returned HTTP status {}", response.status()),
        ));
    }
    if let Err(error) = validate_grpc_outbound_content_type(response.headers()) {
        connection_abort.abort();
        return Err(error);
    }
    let initial_status = match grpc_outbound_status(response.headers()) {
        Ok(status) => status,
        Err(error) => {
            connection_abort.abort();
            return Err(error);
        }
    };
    if let Some(status) = initial_status
        && status != 0
    {
        connection_abort.abort();
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("gRPC outbound rejected with grpc-status {status}"),
        ));
    }

    let response_error = shared_error.clone();
    let mut body = response.into_body();
    let response_task = tokio::spawn(async move {
        let result = async {
            let mut buffered = BytesMut::new();
            let mut saw_status = initial_status.is_some();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("gRPC outbound response body failed: {error}"),
                    )
                })?;
                if let Some(data) = frame.data_ref() {
                    buffered.extend_from_slice(data);
                    while let Some(payloads) =
                        decode_grpc_message_payloads(&mut buffered, multi_mode)?
                    {
                        for payload in payloads {
                            download_write.write_all(&payload).await?;
                        }
                    }
                }
                if let Some(trailers) = frame.trailers_ref() {
                    let status = grpc_outbound_status(trailers)?.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "gRPC outbound trailers are missing grpc-status",
                        )
                    })?;
                    saw_status = true;
                    if status != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!(
                                "gRPC outbound stream ended with grpc-status {status}"
                            ),
                        ));
                    }
                }
            }
            if !buffered.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "gRPC outbound response ended with a truncated message",
                ));
            }
            if !saw_status {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "gRPC outbound response ended without grpc-status",
                ));
            }
            std::io::Result::Ok(())
        }
        .await;
        if let Err(error) = result {
            set_grpc_outbound_error(
                &response_error,
                error.kind(),
                error.to_string(),
            );
        }
        let _ = download_write.shutdown().await;
    });
    let response_abort = response_task.abort_handle();
    drop(response_task);

    Ok(GrpcOutboundStream {
        inner: app_stream,
        shared_error,
        connection_abort,
        response_abort,
    })
}

#[cfg(feature = "grpc_transport")]
fn grpc_outbound_authority(
    settings: &OutboundGrpcClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    reality_transport: bool,
) -> Option<String> {
    if !settings.authority.trim().is_empty() {
        return Some(settings.authority.trim().to_string());
    }
    if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        return Some(server_name.trim().to_string());
    }
    if reality_transport {
        return None;
    }
    match server.address() {
        Address::Hostname(hostname) => Some(hostname.clone()),
        Address::Ipv4(_) | Address::Ipv6(_) => None,
    }
}

#[cfg(feature = "grpc_transport")]
fn validate_grpc_outbound_content_type(
    headers: &hyper::HeaderMap,
) -> std::io::Result<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type == "application/grpc"
        || content_type.starts_with("application/grpc+")
        || content_type.starts_with("application/grpc;")
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("gRPC outbound returned invalid content-type {content_type:?}"),
    ))
}

#[cfg(feature = "grpc_transport")]
fn grpc_outbound_status(headers: &hyper::HeaderMap) -> std::io::Result<Option<u32>> {
    let Some(value) = headers.get("grpc-status") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "gRPC outbound grpc-status is not ASCII",
        )
    })?;
    value.parse::<u32>().map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("gRPC outbound grpc-status is invalid: {value:?}"),
        )
    })
}

#[cfg(feature = "httpupgrade")]
async fn connect_httpupgrade_transport(
    mut stream: Box<dyn AsyncStream>,
    settings: &OutboundHttpUpgradeClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    early_data: Option<&[u8]>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let path = normalize_httpupgrade_request_target(&settings.path)?;
    let host = if !settings.host.trim().is_empty() {
        settings.host.trim().to_string()
    } else if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        server_name.trim().to_string()
    } else {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => format!("[{ip}]"),
        }
    };
    validate_httpupgrade_header_value("Host", &host)?;

    let mut headers = settings.headers.iter().collect::<Vec<_>>();
    headers.sort_unstable_by(|(left, _), (right, _)| {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    });
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    );
    for (name, value) in headers {
        validate_httpupgrade_header_name(name)?;
        validate_httpupgrade_header_value(name, value)?;
        if name.eq_ignore_ascii_case("host") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTPUpgrade outbound headers can't contain Host; use host instead",
            ));
        }
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    if let Some(early_data) = early_data {
        stream.write_all(early_data).await?;
    }
    stream.flush().await?;
    let leftover = read_httpupgrade_response(&mut *stream).await?;
    if leftover.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(PrefixedStream::new(leftover, stream)))
    }
}

#[cfg(feature = "httpupgrade")]
fn normalize_httpupgrade_request_target(path: &str) -> std::io::Result<String> {
    let path = path.trim();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTPUpgrade outbound path contains an invalid HTTP request-target byte",
        ));
    }
    Ok(path)
}

#[cfg(feature = "httpupgrade")]
fn validate_httpupgrade_header_name(name: &str) -> std::io::Result<()> {
    let valid = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTPUpgrade outbound header name {name:?}"),
        ))
    }
}

#[cfg(feature = "httpupgrade")]
fn validate_httpupgrade_header_value(
    name: &str,
    value: &str,
) -> std::io::Result<()> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTPUpgrade outbound header value for {name}"),
        ));
    }
    Ok(())
}

#[cfg(feature = "httpupgrade")]
async fn read_httpupgrade_response<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut response = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) =
            response.windows(4).position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if response.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTPUpgrade outbound response headers are too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade outbound closed before the HTTP upgrade completed",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
    };

    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTPUpgrade outbound response headers are not valid UTF-8/ASCII",
        )
    })?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts.next().unwrap_or_default();
    let reason = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/")
        || status != "101"
        || reason != "Switching Protocols"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("HTTPUpgrade outbound rejected with {status_line}"),
        ));
    }

    let mut upgrade = None::<&str>;
    let mut connection = None::<&str>;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTPUpgrade outbound response header",
            ));
        };
        if name.eq_ignore_ascii_case("upgrade") && upgrade.is_none() {
            upgrade = Some(value.trim());
        } else if name.eq_ignore_ascii_case("connection") && connection.is_none() {
            connection = Some(value.trim());
        }
    }
    if !upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unrecognized HTTPUpgrade outbound response",
        ));
    }
    Ok(response[header_end..].to_vec())
}

#[cfg(feature = "ws")]
async fn connect_websocket_transport(
    mut stream: Box<dyn AsyncStream>,
    settings: &OutboundWebsocketClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    early_data: Option<&[u8]>,
) -> std::io::Result<WebsocketStream> {
    const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

    let path = normalize_websocket_request_target(&settings.path)?;
    let host = websocket_request_host(settings, server, tls_server_name);
    validate_websocket_header_value("Host", &host)?;

    let mut nonce = [0u8; 16];
    rand::rng().fill(&mut nonce);
    let websocket_key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let expected_accept = websocket_accept_value(&websocket_key);
    let early_data_protocol = early_data
        .map(|data| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data));

    let mut headers = settings.headers.iter().collect::<Vec<_>>();
    headers.sort_unstable_by(|(left, _), (right, _)| {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    });
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in headers {
        validate_websocket_header_name(name)?;
        validate_websocket_header_value(name, value)?;
        if is_reserved_websocket_request_header(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "WebSocket outbound header {name} is reserved by the handshake"
                ),
            ));
        }
        if early_data_protocol.is_some()
            && name.eq_ignore_ascii_case("sec-websocket-protocol")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(protocol) = &early_data_protocol {
        request.push_str("Sec-WebSocket-Protocol: ");
        request.push_str(protocol);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let leftover = tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_websocket_upgrade_response(&mut *stream, &expected_accept).await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "WebSocket outbound handshake timed out",
        )
    })??;

    let stream: Box<dyn AsyncStream> = if leftover.is_empty() {
        stream
    } else {
        Box::new(PrefixedStream::new(leftover, stream))
    };
    Ok(WebsocketStream::new_with_heartbeat(
        stream,
        true,
        &[],
        settings.heartbeat_period,
    ))
}

#[cfg(feature = "ws")]
fn normalize_websocket_request_target(path: &str) -> std::io::Result<String> {
    let path = path.trim();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "WebSocket outbound path contains an invalid HTTP request-target byte",
        ));
    }
    Ok(path)
}

#[cfg(feature = "ws")]
fn websocket_request_host(
    settings: &OutboundWebsocketClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
) -> String {
    if !settings.host.trim().is_empty() {
        return settings.host.trim().to_string();
    }
    if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        return server_name.trim().to_string();
    }
    match server.address() {
        Address::Hostname(hostname) => hostname.clone(),
        Address::Ipv4(ip) => ip.to_string(),
        Address::Ipv6(ip) => format!("[{ip}]"),
    }
}

#[cfg(feature = "ws")]
fn validate_websocket_header_name(name: &str) -> std::io::Result<()> {
    let valid = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid WebSocket outbound header name {name:?}"),
        ))
    }
}

#[cfg(feature = "ws")]
fn validate_websocket_header_value(name: &str, value: &str) -> std::io::Result<()> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid WebSocket outbound header value for {name}"),
        ));
    }
    Ok(())
}

#[cfg(feature = "ws")]
fn is_reserved_websocket_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
    )
}

#[cfg(feature = "ws")]
fn websocket_accept_value(key: &str) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID);
    let hash = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &input,
    );
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

#[cfg(feature = "ws")]
async fn read_websocket_upgrade_response<S>(
    stream: &mut S,
    expected_accept: &str,
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut response = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) =
            response.windows(4).position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if response.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket outbound response headers are too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "WebSocket outbound closed before the HTTP upgrade completed",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_HEADER_BYTES
            && !response.windows(4).any(|window| window == b"\r\n\r\n")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket outbound response headers are too large",
            ));
        }
    };

    let header_bytes = &response[..header_end];
    let headers = std::str::from_utf8(header_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WebSocket outbound response headers are not valid UTF-8/ASCII",
        )
    })?;
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts.next().unwrap_or_default();
    if version != "HTTP/1.1" || status != "101" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("WebSocket outbound upgrade rejected with {status_line}"),
        ));
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut accept = None::<&str>;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed WebSocket outbound response header",
            ));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept")
            && accept.replace(value).is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "duplicate Sec-WebSocket-Accept response header",
            ));
        }
    }
    if !upgrade || !connection_upgrade || accept != Some(expected_accept) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid WebSocket outbound upgrade response",
        ));
    }

    Ok(response[header_end..].to_vec())
}

async fn vless_tcp_connect<S>(
    stream: &mut S,
    endpoint: &VlessOutboundEndpoint,
    target: &NetLocation,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    if !endpoint.flow.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VLESS Vision outbound requires transport-aware support",
        ));
    }

    let mut request = Vec::with_capacity(64);
    request.push(0);
    request.extend_from_slice(&endpoint.user_id);
    request.push(0); // empty addons
    request.push(1); // TCP
    request.extend_from_slice(&target.port().to_be_bytes());
    match target.address() {
        Address::Ipv4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Address::Hostname(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS target domain must contain 1..=255 bytes",
                ));
            }
            request.push(2);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
        Address::Ipv6(ip) => {
            request.push(3);
            request.extend_from_slice(&ip.octets());
        }
    }
    stream.write_all(&request).await?;
    stream.flush().await?;

    let version = stream.read_u8().await?;
    if version != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected VLESS response version {version}"),
        ));
    }
    let addon_len = stream.read_u8().await? as usize;
    if addon_len > 0 {
        let mut addons = vec![0u8; addon_len];
        stream.read_exact(&mut addons).await?;
    }
    Ok(())
}

fn build_trojan_request(
    endpoint: &TrojanOutboundEndpoint,
    target: &NetLocation,
    command: TrojanCommand,
) -> std::io::Result<Vec<u8>> {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA224,
        endpoint.password.as_bytes(),
    );
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut request = Vec::with_capacity(128);
    for byte in digest.as_ref() {
        request.push(HEX[(byte >> 4) as usize]);
        request.push(HEX[(byte & 0x0f) as usize]);
    }
    request.extend_from_slice(b"\r\n");
    request.push(command.byte());
    encode_socks5_target(&mut request, target)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

async fn trojan_connect<S>(
    stream: &mut S,
    endpoint: &TrojanOutboundEndpoint,
    target: &NetLocation,
    command: TrojanCommand,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let request = build_trojan_request(endpoint, target, command)?;
    stream.write_all(&request).await?;
    stream.flush().await
}

async fn socks5_connect<S>(
    stream: &mut S,
    endpoint: &SocksOutboundEndpoint,
    target: &NetLocation,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let auth_method = if endpoint.username.is_some() {
        0x02
    } else {
        0x00
    };
    stream.write_all(&[0x05, 0x01, auth_method]).await?;
    stream.flush().await?;

    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response).await?;
    if method_response[0] != 0x05 || method_response[1] != auth_method {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "SOCKS server selected unsupported auth method 0x{:02x}",
                method_response[1]
            ),
        ));
    }

    if auth_method == 0x02 {
        let username = endpoint.username.as_deref().unwrap_or_default().as_bytes();
        let password = endpoint.password.as_deref().unwrap_or_default().as_bytes();
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS username or password exceeds 255 bytes",
            ));
        }
        let mut request = Vec::with_capacity(username.len() + password.len() + 3);
        request.push(0x01);
        request.push(username.len() as u8);
        request.extend_from_slice(username);
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut auth_response = [0u8; 2];
        stream.read_exact(&mut auth_response).await?;
        if auth_response[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SOCKS server rejected account: {}", auth_response[1]),
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    encode_socks5_target(&mut request, target)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected SOCKS server version {}", response[0]),
        ));
    }
    if response[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS server rejected CONNECT request: {}", response[1]),
        ));
    }
    consume_socks5_bound_address(stream, response[3]).await
}

fn encode_socks5_target(
    output: &mut Vec<u8>,
    target: &NetLocation,
) -> std::io::Result<()> {
    match target.address() {
        Address::Ipv4(ip) => {
            output.push(0x01);
            output.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            output.push(0x04);
            output.extend_from_slice(&ip.octets());
        }
        Address::Hostname(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS target domain must contain 1..=255 bytes",
                ));
            }
            output.push(0x03);
            output.push(bytes.len() as u8);
            output.extend_from_slice(bytes);
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

async fn consume_socks5_bound_address<S>(
    stream: &mut S,
    address_type: u8,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin + ?Sized,
{
    match address_type {
        0x01 => {
            let mut bytes = [0u8; 4 + 2];
            stream.read_exact(&mut bytes).await?;
        }
        0x04 => {
            let mut bytes = [0u8; 16 + 2];
            stream.read_exact(&mut bytes).await?;
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0u8; length + 2];
            stream.read_exact(&mut bytes).await?;
        }
        value => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS server returned unknown address type {value}"),
            ));
        }
    }
    Ok(())
}

fn elapsed_millis(started: Instant) -> i64 {
    started.elapsed().as_millis().min(i64::MAX as u128) as i64
}

fn tcp_connect_observation(
    alive: bool,
    delay_ms: i64,
    attempted_at: i64,
    last_error_reason: String,
) -> OutboundObservation {
    OutboundObservation {
        alive,
        delay_ms,
        last_error_reason,
        last_seen_time: if alive { attempted_at } else { 0 },
        last_try_time: attempted_at,
        ..OutboundObservation::default()
    }
}

fn record_tcp_connect_observation(
    runtime: &RuntimeState,
    outbound_tag: Option<&str>,
    observation: OutboundObservation,
) {
    if let Some(tag) = outbound_tag {
        runtime.record_passive_outbound_observation(tag, observation);
    }
}

pub(crate) fn connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    let mut input = unresolved_connection_routing_input(
        inbound_tag,
        user,
        network,
        source_addr,
        target_location,
    );
    input.target_ips = vec![encode_ip(target_addr.ip())];
    input
}

fn unresolved_connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network,
        source_ips: vec![encode_ip(source_addr.ip())],
        target_ips: target_location
            .to_socket_addr_nonblocking()
            .map(|address| vec![encode_ip(address.ip())])
            .unwrap_or_default(),
        source_port: source_addr.port() as u32,
        target_port: target_location.port() as u32,
        target_domain: match target_location.address() {
            Address::Hostname(hostname) => hostname.clone(),
            _ => String::new(),
        },
        user: user.to_string(),
        ..RoutingInput::default()
    }
}

pub(crate) fn select_direct_outbound(
    runtime: &RuntimeState,
    input: &RoutingInput,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    if !runtime.allows_user_domain_access(&input.user, &input.target_domain) {
        return Ok(DirectOutboundAction::Blackhole {
            tag: USER_DOMAIN_ACCESS_BLACKHOLE_TAG.to_string(),
        });
    }

    let outbound = runtime
        .select_outbound_checked(input)
        .map_err(invalid_routing_error)?;
    classify_selected_outbound(outbound, network_name)
}

fn classify_selected_outbound(
    outbound: Option<OutboundSummary>,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    let Some(outbound) = outbound else {
        return Ok(DirectOutboundAction::Freedom { tag: None });
    };
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(DirectOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(DirectOutboundAction::Blackhole { tag: outbound.tag }),
        "socks" if network_name.eq_ignore_ascii_case("tcp") => {
            Ok(DirectOutboundAction::Socks { outbound })
        }
        "vless" if network_name.eq_ignore_ascii_case("tcp") => {
            Ok(DirectOutboundAction::Vless { outbound })
        }
        "trojan"
            if network_name.eq_ignore_ascii_case("tcp")
                || network_name.eq_ignore_ascii_case("udp") =>
        {
            Ok(DirectOutboundAction::Trojan { outbound })
        }
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} outbound {} uses unsupported protocol {}",
                network_name, outbound.tag, protocol
            ),
        )),
    }
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn encode_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[cfg(feature = "grpc_transport")]
    use hyper::{Response, server::conn::http2, service::service_fn};
    #[cfg(feature = "grpc_transport")]
    use std::convert::Infallible;

    use super::*;
    use crate::{
        config::rule::{BalancerConfig, RoutingConfig, RuleConfig},
        resolver::NativeResolver,
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }
    }

    fn socks_outbound(
        tag: &str,
        server: SocketAddr,
        username: Option<&str>,
        password: Option<&str>,
    ) -> OutboundSummary {
        let account = username.map(|username| TypedMessagePayload {
            r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
            value: SocksAccountPayload {
                username: username.to_string(),
                password: password.unwrap_or_default().to_string(),
            }
            .encode_to_vec(),
        });
        let payload = SocksClientConfigPayload {
            server: Some(SocksServerEndpointPayload {
                address: Some(IpOrDomainPayload {
                    address: Some(match server.ip() {
                        IpAddr::V4(ip) => {
                            ip_or_domain_payload::Address::Ip(ip.octets().to_vec())
                        }
                        IpAddr::V6(ip) => {
                            ip_or_domain_payload::Address::Ip(ip.octets().to_vec())
                        }
                    }),
                }),
                port: u32::from(server.port()),
                user: account.map(|account| OutboundUserPayload {
                    level: 0,
                    email: String::new(),
                    account: Some(account),
                }),
            }),
        };
        OutboundSummary {
            tag: tag.into(),
            protocol: "socks".into(),
            proxy_settings_type: Some(TYPE_PROXY_SOCKS_CLIENT_CONFIG.into()),
            proxy_settings_value: Some(payload.encode_to_vec()),
            sender_settings_type: None,
            sender_settings_value: None,
        }
    }

    #[cfg(feature = "grpc_transport")]
    async fn serve_test_grpc_trojan<IO>(
        io: IO,
        expected_authority: &str,
        expected_user_agent: Option<&str>,
        multi_mode: bool,
        expected_command: TrojanCommand,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let expected_authority = expected_authority.to_string();
        let expected_user_agent = expected_user_agent.map(str::to_string);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let expected_authority = expected_authority.clone();
            let expected_user_agent = expected_user_agent.clone();
            async move {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(
                    request.uri().path(),
                    if multi_mode {
                        "/GunService/TunMulti"
                    } else {
                        "/GunService/Tun"
                    }
                );
                assert_eq!(
                    request.uri().authority().map(|value| value.as_str()),
                    Some(expected_authority.as_str())
                );
                assert_eq!(
                    request
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/grpc")
                );
                assert_eq!(
                    request
                        .headers()
                        .get(header::TE)
                        .and_then(|value| value.to_str().ok()),
                    Some("trailers")
                );
                if let Some(expected_user_agent) = expected_user_agent {
                    assert_eq!(
                        request
                            .headers()
                            .get(header::USER_AGENT)
                            .and_then(|value| value.to_str().ok()),
                        Some(expected_user_agent.as_str())
                    );
                }

                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<Frame<bytes::Bytes>, Infallible>,
                >(4);
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut encoded = BytesMut::new();
                    let target = NetLocation::from_str("origin.example:443", None)
                        .expect("test Trojan target");
                    let expected = build_trojan_request(
                        &TrojanOutboundEndpoint {
                            server: NetLocation::UNSPECIFIED,
                            password: "secret".into(),
                        },
                        &target,
                        expected_command,
                    )
                    .expect("build expected Trojan request");
                    let expected_udp_packet =
                        (expected_command == TrojanCommand::Udp).then(|| {
                            crate::handler::trojan_udp::encode_location_packet(
                                &target, b"ping",
                            )
                            .expect("encode expected Trojan UDP request packet")
                        });
                    let expected_len = expected.len()
                        + expected_udp_packet.as_ref().map_or(0, Vec::len);
                    let mut decoded = Vec::new();
                    while decoded.len() < expected_len {
                        let frame = body
                            .frame()
                            .await
                            .expect("gRPC request body must contain Trojan data")
                            .expect("read gRPC request body frame");
                        if let Some(data) = frame.data_ref() {
                            encoded.extend_from_slice(data);
                            while let Some(payloads) = decode_grpc_message_payloads(
                                &mut encoded,
                                multi_mode,
                            )
                            .expect("decode gRPC request Hunk")
                            {
                                for payload in payloads {
                                    decoded.extend_from_slice(&payload);
                                }
                            }
                        }
                    }
                    assert_eq!(&decoded[..expected.len()], expected.as_slice());
                    if let Some(expected_udp_packet) = expected_udp_packet {
                        assert_eq!(
                            &decoded[expected.len()..expected_len],
                            expected_udp_packet.as_slice()
                        );
                    }
                    let reply = if expected_command == TrojanCommand::Udp {
                        let packet =
                            crate::handler::trojan_udp::encode_location_packet(
                                &target, b"pong",
                            )
                            .expect("encode Trojan UDP response packet");
                        encode_grpc_message(&packet, multi_mode)
                    } else if multi_mode {
                        let mut frame = vec![0u8; 5];
                        for byte in *b"xy" {
                            frame.extend_from_slice(&[0x0a, 0x01, byte]);
                        }
                        let message_len = frame.len() - 5;
                        frame[1..5]
                            .copy_from_slice(&(message_len as u32).to_be_bytes());
                        bytes::Bytes::from(frame)
                    } else {
                        encode_grpc_message(b"x", false)
                    };
                    tx.send(Ok(Frame::data(reply)))
                        .await
                        .expect("send gRPC reply Hunk");
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert(
                        "grpc-status",
                        hyper::header::HeaderValue::from_static("0"),
                    );
                    tx.send(Ok(Frame::trailers(trailers)))
                        .await
                        .expect("send gRPC success trailers");
                });
                let response_stream =
                    futures::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|frame| (frame, rx))
                    });
                let response = Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/grpc")
                    .body(StreamBody::new(response_stream))
                    .expect("build fake gRPC response");
                Ok::<_, Infallible>(response)
            }
        });
        http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await
            .expect("serve fake gRPC connection");
    }

    #[cfg(feature = "ws")]
    async fn accept_test_websocket(
        mut stream: Box<dyn AsyncStream>,
        expected_path: &str,
        expected_host: &str,
        expected_header: Option<(&str, &str)>,
    ) -> WebsocketStream {
        let mut request = Vec::new();
        loop {
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(
                request.len() < 64 * 1024,
                "test WebSocket request too large"
            );
            let mut chunk = [0u8; 2048];
            let read = stream
                .read(&mut chunk)
                .await
                .expect("read WebSocket upgrade request");
            assert!(read > 0, "WebSocket client closed during upgrade");
            request.extend_from_slice(&chunk[..read]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("upgrade header terminator")
            + 4;
        assert_eq!(
            request.len(),
            header_end,
            "Trojan data must not be sent before WebSocket upgrade completes"
        );
        let request_text =
            std::str::from_utf8(&request).expect("ASCII upgrade request");
        let mut lines = request_text.split("\r\n");
        assert_eq!(
            lines.next().expect("request line"),
            format!("GET {expected_path} HTTP/1.1")
        );
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("valid request header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        assert_eq!(
            headers.get("upgrade").map(String::as_str),
            Some("websocket")
        );
        assert!(
            headers
                .get("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("Upgrade"))
        );
        assert_eq!(
            headers.get("sec-websocket-version").map(String::as_str),
            Some("13")
        );
        if let Some((name, value)) = expected_header {
            assert_eq!(
                headers.get(&name.to_ascii_lowercase()).map(String::as_str),
                Some(value)
            );
        }
        let key = headers
            .get("sec-websocket-key")
            .expect("Sec-WebSocket-Key request header");
        let accept = websocket_accept_value(key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write WebSocket upgrade response");
        stream
            .flush()
            .await
            .expect("flush WebSocket upgrade response");
        WebsocketStream::new(stream, false, &[])
    }

    #[cfg(feature = "ws")]
    async fn accept_test_websocket_early_data(
        mut stream: Box<dyn AsyncStream>,
        expected_path: &str,
        expected_host: &str,
    ) -> Box<dyn AsyncStream> {
        let mut request = Vec::new();
        loop {
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(
                request.len() < 64 * 1024,
                "test WebSocket early-data request too large"
            );
            let mut chunk = [0u8; 2048];
            let read = stream
                .read(&mut chunk)
                .await
                .expect("read WebSocket early-data upgrade request");
            assert!(
                read > 0,
                "WebSocket early-data client closed during upgrade"
            );
            request.extend_from_slice(&chunk[..read]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("early-data upgrade header terminator")
            + 4;
        assert_eq!(
            request.len(),
            header_end,
            "Trojan early data must be carried only in the WebSocket request headers"
        );
        let request_text =
            std::str::from_utf8(&request).expect("ASCII early-data upgrade request");
        let mut lines = request_text.split("\r\n");
        assert_eq!(
            lines.next().expect("request line"),
            format!("GET {expected_path} HTTP/1.1")
        );
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("valid request header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        let protocol = headers
            .get("sec-websocket-protocol")
            .expect("Xray early data must use Sec-WebSocket-Protocol")
            .clone();
        let early_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protocol.as_bytes())
            .expect("decode Xray WebSocket early data");
        assert!(
            !early_data.is_empty(),
            "Trojan early data must not be empty"
        );
        let key = headers
            .get("sec-websocket-key")
            .expect("Sec-WebSocket-Key request header");
        let accept = websocket_accept_value(key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write WebSocket early-data upgrade response");
        stream
            .flush()
            .await
            .expect("flush WebSocket early-data upgrade response");
        let websocket: Box<dyn AsyncStream> =
            Box::new(WebsocketStream::new(stream, false, &[]));
        Box::new(PrefixedStream::new(early_data, websocket))
    }

    #[cfg(feature = "reality")]
    async fn accept_test_reality(
        mut stream: tokio::net::TcpStream,
        config: crate::reality::RealityServerConfig,
    ) -> crate::reality::RealityTlsStream<
        Box<dyn AsyncStream>,
        crate::reality::RealityServerConnection,
    > {
        let mut record_header = [0u8; 5];
        stream
            .read_exact(&mut record_header)
            .await
            .expect("read REALITY ClientHello record header");
        assert_eq!(record_header[0], 0x16, "expected TLS handshake record");
        let record_len =
            u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut client_hello = Vec::with_capacity(5 + record_len);
        client_hello.extend_from_slice(&record_header);
        client_hello.resize(5 + record_len, 0);
        stream
            .read_exact(&mut client_hello[5..])
            .await
            .expect("read REALITY ClientHello record payload");

        let mut session = crate::reality::RealityServerConnection::new(config)
            .expect("build fake REALITY server session");
        session
            .validate_client_hello(&client_hello)
            .expect("validate REALITY ClientHello");
        session
            .build_server_response(Vec::new())
            .expect("build REALITY server response");
        let mut response = Vec::new();
        while session.wants_write() {
            session
                .write_tls(&mut response)
                .expect("serialize REALITY server handshake");
        }
        stream
            .write_all(&response)
            .await
            .expect("write REALITY server handshake");
        stream
            .flush()
            .await
            .expect("flush REALITY server handshake");

        while session.is_handshaking() {
            let mut buffer = [0u8; 4096];
            let read = stream
                .read(&mut buffer)
                .await
                .expect("read REALITY client Finished");
            assert!(read > 0, "REALITY client closed during handshake");
            session
                .read_tls(&mut std::io::Cursor::new(&buffer[..read]))
                .expect("feed REALITY client handshake data");
            session
                .process_new_packets()
                .expect("process REALITY client handshake data");
            if session.wants_write() {
                let mut pending = Vec::new();
                while session.wants_write() {
                    session
                        .write_tls(&mut pending)
                        .expect("serialize pending REALITY server data");
                }
                stream
                    .write_all(&pending)
                    .await
                    .expect("write pending REALITY server data");
                stream
                    .flush()
                    .await
                    .expect("flush pending REALITY server data");
            }
        }

        crate::reality::RealityTlsStream::new(
            Box::new(stream) as Box<dyn AsyncStream>,
            session,
        )
    }

    #[cfg(feature = "httpupgrade")]
    async fn accept_test_httpupgrade(
        mut stream: Box<dyn AsyncStream>,
        expected_path: &str,
        expected_host: &str,
        expected_header: Option<(&str, &str)>,
    ) -> Box<dyn AsyncStream> {
        let mut request = Vec::new();
        loop {
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(
                request.len() < 64 * 1024,
                "test HTTPUpgrade request too large"
            );
            let mut chunk = [0u8; 2048];
            let read = stream
                .read(&mut chunk)
                .await
                .expect("read HTTPUpgrade request");
            assert!(read > 0, "HTTPUpgrade client closed during upgrade");
            request.extend_from_slice(&chunk[..read]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTPUpgrade header terminator")
            + 4;
        assert_eq!(
            request.len(),
            header_end,
            "Trojan data must not be sent before HTTPUpgrade completes"
        );
        let request_text =
            std::str::from_utf8(&request).expect("ASCII HTTPUpgrade request");
        let mut lines = request_text.split("\r\n");
        assert_eq!(
            lines.next().expect("request line"),
            format!("GET {expected_path} HTTP/1.1")
        );
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("valid request header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        assert_eq!(
            headers.get("upgrade").map(String::as_str),
            Some("websocket")
        );
        assert_eq!(
            headers.get("connection").map(String::as_str),
            Some("Upgrade")
        );
        if let Some((name, value)) = expected_header {
            assert_eq!(
                headers.get(&name.to_ascii_lowercase()).map(String::as_str),
                Some(value)
            );
        }
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("write HTTPUpgrade response");
        stream.flush().await.expect("flush HTTPUpgrade response");
        stream
    }

    #[cfg(feature = "httpupgrade")]
    async fn accept_test_httpupgrade_early_data(
        mut stream: Box<dyn AsyncStream>,
        expected_path: &str,
        expected_host: &str,
    ) -> Box<dyn AsyncStream> {
        let mut request = Vec::new();
        loop {
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(
                request.len() < 64 * 1024,
                "test HTTPUpgrade early-data request too large"
            );
            let mut byte = [0u8; 1];
            let read = stream
                .read(&mut byte)
                .await
                .expect("read HTTPUpgrade early-data request");
            assert!(
                read > 0,
                "HTTPUpgrade early-data client closed during upgrade"
            );
            request.push(byte[0]);
        }
        let request_text = std::str::from_utf8(&request)
            .expect("ASCII HTTPUpgrade early-data request");
        let mut lines = request_text.split("\r\n");
        assert_eq!(
            lines.next().expect("request line"),
            format!("GET {expected_path} HTTP/1.1")
        );
        let mut headers = HashMap::<String, String>::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("valid request header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        assert_eq!(headers.get("host").map(String::as_str), Some(expected_host));
        assert_eq!(
            headers.get("upgrade").map(String::as_str),
            Some("websocket")
        );
        assert_eq!(
            headers.get("connection").map(String::as_str),
            Some("Upgrade")
        );

        assert_trojan_connect(&mut *stream).await;
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("write HTTPUpgrade early-data response");
        stream
            .flush()
            .await
            .expect("flush HTTPUpgrade early-data response");
        stream
    }

    async fn assert_trojan_connect<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        let mut password_hash = [0u8; 56];
        stream
            .read_exact(&mut password_hash)
            .await
            .expect("read Trojan password hash");
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
        let expected = digest
            .as_ref()
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(password_hash.as_slice(), expected.as_slice());
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.expect("read auth CRLF");
        assert_eq!(crlf, *b"\r\n");
        assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
        assert_eq!(
            stream.read_u8().await.expect("read Trojan address type"),
            0x03
        );
        let domain_len =
            stream.read_u8().await.expect("read domain length") as usize;
        let mut domain = vec![0u8; domain_len];
        stream
            .read_exact(&mut domain)
            .await
            .expect("read target domain");
        assert_eq!(domain, b"origin.example");
        assert_eq!(stream.read_u16().await.expect("read target port"), 443);
        stream
            .read_exact(&mut crlf)
            .await
            .expect("read request CRLF");
        assert_eq!(crlf, *b"\r\n");
    }

    async fn assert_trojan_connect_and_reply<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        assert_trojan_connect(stream).await;
        stream.write_all(b"x").await.expect("write relayed byte");
        stream.flush().await.expect("flush relayed byte");
    }

    #[derive(Clone)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        addresses: Vec<SocketAddr>,
    }

    impl CountingResolver {
        fn new(addresses: Vec<SocketAddr>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                addresses,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolver for CountingResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[test]
    fn routing_metadata_is_applied_as_value_transformation() {
        let source_addr: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let target_addr: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let base = connection_routing_input(
            "inbound",
            "alice",
            2,
            source_addr,
            target_addr,
            &target,
        );
        let transformed = apply_routing_metadata(
            base,
            InboundRoutingMetadata {
                local_addr: Some("203.0.113.7:8443".parse().unwrap()),
                vless_route: 42,
                sniffed_protocol: Some("tls".into()),
                route_target_domain: Some("sniffed.example".into()),
                attributes: HashMap::from([("x-test".into(), "ok".into())]),
            },
        );

        assert_eq!(transformed.inbound_tag, "inbound");
        assert_eq!(transformed.user, "alice");
        assert_eq!(transformed.source_port, 12345);
        assert_eq!(transformed.target_port, 443);
        assert_eq!(transformed.local_port, 8443);
        assert_eq!(transformed.local_ips, vec![vec![203, 0, 113, 7]]);
        assert_eq!(transformed.vless_route, 42);
        assert_eq!(transformed.protocol, "tls");
        assert_eq!(transformed.target_domain, "sniffed.example");
        assert_eq!(
            transformed.attributes.get("x-test").map(String::as_str),
            Some("ok")
        );
    }

    #[test]
    fn static_socks_outbound_compiles_xray_short_form() {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "tag": "proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": 1080,
                "user": "alice",
                "pass": "secret",
                "level": 3,
                "email": "alice@example.test"
            }
        }))
        .expect("parse static SOCKS outbound");

        let outbound =
            compile_static_outbound(&item).expect("compile SOCKS outbound");
        assert_eq!(outbound.protocol, "socks");
        let endpoint = decode_socks_outbound(&outbound)
            .expect("decode compiled SOCKS outbound");
        assert_eq!(endpoint.server.to_string(), "127.0.0.1:1080");
        assert_eq!(endpoint.username.as_deref(), Some("alice"));
        assert_eq!(endpoint.password.as_deref(), Some("secret"));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn static_vless_outbound_compiles_xray_short_form_and_rejects_transport_downgrade()
     {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": 1234,
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "encryption": "none"
            }
        }))
        .expect("parse static VLESS outbound");
        let outbound =
            compile_static_outbound(&item).expect("compile VLESS outbound");
        let endpoint =
            decode_vless_outbound(&outbound).expect("decode VLESS outbound");
        assert_eq!(endpoint.server.to_string(), "127.0.0.1:1234");
        assert_eq!(
            endpoint.user_id,
            parse_xray_uuid("3ac9b383-75a1-431c-8184-106c80eb2273").unwrap()
        );
        assert!(endpoint.flow.is_empty());

        let secure_item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "tag": "secure-proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": 1234,
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "encryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality"
            }
        }))
        .expect("parse VLESS outbound with stream settings");
        let error = compile_static_outbound(&secure_item)
            .expect_err("unsupported VLESS transport must fail closed");
        assert!(error.contains("refusing to downgrade transport security"));
    }

    #[cfg(feature = "trojan")]
    #[test]
    fn static_trojan_outbound_compiles_xray_short_form_and_tls_sender_settings() {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "password": "secret",
                "email": "trojan@example.test"
            }
        }))
        .expect("parse static Trojan outbound");
        let outbound =
            compile_static_outbound(&item).expect("compile Trojan outbound");
        let endpoint =
            decode_trojan_outbound(&outbound).expect("decode Trojan outbound");
        assert_eq!(endpoint.server.to_string(), "127.0.0.1:443");
        assert_eq!(endpoint.password, "secret");

        let secure_item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "secure-proxy",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "password": "secret"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls"
            }
        }))
        .expect("parse Trojan outbound with stream settings");
        let secure = compile_static_outbound(&secure_item)
            .expect("Trojan TLS sender settings should compile");
        assert_eq!(
            secure.sender_settings_type.as_deref(),
            Some(TYPE_APP_SENDER_CONFIG)
        );
        let transport = decode_sender_transport(
            secure.sender_settings_type.as_deref(),
            secure.sender_settings_value.as_deref(),
        )
        .expect("decode Trojan TLS sender settings");
        assert!(matches!(transport, OutboundTransport::Tls(_)));
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn routed_tcp_connection_uses_vless_outbound_and_strips_response_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake VLESS server");
        let server_addr = listener.local_addr().expect("fake VLESS address");
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let expected_id = parse_xray_uuid(user_id).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept VLESS client");
            let header =
                crate::handler::vless_handler::protocol::read_request_header(
                    &mut stream,
                )
                .await
                .expect("parse VLESS request");
            assert_eq!(header.user_id, expected_id);
            assert_eq!(
                header.command,
                crate::handler::vless_handler::protocol::COMMAND_TCP
            );
            assert_eq!(header.remote_location.to_string(), "origin.example:443");
            assert!(header.flow.is_empty());
            stream
                .write_all(&[0, 0])
                .await
                .expect("write VLESS response header");
            stream.write_all(b"x").await.expect("write relayed byte");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "id": user_id,
                "encryption": "none"
            }
        }))
        .expect("parse VLESS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![compile_static_outbound(&item).expect("compile VLESS outbound")],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile VLESS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("VLESS routed TCP connect")
        .expect("VLESS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
        server.await.expect("fake VLESS server task");
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_outbound_and_preserves_domain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan server");
        let server_addr = listener.local_addr().expect("fake Trojan address");
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept Trojan client");
            let mut password_hash = [0u8; 56];
            stream
                .read_exact(&mut password_hash)
                .await
                .expect("read Trojan password hash");
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
            let expected = digest
                .as_ref()
                .iter()
                .flat_map(|byte| format!("{byte:02x}").into_bytes())
                .collect::<Vec<_>>();
            assert_eq!(password_hash.as_slice(), expected.as_slice());
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await.expect("read first CRLF");
            assert_eq!(crlf, *b"\r\n");
            assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
            assert_eq!(
                stream.read_u8().await.expect("read Trojan address type"),
                0x03
            );
            let domain_len =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; domain_len];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read target domain");
            assert_eq!(domain, b"origin.example");
            assert_eq!(stream.read_u16().await.expect("read target port"), 443);
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read request CRLF");
            assert_eq!(crlf, *b"\r\n");
            stream.write_all(b"x").await.expect("write relayed byte");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            }
        }))
        .expect("parse Trojan outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![compile_static_outbound(&item).expect("compile Trojan outbound")],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan routed TCP connect")
        .expect("Trojan route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
        server.await.expect("fake Trojan server task");
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn trojan_udp_outbound_roundtrips_raw_transport_and_preserves_domain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan UDP server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan UDP server address");
        let target = NetLocation::from_str("origin.example:443", None)
            .expect("Trojan UDP target");
        let server_target = target.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept Trojan UDP client");
            let expected = build_trojan_request(
                &TrojanOutboundEndpoint {
                    server: NetLocation::UNSPECIFIED,
                    password: "secret".into(),
                },
                &server_target,
                TrojanCommand::Udp,
            )
            .expect("build Trojan UDP request header");
            let mut actual = vec![0u8; expected.len()];
            stream
                .read_exact(&mut actual)
                .await
                .expect("read Trojan UDP request header");
            assert_eq!(actual, expected);

            let mut udp =
                crate::handler::trojan_udp::TrojanUdpStream::new(Box::new(stream));
            let mut payload = [0u8; 16];
            let (packet_target, length) = udp
                .recv_from(&mut payload)
                .await
                .expect("read Trojan UDP request packet");
            assert_eq!(packet_target, server_target);
            assert_eq!(&payload[..length], b"ping");
            udp.send_to(&packet_target, b"pong")
                .await
                .expect("write Trojan UDP response packet");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            }
        }))
        .expect("parse Trojan UDP outbound");
        let outbound =
            compile_static_outbound(&item).expect("compile Trojan UDP outbound");
        let runtime = RuntimeState::new(Vec::new(), vec![outbound.clone()]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let mut udp =
            connect_trojan_udp_via_outbound(&resolver, &target, &runtime, &outbound)
                .await
                .expect("connect Trojan UDP outbound");
        udp.send_to(&target, b"ping")
            .await
            .expect("send Trojan UDP packet");
        let mut payload = [0u8; 16];
        let (source, length) = udp
            .recv_from(&mut payload)
            .await
            .expect("receive Trojan UDP packet");
        assert_eq!(source, target);
        assert_eq!(&payload[..length], b"pong");
        server.await.expect("fake Trojan UDP server task");
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_websocket_outbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan WebSocket server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan WebSocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan WebSocket client");
            let mut stream = accept_test_websocket(
                Box::new(stream),
                "/trojan?foo=bar",
                "ws.example.test",
                Some(("x-test", "chimera")),
            )
            .await;
            assert_trojan_connect_and_reply(&mut stream).await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "host": "ws.example.test",
                    "path": "/trojan?foo=bar",
                    "headers": {
                        "X-Test": "chimera"
                    }
                }
            }
        }))
        .expect("parse Trojan WebSocket outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan WebSocket outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan WebSocket route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan WebSocket routed TCP connect")
        .expect("Trojan WebSocket route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream.read_u8().await.expect("read WebSocket relayed byte"),
            b'x'
        );
        server.await.expect("fake Trojan WebSocket server task");
    }

    #[cfg(all(feature = "trojan", feature = "ws"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_websocket_early_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan WebSocket early-data server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan WebSocket early-data address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan WebSocket early-data client");
            let mut stream = accept_test_websocket_early_data(
                Box::new(stream),
                "/trojan",
                "ws.example.test",
            )
            .await;
            assert_trojan_connect_and_reply(&mut *stream).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                    .await
                    .is_err(),
                "Trojan header must not be repeated as a WebSocket frame after early data"
            );
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "host": "ws.example.test",
                    "path": "/trojan?ed=256"
                }
            }
        }))
        .expect("parse Trojan WebSocket early-data outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan WebSocket early-data outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan WebSocket early-data route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan WebSocket early-data routed TCP connect")
        .expect("Trojan WebSocket early-data route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read WebSocket early-data relayed byte"),
            b'x'
        );
        server
            .await
            .expect("fake Trojan WebSocket early-data server task");
    }

    #[cfg(all(feature = "trojan", feature = "tls", feature = "ws"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_websocket_tls_outbound() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan WSS certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan WSS server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan WSS server");
        let server_addr = listener.local_addr().expect("fake Trojan WSS address");
        let server = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept Trojan WSS client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan WSS TLS");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let mut stream = accept_test_websocket(
                Box::new(tls_stream),
                "/secure",
                "localhost",
                None,
            )
            .await;
            assert_trojan_connect_and_reply(&mut stream).await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "wsSettings": {
                    "path": "/secure"
                }
            }
        }))
        .expect("parse Trojan WSS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item).expect("compile Trojan WSS outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan WSS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan WSS routed TCP connect")
        .expect("Trojan WSS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(stream.read_u8().await.expect("read WSS relayed byte"), b'x');
        server.await.expect("fake Trojan WSS server task");
    }

    #[cfg(all(feature = "trojan", feature = "tls", feature = "ws"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_websocket_tls_early_data() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan WSS early-data certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan WSS early-data server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan WSS early-data server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan WSS early-data address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan WSS early-data client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan WSS early-data TLS");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let mut stream = accept_test_websocket_early_data(
                Box::new(tls_stream),
                "/secure",
                "localhost",
            )
            .await;
            assert_trojan_connect_and_reply(&mut *stream).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                    .await
                    .is_err(),
                "Trojan header must not be repeated after WSS early data"
            );
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "wsSettings": {
                    "path": "/secure?ed=256"
                }
            }
        }))
        .expect("parse Trojan WSS early-data outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan WSS early-data outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan WSS early-data route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan WSS early-data routed TCP connect")
        .expect("Trojan WSS early-data route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read WSS early-data relayed byte"),
            b'x'
        );
        server
            .await
            .expect("fake Trojan WSS early-data server task");
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_httpupgrade_outbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan HTTPUpgrade server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan HTTPUpgrade address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan HTTPUpgrade client");
            let mut stream = accept_test_httpupgrade(
                Box::new(stream),
                "/trojan?foo=bar",
                "upgrade.example.test",
                Some(("x-test", "chimera")),
            )
            .await;
            assert_trojan_connect_and_reply(&mut *stream).await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "none",
                "httpUpgradeSettings": {
                    "host": "upgrade.example.test",
                    "path": "/trojan?foo=bar",
                    "headers": {
                        "X-Test": "chimera"
                    }
                }
            }
        }))
        .expect("parse Trojan HTTPUpgrade outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan HTTPUpgrade outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan HTTPUpgrade route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan HTTPUpgrade routed TCP connect")
        .expect("Trojan HTTPUpgrade route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read HTTPUpgrade relayed byte"),
            b'x'
        );
        server.await.expect("fake Trojan HTTPUpgrade server task");
    }

    #[cfg(all(feature = "trojan", feature = "httpupgrade"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_httpupgrade_early_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan HTTPUpgrade early-data server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan HTTPUpgrade early-data address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan HTTPUpgrade early-data client");
            let mut stream = accept_test_httpupgrade_early_data(
                Box::new(stream),
                "/trojan",
                "upgrade.example.test",
            )
            .await;
            stream
                .write_all(b"x")
                .await
                .expect("write early-data relayed byte");
            stream.flush().await.expect("flush early-data relayed byte");
            assert!(
                tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                    .await
                    .is_err(),
                "Trojan header must not be repeated after HTTPUpgrade early data"
            );
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "none",
                "httpUpgradeSettings": {
                    "host": "upgrade.example.test",
                    "path": "/trojan?ed=1"
                }
            }
        }))
        .expect("parse Trojan HTTPUpgrade early-data outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan HTTPUpgrade early-data outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan HTTPUpgrade early-data route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan HTTPUpgrade early-data routed TCP connect")
        .expect("Trojan HTTPUpgrade early-data route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read HTTPUpgrade early-data relayed byte"),
            b'x'
        );
        server
            .await
            .expect("fake Trojan HTTPUpgrade early-data server task");
    }

    #[cfg(all(feature = "trojan", feature = "tls", feature = "httpupgrade"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_httpupgrade_tls_outbound() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan HTTPUpgrade TLS certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan HTTPUpgrade TLS server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan HTTPUpgrade TLS server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan HTTPUpgrade TLS address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan HTTPUpgrade TLS client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan HTTPUpgrade TLS");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let mut stream = accept_test_httpupgrade(
                Box::new(tls_stream),
                "/secure",
                "localhost",
                None,
            )
            .await;
            assert_trojan_connect_and_reply(&mut *stream).await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "httpUpgradeSettings": {
                    "path": "/secure"
                }
            }
        }))
        .expect("parse Trojan HTTPUpgrade TLS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan HTTPUpgrade TLS outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan HTTPUpgrade TLS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan HTTPUpgrade TLS routed TCP connect")
        .expect("Trojan HTTPUpgrade TLS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read HTTPUpgrade TLS relayed byte"),
            b'x'
        );
        server
            .await
            .expect("fake Trojan HTTPUpgrade TLS server task");
    }

    #[cfg(all(feature = "trojan", feature = "tls", feature = "httpupgrade"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_httpupgrade_tls_early_data() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan HTTPUpgrade TLS early-data certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan HTTPUpgrade TLS early-data server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan HTTPUpgrade TLS early-data server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan HTTPUpgrade TLS early-data address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan HTTPUpgrade TLS early-data client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan HTTPUpgrade TLS early-data");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let mut stream = accept_test_httpupgrade_early_data(
                Box::new(tls_stream),
                "/secure",
                "localhost",
            )
            .await;
            stream
                .write_all(b"x")
                .await
                .expect("write TLS early-data relayed byte");
            stream
                .flush()
                .await
                .expect("flush TLS early-data relayed byte");
            assert!(
                tokio::time::timeout(Duration::from_millis(25), stream.read_u8())
                    .await
                    .is_err(),
                "Trojan header must not be repeated after TLS HTTPUpgrade early data"
            );
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "httpUpgradeSettings": {
                    "path": "/secure?ed=1"
                }
            }
        }))
        .expect("parse Trojan HTTPUpgrade TLS early-data outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan HTTPUpgrade TLS early-data outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan HTTPUpgrade TLS early-data route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan HTTPUpgrade TLS early-data routed TCP connect")
        .expect("Trojan HTTPUpgrade TLS early-data route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read HTTPUpgrade TLS early-data relayed byte"),
            b'x'
        );
        server
            .await
            .expect("fake Trojan HTTPUpgrade TLS early-data server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_grpc_outbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC server");
        let server_addr = listener.local_addr().expect("fake Trojan gRPC address");
        let server = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept Trojan gRPC client");
            serve_test_grpc_trojan(
                stream,
                "grpc.example.test",
                Some("chimera-grpc-test"),
                false,
                TrojanCommand::Tcp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService",
                    "user_agent": "chimera-grpc-test"
                }
            }
        }))
        .expect("parse Trojan gRPC outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan gRPC outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan gRPC route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan gRPC routed TCP connect")
        .expect("Trojan gRPC route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream.read_u8().await.expect("read gRPC relayed byte"),
            b'x'
        );
        let mut tail = Vec::new();
        stream
            .read_to_end(&mut tail)
            .await
            .expect("gRPC success trailers should end with clean EOF");
        assert!(tail.is_empty());
        drop(stream);
        server.await.expect("fake Trojan gRPC server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn trojan_udp_outbound_roundtrips_grpc_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan UDP gRPC server");
        let server_addr =
            listener.local_addr().expect("fake Trojan UDP gRPC address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan UDP gRPC client");
            serve_test_grpc_trojan(
                stream,
                "grpc.example.test",
                Some("chimera-grpc-udp-test"),
                false,
                TrojanCommand::Udp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService",
                    "user_agent": "chimera-grpc-udp-test"
                }
            }
        }))
        .expect("parse Trojan UDP gRPC outbound");
        let outbound = compile_static_outbound(&item)
            .expect("compile Trojan UDP gRPC outbound");
        let runtime = RuntimeState::new(Vec::new(), vec![outbound.clone()]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None)
            .expect("Trojan UDP gRPC target");
        let mut udp =
            connect_trojan_udp_via_outbound(&resolver, &target, &runtime, &outbound)
                .await
                .expect("connect Trojan UDP gRPC outbound");
        udp.send_to(&target, b"ping")
            .await
            .expect("send Trojan UDP gRPC packet");
        let mut payload = [0u8; 16];
        let (source, length) = udp
            .recv_from(&mut payload)
            .await
            .expect("receive Trojan UDP gRPC packet");
        assert_eq!(source, target);
        assert_eq!(&payload[..length], b"pong");
        drop(udp);
        server.await.expect("fake Trojan UDP gRPC server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_grpc_multi_outbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC TunMulti server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan gRPC TunMulti address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan gRPC TunMulti client");
            serve_test_grpc_trojan(
                stream,
                "grpc.example.test",
                Some("chimera-grpc-multi-test"),
                true,
                TrojanCommand::Tcp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService",
                    "multiMode": true,
                    "user_agent": "chimera-grpc-multi-test"
                }
            }
        }))
        .expect("parse Trojan gRPC TunMulti outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan gRPC TunMulti outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan gRPC TunMulti route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan gRPC TunMulti routed TCP connect")
        .expect("Trojan gRPC TunMulti route should not blackhole");
        let mut stream = connection.stream;
        let mut reply = [0u8; 2];
        stream
            .read_exact(&mut reply)
            .await
            .expect("read repeated MultiHunk payloads");
        assert_eq!(&reply, b"xy");
        let mut tail = Vec::new();
        stream
            .read_to_end(&mut tail)
            .await
            .expect("TunMulti success trailers should end with clean EOF");
        assert!(tail.is_empty());
        drop(stream);
        server.await.expect("fake Trojan gRPC TunMulti server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "tls"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_grpc_tls_outbound() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan gRPC TLS certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan gRPC TLS server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC TLS server");
        let server_addr =
            listener.local_addr().expect("fake Trojan gRPC TLS address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan gRPC TLS client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan gRPC TLS");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice())
            );
            serve_test_grpc_trojan(
                tls_stream,
                "localhost",
                Some("chimera-grpc-tls-test"),
                false,
                TrojanCommand::Tcp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "grpcSettings": {
                    "serviceName": "GunService",
                    "user_agent": "chimera-grpc-tls-test"
                }
            }
        }))
        .expect("parse Trojan gRPC TLS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan gRPC TLS outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan gRPC TLS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan gRPC TLS routed TCP connect")
        .expect("Trojan gRPC TLS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream.read_u8().await.expect("read gRPC TLS relayed byte"),
            b'x'
        );
        drop(stream);
        server.await.expect("fake Trojan gRPC TLS server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "tls"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_grpc_tls_multi_outbound() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan gRPC TunMulti TLS certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config =
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("select TLS protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der], private_key)
                .expect("build Trojan gRPC TunMulti TLS server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC TunMulti TLS server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan gRPC TunMulti TLS address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan gRPC TunMulti TLS client");
            let tls_stream = acceptor
                .accept(stream)
                .await
                .expect("accept Trojan gRPC TunMulti TLS");
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice())
            );
            serve_test_grpc_trojan(
                tls_stream,
                "localhost",
                Some("chimera-grpc-tls-multi-test"),
                true,
                TrojanCommand::Tcp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                },
                "grpcSettings": {
                    "serviceName": "GunService",
                    "multiMode": true,
                    "user_agent": "chimera-grpc-tls-multi-test"
                }
            }
        }))
        .expect("parse Trojan gRPC TunMulti TLS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan gRPC TunMulti TLS outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan gRPC TunMulti TLS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan gRPC TunMulti TLS routed TCP connect")
        .expect("Trojan gRPC TunMulti TLS route should not blackhole");
        let mut stream = connection.stream;
        let mut reply = [0u8; 2];
        stream
            .read_exact(&mut reply)
            .await
            .expect("read TLS TunMulti repeated payloads");
        assert_eq!(&reply, b"xy");
        drop(stream);
        server
            .await
            .expect("fake Trojan gRPC TunMulti TLS server task");
    }

    #[cfg(all(feature = "trojan", feature = "grpc_transport", feature = "reality"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_grpc_reality_outbound() {
        let (private_key_b64, public_key_b64) = crate::reality::generate_keypair()
            .expect("generate gRPC REALITY keypair");
        let private_key = crate::reality::decode_private_key(&private_key_b64)
            .expect("decode gRPC REALITY private key");
        let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan gRPC REALITY server");
        let server_addr = listener
            .local_addr()
            .expect("fake Trojan gRPC REALITY address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan gRPC REALITY client");
            let reality_stream = accept_test_reality(
                stream,
                crate::reality::RealityServerConfig {
                    private_key,
                    short_ids: vec![short_id],
                    dest: NetLocation::new(
                        Address::Hostname("reality.example.test".to_string()),
                        443,
                    ),
                    server_names: vec!["reality.example.test".to_string()],
                    max_time_diff: Some(60_000),
                    min_client_version: Some([26, 3, 27]),
                    max_client_version: None,
                    cipher_suites: Vec::new(),
                },
            )
            .await;
            serve_test_grpc_trojan(
                reality_stream,
                "grpc.example.test",
                Some("chimera-grpc-reality-test"),
                false,
                TrojanCommand::Tcp,
            )
            .await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "reality.example.test",
                    "publicKey": public_key_b64,
                    "shortId": "0011223344556677",
                    "spiderX": "/"
                },
                "grpcSettings": {
                    "authority": "grpc.example.test",
                    "serviceName": "GunService",
                    "user_agent": "chimera-grpc-reality-test"
                }
            }
        }))
        .expect("parse Trojan gRPC REALITY outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan gRPC REALITY outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan gRPC REALITY route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan gRPC REALITY routed TCP connect")
        .expect("Trojan gRPC REALITY route should not blackhole");
        let mut stream = connection.stream;
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read gRPC REALITY relayed byte"),
            b'x'
        );
        drop(stream);
        server.await.expect("fake Trojan gRPC REALITY server task");
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_tuning_matches_xray_grpc_go_defaults() {
        let mut settings = OutboundGrpcClientSettings {
            authority: String::new(),
            service_name: "GunService".into(),
            multi_mode: false,
            idle_timeout: 0,
            health_check_timeout: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
            user_agent: String::new(),
        };
        assert_eq!(grpc_initial_stream_window(&settings), 65_535);
        assert_eq!(grpc_keepalive_params(&settings), None);

        settings.permit_without_stream = true;
        assert_eq!(
            grpc_keepalive_params(&settings),
            Some((Duration::from_secs(10), Duration::from_secs(20), true))
        );

        settings.idle_timeout = 3;
        settings.health_check_timeout = 7;
        settings.permit_without_stream = false;
        assert_eq!(
            grpc_keepalive_params(&settings),
            Some((Duration::from_secs(10), Duration::from_secs(7), false))
        );

        settings.idle_timeout = 30;
        settings.health_check_timeout = 0;
        assert_eq!(
            grpc_keepalive_params(&settings),
            Some((Duration::from_secs(30), Duration::from_secs(20), false))
        );

        settings.initial_windows_size = 32_768;
        assert_eq!(grpc_initial_stream_window(&settings), 65_535);
        settings.initial_windows_size = 1 << 20;
        assert_eq!(grpc_initial_stream_window(&settings), 1 << 20);

        let normalized = encode_static_grpc_config(StaticOutboundGrpcSettings {
            idle_timeout: -1,
            health_check_timeout: -1,
            initial_windows_size: -1,
            ..StaticOutboundGrpcSettings::default()
        })
        .expect("normalize static gRPC tuning");
        assert_eq!(normalized.idle_timeout, 0);
        assert_eq!(normalized.health_check_timeout, 0);
        assert_eq!(normalized.initial_windows_size, 0);
    }

    #[cfg(feature = "grpc_transport")]
    #[tokio::test]
    async fn grpc_outbound_write_shutdown_preserves_download_half() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gRPC half-close test server");
        let server_addr = listener
            .local_addr()
            .expect("gRPC half-close server address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept gRPC half-close client");
            let service =
                service_fn(|request: Request<hyper::body::Incoming>| async move {
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<Frame<bytes::Bytes>, Infallible>,
                    >(4);
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut encoded = BytesMut::new();
                        let mut decoded = Vec::new();
                        while let Some(frame) = body.frame().await {
                            let frame =
                                frame.expect("read half-close gRPC request frame");
                            if let Some(data) = frame.data_ref() {
                                encoded.extend_from_slice(data);
                                while let Some(payloads) =
                                    decode_grpc_message_payloads(&mut encoded, false)
                                        .expect("decode half-close gRPC Hunk")
                                {
                                    for payload in payloads {
                                        decoded.extend_from_slice(&payload);
                                    }
                                }
                            }
                        }
                        assert_eq!(decoded, b"hello");
                        tx.send(Ok(Frame::data(encode_grpc_message(b"x", false))))
                            .await
                            .expect("send half-close reply Hunk");
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            "grpc-status",
                            hyper::header::HeaderValue::from_static("0"),
                        );
                        tx.send(Ok(Frame::trailers(trailers)))
                            .await
                            .expect("send half-close success trailers");
                    });
                    let response_stream =
                        futures::stream::unfold(rx, |mut rx| async move {
                            rx.recv().await.map(|frame| (frame, rx))
                        });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(hyper::StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/grpc")
                            .body(StreamBody::new(response_stream))
                            .expect("build half-close gRPC response"),
                    )
                });
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("serve half-close gRPC connection");
        });

        let raw = tokio::net::TcpStream::connect(server_addr)
            .await
            .expect("connect gRPC half-close server");
        let server_location =
            NetLocation::from_ip_addr(server_addr.ip(), server_addr.port());
        let mut stream = connect_grpc_transport(
            Box::new(raw),
            &OutboundGrpcClientSettings {
                authority: "grpc.example.test".into(),
                service_name: "GunService".into(),
                multi_mode: false,
                idle_timeout: 0,
                health_check_timeout: 0,
                permit_without_stream: false,
                initial_windows_size: 0,
                user_agent: String::new(),
            },
            &server_location,
            None,
            false,
        )
        .await
        .expect("establish gRPC half-close tunnel");
        stream.write_all(b"hello").await.expect("write gRPC upload");
        stream.shutdown().await.expect("half-close gRPC upload");
        assert_eq!(
            stream
                .read_u8()
                .await
                .expect("read after gRPC write shutdown"),
            b'x'
        );
        let mut tail = Vec::new();
        stream
            .read_to_end(&mut tail)
            .await
            .expect("read clean gRPC half-close EOF");
        assert!(tail.is_empty());
        drop(stream);
        server.await.expect("gRPC half-close server task");
    }

    #[cfg(feature = "grpc_transport")]
    #[tokio::test]
    async fn grpc_outbound_surfaces_nonzero_trailer_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gRPC status test server");
        let server_addr = listener.local_addr().expect("gRPC status server address");
        let server = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept gRPC status client");
            let service =
                service_fn(|request: Request<hyper::body::Incoming>| async move {
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        while body.frame().await.is_some() {}
                    });
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<Frame<bytes::Bytes>, Infallible>,
                    >(2);
                    tokio::spawn(async move {
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            "grpc-status",
                            hyper::header::HeaderValue::from_static("13"),
                        );
                        tx.send(Ok(Frame::trailers(trailers)))
                            .await
                            .expect("send nonzero gRPC trailers");
                    });
                    let response_stream =
                        futures::stream::unfold(rx, |mut rx| async move {
                            rx.recv().await.map(|frame| (frame, rx))
                        });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(hyper::StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/grpc")
                            .body(StreamBody::new(response_stream))
                            .expect("build gRPC status response"),
                    )
                });
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("serve gRPC status connection");
        });

        let raw = tokio::net::TcpStream::connect(server_addr)
            .await
            .expect("connect gRPC status server");
        let server_location =
            NetLocation::from_ip_addr(server_addr.ip(), server_addr.port());
        let mut stream = connect_grpc_transport(
            Box::new(raw),
            &OutboundGrpcClientSettings {
                authority: "grpc.example.test".into(),
                service_name: "GunService".into(),
                multi_mode: false,
                idle_timeout: 0,
                health_check_timeout: 0,
                permit_without_stream: false,
                initial_windows_size: 0,
                user_agent: String::new(),
            },
            &server_location,
            None,
            false,
        )
        .await
        .expect("establish gRPC status tunnel");
        let error = stream
            .read_u8()
            .await
            .expect_err("nonzero grpc-status must surface as I/O error");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(error.to_string().contains("grpc-status 13"));
        drop(stream);
        server.await.expect("gRPC status server task");
    }

    #[cfg(all(feature = "trojan", feature = "reality"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_reality_outbound() {
        let (private_key_b64, public_key_b64) =
            crate::reality::generate_keypair().expect("generate REALITY keypair");
        let private_key = crate::reality::decode_private_key(&private_key_b64)
            .expect("decode REALITY private key");
        let short_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan REALITY server");
        let server_addr =
            listener.local_addr().expect("fake Trojan REALITY address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept Trojan REALITY client");
            let mut stream = accept_test_reality(
                stream,
                crate::reality::RealityServerConfig {
                    private_key,
                    short_ids: vec![short_id],
                    dest: NetLocation::new(
                        Address::Hostname("reality.example.test".to_string()),
                        443,
                    ),
                    server_names: vec!["reality.example.test".to_string()],
                    max_time_diff: Some(60_000),
                    min_client_version: Some([26, 3, 27]),
                    max_client_version: None,
                    cipher_suites: Vec::new(),
                },
            )
            .await;
            assert_trojan_connect_and_reply(&mut stream).await;
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": "reality.example.test",
                    "publicKey": public_key_b64,
                    "shortId": "0011223344556677",
                    "spiderX": "/"
                }
            }
        }))
        .expect("parse Trojan REALITY outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item)
                    .expect("compile Trojan REALITY outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan REALITY route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan REALITY routed TCP connect")
        .expect("Trojan REALITY route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(
            stream.read_u8().await.expect("read REALITY relayed byte"),
            b'x'
        );
        server.await.expect("fake Trojan REALITY server task");
    }

    #[cfg(all(feature = "trojan", feature = "tls"))]
    #[tokio::test]
    async fn routed_tcp_connection_uses_trojan_tls_with_custom_verify_root() {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate Trojan TLS certificate");
        let certificate_pem = generated.cert.pem();
        let certificate_der =
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("select TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("build Trojan TLS server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Trojan TLS server");
        let server_addr = listener.local_addr().expect("fake Trojan TLS address");
        let server = tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await.expect("accept Trojan TLS client");
            let mut stream =
                acceptor.accept(stream).await.expect("accept Trojan TLS");
            let mut password_hash = [0u8; 56];
            stream
                .read_exact(&mut password_hash)
                .await
                .expect("read Trojan TLS password hash");
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, b"secret");
            let expected = digest
                .as_ref()
                .iter()
                .flat_map(|byte| format!("{byte:02x}").into_bytes())
                .collect::<Vec<_>>();
            assert_eq!(password_hash.as_slice(), expected.as_slice());
            let mut crlf = [0u8; 2];
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read TLS auth CRLF");
            assert_eq!(crlf, *b"\r\n");
            assert_eq!(stream.read_u8().await.expect("read Trojan command"), 0x01);
            assert_eq!(
                stream.read_u8().await.expect("read Trojan address type"),
                0x03
            );
            let domain_len =
                stream.read_u8().await.expect("read domain length") as usize;
            let mut domain = vec![0u8; domain_len];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read target domain");
            assert_eq!(domain, b"origin.example");
            assert_eq!(stream.read_u16().await.expect("read target port"), 443);
            stream
                .read_exact(&mut crlf)
                .await
                .expect("read request CRLF");
            assert_eq!(crlf, *b"\r\n");
            stream
                .write_all(b"x")
                .await
                .expect("write TLS relayed byte");
        });

        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {
                "address": server_addr.ip().to_string(),
                "port": server_addr.port(),
                "password": "secret"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "certificate": [certificate_pem],
                        "usage": "verify"
                    }]
                }
            }
        }))
        .expect("parse Trojan TLS outbound");
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                compile_static_outbound(&item).expect("compile Trojan TLS outbound"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile Trojan TLS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("Trojan TLS routed TCP connect")
        .expect("Trojan TLS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(stream.read_u8().await.expect("read TLS relayed byte"), b'x');
        server.await.expect("fake Trojan TLS server task");
    }

    #[tokio::test]
    async fn routed_tcp_connection_uses_socks_outbound_and_preserves_domain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake SOCKS server");
        let server_addr = listener.local_addr().expect("fake SOCKS address");
        let server = tokio::spawn(async move {
            let (mut stream, _) =
                listener.accept().await.expect("accept SOCKS client");
            let mut greeting = [0u8; 3];
            stream
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            stream.write_all(&[0x05, 0x02]).await.expect("write method");

            let version = stream.read_u8().await.expect("read auth version");
            let username_len =
                stream.read_u8().await.expect("read username length") as usize;
            let mut username = vec![0u8; username_len];
            stream
                .read_exact(&mut username)
                .await
                .expect("read username");
            let password_len =
                stream.read_u8().await.expect("read password length") as usize;
            let mut password = vec![0u8; password_len];
            stream
                .read_exact(&mut password)
                .await
                .expect("read password");
            assert_eq!(version, 0x01);
            assert_eq!(username, b"alice");
            assert_eq!(password, b"secret");
            stream
                .write_all(&[0x01, 0x00])
                .await
                .expect("write auth result");

            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("read CONNECT header");
            assert_eq!(request, [0x05, 0x01, 0x00, 0x03]);
            let domain_len =
                stream.read_u8().await.expect("read target domain length") as usize;
            let mut domain = vec![0u8; domain_len];
            stream
                .read_exact(&mut domain)
                .await
                .expect("read target domain");
            let port = stream.read_u16().await.expect("read target port");
            assert_eq!(domain, b"origin.example");
            assert_eq!(port, 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("write CONNECT result");
            stream.write_all(b"x").await.expect("write relay byte");
        });

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![socks_outbound(
                "proxy",
                server_addr,
                Some("alice"),
                Some("secret"),
            )],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["edge".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile SOCKS route"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_str("origin.example:443", None).unwrap();
        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "edge",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("SOCKS routed TCP connect")
        .expect("SOCKS route should not blackhole");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        let mut stream = connection.stream;
        assert_eq!(stream.read_u8().await.expect("read relayed byte"), b'x');
        server.await.expect("fake SOCKS server task");
    }

    #[test]
    fn tcp_connect_observation_is_a_pure_result_projection() {
        let success = tcp_connect_observation(true, 12, 100, String::new());
        assert!(success.alive);
        assert_eq!(success.delay_ms, 12);
        assert_eq!(success.last_seen_time, 100);
        assert_eq!(success.last_try_time, 100);
        assert!(success.last_error_reason.is_empty());

        let failure = tcp_connect_observation(false, 34, 200, "refused".into());
        assert!(!failure.alive);
        assert_eq!(failure.delay_ms, 34);
        assert_eq!(failure.last_seen_time, 0);
        assert_eq!(failure.last_try_time, 200);
        assert_eq!(failure.last_error_reason, "refused");
    }

    #[test]
    fn direct_outbound_defaults_to_implicit_freedom() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());

        assert_eq!(
            select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
                .unwrap(),
            DirectOutboundAction::Freedom { tag: None }
        );
    }

    #[test]
    fn direct_outbound_rejects_unsupported_protocol() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("proxy", "vmess")]);

        let err = select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "tcp outbound proxy uses unsupported protocol vmess"
        );
    }

    #[test]
    fn direct_outbound_rejects_missing_routed_outbound() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("missing".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("missing outbound routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("missing routed outbound must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing outbound missing"));
    }

    #[test]
    fn direct_outbound_rejects_empty_balancer_without_falling_back() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("empty".into()),
                    ..RuleConfig::default()
                }],
                balancers: vec![BalancerConfig {
                    tag: "empty".into(),
                    outbound_selector: vec!["missing-prefix".into()],
                    strategy: Default::default(),
                    fallback_tag: None,
                }],
                ..RoutingConfig::default()
            }))
            .expect("empty balancer routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("empty routed balancer must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("balancer empty has no available outbound")
        );
    }

    #[test]
    fn direct_outbound_routes_by_authenticated_user() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    user: vec!["alice".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .unwrap(),
        );
        let input = connection_routing_input(
            "quic-in",
            "alice",
            2,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            &NetLocation::from_str("example.com:443", None).unwrap(),
        );

        assert_eq!(
            select_direct_outbound(&runtime, &input, "tcp").unwrap(),
            DirectOutboundAction::Blackhole {
                tag: "blocked".into()
            }
        );
        assert_eq!(input.source_port, 12345);
        assert_eq!(input.target_domain, "example.com");
    }

    #[tokio::test]
    async fn as_is_domain_match_does_not_resolve_before_routing() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                domain_strategy: Some("AsIs".into()),
                rules: vec![RuleConfig {
                    domain: vec!["full:example.test".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("AsIs routing config"),
        );
        let counting =
            CountingResolver::new(vec!["203.0.113.1:443".parse().unwrap()]);
        let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
        let target = NetLocation::from_str("example.test:443", None).unwrap();

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "in",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("domain rule should route without DNS");

        assert!(connection.is_none());
        assert_eq!(counting.calls(), 0);
    }

    #[tokio::test]
    async fn ip_if_non_match_resolves_after_domain_miss_and_matches_any_ip() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                domain_strategy: Some("IpIfNonMatch".into()),
                rules: vec![
                    RuleConfig {
                        domain: vec!["full:other.test".into()],
                        outbound_tag: Some("direct".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        ip: vec!["203.0.113.2/32".into()],
                        outbound_tag: Some("blocked".into()),
                        ..RuleConfig::default()
                    },
                ],
                ..RoutingConfig::default()
            }))
            .expect("IpIfNonMatch routing config"),
        );
        let counting = CountingResolver::new(vec![
            "198.51.100.1:443".parse().unwrap(),
            "203.0.113.2:443".parse().unwrap(),
        ]);
        let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
        let target = NetLocation::from_str("example.test:443", None).unwrap();

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "in",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("resolved IP rule should route");

        assert!(connection.is_none());
        assert_eq!(counting.calls(), 1);
    }

    #[tokio::test]
    async fn ip_on_demand_skips_resolution_when_earlier_domain_rule_matches() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                domain_strategy: Some("IpOnDemand".into()),
                rules: vec![
                    RuleConfig {
                        domain: vec!["full:example.test".into()],
                        outbound_tag: Some("blocked".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        ip: vec!["203.0.113.2/32".into()],
                        outbound_tag: Some("direct".into()),
                        ..RuleConfig::default()
                    },
                ],
                ..RoutingConfig::default()
            }))
            .expect("IpOnDemand routing config"),
        );
        let counting =
            CountingResolver::new(vec!["203.0.113.2:443".parse().unwrap()]);
        let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
        let target = NetLocation::from_str("example.test:443", None).unwrap();

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "in",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("earlier domain rule should avoid DNS");

        assert!(connection.is_none());
        assert_eq!(counting.calls(), 0);
    }

    #[tokio::test]
    async fn ip_on_demand_resolves_when_reachable_rule_requires_target_ip() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                domain_strategy: Some("IpOnDemand".into()),
                rules: vec![RuleConfig {
                    ip: vec!["203.0.113.2/32".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("IpOnDemand routing config"),
        );
        let counting = CountingResolver::new(vec![
            "198.51.100.1:443".parse().unwrap(),
            "203.0.113.2:443".parse().unwrap(),
        ]);
        let resolver: Arc<dyn Resolver> = Arc::new(counting.clone());
        let target = NetLocation::from_str("example.test:443", None).unwrap();

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "in",
            "",
            "192.0.2.10:12345".parse().unwrap(),
        )
        .await
        .expect("on-demand IP rule should route");

        assert!(connection.is_none());
        assert_eq!(counting.calls(), 1);
    }

    #[tokio::test]
    async fn tcp_outbound_records_successful_observation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observed target");
        let target_addr = listener.local_addr().expect("observed target address");
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .expect("observed connection should succeed");
        assert!(connection.is_some());

        let observations = runtime.outbound_observations();
        let status = observations.get("direct").expect("observation missing");
        assert!(status.alive);
        assert!(status.last_seen_time > 0);
        assert_eq!(status.last_error_reason, "");
    }

    #[tokio::test]
    async fn tcp_outbound_records_failed_observation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve failed target port");
        let target_addr = listener.local_addr().expect("failed target address");
        drop(listener);
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        if connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .is_ok()
        {
            panic!("connection to released port should fail");
        }

        let observations = runtime.outbound_observations();
        let status = observations
            .get("direct")
            .expect("failure observation missing");
        assert!(!status.alive);
        assert!(status.last_try_time > 0);
        assert!(!status.last_error_reason.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_outbound_routes_by_local_process() {
        let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing inbound listener");
        let client = tokio::net::TcpStream::connect(
            inbound_listener.local_addr().expect("inbound address"),
        );
        let (client, accepted) = tokio::join!(client, inbound_listener.accept());
        let _client = client.expect("connect local process client");
        let (_accepted, source_addr) =
            accepted.expect("accept local process client");
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing target");
        let target_addr = target_listener.local_addr().expect("target address");
        let process_name = std::env::current_exe()
            .expect("current executable")
            .file_name()
            .expect("current executable name")
            .to_string_lossy()
            .into_owned();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    process: vec![process_name],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("process routing should build"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "process-in",
            "",
            source_addr,
        )
        .await
        .expect("process-routed outbound selection should succeed");

        assert!(
            connection.is_none(),
            "process route should select blackhole"
        );
    }
}
