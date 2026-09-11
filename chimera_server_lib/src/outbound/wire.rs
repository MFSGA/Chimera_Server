use std::collections::HashMap;

use prost::Message;

pub(super) const TYPE_PROXY_SOCKS_CLIENT_CONFIG: &str =
    "xray.proxy.socks.ClientConfig";
pub(super) const TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ClientConfig";
pub(super) const TYPE_PROXY_SOCKS_ACCOUNT: &str = "xray.proxy.socks.Account";
pub(super) const TYPE_PROXY_VLESS_CLIENT_CONFIG: &str =
    "xray.proxy.vless.outbound.Config";
pub(super) const TYPE_PROXY_VLESS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.outbound.Config";
pub(super) const TYPE_PROXY_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
pub(super) const TYPE_PROXY_VLESS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.vless.Account";
pub(super) const TYPE_PROXY_TROJAN_CLIENT_CONFIG: &str =
    "xray.proxy.trojan.ClientConfig";
pub(super) const TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ClientConfig";
pub(super) const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
pub(super) const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.trojan.Account";
pub(super) const TYPE_APP_SENDER_CONFIG: &str = "xray.app.proxyman.SenderConfig";
pub(super) const TYPE_APP_SENDER_CONFIG_V2RAY: &str =
    "v2ray.core.app.proxyman.SenderConfig";
pub(super) const TYPE_TRANSPORT_TLS_CONFIG: &str =
    "xray.transport.internet.tls.Config";
pub(super) const TYPE_TRANSPORT_TLS_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.tls.Config";
pub(super) const TYPE_TRANSPORT_REALITY_CONFIG: &str =
    "xray.transport.internet.reality.Config";
pub(super) const TYPE_TRANSPORT_WEBSOCKET_CONFIG: &str =
    "xray.transport.internet.websocket.Config";
pub(super) const TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.websocket.Config";
pub(super) const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG: &str =
    "xray.transport.internet.httpupgrade.Config";
pub(super) const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.httpupgrade.Config";
#[cfg(feature = "grpc_transport")]
pub(super) const TYPE_TRANSPORT_GRPC_CONFIG: &str =
    "xray.transport.internet.grpc.encoding.Config";
#[cfg(feature = "grpc_transport")]
pub(super) const TYPE_TRANSPORT_GRPC_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.grpc.encoding.Config";

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) server: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksServerEndpointPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    pub(super) port: u32,
    #[prost(message, optional, tag = "3")]
    pub(super) user: Option<OutboundUserPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct IpOrDomainPayload {
    #[prost(oneof = "ip_or_domain_payload::Address", tags = "1, 2")]
    pub(super) address: Option<ip_or_domain_payload::Address>,
}

pub(super) mod ip_or_domain_payload {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(in crate::outbound) enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct OutboundUserPayload {
    #[prost(uint32, tag = "1")]
    pub(super) level: u32,
    #[prost(string, tag = "2")]
    pub(super) email: String,
    #[prost(message, optional, tag = "3")]
    pub(super) account: Option<TypedMessagePayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TypedMessagePayload {
    #[prost(string, tag = "1")]
    pub(super) r#type: String,
    #[prost(bytes, tag = "2")]
    pub(super) value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) username: String,
    #[prost(string, tag = "2")]
    pub(super) password: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) vnext: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) id: String,
    #[prost(string, tag = "2")]
    pub(super) flow: String,
    #[prost(string, tag = "3")]
    pub(super) encryption: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) server: Option<SocksServerEndpointPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) password: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SenderConfigPayload {
    #[prost(message, optional, tag = "2")]
    pub(super) stream_settings: Option<OutboundStreamConfigPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct OutboundStreamConfigPayload {
    #[prost(message, repeated, tag = "2")]
    pub(super) transport_settings: Vec<OutboundTransportConfigPayload>,
    #[prost(string, tag = "5")]
    pub(super) protocol_name: String,
    #[prost(string, tag = "3")]
    pub(super) security_type: String,
    #[prost(message, repeated, tag = "4")]
    pub(super) security_settings: Vec<TypedMessagePayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct OutboundTransportConfigPayload {
    #[prost(message, optional, tag = "2")]
    pub(super) settings: Option<TypedMessagePayload>,
    #[prost(string, tag = "3")]
    pub(super) protocol_name: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct WebsocketConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) host: String,
    #[prost(string, tag = "2")]
    pub(super) path: String,
    #[prost(map = "string, string", tag = "3")]
    pub(super) header: HashMap<String, String>,
    #[prost(bool, tag = "4")]
    pub(super) accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    pub(super) ed: u32,
    #[prost(uint32, tag = "6")]
    pub(super) heartbeat_period: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct HttpUpgradeConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) host: String,
    #[prost(string, tag = "2")]
    pub(super) path: String,
    #[prost(map = "string, string", tag = "3")]
    pub(super) header: HashMap<String, String>,
    #[prost(bool, tag = "4")]
    pub(super) accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    pub(super) ed: u32,
}

#[cfg(feature = "grpc_transport")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct GrpcConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) authority: String,
    #[prost(string, tag = "2")]
    pub(super) service_name: String,
    #[prost(bool, tag = "3")]
    pub(super) multi_mode: bool,
    #[prost(int32, tag = "4")]
    pub(super) idle_timeout: i32,
    #[prost(int32, tag = "5")]
    pub(super) health_check_timeout: i32,
    #[prost(bool, tag = "6")]
    pub(super) permit_without_stream: bool,
    #[prost(int32, tag = "7")]
    pub(super) initial_windows_size: i32,
    #[prost(string, tag = "8")]
    pub(super) user_agent: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct RealityConfigPayload {
    #[prost(bool, tag = "1")]
    pub(super) show: bool,
    #[prost(string, tag = "2")]
    pub(super) dest: String,
    #[prost(string, tag = "3")]
    pub(super) r#type: String,
    #[prost(uint64, tag = "4")]
    pub(super) xver: u64,
    #[prost(string, repeated, tag = "5")]
    pub(super) server_names: Vec<String>,
    #[prost(bytes, tag = "6")]
    pub(super) private_key: Vec<u8>,
    #[prost(bytes, tag = "7")]
    pub(super) min_client_ver: Vec<u8>,
    #[prost(bytes, tag = "8")]
    pub(super) max_client_ver: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub(super) max_time_diff: u64,
    #[prost(bytes, repeated, tag = "10")]
    pub(super) short_ids: Vec<Vec<u8>>,
    #[prost(bytes, tag = "11")]
    pub(super) mldsa65_seed: Vec<u8>,
    #[prost(string, tag = "21")]
    pub(super) fingerprint: String,
    #[prost(string, tag = "22")]
    pub(super) server_name: String,
    #[prost(bytes, tag = "23")]
    pub(super) public_key: Vec<u8>,
    #[prost(bytes, tag = "24")]
    pub(super) short_id: Vec<u8>,
    #[prost(bytes, tag = "25")]
    pub(super) mldsa65_verify: Vec<u8>,
    #[prost(string, tag = "26")]
    pub(super) spider_x: String,
    #[prost(int64, repeated, tag = "27")]
    pub(super) spider_y: Vec<i64>,
    #[prost(string, tag = "31")]
    pub(super) master_key_log: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TlsConfigPayload {
    #[prost(message, repeated, tag = "2")]
    pub(super) certificate: Vec<TlsCertificatePayload>,
    #[prost(string, tag = "3")]
    pub(super) server_name: String,
    #[prost(string, repeated, tag = "4")]
    pub(super) next_protocol: Vec<String>,
    #[prost(bool, tag = "5")]
    pub(super) enable_session_resumption: bool,
    #[prost(bool, tag = "6")]
    pub(super) disable_system_root: bool,
    #[prost(string, tag = "7")]
    pub(super) min_version: String,
    #[prost(string, tag = "8")]
    pub(super) max_version: String,
    #[prost(string, tag = "9")]
    pub(super) cipher_suites: String,
    #[prost(string, tag = "11")]
    pub(super) fingerprint: String,
    #[prost(bool, tag = "12")]
    pub(super) reject_unknown_sni: bool,
    #[prost(string, tag = "15")]
    pub(super) master_key_log: String,
    #[prost(string, repeated, tag = "16")]
    pub(super) curve_preferences: Vec<String>,
    #[prost(string, repeated, tag = "17")]
    pub(super) verify_peer_cert_by_name: Vec<String>,
    #[prost(bytes, tag = "18")]
    pub(super) ech_server_keys: Vec<u8>,
    #[prost(string, tag = "19")]
    pub(super) ech_config_list: String,
    #[prost(bytes, repeated, tag = "22")]
    pub(super) pinned_peer_cert_sha256: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TlsCertificatePayload {
    #[prost(bytes, tag = "1")]
    pub(super) certificate: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub(super) key: Vec<u8>,
    #[prost(int32, tag = "3")]
    pub(super) usage: i32,
    #[prost(string, tag = "5")]
    pub(super) certificate_path: String,
    #[prost(string, tag = "6")]
    pub(super) key_path: String,
}
