use prost::Message;
use tonic::Status;

use super::super::proto;

pub(super) const TYPE_ADD_USER_OPERATION: &str =
    "xray.app.proxyman.command.AddUserOperation";
pub(super) const TYPE_REMOVE_USER_OPERATION: &str =
    "xray.app.proxyman.command.RemoveUserOperation";
pub(super) const TYPE_ADD_USER_OPERATION_V2RAY: &str =
    "v2ray.core.app.proxyman.command.AddUserOperation";
pub(super) const TYPE_REMOVE_USER_OPERATION_V2RAY: &str =
    "v2ray.core.app.proxyman.command.RemoveUserOperation";
pub(super) const ERR_PROXY_NOT_USER_MANAGER: &str =
    "app/proxyman/command: proxy is not a UserManager";
pub(super) const TYPE_APP_RECEIVER_CONFIG: &str = "xray.app.proxyman.ReceiverConfig";
pub(super) const TYPE_APP_RECEIVER_CONFIG_V2RAY: &str =
    "v2ray.core.app.proxyman.ReceiverConfig";
pub(super) const TYPE_PROXY_SOCKS_SERVER_CONFIG: &str =
    "xray.proxy.socks.ServerConfig";
pub(super) const TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ServerConfig";
pub(super) const TYPE_PROXY_DOKODEMO_CONFIG: &str = "xray.proxy.dokodemo.Config";
#[cfg(feature = "hysteria")]
pub(super) const TYPE_PROXY_HYSTERIA_ACCOUNT: &str =
    "xray.proxy.hysteria.account.Account";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_INBOUND_CONFIG: &str =
    "xray.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.inbound.Config";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_OUTBOUND_CONFIG: &str =
    "xray.proxy.vless.outbound.Config";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vless.outbound.Config";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
#[cfg(feature = "vless")]
pub(super) const TYPE_PROXY_VLESS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.vless.Account";
#[cfg(feature = "vmess")]
pub(super) const TYPE_PROXY_VMESS_INBOUND_CONFIG: &str =
    "xray.proxy.vmess.inbound.Config";
#[cfg(feature = "vmess")]
pub(super) const TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.vmess.inbound.Config";
#[cfg(feature = "vmess")]
pub(super) const TYPE_PROXY_VMESS_ACCOUNT: &str = "xray.proxy.vmess.Account";
#[cfg(feature = "vmess")]
pub(super) const TYPE_PROXY_VMESS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.vmess.Account";
#[cfg(feature = "shadowsocks")]
pub(super) const TYPE_PROXY_SHADOWSOCKS_ACCOUNT: &str =
    "xray.proxy.shadowsocks.Account";
#[cfg(feature = "shadowsocks")]
pub(super) const TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.shadowsocks.Account";
#[cfg(feature = "shadowsocks")]
pub(super) const TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT: &str =
    "xray.proxy.shadowsocks_2022.Account";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_SERVER_CONFIG: &str =
    "xray.proxy.trojan.ServerConfig";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ServerConfig";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_CLIENT_CONFIG: &str =
    "xray.proxy.trojan.ClientConfig";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.trojan.ClientConfig";
pub(super) const TYPE_PROXY_FREEDOM_CONFIG: &str = "xray.proxy.freedom.Config";
pub(super) const TYPE_PROXY_FREEDOM_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.freedom.Config";
pub(super) const TYPE_PROXY_SOCKS_CLIENT_CONFIG: &str =
    "xray.proxy.socks.ClientConfig";
pub(super) const TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY: &str =
    "v2ray.core.proxy.socks.ClientConfig";
pub(super) const TYPE_PROXY_BLACKHOLE_CONFIG: &str = "xray.proxy.blackhole.Config";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
#[cfg(feature = "trojan")]
pub(super) const TYPE_PROXY_TROJAN_ACCOUNT_V2RAY: &str =
    "v2ray.core.proxy.trojan.Account";
#[cfg(feature = "ws")]
pub(super) const TYPE_TRANSPORT_WEBSOCKET_CONFIG: &str =
    "xray.transport.internet.websocket.Config";
#[cfg(feature = "ws")]
pub(super) const TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.websocket.Config";
#[cfg(feature = "httpupgrade")]
pub(super) const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG: &str =
    "xray.transport.internet.httpupgrade.Config";
#[cfg(feature = "httpupgrade")]
pub(super) const TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.httpupgrade.Config";
#[cfg(feature = "grpc_transport")]
pub(super) const TYPE_TRANSPORT_GRPC_CONFIG: &str =
    "xray.transport.internet.grpc.encoding.Config";
#[cfg(feature = "grpc_transport")]
pub(super) const TYPE_TRANSPORT_GRPC_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.grpc.encoding.Config";
#[cfg(feature = "tls")]
pub(super) const TYPE_TRANSPORT_TLS_CONFIG: &str =
    "xray.transport.internet.tls.Config";
#[cfg(feature = "tls")]
pub(super) const TYPE_TRANSPORT_TLS_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.tls.Config";
#[cfg(feature = "reality")]
pub(super) const TYPE_TRANSPORT_REALITY_CONFIG: &str =
    "xray.transport.internet.reality.Config";
pub(super) const TYPE_TRANSPORT_XHTTP_CONFIG: &str =
    "xray.transport.internet.splithttp.Config";
pub(super) const TYPE_TRANSPORT_XHTTP_CONFIG_V2RAY: &str =
    "v2ray.core.transport.internet.splithttp.Config";

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) password: String,
}

#[cfg(feature = "hysteria")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct HysteriaAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) auth: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct PortRangePayload {
    #[prost(uint32, tag = "1")]
    pub(super) from: u32,
    #[prost(uint32, tag = "2")]
    pub(super) to: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct PortListPayload {
    #[prost(message, repeated, tag = "1")]
    pub(super) range: Vec<PortRangePayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct IpOrDomainPayload {
    #[prost(oneof = "ip_or_domain_payload::Address", tags = "1, 2")]
    pub(super) address: Option<ip_or_domain_payload::Address>,
}

pub(super) mod ip_or_domain_payload {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct ReceiverConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) port_list: Option<PortListPayload>,
    #[prost(message, optional, tag = "2")]
    pub(super) listen: Option<IpOrDomainPayload>,
    #[prost(message, optional, tag = "3")]
    pub(super) stream_settings: Option<StreamConfigPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct QuicParamsPayload {
    #[prost(string, tag = "1")]
    pub(super) congestion: String,
    #[prost(string, tag = "2")]
    pub(super) bbr_profile: String,
    #[prost(uint64, tag = "6")]
    pub(super) init_stream_receive_window: u64,
    #[prost(uint64, tag = "7")]
    pub(super) max_stream_receive_window: u64,
    #[prost(uint64, tag = "8")]
    pub(super) init_connection_receive_window: u64,
    #[prost(uint64, tag = "9")]
    pub(super) max_connection_receive_window: u64,
    #[prost(int64, tag = "10")]
    pub(super) max_idle_timeout: i64,
    #[prost(int64, tag = "11")]
    pub(super) keep_alive_period: i64,
    #[prost(bool, tag = "12")]
    pub(super) disable_path_mtu_discovery: bool,
    #[prost(int64, tag = "13")]
    pub(super) max_incoming_streams: i64,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksServerConfigPayload {
    #[prost(int32, tag = "1")]
    pub(super) auth_type: i32,
    #[prost(map = "string, string", tag = "2")]
    pub(super) accounts: std::collections::HashMap<String, String>,
    #[prost(message, optional, tag = "3")]
    pub(super) address: Option<IpOrDomainPayload>,
    #[prost(bool, tag = "4")]
    pub(super) udp_enabled: bool,
    #[prost(uint32, tag = "6")]
    pub(super) user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct DokodemoConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    pub(super) port: u32,
    #[prost(map = "string, string", tag = "3")]
    pub(super) port_map: std::collections::HashMap<String, String>,
    #[prost(enumeration = "proto::xray::common::net::Network", repeated, tag = "7")]
    pub(super) networks: Vec<i32>,
    #[prost(bool, tag = "5")]
    pub(super) follow_redirect: bool,
    #[prost(uint32, tag = "6")]
    pub(super) user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct FreedomConfigPayload {}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) server: Option<SocksServerEndpointPayload>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessOutboundConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) vnext: Option<SocksServerEndpointPayload>,
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanClientConfigPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) server: Option<SocksServerEndpointPayload>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessOutboundAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) id: String,
    #[prost(string, tag = "2")]
    pub(super) flow: String,
    #[prost(string, tag = "3")]
    pub(super) encryption: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SocksServerEndpointPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) address: Option<IpOrDomainPayload>,
    #[prost(uint32, tag = "2")]
    pub(super) port: u32,
    #[prost(message, optional, tag = "3")]
    pub(super) user: Option<proto::xray::common::protocol::User>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct BlackholeConfigPayload {}

#[derive(Clone, PartialEq, Message)]
pub(super) struct SenderConfigPayload {
    #[prost(message, optional, tag = "2")]
    pub(super) stream_settings: Option<StreamConfigPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct StreamConfigPayload {
    #[prost(string, tag = "5")]
    pub(super) protocol_name: String,
    #[prost(message, repeated, tag = "2")]
    pub(super) transport_settings: Vec<TransportConfigPayload>,
    #[prost(string, tag = "3")]
    pub(super) security_type: String,
    #[prost(message, repeated, tag = "4")]
    pub(super) security_settings: Vec<proto::xray::common::serial::TypedMessage>,
    #[prost(message, optional, tag = "12")]
    pub(super) quic_params: Option<QuicParamsPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct TransportConfigPayload {
    #[prost(message, optional, tag = "2")]
    pub(super) settings: Option<proto::xray::common::serial::TypedMessage>,
    #[prost(string, tag = "3")]
    pub(super) protocol_name: String,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct XhttpRangePayload {
    #[prost(int32, tag = "1")]
    pub(super) from: i32,
    #[prost(int32, tag = "2")]
    pub(super) to: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct XhttpXmuxPayload {
    #[prost(message, optional, tag = "1")]
    pub(super) max_concurrency: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "2")]
    pub(super) max_connections: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "3")]
    pub(super) c_max_reuse_times: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "4")]
    pub(super) h_max_request_times: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "5")]
    pub(super) h_max_reusable_secs: Option<XhttpRangePayload>,
    #[prost(int64, tag = "6")]
    pub(super) h_keep_alive_period: i64,
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct XhttpConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) host: String,
    #[prost(string, tag = "2")]
    pub(super) path: String,
    #[prost(string, tag = "3")]
    pub(super) mode: String,
    #[prost(map = "string, string", tag = "4")]
    pub(super) headers: std::collections::HashMap<String, String>,
    #[prost(message, optional, tag = "5")]
    pub(super) x_padding_bytes: Option<XhttpRangePayload>,
    #[prost(bool, tag = "6")]
    pub(super) no_grpc_header: bool,
    #[prost(bool, tag = "7")]
    pub(super) no_sse_header: bool,
    #[prost(message, optional, tag = "8")]
    pub(super) sc_max_each_post_bytes: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "9")]
    pub(super) sc_min_posts_interval_ms: Option<XhttpRangePayload>,
    #[prost(int64, tag = "10")]
    pub(super) sc_max_buffered_posts: i64,
    #[prost(message, optional, tag = "11")]
    pub(super) sc_stream_up_server_secs: Option<XhttpRangePayload>,
    #[prost(message, optional, tag = "12")]
    pub(super) xmux: Option<XhttpXmuxPayload>,
    #[prost(message, optional, tag = "13")]
    pub(super) download_settings: Option<StreamConfigPayload>,
    #[prost(bool, tag = "14")]
    pub(super) x_padding_obfs_mode: bool,
    #[prost(string, tag = "15")]
    pub(super) x_padding_key: String,
    #[prost(string, tag = "16")]
    pub(super) x_padding_header: String,
    #[prost(string, tag = "17")]
    pub(super) x_padding_placement: String,
    #[prost(string, tag = "18")]
    pub(super) x_padding_method: String,
    #[prost(string, tag = "19")]
    pub(super) uplink_http_method: String,
    #[prost(string, tag = "20")]
    pub(super) session_id_placement: String,
    #[prost(string, tag = "21")]
    pub(super) session_id_key: String,
    #[prost(string, tag = "22")]
    pub(super) seq_placement: String,
    #[prost(string, tag = "23")]
    pub(super) seq_key: String,
    #[prost(string, tag = "24")]
    pub(super) uplink_data_placement: String,
    #[prost(string, tag = "25")]
    pub(super) uplink_data_key: String,
    #[prost(message, optional, tag = "26")]
    pub(super) uplink_chunk_size: Option<XhttpRangePayload>,
    #[prost(int32, tag = "27")]
    pub(super) server_max_header_bytes: i32,
    #[prost(string, tag = "28")]
    pub(super) session_id_table: String,
    #[prost(message, optional, tag = "29")]
    pub(super) session_id_length: Option<XhttpRangePayload>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessInboundConfigPayload {
    #[prost(message, repeated, tag = "1")]
    pub(super) clients: Vec<proto::xray::common::protocol::User>,
}

#[cfg(feature = "vless")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VlessAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) id: String,
    #[prost(string, tag = "2")]
    pub(super) flow: String,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VmessInboundConfigPayload {
    #[prost(message, repeated, tag = "1")]
    pub(super) users: Vec<proto::xray::common::protocol::User>,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VmessSecurityConfigPayload {
    #[prost(int32, tag = "1")]
    pub(super) r#type: i32,
}

#[cfg(feature = "vmess")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct VmessAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) id: String,
    #[prost(message, optional, tag = "3")]
    pub(super) security_settings: Option<VmessSecurityConfigPayload>,
    #[prost(string, tag = "4")]
    pub(super) tests_enabled: String,
}

#[cfg(feature = "shadowsocks")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct ShadowsocksAccountPayload {
    #[prost(string, tag = "1")]
    pub(super) password: String,
    #[prost(int32, tag = "2")]
    pub(super) cipher_type: i32,
    #[prost(bool, tag = "3")]
    pub(super) iv_check: bool,
}

#[cfg(feature = "shadowsocks")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct Shadowsocks2022AccountPayload {
    #[prost(string, tag = "1")]
    pub(super) key: String,
}

#[cfg(feature = "vless")]
pub(super) fn validate_vless_flow(flow: &str) -> Result<(), Status> {
    match flow {
        "" | "xtls-rprx-vision" => Ok(()),
        unsupported => Err(Status::invalid_argument(format!(
            "vless clients.flow doesn't support {unsupported}"
        ))),
    }
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanServerConfigPayload {
    #[prost(message, repeated, tag = "1")]
    pub(super) users: Vec<proto::xray::common::protocol::User>,
    #[prost(message, repeated, tag = "2")]
    pub(super) fallbacks: Vec<TrojanFallbackPayload>,
}

#[cfg(feature = "trojan")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TrojanFallbackPayload {
    #[prost(string, tag = "5")]
    pub(super) dest: String,
}

#[cfg(feature = "ws")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct WebsocketConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) host: String,
    #[prost(string, tag = "2")]
    pub(super) path: String,
    #[prost(map = "string, string", tag = "3")]
    pub(super) header: std::collections::HashMap<String, String>,
    #[prost(bool, tag = "4")]
    pub(super) accept_proxy_protocol: bool,
    #[prost(uint32, tag = "5")]
    pub(super) ed: u32,
    #[prost(uint32, tag = "6")]
    pub(super) heartbeat_period: u32,
}

#[cfg(feature = "httpupgrade")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct HttpUpgradeConfigPayload {
    #[prost(string, tag = "1")]
    pub(super) host: String,
    #[prost(string, tag = "2")]
    pub(super) path: String,
    #[prost(map = "string, string", tag = "3")]
    pub(super) header: std::collections::HashMap<String, String>,
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

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TlsConfigPayload {
    #[prost(message, repeated, tag = "2")]
    pub(super) certificate: Vec<TlsCertificatePayload>,
    #[prost(string, tag = "3")]
    pub(super) server_name: String,
    #[prost(string, repeated, tag = "4")]
    pub(super) next_protocol: Vec<String>,
    #[prost(bool, tag = "6")]
    pub(super) disable_system_root: bool,
}

#[cfg(feature = "tls")]
#[derive(Clone, PartialEq, Message)]
pub(super) struct TlsCertificatePayload {
    #[prost(bytes = "vec", tag = "1")]
    pub(super) certificate: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) key: Vec<u8>,
    #[prost(string, tag = "5")]
    pub(super) certificate_path: String,
    #[prost(string, tag = "6")]
    pub(super) key_path: String,
}

#[cfg(feature = "reality")]
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
    #[prost(bytes = "vec", tag = "6")]
    pub(super) private_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub(super) min_client_ver: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub(super) max_client_ver: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub(super) max_time_diff: u64,
    #[prost(bytes = "vec", repeated, tag = "10")]
    pub(super) short_ids: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "11")]
    pub(super) mldsa65_seed: Vec<u8>,
    #[prost(string, tag = "21")]
    pub(super) fingerprint: String,
    #[prost(string, tag = "22")]
    pub(super) server_name: String,
    #[prost(bytes = "vec", tag = "23")]
    pub(super) public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "24")]
    pub(super) short_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "25")]
    pub(super) mldsa65_verify: Vec<u8>,
    #[prost(string, tag = "26")]
    pub(super) spider_x: String,
    #[prost(int64, repeated, tag = "27")]
    pub(super) spider_y: Vec<i64>,
    #[prost(string, tag = "31")]
    pub(super) master_key_log: String,
}
