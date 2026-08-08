mod builder;
#[cfg(feature = "api")]
pub(crate) use builder::collect_xhttp_settings_from_json;
pub mod quic;
mod types;
#[cfg(feature = "ws")]
pub mod ws;

pub use types::DokodemoDoorConfig;
#[cfg(feature = "http")]
pub use types::HttpUser;
#[cfg(feature = "tuic")]
pub use types::TuicServerConfig;
#[cfg(feature = "vless")]
pub use types::{VlessFallback, VlessUser};

#[cfg(feature = "grpc_transport")]
pub use types::GrpcServerConfig;
#[cfg(feature = "hysteria")]
#[allow(unused_imports)]
pub use types::{
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2MasqueradeConfig,
    Hysteria2QuicParams, Hysteria2ServerConfig,
};
pub use types::{
    ServerConfig, ServerProxyConfig, SocksUser, SocksUserStore, XhttpDataPlacement,
    XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement,
    XhttpServerConfig,
};

#[cfg(feature = "reality")]
pub use types::RealityTransportConfig;
#[cfg(feature = "shadowsocks")]
pub use types::{ShadowsocksServerIdentity, ShadowsocksUser};
#[cfg(feature = "tls")]
pub use types::{TlsCertificateConfig, TlsCertificateUsage, TlsServerConfig};

#[cfg(feature = "trojan")]
pub use types::{TrojanFallback, TrojanUser};

#[cfg(feature = "vmess")]
pub use types::VmessUser;
