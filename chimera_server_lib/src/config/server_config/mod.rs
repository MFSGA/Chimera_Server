mod builder;
pub mod quic;
mod types;
#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "tuic")]
pub use types::TuicServerConfig;
#[cfg(feature = "hysteria")]
#[allow(unused_imports)]
pub use types::{Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig};
pub use types::{ServerConfig, ServerProxyConfig, SocksUser};
#[cfg(feature = "xhttp")]
#[allow(unused_imports)]
pub use types::{XhttpMode, XhttpServerConfig};

#[cfg(feature = "reality")]
pub use types::RealityTransportConfig;
#[cfg(feature = "tls")]
pub use types::TlsServerConfig;

#[cfg(feature = "trojan")]
pub use types::{TrojanFallback, TrojanUser};
