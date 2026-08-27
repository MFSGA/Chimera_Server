use std::collections::HashMap;

use serde::Deserialize;

use super::ServerProxyConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct WebsocketServerConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub xray_mismatch_404: bool,
    #[serde(default)]
    pub trusted_x_forwarded_for: Vec<String>,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub heartbeat_period: u32,
    pub protocol: ServerProxyConfig,
}
