use std::collections::HashMap;

use serde::Deserialize;

use super::ServerProxyConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct WebsocketServerConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    pub protocol: ServerProxyConfig,
}
