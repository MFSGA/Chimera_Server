#![cfg(feature = "reality")]

mod buf_reader;
mod client;
mod common;
mod reality_aead;
mod reality_auth;
mod reality_certificate;
mod reality_client_verify;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_server_connection;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
mod slide_buffer;
mod stream;
mod sync_adapter;

use serde::Deserialize;

pub use buf_reader::BufReader;
pub use client::{feed_reality_client_connection, RealityClientConfig, RealityClientConnection};
pub use reality_reader_writer::{RealityReader, RealityWriter};
pub use reality_server_connection::{
    feed_reality_server_connection, RealityServerConfig, RealityServerConnection,
};
pub use reality_util::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};
pub use stream::RealityTlsStream;

/// mihomo (Clash.Meta) reality-opts helper for building a client config.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MihomoRealityOpts {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "short-id", default)]
    pub short_id: Option<String>,
    /// Optional override for SNI; fall back to proxy server host when missing.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Placeholder accepted for compatibility; not used by the handshake.
    #[serde(rename = "spider-x", default)]
    pub spider_x: Option<String>,
}

impl MihomoRealityOpts {
    /// Build a Reality client config using a fallback SNI if the mihomo entry omitted it.
    pub fn to_client_config(
        &self,
        default_server_name: &str,
    ) -> Result<RealityClientConfig, crate::Error> {
        let public_key = decode_public_key(&self.public_key)
            .map_err(|e| crate::Error::InvalidConfig(format!("invalid reality public key: {e}")))?;
        let short_id = decode_short_id(self.short_id.as_deref().unwrap_or(""))
            .map_err(|e| crate::Error::InvalidConfig(format!("invalid reality short_id: {e}")))?;
        let server_name = self
            .server_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default_server_name.to_string());

        Ok(RealityClientConfig {
            public_key,
            short_id,
            server_name,
        })
    }
}
