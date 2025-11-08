use serde::Deserialize;

use crate::util::option::NoneOrSome;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerQuicConfig {
    pub cert: String,
    pub key: String,

    pub alpn_protocols: NoneOrSome<String>,

    pub client_fingerprints: NoneOrSome<String>,
}
