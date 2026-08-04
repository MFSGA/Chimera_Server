use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "vless")]
use serde::Deserialize;

#[cfg(feature = "vless")]
use crate::address::{Address, NetLocation};
use crate::runtime::OutboundSummary;

#[cfg(feature = "vless")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VlessTcpOutboundConfig {
    pub server: NetLocation,
    pub user_uuid: [u8; 16],
}

#[cfg(feature = "vless")]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiteralVlessOutboundSettings {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    vnext: Vec<LiteralVlessServer>,
}

#[cfg(feature = "vless")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiteralVlessServer {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<LiteralVlessUser>,
}

#[cfg(feature = "vless")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiteralVlessUser {
    id: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    encryption: String,
}

/// Compiled outbound behavior installed in the runtime registry.
///
/// Unsupported entries are retained only by the lenient constructor used by
/// tests and compatibility helpers. Production installation paths use strict
/// compilation and reject them before the runtime becomes active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutboundConnectorKind {
    Freedom,
    Blackhole,
    #[cfg(feature = "vless")]
    VlessTcp(VlessTcpOutboundConfig),
    Unsupported {
        protocol: Arc<str>,
    },
}

#[cfg(feature = "vless")]
fn compile_vless_tcp(
    summary: &OutboundSummary,
) -> Result<VlessTcpOutboundConfig, String> {
    let settings = summary.settings.as_ref().ok_or_else(|| {
        format!("VLESS outbound {} requires settings", summary.tag)
    })?;
    let settings =
        serde_json::from_value::<LiteralVlessOutboundSettings>(settings.clone())
            .map_err(|error| {
                format!("invalid VLESS outbound {} settings: {error}", summary.tag)
            })?;

    let (address, port, user) = if let Some(address) = settings.address {
        if !settings.vnext.is_empty() {
            return Err(format!(
                "VLESS outbound {} cannot combine address with vnext",
                summary.tag
            ));
        }
        let port = settings.port.ok_or_else(|| {
            format!("VLESS outbound {} requires port", summary.tag)
        })?;
        let id = settings
            .id
            .ok_or_else(|| format!("VLESS outbound {} requires id", summary.tag))?;
        (
            address,
            port,
            LiteralVlessUser {
                id,
                flow: settings.flow.unwrap_or_default(),
                encryption: settings.encryption.unwrap_or_default(),
            },
        )
    } else {
        if settings.vnext.len() != 1 {
            return Err(format!(
                "VLESS outbound {} requires exactly one vnext endpoint",
                summary.tag
            ));
        }
        let mut vnext = settings.vnext;
        let server = vnext.pop().ok_or_else(|| {
            format!("VLESS outbound {} endpoint disappeared", summary.tag)
        })?;
        if server.users.len() != 1 {
            return Err(format!(
                "VLESS outbound {} requires exactly one user",
                summary.tag
            ));
        }
        let mut users = server.users;
        let user = users.pop().ok_or_else(|| {
            format!("VLESS outbound {} user disappeared", summary.tag)
        })?;
        (server.address, server.port, user)
    };

    if address.trim().is_empty() {
        return Err(format!(
            "VLESS outbound {} server address must not be empty",
            summary.tag
        ));
    }
    if port == 0 {
        return Err(format!(
            "VLESS outbound {} server port must not be zero",
            summary.tag
        ));
    }
    if !user.flow.trim().is_empty() {
        return Err(format!(
            "VLESS outbound {} plain TCP slice does not support flow {}",
            summary.tag, user.flow
        ));
    }
    let encryption = user.encryption.trim().to_ascii_lowercase();
    if !encryption.is_empty() && encryption != "none" {
        return Err(format!(
            "VLESS outbound {} plain TCP slice requires encryption none",
            summary.tag
        ));
    }

    let network = summary
        .stream_settings
        .as_ref()
        .map(|stream| stream.network.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !network.is_empty() && network != "tcp" {
        return Err(format!(
            "VLESS outbound {} plain slice requires TCP network, got {}",
            summary.tag, network
        ));
    }
    let security = summary
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !security.is_empty() && security != "none" {
        return Err(format!(
            "VLESS outbound {} plain slice requires security none, got {}",
            summary.tag, security
        ));
    }

    let server_address = Address::from(address.trim()).map_err(|error| {
        format!(
            "invalid VLESS outbound {} server address: {error}",
            summary.tag
        )
    })?;
    let user_uuid = uuid::Uuid::parse_str(user.id.trim())
        .map_err(|error| {
            format!("invalid VLESS outbound {} user id: {error}", summary.tag)
        })?
        .into_bytes();

    Ok(VlessTcpOutboundConfig {
        server: NetLocation::new(server_address, port),
        user_uuid,
    })
}

impl OutboundConnectorKind {
    fn compile(summary: &OutboundSummary, strict: bool) -> Result<Self, String> {
        let protocol = summary.protocol.trim().to_ascii_lowercase();
        match protocol.as_str() {
            "freedom" => Ok(Self::Freedom),
            "blackhole" => Ok(Self::Blackhole),
            #[cfg(feature = "vless")]
            "vless" => compile_vless_tcp(summary).map(Self::VlessTcp),
            "" => Err(format!(
                "outbound {} protocol must not be empty",
                summary.tag
            )),
            _ if strict => Err(format!(
                "outbound {} uses unsupported protocol {}",
                summary.tag, protocol
            )),
            _ => Ok(Self::Unsupported {
                protocol: Arc::from(protocol),
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct OutboundRegistry {
    entries: HashMap<String, Arc<OutboundConnectorKind>>,
}

impl OutboundRegistry {
    pub(crate) fn from_outbounds_lenient(outbounds: &[OutboundSummary]) -> Self {
        let mut entries = HashMap::with_capacity(outbounds.len());
        for outbound in outbounds {
            if outbound.tag.trim().is_empty() {
                continue;
            }
            let connector = OutboundConnectorKind::compile(outbound, false)
                .unwrap_or_else(|_| OutboundConnectorKind::Unsupported {
                    protocol: Arc::from(
                        outbound.protocol.trim().to_ascii_lowercase(),
                    ),
                });
            entries
                .entry(outbound.tag.clone())
                .or_insert_with(|| Arc::new(connector));
        }
        Self { entries }
    }

    pub(crate) fn validate_strict(
        outbounds: &[OutboundSummary],
    ) -> Result<(), String> {
        let mut tags = HashMap::<&str, usize>::with_capacity(outbounds.len());
        for (index, outbound) in outbounds.iter().enumerate() {
            let tag = outbound.tag.trim();
            if tag.is_empty() {
                return Err("outbound tag must not be empty".into());
            }
            if let Some(first_index) = tags.insert(tag, index) {
                return Err(format!(
                    "duplicate outbound tag {} at indexes {} and {}",
                    tag, first_index, index
                ));
            }
            OutboundConnectorKind::compile(outbound, true)?;
        }
        Ok(())
    }

    pub(crate) fn insert_strict(
        &mut self,
        outbound: &OutboundSummary,
    ) -> Result<(), String> {
        let tag = outbound.tag.trim();
        if tag.is_empty() {
            return Err("outbound tag must not be empty".into());
        }
        if self.entries.contains_key(tag) {
            return Err(format!("outbound {tag} already exists"));
        }
        let connector = OutboundConnectorKind::compile(outbound, true)?;
        self.entries.insert(tag.to_string(), Arc::new(connector));
        Ok(())
    }

    pub(crate) fn remove(
        &mut self,
        tag: &str,
    ) -> Option<Arc<OutboundConnectorKind>> {
        self.entries.remove(tag)
    }

    pub(crate) fn get(&self, tag: &str) -> Option<Arc<OutboundConnectorKind>> {
        self.entries.get(tag).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            settings: None,
            stream_settings: None,
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "vless")]
    fn literal_vless(settings: serde_json::Value) -> OutboundSummary {
        OutboundSummary {
            tag: "proxy".into(),
            protocol: "vless".into(),
            settings: Some(settings),
            stream_settings: Some(crate::config::def::OutboundStreamSettings {
                network: "tcp".into(),
                security: Some("none".into()),
            }),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn compiles_standard_and_simplified_vless_plain_tcp_settings() {
        let id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let standard = literal_vless(serde_json::json!({
            "vnext": [{
                "address": "127.0.0.1",
                "port": 443,
                "users": [{ "id": id, "encryption": "none" }]
            }]
        }));
        let simplified = literal_vless(serde_json::json!({
            "address": "127.0.0.1",
            "port": 443,
            "id": id,
            "encryption": "none"
        }));
        let expected = VlessTcpOutboundConfig {
            server: NetLocation::new(
                Address::Ipv4("127.0.0.1".parse().unwrap()),
                443,
            ),
            user_uuid: uuid::Uuid::parse_str(id).unwrap().into_bytes(),
        };
        assert_eq!(
            OutboundConnectorKind::compile(&standard, true).unwrap(),
            OutboundConnectorKind::VlessTcp(expected.clone())
        );
        assert_eq!(
            OutboundConnectorKind::compile(&simplified, true).unwrap(),
            OutboundConnectorKind::VlessTcp(expected)
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn rejects_vless_features_outside_the_plain_tcp_slice() {
        let id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let cases = [
            (
                serde_json::json!({
                    "address": "127.0.0.1",
                    "port": 443,
                    "id": id,
                    "flow": "xtls-rprx-vision"
                }),
                "does not support flow",
            ),
            (
                serde_json::json!({
                    "address": "127.0.0.1",
                    "port": 443,
                    "id": id,
                    "encryption": "mlkem"
                }),
                "requires encryption none",
            ),
        ];
        for (settings, expected) in cases {
            let error =
                OutboundConnectorKind::compile(&literal_vless(settings), true)
                    .expect_err("unsupported VLESS setting must fail closed");
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        let mut websocket = literal_vless(serde_json::json!({
            "address": "127.0.0.1",
            "port": 443,
            "id": id
        }));
        websocket.stream_settings.as_mut().unwrap().network = "ws".into();
        assert!(
            OutboundConnectorKind::compile(&websocket, true)
                .unwrap_err()
                .contains("requires TCP network")
        );

        let mut tls = literal_vless(serde_json::json!({
            "address": "127.0.0.1",
            "port": 443,
            "id": id
        }));
        tls.stream_settings.as_mut().unwrap().security = Some("tls".into());
        assert!(
            OutboundConnectorKind::compile(&tls, true)
                .unwrap_err()
                .contains("requires security none")
        );
    }

    #[test]
    fn strict_registry_accepts_only_currently_executable_protocols() {
        OutboundRegistry::validate_strict(&[
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ])
        .expect("supported outbounds should validate");

        let error = OutboundRegistry::validate_strict(&[outbound("proxy", "vmess")])
            .expect_err("unsupported outbound must fail before installation");
        assert!(error.contains("unsupported protocol vmess"));
    }

    #[test]
    fn strict_registry_rejects_duplicate_and_empty_tags() {
        assert!(
            OutboundRegistry::validate_strict(&[outbound("", "freedom")])
                .unwrap_err()
                .contains("tag must not be empty")
        );
        assert!(
            OutboundRegistry::validate_strict(&[
                outbound("direct", "freedom"),
                outbound("direct", "blackhole"),
            ])
            .unwrap_err()
            .contains("duplicate outbound tag direct")
        );
    }

    #[test]
    fn removed_connector_remains_valid_for_an_in_flight_session() {
        let mut registry = OutboundRegistry::default();
        registry
            .insert_strict(&outbound("direct", "freedom"))
            .expect("freedom connector should install");
        let in_flight = registry
            .get("direct")
            .expect("active session should acquire connector");

        registry.remove("direct");
        assert!(registry.get("direct").is_none());
        assert_eq!(in_flight.as_ref(), &OutboundConnectorKind::Freedom);
    }

    #[test]
    fn lenient_registry_retains_unsupported_protocol_for_diagnostics() {
        let registry =
            OutboundRegistry::from_outbounds_lenient(&[outbound("proxy", "vmess")]);
        assert_eq!(
            registry.get("proxy").as_deref(),
            Some(&OutboundConnectorKind::Unsupported {
                protocol: Arc::from("vmess")
            })
        );
    }
}
