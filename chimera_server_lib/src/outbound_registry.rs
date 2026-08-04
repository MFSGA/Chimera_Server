use std::{collections::HashMap, sync::Arc};

use crate::runtime::OutboundSummary;

/// Compiled outbound behavior installed in the runtime registry.
///
/// Unsupported entries are retained only by the lenient constructor used by
/// tests and compatibility helpers. Production installation paths use strict
/// compilation and reject them before the runtime becomes active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutboundConnectorKind {
    Freedom,
    Blackhole,
    Unsupported { protocol: Arc<str> },
}

impl OutboundConnectorKind {
    fn compile(summary: &OutboundSummary, strict: bool) -> Result<Self, String> {
        let protocol = summary.protocol.trim().to_ascii_lowercase();
        match protocol.as_str() {
            "freedom" => Ok(Self::Freedom),
            "blackhole" => Ok(Self::Blackhole),
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
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[test]
    fn strict_registry_accepts_only_currently_executable_protocols() {
        OutboundRegistry::validate_strict(&[
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ])
        .expect("supported outbounds should validate");

        let error = OutboundRegistry::validate_strict(&[outbound("proxy", "vless")])
            .expect_err("unsupported outbound must fail before installation");
        assert!(error.contains("unsupported protocol vless"));
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
