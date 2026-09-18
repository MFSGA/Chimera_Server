use crate::config::def::LiteralConfig;

#[allow(dead_code)] // Reserved internal-config conversion boundary for future adapters.
pub struct InternalConfig {}

impl TryFrom<LiteralConfig> for InternalConfig {
    type Error = crate::Error;

    fn try_from(_c: LiteralConfig) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}
