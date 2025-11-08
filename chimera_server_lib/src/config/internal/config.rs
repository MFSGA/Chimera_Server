use crate::config::def::LiteralConfig;


pub struct InternalConfig {}

impl TryFrom<LiteralConfig> for InternalConfig {
    type Error = crate::Error;

    fn try_from(c: LiteralConfig) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}
