use serde::Deserialize;

#[cfg(any(feature = "ws", feature = "api"))]
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrSome<T> {
    One(T),
    #[serde(deserialize_with = "validate_non_empty")]
    Some(Vec<T>),
}

#[cfg(any(feature = "ws", feature = "api"))]
fn validate_non_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = Vec::deserialize(d)?;
    if value.is_empty() {
        return Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("empty"),
            &"need at least one element",
        ));
    }
    Ok(value)
}

#[cfg(any(feature = "ws", feature = "api"))]
impl<T> OneOrSome<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrSome::One(item) => vec![item],
            OneOrSome::Some(v) => v,
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NoneOrSome<T> {
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
    None,
    One(T),
    Some(Vec<T>),
}

impl<T> NoneOrSome<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, NoneOrSome::Unspecified)
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => vec![],
            NoneOrSome::One(item) => vec![item],
            NoneOrSome::Some(v) => v,
        }
    }
}
