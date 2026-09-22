// Batch C lands the Xray-compatible wire primitive before Batch D adds the
// supervised Reverse Mux runtime that consumes it.
#![allow(dead_code)]

use prost::Message;

const MAX_CONTROL_PAYLOAD_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum ControlState {
    Active = 0,
    Drain = 1,
}

#[derive(Clone, PartialEq, Message)]
struct ControlPayload {
    #[prost(enumeration = "ControlState", tag = "1")]
    state: i32,
    #[prost(bytes = "vec", tag = "99")]
    random: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReverseControl {
    pub(crate) state: ControlState,
    pub(crate) random: Vec<u8>,
}

impl ReverseControl {
    pub(crate) fn active(random: Vec<u8>) -> Self {
        Self {
            state: ControlState::Active,
            random,
        }
    }

    pub(crate) fn drain(random: Vec<u8>) -> Self {
        Self {
            state: ControlState::Drain,
            random,
        }
    }

    pub(crate) fn encode(&self) -> std::io::Result<Vec<u8>> {
        if self.random.len() > 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "VLESS Reverse control random padding exceeds 64 bytes: {}",
                    self.random.len()
                ),
            ));
        }

        Ok(ControlPayload {
            state: self.state as i32,
            random: self.random.clone(),
        }
        .encode_to_vec())
    }

    pub(crate) fn decode(input: &[u8]) -> std::io::Result<Self> {
        if input.len() > MAX_CONTROL_PAYLOAD_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "VLESS Reverse control payload exceeds {MAX_CONTROL_PAYLOAD_LEN} bytes: {}",
                    input.len()
                ),
            ));
        }

        let payload = ControlPayload::decode(input).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid VLESS Reverse control protobuf: {error}"),
            )
        })?;
        let state = ControlState::try_from(payload.state).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown VLESS Reverse control state: {}", payload.state),
            )
        })?;

        Ok(Self {
            state,
            random: payload.random,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_control_matches_xray_proto_wire() {
        let control = ReverseControl::active(vec![0xaa, 0xbb]);
        let encoded = control.encode().expect("encode ACTIVE control");
        assert_eq!(encoded, vec![0x9a, 0x06, 0x02, 0xaa, 0xbb]);

        let decoded =
            ReverseControl::decode(&encoded).expect("decode ACTIVE control");
        assert_eq!(decoded, control);
    }

    #[test]
    fn drain_control_matches_xray_proto_wire() {
        let control = ReverseControl::drain(vec![0x11]);
        let encoded = control.encode().expect("encode DRAIN control");
        assert_eq!(encoded, vec![0x08, 0x01, 0x9a, 0x06, 0x01, 0x11]);

        let decoded =
            ReverseControl::decode(&encoded).expect("decode DRAIN control");
        assert_eq!(decoded, control);
    }

    #[test]
    fn empty_active_control_is_valid_xray_default_state() {
        let decoded =
            ReverseControl::decode(&[]).expect("decode default ACTIVE control");
        assert_eq!(decoded, ReverseControl::active(Vec::new()));
        assert_eq!(
            decoded.encode().expect("encode default ACTIVE control"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn unknown_control_state_fails_closed() {
        let error = ReverseControl::decode(&[0x08, 0x02])
            .expect_err("unknown control state must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("unknown VLESS Reverse control state")
        );
    }

    #[test]
    fn malformed_and_oversized_control_payloads_fail_closed() {
        let malformed = ReverseControl::decode(&[0x9a, 0x06, 0x02, 0xaa])
            .expect_err("truncated control protobuf must fail");
        assert_eq!(malformed.kind(), std::io::ErrorKind::InvalidData);

        let oversized = ReverseControl::decode(&[0u8; MAX_CONTROL_PAYLOAD_LEN + 1])
            .expect_err("oversized control payload must fail");
        assert_eq!(oversized.kind(), std::io::ErrorKind::InvalidData);

        let padding = ReverseControl::active(vec![0u8; 65])
            .encode()
            .expect_err("Xray-generated random padding is bounded to 64 bytes");
        assert_eq!(padding.kind(), std::io::ErrorKind::InvalidInput);
    }
}
