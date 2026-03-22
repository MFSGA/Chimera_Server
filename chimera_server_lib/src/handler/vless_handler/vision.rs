use async_trait::async_trait;
use tracing::warn;

use crate::{
    async_stream::AsyncStream,
    config::server_config::VlessUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    reality::{RealityServerConnection, RealityTlsStream},
    traffic::TrafficContext,
};

use super::protocol::{
    COMMAND_TCP, ParsedVlessHeader, XTLS_VISION_FLOW, read_request_header,
};
use super::reality_vision_stream::RealityVisionServerStream;
use super::vision_stream::VisionServerStream;
use super::{encode_hex, parse_hex};

pub(crate) type ParsedVisionUser = (Box<[u8]>, String);

#[derive(Debug)]
pub struct VisionVlessTcpHandler {
    users: Vec<ParsedVisionUser>,
    inbound_tag: String,
}

impl VisionVlessTcpHandler {
    pub fn new(users: &[VlessUser], inbound_tag: &str) -> Self {
        Self {
            users: parse_vision_users(users),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

pub async fn setup_reality_vision_server_stream(
    mut tls_stream: RealityTlsStream<Box<dyn AsyncStream>, RealityServerConnection>,
    users: &[ParsedVisionUser],
    inbound_tag: &str,
) -> std::io::Result<TcpServerSetupResult> {
    let ParsedVlessHeader {
        user_id,
        flow: request_flow,
        command,
        remote_location,
    } = read_request_header(&mut tls_stream).await?;

    let user_label = find_matching_user_label(users, &user_id, inbound_tag)?;
    validate_vision_request_flow(&request_flow, command)?;

    let (tcp, mut session) = tls_stream.into_inner();
    let initial_plaintext = RealityVisionServerStream::<
        Box<dyn AsyncStream>,
        RealityServerConnection,
    >::drain_plaintext_from_session(&mut session)?;

    Ok(TcpServerSetupResult::TcpForward {
        remote_location,
        stream: Box::new(RealityVisionServerStream::new(
            tcp,
            session,
            user_id,
            &initial_plaintext,
        )?),
        need_initial_flush: false,
        connection_success_response: None,
        traffic_context: Some(
            TrafficContext::new("vless")
                .with_identity(user_label)
                .with_inbound_tag(inbound_tag.to_string()),
        ),
    })
}

#[async_trait]
impl TcpServerHandler for VisionVlessTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedVlessHeader {
            user_id,
            flow: request_flow,
            command,
            remote_location,
        } = read_request_header(&mut server_stream).await?;

        let user_label =
            find_matching_user_label(&self.users, &user_id, &self.inbound_tag)?;

        validate_vision_request_flow(&request_flow, command)?;

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(VisionServerStream::new(server_stream, user_id)),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context: Some(
                TrafficContext::new("vless")
                    .with_identity(user_label)
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        })
    }
}

pub(crate) fn parse_vision_users(users: &[VlessUser]) -> Vec<ParsedVisionUser> {
    users
        .iter()
        .map(|user| (parse_hex(&user.user_id), user.user_label.clone()))
        .collect()
}

fn find_matching_user_label(
    users: &[ParsedVisionUser],
    user_id: &[u8; 16],
    inbound_tag: &str,
) -> std::io::Result<String> {
    let matched_user = users.iter().find(|(stored_user_id, _)| {
        stored_user_id.len() == 16 && stored_user_id.as_ref() == user_id.as_slice()
    });

    let Some((_, user_label)) = matched_user else {
        let expected = users
            .iter()
            .map(|(user_id, _)| encode_hex(user_id.as_ref()))
            .collect::<Vec<_>>()
            .join(",");
        let got = encode_hex(user_id);
        warn!(
            inbound_tag = %inbound_tag,
            expected = %expected,
            got = %got,
            "Vision VLESS inbound rejected request with mismatched user id"
        );

        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("invalid VLESS user id: {got}"),
        ));
    };

    Ok(user_label.clone())
}

fn validate_vision_request_flow(
    request_flow: &str,
    command: u8,
) -> std::io::Result<()> {
    if request_flow != XTLS_VISION_FLOW {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("vision inbound requires flow {XTLS_VISION_FLOW}"),
        ));
    }

    if command != COMMAND_TCP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xtls-rprx-vision currently supports only TCP requests",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_vision_request_flow;
    use crate::handler::vless_handler::protocol::XTLS_VISION_FLOW;

    #[test]
    fn validate_vision_request_flow_requires_vision_marker() {
        let err = validate_vision_request_flow("", 1)
            .expect_err("vision handler should require vision flow");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_vision_request_flow_rejects_non_tcp() {
        let err = validate_vision_request_flow(XTLS_VISION_FLOW, 2)
            .expect_err("vision handler should reject udp");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn validate_vision_request_flow_accepts_tcp() {
        validate_vision_request_flow(XTLS_VISION_FLOW, 1)
            .expect("vision handler should accept tcp header shape");
    }
}
