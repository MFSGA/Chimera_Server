#[cfg(feature = "grpc_transport")]
pub(crate) mod grpc;
mod listener_plan;
pub(crate) mod tcp;
pub(crate) mod xhttp;

/// Wait for the next QUIC connection attempt and surface endpoint-driver loss as
/// a listener failure. Quinn reports UDP socket I/O failure by terminating its
/// internal endpoint driver; a naturally completed accept is unexpected for
/// these server-owned endpoints and must reach generation-aware health.
#[allow(dead_code)] // Used by QUIC-based transports when their features are enabled.
pub(crate) async fn accept_quic_with_health(
    endpoint: &quinn::Endpoint,
    listener_kind: &'static str,
) -> std::io::Result<quinn::Incoming> {
    match endpoint.accept().await {
        Some(incoming) => Ok(incoming),
        None => {
            let error = std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("{listener_kind} QUIC endpoint stopped accepting"),
            );
            tracing::error!(
                listener_kind,
                %error,
                "QUIC endpoint stopped unexpectedly; stopping listener task"
            );
            Err(error)
        }
    }
}

#[cfg(feature = "grpc_transport")]
pub(crate) use listener_plan::GrpcListenerPlan;
pub(crate) use listener_plan::{
    InboundListenerPlan, ListenerSecurityPlan, XhttpListenerPlan,
    compile_listener_plan,
};
