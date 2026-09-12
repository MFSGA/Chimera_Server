use std::{fmt::Debug, time::Duration};

use async_trait::async_trait;

use crate::{
    address::NetLocation,
    async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream},
    runtime::{DataPlaneRuntime, InboundHandshakeRuntime},
    traffic::TrafficContext,
};

#[derive(Debug, Clone, Default)]
pub struct TcpServerConnectionContext {
    pub original_destination: Option<NetLocation>,
    pub peer_addr: Option<std::net::SocketAddr>,
    pub local_addr: Option<std::net::SocketAddr>,
    pub listener_addr: Option<std::net::SocketAddr>,
    pub server_name: Option<String>,
    pub alpn_protocol: Option<String>,
    /// Narrow capability used by built-in protocol handlers for handshake
    /// policy and dynamic inbound identity snapshots.
    pub handshake_runtime: Option<InboundHandshakeRuntime>,
    /// Legacy compatibility capability for callers that still populate the
    /// pre-Phase-B context shape. Internal listener/session paths leave this
    /// unset and project `DataPlaneRuntime` into `handshake_runtime` instead.
    pub runtime: Option<DataPlaneRuntime>,
}

impl TcpServerConnectionContext {
    pub fn inbound_handshake_runtime(&self) -> Option<InboundHandshakeRuntime> {
        self.handshake_runtime.clone().or_else(|| {
            self.runtime
                .as_ref()
                .map(DataPlaneRuntime::inbound_handshake_runtime)
        })
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    fn requires_original_destination(&self) -> bool {
        false
    }

    fn manages_handshake_timeout(&self) -> bool {
        false
    }

    fn pre_transport_handshake_timeout(
        &self,
        _context: &TcpServerConnectionContext,
    ) -> Option<Duration> {
        None
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        _context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream(server_stream).await
    }
}

pub enum TcpServerSetupResult {
    /// Transport wrappers may override the effective peer address while
    /// preserving the inner protocol/session outcome. This compatibility
    /// wrapper is normalized before the session dispatcher sees the result.
    PeerAddrOverride {
        peer_addr: std::net::SocketAddr,
        inner: Box<TcpServerSetupResult>,
    },
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,

        connection_success_response: Option<Box<[u8]>>,
        traffic_context: Option<TrafficContext>,
    },
    HttpPlainForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        request_head: Box<[u8]>,
        request_method: String,
        keep_alive: bool,
        next_handler: Box<dyn TcpServerHandler>,
        traffic_context: Option<TrafficContext>,
    },
    TcpFallback {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        proxy_protocol_version: u8,
        traffic_context: Option<TrafficContext>,
    },
    UdpAssociate {
        stream: Box<dyn AsyncStream>,
        udp_socket: std::sync::Arc<tokio::net::UdpSocket>,
        expected_client: std::net::SocketAddr,
        user_level: u32,
        traffic_context: Option<TrafficContext>,
    },
    BidirectionalUdp {
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    MultiDirectionalUdp {
        stream: Box<dyn AsyncTargetedMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    SessionBasedUdp {
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    /// The handler has taken full ownership of the stream and all work is
    /// already handled (via a spawned task). `process_stream` should
    /// return `Ok(())` immediately.
    AlreadyHandled,
}

/// Handler result after transport-only compatibility wrappers have been
/// removed. Session dispatch should match this type rather than depending on
/// wrapper-specific metadata such as a forwarded peer-address override.
pub(crate) enum TcpServerSetupOutcome {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        connection_success_response: Option<Box<[u8]>>,
        traffic_context: Option<TrafficContext>,
    },
    HttpPlainForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        request_head: Box<[u8]>,
        request_method: String,
        keep_alive: bool,
        next_handler: Box<dyn TcpServerHandler>,
        traffic_context: Option<TrafficContext>,
    },
    TcpFallback {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        proxy_protocol_version: u8,
        traffic_context: Option<TrafficContext>,
    },
    UdpAssociate {
        stream: Box<dyn AsyncStream>,
        udp_socket: std::sync::Arc<tokio::net::UdpSocket>,
        expected_client: std::net::SocketAddr,
        user_level: u32,
        traffic_context: Option<TrafficContext>,
    },
    BidirectionalUdp {
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    MultiDirectionalUdp {
        stream: Box<dyn AsyncTargetedMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    SessionBasedUdp {
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    AlreadyHandled,
}

pub(crate) struct NormalizedTcpServerSetup {
    pub peer_addr_override: Option<std::net::SocketAddr>,
    pub outcome: TcpServerSetupOutcome,
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        if let TcpServerSetupResult::TcpForward {
            need_initial_flush: flush,
            ..
        } = self
        {
            *flush = need_initial_flush;
        }
    }

    pub(crate) fn into_normalized(self) -> NormalizedTcpServerSetup {
        let mut peer_addr_override = None;
        let mut result = self;
        loop {
            match result {
                TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } => {
                    // Nested wrappers are applied from outer to inner, so the
                    // innermost transport is the effective peer source.
                    peer_addr_override = Some(peer_addr);
                    result = *inner;
                }
                TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream,
                    need_initial_flush,
                    connection_success_response,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::TcpForward {
                            remote_location,
                            stream,
                            need_initial_flush,
                            connection_success_response,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::HttpPlainForward {
                    remote_location,
                    stream,
                    request_head,
                    request_method,
                    keep_alive,
                    next_handler,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::HttpPlainForward {
                            remote_location,
                            stream,
                            request_head,
                            request_method,
                            keep_alive,
                            next_handler,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::TcpFallback {
                    remote_location,
                    stream,
                    proxy_protocol_version,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::TcpFallback {
                            remote_location,
                            stream,
                            proxy_protocol_version,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::UdpAssociate {
                    stream,
                    udp_socket,
                    expected_client,
                    user_level,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::UdpAssociate {
                            stream,
                            udp_socket,
                            expected_client,
                            user_level,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::BidirectionalUdp {
                            remote_location,
                            stream,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::MultiDirectionalUdp {
                    stream,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::MultiDirectionalUdp {
                            stream,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::SessionBasedUdp {
                    stream,
                    traffic_context,
                } => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::SessionBasedUdp {
                            stream,
                            traffic_context,
                        },
                    };
                }
                TcpServerSetupResult::AlreadyHandled => {
                    return NormalizedTcpServerSetup {
                        peer_addr_override,
                        outcome: TcpServerSetupOutcome::AlreadyHandled,
                    };
                }
            }
        }
    }
}
