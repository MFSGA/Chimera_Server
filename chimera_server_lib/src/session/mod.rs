pub(crate) mod dispatcher;
pub(crate) mod policy_stream;
#[cfg(all(feature = "xray-tun", target_os = "linux"))]
#[cfg(any(feature = "xray-tun", test))]
pub(crate) mod quic_sniff;
pub(crate) mod sniff;
pub(crate) mod tcp_relay;
pub(crate) mod udp;
pub(crate) mod xhttp;

#[cfg(all(test, feature = "vless-reverse"))]
mod dispatcher_tests;
