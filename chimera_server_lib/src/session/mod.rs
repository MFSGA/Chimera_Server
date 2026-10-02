pub(crate) mod dispatcher;
pub(crate) mod policy_stream;
pub(crate) mod sniff;
pub(crate) mod tcp_relay;
pub(crate) mod udp;
pub(crate) mod xhttp;

#[cfg(all(test, feature = "vless-reverse"))]
mod dispatcher_tests;
