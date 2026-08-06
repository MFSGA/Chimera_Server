pub mod dokodemo;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "httpupgrade")]
pub mod httpupgrade;
#[cfg(feature = "mixed")]
pub mod mixed;
pub mod proxy_protocol;
pub mod tcp;
pub mod tcp_congestion;
pub mod tcp_keepalive;
pub mod tcp_user_timeout;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(any(feature = "reality", feature = "vless"))]
pub mod tls_deframer;
#[cfg(feature = "vless")]
pub mod vless_handler;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "hysteria")]
pub mod hysteria2;

#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "trojan")]
pub(crate) mod trojan_udp;

pub mod socks;

#[cfg(feature = "reality")]
pub mod reality;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "vmess")]
pub mod vmess;

#[cfg(any(feature = "vless", feature = "vmess"))]
pub(crate) mod xudp;
