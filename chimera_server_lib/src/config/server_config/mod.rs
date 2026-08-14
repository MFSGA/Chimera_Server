mod builder;
pub mod quic;
mod types;
#[cfg(feature = "ws")]
pub mod ws;

pub use types::DokodemoDoorConfig;
#[cfg(feature = "http")]
pub use types::HttpUser;
#[cfg(feature = "tuic")]
pub use types::TuicServerConfig;
#[cfg(feature = "vless")]
pub use types::{VlessFallback, VlessUser};

#[cfg(feature = "grpc_transport")]
pub use types::GrpcServerConfig;
#[cfg(feature = "hysteria")]
#[allow(unused_imports)]
pub use types::{Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig};
#[allow(unused_imports)]
pub use types::{
    ServerConfig, ServerProxyConfig, SocksUser, SocksUserStore, XhttpDataPlacement,
    XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement,
    XhttpServerConfig,
};

#[cfg(feature = "reality")]
pub use types::RealityTransportConfig;
#[cfg(feature = "shadowsocks")]
pub use types::{ShadowsocksServerIdentity, ShadowsocksUser};
#[cfg(feature = "tls")]
pub use types::{TlsCertificateConfig, TlsCertificateUsage, TlsServerConfig};

#[cfg(feature = "trojan")]
pub use types::{TrojanFallback, TrojanUser};

#[cfg(feature = "vmess")]
pub use types::VmessUser;

#[cfg(feature = "vmess")]
pub(crate) fn parse_vmess_user_id(value: &str) -> Result<[u8; 16], String> {
    use sha1::{Digest, Sha1};

    let text = value.as_bytes();
    if text.len() < 32 || text.len() > 36 {
        if text.is_empty() || text.len() > 30 {
            return Err(format!("invalid VMess UUID: {value}"));
        }

        let mut hasher = Sha1::new();
        hasher.update([0u8; 16]);
        hasher.update(text);
        let digest = hasher.finalize();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&digest[..16]);
        uuid[6] = (uuid[6] & 0x0f) | 0x50;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        return Ok(uuid);
    }

    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut uuid = [0u8; 16];
    let mut text_offset = 0usize;
    let mut uuid_offset = 0usize;

    for group_len in GROUPS {
        if text.get(text_offset) == Some(&b'-') {
            text_offset += 1;
        }
        let group = text
            .get(text_offset..text_offset + group_len)
            .ok_or_else(|| format!("invalid VMess UUID: {value}"))?;
        for pair in group.chunks_exact(2) {
            let high = vmess_hex_nibble(pair[0])
                .ok_or_else(|| format!("invalid VMess UUID: {value}"))?;
            let low = vmess_hex_nibble(pair[1])
                .ok_or_else(|| format!("invalid VMess UUID: {value}"))?;
            uuid[uuid_offset] = (high << 4) | low;
            uuid_offset += 1;
        }
        text_offset += group_len;
    }

    Ok(uuid)
}

#[cfg(feature = "vmess")]
pub(crate) fn normalize_vmess_user_id(value: &str) -> Result<String, String> {
    let uuid = parse_vmess_user_id(value)?;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    ))
}

#[cfg(feature = "vmess")]
fn vmess_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
