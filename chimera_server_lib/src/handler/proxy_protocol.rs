use std::io;

use tokio::io::AsyncReadExt;

use crate::async_stream::AsyncStream;

pub(crate) async fn read_proxy_protocol(
    stream: &mut Box<dyn AsyncStream>,
) -> io::Result<Option<std::net::SocketAddr>> {
    const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

    let mut prefix = [0u8; 12];
    stream.read_exact(&mut prefix).await?;
    if &prefix == V2_SIGNATURE {
        let mut fixed = [0u8; 4];
        stream.read_exact(&mut fixed).await?;
        let version_command = fixed[0];
        if version_command >> 4 != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v2 version",
            ));
        }
        let family_protocol = fixed[1];
        let payload_len = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;

        if version_command & 0x0f == 0 {
            // go-proxyproto v0.9.2 (used by Xray v26.2.6) still validates the
            // address-block length for LOCAL frames when the family nibble is
            // IPv4, IPv6, or UNIX. The transport nibble itself is ignored for
            // this check. UNSPEC/unknown families remain length-agnostic.
            let minimum_address_len = match family_protocol >> 4 {
                1 => Some(12),
                2 => Some(36),
                3 => Some(216),
                _ => None,
            };
            if minimum_address_len.is_some_and(|minimum| payload_len < minimum) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PROXY protocol v2 LOCAL address length",
                ));
            }
            return Ok(None);
        }
        if version_command & 0x0f != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v2 command",
            ));
        }
        let family = family_protocol >> 4;
        let transport = family_protocol & 0x0f;
        match family {
            1 if payload.len() >= 12 => {
                let source = std::net::Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                let source_port = u16::from_be_bytes([payload[8], payload[9]]);
                Ok(Some(std::net::SocketAddr::new(source.into(), source_port)))
            }
            2 if payload.len() >= 36 => {
                let mut source = [0u8; 16];
                source.copy_from_slice(&payload[..16]);
                let source_port = u16::from_be_bytes([payload[32], payload[33]]);
                Ok(Some(std::net::SocketAddr::new(
                    canonicalize_xray_proxy_ip(
                        std::net::Ipv6Addr::from(source).into(),
                    ),
                    source_port,
                )))
            }
            // go-proxyproto v0.9.2 accepts UNIX addresses but Xray's
            // HTTPUpgrade path only needs the connection to proceed. Chimera's
            // logical peer type is SocketAddr, so consume the address block and
            // keep the underlying TCP peer instead of rejecting the handshake.
            3 if payload.len() >= 216 => Ok(None),
            // The v0.9.2 parser also accepts the odd half-specified family /
            // transport combinations where exactly one nibble is UNSPEC. They
            // carry no IP endpoint, so there is nothing to override locally.
            0 if transport != 0 => Ok(None),
            4..=15 if transport == 0 => Ok(None),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v2 address family",
            )),
        }
    } else if prefix.starts_with(b"PROXY") {
        let mut line = prefix.to_vec();
        while !line.ends_with(b"\r\n") {
            // go-proxyproto v0.9.2 caps the complete PROXY v1 line at 107
            // bytes, including CRLF. Reject before reading byte 108 so the
            // boundary matches Xray v26.2.6 exactly.
            if line.len() >= 107 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY protocol v1 header is too long",
                ));
            }
            line.push(stream.read_u8().await?);
        }
        let line = std::str::from_utf8(&line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid PROXY protocol v1 encoding: {error}"),
            )
        })?;
        // go-proxyproto v0.9.2 (used by Xray v26.2.6) splits the v1 line on
        // literal single spaces. Repeated whitespace therefore produces empty
        // fields instead of being collapsed like `split_whitespace()` would.
        let mut fields = line.trim_end_matches("\r\n").split(' ');
        // go-proxyproto v0.9.2 dispatches v1 after peeking only the first five
        // bytes ("PROXY") and does not revalidate the complete first token.
        // Xray v26.2.6 therefore accepts quirks such as "PROXYjunk TCP4 ...".
        let _signature_token = fields.next();
        let family = fields.next().unwrap_or_default();
        if family == "UNKNOWN" {
            return Ok(None);
        }
        if !matches!(family, "TCP4" | "TCP6") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v1 family",
            ));
        }
        let source_ip = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing PROXY source IP")
            })?
            .parse::<std::net::IpAddr>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY source IP: {error}"),
                )
            })?;
        let destination_ip = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY destination IP",
                )
            })?
            .parse::<std::net::IpAddr>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY destination IP: {error}"),
                )
            })?;
        let source_port = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY source port",
                )
            })?
            .parse::<u16>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY source port: {error}"),
                )
            })?;
        let _destination_port = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY destination port",
                )
            })?
            .parse::<u16>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY destination port: {error}"),
                )
            })?;
        // Xray's go-proxyproto v0.9.2 only requires at least the six standard
        // TCP4/TCP6 tokens and ignores any trailing tokens before CRLF.
        if (family == "TCP4" && (!source_ip.is_ipv4() || !destination_ip.is_ipv4()))
            || (family == "TCP6"
                && (!source_ip.is_ipv6() || !destination_ip.is_ipv6()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v1 address family",
            ));
        }
        Ok(Some(std::net::SocketAddr::new(
            canonicalize_xray_proxy_ip(source_ip),
            source_port,
        )))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing required PROXY protocol header",
        ))
    }
}

fn canonicalize_xray_proxy_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(ipv6)),
        ipv4 => ipv4,
    }
}
