use std::io;

use tracing::warn;

pub struct ReadHeaderInfo {
    pub response_header_key: [u8; 16],
    pub response_header_iv: [u8; 16],
    pub response_authentication_v: u8,
}

pub(super) fn check_header_response(
    response_header_bytes: &[u8],
    response_authentication_v: u8,
) -> io::Result<()> {
    if response_header_bytes.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VMess response header is too short: {} bytes",
                response_header_bytes.len()
            ),
        ));
    }
    if response_header_bytes[0] != response_authentication_v {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid response auth value, expected {}, got {}",
                response_authentication_v, response_header_bytes[0]
            ),
        ));
    }

    let command_len = response_header_bytes[3] as usize;
    if command_len > response_header_bytes.len() - 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VMess response command length exceeds header content: {command_len} > {}",
                response_header_bytes.len() - 4
            ),
        ));
    }
    if (response_header_bytes[2] & 0x01) == 0x01 {
        warn!("Ignoring unsupported server dynamic port instructions.");
    }
    Ok(())
}
