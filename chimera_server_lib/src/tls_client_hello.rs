const TLS_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const SERVER_NAME_EXTENSION: u16 = 0;
const ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;
const MAX_TLS_RECORD_PAYLOAD: usize = 18_432;
const MAX_CLIENT_HELLO_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientHelloInspection {
    Incomplete,
    NotTls,
    Malformed,
    NoServerName,
    ServerName(String),
    EncryptedClientHello,
}

pub(crate) fn inspect_client_hello(input: &[u8]) -> ClientHelloInspection {
    if input.len() < TLS_HEADER_LEN {
        return ClientHelloInspection::Incomplete;
    }

    let mut offset = 0usize;
    let mut handshake = Vec::new();
    loop {
        let Some(header) = input.get(offset..offset + TLS_HEADER_LEN) else {
            return ClientHelloInspection::Incomplete;
        };
        if header[0] != TLS_HANDSHAKE_CONTENT_TYPE || header[1] != 3 {
            return if offset == 0 {
                ClientHelloInspection::NotTls
            } else {
                ClientHelloInspection::Malformed
            };
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || record_len > MAX_TLS_RECORD_PAYLOAD {
            return ClientHelloInspection::Malformed;
        }
        let record_start = offset + TLS_HEADER_LEN;
        let Some(record_end) = record_start.checked_add(record_len) else {
            return ClientHelloInspection::Malformed;
        };
        let Some(payload) = input.get(record_start..record_end) else {
            return ClientHelloInspection::Incomplete;
        };
        if handshake.len().saturating_add(payload.len()) > MAX_CLIENT_HELLO_BYTES {
            return ClientHelloInspection::Malformed;
        }
        handshake.extend_from_slice(payload);

        if handshake.len() >= 4 {
            if handshake[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
                return ClientHelloInspection::NotTls;
            }
            let body_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if body_len > MAX_CLIENT_HELLO_BYTES - 4 {
                return ClientHelloInspection::Malformed;
            }
            if handshake.len() >= body_len + 4 {
                return parse_client_hello_body(&handshake[4..4 + body_len]);
            }
        }

        offset = record_end;
        if offset == input.len() {
            return ClientHelloInspection::Incomplete;
        }
    }
}

fn parse_client_hello_body(body: &[u8]) -> ClientHelloInspection {
    let mut cursor = 0usize;
    if take(body, &mut cursor, 2 + 32).is_none() {
        return ClientHelloInspection::Malformed;
    }

    let Some(session_id_len) = take_u8(body, &mut cursor) else {
        return ClientHelloInspection::Malformed;
    };
    if take(body, &mut cursor, session_id_len as usize).is_none() {
        return ClientHelloInspection::Malformed;
    }

    let Some(cipher_len) = take_u16(body, &mut cursor) else {
        return ClientHelloInspection::Malformed;
    };
    if cipher_len == 0
        || cipher_len % 2 != 0
        || take(body, &mut cursor, cipher_len as usize).is_none()
    {
        return ClientHelloInspection::Malformed;
    }

    let Some(compression_len) = take_u8(body, &mut cursor) else {
        return ClientHelloInspection::Malformed;
    };
    if compression_len == 0
        || take(body, &mut cursor, compression_len as usize).is_none()
    {
        return ClientHelloInspection::Malformed;
    }

    if cursor == body.len() {
        return ClientHelloInspection::NoServerName;
    }
    let Some(extensions_len) = take_u16(body, &mut cursor) else {
        return ClientHelloInspection::Malformed;
    };
    let Some(extensions) = take(body, &mut cursor, extensions_len as usize) else {
        return ClientHelloInspection::Malformed;
    };
    if cursor != body.len() {
        return ClientHelloInspection::Malformed;
    }

    let mut extension_cursor = 0usize;
    let mut server_name = None;
    let mut ech = false;
    while extension_cursor < extensions.len() {
        let Some(extension_type) = take_u16(extensions, &mut extension_cursor)
        else {
            return ClientHelloInspection::Malformed;
        };
        let Some(extension_len) = take_u16(extensions, &mut extension_cursor) else {
            return ClientHelloInspection::Malformed;
        };
        let Some(extension) =
            take(extensions, &mut extension_cursor, extension_len as usize)
        else {
            return ClientHelloInspection::Malformed;
        };
        match extension_type {
            ENCRYPTED_CLIENT_HELLO_EXTENSION => ech = true,
            SERVER_NAME_EXTENSION => {
                let Some(name) = parse_server_name_extension(extension) else {
                    return ClientHelloInspection::Malformed;
                };
                if server_name.replace(name).is_some() {
                    return ClientHelloInspection::Malformed;
                }
            }
            _ => {}
        }
    }

    if ech {
        ClientHelloInspection::EncryptedClientHello
    } else if let Some(server_name) = server_name {
        ClientHelloInspection::ServerName(server_name)
    } else {
        ClientHelloInspection::NoServerName
    }
}

fn parse_server_name_extension(extension: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    let list_len = take_u16(extension, &mut cursor)? as usize;
    let names = take(extension, &mut cursor, list_len)?;
    if cursor != extension.len() {
        return None;
    }

    let mut name_cursor = 0usize;
    let mut server_name = None;
    while name_cursor < names.len() {
        let name_type = take_u8(names, &mut name_cursor)?;
        let name_len = take_u16(names, &mut name_cursor)? as usize;
        let name = take(names, &mut name_cursor, name_len)?;
        if name_type == 0 {
            if name.is_empty() || server_name.is_some() {
                return None;
            }
            server_name = Some(std::str::from_utf8(name).ok()?.to_string());
        }
    }
    server_name
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(len)?;
    let value = input.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn take_u8(input: &[u8], cursor: &mut usize) -> Option<u8> {
    Some(*take(input, cursor, 1)?.first()?)
}

fn take_u16(input: &[u8], cursor: &mut usize) -> Option<u16> {
    let bytes: [u8; 2] = take(input, cursor, 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(server_name: Option<&str>, ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(server_name) = server_name {
            let name = server_name.as_bytes();
            let mut extension = Vec::new();
            extension.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
            extension.push(0);
            extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
            extension.extend_from_slice(name);
            extensions.extend_from_slice(&SERVER_NAME_EXTENSION.to_be_bytes());
            extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&extension);
        }
        if ech {
            extensions
                .extend_from_slice(&ENCRYPTED_CLIENT_HELLO_EXTENSION.to_be_bytes());
            extensions.extend_from_slice(&1u16.to_be_bytes());
            extensions.push(1);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(CLIENT_HELLO_HANDSHAKE_TYPE);
        let len = body.len();
        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![
            TLS_HANDSHAKE_CONTENT_TYPE,
            3,
            1,
            ((handshake.len() >> 8) & 0xff) as u8,
            (handshake.len() & 0xff) as u8,
        ];
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_server_name() {
        assert_eq!(
            inspect_client_hello(&client_hello(Some("Api.Example.COM"), false)),
            ClientHelloInspection::ServerName("Api.Example.COM".into())
        );
    }

    #[test]
    fn ech_takes_precedence_over_outer_server_name() {
        assert_eq!(
            inspect_client_hello(&client_hello(Some("public.example"), true)),
            ClientHelloInspection::EncryptedClientHello
        );
    }

    #[test]
    fn handles_fragmented_tls_records() {
        let original = client_hello(Some("fragmented.example"), false);
        let payload = &original[TLS_HEADER_LEN..];
        let split = 17;
        let mut fragmented = vec![TLS_HANDSHAKE_CONTENT_TYPE, 3, 1, 0, split as u8];
        fragmented.extend_from_slice(&payload[..split]);
        let remaining = payload.len() - split;
        fragmented.extend_from_slice(&[
            TLS_HANDSHAKE_CONTENT_TYPE,
            3,
            1,
            ((remaining >> 8) & 0xff) as u8,
            (remaining & 0xff) as u8,
        ]);
        fragmented.extend_from_slice(&payload[split..]);
        assert_eq!(
            inspect_client_hello(&fragmented),
            ClientHelloInspection::ServerName("fragmented.example".into())
        );
    }

    #[test]
    fn distinguishes_incomplete_and_non_tls_data() {
        assert_eq!(
            inspect_client_hello(&[TLS_HANDSHAKE_CONTENT_TYPE, 3, 1]),
            ClientHelloInspection::Incomplete
        );
        assert_eq!(
            inspect_client_hello(b"GET / HTTP/1.1\r\n"),
            ClientHelloInspection::NotTls
        );
    }
}
