use aws_lc_rs::digest::{SHA224, digest};

use crate::address::{Address, NetLocation};

const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x03;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;
const CRLF: [u8; 2] = *b"\r\n";

pub(crate) fn encode_trojan_tcp_request(
    password: &str,
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    encode_trojan_request(password, COMMAND_TCP, target)
}

pub(crate) fn encode_trojan_udp_request(
    password: &str,
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    encode_trojan_request(password, COMMAND_UDP, target)
}

fn encode_trojan_request(
    password: &str,
    command: u8,
    target: &NetLocation,
) -> std::io::Result<Vec<u8>> {
    if password.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Trojan password must not be empty",
        ));
    }

    let password_hash = password_hash(password);
    let mut request = Vec::with_capacity(96);
    request.extend_from_slice(&password_hash);
    request.extend_from_slice(&CRLF);
    request.push(command);
    write_address(&mut request, target.address())?;
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(&CRLF);
    Ok(request)
}

fn password_hash(password: &str) -> [u8; 56] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = digest(&SHA224, password.as_bytes());
    let mut encoded = [0u8; 56];
    for (index, byte) in hash.as_ref().iter().copied().enumerate() {
        encoded[index * 2] = HEX[(byte >> 4) as usize];
        encoded[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    encoded
}

fn write_address(output: &mut Vec<u8>, address: &Address) -> std::io::Result<()> {
    match address {
        Address::Ipv4(address) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&address.octets());
        }
        Address::Ipv6(address) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            let bytes = hostname.as_bytes();
            let length = u8::try_from(bytes.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Trojan target domain exceeds 255 bytes",
                )
            })?;
            if length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Trojan target domain must not be empty",
                ));
            }
            output.push(ADDRESS_DOMAIN);
            output.push(length);
            output.extend_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn request_encoding_preserves_ipv4_domain_and_ipv6_targets() {
        let password = "test-password";
        let cases = [
            (
                NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 80),
                ADDRESS_IPV4,
            ),
            (
                NetLocation::new(Address::Hostname("example.test".into()), 443),
                ADDRESS_DOMAIN,
            ),
            (
                NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
                ADDRESS_IPV6,
            ),
        ];

        for (target, expected_type) in cases {
            let request = encode_trojan_tcp_request(password, &target).unwrap();
            assert!(request.len() >= 62);
            assert!(request[..56].iter().all(u8::is_ascii_hexdigit));
            assert_eq!(&request[56..58], &CRLF);
            assert_eq!(request[58], COMMAND_TCP);
            assert_eq!(request[59], expected_type);
            assert_eq!(&request[request.len() - 2..], &CRLF);
        }
    }

    #[test]
    fn udp_request_uses_associate_command_and_preserves_domain_target() {
        let target = NetLocation::new(Address::Hostname("dns.example".into()), 53);
        let request = encode_trojan_udp_request("test-password", &target).unwrap();
        assert_eq!(&request[56..58], &CRLF);
        assert_eq!(request[58], COMMAND_UDP);
        assert_eq!(request[59], ADDRESS_DOMAIN);
        assert_eq!(request[60] as usize, "dns.example".len());
        assert_eq!(&request[61..72], b"dns.example");
        assert_eq!(&request[72..74], &53u16.to_be_bytes());
        assert_eq!(&request[74..], &CRLF);
    }

    #[test]
    fn password_hash_matches_known_sha224_hex() {
        assert_eq!(
            std::str::from_utf8(&password_hash("password")).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }
}
