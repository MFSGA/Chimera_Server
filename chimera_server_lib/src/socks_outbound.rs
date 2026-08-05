use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCEEDED: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const REP_SUCCEEDED: u8 = 0x00;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Socks5Credentials {
    pub username: String,
    pub password: String,
}

pub(crate) async fn connect_socks5(
    stream: &mut dyn AsyncStream,
    credentials: Option<&Socks5Credentials>,
    target: &NetLocation,
) -> std::io::Result<()> {
    negotiate_authentication(stream, credentials).await?;
    send_connect_request(stream, target).await?;
    read_connect_response(stream).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Socks5UdpPacket {
    pub location: NetLocation,
    pub payload: Vec<u8>,
}

pub(crate) async fn associate_socks5_udp(
    stream: &mut dyn AsyncStream,
    credentials: Option<&Socks5Credentials>,
) -> std::io::Result<NetLocation> {
    negotiate_authentication(stream, credentials).await?;
    let mut request = Vec::with_capacity(10);
    request.extend_from_slice(&[SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0]);
    write_address(&mut request, &Address::Ipv4(Ipv4Addr::UNSPECIFIED))?;
    request.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&request).await?;
    read_command_response(stream, "UDP ASSOCIATE").await
}

pub(crate) fn encode_socks5_udp_packet(
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + 1 + 16 + 2 + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    write_address(&mut packet, target.address())?;
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub(crate) fn decode_socks5_udp_packet(
    packet: &[u8],
) -> std::io::Result<Socks5UdpPacket> {
    if packet.len() < 4 {
        return Err(invalid_data("SOCKS UDP packet is too short"));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(invalid_data("SOCKS UDP reserved bytes are nonzero"));
    }
    if packet[2] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fragmented SOCKS UDP packets are not supported",
        ));
    }
    let (location, payload_offset) = parse_udp_location(packet, 3)?;
    Ok(Socks5UdpPacket {
        location,
        payload: packet[payload_offset..].to_vec(),
    })
}

async fn negotiate_authentication(
    stream: &mut dyn AsyncStream,
    credentials: Option<&Socks5Credentials>,
) -> std::io::Result<()> {
    let methods: &[u8] = if credentials.is_some() {
        &[METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.extend_from_slice(&[SOCKS_VERSION, methods.len() as u8]);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "SOCKS server selected invalid version {}",
            response[0]
        )));
    }
    match response[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USERNAME_PASSWORD => authenticate_username_password(
            stream,
            credentials.ok_or_else(|| {
                invalid_data(
                    "SOCKS server requested username/password without credentials",
                )
            })?,
        )
        .await,
        METHOD_NO_ACCEPTABLE => Err(permission_denied(
            "SOCKS server rejected all authentication methods",
        )),
        method => Err(invalid_data(format!(
            "SOCKS server selected unsupported authentication method {method}"
        ))),
    }
}

async fn authenticate_username_password(
    stream: &mut dyn AsyncStream,
    credentials: &Socks5Credentials,
) -> std::io::Result<()> {
    let username = credentials.username.as_bytes();
    let password = credentials.password.as_bytes();
    let username_len = u8::try_from(username.len())
        .map_err(|_| invalid_input("SOCKS username exceeds 255 bytes"))?;
    let password_len = u8::try_from(password.len())
        .map_err(|_| invalid_input("SOCKS password exceeds 255 bytes"))?;
    if username_len == 0 {
        return Err(invalid_input("SOCKS username must not be empty"));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[AUTH_VERSION, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != AUTH_VERSION {
        return Err(invalid_data(format!(
            "SOCKS authentication response used invalid version {}",
            response[0]
        )));
    }
    if response[1] != AUTH_SUCCEEDED {
        return Err(permission_denied(
            "SOCKS username/password authentication failed",
        ));
    }
    Ok(())
}

async fn send_connect_request(
    stream: &mut dyn AsyncStream,
    target: &NetLocation,
) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(32);
    request.extend_from_slice(&[SOCKS_VERSION, COMMAND_CONNECT, 0]);
    write_address(&mut request, target.address())?;
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await
}

async fn read_connect_response(stream: &mut dyn AsyncStream) -> std::io::Result<()> {
    read_command_response(stream, "CONNECT").await.map(|_| ())
}

async fn read_command_response(
    stream: &mut dyn AsyncStream,
    command_name: &str,
) -> std::io::Result<NetLocation> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    if prefix[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "SOCKS {command_name} response used invalid version {}",
            prefix[0]
        )));
    }
    if prefix[2] != 0 {
        return Err(invalid_data(format!(
            "SOCKS {command_name} response reserved byte is nonzero"
        )));
    }
    if prefix[1] != REP_SUCCEEDED {
        return Err(std::io::Error::new(
            response_error_kind(prefix[1]),
            format!("SOCKS {command_name} failed with reply code {}", prefix[1]),
        ));
    }

    let address = match prefix[3] {
        ADDRESS_IPV4 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            Address::Ipv4(Ipv4Addr::from(bytes))
        }
        ADDRESS_IPV6 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            Address::Ipv6(Ipv6Addr::from(bytes))
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid_data(format!(
                    "SOCKS {command_name} response domain must not be empty"
                )));
            }
            let mut bytes = vec![0u8; length];
            stream.read_exact(&mut bytes).await?;
            let domain = std::str::from_utf8(&bytes).map_err(|_| {
                invalid_data(format!(
                    "SOCKS {command_name} response domain is not UTF-8"
                ))
            })?;
            Address::from(domain)?
        }
        address_type => {
            return Err(invalid_data(format!(
                "SOCKS {command_name} response used unsupported address type {address_type}"
            )));
        }
    };
    let port = stream.read_u16().await?;
    Ok(NetLocation::new(address, port))
}

fn parse_udp_location(
    packet: &[u8],
    mut offset: usize,
) -> std::io::Result<(NetLocation, usize)> {
    let address_type = *packet
        .get(offset)
        .ok_or_else(|| invalid_data("SOCKS UDP packet is missing address type"))?;
    offset += 1;
    let address = match address_type {
        ADDRESS_IPV4 => {
            let end = offset
                .checked_add(4)
                .ok_or_else(|| invalid_data("SOCKS UDP IPv4 offset overflow"))?;
            let bytes: [u8; 4] = packet
                .get(offset..end)
                .ok_or_else(|| invalid_data("SOCKS UDP IPv4 address is truncated"))?
                .try_into()
                .expect("IPv4 slice length");
            offset = end;
            Address::Ipv4(Ipv4Addr::from(bytes))
        }
        ADDRESS_IPV6 => {
            let end = offset
                .checked_add(16)
                .ok_or_else(|| invalid_data("SOCKS UDP IPv6 offset overflow"))?;
            let bytes: [u8; 16] = packet
                .get(offset..end)
                .ok_or_else(|| invalid_data("SOCKS UDP IPv6 address is truncated"))?
                .try_into()
                .expect("IPv6 slice length");
            offset = end;
            Address::Ipv6(Ipv6Addr::from(bytes))
        }
        ADDRESS_DOMAIN => {
            let length = *packet
                .get(offset)
                .ok_or_else(|| invalid_data("SOCKS UDP domain length is missing"))?
                as usize;
            offset += 1;
            if length == 0 {
                return Err(invalid_data("SOCKS UDP domain must not be empty"));
            }
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid_data("SOCKS UDP domain offset overflow"))?;
            let bytes = packet
                .get(offset..end)
                .ok_or_else(|| invalid_data("SOCKS UDP domain is truncated"))?;
            let domain = std::str::from_utf8(bytes)
                .map_err(|_| invalid_data("SOCKS UDP domain is not UTF-8"))?;
            offset = end;
            Address::from(domain)?
        }
        value => {
            return Err(invalid_data(format!(
                "SOCKS UDP packet used unsupported address type {value}"
            )));
        }
    };
    let port_end = offset
        .checked_add(2)
        .ok_or_else(|| invalid_data("SOCKS UDP port offset overflow"))?;
    let port_bytes: [u8; 2] = packet
        .get(offset..port_end)
        .ok_or_else(|| invalid_data("SOCKS UDP port is truncated"))?
        .try_into()
        .expect("port slice length");
    Ok((
        NetLocation::new(address, u16::from_be_bytes(port_bytes)),
        port_end,
    ))
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
                invalid_input("SOCKS target domain exceeds 255 bytes")
            })?;
            if length == 0 {
                return Err(invalid_input("SOCKS target domain must not be empty"));
            }
            output.extend_from_slice(&[ADDRESS_DOMAIN, length]);
            output.extend_from_slice(bytes);
        }
    }
    Ok(())
}

fn response_error_kind(reply: u8) -> std::io::ErrorKind {
    match reply {
        0x02 => std::io::ErrorKind::PermissionDenied,
        0x03 | 0x04 => std::io::ErrorKind::NetworkUnreachable,
        0x05 => std::io::ErrorKind::ConnectionRefused,
        0x06 => std::io::ErrorKind::TimedOut,
        0x07 | 0x08 => std::io::ErrorKind::Unsupported,
        _ => std::io::ErrorKind::ConnectionAborted,
    }
}

fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn permission_denied(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn no_auth_connect_preserves_domain_target_and_payload() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 1, METHOD_NO_AUTH]);
            server
                .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                .await
                .unwrap();

            let mut request = [0u8; 5];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [SOCKS_VERSION, COMMAND_CONNECT, 0, ADDRESS_DOMAIN, 12]
            );
            let mut domain = [0u8; 12];
            server.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain, b"example.test");
            let port = server.read_u16().await.unwrap();
            assert_eq!(port, 443);
            server
                .write_all(&[
                    SOCKS_VERSION,
                    REP_SUCCEEDED,
                    0,
                    ADDRESS_IPV4,
                    127,
                    0,
                    0,
                    1,
                    0,
                    0,
                ])
                .await
                .unwrap();
            let mut payload = [0u8; 5];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
        });

        connect_socks5(
            &mut client,
            None,
            &NetLocation::new(Address::Hostname("example.test".into()), 443),
        )
        .await
        .unwrap();
        client.write_all(b"hello").await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn username_password_connect_handles_ipv4_and_ipv6_responses() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(
                greeting,
                [SOCKS_VERSION, 2, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            );
            server
                .write_all(&[SOCKS_VERSION, METHOD_USERNAME_PASSWORD])
                .await
                .unwrap();

            assert_eq!(server.read_u8().await.unwrap(), AUTH_VERSION);
            let username_len = server.read_u8().await.unwrap() as usize;
            let mut username = vec![0; username_len];
            server.read_exact(&mut username).await.unwrap();
            let password_len = server.read_u8().await.unwrap() as usize;
            let mut password = vec![0; password_len];
            server.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"alice");
            assert_eq!(password, b"secret");
            server.write_all(&[AUTH_VERSION, 0]).await.unwrap();

            let mut prefix = [0u8; 4];
            server.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [SOCKS_VERSION, COMMAND_CONNECT, 0, ADDRESS_IPV6]);
            let mut address = [0u8; 16];
            server.read_exact(&mut address).await.unwrap();
            assert_eq!(Ipv6Addr::from(address), Ipv6Addr::LOCALHOST);
            assert_eq!(server.read_u16().await.unwrap(), 8443);
            let mut response = vec![SOCKS_VERSION, 0, 0, ADDRESS_DOMAIN, 4];
            response.extend_from_slice(b"bind");
            response.extend_from_slice(&1080u16.to_be_bytes());
            response.extend_from_slice(b"ready");
            server.write_all(&response).await.unwrap();
        });

        connect_socks5(
            &mut client,
            Some(&Socks5Credentials {
                username: "alice".into(),
                password: "secret".into(),
            }),
            &NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
        )
        .await
        .unwrap();
        let mut application = [0u8; 5];
        client.read_exact(&mut application).await.unwrap();
        assert_eq!(&application, b"ready");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_auth_and_connect_fail_closed() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server
                .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                .await
                .unwrap();
        });
        let error = connect_socks5(
            &mut client,
            None,
            &NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        server_task.await.unwrap();

        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server
                .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                .await
                .unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[SOCKS_VERSION, 0x05, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let error = connect_socks5(
            &mut client,
            None,
            &NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_associate_negotiates_authentication_and_returns_relay() {
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(
                greeting,
                [SOCKS_VERSION, 2, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            );
            server
                .write_all(&[SOCKS_VERSION, METHOD_USERNAME_PASSWORD])
                .await
                .unwrap();
            assert_eq!(server.read_u8().await.unwrap(), AUTH_VERSION);
            let username_len = server.read_u8().await.unwrap() as usize;
            let mut username = vec![0u8; username_len];
            server.read_exact(&mut username).await.unwrap();
            let password_len = server.read_u8().await.unwrap() as usize;
            let mut password = vec![0u8; password_len];
            server.read_exact(&mut password).await.unwrap();
            assert_eq!(&username, b"udp-user");
            assert_eq!(&password, b"udp-pass");
            server.write_all(&[AUTH_VERSION, 0]).await.unwrap();

            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [
                    SOCKS_VERSION,
                    COMMAND_UDP_ASSOCIATE,
                    0,
                    ADDRESS_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            );
            let mut response = vec![SOCKS_VERSION, 0, 0, ADDRESS_DOMAIN, 10];
            response.extend_from_slice(b"relay.test");
            response.extend_from_slice(&5300u16.to_be_bytes());
            server.write_all(&response).await.unwrap();
        });

        let relay = associate_socks5_udp(
            &mut client,
            Some(&Socks5Credentials {
                username: "udp-user".into(),
                password: "udp-pass".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(relay.address(), &Address::Hostname("relay.test".into()));
        assert_eq!(relay.port(), 5300);
        server_task.await.unwrap();
    }

    #[test]
    fn udp_packet_roundtrips_all_address_families() {
        for target in [
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53),
            NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 5353),
            NetLocation::new(Address::Hostname("dns.example".into()), 853),
        ] {
            let packet = encode_socks5_udp_packet(&target, b"dns payload").unwrap();
            let decoded = decode_socks5_udp_packet(&packet).unwrap();
            assert_eq!(decoded.location, target);
            assert_eq!(decoded.payload, b"dns payload");
        }
    }

    #[test]
    fn udp_packet_rejects_reserved_fragmented_and_truncated_headers() {
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53);
        let packet = encode_socks5_udp_packet(&target, b"payload").unwrap();

        let mut reserved = packet.clone();
        reserved[0] = 1;
        assert_eq!(
            decode_socks5_udp_packet(&reserved).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut fragmented = packet.clone();
        fragmented[2] = 1;
        assert_eq!(
            decode_socks5_udp_packet(&fragmented).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        assert_eq!(
            decode_socks5_udp_packet(&packet[..7]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn rejected_udp_associate_reply_fails_closed() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server
                .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                .await
                .unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], COMMAND_UDP_ASSOCIATE);
            server
                .write_all(&[SOCKS_VERSION, 0x07, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let error = associate_socks5_udp(&mut client, None).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        server_task.await.unwrap();
    }
}
