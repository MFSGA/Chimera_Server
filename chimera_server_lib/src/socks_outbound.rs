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
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    if prefix[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "SOCKS CONNECT response used invalid version {}",
            prefix[0]
        )));
    }
    if prefix[2] != 0 {
        return Err(invalid_data(
            "SOCKS CONNECT response reserved byte is nonzero",
        ));
    }
    if prefix[1] != REP_SUCCEEDED {
        return Err(std::io::Error::new(
            response_error_kind(prefix[1]),
            format!("SOCKS CONNECT failed with reply code {}", prefix[1]),
        ));
    }

    match prefix[3] {
        ADDRESS_IPV4 => discard_exact(stream, 4).await?,
        ADDRESS_IPV6 => discard_exact(stream, 16).await?,
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid_data(
                    "SOCKS CONNECT response domain must not be empty",
                ));
            }
            discard_exact(stream, length).await?;
        }
        address_type => {
            return Err(invalid_data(format!(
                "SOCKS CONNECT response used unsupported address type {address_type}"
            )));
        }
    }
    discard_exact(stream, 2).await
}

async fn discard_exact(
    stream: &mut dyn AsyncStream,
    length: usize,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 256];
    let mut remaining = length;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..chunk]).await?;
        remaining -= chunk;
    }
    Ok(())
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
}
