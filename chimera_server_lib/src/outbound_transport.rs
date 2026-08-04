use std::sync::Arc;

#[cfg(feature = "tls")]
use std::io::Cursor;

#[cfg(feature = "tls")]
use rustls::{
    ClientConfig, RootCertStore,
    client::Resumption,
    pki_types::ServerName,
    version::{TLS12, TLS13},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

#[cfg(any(feature = "tls", test))]
use crate::address::Address;
#[cfg(feature = "httpupgrade")]
use crate::handler::httpupgrade::HttpUpgradeClientConfig;
#[cfg(feature = "ws")]
use crate::handler::ws::WebsocketClientConfig;
#[cfg(feature = "reality")]
use crate::reality::{
    RealityClientConfig, RealityClientConnection, RealityTlsStream,
    decode_public_key, decode_short_id,
};
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::def::OutboundStreamSettings,
    resolver::{Resolver, resolve_single_address},
    util::socket::new_tcp_socket,
};

#[derive(Debug, Clone)]
pub(crate) struct OutboundTransportConfig {
    security: OutboundSecurityConfig,
    protocol: OutboundProtocolConfig,
}

#[derive(Debug, Clone)]
enum OutboundSecurityConfig {
    None,
    #[cfg(feature = "tls")]
    Tls(TlsOutboundTransportConfig),
    #[cfg(feature = "reality")]
    Reality(RealityClientConfig),
}

#[derive(Debug, Clone)]
enum OutboundProtocolConfig {
    Tcp,
    #[cfg(feature = "ws")]
    Websocket(WebsocketClientConfig),
    #[cfg(feature = "httpupgrade")]
    HttpUpgrade(HttpUpgradeClientConfig),
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub(crate) struct TlsOutboundTransportConfig {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl OutboundTransportConfig {
    pub(crate) fn tcp() -> Self {
        Self {
            security: OutboundSecurityConfig::None,
            protocol: OutboundProtocolConfig::Tcp,
        }
    }

    pub(crate) fn compile(
        server: &NetLocation,
        stream: Option<&OutboundStreamSettings>,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        let network = stream
            .map(|stream| stream.network.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let protocol = match network.as_str() {
            "" | "tcp" => {
                if has_websocket_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides wsSettings without network=ws"
                    ));
                }
                if has_httpupgrade_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides httpupgradeSettings without network=httpupgrade"
                    ));
                }
                OutboundProtocolConfig::Tcp
            }
            "ws" | "websocket" => {
                if has_httpupgrade_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides httpupgradeSettings with network=ws"
                    ));
                }
                #[cfg(feature = "ws")]
                {
                    compile_websocket_transport(server, stream, outbound_tag)
                        .map(OutboundProtocolConfig::Websocket)?
                }
                #[cfg(not(feature = "ws"))]
                {
                    let _ = server;
                    return Err(format!(
                        "outbound {outbound_tag} requires the ws feature"
                    ));
                }
            }
            "httpupgrade" => {
                if has_websocket_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides wsSettings with network=httpupgrade"
                    ));
                }
                #[cfg(feature = "httpupgrade")]
                {
                    compile_httpupgrade_transport(server, stream, outbound_tag)
                        .map(OutboundProtocolConfig::HttpUpgrade)?
                }
                #[cfg(not(feature = "httpupgrade"))]
                {
                    let _ = server;
                    return Err(format!(
                        "outbound {outbound_tag} requires the httpupgrade feature"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "outbound {outbound_tag} uses unsupported network {other}"
                ));
            }
        };
        let security = compile_security_transport(
            server,
            stream,
            outbound_tag,
            protocol_requires_http1(&protocol),
            protocol_supports_reality(&protocol),
        )?;
        Ok(Self { security, protocol })
    }

    pub(crate) async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        server: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let address = resolve_single_address(resolver, server).await?;
        let socket = new_tcp_socket(None, address.is_ipv6())?;
        let stream = socket.connect(address).await?;
        stream.set_nodelay(true)?;
        let stream: Box<dyn AsyncStream> = Box::new(stream);

        let stream = match &self.security {
            OutboundSecurityConfig::None => stream,
            #[cfg(feature = "tls")]
            OutboundSecurityConfig::Tls(config) => {
                let connector =
                    TlsConnector::from(Arc::clone(&config.client_config));
                let stream = connector
                    .connect(config.server_name.clone(), stream)
                    .await
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!("outbound TLS handshake failed: {error}"),
                        )
                    })?;
                Box::new(stream)
            }
            #[cfg(feature = "reality")]
            OutboundSecurityConfig::Reality(config) => {
                let session = RealityClientConnection::new(config.clone()).map_err(
                    |error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "failed to initialize outbound REALITY: {error}"
                            ),
                        )
                    },
                )?;
                Box::new(RealityTlsStream::new(stream, session))
            }
        };

        match &self.protocol {
            OutboundProtocolConfig::Tcp => Ok(stream),
            #[cfg(feature = "ws")]
            OutboundProtocolConfig::Websocket(config) => {
                config.connect(stream).await
            }
            #[cfg(feature = "httpupgrade")]
            OutboundProtocolConfig::HttpUpgrade(config) => {
                config.connect(stream).await
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_tcp(&self) -> bool {
        matches!(self.security, OutboundSecurityConfig::None)
            && matches!(self.protocol, OutboundProtocolConfig::Tcp)
    }

    #[cfg(all(test, feature = "tls"))]
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self.security, OutboundSecurityConfig::Tls(_))
    }

    #[cfg(all(test, feature = "reality"))]
    pub(crate) fn is_reality(&self) -> bool {
        matches!(self.security, OutboundSecurityConfig::Reality(_))
    }

    #[cfg(all(test, feature = "ws"))]
    pub(crate) fn is_websocket(&self) -> bool {
        matches!(self.protocol, OutboundProtocolConfig::Websocket(_))
    }

    #[cfg(all(test, feature = "httpupgrade"))]
    pub(crate) fn is_httpupgrade(&self) -> bool {
        matches!(self.protocol, OutboundProtocolConfig::HttpUpgrade(_))
    }
}

fn protocol_requires_http1(protocol: &OutboundProtocolConfig) -> bool {
    match protocol {
        OutboundProtocolConfig::Tcp => false,
        #[cfg(feature = "ws")]
        OutboundProtocolConfig::Websocket(_) => true,
        #[cfg(feature = "httpupgrade")]
        OutboundProtocolConfig::HttpUpgrade(_) => true,
    }
}

fn protocol_supports_reality(protocol: &OutboundProtocolConfig) -> bool {
    matches!(protocol, OutboundProtocolConfig::Tcp)
}

fn compile_security_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
    requires_http1: bool,
    supports_reality: bool,
) -> Result<OutboundSecurityConfig, String> {
    let security = stream
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match security.as_str() {
        "" | "none" => {
            if stream.is_some_and(|stream| stream.tls_settings.is_some()) {
                return Err(format!(
                    "outbound {outbound_tag} provides tlsSettings without security=tls"
                ));
            }
            if has_reality_settings(stream) {
                return Err(format!(
                    "outbound {outbound_tag} provides realitySettings without security=reality"
                ));
            }
            Ok(OutboundSecurityConfig::None)
        }
        "tls" => {
            if has_reality_settings(stream) {
                return Err(format!(
                    "outbound {outbound_tag} provides realitySettings with security=tls"
                ));
            }
            #[cfg(feature = "tls")]
            {
                compile_tls_transport(server, stream, outbound_tag, requires_http1)
                    .map(OutboundSecurityConfig::Tls)
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (server, requires_http1, supports_reality);
                Err(format!("outbound {outbound_tag} requires the tls feature"))
            }
        }
        "reality" => {
            if stream.is_some_and(|stream| stream.tls_settings.is_some()) {
                return Err(format!(
                    "outbound {outbound_tag} provides tlsSettings with security=reality"
                ));
            }
            #[cfg(feature = "reality")]
            {
                if !supports_reality {
                    return Err(format!(
                        "outbound {outbound_tag} REALITY does not support the selected application transport"
                    ));
                }
                compile_reality_transport(stream, outbound_tag)
                    .map(OutboundSecurityConfig::Reality)
            }
            #[cfg(not(feature = "reality"))]
            {
                let _ = (server, requires_http1, supports_reality);
                Err(format!(
                    "outbound {outbound_tag} requires the reality feature"
                ))
            }
        }
        other => Err(format!(
            "outbound {outbound_tag} uses unsupported security {other}"
        )),
    }
}

fn has_websocket_settings(stream: Option<&OutboundStreamSettings>) -> bool {
    #[cfg(feature = "ws")]
    {
        stream.is_some_and(|stream| stream.ws_settings.is_some())
    }
    #[cfg(not(feature = "ws"))]
    {
        let _ = stream;
        false
    }
}

fn has_httpupgrade_settings(stream: Option<&OutboundStreamSettings>) -> bool {
    #[cfg(feature = "httpupgrade")]
    {
        stream.is_some_and(|stream| stream.httpupgrade_settings.is_some())
    }
    #[cfg(not(feature = "httpupgrade"))]
    {
        let _ = stream;
        false
    }
}

#[cfg(feature = "httpupgrade")]
fn compile_httpupgrade_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
) -> Result<HttpUpgradeClientConfig, String> {
    let settings = stream
        .and_then(|stream| stream.httpupgrade_settings.as_ref())
        .cloned()
        .unwrap_or_default();
    let security = stream
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let tls_server_name = if security == "tls" {
        stream
            .and_then(|stream| stream.tls_settings.as_ref())
            .and_then(|settings| settings.server_name.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    } else {
        None
    };
    let fallback_host = tls_server_name
        .map(str::to_string)
        .unwrap_or_else(|| server.address().to_string());

    HttpUpgradeClientConfig::compile(
        settings.host.as_deref(),
        settings.path.as_deref(),
        &settings.headers,
        &fallback_host,
        settings.accept_proxy_protocol,
        outbound_tag,
    )
}

#[cfg(feature = "ws")]
fn compile_websocket_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
) -> Result<WebsocketClientConfig, String> {
    let settings = stream
        .and_then(|stream| stream.ws_settings.as_ref())
        .cloned()
        .unwrap_or_default();
    let security = stream
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let tls_server_name = if security == "tls" {
        stream
            .and_then(|stream| stream.tls_settings.as_ref())
            .and_then(|settings| settings.server_name.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    } else {
        None
    };
    let fallback_host = tls_server_name
        .map(str::to_string)
        .unwrap_or_else(|| server.address().to_string());

    WebsocketClientConfig::compile(
        settings.host.as_deref(),
        settings.path.as_deref(),
        &settings.headers,
        &fallback_host,
        settings.accept_proxy_protocol,
        settings.heartbeat_period,
        outbound_tag,
    )
}

fn has_reality_settings(stream: Option<&OutboundStreamSettings>) -> bool {
    #[cfg(feature = "reality")]
    {
        stream.is_some_and(|stream| stream.reality_settings.is_some())
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = stream;
        false
    }
}

#[cfg(feature = "reality")]
fn compile_reality_transport(
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
) -> Result<RealityClientConfig, String> {
    let settings = stream
        .and_then(|stream| stream.reality_settings.as_ref())
        .ok_or_else(|| {
            format!(
                "outbound {outbound_tag} security=reality requires realitySettings"
            )
        })?;

    for (field, value) in [
        ("fingerprint", settings.fingerprint.as_deref()),
        ("spiderX", settings.spider_x.as_deref()),
    ] {
        if value.is_some_and(|value| !value.trim().is_empty()) {
            return Err(format!(
                "outbound {outbound_tag} REALITY field {field} is not supported yet"
            ));
        }
    }

    let server_name = settings
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("outbound {outbound_tag} REALITY serverName is required")
        })?
        .to_string();
    let public_key = settings
        .public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("outbound {outbound_tag} REALITY publicKey is required")
        })?;
    let public_key = decode_public_key(public_key).map_err(|error| {
        format!("outbound {outbound_tag} has invalid REALITY publicKey: {error}")
    })?;
    let short_id =
        decode_short_id(settings.short_id.as_deref().unwrap_or_default().trim())
            .map_err(|error| {
                format!(
                    "outbound {outbound_tag} has invalid REALITY shortId: {error}"
                )
            })?;

    Ok(RealityClientConfig {
        public_key,
        short_id,
        server_name,
        cipher_suites: settings.cipher_suites.clone(),
    })
}

#[cfg(feature = "tls")]
fn compile_tls_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
    requires_http1: bool,
) -> Result<TlsOutboundTransportConfig, String> {
    let settings = stream
        .and_then(|stream| stream.tls_settings.as_ref())
        .cloned()
        .unwrap_or_default();

    if settings.allow_insecure {
        return Err(format!(
            "outbound {outbound_tag} does not support removed allowInsecure semantics"
        ));
    }
    for (field, value) in [
        ("fingerprint", settings.fingerprint.as_deref()),
        (
            "pinnedPeerCertSha256",
            settings.pinned_peer_cert_sha256.as_deref(),
        ),
        (
            "verifyPeerCertByName",
            settings.verify_peer_cert_by_name.as_deref(),
        ),
        ("echConfigList", settings.ech_config_list.as_deref()),
    ] {
        if value.is_some_and(|value| !value.trim().is_empty()) {
            return Err(format!(
                "outbound {outbound_tag} TLS field {field} is not supported yet"
            ));
        }
    }

    let mut roots = RootCertStore::empty();
    if !settings.disable_system_root {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots.add(certificate).map_err(|error| {
                format!(
                    "outbound {outbound_tag} failed to load a system root: {error}"
                )
            })?;
        }
        if roots.is_empty() && !native.errors.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} could not load system roots: {:?}",
                native.errors
            ));
        }
    }

    for certificate in settings.certificates {
        if certificate
            .certificate_file
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(format!(
                "outbound {outbound_tag} certificateFile is not supported yet; use inline certificate"
            ));
        }
        if certificate
            .key_file
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !certificate.key.is_empty()
        {
            return Err(format!(
                "outbound {outbound_tag} client certificates are not supported yet"
            ));
        }
        let usage = certificate
            .usage
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if usage != "verify" {
            return Err(format!(
                "outbound {outbound_tag} inline TLS certificate must use usage=verify"
            ));
        }
        if certificate.certificate.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} inline verify certificate must not be empty"
            ));
        }
        let pem = certificate.certificate.join("\n");
        let mut reader = Cursor::new(pem.as_bytes());
        let mut count = 0usize;
        for certificate in rustls_pemfile::certs(&mut reader) {
            let certificate = certificate.map_err(|error| {
                format!(
                    "outbound {outbound_tag} has invalid inline TLS certificate: {error}"
                )
            })?;
            roots.add(certificate).map_err(|error| {
                format!(
                    "outbound {outbound_tag} rejected inline TLS certificate: {error}"
                )
            })?;
            count += 1;
        }
        if count == 0 {
            return Err(format!(
                "outbound {outbound_tag} inline TLS certificate contains no PEM certificates"
            ));
        }
    }

    if roots.is_empty() {
        return Err(format!(
            "outbound {outbound_tag} TLS has no trusted root certificates"
        ));
    }

    let versions = tls_versions(
        settings.min_version.as_deref(),
        settings.max_version.as_deref(),
        outbound_tag,
    )?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|error| {
            format!("outbound {outbound_tag} has invalid TLS version range: {error}")
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = settings
        .alpn
        .into_iter()
        .map(|protocol| {
            let protocol = protocol.trim().as_bytes().to_vec();
            if protocol.is_empty() || protocol.len() > u8::MAX as usize {
                return Err(format!(
                    "outbound {outbound_tag} has invalid ALPN protocol length"
                ));
            }
            Ok(protocol)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if requires_http1 && client_config.alpn_protocols.is_empty() {
        client_config.alpn_protocols.push(b"http/1.1".to_vec());
    }
    if !settings.enable_session_resumption {
        client_config.resumption = Resumption::disabled();
    }

    let server_name = settings
        .server_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(address) => address.to_string(),
            Address::Ipv6(address) => address.to_string(),
        });
    let server_name = ServerName::try_from(server_name.trim().to_string()).map_err(
        |error| {
            format!(
                "outbound {outbound_tag} has invalid TLS serverName {server_name}: {error}"
            )
        },
    )?;

    Ok(TlsOutboundTransportConfig {
        client_config: Arc::new(client_config),
        server_name,
    })
}

#[cfg(feature = "tls")]
fn tls_versions(
    minimum: Option<&str>,
    maximum: Option<&str>,
    outbound_tag: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, String> {
    let parse = |value: Option<&str>, default: u8| -> Result<u8, String> {
        let value = value.unwrap_or_default().trim().to_ascii_lowercase();
        match value.as_str() {
            "" => Ok(default),
            "1.2" | "tls1.2" | "tls12" => Ok(12),
            "1.3" | "tls1.3" | "tls13" => Ok(13),
            other => Err(format!(
                "outbound {outbound_tag} uses unsupported TLS version {other}"
            )),
        }
    };
    let minimum = parse(minimum, 12)?;
    let maximum = parse(maximum, 13)?;
    if minimum > maximum {
        return Err(format!(
            "outbound {outbound_tag} TLS minVersion exceeds maxVersion"
        ));
    }
    Ok(match (minimum, maximum) {
        (12, 12) => vec![&TLS12],
        (12, 13) => vec![&TLS13, &TLS12],
        (13, 13) => vec![&TLS13],
        _ => {
            return Err(format!(
                "outbound {outbound_tag} has an invalid TLS version range"
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "httpupgrade")]
    use crate::config::def::OutboundHttpUpgradeSettings;
    #[cfg(feature = "reality")]
    use crate::config::def::OutboundRealitySettings;
    use crate::config::def::OutboundTlsSettings;
    #[cfg(feature = "ws")]
    use crate::config::def::OutboundWebsocketSettings;

    #[test]
    fn plain_tcp_is_the_default_transport() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        assert!(
            OutboundTransportConfig::compile(&server, None, "proxy")
                .unwrap()
                .is_tcp()
        );
    }

    #[test]
    fn rejects_unknown_networks_before_connecting() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "unknown".into(),
            security: None,
            tls_settings: None,
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("unsupported network unknown")
        );
    }

    #[cfg(feature = "ws")]
    #[test]
    fn websocket_compiles_as_an_application_transport() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "ws".into(),
            security: None,
            tls_settings: None,
            #[cfg(feature = "reality")]
            reality_settings: None,
            ws_settings: Some(OutboundWebsocketSettings {
                host: Some("edge.example".into()),
                path: Some("proxy".into()),
                ..OutboundWebsocketSettings::default()
            }),
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("WebSocket settings should compile");
        assert!(transport.is_websocket());
    }

    #[cfg(feature = "httpupgrade")]
    #[test]
    fn httpupgrade_compiles_as_a_raw_application_transport() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "httpupgrade".into(),
            security: None,
            tls_settings: None,
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            httpupgrade_settings: Some(OutboundHttpUpgradeSettings {
                host: Some("edge.example".into()),
                path: Some("proxy".into()),
                ..OutboundHttpUpgradeSettings::default()
            }),
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("HTTPUpgrade settings should compile");
        assert!(transport.is_httpupgrade());
    }

    #[cfg(all(feature = "tls", feature = "httpupgrade"))]
    #[test]
    fn tls_httpupgrade_composes_security_and_application_layers() {
        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "httpupgrade".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                server_name: Some("proxy.example".into()),
                disable_system_root: true,
                certificates: vec![crate::config::def::OutboundTlsCertificate {
                    certificate: vec![generated.cert.pem()],
                    usage: Some("verify".into()),
                    ..crate::config::def::OutboundTlsCertificate::default()
                }],
                ..OutboundTlsSettings::default()
            }),
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            httpupgrade_settings: Some(OutboundHttpUpgradeSettings {
                path: Some("/proxy".into()),
                ..OutboundHttpUpgradeSettings::default()
            }),
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("TLS and HTTPUpgrade should compose");
        assert!(transport.is_tls());
        assert!(transport.is_httpupgrade());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_compiles_with_an_inline_verify_root() {
        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                server_name: Some("proxy.example".into()),
                disable_system_root: true,
                min_version: Some("1.2".into()),
                max_version: Some("1.3".into()),
                alpn: vec!["http/1.1".into()],
                certificates: vec![crate::config::def::OutboundTlsCertificate {
                    certificate: vec![generated.cert.pem()],
                    usage: Some("verify".into()),
                    ..crate::config::def::OutboundTlsCertificate::default()
                }],
                ..OutboundTlsSettings::default()
            }),
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("inline verify root should compile");
        assert!(transport.is_tls());
    }

    #[cfg(all(feature = "tls", feature = "ws"))]
    #[test]
    fn tls_websocket_composes_security_and_application_layers() {
        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "ws".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                server_name: Some("proxy.example".into()),
                disable_system_root: true,
                certificates: vec![crate::config::def::OutboundTlsCertificate {
                    certificate: vec![generated.cert.pem()],
                    usage: Some("verify".into()),
                    ..crate::config::def::OutboundTlsCertificate::default()
                }],
                ..OutboundTlsSettings::default()
            }),
            #[cfg(feature = "reality")]
            reality_settings: None,
            ws_settings: Some(OutboundWebsocketSettings {
                path: Some("/proxy".into()),
                ..OutboundWebsocketSettings::default()
            }),
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("TLS and WebSocket should compose");
        assert!(transport.is_tls());
        assert!(transport.is_websocket());
    }

    #[cfg(all(feature = "reality", feature = "ws"))]
    #[test]
    fn reality_rejects_websocket_transport() {
        let (_, public_key) = crate::reality::generate_keypair().unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "ws".into(),
            security: Some("reality".into()),
            tls_settings: None,
            reality_settings: Some(OutboundRealitySettings {
                server_name: Some("cover.example".into()),
                public_key: Some(public_key),
                short_id: Some("4ac97aaf8b9b0356".into()),
                ..OutboundRealitySettings::default()
            }),
            ws_settings: Some(OutboundWebsocketSettings::default()),
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains(
                    "REALITY does not support the selected application transport"
                )
        );
    }

    #[cfg(feature = "reality")]
    #[test]
    fn reality_compiles_core_client_handshake_settings() {
        let (_, public_key) = crate::reality::generate_keypair().unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("reality".into()),
            tls_settings: None,
            reality_settings: Some(OutboundRealitySettings {
                server_name: Some("cover.example".into()),
                public_key: Some(public_key),
                short_id: Some("4ac97aaf8b9b0356".into()),
                ..OutboundRealitySettings::default()
            }),
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };

        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("core REALITY client settings should compile");
        assert!(transport.is_reality());
    }

    #[cfg(feature = "reality")]
    #[test]
    fn reality_rejects_missing_or_unimplemented_client_fields() {
        let (_, public_key) = crate::reality::generate_keypair().unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let mut stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("reality".into()),
            tls_settings: None,
            reality_settings: Some(OutboundRealitySettings {
                public_key: Some(public_key),
                short_id: Some("4ac97aaf8b9b0356".into()),
                ..OutboundRealitySettings::default()
            }),
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("serverName is required")
        );

        let settings = stream.reality_settings.as_mut().unwrap();
        settings.server_name = Some("cover.example".into());
        settings.fingerprint = Some("chrome".into());
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("fingerprint is not supported yet")
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_requires_trust_and_rejects_unsafe_or_unimplemented_fields() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let mut stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                disable_system_root: true,
                ..OutboundTlsSettings::default()
            }),
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("no trusted root")
        );

        stream.tls_settings.as_mut().unwrap().allow_insecure = true;
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("allowInsecure")
        );
    }
}
