use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

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

#[cfg(any(feature = "tls", feature = "grpc_transport", test))]
use crate::address::Address;
#[cfg(feature = "grpc_transport")]
use crate::beginning::GrpcClientConfig;
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
    xhttp_outbound::{
        XhttpClientConfig, XhttpDownlinkConnector, XhttpH3Dialer, XhttpHttpVersion,
        XhttpStreamDialer,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct OutboundTransportConfig {
    security: OutboundSecurityConfig,
    protocol: OutboundProtocolConfig,
    xhttp_download: Option<Arc<XhttpDownloadTransportConfig>>,
}

#[derive(Debug, Clone)]
struct XhttpDownloadTransportConfig {
    server: NetLocation,
    transport: OutboundTransportConfig,
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
    #[cfg(feature = "grpc_transport")]
    Grpc(GrpcClientConfig),
    Xhttp(Box<XhttpClientConfig>),
}

#[derive(Clone)]
struct OutboundXhttpStreamDialer {
    resolver: Arc<dyn Resolver>,
    server: NetLocation,
    security: OutboundSecurityConfig,
}

#[async_trait]
impl XhttpStreamDialer for OutboundXhttpStreamDialer {
    async fn dial(&self) -> std::io::Result<Box<dyn AsyncStream>> {
        dial_secured_tcp(&self.resolver, &self.server, &self.security).await
    }
}

#[derive(Clone)]
struct OutboundXhttpH3Dialer {
    resolver: Arc<dyn Resolver>,
    server: NetLocation,
    security: OutboundSecurityConfig,
}

#[async_trait]
impl XhttpH3Dialer for OutboundXhttpH3Dialer {
    async fn dial_h3(
        &self,
        keep_alive: Option<std::time::Duration>,
    ) -> std::io::Result<(Arc<quinn::Endpoint>, quinn::Connection)> {
        dial_xhttp_h3(&self.resolver, &self.server, &self.security, keep_alive).await
    }
}

#[derive(Clone)]
struct OutboundXhttpDownlinkConnector {
    resolver: Arc<dyn Resolver>,
    config: Arc<XhttpDownloadTransportConfig>,
}

#[async_trait]
impl XhttpDownlinkConnector for OutboundXhttpDownlinkConnector {
    async fn open_downlink(
        &self,
        session_id: &str,
    ) -> std::io::Result<tokio::io::DuplexStream> {
        self.config
            .transport
            .open_xhttp_downlink(&self.resolver, &self.config.server, session_id)
            .await
    }
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub(crate) struct TlsOutboundTransportConfig {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    server_name_text: String,
}

impl OutboundTransportConfig {
    pub(crate) fn tcp() -> Self {
        Self {
            security: OutboundSecurityConfig::None,
            protocol: OutboundProtocolConfig::Tcp,
            xhttp_download: None,
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
        let mut download_settings = None;
        let mut protocol = match network.as_str() {
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
                if has_grpc_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides grpcSettings without network=grpc"
                    ));
                }
                if has_xhttp_settings(stream) {
                    return Err(format!(
                        "outbound {outbound_tag} provides xhttpSettings without network=xhttp"
                    ));
                }
                OutboundProtocolConfig::Tcp
            }
            "ws" | "websocket" => {
                if has_httpupgrade_settings(stream)
                    || has_grpc_settings(stream)
                    || has_xhttp_settings(stream)
                {
                    return Err(format!(
                        "outbound {outbound_tag} provides incompatible transport settings with network=ws"
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
                if has_websocket_settings(stream)
                    || has_grpc_settings(stream)
                    || has_xhttp_settings(stream)
                {
                    return Err(format!(
                        "outbound {outbound_tag} provides incompatible transport settings with network=httpupgrade"
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
            "grpc" => {
                if has_websocket_settings(stream)
                    || has_httpupgrade_settings(stream)
                    || has_xhttp_settings(stream)
                {
                    return Err(format!(
                        "outbound {outbound_tag} provides incompatible transport settings with network=grpc"
                    ));
                }
                #[cfg(feature = "grpc_transport")]
                {
                    compile_grpc_transport(server, stream, outbound_tag)
                        .map(OutboundProtocolConfig::Grpc)?
                }
                #[cfg(not(feature = "grpc_transport"))]
                {
                    let _ = server;
                    return Err(format!(
                        "outbound {outbound_tag} requires the grpc_transport feature"
                    ));
                }
            }
            "xhttp" | "splithttp" => {
                if has_websocket_settings(stream)
                    || has_httpupgrade_settings(stream)
                    || has_grpc_settings(stream)
                {
                    return Err(format!(
                        "outbound {outbound_tag} provides incompatible transport settings with network=xhttp"
                    ));
                }
                let mut settings = stream
                    .and_then(|stream| stream.xhttp_settings.clone())
                    .ok_or_else(|| {
                        format!(
                            "outbound {outbound_tag} requires xhttpSettings with network=xhttp"
                        )
                    })?;
                download_settings = take_download_settings(&mut settings)?;
                OutboundProtocolConfig::Xhttp(Box::new(XhttpClientConfig::compile(
                    server,
                    settings,
                    outbound_tag,
                )?))
            }
            other => {
                return Err(format!(
                    "outbound {outbound_tag} uses unsupported network {other}"
                ));
            }
        };
        if let OutboundProtocolConfig::Xhttp(config) = &mut protocol {
            let version = decide_xhttp_http_version(stream, outbound_tag)?;
            config.configure_http_version(version, outbound_tag)?;
        }
        let security = compile_security_transport(
            server,
            stream,
            outbound_tag,
            protocol_required_alpn(&protocol),
            protocol_supports_reality(&protocol),
        )?;
        let xhttp_download = download_settings
            .map(|settings| {
                compile_xhttp_download_transport(settings, outbound_tag)
                    .map(Arc::new)
            })
            .transpose()?;
        Ok(Self {
            security,
            protocol,
            xhttp_download,
        })
    }

    pub(crate) async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        server: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let downlink = self.xhttp_download.as_ref().map(|config| {
            Arc::new(OutboundXhttpDownlinkConnector {
                resolver: Arc::clone(resolver),
                config: Arc::clone(config),
            }) as Arc<dyn XhttpDownlinkConnector>
        });
        if let OutboundProtocolConfig::Xhttp(config) = &self.protocol {
            if config.uses_http3() {
                return self
                    .connect_xhttp_h3(resolver, server, config, downlink)
                    .await;
            }
            if config.uses_http1() {
                #[cfg(feature = "reality")]
                let reality =
                    matches!(&self.security, OutboundSecurityConfig::Reality(_));
                #[cfg(not(feature = "reality"))]
                let reality = false;
                let dialer: Arc<dyn XhttpStreamDialer> =
                    Arc::new(OutboundXhttpStreamDialer {
                        resolver: Arc::clone(resolver),
                        server: server.clone(),
                        security: self.security.clone(),
                    });
                return config
                    .connect_http1_with_dialer(
                        dialer,
                        !matches!(&self.security, OutboundSecurityConfig::None),
                        reality,
                        downlink,
                    )
                    .await;
            }
            #[cfg(feature = "reality")]
            let reality =
                matches!(&self.security, OutboundSecurityConfig::Reality(_));
            #[cfg(not(feature = "reality"))]
            let reality = false;
            let dialer: Arc<dyn XhttpStreamDialer> =
                Arc::new(OutboundXhttpStreamDialer {
                    resolver: Arc::clone(resolver),
                    server: server.clone(),
                    security: self.security.clone(),
                });
            return config
                .connect_h2_with_dialer(
                    dialer,
                    !matches!(&self.security, OutboundSecurityConfig::None),
                    reality,
                    downlink,
                )
                .await;
        }

        let stream = dial_secured_tcp(resolver, server, &self.security).await?;

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
            #[cfg(feature = "grpc_transport")]
            OutboundProtocolConfig::Grpc(config) => config.connect(stream).await,
            OutboundProtocolConfig::Xhttp(config) => {
                #[cfg(feature = "reality")]
                let reality =
                    matches!(&self.security, OutboundSecurityConfig::Reality(_));
                #[cfg(not(feature = "reality"))]
                let reality = false;
                config
                    .connect(
                        stream,
                        !matches!(&self.security, OutboundSecurityConfig::None),
                        reality,
                        downlink,
                    )
                    .await
            }
        }
    }

    async fn connect_xhttp_h3(
        &self,
        resolver: &Arc<dyn Resolver>,
        server: &NetLocation,
        config: &XhttpClientConfig,
        downlink: Option<Arc<dyn XhttpDownlinkConnector>>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let dialer: Arc<dyn XhttpH3Dialer> = Arc::new(OutboundXhttpH3Dialer {
            resolver: Arc::clone(resolver),
            server: server.clone(),
            security: self.security.clone(),
        });
        config.connect_h3_with_dialer(dialer, false, downlink).await
    }

    async fn open_xhttp_downlink(
        &self,
        resolver: &Arc<dyn Resolver>,
        server: &NetLocation,
        session_id: &str,
    ) -> std::io::Result<tokio::io::DuplexStream> {
        let OutboundProtocolConfig::Xhttp(config) = &self.protocol else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP download transport is not XHTTP",
            ));
        };
        let secure = !matches!(&self.security, OutboundSecurityConfig::None);
        if config.uses_http1() {
            let dialer: Arc<dyn XhttpStreamDialer> =
                Arc::new(OutboundXhttpStreamDialer {
                    resolver: Arc::clone(resolver),
                    server: server.clone(),
                    security: self.security.clone(),
                });
            return config.open_http1_downlink(dialer, secure, session_id).await;
        }
        if config.uses_http3() {
            let dialer: Arc<dyn XhttpH3Dialer> = Arc::new(OutboundXhttpH3Dialer {
                resolver: Arc::clone(resolver),
                server: server.clone(),
                security: self.security.clone(),
            });
            return config
                .open_h3_downlink_with_dialer(dialer, session_id)
                .await;
        }
        let dialer: Arc<dyn XhttpStreamDialer> =
            Arc::new(OutboundXhttpStreamDialer {
                resolver: Arc::clone(resolver),
                server: server.clone(),
                security: self.security.clone(),
            });
        config
            .open_h2_downlink_with_dialer(dialer, secure, session_id)
            .await
    }

    pub(crate) fn supports_direct_udp(&self) -> bool {
        matches!(self.security, OutboundSecurityConfig::None)
            && matches!(self.protocol, OutboundProtocolConfig::Tcp)
    }

    #[cfg(test)]
    pub(crate) fn is_tcp(&self) -> bool {
        self.supports_direct_udp()
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

    #[cfg(all(test, feature = "grpc_transport"))]
    pub(crate) fn is_grpc(&self) -> bool {
        matches!(self.protocol, OutboundProtocolConfig::Grpc(_))
    }

    #[cfg(test)]
    pub(crate) fn is_xhttp(&self) -> bool {
        matches!(self.protocol, OutboundProtocolConfig::Xhttp(_))
    }
}

fn take_download_settings(settings: &mut Value) -> Result<Option<Value>, String> {
    let object = settings
        .as_object_mut()
        .ok_or_else(|| "XHTTP settings must be a JSON object".to_string())?;
    Ok(object.remove("downloadSettings"))
}

fn compile_xhttp_download_transport(
    settings: Value,
    outbound_tag: &str,
) -> Result<XhttpDownloadTransportConfig, String> {
    let mut object = settings.as_object().cloned().ok_or_else(|| {
        format!("XHTTP outbound {outbound_tag} downloadSettings must be an object")
    })?;
    let address = object
        .remove("address")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            format!(
                "XHTTP outbound {outbound_tag} downloadSettings requires address"
            )
        })?;
    let port = object
        .remove("port")
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            format!(
                "XHTTP outbound {outbound_tag} downloadSettings requires a valid port"
            )
        })?;
    let xhttp_key = if object.contains_key("xhttpSettings") {
        "xhttpSettings"
    } else {
        "splithttpSettings"
    };
    let xhttp_value = object.get_mut(xhttp_key).ok_or_else(|| {
        format!(
            "XHTTP outbound {outbound_tag} downloadSettings requires xhttpSettings"
        )
    })?;
    if xhttp_value
        .as_object()
        .is_some_and(|value| value.contains_key("downloadSettings"))
    {
        return Err(format!(
            "XHTTP outbound {outbound_tag} does not allow recursive downloadSettings"
        ));
    }
    if !object.contains_key("network") {
        object.insert("network".into(), Value::String("xhttp".into()));
    }
    let stream = serde_json::from_value::<OutboundStreamSettings>(Value::Object(
        object,
    ))
    .map_err(|error| {
        format!(
            "XHTTP outbound {outbound_tag} has invalid downloadSettings: {error}"
        )
    })?;
    if !matches!(
        stream.network.trim().to_ascii_lowercase().as_str(),
        "xhttp" | "splithttp"
    ) {
        return Err(format!(
            "XHTTP outbound {outbound_tag} downloadSettings network must be xhttp"
        ));
    }
    let server = NetLocation::from_str(&address, Some(port)).map_err(|error| {
        format!(
            "XHTTP outbound {outbound_tag} has invalid downloadSettings address: {error}"
        )
    })?;
    let transport = OutboundTransportConfig::compile(
        &server,
        Some(&stream),
        &format!("{outbound_tag}#download"),
    )?;
    Ok(XhttpDownloadTransportConfig { server, transport })
}

async fn dial_xhttp_h3(
    resolver: &Arc<dyn Resolver>,
    server: &NetLocation,
    security: &OutboundSecurityConfig,
    keep_alive: Option<std::time::Duration>,
) -> std::io::Result<(Arc<quinn::Endpoint>, quinn::Connection)> {
    #[cfg(feature = "tls")]
    {
        let tls = match security {
            OutboundSecurityConfig::Tls(config) => config,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "XHTTP HTTP/3 requires security=tls",
                ));
            }
        };
        let remote = resolve_single_address(resolver, server).await?;
        let local = if remote.is_ipv6() {
            std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        } else {
            std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        };
        let mut endpoint =
            quinn::Endpoint::client(local).map_err(std::io::Error::other)?;
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            Arc::clone(&tls.client_config),
        )
        .map_err(std::io::Error::other)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        let mut transport = quinn::TransportConfig::default();
        let idle_timeout = std::time::Duration::from_secs(300)
            .try_into()
            .map_err(std::io::Error::other)?;
        transport
            .max_concurrent_bidi_streams(4096_u32.into())
            .max_concurrent_uni_streams(4096_u32.into())
            .max_idle_timeout(Some(idle_timeout))
            .keep_alive_interval(keep_alive)
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into());
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(remote, &tls.server_name_text)
            .map_err(std::io::Error::other)?
            .await
            .map_err(std::io::Error::other)?;
        Ok((Arc::new(endpoint), connection))
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = (resolver, server, security, keep_alive);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "XHTTP HTTP/3 requires the tls feature",
        ))
    }
}

async fn dial_secured_tcp(
    resolver: &Arc<dyn Resolver>,
    server: &NetLocation,
    security: &OutboundSecurityConfig,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let address = resolve_single_address(resolver, server).await?;
    let socket = new_tcp_socket(None, address.is_ipv6())?;
    let stream = socket.connect(address).await?;
    stream.set_nodelay(true)?;
    let stream: Box<dyn AsyncStream> = Box::new(stream);

    match security {
        OutboundSecurityConfig::None => Ok(stream),
        #[cfg(feature = "tls")]
        OutboundSecurityConfig::Tls(config) => {
            let connector = TlsConnector::from(Arc::clone(&config.client_config));
            let stream = connector
                .connect(config.server_name.clone(), stream)
                .await
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("outbound TLS handshake failed: {error}"),
                    )
                })?;
            Ok(Box::new(stream))
        }
        #[cfg(feature = "reality")]
        OutboundSecurityConfig::Reality(config) => {
            let session =
                RealityClientConnection::new(config.clone()).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("failed to initialize outbound REALITY: {error}"),
                    )
                })?;
            Ok(Box::new(RealityTlsStream::new(stream, session)))
        }
    }
}

fn decide_xhttp_http_version(
    stream: Option<&OutboundStreamSettings>,
    _outbound_tag: &str,
) -> Result<XhttpHttpVersion, String> {
    let security = stream
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match security.as_str() {
        "reality" => Ok(XhttpHttpVersion::Http2),
        "" | "none" => Ok(XhttpHttpVersion::Http2),
        "tls" => {
            let alpn = stream
                .and_then(|stream| stream.tls_settings.as_ref())
                .map(|settings| settings.alpn.as_slice())
                .unwrap_or_default();
            if alpn.len() == 1 {
                let protocol = alpn[0].trim().to_ascii_lowercase();
                if protocol == "http/1.1" {
                    return Ok(XhttpHttpVersion::Http1);
                }
                if protocol == "h3" {
                    return Ok(XhttpHttpVersion::Http3);
                }
            }
            Ok(XhttpHttpVersion::Http2)
        }
        _ => Ok(XhttpHttpVersion::Http2),
    }
}

fn protocol_required_alpn(
    protocol: &OutboundProtocolConfig,
) -> Option<&'static [u8]> {
    match protocol {
        OutboundProtocolConfig::Tcp => None,
        #[cfg(feature = "ws")]
        OutboundProtocolConfig::Websocket(_) => Some(b"http/1.1"),
        #[cfg(feature = "httpupgrade")]
        OutboundProtocolConfig::HttpUpgrade(_) => Some(b"http/1.1"),
        #[cfg(feature = "grpc_transport")]
        OutboundProtocolConfig::Grpc(_) => Some(b"h2"),
        OutboundProtocolConfig::Xhttp(config) => Some(config.required_alpn()),
    }
}

fn protocol_supports_reality(protocol: &OutboundProtocolConfig) -> bool {
    match protocol {
        OutboundProtocolConfig::Tcp => true,
        #[cfg(feature = "grpc_transport")]
        OutboundProtocolConfig::Grpc(_) => true,
        OutboundProtocolConfig::Xhttp(_) => true,
        #[cfg(feature = "ws")]
        OutboundProtocolConfig::Websocket(_) => false,
        #[cfg(feature = "httpupgrade")]
        OutboundProtocolConfig::HttpUpgrade(_) => false,
    }
}

fn compile_security_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
    required_alpn: Option<&'static [u8]>,
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
                compile_tls_transport(server, stream, outbound_tag, required_alpn)
                    .map(OutboundSecurityConfig::Tls)
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (server, required_alpn, supports_reality);
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
                let _ = (server, required_alpn, supports_reality);
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

fn has_grpc_settings(stream: Option<&OutboundStreamSettings>) -> bool {
    #[cfg(feature = "grpc_transport")]
    {
        stream.is_some_and(|stream| stream.grpc_settings.is_some())
    }
    #[cfg(not(feature = "grpc_transport"))]
    {
        let _ = stream;
        false
    }
}

fn has_xhttp_settings(stream: Option<&OutboundStreamSettings>) -> bool {
    stream.is_some_and(|stream| stream.xhttp_settings.is_some())
}

#[cfg(feature = "grpc_transport")]
fn compile_grpc_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
) -> Result<GrpcClientConfig, String> {
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
    let fallback_authority = tls_server_name
        .map(str::to_string)
        .unwrap_or_else(|| authority_for_server(server));
    GrpcClientConfig::compile(
        stream.and_then(|stream| stream.grpc_settings.as_ref()),
        &fallback_authority,
        outbound_tag,
    )
}

#[cfg(feature = "grpc_transport")]
fn authority_for_server(server: &NetLocation) -> String {
    match server.address() {
        Address::Ipv6(address) => format!("[{address}]"),
        address => address.to_string(),
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
    required_alpn: Option<&'static [u8]>,
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
    if let Some(required_alpn) = required_alpn
        && !client_config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.as_slice() == required_alpn)
    {
        client_config.alpn_protocols.push(required_alpn.to_vec());
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
    let server_name_text = server_name.trim().to_string();
    let server_name = ServerName::try_from(server_name_text.clone()).map_err(|error| {
        format!(
            "outbound {outbound_tag} has invalid TLS serverName {server_name_text}: {error}"
        )
    })?;

    Ok(TlsOutboundTransportConfig {
        client_config: Arc::new(client_config),
        server_name,
        server_name_text,
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
    #[cfg(feature = "grpc_transport")]
    use crate::config::def::OutboundGrpcSettings;
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("WebSocket settings should compile");
        assert!(transport.is_websocket());
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_compiles_as_an_http2_application_transport() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "grpc".into(),
            security: None,
            tls_settings: None,
            #[cfg(feature = "reality")]
            reality_settings: None,
            #[cfg(feature = "ws")]
            ws_settings: None,
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
            grpc_settings: Some(OutboundGrpcSettings {
                service_name: Some("chimera-grpc".into()),
                ..OutboundGrpcSettings::default()
            }),
            xhttp_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("gRPC settings should compile");
        assert!(transport.is_grpc());
    }

    #[cfg(all(feature = "tls", feature = "grpc_transport"))]
    #[test]
    fn tls_grpc_composes_security_and_http2_layers() {
        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "grpc".into(),
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
            #[cfg(feature = "httpupgrade")]
            httpupgrade_settings: None,
            grpc_settings: Some(OutboundGrpcSettings {
                service_name: Some("chimera-grpc".into()),
                ..OutboundGrpcSettings::default()
            }),
            xhttp_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("TLS and gRPC should compose");
        assert!(transport.is_tls());
        assert!(transport.is_grpc());
    }

    #[cfg(all(feature = "reality", feature = "grpc_transport"))]
    #[test]
    fn reality_grpc_composes_security_and_http2_layers() {
        let (_, public_key) = crate::reality::generate_keypair().unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "grpc".into(),
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
            grpc_settings: Some(OutboundGrpcSettings {
                service_name: Some("chimera-grpc".into()),
                ..OutboundGrpcSettings::default()
            }),
            xhttp_settings: None,
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("REALITY and gRPC should compose");
        assert!(transport.is_reality());
        assert!(transport.is_grpc());
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
            #[cfg(feature = "grpc_transport")]
            grpc_settings: None,
            xhttp_settings: None,
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
