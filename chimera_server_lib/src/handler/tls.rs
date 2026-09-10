use std::{
    fs::File,
    io::{self, BufReader, Cursor},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
            PrivateSec1KeyDer,
        },
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
        version::{TLS12, TLS13},
    },
};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

use crate::{
    async_stream::AsyncStream,
    config::server_config::{TlsCertificateConfig, TlsCertificateUsage},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};
#[cfg(feature = "vless")]
use crate::{
    config::server_config::{VlessFallback, VlessUser},
    handler::vless_handler::{VisionRecordIo, setup_tls_mixed_vless_server_stream},
};

enum TlsInner {
    Handler(Box<dyn TcpServerHandler>),
    #[cfg(feature = "vless")]
    VisionVless {
        users: Vec<VlessUser>,
        fallbacks: Vec<VlessFallback>,
        inbound_tag: String,
    },
}

pub struct TlsServerHandler {
    acceptor: TlsAcceptor,
    inner: TlsInner,
}

#[derive(Debug)]
struct XraySniCertificate {
    certified_key: Arc<CertifiedKey>,
    names: Vec<String>,
}

#[derive(Debug)]
struct XraySniResolver {
    certificates: Vec<XraySniCertificate>,
    reject_unknown_sni: bool,
}

impl ResolvesServerCert for XraySniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name().unwrap_or_default();
        let index = select_sni_certificate(
            self.certificates
                .iter()
                .map(|certificate| certificate.names.as_slice()),
            sni,
            self.reject_unknown_sni,
        )?;
        Some(self.certificates[index].certified_key.clone())
    }
}

fn select_sni_certificate<'a>(
    certificate_names: impl Iterator<Item = &'a [String]>,
    sni: &str,
    reject_unknown_sni: bool,
) -> Option<usize> {
    certificate_names
        .enumerate()
        .find_map(|(index, names)| sni_matches_names(sni, names).then_some(index))
        .or_else(|| (!reject_unknown_sni).then_some(0))
}

fn sni_matches_names(sni: &str, names: &[String]) -> bool {
    let sni = sni.to_ascii_lowercase();
    let wildcard = sni.find('.').map(|index| format!("*{}", &sni[index..]));
    names
        .iter()
        .any(|name| name == &sni || wildcard.as_deref() == Some(name.as_str()))
}

impl TlsServerHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificates: Vec<TlsCertificateConfig>,
        alpn_protocols: Vec<String>,
        enable_session_resumption: bool,
        reject_unknown_sni: bool,
        min_version: Option<String>,
        max_version: Option<String>,
        _server_name: Option<String>,
        inner: Box<dyn TcpServerHandler>,
    ) -> io::Result<Self> {
        let config = build_server_config(
            &certificates,
            &alpn_protocols,
            enable_session_resumption,
            reject_unknown_sni,
            min_version.as_deref(),
            max_version.as_deref(),
        )?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            inner: TlsInner::Handler(inner),
        })
    }

    #[cfg(feature = "vless")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_vision_vless(
        certificates: Vec<TlsCertificateConfig>,
        alpn_protocols: Vec<String>,
        enable_session_resumption: bool,
        reject_unknown_sni: bool,
        min_version: Option<String>,
        max_version: Option<String>,
        _server_name: Option<String>,
        users: &[VlessUser],
        fallbacks: &[VlessFallback],
        inbound_tag: &str,
    ) -> io::Result<Self> {
        let config = build_server_config(
            &certificates,
            &alpn_protocols,
            enable_session_resumption,
            reject_unknown_sni,
            min_version.as_deref(),
            max_version.as_deref(),
        )?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            inner: TlsInner::VisionVless {
                users: users.to_vec(),
                fallbacks: fallbacks.to_vec(),
                inbound_tag: inbound_tag.to_string(),
            },
        })
    }
}

fn tls_inner_manages_handshake_timeout(inner: &TlsInner) -> bool {
    match inner {
        TlsInner::Handler(inner) => inner.manages_handshake_timeout(),
        #[cfg(feature = "vless")]
        TlsInner::VisionVless { .. } => true,
    }
}

impl std::fmt::Debug for TlsServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerHandler").finish()
    }
}

#[async_trait]
impl TcpServerHandler for TlsServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        tls_inner_manages_handshake_timeout(&self.inner)
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        mut context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        match &self.inner {
            TlsInner::Handler(inner) => {
                let timeout = inner.pre_transport_handshake_timeout(&context);
                let setup = async {
                    let tls_stream = self.acceptor.accept(server_stream).await?;
                    let connection = tls_stream.get_ref().1;
                    context.server_name =
                        connection.server_name().map(ToOwned::to_owned);
                    context.alpn_protocol = connection
                        .alpn_protocol()
                        .and_then(|value| std::str::from_utf8(value).ok())
                        .map(ToOwned::to_owned);
                    inner
                        .setup_server_stream_with_context(
                            Box::new(tls_stream),
                            context,
                        )
                        .await
                };
                let Some(timeout) = timeout else {
                    return setup.await;
                };
                tokio::time::timeout(timeout, setup).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS inner handshake timed out",
                    )
                })?
            }
            #[cfg(feature = "vless")]
            TlsInner::VisionVless {
                users,
                fallbacks,
                inbound_tag,
            } => {
                let timeout = context
                    .runtime
                    .as_ref()
                    .map(|runtime| runtime.xray_handshake_timeout_for_level(0))
                    .unwrap_or(Duration::from_secs(60));
                let dynamic_users = context
                    .runtime
                    .as_ref()
                    .and_then(|runtime| runtime.vless_users_snapshot(inbound_tag));
                let users = dynamic_users.as_deref().unwrap_or(users);
                let setup = async {
                    let tls_stream = self
                        .acceptor
                        .accept(VisionRecordIo::new(server_stream))
                        .await?;
                    setup_tls_mixed_vless_server_stream(
                        tls_stream,
                        users,
                        fallbacks,
                        inbound_tag,
                    )
                    .await
                };
                tokio::time::timeout(timeout, setup).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS VLESS handshake timed out",
                    )
                })?
            }
        }
    }
}

pub(crate) fn build_server_config(
    certificates: &[TlsCertificateConfig],
    alpn_protocols: &[String],
    enable_session_resumption: bool,
    reject_unknown_sni: bool,
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> io::Result<rustls::ServerConfig> {
    let encipherment_certificates = certificates
        .iter()
        .filter(|certificate| {
            matches!(certificate.usage, TlsCertificateUsage::Encipherment)
        })
        .collect::<Vec<_>>();
    let certificate = encipherment_certificates.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no encipherment certificate found for TLS server",
        )
    })?;
    let cert_chain = load_certs(certificate)?;
    let private_key = load_private_key(certificate)?;

    let versions = tls_versions(min_version, max_version)?;
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if reject_unknown_sni || encipherment_certificates.len() > 1 {
        let mut sni_certificates =
            Vec::with_capacity(encipherment_certificates.len());
        for certificate in encipherment_certificates {
            let cert_chain = load_certs(certificate)?;
            let private_key = load_private_key(certificate)?;
            let certified_key = CertifiedKey::from_der(
                cert_chain.clone(),
                private_key,
                config.crypto_provider(),
            )
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            sni_certificates.push(XraySniCertificate {
                certified_key: Arc::new(certified_key),
                names: certificate_dns_names(&cert_chain[0])?,
            });
        }
        config.cert_resolver = Arc::new(XraySniResolver {
            certificates: sni_certificates,
            reject_unknown_sni,
        });
    }

    config.alpn_protocols = tls_alpn_protocols(alpn_protocols);
    config.send_tls13_tickets = if enable_session_resumption { 2 } else { 0 };

    Ok(config)
}

fn certificate_dns_names(
    certificate: &CertificateDer<'_>,
) -> io::Result<Vec<String>> {
    let (_, parsed) =
        x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
            .map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, err.to_string())
            })?;
    let mut names = Vec::new();
    if let Some(common_name) = parsed.subject().iter_common_name().next()
        && let Ok(common_name) = common_name.as_str()
    {
        names.push(common_name.to_ascii_lowercase());
    }
    if let Ok(Some(subject_alt_name)) = parsed.subject_alternative_name() {
        for name in &subject_alt_name.value.general_names {
            if let GeneralName::DNSName(name) = name {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    Ok(names)
}

fn load_certs(
    certificate: &TlsCertificateConfig,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = open_pem_reader(
        certificate.certificate_path.as_deref(),
        &certificate.certificate_pem,
        "certificate",
    )?;
    let certs: Vec<CertificateDer<'static>> =
        certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificates found in certificate file",
        ));
    }

    Ok(certs)
}

fn load_private_key(
    certificate: &TlsCertificateConfig,
) -> io::Result<PrivateKeyDer<'static>> {
    let key_bytes = certificate
        .key_pem
        .as_deref()
        .filter(|bytes| !bytes.is_empty());

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs8KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs1KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = ec_private_keys(&mut reader)
        .collect::<Result<Vec<PrivateSec1KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "no valid private keys found",
    ))
}

fn open_pem_reader(
    path: Option<&str>,
    inline_pem: &[u8],
    label: &str,
) -> io::Result<BufReader<Box<dyn io::Read>>> {
    if let Some(path) = path {
        let file = File::open(path)?;
        return Ok(BufReader::new(Box::new(file)));
    }

    if inline_pem.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no {label} provided"),
        ));
    }

    Ok(BufReader::new(Box::new(Cursor::new(inline_pem.to_vec()))))
}

fn tls_alpn_protocols(alpn_protocols: &[String]) -> Vec<Vec<u8>> {
    if alpn_protocols.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect()
    }
}

fn tls_versions(
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let parse = |value: Option<&str>, default: u8, field: &str| -> io::Result<u8> {
        match value.unwrap_or_default().trim() {
            "" => Ok(default),
            "1.2" => Ok(12),
            "1.3" => Ok(13),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported tls {field}: {other}"),
            )),
        }
    };
    let minimum = parse(min_version, 12, "minVersion")?;
    let maximum = parse(max_version, 13, "maxVersion")?;
    if minimum > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls minVersion exceeds maxVersion",
        ));
    }

    Ok(match (minimum, maximum) {
        (12, 12) => vec![&TLS12],
        (12, 13) => vec![&TLS13, &TLS12],
        (13, 13) => vec![&TLS13],
        _ => unreachable!("validated TLS version bounds"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "vless")]
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            server_config::{ServerConfig, ServerProxyConfig},
        },
        handler::vless_handler::protocol::{
            COMMAND_TCP, XTLS_VISION_FLOW, encode_flow_addon_data,
        },
        runtime::RuntimeState,
    };
    #[cfg(feature = "vless")]
    use std::net::Ipv4Addr;
    #[cfg(feature = "vless")]
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    #[cfg(feature = "vless")]
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct ManagedTestHandler;

    #[async_trait]
    impl TcpServerHandler for ManagedTestHandler {
        fn manages_handshake_timeout(&self) -> bool {
            true
        }

        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Err(io::Error::other("test handler is not executed"))
        }
    }

    #[test]
    fn tls_propagates_inner_handshake_timeout_ownership() {
        let inner = TlsInner::Handler(Box::new(ManagedTestHandler));
        assert!(tls_inner_manages_handshake_timeout(&inner));
    }

    #[cfg(feature = "vless")]
    fn vision_vless_tcp_request(user_id: [u8; 16]) -> Vec<u8> {
        let addon = encode_flow_addon_data(XTLS_VISION_FLOW)
            .expect("valid VLESS Vision addon");
        let mut request = Vec::with_capacity(32 + addon.len());
        request.push(0);
        request.extend_from_slice(&user_id);
        request.push(addon.len() as u8);
        request.extend_from_slice(&addon);
        request.push(COMMAND_TCP);
        request.extend_from_slice(&443u16.to_be_bytes());
        request.push(1);
        request.extend_from_slice(&[127, 0, 0, 1]);
        request
    }

    #[cfg(feature = "vless")]
    async fn setup_tls_vless_request(
        handler: Arc<TlsServerHandler>,
        runtime: RuntimeState,
        connector: &TlsConnector,
        request: Vec<u8>,
    ) -> TcpServerSetupResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TLS VLESS test listener");
        let address = listener.local_addr().expect("TLS VLESS listener address");
        let server_task = tokio::spawn(async move {
            let (server_io, _) = listener.accept().await?;
            handler
                .setup_server_stream_with_context(
                    Box::new(server_io),
                    TcpServerConnectionContext {
                        runtime: Some(runtime),
                        ..TcpServerConnectionContext::default()
                    },
                )
                .await
        });
        let client_io = TcpStream::connect(address)
            .await
            .expect("connect TLS VLESS test listener");
        let mut client = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost")
                    .expect("valid test server name"),
                client_io,
            )
            .await
            .expect("establish test TLS connection");
        client
            .write_all(&request)
            .await
            .expect("write VLESS request over TLS");
        client.flush().await.expect("flush VLESS TLS request");
        let result = server_task
            .await
            .expect("TLS VLESS server task")
            .expect("TLS VLESS setup");
        drop(client);
        result
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn tls_vless_handler_accepts_dynamic_vision_without_rebuild() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate test certificate");
        let certificate = TlsCertificateConfig {
            certificate_path: None,
            certificate_pem: generated.cert.pem().into_bytes(),
            key_path: None,
            key_pem: Some(generated.signing_key.serialize_pem().into_bytes()),
            usage: TlsCertificateUsage::Encipherment,
        };
        let plain_user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let vision_user_id = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
        let vision_user_bytes = [
            0xe0, 0x41, 0xe7, 0x3e, 0xa0, 0xa0, 0x49, 0xf5, 0x97, 0x54, 0x64, 0x01,
            0xaa, 0x62, 0x1f, 0xb7,
        ];
        let plain_user = VlessUser {
            user_id: plain_user_id.into(),
            user_label: "plain-user".into(),
            user_level: 0,
            flow: String::new(),
        };
        let handler = Arc::new(
            TlsServerHandler::new_vision_vless(
                vec![certificate],
                Vec::new(),
                true,
                false,
                None,
                None,
                None,
                std::slice::from_ref(&plain_user),
                &[],
                "tls-vless-dynamic",
            )
            .expect("build mixed TLS VLESS handler"),
        );
        let runtime = RuntimeState::new(
            vec![ServerConfig {
                tag: "tls-vless-dynamic".into(),
                bind_location: BindLocation::Address(NetLocation::new(
                    Address::Ipv4(Ipv4Addr::LOCALHOST),
                    0,
                )),
                protocol: ServerProxyConfig::Vless {
                    users: vec![plain_user],
                    fallbacks: Vec::new(),
                },
                transport: Transport::Tcp,
                quic_settings: None,
                sniffing: None,
                tcp_socket_policy: None,
            }],
            Vec::new(),
        );
        runtime
            .alter_inbound_users(
                "tls-vless-dynamic",
                |_| -> Result<ServerConfig, ()> {
                    panic!("dynamic VLESS user update must not rebuild TLS handler")
                },
                |users| {
                    users.push(VlessUser {
                        user_id: vision_user_id.into(),
                        user_label: "vision-user".into(),
                        user_level: 7,
                        flow: XTLS_VISION_FLOW.into(),
                    });
                    Ok(true)
                },
            )
            .await
            .expect("add dynamic Vision user");

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                generated.cert.der().to_vec(),
            ))
            .expect("trust test certificate");
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));

        let vision = setup_tls_vless_request(
            handler.clone(),
            runtime.clone(),
            &connector,
            vision_vless_tcp_request(vision_user_bytes),
        )
        .await;
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = vision
        else {
            panic!("Vision user should produce TCP forwarding");
        };
        let context = traffic_context.expect("Vision traffic context");
        assert_eq!(context.identity.as_deref(), Some("vision-user"));
        assert_eq!(context.user_level, 7);
    }

    #[test]
    fn empty_alpn_uses_xray_server_defaults() {
        assert_eq!(
            tls_alpn_protocols(&[]),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            tls_alpn_protocols(&["custom".into()]),
            vec![b"custom".to_vec()]
        );
    }

    #[test]
    fn tls_versions_apply_xray_server_bounds() {
        assert_eq!(tls_versions(None, None).unwrap(), vec![&TLS13, &TLS12]);
        assert_eq!(
            tls_versions(Some("1.2"), Some("1.2")).unwrap(),
            vec![&TLS12]
        );
        assert_eq!(tls_versions(Some("1.3"), None).unwrap(), vec![&TLS13]);
        assert!(tls_versions(Some("1.3"), Some("1.2")).is_err());
        assert!(tls_versions(Some("1.1"), None).is_err());
    }

    #[test]
    fn multiple_certificates_follow_xray_sni_selection_and_fallback() {
        let names = [
            vec!["first.example".into()],
            vec!["second.example".into(), "*.example.net".into()],
        ];
        let certificate_names = || names.iter().map(Vec::as_slice);
        assert_eq!(
            select_sni_certificate(certificate_names(), "second.example", false),
            Some(1)
        );
        assert_eq!(
            select_sni_certificate(certificate_names(), "api.example.net", false),
            Some(1)
        );
        assert_eq!(
            select_sni_certificate(certificate_names(), "unknown.example", false),
            Some(0)
        );
        assert_eq!(
            select_sni_certificate(certificate_names(), "unknown.example", true),
            None
        );
    }

    #[test]
    fn sni_matching_follows_xray_exact_and_wildcard_rules() {
        let names = vec!["proxy.example".into(), "*.example.com".into()];
        assert!(sni_matches_names("PROXY.EXAMPLE", &names));
        assert!(sni_matches_names("api.example.com", &names));
        assert!(!sni_matches_names("deep.api.example.com", &names));
        assert!(!sni_matches_names("unknown.example", &names));
    }

    #[test]
    fn certificate_dns_names_reads_subject_alt_names() {
        let generated = rcgen::generate_simple_self_signed([
            "proxy.example".to_string(),
            "api.example.com".to_string(),
        ])
        .unwrap();
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let names = certificate_dns_names(&certificate).unwrap();
        assert!(names.iter().any(|name| name == "proxy.example"));
        assert!(names.iter().any(|name| name == "api.example.com"));
    }
}
