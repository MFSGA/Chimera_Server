use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::future::FutureExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::watch,
};
use tracing::debug;

use crate::address::{Address, NetLocation};

const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;
const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

pub trait Resolver: Send + Sync {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;
}

/// Configuration for the shared DNS cache used by [`CachedResolver`].
#[derive(Debug, Clone, Copy)]
pub struct ResolverCacheOptions {
    pub positive_ttl: Duration,
    pub negative_ttl: Duration,
    pub max_entries: usize,
}

impl Default for ResolverCacheOptions {
    fn default() -> Self {
        Self {
            positive_ttl: DEFAULT_POSITIVE_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }
}

/// Point-in-time counters for resolver cache behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolverCacheStats {
    pub cache_entries: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub coalesced_waiters: u64,
    pub upstream_lookups: u64,
    pub upstream_failures: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone)]
struct CachedLookupError {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl CachedLookupError {
    fn from_io(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: Arc::from(error.to_string()),
        }
    }

    fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

type CachedLookupResult = Result<Vec<SocketAddr>, CachedLookupError>;

enum CacheEntry {
    Ready {
        expires_at: Instant,
        result: CachedLookupResult,
    },
    InFlight {
        id: u64,
        sender: watch::Sender<Option<CachedLookupResult>>,
    },
}

struct ResolverCache {
    options: ResolverCacheOptions,
    entries: Mutex<HashMap<NetLocation, CacheEntry>>,
    next_lookup_id: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    coalesced_waiters: AtomicU64,
    upstream_lookups: AtomicU64,
    upstream_failures: AtomicU64,
    evictions: AtomicU64,
}

impl ResolverCache {
    fn new(options: ResolverCacheOptions) -> Self {
        Self {
            options: ResolverCacheOptions {
                max_entries: options.max_entries.max(1),
                ..options
            },
            entries: Mutex::new(HashMap::new()),
            next_lookup_id: AtomicU64::new(1),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            coalesced_waiters: AtomicU64::new(0),
            upstream_lookups: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<NetLocation, CacheEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn prepare(&self, location: &NetLocation) -> CacheDecision {
        let now = Instant::now();
        let mut entries = self.entries();

        if let Some(entry) = entries.get(location) {
            match entry {
                CacheEntry::Ready { expires_at, result } if *expires_at > now => {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return CacheDecision::Ready(result.clone());
                }
                CacheEntry::InFlight { sender, .. } => {
                    self.coalesced_waiters.fetch_add(1, Ordering::Relaxed);
                    return CacheDecision::Wait(sender.subscribe());
                }
                CacheEntry::Ready { .. } => {}
            }
        }

        entries.remove(location);
        entries.retain(|_, entry| match entry {
            CacheEntry::Ready { expires_at, .. } => *expires_at > now,
            CacheEntry::InFlight { .. } => true,
        });

        if entries.len() >= self.options.max_entries
            && let Some(key) = entries.iter().find_map(|(key, entry)| {
                matches!(entry, CacheEntry::Ready { .. }).then(|| key.clone())
            })
        {
            entries.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }

        let id = self.next_lookup_id.fetch_add(1, Ordering::Relaxed);
        let (sender, _) = watch::channel(None);
        entries.insert(
            location.clone(),
            CacheEntry::InFlight {
                id,
                sender: sender.clone(),
            },
        );
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.upstream_lookups.fetch_add(1, Ordering::Relaxed);
        CacheDecision::Resolve { id, sender }
    }

    fn finish(
        &self,
        location: &NetLocation,
        id: u64,
        sender: &watch::Sender<Option<CachedLookupResult>>,
        result: CachedLookupResult,
    ) {
        if result.is_err() {
            self.upstream_failures.fetch_add(1, Ordering::Relaxed);
        }
        let _ = sender.send(Some(result.clone()));
        let ttl = if result.is_ok() {
            self.options.positive_ttl
        } else {
            self.options.negative_ttl
        };
        let mut entries = self.entries();
        if matches!(entries.get(location), Some(CacheEntry::InFlight { id: active, .. }) if *active == id)
        {
            entries.insert(
                location.clone(),
                CacheEntry::Ready {
                    expires_at: Instant::now() + ttl,
                    result,
                },
            );
        }
    }

    fn stats(&self) -> ResolverCacheStats {
        ResolverCacheStats {
            cache_entries: self.entries().len(),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            coalesced_waiters: self.coalesced_waiters.load(Ordering::Relaxed),
            upstream_lookups: self.upstream_lookups.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    fn cancel(
        &self,
        location: &NetLocation,
        id: u64,
        sender: &watch::Sender<Option<CachedLookupResult>>,
    ) {
        let error = CachedLookupError {
            kind: io::ErrorKind::Interrupted,
            message: Arc::from("DNS lookup task was cancelled"),
        };
        let _ = sender.send(Some(Err(error)));
        let mut entries = self.entries();
        if matches!(entries.get(location), Some(CacheEntry::InFlight { id: active, .. }) if *active == id)
        {
            entries.remove(location);
        }
    }
}

enum CacheDecision {
    Ready(CachedLookupResult),
    Wait(watch::Receiver<Option<CachedLookupResult>>),
    Resolve {
        id: u64,
        sender: watch::Sender<Option<CachedLookupResult>>,
    },
}

struct LookupGuard {
    cache: Arc<ResolverCache>,
    location: NetLocation,
    id: u64,
    sender: watch::Sender<Option<CachedLookupResult>>,
    completed: bool,
}

impl LookupGuard {
    fn complete(mut self, result: CachedLookupResult) {
        self.cache
            .finish(&self.location, self.id, &self.sender, result);
        self.completed = true;
    }
}

impl Drop for LookupGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.cancel(&self.location, self.id, &self.sender);
        }
    }
}

/// Resolver wrapper that caches positive and negative results and coalesces
/// concurrent lookups for the same destination.
#[derive(Clone)]
pub struct CachedResolver {
    inner: Arc<dyn Resolver>,
    cache: Arc<ResolverCache>,
}

impl CachedResolver {
    pub fn new(inner: Arc<dyn Resolver>) -> Self {
        Self::with_options(inner, ResolverCacheOptions::default())
    }

    pub fn with_options(
        inner: Arc<dyn Resolver>,
        options: ResolverCacheOptions,
    ) -> Self {
        Self {
            inner,
            cache: Arc::new(ResolverCache::new(options)),
        }
    }

    fn with_cache(inner: Arc<dyn Resolver>, cache: Arc<ResolverCache>) -> Self {
        Self { inner, cache }
    }

    pub fn stats(&self) -> ResolverCacheStats {
        self.cache.stats()
    }
}

impl Resolver for CachedResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }

        let inner = self.inner.clone();
        let cache = self.cache.clone();
        let location = location.clone();
        Box::pin(async move {
            loop {
                match cache.prepare(&location) {
                    CacheDecision::Ready(result) => {
                        return cached_result_to_io(result);
                    }
                    CacheDecision::Wait(mut receiver) => {
                        if receiver.borrow().is_none()
                            && receiver.changed().await.is_err()
                        {
                            continue;
                        }
                        if let Some(result) = receiver.borrow().clone() {
                            return cached_result_to_io(result);
                        }
                    }
                    CacheDecision::Resolve { id, sender } => {
                        let guard = LookupGuard {
                            cache: cache.clone(),
                            location: location.clone(),
                            id,
                            sender,
                            completed: false,
                        };
                        let result = inner
                            .resolve_location(&location)
                            .await
                            .and_then(|addresses| {
                                if addresses.is_empty() {
                                    Err(io::Error::new(
                                        io::ErrorKind::NotFound,
                                        format!(
                                            "DNS lookup returned no addresses for {location}"
                                        ),
                                    ))
                                } else {
                                    Ok(addresses)
                                }
                            })
                            .map_err(CachedLookupError::from_io);
                        let return_value = result.clone();
                        guard.complete(result);
                        return cached_result_to_io(return_value);
                    }
                }
            }
        })
    }
}

fn cached_result_to_io(result: CachedLookupResult) -> io::Result<Vec<SocketAddr>> {
    result.map_err(|error| error.to_io())
}

/// Resolver that applies exact static hostname overrides before falling back to
/// another resolver. Hostnames are normalized to lowercase without a trailing
/// dot, while the destination port always comes from the original request.
#[derive(Clone)]
pub struct HostsResolver {
    hosts: Arc<HashMap<String, Vec<IpAddr>>>,
    fallback: Arc<dyn Resolver>,
}

impl HostsResolver {
    pub fn new(
        hosts: HashMap<String, Vec<IpAddr>>,
        fallback: Arc<dyn Resolver>,
    ) -> Self {
        let hosts = hosts
            .into_iter()
            .map(|(hostname, addresses)| (normalize_hostname(&hostname), addresses))
            .collect();
        Self {
            hosts: Arc::new(hosts),
            fallback,
        }
    }
}

impl Resolver for HostsResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let hostname = match location.address() {
            crate::address::Address::Hostname(hostname) => {
                normalize_hostname(hostname)
            }
            _ => return self.fallback.resolve_location(location),
        };
        let port = location.port();
        if let Some(addresses) = self.hosts.get(&hostname) {
            let addresses = addresses
                .iter()
                .copied()
                .map(|address| SocketAddr::new(address, port))
                .collect::<Vec<_>>();
            return Box::pin(async move { Ok(addresses) });
        }
        self.fallback.resolve_location(location)
    }
}

fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

const DNS_DEFAULT_PORT: u16 = 53;
const DNS_HEADER_LENGTH: usize = 12;
const DNS_MAX_UDP_RESPONSE: usize = 4096;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsUpstreamTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsUpstream {
    transport: DnsUpstreamTransport,
    location: NetLocation,
}

impl DnsUpstream {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("DNS upstream must not be empty".into());
        }
        let (transport, authority) =
            if let Some(authority) = raw.strip_prefix("tcp://") {
                (DnsUpstreamTransport::Tcp, authority)
            } else if let Some(authority) = raw.strip_prefix("udp://") {
                (DnsUpstreamTransport::Udp, authority)
            } else if raw.contains("://") {
                return Err(format!("unsupported DNS upstream scheme in {raw:?}"));
            } else {
                (DnsUpstreamTransport::Udp, raw)
            };
        if authority.is_empty() {
            return Err(format!("DNS upstream {raw:?} is missing an address"));
        }
        let location = if let Ok(address) = authority.parse::<SocketAddr>() {
            NetLocation::from_ip_addr(address.ip(), address.port())
        } else if let Ok(address) = authority.parse::<IpAddr>() {
            NetLocation::from_ip_addr(address, DNS_DEFAULT_PORT)
        } else {
            NetLocation::from_str(authority, Some(DNS_DEFAULT_PORT))
                .map_err(|error| format!("invalid DNS upstream {raw:?}: {error}"))?
        };
        if location.port() == 0 {
            return Err(format!("DNS upstream {raw:?} has port zero"));
        }
        Ok(Self {
            transport,
            location,
        })
    }
}

#[derive(Clone)]
pub(crate) struct DnsWireResolver {
    upstream: DnsUpstream,
    next_query_id: Arc<AtomicU16>,
}

impl DnsWireResolver {
    pub(crate) fn new(upstream: DnsUpstream) -> Self {
        Self {
            upstream,
            next_query_id: Arc::new(AtomicU16::new(1)),
        }
    }
}

impl Resolver for DnsWireResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }
        let hostname = match location.address() {
            Address::Hostname(hostname) => normalize_hostname(hostname),
            _ => unreachable!("non-hostname destinations returned above"),
        };
        let port = location.port();
        let upstream = self.upstream.clone();
        let next_query_id = self.next_query_id.clone();
        Box::pin(async move {
            let mut addresses = Vec::new();
            let mut last_error = None;
            for query_type in [DNS_TYPE_A, DNS_TYPE_AAAA] {
                let query_id = next_query_id.fetch_add(1, Ordering::Relaxed);
                match query_dns_upstream(&upstream, &hostname, query_type, query_id)
                    .await
                {
                    Ok(results) => {
                        for address in results {
                            let socket = SocketAddr::new(address, port);
                            if !addresses.contains(&socket) {
                                addresses.push(socket);
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        last_error = Some(error);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if addresses.is_empty() {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("DNS returned no addresses for {hostname}"),
                    )
                }));
            }
            Ok(addresses)
        })
    }
}

async fn query_dns_upstream(
    upstream: &DnsUpstream,
    hostname: &str,
    query_type: u16,
    query_id: u16,
) -> io::Result<Vec<IpAddr>> {
    let request = build_dns_query(hostname, query_type, query_id)?;
    let upstream_address = resolve_dns_upstream_address(&upstream.location).await?;
    let response = match upstream.transport {
        DnsUpstreamTransport::Udp => {
            let response = query_dns_udp(upstream_address, &request).await?;
            if dns_response_is_truncated(&response, query_id)? {
                query_dns_tcp(upstream_address, &request).await?
            } else {
                response
            }
        }
        DnsUpstreamTransport::Tcp => {
            query_dns_tcp(upstream_address, &request).await?
        }
    };
    parse_dns_response(&response, query_id)
}

async fn resolve_dns_upstream_address(
    location: &NetLocation,
) -> io::Result<SocketAddr> {
    if let Some(address) = location.to_socket_addr_nonblocking() {
        return Ok(address);
    }
    let Address::Hostname(hostname) = location.address() else {
        unreachable!("non-hostname DNS upstream returned above");
    };
    tokio::net::lookup_host((hostname.as_str(), location.port()))
        .await?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not resolve DNS upstream {location}"),
            )
        })
}

fn build_dns_query(
    hostname: &str,
    query_type: u16,
    query_id: u16,
) -> io::Result<Vec<u8>> {
    let hostname = normalize_hostname(hostname);
    if hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS hostname must not be empty",
        ));
    }
    let mut query = Vec::with_capacity(DNS_HEADER_LENGTH + hostname.len() + 6);
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS label in {hostname:?}"),
            ));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

async fn query_dns_udp(server: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let bind_address = if server.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.send_to(request, server).await?;
    let mut response = vec![0u8; DNS_MAX_UDP_RESPONSE];
    loop {
        let (length, source) = socket.recv_from(&mut response).await?;
        if source == server {
            response.truncate(length);
            return Ok(response);
        }
    }
}

async fn query_dns_tcp(server: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let request_length = u16::try_from(request.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "DNS request exceeds u16")
    })?;
    let mut stream = TcpStream::connect(server).await?;
    stream.write_u16(request_length).await?;
    stream.write_all(request).await?;
    stream.flush().await?;
    let response_length = stream.read_u16().await? as usize;
    if response_length < DNS_HEADER_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS-over-TCP response is shorter than its header",
        ));
    }
    let mut response = vec![0u8; response_length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

fn dns_response_is_truncated(response: &[u8], query_id: u16) -> io::Result<bool> {
    let (response_id, flags) = read_dns_response_prefix(response)?;
    if response_id != query_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response transaction ID does not match the query",
        ));
    }
    Ok(flags & 0x0200 != 0)
}

fn parse_dns_response(response: &[u8], query_id: u16) -> io::Result<Vec<IpAddr>> {
    let (response_id, flags) = read_dns_response_prefix(response)?;
    if response_id != query_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response transaction ID does not match the query",
        ));
    }
    if flags & 0x8000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS packet is not a response",
        ));
    }
    let response_code = flags & 0x000f;
    if response_code == 3 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "DNS NXDOMAIN"));
    }
    if response_code != 0 {
        return Err(io::Error::other(format!(
            "DNS server returned response code {response_code}"
        )));
    }

    let question_count = read_dns_u16(response, 4)? as usize;
    let answer_count = read_dns_u16(response, 6)? as usize;
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..question_count {
        offset = skip_dns_name(response, offset)?;
        offset = offset.checked_add(4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS question overflow")
        })?;
        if offset > response.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated DNS question",
            ));
        }
    }

    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated DNS answer header",
            ));
        }
        let record_type = read_dns_u16(response, offset)?;
        let class = read_dns_u16(response, offset + 2)?;
        let data_length = read_dns_u16(response, offset + 8)? as usize;
        offset += 10;
        let data_end = offset.checked_add(data_length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS record length overflow")
        })?;
        if data_end > response.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated DNS answer data",
            ));
        }
        if class == DNS_CLASS_IN {
            match (record_type, data_length) {
                (DNS_TYPE_A, 4) => {
                    addresses.push(IpAddr::V4(std::net::Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    )))
                }
                (DNS_TYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&response[offset..data_end]);
                    addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset = data_end;
    }
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS response contained no A or AAAA records",
        ));
    }
    Ok(addresses)
}

fn read_dns_response_prefix(response: &[u8]) -> io::Result<(u16, u16)> {
    if response.len() < DNS_HEADER_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "DNS response is shorter than its header",
        ));
    }
    Ok((read_dns_u16(response, 0)?, read_dns_u16(response, 2)?))
}

fn read_dns_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet.get(offset..offset + 2).ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated DNS integer")
    })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        let length = *packet.get(offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated DNS name")
        })?;
        if length & 0xc0 == 0xc0 {
            if offset + 2 > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated DNS compression pointer",
                ));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS label type",
            ));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset.checked_add(length as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS name length overflow")
        })?;
        if offset > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated DNS label",
            ));
        }
    }
}

/// Resolver that tries multiple upstreams in order until one returns addresses.
#[derive(Clone)]
pub struct CompositeResolver {
    resolvers: Vec<Arc<dyn Resolver>>,
}

impl CompositeResolver {
    pub fn new(resolvers: Vec<Arc<dyn Resolver>>) -> Self {
        Self { resolvers }
    }
}

impl Resolver for CompositeResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let resolvers = self.resolvers.clone();
        let location = location.clone();
        Box::pin(async move {
            let mut last_error = None;
            for (index, resolver) in resolvers.iter().enumerate() {
                match resolver.resolve_location(&location).await {
                    Ok(addresses) if !addresses.is_empty() => {
                        if index > 0 {
                            debug!(
                                resolver_index = index,
                                destination = %location,
                                "DNS lookup succeeded after resolver fallback"
                            );
                        }
                        return Ok(addresses);
                    }
                    Ok(_) => {
                        debug!(
                            resolver_index = index,
                            destination = %location,
                            "DNS resolver returned no addresses"
                        );
                        last_error = Some(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "DNS resolver #{index} returned no addresses for {location}"
                            ),
                        ));
                    }
                    Err(error) => {
                        debug!(
                            resolver_index = index,
                            destination = %location,
                            error = %error,
                            "DNS resolver failed; trying the next resolver"
                        );
                        last_error = Some(error);
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no DNS resolvers configured",
                )
            }))
        })
    }
}

/// Address-family ordering applied to resolver results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddressFamilyPreference {
    #[default]
    Preserve,
    Ipv4First,
    Ipv6First,
}

/// Removes unusable and duplicate addresses, then optionally interleaves IPv4
/// and IPv6 candidates. The first family follows `preference`.
pub fn normalize_resolved_addresses(
    addresses: Vec<SocketAddr>,
    preference: AddressFamilyPreference,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::with_capacity(addresses.len());
    let unique = addresses
        .into_iter()
        .filter(|address| !address.ip().is_unspecified())
        .filter(|address| seen.insert(*address))
        .collect::<Vec<_>>();

    if preference == AddressFamilyPreference::Preserve {
        return unique;
    }

    let mut ipv4 = unique
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect::<VecDeque<_>>();
    let mut ipv6 = unique
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv6)
        .collect::<VecDeque<_>>();
    let mut ordered = Vec::with_capacity(unique.len());

    while !ipv4.is_empty() || !ipv6.is_empty() {
        let (first, second) = match preference {
            AddressFamilyPreference::Ipv4First => (&mut ipv4, &mut ipv6),
            AddressFamilyPreference::Ipv6First => (&mut ipv6, &mut ipv4),
            AddressFamilyPreference::Preserve => unreachable!(),
        };
        if let Some(address) = first.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = second.pop_front() {
            ordered.push(address);
        }
    }
    ordered
}

/// Resolver wrapper that normalizes and orders returned socket addresses.
#[derive(Clone)]
pub struct AddressOrderingResolver {
    inner: Arc<dyn Resolver>,
    preference: AddressFamilyPreference,
}

impl AddressOrderingResolver {
    pub fn new(
        inner: Arc<dyn Resolver>,
        preference: AddressFamilyPreference,
    ) -> Self {
        Self { inner, preference }
    }
}

impl Resolver for AddressOrderingResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let inner = self.inner.clone();
        let preference = self.preference;
        let location = location.clone();
        Box::pin(async move {
            inner
                .resolve_location(&location)
                .await
                .map(|addresses| normalize_resolved_addresses(addresses, preference))
        })
    }
}

/// Resolver wrapper that bounds each upstream query with a hard timeout.
#[derive(Clone)]
pub struct TimeoutResolver {
    inner: Arc<dyn Resolver>,
    timeout: Duration,
}

impl TimeoutResolver {
    pub fn new(inner: Arc<dyn Resolver>, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl Resolver for TimeoutResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let inner = self.inner.clone();
        let timeout = self.timeout;
        let location = location.clone();
        Box::pin(async move {
            match tokio::time::timeout(timeout, inner.resolve_location(&location))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DNS lookup for {location} timed out after {timeout:?}"),
                )),
            }
        })
    }
}

struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let address = location.address().clone();
        let port = location.port();

        Box::pin(tokio::net::lookup_host((address.to_string(), port)).map(
            move |result| {
                let result = result.map(|addresses| {
                    addresses
                        .filter(|address| !address.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!(
                    "system resolver resolved {}:{} -> {:?}",
                    address, port, result
                );
                result
            },
        ))
    }
}

/// System resolver with a process-wide shared DNS cache.
pub struct NativeResolver {
    cached: CachedResolver,
}

impl NativeResolver {
    pub fn new() -> Self {
        static CACHE: OnceLock<Arc<ResolverCache>> = OnceLock::new();
        let cache = CACHE
            .get_or_init(|| {
                Arc::new(ResolverCache::new(ResolverCacheOptions::default()))
            })
            .clone();
        let system: Arc<dyn Resolver> = Arc::new(SystemResolver);
        let normalized: Arc<dyn Resolver> = Arc::new(AddressOrderingResolver::new(
            system,
            AddressFamilyPreference::Preserve,
        ));
        let bounded: Arc<dyn Resolver> =
            Arc::new(TimeoutResolver::new(normalized, DEFAULT_LOOKUP_TIMEOUT));
        Self {
            cached: CachedResolver::with_cache(bounded, cache),
        }
    }

    pub fn stats(&self) -> ResolverCacheStats {
        self.cached.stats()
    }
}

impl Default for NativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        self.cached.resolve_location(location)
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> io::Result<SocketAddr> {
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(io::Error::other(format!(
            "could not resolve location: {}",
            location
        )));
    }
    Ok(resolve_results[0])
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    fn dns_test_response(query: &[u8]) -> Vec<u8> {
        let query_type =
            u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let rdata = match query_type {
            DNS_TYPE_A => vec![192, 0, 2, 77],
            DNS_TYPE_AAAA => "2001:db8::77"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            other => panic!("unexpected DNS test query type {other}"),
        };
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[DNS_HEADER_LENGTH..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        response
    }

    fn truncated_dns_test_response(query: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(DNS_HEADER_LENGTH);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8200u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response
    }

    #[derive(Clone)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        response: Result<Vec<SocketAddr>, (io::ErrorKind, String)>,
    }

    impl CountingResolver {
        fn successful(delay: Duration) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                delay,
                response: Ok(vec!["192.0.2.1:443".parse().unwrap()]),
            }
        }

        fn failing() -> Self {
            Self::failing_with("test DNS failure")
        }

        fn failing_with(message: &str) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                response: Err((io::ErrorKind::NotFound, message.into())),
            }
        }

        fn empty() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                response: Ok(Vec::new()),
            }
        }
    }

    impl Resolver for CountingResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
        {
            let calls = self.calls.clone();
            let delay = self.delay;
            let response = self.response.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(delay).await;
                response.map_err(|(kind, message)| io::Error::new(kind, message))
            })
        }
    }

    fn domain_location() -> NetLocation {
        NetLocation::from_str("cache.example:443", None).unwrap()
    }

    fn test_options() -> ResolverCacheOptions {
        ResolverCacheOptions {
            positive_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(30),
            max_entries: 16,
        }
    }

    #[tokio::test]
    async fn dns_wire_udp_truncation_falls_back_to_tcp_for_a_and_aaaa() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(server).await.unwrap();

        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 512];
            for _ in 0..2 {
                let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
                let response = truncated_dns_test_response(&buffer[..length]);
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        let tcp_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap() as usize;
                let mut request = vec![0u8; length];
                stream.read_exact(&mut request).await.unwrap();
                let response = dns_test_response(&request);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let resolver = DnsWireResolver::new(
            DnsUpstream::parse(&format!("udp://{server}")).unwrap(),
        );
        let addresses = tokio::time::timeout(
            Duration::from_secs(2),
            resolver.resolve_location(
                &NetLocation::from_str("wire.example:8443", None).unwrap(),
            ),
        )
        .await
        .expect("DNS wire lookup timeout")
        .expect("DNS wire lookup failed");
        assert_eq!(
            addresses,
            vec![
                "192.0.2.77:8443".parse().unwrap(),
                "[2001:db8::77]:8443".parse().unwrap(),
            ]
        );
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn dns_wire_tcp_queries_a_and_aaaa() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap() as usize;
                let mut request = vec![0u8; length];
                stream.read_exact(&mut request).await.unwrap();
                let response = dns_test_response(&request);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let resolver = DnsWireResolver::new(
            DnsUpstream::parse(&format!("tcp://{server}")).unwrap(),
        );
        let addresses = tokio::time::timeout(
            Duration::from_secs(2),
            resolver.resolve_location(
                &NetLocation::from_str("tcp-wire.example:7443", None).unwrap(),
            ),
        )
        .await
        .expect("DNS-over-TCP lookup timeout")
        .expect("DNS-over-TCP lookup failed");
        assert_eq!(
            addresses,
            vec![
                "192.0.2.77:7443".parse().unwrap(),
                "[2001:db8::77]:7443".parse().unwrap(),
            ]
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dns_wire_rejects_mismatched_transaction_ids() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = udp.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 512];
            for _ in 0..2 {
                let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
                let mut response = dns_test_response(&buffer[..length]);
                let transaction_id =
                    u16::from_be_bytes([response[0], response[1]]).wrapping_add(1);
                response[..2].copy_from_slice(&transaction_id.to_be_bytes());
                udp.send_to(&response, peer).await.unwrap();
            }
        });

        let resolver =
            DnsWireResolver::new(DnsUpstream::parse(&server.to_string()).unwrap());
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            resolver.resolve_location(
                &NetLocation::from_str("mismatch.example:443", None).unwrap(),
            ),
        )
        .await
        .expect("mismatched DNS lookup timeout")
        .expect_err("mismatched DNS transaction ID must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn hosts_resolver_overrides_exact_names_and_preserves_ports() {
        let fallback = CountingResolver::successful(Duration::ZERO);
        let fallback_calls = fallback.calls.clone();
        let resolver = HostsResolver::new(
            HashMap::from([(
                "Static.Example.".to_string(),
                vec![
                    "192.0.2.20".parse().unwrap(),
                    "2001:db8::20".parse().unwrap(),
                ],
            )]),
            Arc::new(fallback),
        );

        let addresses = resolver
            .resolve_location(
                &NetLocation::from_str("static.example:8443", None).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.20:8443".parse().unwrap(),
                "[2001:db8::20]:8443".parse().unwrap(),
            ]
        );
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 0);

        resolver
            .resolve_location(
                &NetLocation::from_str("fallback.example:443", None).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn address_normalization_preserves_unique_usable_addresses() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        assert_eq!(
            normalize_resolved_addresses(
                vec!["0.0.0.0:443".parse().unwrap(), ipv6, ipv4, ipv6,],
                AddressFamilyPreference::Preserve,
            ),
            vec![ipv6, ipv4]
        );
    }

    #[test]
    fn address_normalization_interleaves_ipv4_first() {
        let ipv4_a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv4_b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let ipv6_a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let ipv6_b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();

        assert_eq!(
            normalize_resolved_addresses(
                vec![ipv6_a, ipv6_b, ipv4_a, ipv4_b],
                AddressFamilyPreference::Ipv4First,
            ),
            vec![ipv4_a, ipv6_a, ipv4_b, ipv6_b]
        );
    }

    #[test]
    fn address_normalization_interleaves_ipv6_first() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv6_a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let ipv6_b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();

        assert_eq!(
            normalize_resolved_addresses(
                vec![ipv4, ipv6_a, ipv6_b],
                AddressFamilyPreference::Ipv6First,
            ),
            vec![ipv6_a, ipv4, ipv6_b]
        );
    }

    #[tokio::test]
    async fn composite_stops_after_first_success() {
        let first = CountingResolver::successful(Duration::ZERO);
        let first_calls = first.calls.clone();
        let second = CountingResolver::successful(Duration::ZERO);
        let second_calls = second.calls.clone();
        let resolver =
            CompositeResolver::new(vec![Arc::new(first), Arc::new(second)]);

        let addresses = resolver.resolve_location(&domain_location()).await.unwrap();

        assert_eq!(addresses, vec!["192.0.2.1:443".parse().unwrap()]);
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn composite_falls_back_after_error() {
        let first = CountingResolver::failing();
        let first_calls = first.calls.clone();
        let second = CountingResolver::successful(Duration::ZERO);
        let second_calls = second.calls.clone();
        let resolver =
            CompositeResolver::new(vec![Arc::new(first), Arc::new(second)]);

        assert!(resolver.resolve_location(&domain_location()).await.is_ok());
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn composite_falls_back_after_empty_result() {
        let first = CountingResolver::empty();
        let first_calls = first.calls.clone();
        let second = CountingResolver::successful(Duration::ZERO);
        let resolver =
            CompositeResolver::new(vec![Arc::new(first), Arc::new(second)]);

        assert!(resolver.resolve_location(&domain_location()).await.is_ok());
        assert_eq!(first_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn composite_returns_last_error_when_all_fail() {
        let resolver = CompositeResolver::new(vec![
            Arc::new(CountingResolver::failing_with("first failure")),
            Arc::new(CountingResolver::failing_with("last failure")),
        ]);

        let error = resolver
            .resolve_location(&domain_location())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "last failure");
    }

    #[tokio::test]
    async fn caches_successful_lookups() {
        let upstream = CountingResolver::successful(Duration::ZERO);
        let calls = upstream.calls.clone();
        let resolver =
            CachedResolver::with_options(Arc::new(upstream), test_options());
        let location = domain_location();

        let first = resolver.resolve_location(&location).await.unwrap();
        let second = resolver.resolve_location(&location).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            resolver.stats(),
            ResolverCacheStats {
                cache_entries: 1,
                cache_hits: 1,
                cache_misses: 1,
                upstream_lookups: 1,
                ..ResolverCacheStats::default()
            }
        );
    }

    #[tokio::test]
    async fn coalesces_concurrent_lookups() {
        let upstream = CountingResolver::successful(Duration::from_millis(50));
        let calls = upstream.calls.clone();
        let resolver = Arc::new(CachedResolver::with_options(
            Arc::new(upstream),
            test_options(),
        ));
        let location = domain_location();
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let resolver = resolver.clone();
            let location = location.clone();
            tasks.push(tokio::spawn(async move {
                resolver.resolve_location(&location).await.unwrap()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), vec!["192.0.2.1:443".parse().unwrap()]);
        }

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let stats = resolver.stats();
        assert_eq!(stats.upstream_lookups, 1);
        assert_eq!(stats.coalesced_waiters + stats.cache_hits, 15);
    }

    #[tokio::test]
    async fn negatively_caches_empty_results() {
        let upstream = CountingResolver::empty();
        let calls = upstream.calls.clone();
        let resolver =
            CachedResolver::with_options(Arc::new(upstream), test_options());
        let location = domain_location();

        let first = resolver.resolve_location(&location).await.unwrap_err();
        let second = resolver.resolve_location(&location).await.unwrap_err();

        assert_eq!(first.kind(), io::ErrorKind::NotFound);
        assert_eq!(second.kind(), io::ErrorKind::NotFound);
        assert!(first.to_string().contains("returned no addresses"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.stats().cache_hits, 1);
        assert_eq!(resolver.stats().upstream_failures, 1);
    }

    #[tokio::test]
    async fn negatively_caches_upstream_errors() {
        let upstream = CountingResolver::failing();
        let calls = upstream.calls.clone();
        let resolver =
            CachedResolver::with_options(Arc::new(upstream), test_options());
        let location = domain_location();

        let first = resolver.resolve_location(&location).await.unwrap_err();
        let second = resolver.resolve_location(&location).await.unwrap_err();

        assert_eq!(first.kind(), io::ErrorKind::NotFound);
        assert_eq!(second.kind(), io::ErrorKind::NotFound);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.stats().cache_hits, 1);
        assert_eq!(resolver.stats().upstream_failures, 1);
    }

    #[tokio::test]
    async fn times_out_slow_upstream_lookups() {
        let upstream = CountingResolver::successful(Duration::from_millis(50));
        let calls = upstream.calls.clone();
        let resolver =
            TimeoutResolver::new(Arc::new(upstream), Duration::from_millis(5));

        let error = resolver
            .resolve_location(&domain_location())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("timed out"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refreshes_expired_entries() {
        let upstream = CountingResolver::successful(Duration::ZERO);
        let calls = upstream.calls.clone();
        let resolver = CachedResolver::with_options(
            Arc::new(upstream),
            ResolverCacheOptions {
                positive_ttl: Duration::from_millis(5),
                ..test_options()
            },
        );
        let location = domain_location();

        resolver.resolve_location(&location).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        resolver.resolve_location(&location).await.unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn bypasses_upstream_for_literal_ip_addresses() {
        let upstream = CountingResolver::failing();
        let calls = upstream.calls.clone();
        let resolver =
            CachedResolver::with_options(Arc::new(upstream), test_options());
        let location = NetLocation::from_str("192.0.2.9:8443", None).unwrap();

        assert_eq!(
            resolver.resolve_location(&location).await.unwrap(),
            vec!["192.0.2.9:8443".parse().unwrap()]
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
