use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{
    future::FutureExt,
    stream::{FuturesUnordered, StreamExt},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tracing::debug;

use crate::{
    address::{Address, NetLocation},
    config::def::{CompiledDnsServer, DnsQueryStrategy, DnsServerTransport},
};

const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;
const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DNS_SERVER_TIMEOUT_MS: u64 = 4_000;
const DNS_MAX_PACKET_SIZE: usize = 4096;

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
#[allow(dead_code)] // Public cache metrics are consumed by optional diagnostics.
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

#[allow(dead_code)]
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
    cache: Option<Arc<ResolverCache>>,
}

#[allow(dead_code)]
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
            cache: Some(Arc::new(ResolverCache::new(options))),
        }
    }

    fn with_cache(inner: Arc<dyn Resolver>, cache: Arc<ResolverCache>) -> Self {
        Self {
            inner,
            cache: Some(cache),
        }
    }

    fn without_cache(inner: Arc<dyn Resolver>) -> Self {
        Self { inner, cache: None }
    }

    pub fn stats(&self) -> ResolverCacheStats {
        self.cache
            .as_ref()
            .map(|cache| cache.stats())
            .unwrap_or_default()
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
            let Some(cache) = cache else {
                return inner.resolve_location(&location).await;
            };
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

/// Resolver that tries multiple upstreams in order until one returns addresses.
#[derive(Clone)]
#[allow(dead_code)] // Public fallback resolver retained for resolver composition.
pub struct CompositeResolver {
    resolvers: Vec<Arc<dyn Resolver>>,
}

#[allow(dead_code)]
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
#[allow(dead_code)] // Exposed for callers that need an explicit family preference.
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

struct SystemResolver {
    query_strategy: DnsQueryStrategy,
}

impl SystemResolver {
    fn new(query_strategy: DnsQueryStrategy) -> Self {
        Self { query_strategy }
    }
}

impl Resolver for SystemResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let address = location.address().clone();
        let port = location.port();
        let query_strategy = self.query_strategy;

        Box::pin(tokio::net::lookup_host((address.to_string(), port)).map(
            move |result| {
                let result = result.map(|addresses| {
                    addresses
                        .filter(|address| !address.ip().is_unspecified())
                        .filter(|address| match query_strategy {
                            DnsQueryStrategy::UseIp => true,
                            DnsQueryStrategy::UseIpv4 => address.is_ipv4(),
                            DnsQueryStrategy::UseIpv6 => address.is_ipv6(),
                            DnsQueryStrategy::UseSystem => {
                                let (ipv4, ipv6) = system_route_families();
                                (address.is_ipv4() && ipv4)
                                    || (address.is_ipv6() && ipv6)
                            }
                        })
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

#[derive(Clone)]
struct DnsIpMatcher {
    rules: Vec<DnsIpRule>,
}

#[derive(Clone, Copy)]
struct DnsIpRule {
    network: IpAddr,
    prefix: u8,
    reverse: bool,
}

impl DnsIpMatcher {
    fn from_rules(rules: &[String]) -> io::Result<Option<Self>> {
        if rules.is_empty() {
            return Ok(None);
        }
        let rules = rules
            .iter()
            .map(|rule| DnsIpRule::parse(rule))
            .collect::<io::Result<Vec<_>>>()?;
        Ok((!rules.is_empty()).then_some(Self { rules }))
    }

    fn matches(&self, address: IpAddr) -> bool {
        self.rules.iter().any(|rule| rule.matches(address))
    }

    fn filter(&self, addresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
        addresses
            .into_iter()
            .filter(|address| self.matches(*address))
            .collect()
    }
}

impl DnsIpRule {
    fn parse(raw_rule: &str) -> io::Result<Self> {
        let mut reverse = false;
        let rule = raw_rule.trim();
        let rule = rule.trim_start_matches(|character| {
            if character == '!' {
                reverse = !reverse;
                true
            } else {
                false
            }
        });
        let (address, prefix) = rule
            .split_once('/')
            .map_or((rule, None), |(address, prefix)| (address, Some(prefix)));
        let address = address.parse::<IpAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS IP rule {raw_rule}"),
            )
        })?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid DNS CIDR prefix in {raw_rule}"),
                )
            })?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("DNS CIDR prefix in {raw_rule} exceeds {max_prefix}"),
            ));
        }
        Ok(Self {
            network: mask_ip(address, prefix),
            prefix,
            reverse,
        })
    }

    fn matches(self, address: IpAddr) -> bool {
        let matched = match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                mask_ipv4(address, self.prefix) == network
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                mask_ipv6(address, self.prefix) == network
            }
            _ => false,
        };
        matched != self.reverse
    }
}

fn mask_ip(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(mask_ipv4(address, prefix)),
        IpAddr::V6(address) => IpAddr::V6(mask_ipv6(address, prefix)),
    }
}

fn mask_ipv4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from_be_bytes(address.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_ipv6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = u128::from_be_bytes(address.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(bits & mask)
}

/// Minimal direct UDP/TCP nameserver resolver for Xray's plain IP server forms.
///
/// Xray supports several nameserver transports and per-server policies. This
/// resolver intentionally owns only the wire-level UDP/TCP lookup needed by the
/// current Linux routing slice; unsupported server forms are rejected while
/// compiling the literal configuration.
#[derive(Clone)]
pub struct UdpDnsResolver {
    servers: Arc<Vec<UdpDnsServer>>,
    next_id: Arc<AtomicU16>,
    client_ip: Option<IpAddr>,
    query_strategy: DnsQueryStrategy,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    enable_parallel_query: bool,
}

#[derive(Clone)]
struct UdpDnsServer {
    address: SocketAddr,
    transport: DnsServerTransport,
    parallel_policy_key: String,
    client_ip: Option<IpAddr>,
    query_strategy: Option<DnsQueryStrategy>,
    domain_matchers: Vec<HostMatcher>,
    skip_fallback: bool,
    final_query: bool,
    timeout_ms: Option<u64>,
    expected_ips: Option<DnsIpMatcher>,
    expected_ips_prefer: bool,
    unexpected_ips: Option<DnsIpMatcher>,
    unexpected_ips_prefer: bool,
}

impl UdpDnsServer {
    fn matches_domain(&self, domain: &str) -> bool {
        !self.domain_matchers.is_empty()
            && self
                .domain_matchers
                .iter()
                .any(|matcher| matcher.matches(domain))
    }
}

fn dns_server_policy_key(server: &CompiledDnsServer) -> String {
    let mut domains = server.domains.clone();
    domains.sort_unstable_by_key(|rule| rule.to_ascii_lowercase());
    let mut expected_ips = server.expected_ips.clone();
    expected_ips.sort_unstable();
    let mut unexpected_ips = server.unexpected_ips.clone();
    unexpected_ips.sort_unstable();
    format!(
        "transport={:?}|client={:?}|skip={}|strategy={:?}|domains={domains:?}|expected={expected_ips:?}|expected_prefer={}|unexpected={unexpected_ips:?}|unexpected_prefer={}",
        server.transport,
        server.client_ip,
        server.skip_fallback,
        server.query_strategy,
        server.expected_ips_prefer,
        server.unexpected_ips_prefer,
    )
}

fn make_dns_server_groups(
    server_order: &[usize],
    servers: &[UdpDnsServer],
) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for &index in server_order {
        let same_group = groups.last().is_some_and(|group| {
            servers[group[0]].parallel_policy_key
                == servers[index].parallel_policy_key
        });
        if same_group {
            if let Some(group) = groups.last_mut() {
                group.push(index);
            }
        } else {
            groups.push(vec![index]);
        }
    }
    groups
}

#[allow(dead_code)]
impl UdpDnsResolver {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self::with_query_strategy(servers, DnsQueryStrategy::UseIp)
    }

    pub fn with_query_strategy(
        servers: Vec<SocketAddr>,
        query_strategy: DnsQueryStrategy,
    ) -> Self {
        let servers: Vec<CompiledDnsServer> = servers
            .into_iter()
            .map(|address| CompiledDnsServer {
                address,
                transport: DnsServerTransport::Udp,
                client_ip: None,
                query_strategy: None,
                domains: Vec::new(),
                skip_fallback: false,
                final_query: false,
                timeout_ms: None,
                expected_ips: Vec::new(),
                expected_ips_prefer: false,
                unexpected_ips: Vec::new(),
                unexpected_ips_prefer: false,
            })
            .collect();
        Self {
            servers: Arc::new(
                servers
                    .into_iter()
                    .map(|server| UdpDnsServer {
                        address: server.address,
                        transport: server.transport,
                        parallel_policy_key: dns_server_policy_key(&server),
                        client_ip: server.client_ip,
                        query_strategy: server.query_strategy,
                        domain_matchers: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: None,
                        expected_ips_prefer: false,
                        unexpected_ips: None,
                        unexpected_ips_prefer: false,
                    })
                    .collect(),
            ),
            next_id: Arc::new(AtomicU16::new(1)),
            client_ip: None,
            query_strategy,
            disable_fallback: false,
            disable_fallback_if_match: false,
            enable_parallel_query: false,
        }
    }

    pub fn with_server_configs(
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Self> {
        Self::with_server_configs_with_fallback_options(
            servers,
            query_strategy,
            false,
            false,
        )
    }

    pub fn with_server_configs_with_fallback_options(
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> io::Result<Self> {
        Self::with_server_configs_with_fallback_options_and_client_ip(
            servers,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            None,
        )
    }

    pub fn with_server_configs_with_fallback_options_and_client_ip(
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        Self::with_server_configs_with_fallback_options_and_client_ip_and_parallel_query(
            servers,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            client_ip,
            false,
        )
    }

    pub fn with_server_configs_with_fallback_options_and_client_ip_and_parallel_query(
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
        client_ip: Option<IpAddr>,
        enable_parallel_query: bool,
    ) -> io::Result<Self> {
        let servers = servers
            .into_iter()
            .map(|server| {
                let domain_matchers = server
                    .domains
                    .iter()
                    .map(|rule| HostMatcher::from_server_rule(rule))
                    .collect::<io::Result<Vec<_>>>()?;
                Ok(UdpDnsServer {
                    address: server.address,
                    transport: server.transport,
                    parallel_policy_key: dns_server_policy_key(&server),
                    client_ip: server.client_ip,
                    query_strategy: server.query_strategy,
                    domain_matchers,
                    skip_fallback: server.skip_fallback,
                    final_query: server.final_query,
                    timeout_ms: server.timeout_ms,
                    expected_ips: DnsIpMatcher::from_rules(&server.expected_ips)?,
                    expected_ips_prefer: server.expected_ips_prefer,
                    unexpected_ips: DnsIpMatcher::from_rules(
                        &server.unexpected_ips,
                    )?,
                    unexpected_ips_prefer: server.unexpected_ips_prefer,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            servers: Arc::new(servers),
            next_id: Arc::new(AtomicU16::new(1)),
            client_ip,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            enable_parallel_query,
        })
    }

    fn query_types(query_strategy: DnsQueryStrategy) -> io::Result<Vec<u16>> {
        match query_strategy {
            DnsQueryStrategy::UseIp => Ok(vec![1, 28]),
            DnsQueryStrategy::UseIpv4 => Ok(vec![1]),
            DnsQueryStrategy::UseIpv6 => Ok(vec![28]),
            DnsQueryStrategy::UseSystem => {
                let (ipv4, ipv6) = system_route_families();
                let mut query_types = Vec::with_capacity(2);
                if ipv4 {
                    query_types.push(1);
                }
                if ipv6 {
                    query_types.push(28);
                }
                if query_types.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "system DNS query strategy found no usable IP route",
                    ));
                }
                Ok(query_types)
            }
        }
    }

    async fn resolve_hostname(&self, hostname: &str) -> io::Result<Vec<IpAddr>> {
        let mut last_error = None;
        let mut server_order = Vec::with_capacity(self.servers.len());
        let mut has_domain_match = false;
        'server_order: for prioritized in [true, false] {
            for (index, server) in self.servers.iter().enumerate() {
                if server.matches_domain(hostname) != prioritized {
                    continue;
                }
                if prioritized {
                    has_domain_match = true;
                } else if self.disable_fallback
                    || (self.disable_fallback_if_match && has_domain_match)
                    || server.skip_fallback
                {
                    continue;
                }
                server_order.push(index);
                if server.final_query {
                    break 'server_order;
                }
            }
        }
        if server_order.is_empty() && !self.servers.is_empty() {
            // Match Xray's safety fallback when every configured server
            // is excluded from the ordinary fallback pass.
            server_order.push(0);
        }
        if self.enable_parallel_query {
            return self
                .resolve_hostname_parallel(hostname, &server_order)
                .await;
        }
        for index in server_order {
            let server = &self.servers[index];
            let query_strategy =
                server.query_strategy.unwrap_or(self.query_strategy);
            match self.query_server(server, hostname, query_strategy).await {
                Ok(addresses) if !addresses.is_empty() => return Ok(addresses),
                Ok(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "DNS server {} returned no addresses",
                            server.address
                        ),
                    ));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no DNS servers configured")
        }))
    }

    async fn resolve_hostname_parallel(
        &self,
        hostname: &str,
        server_order: &[usize],
    ) -> io::Result<Vec<IpAddr>> {
        let groups = make_dns_server_groups(server_order, &self.servers);
        if groups.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no DNS servers configured",
            ));
        }

        let mut pending = FuturesUnordered::new();
        let mut pending_by_group: Vec<usize> = groups.iter().map(Vec::len).collect();
        let mut successes: Vec<Vec<Option<Vec<IpAddr>>>> =
            groups.iter().map(|group| vec![None; group.len()]).collect();
        let mut last_error = None;

        for (group_index, group) in groups.iter().enumerate() {
            for (slot, index) in group.iter().copied().enumerate() {
                let resolver = self.clone();
                let server = self.servers[index].clone();
                let hostname = hostname.to_owned();
                let query_strategy =
                    server.query_strategy.unwrap_or(self.query_strategy);
                pending.push(async move {
                    let result = resolver
                        .query_server(&server, &hostname, query_strategy)
                        .await;
                    (group_index, slot, index, result)
                });
            }
        }

        let mut next_group = 0;
        while let Some((group_index, slot, index, result)) = pending.next().await {
            pending_by_group[group_index] -= 1;
            match result {
                Ok(addresses) if !addresses.is_empty() => {
                    successes[group_index][slot] = Some(addresses);
                }
                Ok(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "DNS server {} returned no addresses",
                            self.servers[index].address
                        ),
                    ));
                }
                Err(error) => last_error = Some(error),
            }

            loop {
                if let Some(addresses) = successes[next_group]
                    .iter()
                    .find_map(|addresses| addresses.as_ref())
                {
                    return Ok(addresses.clone());
                }
                if pending_by_group[next_group] > 0 {
                    break;
                }
                next_group += 1;
                if next_group == groups.len() {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "DNS servers returned no addresses for {hostname}"
                            ),
                        )
                    }));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS servers returned no addresses for {hostname}"),
            )
        }))
    }

    async fn query_server(
        &self,
        server_config: &UdpDnsServer,
        hostname: &str,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Vec<IpAddr>> {
        let timeout = Duration::from_millis(
            server_config
                .timeout_ms
                .filter(|timeout_ms| *timeout_ms > 0)
                .unwrap_or(DEFAULT_DNS_SERVER_TIMEOUT_MS),
        );
        match tokio::time::timeout(
            timeout,
            self.query_server_until_timeout(server_config, hostname, query_strategy),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "DNS query to {} timed out after {timeout:?}",
                    server_config.address
                ),
            )),
        }
    }

    async fn query_server_until_timeout(
        &self,
        server_config: &UdpDnsServer,
        hostname: &str,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Vec<IpAddr>> {
        if server_config.transport == DnsServerTransport::Tcp {
            return self
                .query_tcp_server(server_config, hostname, query_strategy)
                .await;
        }

        let server = server_config.address;
        let bind_address = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_address).await?;
        socket.connect(server).await?;
        let mut addresses = Vec::new();
        let mut last_error = None;
        for query_type in Self::query_types(query_strategy)? {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let packet = build_dns_query(
                id,
                hostname,
                query_type,
                server_config.client_ip.or(self.client_ip),
            )?;
            socket.send(&packet).await?;
            let mut response = [0u8; DNS_MAX_PACKET_SIZE];
            let received = socket.recv(&mut response).await?;
            match parse_dns_response(&response[..received], id, query_type) {
                Ok(mut found) => addresses.append(&mut found),
                Err(error) => last_error = Some(error),
            }
        }
        if !addresses.is_empty() {
            addresses.sort();
            addresses.dedup();
            return Ok(filter_dns_server_addresses(addresses, server_config));
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS server {server} returned no addresses for {hostname}"),
            )
        }))
    }

    async fn query_tcp_server(
        &self,
        server_config: &UdpDnsServer,
        hostname: &str,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Vec<IpAddr>> {
        let server = server_config.address;
        let mut addresses = Vec::new();
        let mut last_error = None;
        for query_type in Self::query_types(query_strategy)? {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let packet = build_dns_query(
                id,
                hostname,
                query_type,
                server_config.client_ip.or(self.client_ip),
            )?;
            let length = u16::try_from(packet.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS over TCP query exceeds the 65535-byte wire limit",
                )
            })?;
            let mut stream = tokio::net::TcpStream::connect(server).await?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&packet).await?;

            let mut response_length = [0u8; 2];
            stream.read_exact(&mut response_length).await?;
            let response_length = usize::from(u16::from_be_bytes(response_length));
            if response_length == 0 || response_length > DNS_MAX_PACKET_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "DNS over TCP response from {server} has invalid length {response_length}"
                    ),
                ));
            }
            let mut response = vec![0u8; response_length];
            stream.read_exact(&mut response).await?;
            match parse_dns_response(&response, id, query_type) {
                Ok(mut found) => addresses.append(&mut found),
                Err(error) => last_error = Some(error),
            }
        }
        if !addresses.is_empty() {
            addresses.sort();
            addresses.dedup();
            return Ok(filter_dns_server_addresses(addresses, server_config));
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS server {server} returned no addresses for {hostname}"),
            )
        }))
    }
}

fn filter_dns_server_addresses(
    mut addresses: Vec<IpAddr>,
    server: &UdpDnsServer,
) -> Vec<IpAddr> {
    if let Some(expected) = &server.expected_ips {
        if server.expected_ips_prefer {
            let matched = expected.filter(addresses.iter().copied());
            if !matched.is_empty() {
                addresses = matched;
            }
        } else {
            addresses = expected.filter(addresses);
        }
    }

    if let Some(unexpected) = &server.unexpected_ips {
        let has_match = addresses
            .iter()
            .copied()
            .any(|address| unexpected.matches(address));
        if !server.unexpected_ips_prefer || has_match {
            addresses.retain(|address| !unexpected.matches(*address));
        }
    }
    addresses
}

/// Mirrors Xray's `UseSystem` route probe without sending probe packets.
/// UDP connect only asks the kernel for a route and is cached for the process.
fn system_route_families() -> (bool, bool) {
    static ROUTES: OnceLock<(bool, bool)> = OnceLock::new();
    *ROUTES.get_or_init(|| {
        let ipv4 = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| socket.connect("192.33.4.12:53"))
            .is_ok();
        let ipv6 = std::net::UdpSocket::bind("[::]:0")
            .and_then(|socket| socket.connect("[2001:500:2::c]:53"))
            .is_ok();
        (ipv4, ipv6)
    })
}

impl Resolver for UdpDnsResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let Some(hostname) = location.address().hostname() else {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP DNS resolver requires a hostname",
                ))
            });
        };
        let Some(hostname) = normalize_dns_hostname(hostname) else {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP DNS resolver received an invalid hostname",
                ))
            });
        };
        let hostname = hostname.to_string();
        let port = location.port();
        let resolver = self.clone();
        Box::pin(async move {
            resolver.resolve_hostname(&hostname).await.map(|addresses| {
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            })
        })
    }
}

fn normalize_dns_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim().trim_end_matches('.');
    if hostname.is_empty() {
        return None;
    }
    idna::domain_to_ascii(hostname)
        .ok()
        .map(|hostname| hostname.to_ascii_lowercase())
}

fn build_dns_query(
    id: u16,
    hostname: &str,
    query_type: u16,
    client_ip: Option<IpAddr>,
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&(u16::from(client_ip.is_some())).to_be_bytes());
    let hostname = hostname.trim_end_matches('.');
    if hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS query hostname is empty",
        ));
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS query contains an invalid label",
            ));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&query_type.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    if let Some(client_ip) = client_ip {
        append_edns_client_subnet(&mut packet, client_ip);
    }
    Ok(packet)
}

fn append_edns_client_subnet(packet: &mut Vec<u8>, client_ip: IpAddr) {
    let (family, prefix, address) = match client_ip {
        IpAddr::V4(address) => (1u16, 24u8, address.octets().to_vec()),
        IpAddr::V6(address) => (2u16, 96u8, address.octets().to_vec()),
    };
    let address_len = usize::from(prefix.div_ceil(8));

    // Match x/net/dns/dnsmessage.SetEDNS0(1350, 0xfe00, true), which is
    // what Xray uses for every query carrying its ECS option.
    packet.push(0);
    packet.extend_from_slice(&41u16.to_be_bytes());
    packet.extend_from_slice(&1350u16.to_be_bytes());
    packet.extend_from_slice(&0xe0008000u32.to_be_bytes());
    packet.extend_from_slice(&((8 + address_len) as u16).to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.extend_from_slice(&((4 + address_len) as u16).to_be_bytes());
    packet.extend_from_slice(&family.to_be_bytes());
    packet.push(prefix);
    packet.push(0);
    packet.extend_from_slice(&address[..address_len]);
}

fn parse_dns_response(
    packet: &[u8],
    expected_id: u16,
    query_type: u16,
) -> io::Result<Vec<IpAddr>> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response header is truncated",
        ));
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if id != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response transaction ID does not match",
        ));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS packet is not a response",
        ));
    }
    if flags & 0x0200 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is truncated",
        ));
    }
    let response_code = flags & 0x000f;
    if response_code != 0 {
        let kind = if response_code == 3 {
            io::ErrorKind::NotFound
        } else {
            io::ErrorKind::Other
        };
        return Err(io::Error::new(
            kind,
            format!("DNS response returned rcode {response_code}"),
        ));
    }
    let question_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..question_count {
        skip_dns_name(packet, &mut offset)?;
        checked_advance(packet, &mut offset, 4)?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        skip_dns_name(packet, &mut offset)?;
        let record_type = u16::from_be_bytes([
            *packet.get(offset).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
            *packet.get(offset + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
        ]);
        let class = u16::from_be_bytes([
            *packet.get(offset + 2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
            *packet.get(offset + 3).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
        ]);
        let data_length = u16::from_be_bytes([
            *packet.get(offset + 8).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
            *packet.get(offset + 9).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record is truncated")
            })?,
        ]) as usize;
        checked_advance(packet, &mut offset, 10)?;
        let data_start = offset;
        checked_advance(packet, &mut offset, data_length)?;
        if class != 1 || record_type != query_type {
            continue;
        }
        match query_type {
            1 if data_length == 4 => addresses.push(IpAddr::from([
                packet[data_start],
                packet[data_start + 1],
                packet[data_start + 2],
                packet[data_start + 3],
            ])),
            28 if data_length == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&packet[data_start..data_start + 16]);
                addresses.push(IpAddr::from(bytes));
            }
            _ => {}
        }
    }
    Ok(addresses)
}

fn skip_dns_name(packet: &[u8], offset: &mut usize) -> io::Result<()> {
    loop {
        let length = *packet.get(*offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS name is truncated")
        })?;
        if length & 0xc0 == 0xc0 {
            checked_advance(packet, offset, 2)?;
            return Ok(());
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS name contains an invalid label",
            ));
        }
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        checked_advance(packet, offset, length as usize)?;
    }
}

fn checked_advance(
    packet: &[u8],
    offset: &mut usize,
    amount: usize,
) -> io::Result<()> {
    let end = offset.checked_add(amount).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS response offset overflow")
    })?;
    if end > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is truncated",
        ));
    }
    *offset = end;
    Ok(())
}

/// Resolver wrapper for Xray's static `dns.hosts` IP mappings.
///
/// Host mappings use the same custom domain rule forms as Xray's hosts
/// builder. A miss deliberately falls through to the configured resolver;
/// after a `ProxiedDomain` mapping, that fallback uses the final alias just as
/// Xray's DNS client continues with the replaced domain.
pub struct HostsResolver {
    hosts: Arc<Vec<HostEntry>>,
    inner: Arc<dyn Resolver>,
}

#[derive(Clone)]
struct HostEntry {
    matcher: HostMatcher,
    value: HostRuleValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRuleValue {
    Ips(Vec<IpAddr>),
    ProxiedDomain(String),
    ResponseCode(u16),
}

#[derive(Debug)]
struct DnsResponseCode(u16);

impl fmt::Display for DnsResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "rcode: {}", self.0)
    }
}

impl std::error::Error for DnsResponseCode {}

fn dns_hosts_response_error(code: u16) -> io::Error {
    if code == 0 {
        io::Error::new(
            io::ErrorKind::NotFound,
            "DNS hosts returned an empty response",
        )
    } else {
        io::Error::other(DnsResponseCode(code))
    }
}

#[derive(Clone)]
enum HostMatcher {
    Full(String),
    Domain(String),
    Keyword(String),
    Regexp(regex::Regex),
}

impl HostsResolver {
    pub fn new(
        hosts: HashMap<String, Vec<IpAddr>>,
        inner: Arc<dyn Resolver>,
    ) -> Self {
        let hosts = hosts
            .into_iter()
            .filter_map(|(domain, addresses)| {
                Self::normalize_host(&domain).map(|domain| HostEntry {
                    matcher: HostMatcher::Full(domain),
                    value: HostRuleValue::Ips(addresses),
                })
            })
            .collect();
        Self {
            hosts: Arc::new(hosts),
            inner,
        }
    }

    fn with_rules(
        rules: Vec<(String, HostRuleValue)>,
        inner: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        let hosts = rules
            .into_iter()
            .map(|(rule, value)| {
                let value = match value {
                    HostRuleValue::Ips(addresses) => HostRuleValue::Ips(addresses),
                    HostRuleValue::ProxiedDomain(domain) => {
                        HostRuleValue::ProxiedDomain(
                            Self::normalize_host(&domain).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "invalid dns.hosts proxied domain",
                                )
                            })?,
                        )
                    }
                    HostRuleValue::ResponseCode(code) => {
                        HostRuleValue::ResponseCode(code)
                    }
                };
                Ok(HostEntry {
                    matcher: HostMatcher::from_rule(&rule)?,
                    value,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            hosts: Arc::new(hosts),
            inner,
        })
    }

    fn normalize_host(host: &str) -> Option<String> {
        let host = host.trim().trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        idna::domain_to_ascii(host)
            .ok()
            .map(|host| host.to_ascii_lowercase())
    }
}

impl HostMatcher {
    fn from_rule(rule: &str) -> io::Result<Self> {
        let rule = rule.trim();
        if let Some(pattern) = rule.strip_prefix("regexp:") {
            return regex::Regex::new(pattern)
                .map(Self::Regexp)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid dns.hosts regexp: {error}"),
                    )
                });
        }
        if let Some(pattern) = rule.strip_prefix("keyword:") {
            return Ok(Self::Keyword(pattern.to_ascii_lowercase()));
        }
        let (kind, pattern) = if let Some(pattern) = rule.strip_prefix("domain:") {
            ("domain", pattern)
        } else if let Some(pattern) = rule.strip_prefix("full:") {
            ("full", pattern)
        } else {
            ("full", rule)
        };
        let pattern = HostsResolver::normalize_host(pattern).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid dns.hosts domain rule: {rule}"),
            )
        })?;
        Ok(match kind {
            "domain" => Self::Domain(pattern),
            _ => Self::Full(pattern),
        })
    }

    fn from_server_rule(rule: &str) -> io::Result<Self> {
        let rule = rule.trim();
        if let Some(pattern) = rule.strip_prefix("regexp:") {
            return regex::Regex::new(pattern)
                .map(Self::Regexp)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid dns.servers domain regexp: {error}"),
                    )
                });
        }
        if let Some(pattern) = rule.strip_prefix("keyword:") {
            return Ok(Self::Keyword(pattern.to_ascii_lowercase()));
        }
        let (kind, pattern) = if let Some(pattern) = rule.strip_prefix("domain:") {
            ("domain", pattern)
        } else if let Some(pattern) = rule.strip_prefix("full:") {
            ("full", pattern)
        } else {
            ("keyword", rule)
        };
        let pattern = HostsResolver::normalize_host(pattern).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid dns.servers domain rule: {rule}"),
            )
        })?;
        Ok(match kind {
            "domain" => Self::Domain(pattern),
            "full" => Self::Full(pattern),
            _ => Self::Keyword(pattern),
        })
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(pattern) => domain == pattern,
            Self::Domain(pattern) => {
                domain == pattern || domain.ends_with(&format!(".{pattern}"))
            }
            Self::Keyword(pattern) => domain.contains(pattern),
            Self::Regexp(pattern) => pattern.is_match(domain),
        }
    }
}

impl Resolver for HostsResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        let Some(hostname) =
            location.address().hostname().and_then(Self::normalize_host)
        else {
            return self.inner.resolve_location(location);
        };
        let port = location.port();
        let hosts = Arc::clone(&self.hosts);
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let mut hostname = hostname;
            for depth in 0..=5 {
                let mut matched = false;
                let mut addresses = Vec::new();
                let mut proxied_domains = Vec::new();
                let mut response_code = None;
                for entry in hosts.iter() {
                    if !entry.matcher.matches(&hostname) {
                        continue;
                    }
                    matched = true;
                    match &entry.value {
                        HostRuleValue::Ips(values) => {
                            addresses.extend(values.iter().copied())
                        }
                        HostRuleValue::ProxiedDomain(domain) => {
                            proxied_domains.push(domain.clone())
                        }
                        HostRuleValue::ResponseCode(code) => {
                            response_code = Some(*code)
                        }
                    }
                }
                if !matched {
                    return inner
                        .resolve_location(&NetLocation::new(
                            Address::Hostname(hostname),
                            port,
                        ))
                        .await;
                }
                if let Some(code) = response_code {
                    return Err(dns_hosts_response_error(code));
                }
                if !addresses.is_empty() {
                    return Ok(addresses
                        .into_iter()
                        .map(|address| SocketAddr::new(address, port))
                        .collect());
                }
                if proxied_domains.len() != 1 {
                    return Ok(Vec::new());
                }
                if depth == 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dns.hosts proxied domain chain exceeded maximum depth",
                    ));
                }
                if let Some(domain) = proxied_domains.pop() {
                    hostname = domain;
                } else {
                    return Ok(Vec::new());
                }
            }
            unreachable!("proxied domain depth is bounded")
        })
    }
}

/// System resolver with a process-wide shared DNS cache.
pub struct NativeResolver {
    cached: CachedResolver,
}

/// Runtime switches owned by the shared native resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeResolverOptions {
    pub disable_cache: bool,
    pub enable_parallel_query: bool,
}

#[allow(dead_code)]
impl NativeResolver {
    pub fn new() -> Self {
        Self::with_hosts(HashMap::new())
    }

    pub fn with_hosts(hosts: HashMap<String, Vec<IpAddr>>) -> Self {
        static CACHE: OnceLock<Arc<ResolverCache>> = OnceLock::new();
        let system: Arc<dyn Resolver> =
            Arc::new(SystemResolver::new(DnsQueryStrategy::UseIp));
        let has_hosts = !hosts.is_empty();
        let base: Arc<dyn Resolver> = if has_hosts {
            Arc::new(HostsResolver::new(hosts, system))
        } else {
            system
        };
        let normalized: Arc<dyn Resolver> = Arc::new(AddressOrderingResolver::new(
            base,
            AddressFamilyPreference::Preserve,
        ));
        let bounded: Arc<dyn Resolver> =
            Arc::new(TimeoutResolver::new(normalized, DEFAULT_LOOKUP_TIMEOUT));
        let cached = if has_hosts {
            CachedResolver::new(bounded)
        } else {
            let cache = CACHE
                .get_or_init(|| {
                    Arc::new(ResolverCache::new(ResolverCacheOptions::default()))
                })
                .clone();
            CachedResolver::with_cache(bounded, cache)
        };
        Self { cached }
    }

    pub fn with_host_rules(hosts: Vec<(String, HostRuleValue)>) -> io::Result<Self> {
        Self::with_host_rules_and_servers(hosts, Vec::new())
    }

    pub fn with_servers(servers: Vec<SocketAddr>) -> io::Result<Self> {
        Self::with_host_rules_and_servers(Vec::new(), servers)
    }

    pub fn with_servers_and_query_strategy(
        servers: Vec<SocketAddr>,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_servers_with_query_strategy(
            Vec::new(),
            servers,
            query_strategy,
        )
    }

    pub fn with_host_rules_and_servers(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<SocketAddr>,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_servers_with_query_strategy(
            hosts,
            servers,
            DnsQueryStrategy::UseIp,
        )
    }

    pub fn with_host_rules_and_servers_with_query_strategy(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<SocketAddr>,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Self> {
        let servers = servers
            .into_iter()
            .map(|address| CompiledDnsServer {
                address,
                transport: DnsServerTransport::Udp,
                client_ip: None,
                query_strategy: None,
                domains: Vec::new(),
                skip_fallback: false,
                final_query: false,
                timeout_ms: None,
                expected_ips: Vec::new(),
                expected_ips_prefer: false,
                unexpected_ips: Vec::new(),
                unexpected_ips_prefer: false,
            })
            .collect();
        Self::with_host_rules_and_server_configs_with_query_strategy(
            hosts,
            servers,
            query_strategy,
        )
    }

    pub fn with_host_rules_and_server_configs_with_query_strategy(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options(
            hosts,
            servers,
            query_strategy,
            false,
            false,
        )
    }

    pub fn with_host_rules_and_server_configs_with_query_strategy_and_fallback_options(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_client_ip(
            hosts,
            servers,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            None,
        )
    }

    pub fn with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_client_ip(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_resolver_options(
            hosts,
            servers,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            client_ip,
            false,
        )
    }

    pub fn with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_resolver_options(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
        client_ip: Option<IpAddr>,
        disable_cache: bool,
    ) -> io::Result<Self> {
        Self::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_runtime_options(
            hosts,
            servers,
            query_strategy,
            disable_fallback,
            disable_fallback_if_match,
            client_ip,
            NativeResolverOptions {
                disable_cache,
                enable_parallel_query: false,
            },
        )
    }

    pub fn with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_runtime_options(
        hosts: Vec<(String, HostRuleValue)>,
        servers: Vec<CompiledDnsServer>,
        query_strategy: DnsQueryStrategy,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
        client_ip: Option<IpAddr>,
        options: NativeResolverOptions,
    ) -> io::Result<Self> {
        static CACHE: OnceLock<Arc<ResolverCache>> = OnceLock::new();
        let has_custom_resolver = !hosts.is_empty() || !servers.is_empty();
        let system: Arc<dyn Resolver> = if servers.is_empty() {
            Arc::new(SystemResolver::new(query_strategy))
        } else {
            Arc::new(
                UdpDnsResolver::with_server_configs_with_fallback_options_and_client_ip_and_parallel_query(
                    servers,
                    query_strategy,
                    disable_fallback,
                    disable_fallback_if_match,
                    client_ip,
                    options.enable_parallel_query,
                )?,
            )
        };
        let base: Arc<dyn Resolver> = if hosts.is_empty() {
            system
        } else {
            Arc::new(HostsResolver::with_rules(hosts, system)?)
        };
        let bounded: Arc<dyn Resolver> =
            Arc::new(TimeoutResolver::new(base, DEFAULT_LOOKUP_TIMEOUT));
        let cached = if options.disable_cache {
            CachedResolver::without_cache(bounded)
        } else if has_custom_resolver {
            CachedResolver::new(bounded)
        } else {
            let cache = CACHE
                .get_or_init(|| {
                    Arc::new(ResolverCache::new(ResolverCacheOptions::default()))
                })
                .clone();
            CachedResolver::with_cache(bounded, cache)
        };
        Ok(Self { cached })
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

    #[derive(Clone)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        requested_domains: Arc<Mutex<Vec<String>>>,
        delay: Duration,
        response: Result<Vec<SocketAddr>, (io::ErrorKind, String)>,
    }

    impl CountingResolver {
        fn successful(delay: Duration) -> Self {
            Self::successful_with(delay, vec!["192.0.2.1:443".parse().unwrap()])
        }

        fn successful_with(delay: Duration, addresses: Vec<SocketAddr>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requested_domains: Arc::new(Mutex::new(Vec::new())),
                delay,
                response: Ok(addresses),
            }
        }

        fn failing() -> Self {
            Self::failing_with("test DNS failure")
        }

        fn failing_with(message: &str) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requested_domains: Arc::new(Mutex::new(Vec::new())),
                delay: Duration::ZERO,
                response: Err((io::ErrorKind::NotFound, message.into())),
            }
        }

        fn empty() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requested_domains: Arc::new(Mutex::new(Vec::new())),
                delay: Duration::ZERO,
                response: Ok(Vec::new()),
            }
        }
    }

    impl Resolver for CountingResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
        {
            let calls = self.calls.clone();
            let requested_domains = self.requested_domains.clone();
            let requested_domain = location.address().to_string();
            let delay = self.delay;
            let response = self.response.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::Relaxed);
                requested_domains.lock().unwrap().push(requested_domain);
                tokio::time::sleep(delay).await;
                response.map_err(|(kind, message)| io::Error::new(kind, message))
            })
        }
    }

    fn domain_location() -> NetLocation {
        NetLocation::from_str("cache.example:443", None).unwrap()
    }

    async fn start_dns_fixture(answer: Option<[u8; 4]>) -> SocketAddr {
        start_dns_fixture_with_request_count(answer, 2).await
    }

    async fn start_dns_fixture_with_request_count(
        answer: Option<[u8; 4]>,
        request_count: usize,
    ) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind DNS fixture");
        let address = socket.local_addr().expect("DNS fixture address");
        tokio::spawn(async move {
            let mut request = [0u8; DNS_MAX_PACKET_SIZE];
            for _ in 0..request_count {
                let (length, peer) = socket
                    .recv_from(&mut request)
                    .await
                    .expect("receive DNS fixture query");
                let mut question_end = 12;
                skip_dns_name(&request[..length], &mut question_end)
                    .expect("valid DNS fixture question name");
                checked_advance(&request[..length], &mut question_end, 4)
                    .expect("valid DNS fixture question");
                let query_type = u16::from_be_bytes([
                    request[question_end - 4],
                    request[question_end - 3],
                ]);
                let response = build_dns_fixture_response(
                    &request[..length],
                    question_end,
                    query_type == 1 && answer.is_some(),
                    answer.unwrap_or([0, 0, 0, 0]),
                );
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("send DNS fixture response");
            }
        });
        address
    }

    async fn start_tcp_dns_fixture(
        answer: [u8; 4],
        request_count: usize,
    ) -> SocketAddr {
        start_tcp_dns_fixture_with_delay(answer, request_count, Duration::ZERO).await
    }

    async fn start_tcp_dns_fixture_with_delay(
        answer: [u8; 4],
        request_count: usize,
        delay: Duration,
    ) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP DNS fixture");
        let address = listener.local_addr().expect("TCP DNS fixture address");
        tokio::spawn(async move {
            for _ in 0..request_count {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept TCP DNS fixture connection");
                let mut length = [0u8; 2];
                stream
                    .read_exact(&mut length)
                    .await
                    .expect("receive TCP DNS query length");
                let length = usize::from(u16::from_be_bytes(length));
                let mut request = vec![0u8; length];
                stream
                    .read_exact(&mut request)
                    .await
                    .expect("receive TCP DNS query");
                let mut question_end = 12;
                skip_dns_name(&request, &mut question_end)
                    .expect("valid TCP DNS fixture question name");
                checked_advance(&request, &mut question_end, 4)
                    .expect("valid TCP DNS fixture question");
                let query_type = u16::from_be_bytes([
                    request[question_end - 4],
                    request[question_end - 3],
                ]);
                let response = build_dns_fixture_response(
                    &request,
                    question_end,
                    query_type == 1,
                    answer,
                );
                tokio::time::sleep(delay).await;
                let response_length = u16::try_from(response.len())
                    .expect("TCP DNS fixture response fits wire length");
                stream
                    .write_all(&response_length.to_be_bytes())
                    .await
                    .expect("send TCP DNS response length");
                stream
                    .write_all(&response)
                    .await
                    .expect("send TCP DNS response");
            }
        });
        address
    }

    async fn start_dns_fixture_observing_ecs(
        answer: [u8; 4],
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Option<Vec<u8>>>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind ECS DNS fixture");
        let address = socket.local_addr().expect("ECS DNS fixture address");
        let (observed_sender, observed_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut observed_sender = Some(observed_sender);
            let mut request = [0u8; DNS_MAX_PACKET_SIZE];
            let (length, peer) = socket
                .recv_from(&mut request)
                .await
                .expect("receive ECS DNS fixture query");
            let mut question_end = 12;
            skip_dns_name(&request[..length], &mut question_end)
                .expect("valid ECS DNS fixture question name");
            checked_advance(&request[..length], &mut question_end, 4)
                .expect("valid ECS DNS fixture question");
            if let Some(sender) = observed_sender.take() {
                let _ = sender.send(extract_dns_client_subnet(
                    &request[..length],
                    question_end,
                ));
            }
            let query_type = u16::from_be_bytes([
                request[question_end - 4],
                request[question_end - 3],
            ]);
            let response = build_dns_fixture_response(
                &request[..length],
                question_end,
                query_type == 1,
                answer,
            );
            socket
                .send_to(&response, peer)
                .await
                .expect("send ECS DNS fixture response");
        });
        (address, observed_receiver)
    }

    fn extract_dns_client_subnet(
        packet: &[u8],
        mut offset: usize,
    ) -> Option<Vec<u8>> {
        if packet.get(offset).copied() != Some(0)
            || packet.get(offset + 1).copied() != Some(0)
            || packet.get(offset + 2).copied() != Some(41)
        {
            return None;
        }
        offset += 9;
        let data_length = usize::from(u16::from_be_bytes([
            *packet.get(offset)?,
            *packet.get(offset + 1)?,
        ]));
        offset += 2;
        let end = offset.checked_add(data_length)?;
        while offset + 4 <= end {
            let code = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let length = usize::from(u16::from_be_bytes([
                packet[offset + 2],
                packet[offset + 3],
            ]));
            offset += 4;
            let option_end = offset.checked_add(length)?;
            if option_end > end {
                return None;
            }
            if code == 8 {
                return Some(packet[offset..option_end].to_vec());
            }
            offset = option_end;
        }
        None
    }

    async fn start_silent_dns_fixture() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind silent DNS fixture");
        let address = socket.local_addr().expect("silent DNS fixture address");
        tokio::spawn(async move {
            let mut request = [0u8; DNS_MAX_PACKET_SIZE];
            while socket.recv_from(&mut request).await.is_ok() {}
        });
        address
    }

    fn build_dns_fixture_response(
        request: &[u8],
        question_end: usize,
        include_answer: bool,
        answer: [u8; 4],
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(question_end + 32);
        response.extend_from_slice(&request[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(include_answer as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&request[12..question_end]);
        if include_answer {
            response.extend_from_slice(&0xc00cu16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&answer);
        }
        response
    }

    #[test]
    fn dns_query_strategy_selects_xray_record_types() {
        assert_eq!(
            UdpDnsResolver::query_types(DnsQueryStrategy::UseIp).unwrap(),
            vec![1, 28]
        );
        assert_eq!(
            UdpDnsResolver::query_types(DnsQueryStrategy::UseIpv4).unwrap(),
            vec![1]
        );
        assert_eq!(
            UdpDnsResolver::query_types(DnsQueryStrategy::UseIpv6).unwrap(),
            vec![28]
        );
    }

    #[test]
    fn dns_query_adds_xray_edns_client_subnet() {
        let without_ecs = build_dns_query(0x1234, "example.com", 1, None)
            .expect("build DNS query without ECS");
        let ipv4 = build_dns_query(
            0x1234,
            "example.com",
            1,
            Some("192.0.2.129".parse().unwrap()),
        )
        .expect("build IPv4 ECS DNS query");
        assert!(extract_dns_client_subnet(&ipv4, without_ecs.len()).is_some());
        assert_eq!(&ipv4[10..12], &1u16.to_be_bytes());
        assert_eq!(
            &ipv4[without_ecs.len()..],
            &[
                0, 0, 0x29, 0x05, 0x46, 0xe0, 0x00, 0x80, 0x00, 0, 11, 0, 8, 0, 7,
                0, 1, 24, 0, 192, 0, 2
            ]
        );

        let ipv6 = build_dns_query(
            0x1234,
            "example.com",
            28,
            Some("2001:db8:1234:5678::9".parse().unwrap()),
        )
        .expect("build IPv6 ECS DNS query");
        assert_eq!(&ipv6[10..12], &1u16.to_be_bytes());
        assert_eq!(
            &ipv6[without_ecs.len()..],
            &[
                0, 0, 0x29, 0x05, 0x46, 0xe0, 0x00, 0x80, 0x00, 0, 20, 0, 8, 0, 16,
                0, 2, 96, 0, 0x20, 1, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0,
                0
            ]
        );
    }

    #[tokio::test]
    async fn system_dns_resolver_applies_ipv4_query_strategy() {
        let resolver = SystemResolver::new(DnsQueryStrategy::UseIpv4);
        let location = NetLocation::from_str("localhost:443", None)
            .expect("valid localhost location");
        let addresses = resolver
            .resolve_location(&location)
            .await
            .expect("resolve localhost through system resolver");

        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(SocketAddr::is_ipv4));
    }

    #[tokio::test]
    async fn hosts_resolver_matches_case_trailing_dot_and_idn() {
        let inner = CountingResolver::failing_with("system resolver must not run");
        let resolver = HostsResolver::new(
            HashMap::from([
                (
                    "example.com".to_string(),
                    vec!["192.0.2.10".parse().unwrap()],
                ),
                (
                    "xn--bcher-kva.example".to_string(),
                    vec!["2001:db8::10".parse().unwrap()],
                ),
            ]),
            Arc::new(inner.clone()),
        );

        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("EXAMPLE.COM.:8443", None).unwrap()
                )
                .await
                .unwrap(),
            vec!["192.0.2.10:8443".parse().unwrap()]
        );
        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("bücher.example:443", None).unwrap()
                )
                .await
                .unwrap(),
            vec!["[2001:db8::10]:443".parse().unwrap()]
        );
        assert_eq!(inner.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn hosts_resolver_matches_xray_domain_rule_forms() {
        let inner = CountingResolver::failing_with("system resolver must not run");
        let resolver = HostsResolver::with_rules(
            vec![
                (
                    "domain:example.com".into(),
                    HostRuleValue::Ips(vec!["192.0.2.10".parse().unwrap()]),
                ),
                (
                    "keyword:service".into(),
                    HostRuleValue::Ips(vec!["192.0.2.11".parse().unwrap()]),
                ),
                (
                    "regexp:^api\\.example\\.com$".into(),
                    HostRuleValue::Ips(vec!["192.0.2.12".parse().unwrap()]),
                ),
            ],
            Arc::new(inner.clone()),
        )
        .expect("valid Xray host rules");

        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("www.example.com:443", None).unwrap()
                )
                .await
                .unwrap(),
            vec!["192.0.2.10:443".parse().unwrap()]
        );
        assert!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("badexample.com:443", None).unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("api.service.example.com:443", None)
                        .unwrap()
                )
                .await
                .unwrap(),
            vec![
                "192.0.2.10:443".parse().unwrap(),
                "192.0.2.11:443".parse().unwrap(),
            ]
        );
        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("API.EXAMPLE.COM:443", None).unwrap()
                )
                .await
                .unwrap(),
            vec![
                "192.0.2.10:443".parse().unwrap(),
                "192.0.2.12:443".parse().unwrap(),
            ]
        );
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn hosts_resolver_returns_xray_response_code_without_upstream_fallback() {
        let inner =
            CountingResolver::failing_with("static response code must stop lookup");
        let resolver = HostsResolver::with_rules(
            vec![
                (
                    "full:nxdomain.example".into(),
                    HostRuleValue::ResponseCode(3),
                ),
                ("full:empty.example".into(), HostRuleValue::ResponseCode(0)),
            ],
            Arc::new(inner.clone()),
        )
        .expect("valid response-code host rules");

        let error = resolver
            .resolve_location(
                &NetLocation::from_str("NXDOMAIN.EXAMPLE.:443", None).unwrap(),
            )
            .await
            .expect_err("#3 must return a DNS response-code error");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "rcode: 3");

        let error = resolver
            .resolve_location(
                &NetLocation::from_str("empty.example:443", None).unwrap(),
            )
            .await
            .expect_err("#0 must return an empty response");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "DNS hosts returned an empty response");
        assert_eq!(inner.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn hosts_resolver_unwraps_proxied_domain_and_falls_through_after_alias_miss()
     {
        let inner = CountingResolver::successful_with(
            Duration::ZERO,
            vec!["192.0.2.20:443".parse().unwrap()],
        );
        let resolver = HostsResolver::with_rules(
            vec![
                (
                    "full:alias.example".into(),
                    HostRuleValue::ProxiedDomain("target.example".into()),
                ),
                (
                    "full:target.example".into(),
                    HostRuleValue::Ips(vec!["192.0.2.10".parse().unwrap()]),
                ),
                (
                    "full:missing-alias.example".into(),
                    HostRuleValue::ProxiedDomain("not-mapped.example".into()),
                ),
            ],
            Arc::new(inner.clone()),
        )
        .expect("valid proxied domain host rules");

        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("alias.example:8443", None).unwrap()
                )
                .await
                .unwrap(),
            vec!["192.0.2.10:8443".parse().unwrap()]
        );
        assert_eq!(
            resolver
                .resolve_location(
                    &NetLocation::from_str("missing-alias.example:443", None)
                        .unwrap(),
                )
                .await
                .unwrap(),
            vec!["192.0.2.20:443".parse().unwrap()]
        );
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            inner.requested_domains.lock().unwrap().as_slice(),
            ["not-mapped.example"]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_queries_configured_server() {
        let server = start_dns_fixture(Some([203, 0, 113, 9])).await;
        let resolver = NativeResolver::with_servers(vec![server])
            .expect("configure UDP DNS resolver");
        let location = NetLocation::from_str("fixture.example:8443", None)
            .expect("valid fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("resolve through configured DNS server"),
            vec!["203.0.113.9:8443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn tcp_dns_resolver_queries_xray_tcp_server() {
        let server = start_tcp_dns_fixture([203, 0, 113, 15], 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![CompiledDnsServer {
                    address: server,
                    transport: DnsServerTransport::Tcp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                }],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure DNS over TCP resolver");
        let location = NetLocation::from_str("tcp-fixture.example:8443", None)
            .expect("valid TCP fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("resolve through DNS over TCP fixture"),
            vec!["203.0.113.15:8443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_parallel_query_returns_fast_same_policy_server() {
        let slow_server = start_tcp_dns_fixture_with_delay(
            [203, 0, 113, 40],
            1,
            Duration::from_millis(100),
        )
        .await;
        let fast_server = start_tcp_dns_fixture([203, 0, 113, 41], 1).await;
        let resolver = NativeResolver::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_runtime_options(
            Vec::new(),
            vec![
                CompiledDnsServer {
                    address: slow_server,
                    transport: DnsServerTransport::Tcp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
                CompiledDnsServer {
                    address: fast_server,
                    transport: DnsServerTransport::Tcp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
            ],
            DnsQueryStrategy::UseIpv4,
            false,
            false,
            None,
            NativeResolverOptions {
                disable_cache: true,
                enable_parallel_query: true,
            },
        )
        .expect("configure parallel DNS resolver");
        let location = NetLocation::from_str("parallel.example:443", None)
            .expect("valid parallel fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("fast parallel DNS server should answer"),
            vec!["203.0.113.41:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_parallel_query_preserves_policy_group_priority() {
        let priority_server = start_tcp_dns_fixture_with_delay(
            [203, 0, 113, 42],
            1,
            Duration::from_millis(100),
        )
        .await;
        let fallback_server = start_tcp_dns_fixture([203, 0, 113, 43], 1).await;
        let resolver = NativeResolver::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_runtime_options(
            Vec::new(),
            vec![
                CompiledDnsServer {
                    address: priority_server,
                    transport: DnsServerTransport::Tcp,
                    client_ip: Some("192.0.2.44".parse().unwrap()),
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
                CompiledDnsServer {
                    address: fallback_server,
                    transport: DnsServerTransport::Tcp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
            ],
            DnsQueryStrategy::UseIpv4,
            false,
            false,
            None,
            NativeResolverOptions {
                disable_cache: true,
                enable_parallel_query: true,
            },
        )
        .expect("configure prioritized parallel DNS resolver");
        let location = NetLocation::from_str("priority.example:443", None)
            .expect("valid priority fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("priority DNS server should answer"),
            vec!["203.0.113.42:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_ipv4_query_strategy() {
        let server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 11]), 1).await;
        let resolver = NativeResolver::with_servers_and_query_strategy(
            vec![server],
            DnsQueryStrategy::UseIpv4,
        )
        .expect("configure IPv4-only UDP DNS resolver");
        let location = NetLocation::from_str("ipv4-only.example:443", None)
            .expect("valid fixture location");

        let addresses = tokio::time::timeout(
            Duration::from_millis(500),
            resolver.resolve_location(&location),
        )
        .await
        .expect("IPv4-only lookup should not wait for an AAAA response")
        .expect("resolve through IPv4-only configured DNS server");
        assert_eq!(addresses, vec!["203.0.113.11:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_per_server_query_strategy() {
        let server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 12]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![CompiledDnsServer {
                    address: server,
                    transport: DnsServerTransport::Udp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                }],
                DnsQueryStrategy::UseIpv6,
            )
            .expect("configure per-server DNS query strategy");
        let location = NetLocation::from_str("per-server.example:443", None)
            .expect("valid per-server fixture location");

        let addresses = tokio::time::timeout(
            Duration::from_millis(500),
            resolver.resolve_location(&location),
        )
        .await
        .expect("per-server IPv4 lookup should not wait for an AAAA response")
        .expect("resolve through per-server query strategy");
        assert_eq!(addresses, vec!["203.0.113.12:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn udp_dns_resolver_sends_xray_client_ip_with_server_override() {
        let cases = [
            (None, "192.0.2.44", "global-ecs.example"),
            (
                Some("198.51.100.44"),
                "198.51.100.44",
                "override-ecs.example",
            ),
        ];
        for (server_client_ip, expected_prefix, hostname) in cases {
            let (server, observed) =
                start_dns_fixture_observing_ecs([203, 0, 113, 13]).await;
            let resolver =
                NativeResolver::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_client_ip(
                    Vec::new(),
                    vec![CompiledDnsServer {
                        address: server,
                        transport: DnsServerTransport::Udp,
                        client_ip: server_client_ip.map(|ip| ip.parse().unwrap()),
                        query_strategy: Some(DnsQueryStrategy::UseIpv4),
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    }],
                    DnsQueryStrategy::UseIpv4,
                    false,
                    false,
                    Some("192.0.2.44".parse().unwrap()),
                )
                .expect("configure ECS DNS resolver");
            let location = NetLocation::from_str(&format!("{hostname}:443"), None)
                .expect("valid ECS fixture location");
            resolver
                .resolve_location(&location)
                .await
                .expect("resolve through ECS fixture");

            let expected_ip: IpAddr = expected_prefix.parse().unwrap();
            let expected = match expected_ip {
                IpAddr::V4(ip) => {
                    [vec![0, 1, 24, 0], ip.octets()[..3].to_vec()].concat()
                }
                IpAddr::V6(ip) => {
                    [vec![0, 2, 96, 0], ip.octets()[..12].to_vec()].concat()
                }
            };
            assert_eq!(observed.await.expect("observe ECS query"), Some(expected));
        }
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_xray_per_server_timeout() {
        let server = start_silent_dns_fixture().await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![CompiledDnsServer {
                    address: server,
                    transport: DnsServerTransport::Udp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv4),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: Some(20),
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                }],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure per-server DNS timeout");
        let location = NetLocation::from_str("timeout.example:443", None)
            .expect("valid timeout fixture location");

        let started = Instant::now();
        let error = resolver
            .resolve_location(&location)
            .await
            .expect_err("silent DNS server should time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= Duration::from_millis(10),
            "configured timeout should be observable"
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_prioritizes_xray_server_domain_matches() {
        let default_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 21]), 1).await;
        let domain_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 22]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: default_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: domain_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: vec!["domain:example.com".into()],
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure domain-selected DNS servers");

        let matched = NetLocation::from_str("api.example.com:443", None)
            .expect("valid matching fixture location");
        assert_eq!(
            resolver
                .resolve_location(&matched)
                .await
                .expect("resolve through matching DNS server"),
            vec!["203.0.113.22:443".parse().unwrap()]
        );

        let fallback = NetLocation::from_str("other.example.net:443", None)
            .expect("valid fallback fixture location");
        assert_eq!(
            resolver
                .resolve_location(&fallback)
                .await
                .expect("resolve through default DNS server"),
            vec!["203.0.113.21:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_xray_skip_fallback() {
        let skipped_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 23]), 1).await;
        let fallback_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 24]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: skipped_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: true,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: fallback_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure skip-fallback DNS servers");
        let location = NetLocation::from_str("skip-fallback.example:443", None)
            .expect("valid skip-fallback fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("skip-fallback server should not be queried"),
            vec!["203.0.113.24:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_stops_at_xray_final_query() {
        let default_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 25]), 1).await;
        let final_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 26]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: default_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: final_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: vec!["full:final.example".into()],
                        skip_fallback: false,
                        final_query: true,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure final-query DNS servers");
        let location = NetLocation::from_str("final.example:443", None)
            .expect("valid final-query fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("final-query server should terminate selection"),
            vec!["203.0.113.26:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_disables_fallback_after_domain_match() {
        for (disable_fallback, disable_fallback_if_match) in
            [(true, false), (false, true), (true, true)]
        {
            let matched_server = start_dns_fixture_with_request_count(None, 1).await;
            let fallback_server =
                start_dns_fixture_with_request_count(Some([203, 0, 113, 27]), 1)
                    .await;
            let resolver = NativeResolver::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: matched_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: vec!["full:no-fallback.example".into()],
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: fallback_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
                disable_fallback,
                disable_fallback_if_match,
            )
            .expect("configure DNS fallback switches");
            let location = NetLocation::from_str("no-fallback.example:443", None)
                .expect("valid no-fallback fixture location");

            assert!(
                resolver.resolve_location(&location).await.is_err(),
                "a matched empty server must not fall back when Xray fallback is disabled"
            );
        }
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_expected_ip_filter() {
        let server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 30]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![CompiledDnsServer {
                    address: server,
                    transport: DnsServerTransport::Udp,
                    client_ip: None,
                    query_strategy: None,
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: vec!["203.0.113.0/24".into()],
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                }],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure expected IP filter");
        let location = NetLocation::from_str("expected-filter.example:443", None)
            .expect("valid expected-filter fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("expected IP should be retained"),
            vec!["203.0.113.30:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_falls_back_after_expected_ip_filter_removes_answer() {
        let filtered_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 31]), 1).await;
        let fallback_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 32]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: filtered_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: vec!["192.0.2.0/24".into()],
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: fallback_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure expected IP fallback");
        let location = NetLocation::from_str("expected-fallback.example:443", None)
            .expect("valid expected fallback fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("fallback server should answer after filtering"),
            vec!["203.0.113.32:443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_applies_unexpected_ip_filter() {
        let filtered_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 33]), 1).await;
        let fallback_server =
            start_dns_fixture_with_request_count(Some([203, 0, 113, 34]), 1).await;
        let resolver =
            NativeResolver::with_host_rules_and_server_configs_with_query_strategy(
                Vec::new(),
                vec![
                    CompiledDnsServer {
                        address: filtered_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: vec!["203.0.113.0/24".into()],
                        unexpected_ips_prefer: false,
                    },
                    CompiledDnsServer {
                        address: fallback_server,
                        transport: DnsServerTransport::Udp,
                        client_ip: None,
                        query_strategy: None,
                        domains: Vec::new(),
                        skip_fallback: false,
                        final_query: false,
                        timeout_ms: None,
                        expected_ips: Vec::new(),
                        expected_ips_prefer: false,
                        unexpected_ips: Vec::new(),
                        unexpected_ips_prefer: false,
                    },
                ],
                DnsQueryStrategy::UseIpv4,
            )
            .expect("configure unexpected IP fallback");
        let location = NetLocation::from_str("unexpected-filter.example:443", None)
            .expect("valid unexpected filter fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("fallback server should answer after unexpected filtering"),
            vec!["203.0.113.34:443".parse().unwrap()]
        );
    }

    #[test]
    fn dns_server_ip_filters_match_xray_prefer_and_reverse_semantics() {
        let addresses = vec![
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            "198.51.100.10".parse::<IpAddr>().unwrap(),
        ];
        let expected = DnsIpMatcher::from_rules(&["203.0.113.0/24".into()])
            .expect("valid expected IP rules")
            .expect("expected matcher");
        let server = UdpDnsServer {
            address: "127.0.0.1:53".parse().unwrap(),
            transport: DnsServerTransport::Udp,
            parallel_policy_key: String::new(),
            client_ip: None,
            query_strategy: None,
            domain_matchers: Vec::new(),
            skip_fallback: false,
            final_query: false,
            timeout_ms: None,
            expected_ips: Some(expected.clone()),
            expected_ips_prefer: true,
            unexpected_ips: None,
            unexpected_ips_prefer: false,
        };
        assert_eq!(
            filter_dns_server_addresses(addresses.clone(), &server),
            vec!["203.0.113.10".parse::<IpAddr>().unwrap()]
        );

        let no_expected_match = UdpDnsServer {
            expected_ips: Some(expected),
            expected_ips_prefer: true,
            ..server.clone()
        };
        assert_eq!(
            filter_dns_server_addresses(
                vec![
                    "192.0.2.10".parse::<IpAddr>().unwrap(),
                    "198.51.100.10".parse::<IpAddr>().unwrap()
                ],
                &no_expected_match,
            ),
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "198.51.100.10".parse::<IpAddr>().unwrap()
            ]
        );

        let reverse_unexpected =
            DnsIpMatcher::from_rules(&["!203.0.113.0/24".into()])
                .expect("valid reverse unexpected IP rules")
                .expect("unexpected matcher");
        let reverse_server = UdpDnsServer {
            expected_ips: None,
            expected_ips_prefer: false,
            unexpected_ips: Some(reverse_unexpected),
            unexpected_ips_prefer: false,
            ..server
        };
        assert_eq!(
            filter_dns_server_addresses(addresses, &reverse_server),
            vec!["203.0.113.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn udp_dns_resolver_tries_servers_in_order_after_empty_response() {
        let empty_server = start_dns_fixture(None).await;
        let answer_server = start_dns_fixture(Some([203, 0, 113, 10])).await;
        let resolver =
            NativeResolver::with_servers(vec![empty_server, answer_server])
                .expect("configure ordered UDP DNS resolvers");
        let location = NetLocation::from_str("ordered.example:9443", None)
            .expect("valid ordered fixture location");

        assert_eq!(
            resolver
                .resolve_location(&location)
                .await
                .expect("fall back to the second DNS server"),
            vec!["203.0.113.10:9443".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn hosts_resolver_rejects_proxied_domain_cycles() {
        let resolver = HostsResolver::with_rules(
            vec![
                (
                    "full:first.example".into(),
                    HostRuleValue::ProxiedDomain("second.example".into()),
                ),
                (
                    "full:second.example".into(),
                    HostRuleValue::ProxiedDomain("first.example".into()),
                ),
            ],
            Arc::new(CountingResolver::failing_with("must not fall through")),
        )
        .expect("valid cyclic host rules");

        let error = resolver
            .resolve_location(
                &NetLocation::from_str("first.example:443", None).unwrap(),
            )
            .await
            .expect_err("proxied domain cycle must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn hosts_resolver_falls_through_for_unmapped_domains() {
        let inner = CountingResolver::successful(Duration::ZERO);
        let resolver = HostsResolver::new(HashMap::new(), Arc::new(inner.clone()));

        assert!(resolver.resolve_location(&domain_location()).await.is_ok());
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    fn test_options() -> ResolverCacheOptions {
        ResolverCacheOptions {
            positive_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(30),
            max_entries: 16,
        }
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
    async fn disabling_xray_dns_cache_queries_upstream_each_time() {
        let upstream = CountingResolver::successful(Duration::ZERO);
        let calls = upstream.calls.clone();
        let resolver = CachedResolver::without_cache(Arc::new(upstream));
        let location = domain_location();

        resolver.resolve_location(&location).await.unwrap();
        resolver.resolve_location(&location).await.unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(resolver.stats(), ResolverCacheStats::default());
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
