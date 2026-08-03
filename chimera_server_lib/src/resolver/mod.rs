use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::future::FutureExt;
use tokio::sync::watch;
use tracing::debug;

use crate::address::NetLocation;

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
