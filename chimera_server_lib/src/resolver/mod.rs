use std::{
    collections::HashMap,
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
                    return CacheDecision::Ready(result.clone());
                }
                CacheEntry::InFlight { sender, .. } => {
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
        CacheDecision::Resolve { id, sender }
    }

    fn finish(
        &self,
        location: &NetLocation,
        id: u64,
        sender: &watch::Sender<Option<CachedLookupResult>>,
        result: CachedLookupResult,
    ) {
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
        Self {
            cached: CachedResolver::with_cache(Arc::new(SystemResolver), cache),
        }
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
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                response: Err((io::ErrorKind::NotFound, "test DNS failure".into())),
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
