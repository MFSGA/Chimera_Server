use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    sync::{Arc, RwLock},
};

use tokio::{sync::Mutex, task::JoinHandle};

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::connection::HysteriaUserStore;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksUserStore;
use crate::{
    beginning::start_servers,
    config::server_config::{ServerConfig, ServerProxyConfig},
    runtime::RuntimeState,
};
#[cfg(feature = "trojan")]
use crate::{config::server_config::TrojanUser, handler::trojan::TrojanUserStore};
#[cfg(feature = "vmess")]
use crate::{
    config::server_config::VmessUser, handler::vmess::vmess_handler::VmessUserStore,
};

const OPERATION_LOCK_SHARDS: usize = 64;

/// Owns mutable inbound runtime state and lifecycle serialization.
///
/// Tags are external addresses, while `generation` identifies one concrete
/// incarnation of a tag. Generation-aware task operations prevent delayed
/// cleanup from an older incarnation from affecting a replacement instance.
#[derive(Debug)]
pub(crate) struct InboundManager {
    state: RwLock<InboundState>,
    operation_locks: [Mutex<()>; OPERATION_LOCK_SHARDS],
}

#[derive(Debug)]
struct InboundState {
    configs: Vec<InboundInstance>,
    pending: HashMap<String, PendingInboundLifecycle>,
    next_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundLifecycleState {
    Prepared,
    Starting,
    Running,
    Stopping,
    Recovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingInboundLifecycle {
    generation: u64,
    lifecycle: InboundLifecycleState,
}

#[derive(Debug)]
struct InboundInstance {
    generation: u64,
    lifecycle: InboundLifecycleState,
    tasks: Option<Vec<JoinHandle<()>>>,
    config: ServerConfig,
    #[cfg(feature = "vless")]
    vless_users: Option<VlessUserStore>,
    #[cfg(feature = "vmess")]
    vmess_users: Option<Arc<VmessUserStore>>,
    #[cfg(feature = "trojan")]
    trojan_users: Option<Arc<TrojanUserStore>>,
    #[cfg(feature = "hysteria")]
    hysteria_users: Option<Arc<HysteriaUserStore>>,
    #[cfg(feature = "shadowsocks")]
    shadowsocks_users: Option<Arc<ShadowsocksUserStore>>,
}

#[cfg(feature = "vless")]
#[derive(Debug, Clone)]
struct VlessUserStore(Arc<RwLock<Vec<VlessUser>>>);

#[cfg(feature = "vless")]
impl VlessUserStore {
    fn new(users: Vec<VlessUser>) -> Self {
        Self(Arc::new(RwLock::new(users)))
    }

    fn snapshot(&self) -> Vec<VlessUser> {
        self.0
            .read()
            .expect("VLESS user store lock poisoned")
            .clone()
    }

    fn update<R, E, F>(&self, update: F) -> Result<R, E>
    where
        F: FnOnce(&mut Vec<VlessUser>) -> Result<R, E>,
    {
        let mut users = self.0.write().expect("VLESS user store lock poisoned");
        update(&mut users)
    }
}

impl InboundInstance {
    fn new(generation: u64, config: ServerConfig) -> Self {
        Self {
            #[cfg(feature = "vless")]
            vless_users: single_vless_users(&config.protocol)
                .map(VlessUserStore::new),
            #[cfg(feature = "vmess")]
            vmess_users: single_vmess_users(&config.protocol)
                .map(VmessUserStore::new)
                .map(Arc::new),
            #[cfg(feature = "trojan")]
            trojan_users: single_trojan_users(&config.protocol)
                .map(TrojanUserStore::new)
                .map(Arc::new),
            #[cfg(feature = "hysteria")]
            hysteria_users: match &config.protocol {
                ServerProxyConfig::Hysteria2 { config } => {
                    Some(Arc::new(HysteriaUserStore::new(config.clients.clone())))
                }
                _ => None,
            },
            #[cfg(feature = "shadowsocks")]
            shadowsocks_users: single_shadowsocks_users(&config.protocol)
                .and_then(|(users, identity)| {
                    ShadowsocksUserStore::new(users, identity).ok()
                })
                .map(Arc::new),
            generation,
            lifecycle: InboundLifecycleState::Prepared,
            tasks: None,
            config,
        }
    }

    fn running_with_tasks(mut self, handles: Vec<JoinHandle<()>>) -> Self {
        self.lifecycle = InboundLifecycleState::Running;
        self.tasks = Some(handles);
        self
    }

    fn config_view(&self) -> ServerConfig {
        let mut config = self.config.clone();
        #[cfg(feature = "vless")]
        if let Some(store) = &self.vless_users {
            let users = store.snapshot();
            let _ = replace_single_vless_users(&mut config.protocol, &users);
        }
        #[cfg(feature = "vmess")]
        if let Some(store) = &self.vmess_users {
            let users = store.snapshot();
            let _ = replace_single_vmess_users(&mut config.protocol, &users);
        }
        #[cfg(feature = "trojan")]
        if let Some(store) = &self.trojan_users {
            let users = store.snapshot();
            let _ = replace_single_trojan_users(&mut config.protocol, &users);
        }
        #[cfg(feature = "hysteria")]
        if let Some(store) = &self.hysteria_users
            && let ServerProxyConfig::Hysteria2 { config: hysteria } =
                &mut config.protocol
        {
            hysteria.clients = store.snapshot();
        }
        #[cfg(feature = "shadowsocks")]
        if let Some(store) = &self.shadowsocks_users {
            let users = store.snapshot();
            let _ = replace_single_shadowsocks_users(&mut config.protocol, &users);
        }
        config
    }
}

#[cfg(feature = "vless")]
fn single_vless_users(protocol: &ServerProxyConfig) -> Option<Vec<VlessUser>> {
    let mut matches = Vec::new();
    collect_vless_users(protocol, &mut matches);
    (matches.len() == 1).then(|| matches.remove(0))
}

#[cfg(feature = "vless")]
fn collect_vless_users(
    protocol: &ServerProxyConfig,
    matches: &mut Vec<Vec<VlessUser>>,
) {
    match protocol {
        ServerProxyConfig::Vless { users, .. } => matches.push(users.clone()),
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
            crate::util::option::OneOrSome::One(target) => {
                collect_vless_users(&target.protocol, matches);
            }
            crate::util::option::OneOrSome::Some(targets) => {
                for target in targets {
                    collect_vless_users(&target.protocol, matches);
                }
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            collect_vless_users(&config.inner, matches)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            collect_vless_users(&config.inner, matches)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            collect_vless_users(inner, matches)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            collect_vless_users(&config.inner, matches)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            collect_vless_users(&config.inner, matches)
        }
        _ => {}
    }
}

#[cfg(feature = "vless")]
fn replace_single_vless_users(
    protocol: &mut ServerProxyConfig,
    users: &[VlessUser],
) -> bool {
    match protocol {
        ServerProxyConfig::Vless { users: current, .. } => {
            *current = users.to_vec();
            true
        }
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
            crate::util::option::OneOrSome::One(target) => {
                replace_single_vless_users(&mut target.protocol, users)
            }
            crate::util::option::OneOrSome::Some(targets) => {
                let mut replaced = false;
                for target in targets {
                    replaced |=
                        replace_single_vless_users(&mut target.protocol, users);
                }
                replaced
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            replace_single_vless_users(&mut config.inner, users)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            replace_single_vless_users(&mut config.inner, users)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            replace_single_vless_users(inner, users)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            replace_single_vless_users(&mut config.inner, users)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            replace_single_vless_users(&mut config.inner, users)
        }
        _ => false,
    }
}

#[cfg(feature = "vmess")]
fn single_vmess_users(protocol: &ServerProxyConfig) -> Option<Vec<VmessUser>> {
    let mut matches = Vec::new();
    collect_vmess_users(protocol, &mut matches);
    (matches.len() == 1).then(|| matches.remove(0))
}

#[cfg(feature = "vmess")]
fn collect_vmess_users(
    protocol: &ServerProxyConfig,
    matches: &mut Vec<Vec<VmessUser>>,
) {
    match protocol {
        ServerProxyConfig::Vmess { users } => matches.push(users.clone()),
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
            crate::util::option::OneOrSome::One(target) => {
                collect_vmess_users(&target.protocol, matches);
            }
            crate::util::option::OneOrSome::Some(targets) => {
                for target in targets {
                    collect_vmess_users(&target.protocol, matches);
                }
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            collect_vmess_users(&config.inner, matches)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            collect_vmess_users(&config.inner, matches)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            collect_vmess_users(inner, matches)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            collect_vmess_users(&config.inner, matches)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            collect_vmess_users(&config.inner, matches)
        }
        _ => {}
    }
}

#[cfg(feature = "vmess")]
fn replace_single_vmess_users(
    protocol: &mut ServerProxyConfig,
    users: &[VmessUser],
) -> bool {
    match protocol {
        ServerProxyConfig::Vmess { users: current } => {
            *current = users.to_vec();
            true
        }
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
            crate::util::option::OneOrSome::One(target) => {
                replace_single_vmess_users(&mut target.protocol, users)
            }
            crate::util::option::OneOrSome::Some(targets) => {
                let mut replaced = false;
                for target in targets {
                    replaced |=
                        replace_single_vmess_users(&mut target.protocol, users);
                }
                replaced
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            replace_single_vmess_users(&mut config.inner, users)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            replace_single_vmess_users(&mut config.inner, users)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            replace_single_vmess_users(inner, users)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            replace_single_vmess_users(&mut config.inner, users)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            replace_single_vmess_users(&mut config.inner, users)
        }
        _ => false,
    }
}

#[cfg(feature = "trojan")]
fn single_trojan_users(protocol: &ServerProxyConfig) -> Option<Vec<TrojanUser>> {
    let mut matches = Vec::new();
    collect_trojan_users(protocol, &mut matches);
    (matches.len() == 1).then(|| matches.remove(0))
}

#[cfg(feature = "trojan")]
fn collect_trojan_users(
    protocol: &ServerProxyConfig,
    matches: &mut Vec<Vec<TrojanUser>>,
) {
    match protocol {
        ServerProxyConfig::Trojan { users, .. } => matches.push(users.clone()),
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
            crate::util::option::OneOrSome::One(target) => {
                collect_trojan_users(&target.protocol, matches);
            }
            crate::util::option::OneOrSome::Some(targets) => {
                for target in targets {
                    collect_trojan_users(&target.protocol, matches);
                }
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            collect_trojan_users(&config.inner, matches)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            collect_trojan_users(&config.inner, matches)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            collect_trojan_users(inner, matches)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            collect_trojan_users(&config.inner, matches)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            collect_trojan_users(&config.inner, matches)
        }
        _ => {}
    }
}

#[cfg(feature = "trojan")]
fn replace_single_trojan_users(
    protocol: &mut ServerProxyConfig,
    users: &[TrojanUser],
) -> bool {
    match protocol {
        ServerProxyConfig::Trojan { users: current, .. } => {
            *current = users.to_vec();
            true
        }
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
            crate::util::option::OneOrSome::One(target) => {
                replace_single_trojan_users(&mut target.protocol, users)
            }
            crate::util::option::OneOrSome::Some(targets) => {
                let mut replaced = false;
                for target in targets {
                    replaced |=
                        replace_single_trojan_users(&mut target.protocol, users);
                }
                replaced
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            replace_single_trojan_users(&mut config.inner, users)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            replace_single_trojan_users(&mut config.inner, users)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            replace_single_trojan_users(inner, users)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            replace_single_trojan_users(&mut config.inner, users)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            replace_single_trojan_users(&mut config.inner, users)
        }
        _ => false,
    }
}

#[cfg(feature = "shadowsocks")]
fn single_shadowsocks_users(
    protocol: &ServerProxyConfig,
) -> Option<(
    Vec<crate::config::server_config::ShadowsocksUser>,
    Option<crate::config::server_config::ShadowsocksServerIdentity>,
)> {
    let mut matches = Vec::new();
    collect_shadowsocks_users(protocol, &mut matches);
    (matches.len() == 1).then(|| matches.remove(0))
}

#[cfg(feature = "shadowsocks")]
fn collect_shadowsocks_users(
    protocol: &ServerProxyConfig,
    matches: &mut Vec<(
        Vec<crate::config::server_config::ShadowsocksUser>,
        Option<crate::config::server_config::ShadowsocksServerIdentity>,
    )>,
) {
    match protocol {
        ServerProxyConfig::Shadowsocks { users, identity } => {
            matches.push((users.clone(), identity.clone()));
        }
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
            crate::util::option::OneOrSome::One(target) => {
                collect_shadowsocks_users(&target.protocol, matches);
            }
            crate::util::option::OneOrSome::Some(targets) => {
                for target in targets {
                    collect_shadowsocks_users(&target.protocol, matches);
                }
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            collect_shadowsocks_users(&config.inner, matches);
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            collect_shadowsocks_users(&config.inner, matches);
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            collect_shadowsocks_users(inner, matches);
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            collect_shadowsocks_users(&config.inner, matches);
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            collect_shadowsocks_users(&config.inner, matches);
        }
        _ => {}
    }
}

#[cfg(feature = "shadowsocks")]
fn replace_single_shadowsocks_users(
    protocol: &mut ServerProxyConfig,
    users: &[crate::config::server_config::ShadowsocksUser],
) -> bool {
    match protocol {
        ServerProxyConfig::Shadowsocks { users: current, .. } => {
            *current = users.to_vec();
            true
        }
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
            crate::util::option::OneOrSome::One(target) => {
                replace_single_shadowsocks_users(&mut target.protocol, users)
            }
            crate::util::option::OneOrSome::Some(targets) => {
                let mut replaced = false;
                for target in targets {
                    replaced |= replace_single_shadowsocks_users(
                        &mut target.protocol,
                        users,
                    );
                }
                replaced
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            replace_single_shadowsocks_users(&mut config.inner, users)
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            replace_single_shadowsocks_users(&mut config.inner, users)
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            replace_single_shadowsocks_users(inner, users)
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            replace_single_shadowsocks_users(&mut config.inner, users)
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            replace_single_shadowsocks_users(&mut config.inner, users)
        }
        _ => false,
    }
}

#[derive(Debug)]
struct InboundTaskSet {
    generation: u64,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
pub(crate) enum AddInboundError {
    AlreadyExists(String),
    Start(io::Error),
    State(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveInboundError {
    NotFound,
}

#[derive(Debug)]
pub(crate) enum AlterInboundError<E> {
    NotFound,
    Update(E),
    State(&'static str),
    Restart {
        start_error: io::Error,
        rollback_error: Option<io::Error>,
    },
}

struct PendingTasks {
    handles: Option<Vec<JoinHandle<()>>>,
}

impl PendingTasks {
    fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            handles: Some(handles),
        }
    }

    fn commit(mut self) -> Vec<JoinHandle<()>> {
        self.handles.take().unwrap_or_default()
    }
}

impl Drop for PendingTasks {
    fn drop(&mut self) {
        if let Some(handles) = self.handles.take() {
            abort_tasks(&handles);
        }
    }
}

struct ConfiguredStartGuard {
    manager: Arc<InboundManager>,
    started: Vec<(String, u64)>,
}

impl ConfiguredStartGuard {
    fn new(manager: Arc<InboundManager>) -> Self {
        Self {
            manager,
            started: Vec::new(),
        }
    }

    fn record(&mut self, tag: String, generation: u64) {
        self.started.push((tag, generation));
    }

    async fn rollback(&mut self) {
        while let Some((tag, generation)) = self.started.last().cloned() {
            self.manager
                .stop_tasks_for_generation(&tag, generation)
                .await;
            self.started.pop();
        }
    }

    fn disarm(&mut self) {
        self.started.clear();
    }
}

impl Drop for ConfiguredStartGuard {
    fn drop(&mut self) {
        if self.started.is_empty() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let manager = Arc::clone(&self.manager);
        let started = std::mem::take(&mut self.started);
        handle.spawn(async move {
            for (tag, generation) in started.into_iter().rev() {
                manager.stop_tasks_for_generation(&tag, generation).await;
            }
        });
    }
}

struct PendingAddGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    armed: bool,
}

impl PendingAddGuard {
    fn new(manager: Arc<InboundManager>, tag: String, generation: u64) -> Self {
        Self {
            manager,
            tag,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingAddGuard {
    fn drop(&mut self) {
        if self.armed {
            self.manager.clear_pending_lifecycle(
                &self.tag,
                self.generation,
                InboundLifecycleState::Starting,
            );
        }
    }
}

struct RemoveCleanupGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    handles: Vec<JoinHandle<()>>,
    armed: bool,
}

impl RemoveCleanupGuard {
    fn new(
        manager: Arc<InboundManager>,
        tag: String,
        generation: u64,
        task_set: Option<InboundTaskSet>,
    ) -> Self {
        let handles = task_set.map(|tasks| tasks.handles).unwrap_or_default();
        abort_tasks(&handles);
        Self {
            manager,
            tag,
            generation,
            handles,
            armed: true,
        }
    }

    async fn finish(&mut self) {
        while let Some(handle) = self.handles.last_mut() {
            let _ = handle.await;
            self.handles.pop();
        }
        self.manager.clear_pending_lifecycle(
            &self.tag,
            self.generation,
            InboundLifecycleState::Stopping,
        );
        self.armed = false;
    }
}

impl Drop for RemoveCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let handles = std::mem::take(&mut self.handles);
        let manager = Arc::clone(&self.manager);
        let tag = self.tag.clone();
        let generation = self.generation;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for handle in handles {
                    let _ = handle.await;
                }
                manager.clear_pending_lifecycle(
                    &tag,
                    generation,
                    InboundLifecycleState::Stopping,
                );
            });
        } else {
            manager.clear_pending_lifecycle(
                &tag,
                generation,
                InboundLifecycleState::Stopping,
            );
        }
    }
}

struct ConfiguredStartingGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    armed: bool,
}

impl ConfiguredStartingGuard {
    fn new(manager: Arc<InboundManager>, tag: String, generation: u64) -> Self {
        Self {
            manager,
            tag,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConfiguredStartingGuard {
    fn drop(&mut self) {
        if self.armed {
            self.manager
                .restore_prepared_state(&self.tag, self.generation);
        }
    }
}

struct AlterRecoveryGuard {
    manager: Arc<InboundManager>,
    runtime: RuntimeState,
    tag: String,
    generation: u64,
    original: Option<ServerConfig>,
}

impl AlterRecoveryGuard {
    fn new(
        manager: Arc<InboundManager>,
        runtime: RuntimeState,
        tag: String,
        generation: u64,
        original: ServerConfig,
    ) -> Self {
        Self {
            manager,
            runtime,
            tag,
            generation,
            original: Some(original),
        }
    }

    fn disarm(&mut self) {
        self.original = None;
    }
}

impl Drop for AlterRecoveryGuard {
    fn drop(&mut self) {
        let Some(original) = self.original.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let manager = Arc::clone(&self.manager);
        let runtime = self.runtime.clone();
        let tag = self.tag.clone();
        let generation = self.generation;
        handle.spawn(async move {
            manager
                .recover_cancelled_alter(runtime, tag, generation, original)
                .await;
        });
    }
}

impl InboundManager {
    pub(crate) fn new(configs: Vec<ServerConfig>) -> Self {
        let next_generation = u64::try_from(configs.len()).unwrap_or(u64::MAX);
        let configs = configs
            .into_iter()
            .enumerate()
            .map(|(index, config)| {
                InboundInstance::new(
                    u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
                    config,
                )
            })
            .collect();
        Self {
            state: RwLock::new(InboundState {
                configs,
                pending: HashMap::new(),
                next_generation,
            }),
            operation_locks: std::array::from_fn(|_| Mutex::new(())),
        }
    }

    fn operation_lock(&self, tag: &str) -> &Mutex<()> {
        let mut hasher = DefaultHasher::new();
        tag.hash(&mut hasher);
        &self.operation_locks[(hasher.finish() as usize) % OPERATION_LOCK_SHARDS]
    }

    fn set_lifecycle_for_generation(
        &self,
        tag: &str,
        generation: u64,
        lifecycle: InboundLifecycleState,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag && entry.generation == generation)
        else {
            return false;
        };
        entry.lifecycle = lifecycle;
        true
    }

    fn restore_prepared_state(&self, tag: &str, generation: u64) {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if let Some(entry) = state.configs.iter_mut().find(|entry| {
            entry.config.tag == tag
                && entry.generation == generation
                && entry.lifecycle == InboundLifecycleState::Starting
        }) {
            entry.lifecycle = InboundLifecycleState::Prepared;
        }
    }

    fn clear_pending_lifecycle(
        &self,
        tag: &str,
        generation: u64,
        lifecycle: InboundLifecycleState,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if state.pending.get(tag).copied()
            != Some(PendingInboundLifecycle {
                generation,
                lifecycle,
            })
        {
            return false;
        }
        state.pending.remove(tag);
        true
    }

    #[cfg(test)]
    fn lifecycle_state(&self, tag: &str) -> Option<InboundLifecycleState> {
        let state = self.state.read().expect("inbound manager lock poisoned");
        state
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(|entry| entry.lifecycle)
            .or_else(|| state.pending.get(tag).map(|entry| entry.lifecycle))
    }

    pub(crate) fn configs(&self) -> Vec<ServerConfig> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .map(InboundInstance::config_view)
            .collect()
    }

    pub(crate) fn config_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(InboundInstance::config_view)
    }

    pub(crate) fn generation(&self, tag: &str) -> Option<u64> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(|entry| entry.generation)
    }

    #[cfg(feature = "vless")]
    pub(crate) fn vless_users_snapshot(&self, tag: &str) -> Option<Vec<VlessUser>> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .and_then(|entry| entry.vless_users.as_ref())
            .map(VlessUserStore::snapshot)
    }

    #[cfg(feature = "vmess")]
    pub(crate) fn vmess_user_store(&self, tag: &str) -> Option<Arc<VmessUserStore>> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .and_then(|entry| entry.vmess_users.as_ref())
            .cloned()
    }

    #[cfg(feature = "trojan")]
    pub(crate) fn trojan_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<TrojanUserStore>> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .and_then(|entry| entry.trojan_users.as_ref())
            .cloned()
    }

    #[cfg(feature = "hysteria")]
    pub(crate) fn hysteria_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<HysteriaUserStore>> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .and_then(|entry| entry.hysteria_users.as_ref())
            .cloned()
    }

    #[cfg(feature = "shadowsocks")]
    pub(crate) fn shadowsocks_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<ShadowsocksUserStore>> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .and_then(|entry| entry.shadowsocks_users.as_ref())
            .cloned()
    }

    pub(crate) fn with_config_mut<R, F>(&self, tag: &str, mutator: F) -> Option<R>
    where
        F: FnOnce(&mut ServerConfig) -> R,
    {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let config = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag)?;
        Some(mutator(&mut config.config))
    }

    pub(crate) fn remove_config(&self, tag: &str) -> Option<ServerConfig> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let index = state
            .configs
            .iter()
            .position(|entry| entry.config.tag == tag)?;
        let removed = state.configs.remove(index);
        if let Some(handles) = removed.tasks {
            abort_tasks(&handles);
        }
        Some(removed.config)
    }

    pub(crate) fn add_config(&self, config: ServerConfig) -> Result<(), String> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if state
            .configs
            .iter()
            .any(|current| current.config.tag == config.tag)
            || state.pending.contains_key(&config.tag)
        {
            return Err(format!("inbound {} already exists", config.tag));
        }
        let generation =
            allocate_generation(&mut state).map_err(ToString::to_string)?;
        state.configs.push(InboundInstance::new(generation, config));
        Ok(())
    }

    pub(crate) fn register_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag)
        else {
            abort_tasks(&handles);
            return;
        };
        entry.lifecycle = InboundLifecycleState::Running;
        if let Some(previous) = entry.tasks.replace(handles) {
            abort_tasks(&previous);
        }
    }

    pub(crate) fn register_tasks_for_generation(
        &self,
        tag: &str,
        generation: u64,
        handles: Vec<JoinHandle<()>>,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag && entry.generation == generation)
        else {
            abort_tasks(&handles);
            return false;
        };
        entry.lifecycle = InboundLifecycleState::Running;
        if let Some(previous) = entry.tasks.replace(handles) {
            abort_tasks(&previous);
        }
        true
    }

    pub(crate) async fn stop_tasks(&self, tag: &str) -> bool {
        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(entry) = state
                .configs
                .iter_mut()
                .find(|entry| entry.config.tag == tag)
            else {
                return false;
            };
            let Some(handles) = entry.tasks.take() else {
                return false;
            };
            entry.lifecycle = InboundLifecycleState::Stopping;
            Some(InboundTaskSet {
                generation: entry.generation,
                handles,
            })
        };
        let Some(task_set) = task_set else {
            return false;
        };
        let generation = task_set.generation;
        stop_task_set(task_set).await;
        self.set_lifecycle_for_generation(
            tag,
            generation,
            InboundLifecycleState::Prepared,
        );
        true
    }

    pub(crate) async fn stop_tasks_for_generation(
        &self,
        tag: &str,
        generation: u64,
    ) -> bool {
        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(entry) = state.configs.iter_mut().find(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) else {
                return false;
            };
            let Some(handles) = entry.tasks.take() else {
                return false;
            };
            entry.lifecycle = InboundLifecycleState::Stopping;
            InboundTaskSet {
                generation,
                handles,
            }
        };
        stop_task_set(task_set).await;
        self.set_lifecycle_for_generation(
            tag,
            generation,
            InboundLifecycleState::Prepared,
        );
        true
    }

    pub(crate) async fn add_started(
        self: &Arc<Self>,
        runtime: RuntimeState,
        config: ServerConfig,
    ) -> Result<(), AddInboundError> {
        let tag = config.tag.clone();
        let _operation_guard = self.operation_lock(&tag).lock().await;
        let generation = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            if state.configs.iter().any(|entry| entry.config.tag == tag)
                || state.pending.contains_key(&tag)
            {
                return Err(AddInboundError::AlreadyExists(format!(
                    "inbound {tag} already exists"
                )));
            }
            let generation =
                allocate_generation(&mut state).map_err(AddInboundError::State)?;
            state.pending.insert(
                tag.clone(),
                PendingInboundLifecycle {
                    generation,
                    lifecycle: InboundLifecycleState::Starting,
                },
            );
            generation
        };
        let mut add_guard =
            PendingAddGuard::new(Arc::clone(self), tag.clone(), generation);

        let pending = PendingTasks::new(
            start_servers(config.clone(), runtime)
                .await
                .map_err(AddInboundError::Start)?,
        );
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if state.configs.iter().any(|entry| entry.config.tag == tag) {
            return Err(AddInboundError::AlreadyExists(format!(
                "inbound {tag} already exists"
            )));
        }
        if state.pending.get(&tag).copied()
            != Some(PendingInboundLifecycle {
                generation,
                lifecycle: InboundLifecycleState::Starting,
            })
        {
            return Err(AddInboundError::State(
                "inbound starting reservation changed before publish",
            ));
        }
        state.pending.remove(&tag);
        state.configs.push(
            InboundInstance::new(generation, config)
                .running_with_tasks(pending.commit()),
        );
        add_guard.disarm();
        Ok(())
    }

    pub(crate) async fn start_configured_inbounds(
        &self,
        runtime: RuntimeState,
        skip_tag: Option<&str>,
    ) -> io::Result<usize> {
        let manager = runtime.inbound_manager();
        let tags = self
            .configs()
            .into_iter()
            .map(|config| config.tag)
            .collect::<Vec<_>>();
        let mut rollback = ConfiguredStartGuard::new(Arc::clone(&manager));
        let mut started = 0usize;

        for tag in tags {
            if skip_tag == Some(tag.as_str()) {
                continue;
            }
            let _operation_guard = self.operation_lock(&tag).lock().await;
            let prepared = {
                let mut state =
                    self.state.write().expect("inbound manager lock poisoned");
                match state
                    .configs
                    .iter()
                    .position(|entry| entry.config.tag == tag)
                {
                    None => Err(io::Error::other(format!(
                        "configured inbound {tag} disappeared during startup"
                    ))),
                    Some(index)
                        if state.configs[index].tasks.is_some()
                            || state.configs[index].lifecycle
                                != InboundLifecycleState::Prepared =>
                    {
                        Err(io::Error::other(format!(
                            "configured inbound {tag} is not prepared for startup"
                        )))
                    }
                    Some(index) => {
                        state.configs[index].lifecycle =
                            InboundLifecycleState::Starting;
                        Ok((
                            state.configs[index].generation,
                            state.configs[index].config_view(),
                        ))
                    }
                }
            };
            let (generation, config) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    rollback.rollback().await;
                    return Err(error);
                }
            };

            let mut starting = ConfiguredStartingGuard::new(
                Arc::clone(&manager),
                tag.clone(),
                generation,
            );
            let handles = match start_servers(config, runtime.clone()).await {
                Ok(handles) => handles,
                Err(error) => {
                    drop(starting);
                    rollback.rollback().await;
                    return Err(error);
                }
            };
            let pending = PendingTasks::new(handles);
            let published = self.register_tasks_for_generation(
                &tag,
                generation,
                pending.commit(),
            );
            if !published {
                drop(starting);
                rollback.rollback().await;
                return Err(io::Error::other(format!(
                    "configured inbound {tag} changed during startup"
                )));
            }
            starting.disarm();
            rollback.record(tag, generation);
            started += 1;
        }

        rollback.disarm();
        Ok(started)
    }

    pub(crate) async fn remove_started(
        self: &Arc<Self>,
        tag: &str,
    ) -> Result<(), RemoveInboundError> {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let (generation, task_set) = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(index) = state
                .configs
                .iter()
                .position(|entry| entry.config.tag == tag)
            else {
                return Err(RemoveInboundError::NotFound);
            };
            let mut removed = state.configs.remove(index);
            let generation = removed.generation;
            let task_set = removed.tasks.take().map(|handles| InboundTaskSet {
                generation,
                handles,
            });
            state.pending.insert(
                tag.to_string(),
                PendingInboundLifecycle {
                    generation,
                    lifecycle: InboundLifecycleState::Stopping,
                },
            );
            (generation, task_set)
        };
        let mut cleanup = RemoveCleanupGuard::new(
            Arc::clone(self),
            tag.to_string(),
            generation,
            task_set,
        );
        cleanup.finish().await;
        Ok(())
    }

    pub(crate) async fn alter_started<E, F>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update: F,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        self.alter_started_locked(runtime, tag, update).await
    }

    #[cfg(feature = "vless")]
    pub(crate) async fn alter_users<E, F, U>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update_config: F,
        update_vless_users: U,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&mut Vec<VlessUser>) -> Result<bool, E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let vless_store = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            entry.vless_users.clone()
        };

        if let Some(store) = vless_store {
            let original_users = store.snapshot();
            let update_in_place = store
                .update(update_vless_users)
                .map_err(AlterInboundError::Update)?;
            if update_in_place {
                return Ok(());
            }
            store
                .update::<(), E, _>(|users| {
                    *users = original_users;
                    Ok(())
                })
                .map_err(AlterInboundError::Update)?;
        }

        self.alter_started_locked(runtime, tag, update_config).await
    }

    #[cfg(feature = "vmess")]
    pub(crate) async fn alter_vmess_users<E, F, U>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update_config: F,
        update_vmess_users: U,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&mut Vec<VmessUser>) -> Result<(), E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let vmess_store = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            entry.vmess_users.clone()
        };

        if let Some(store) = vmess_store {
            store
                .update(update_vmess_users)
                .map_err(AlterInboundError::Update)?;
            return Ok(());
        }

        self.alter_started_locked(runtime, tag, update_config).await
    }

    #[cfg(feature = "trojan")]
    pub(crate) async fn alter_trojan_users<E, F, U>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update_config: F,
        update_trojan_users: U,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&TrojanUserStore) -> Result<(), E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let trojan_store = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            entry.trojan_users.clone()
        };

        if let Some(store) = trojan_store {
            update_trojan_users(store.as_ref())
                .map_err(AlterInboundError::Update)?;
            return Ok(());
        }

        self.alter_started_locked(runtime, tag, update_config).await
    }

    #[cfg(feature = "hysteria")]
    pub(crate) async fn alter_hysteria_users<E, F, U>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update_config: F,
        update_hysteria_users: U,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&HysteriaUserStore) -> Result<(), E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let hysteria_store = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            entry.hysteria_users.clone()
        };

        if let Some(store) = hysteria_store {
            update_hysteria_users(store.as_ref())
                .map_err(AlterInboundError::Update)?;
            return Ok(());
        }

        self.alter_started_locked(runtime, tag, update_config).await
    }

    #[cfg(feature = "shadowsocks")]
    pub(crate) async fn alter_shadowsocks_users<E, F, U>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update_config: F,
        update_shadowsocks_users: U,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&ShadowsocksUserStore) -> Result<(), E> + Send,
    {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let shadowsocks_store = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            entry.shadowsocks_users.clone()
        };

        if let Some(store) = shadowsocks_store {
            update_shadowsocks_users(store.as_ref())
                .map_err(AlterInboundError::Update)?;
            return Ok(());
        }

        self.alter_started_locked(runtime, tag, update_config).await
    }

    async fn alter_started_locked<E, F>(
        &self,
        runtime: RuntimeState,
        tag: &str,
        update: F,
    ) -> Result<(), AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
    {
        let (generation, original) = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let Some(entry) =
                state.configs.iter().find(|entry| entry.config.tag == tag)
            else {
                return Err(AlterInboundError::NotFound);
            };
            (entry.generation, entry.config_view())
        };
        let updated = update(&original).map_err(AlterInboundError::Update)?;

        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(entry) = state.configs.iter_mut().find(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) else {
                return Err(AlterInboundError::State(
                    "inbound generation changed during alter",
                ));
            };
            entry.tasks.take().map(|handles| {
                entry.lifecycle = InboundLifecycleState::Stopping;
                InboundTaskSet {
                    generation,
                    handles,
                }
            })
        };

        let Some(task_set) = task_set else {
            self.replace_config_generation(tag, generation, updated)
                .map_err(AlterInboundError::State)?;
            return Ok(());
        };

        let mut recovery = AlterRecoveryGuard::new(
            runtime.inbound_manager(),
            runtime.clone(),
            tag.to_string(),
            generation,
            original.clone(),
        );
        stop_task_set(task_set).await;
        if !self.set_lifecycle_for_generation(
            tag,
            generation,
            InboundLifecycleState::Starting,
        ) {
            return Err(AlterInboundError::State(
                "inbound generation changed before restart",
            ));
        }

        match start_servers(updated.clone(), runtime.clone()).await {
            Ok(handles) => {
                let pending = PendingTasks::new(handles);
                self.replace_running_generation(
                    tag,
                    generation,
                    updated,
                    pending.commit(),
                )
                .map_err(AlterInboundError::State)?;
                recovery.disarm();
                Ok(())
            }
            Err(start_error) => {
                self.set_lifecycle_for_generation(
                    tag,
                    generation,
                    InboundLifecycleState::Recovering,
                );
                tokio::task::yield_now().await;
                match start_servers(original.clone(), runtime).await {
                    Ok(handles) => {
                        let pending = PendingTasks::new(handles);
                        self.replace_running_generation(
                            tag,
                            generation,
                            original,
                            pending.commit(),
                        )
                        .map_err(AlterInboundError::State)?;
                        recovery.disarm();
                        Err(AlterInboundError::Restart {
                            start_error,
                            rollback_error: None,
                        })
                    }
                    Err(rollback_error) => {
                        self.set_lifecycle_for_generation(
                            tag,
                            generation,
                            InboundLifecycleState::Prepared,
                        );
                        recovery.disarm();
                        Err(AlterInboundError::Restart {
                            start_error,
                            rollback_error: Some(rollback_error),
                        })
                    }
                }
            }
        }
    }

    async fn recover_cancelled_alter(
        &self,
        runtime: RuntimeState,
        tag: String,
        generation: u64,
        original: ServerConfig,
    ) {
        let _operation_guard = self.operation_lock(&tag).lock().await;
        let should_recover = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            if let Some(entry) = state.configs.iter_mut().find(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) {
                if entry.tasks.is_some() {
                    false
                } else {
                    entry.lifecycle = InboundLifecycleState::Recovering;
                    true
                }
            } else {
                false
            }
        };
        if !should_recover {
            return;
        }

        match start_servers(original.clone(), runtime).await {
            Ok(handles) => {
                let pending = PendingTasks::new(handles);
                if let Err(error) = self.replace_running_generation(
                    &tag,
                    generation,
                    original,
                    pending.commit(),
                ) {
                    tracing::warn!(
                        inbound_tag = %tag,
                        reason = error,
                        "cancelled inbound alter recovery was superseded"
                    );
                }
            }
            Err(error) => {
                self.set_lifecycle_for_generation(
                    &tag,
                    generation,
                    InboundLifecycleState::Prepared,
                );
                tracing::warn!(
                    inbound_tag = %tag,
                    error = %error,
                    "failed to recover inbound after cancelled alter"
                );
            }
        }
    }

    fn replace_config_generation(
        &self,
        tag: &str,
        expected_generation: u64,
        config: ServerConfig,
    ) -> Result<(), &'static str> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(index) = state.configs.iter().position(|entry| {
            entry.config.tag == tag && entry.generation == expected_generation
        }) else {
            return Err("inbound generation changed during update");
        };
        let generation = allocate_generation(&mut state)?;
        state.configs[index] = InboundInstance::new(generation, config);
        Ok(())
    }

    fn replace_running_generation(
        &self,
        tag: &str,
        expected_generation: u64,
        config: ServerConfig,
        handles: Vec<JoinHandle<()>>,
    ) -> Result<(), &'static str> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(index) = state.configs.iter().position(|entry| {
            entry.config.tag == tag && entry.generation == expected_generation
        }) else {
            abort_tasks(&handles);
            return Err("inbound generation changed during restart");
        };
        let generation = match allocate_generation(&mut state) {
            Ok(generation) => generation,
            Err(error) => {
                abort_tasks(&handles);
                return Err(error);
            }
        };
        state.configs[index] =
            InboundInstance::new(generation, config).running_with_tasks(handles);
        Ok(())
    }
}

fn allocate_generation(state: &mut InboundState) -> Result<u64, &'static str> {
    state.next_generation = state
        .next_generation
        .checked_add(1)
        .ok_or("inbound generation counter exhausted")?;
    Ok(state.next_generation)
}

fn abort_tasks(handles: &[JoinHandle<()>]) {
    for handle in handles {
        handle.abort();
    }
}

async fn stop_task_set(task_set: InboundTaskSet) {
    abort_tasks(&task_set.handles);
    for handle in task_set.handles {
        let _ = handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlterRecoveryGuard, ConfiguredStartGuard, ConfiguredStartingGuard,
        InboundLifecycleState, InboundManager, InboundTaskSet, stop_task_set,
    };
    use crate::{
        address::{BindLocation, NetLocation},
        beginning::start_servers,
        config::{
            Transport,
            server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
        },
        runtime::RuntimeState,
    };
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    fn free_localhost_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral port")
            .local_addr()
            .expect("read local addr")
            .port()
    }

    async fn wait_for_tcp_listener(port: u16) -> bool {
        for _ in 0..50 {
            if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn inbound(tag: &str, port: u16) -> ServerConfig {
        ServerConfig {
            tag: tag.to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: SocksUserStore::new(Vec::new()),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }
    }

    #[test]
    fn config_registry_rejects_duplicate_tags() {
        let manager = InboundManager::new(vec![inbound("primary", 10001)]);

        assert!(manager.add_config(inbound("primary", 10002)).is_err());
        assert_eq!(manager.configs().len(), 1);
        assert_eq!(
            manager.config_by_tag("primary").map(|config| config.tag),
            Some("primary".to_string())
        );
    }

    #[tokio::test]
    async fn stopping_tasks_does_not_remove_config() {
        let manager = InboundManager::new(vec![inbound("primary", 10001)]);
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Prepared)
        );
        let task = tokio::spawn(std::future::pending());
        manager.register_tasks("primary", vec![task]);
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Running)
        );

        assert!(manager.stop_tasks("primary").await);
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Prepared)
        );
        assert!(manager.config_by_tag("primary").is_some());
        assert!(!manager.stop_tasks("primary").await);
    }

    #[tokio::test]
    async fn registering_tasks_for_missing_instance_aborts_them() {
        let manager = InboundManager::new(Vec::new());
        let task = tokio::spawn(std::future::pending());
        let abort_handle = task.abort_handle();

        manager.register_tasks("missing", vec![task]);
        tokio::task::yield_now().await;

        assert!(abort_handle.is_finished());
        assert_eq!(manager.lifecycle_state("missing"), None);
    }

    #[test]
    fn cancelled_configured_start_restores_prepared_state() {
        let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
        let generation = manager.generation("primary").unwrap();
        assert!(manager.set_lifecycle_for_generation(
            "primary",
            generation,
            InboundLifecycleState::Starting,
        ));
        let guard = ConfiguredStartingGuard::new(
            Arc::clone(&manager),
            "primary".to_string(),
            generation,
        );

        drop(guard);

        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Prepared)
        );
    }

    #[tokio::test]
    async fn stale_generation_cannot_stop_recreated_inbound_tasks() {
        let manager = InboundManager::new(vec![inbound("primary", 10001)]);
        let old_generation = manager.generation("primary").unwrap();
        assert!(manager.remove_config("primary").is_some());
        manager.add_config(inbound("primary", 10002)).unwrap();
        let new_generation = manager.generation("primary").unwrap();
        assert_ne!(old_generation, new_generation);

        let task = tokio::spawn(std::future::pending());
        assert!(manager.register_tasks_for_generation(
            "primary",
            new_generation,
            vec![task]
        ));
        assert!(
            !manager
                .stop_tasks_for_generation("primary", old_generation)
                .await
        );
        assert!(
            manager
                .stop_tasks_for_generation("primary", new_generation)
                .await
        );
    }

    #[tokio::test]
    async fn stale_generation_registration_aborts_old_task() {
        let manager = InboundManager::new(vec![inbound("primary", 10001)]);
        let old_generation = manager.generation("primary").unwrap();
        assert!(manager.remove_config("primary").is_some());
        manager.add_config(inbound("primary", 10002)).unwrap();

        let task = tokio::spawn(std::future::pending());
        let abort_handle = task.abort_handle();
        assert!(!manager.register_tasks_for_generation(
            "primary",
            old_generation,
            vec![task]
        ));
        tokio::task::yield_now().await;
        assert!(abort_handle.is_finished());
    }

    #[tokio::test]
    async fn cancelled_alter_recovers_original_listener() {
        let port = free_localhost_port();
        let original = inbound("primary", port);
        let runtime = RuntimeState::new(vec![original.clone()], Vec::new());
        let manager = runtime.inbound_manager();
        let generation = manager.generation("primary").unwrap();
        let handles = start_servers(original.clone(), runtime.clone())
            .await
            .expect("start original listener");
        assert!(
            manager.register_tasks_for_generation("primary", generation, handles)
        );
        assert!(wait_for_tcp_listener(port).await);

        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let transition_manager = Arc::clone(&manager);
        let transition_runtime = runtime.clone();
        let transition_original = original.clone();
        let transition = tokio::spawn(async move {
            let _operation_guard =
                transition_manager.operation_lock("primary").lock().await;
            let task_set = {
                let mut state = transition_manager
                    .state
                    .write()
                    .expect("inbound manager lock poisoned");
                let entry = state
                    .configs
                    .iter_mut()
                    .find(|entry| entry.config.tag == "primary")
                    .expect("original inbound registered");
                InboundTaskSet {
                    generation: entry.generation,
                    handles: entry
                        .tasks
                        .take()
                        .expect("original listener tasks registered"),
                }
            };
            let _recovery = AlterRecoveryGuard::new(
                Arc::clone(&transition_manager),
                transition_runtime,
                "primary".to_string(),
                generation,
                transition_original,
            );
            stop_task_set(task_set).await;
            let _ = armed_tx.send(());
            std::future::pending::<()>().await;
        });

        armed_rx.await.expect("alter recovery guard armed");
        transition.abort();
        let _ = transition.await;

        assert!(
            wait_for_tcp_listener(port).await,
            "cancelling alter must restore the original listener"
        );
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Running)
        );
        assert!(manager.stop_tasks("primary").await);
    }

    #[tokio::test]
    async fn configured_start_rolls_back_prior_listener_on_later_bind_failure() {
        let first_port = free_localhost_port();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind occupied second port");
        let second_port = occupied.local_addr().unwrap().port();
        let runtime = RuntimeState::new(
            vec![inbound("first", first_port), inbound("second", second_port)],
            Vec::new(),
        );
        let manager = runtime.inbound_manager();

        manager
            .start_configured_inbounds(runtime.clone(), None)
            .await
            .expect_err("second inbound bind must fail");

        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, first_port)).is_ok(),
            "failed initial startup must release previously started listeners"
        );
        assert!(manager.config_by_tag("first").is_some());
        assert!(manager.config_by_tag("second").is_some());
        assert_eq!(
            manager.lifecycle_state("first"),
            Some(InboundLifecycleState::Prepared)
        );
        assert_eq!(
            manager.lifecycle_state("second"),
            Some(InboundLifecycleState::Prepared)
        );
        assert!(!manager.stop_tasks("first").await);
    }

    #[tokio::test]
    async fn cancelled_configured_start_guard_cleans_recorded_generation() {
        let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
        let generation = manager.generation("primary").unwrap();
        let task = tokio::spawn(std::future::pending());
        let abort_handle = task.abort_handle();
        assert!(manager.register_tasks_for_generation(
            "primary",
            generation,
            vec![task]
        ));

        let mut guard = ConfiguredStartGuard::new(Arc::clone(&manager));
        guard.record("primary".to_string(), generation);
        drop(guard);
        for _ in 0..20 {
            if abort_handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(abort_handle.is_finished());
        assert!(!manager.stop_tasks("primary").await);
    }

    #[tokio::test]
    async fn dynamic_add_publishes_running_and_remove_clears_lifecycle() {
        let port = free_localhost_port();
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let manager = runtime.inbound_manager();

        manager
            .add_started(runtime.clone(), inbound("primary", port))
            .await
            .expect("dynamic add");
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Running)
        );
        assert!(wait_for_tcp_listener(port).await);

        manager
            .remove_started("primary")
            .await
            .expect("dynamic remove");
        assert_eq!(manager.lifecycle_state("primary"), None);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[tokio::test]
    async fn failed_dynamic_add_clears_starting_reservation() {
        let occupied =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind occupied port");
        let port = occupied.local_addr().unwrap().port();
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let manager = runtime.inbound_manager();

        assert!(
            manager
                .add_started(runtime, inbound("primary", port))
                .await
                .is_err()
        );
        assert_eq!(manager.lifecycle_state("primary"), None);
        assert!(manager.config_by_tag("primary").is_none());
    }

    #[tokio::test]
    async fn cancelled_remove_keeps_tombstone_until_task_reaped() {
        let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
        let generation = manager.generation("primary").unwrap();
        let task = tokio::task::spawn_blocking(|| {
            std::thread::sleep(Duration::from_millis(500));
        });
        assert!(manager.register_tasks_for_generation(
            "primary",
            generation,
            vec![task]
        ));

        let removing_manager = Arc::clone(&manager);
        let removing =
            tokio::spawn(
                async move { removing_manager.remove_started("primary").await },
            );
        for _ in 0..50 {
            if manager.lifecycle_state("primary")
                == Some(InboundLifecycleState::Stopping)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Stopping)
        );
        assert!(manager.config_by_tag("primary").is_none());

        removing.abort();
        let _ = removing.await;
        assert_eq!(
            manager.lifecycle_state("primary"),
            Some(InboundLifecycleState::Stopping)
        );
        assert!(manager.add_config(inbound("primary", 10002)).is_err());

        for _ in 0..100 {
            if manager.lifecycle_state("primary").is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.lifecycle_state("primary"), None);
        assert!(manager.add_config(inbound("primary", 10002)).is_ok());
    }

    #[tokio::test]
    async fn cancelled_alter_recovery_does_not_revive_stale_generation() {
        let old_port = free_localhost_port();
        let new_port = free_localhost_port();
        let original = inbound("primary", old_port);
        let runtime = RuntimeState::new(vec![original.clone()], Vec::new());
        let manager = runtime.inbound_manager();
        let old_generation = manager.generation("primary").unwrap();

        assert!(manager.remove_config("primary").is_some());
        manager.add_config(inbound("primary", new_port)).unwrap();
        let new_generation = manager.generation("primary").unwrap();
        let new_task = tokio::spawn(std::future::pending());
        let new_abort = new_task.abort_handle();
        assert!(manager.register_tasks_for_generation(
            "primary",
            new_generation,
            vec![new_task]
        ));

        drop(AlterRecoveryGuard::new(
            Arc::clone(&manager),
            runtime,
            "primary".to_string(),
            old_generation,
            original,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(manager.generation("primary"), Some(new_generation));
        assert!(!new_abort.is_finished());
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, old_port))
                .await
                .is_err(),
            "stale recovery must not revive the removed generation"
        );
        assert!(manager.stop_tasks("primary").await);
    }
}
