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
    configs: Vec<VersionedConfig>,
    tasks: HashMap<String, InboundTaskSet>,
    next_generation: u64,
}

#[derive(Debug)]
struct VersionedConfig {
    generation: u64,
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

impl VersionedConfig {
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
            config,
        }
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
                VersionedConfig::new(
                    u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
                    config,
                )
            })
            .collect();
        Self {
            state: RwLock::new(InboundState {
                configs,
                tasks: HashMap::new(),
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

    pub(crate) fn configs(&self) -> Vec<ServerConfig> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .map(VersionedConfig::config_view)
            .collect()
    }

    pub(crate) fn config_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(VersionedConfig::config_view)
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
        Some(state.configs.remove(index).config)
    }

    pub(crate) fn add_config(&self, config: ServerConfig) -> Result<(), String> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if state
            .configs
            .iter()
            .any(|current| current.config.tag == config.tag)
        {
            return Err(format!("inbound {} already exists", config.tag));
        }
        let generation =
            allocate_generation(&mut state).map_err(ToString::to_string)?;
        if let Some(stale) = state.tasks.remove(&config.tag) {
            abort_tasks(&stale.handles);
        }
        state.configs.push(VersionedConfig::new(generation, config));
        Ok(())
    }

    pub(crate) fn register_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let generation = state
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(|entry| entry.generation)
            .or_else(|| state.tasks.get(tag).map(|tasks| tasks.generation));
        let generation = match generation {
            Some(generation) => generation,
            None => match allocate_generation(&mut state) {
                Ok(generation) => generation,
                Err(_) => {
                    abort_tasks(&handles);
                    return;
                }
            },
        };
        if let Some(previous) = state.tasks.insert(
            tag.to_string(),
            InboundTaskSet {
                generation,
                handles,
            },
        ) {
            abort_tasks(&previous.handles);
        }
    }

    pub(crate) fn register_tasks_for_generation(
        &self,
        tag: &str,
        generation: u64,
        handles: Vec<JoinHandle<()>>,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let is_current = state
            .configs
            .iter()
            .any(|entry| entry.config.tag == tag && entry.generation == generation);
        if !is_current {
            abort_tasks(&handles);
            return false;
        }
        if let Some(previous) = state.tasks.insert(
            tag.to_string(),
            InboundTaskSet {
                generation,
                handles,
            },
        ) {
            abort_tasks(&previous.handles);
        }
        true
    }

    pub(crate) async fn stop_tasks(&self, tag: &str) -> bool {
        let task_set = self
            .state
            .write()
            .expect("inbound manager lock poisoned")
            .tasks
            .remove(tag);
        let Some(task_set) = task_set else {
            return false;
        };
        stop_task_set(task_set).await;
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
            if state.tasks.get(tag).map(|tasks| tasks.generation) != Some(generation)
            {
                return false;
            }
            state.tasks.remove(tag)
        };
        let Some(task_set) = task_set else {
            return false;
        };
        stop_task_set(task_set).await;
        true
    }

    pub(crate) async fn add_started(
        &self,
        runtime: RuntimeState,
        config: ServerConfig,
    ) -> Result<(), AddInboundError> {
        let tag = config.tag.clone();
        let _operation_guard = self.operation_lock(&tag).lock().await;
        if self.config_by_tag(&tag).is_some() {
            return Err(AddInboundError::AlreadyExists(format!(
                "inbound {tag} already exists"
            )));
        }

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
        let generation =
            allocate_generation(&mut state).map_err(AddInboundError::State)?;
        state.configs.push(VersionedConfig::new(generation, config));
        if let Some(previous) = state.tasks.insert(
            tag,
            InboundTaskSet {
                generation,
                handles: pending.commit(),
            },
        ) {
            abort_tasks(&previous.handles);
        }
        Ok(())
    }

    pub(crate) async fn remove_started(
        &self,
        tag: &str,
    ) -> Result<(), RemoveInboundError> {
        let _operation_guard = self.operation_lock(tag).lock().await;
        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(index) = state
                .configs
                .iter()
                .position(|entry| entry.config.tag == tag)
            else {
                return Err(RemoveInboundError::NotFound);
            };
            state.configs.remove(index);
            state.tasks.remove(tag)
        };
        if let Some(task_set) = task_set {
            stop_task_set(task_set).await;
        }
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
            match state.tasks.get(tag) {
                Some(tasks) if tasks.generation != generation => {
                    return Err(AlterInboundError::State(
                        "inbound task generation mismatch",
                    ));
                }
                Some(_) => state.tasks.remove(tag),
                None => None,
            }
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

        match start_servers(updated.clone(), runtime.clone()).await {
            Ok(handles) => {
                recovery.disarm();
                let pending = PendingTasks::new(handles);
                self.replace_running_generation(
                    tag,
                    generation,
                    updated,
                    pending.commit(),
                )
                .map_err(AlterInboundError::State)?;
                Ok(())
            }
            Err(start_error) => {
                tokio::task::yield_now().await;
                let rollback = start_servers(original.clone(), runtime).await;
                recovery.disarm();
                match rollback {
                    Ok(handles) => {
                        let pending = PendingTasks::new(handles);
                        self.replace_running_generation(
                            tag,
                            generation,
                            original,
                            pending.commit(),
                        )
                        .map_err(AlterInboundError::State)?;
                        Err(AlterInboundError::Restart {
                            start_error,
                            rollback_error: None,
                        })
                    }
                    Err(rollback_error) => Err(AlterInboundError::Restart {
                        start_error,
                        rollback_error: Some(rollback_error),
                    }),
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
            let state = self.state.read().expect("inbound manager lock poisoned");
            state.configs.iter().any(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) && !state.tasks.contains_key(&tag)
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
        state.configs[index] = VersionedConfig::new(generation, config);
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
        state.configs[index] = VersionedConfig::new(generation, config);
        if let Some(previous) = state.tasks.insert(
            tag.to_string(),
            InboundTaskSet {
                generation,
                handles,
            },
        ) {
            abort_tasks(&previous.handles);
        }
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
    use super::{AlterRecoveryGuard, InboundManager, stop_task_set};
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
        let task = tokio::spawn(std::future::pending());
        manager.register_tasks("primary", vec![task]);

        assert!(manager.stop_tasks("primary").await);
        assert!(manager.config_by_tag("primary").is_some());
        assert!(!manager.stop_tasks("primary").await);
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
            let task_set = transition_manager
                .state
                .write()
                .expect("inbound manager lock poisoned")
                .tasks
                .remove("primary")
                .expect("original listener tasks registered");
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
        assert!(manager.stop_tasks("primary").await);
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
