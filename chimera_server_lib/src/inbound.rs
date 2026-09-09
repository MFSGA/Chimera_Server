use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    sync::{Arc, RwLock},
};

use tokio::{sync::Mutex, task::JoinHandle};

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
use crate::{
    beginning::start_servers,
    config::server_config::{ServerConfig, ServerProxyConfig},
    runtime::RuntimeState,
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
        stop_task_set(task_set).await;

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
                Ok(())
            }
            Err(start_error) => {
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
    use super::InboundManager;
    use crate::{
        address::{BindLocation, NetLocation},
        config::{
            Transport,
            server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
        },
    };
    use std::net::{IpAddr, Ipv4Addr};

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
}
