use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::{sync::Mutex, task::JoinHandle};

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::connection::HysteriaUserStore;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksUserStore;
#[cfg(feature = "trojan")]
use crate::handler::trojan::TrojanUserStore;
use crate::{
    beginning::start_bound_servers, config::server_config::ServerConfig,
    runtime::RuntimeState,
};
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
    Draining,
    Stopping,
    Recovering,
    Failed,
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

mod identity;

#[cfg(feature = "vless")]
use identity::VlessUserStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InboundFailure {
    pub(crate) tag: String,
    pub(crate) generation: u64,
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

    pub(crate) fn unhealthy_inbound(&self) -> Option<InboundFailure> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| {
                entry.lifecycle == InboundLifecycleState::Failed
                    || (entry.lifecycle == InboundLifecycleState::Running
                        && entry.tasks.as_ref().is_some_and(|handles| {
                            handles.iter().any(JoinHandle::is_finished)
                        }))
            })
            .map(|entry| InboundFailure {
                tag: entry.config.tag.clone(),
                generation: entry.generation,
            })
    }

    pub(crate) fn has_unhealthy_inbound(&self) -> bool {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .any(|entry| {
                entry.lifecycle == InboundLifecycleState::Failed
                    || (entry.lifecycle == InboundLifecycleState::Running
                        && entry.tasks.as_ref().is_some_and(|handles| {
                            handles.iter().any(JoinHandle::is_finished)
                        }))
            })
    }

    fn detect_running_failure(&self) -> Option<InboundFailure> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let entry = state.configs.iter_mut().find(|entry| {
            entry.lifecycle == InboundLifecycleState::Running
                && entry.tasks.as_ref().is_some_and(|handles| {
                    handles.iter().any(JoinHandle::is_finished)
                })
        })?;
        entry.lifecycle = InboundLifecycleState::Failed;
        Some(InboundFailure {
            tag: entry.config.tag.clone(),
            generation: entry.generation,
        })
    }

    pub(crate) async fn wait_for_failure(&self) -> InboundFailure {
        const POLL_INTERVAL: Duration = Duration::from_millis(25);

        loop {
            if let Some(failure) = self.detect_running_failure() {
                return failure;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
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
        if (!config.tag.is_empty()
            && state
                .configs
                .iter()
                .any(|current| current.config.tag == config.tag))
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

    pub(crate) async fn stop_all_tasks(&self) -> usize {
        let task_sets = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            state
                .configs
                .iter_mut()
                .filter_map(|entry| {
                    let handles = entry.tasks.take()?;
                    let failed = entry.lifecycle == InboundLifecycleState::Failed;
                    if !failed {
                        entry.lifecycle = InboundLifecycleState::Draining;
                    }
                    Some((
                        entry.config.tag.clone(),
                        failed,
                        InboundTaskSet {
                            generation: entry.generation,
                            handles,
                        },
                    ))
                })
                .collect::<Vec<_>>()
        };

        // Abort every listener before awaiting any of them so server shutdown
        // stops accepting new connections across all inbounds promptly.
        for (_, _, task_set) in &task_sets {
            abort_tasks(&task_set.handles);
        }

        let stopped = task_sets.len();
        for (tag, failed, task_set) in task_sets {
            let generation = task_set.generation;
            stop_task_set(task_set).await;
            if !failed {
                self.set_lifecycle_for_generation(
                    &tag,
                    generation,
                    InboundLifecycleState::Prepared,
                );
            }
        }
        stopped
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
            if (!tag.is_empty()
                && state.configs.iter().any(|entry| entry.config.tag == tag))
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
            start_bound_servers(config.clone(), runtime)
                .await
                .map_err(AddInboundError::Start)?
                .into_handles(),
        );
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if !tag.is_empty()
            && state.configs.iter().any(|entry| entry.config.tag == tag)
        {
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
        let identities = {
            let state = self.state.read().expect("inbound manager lock poisoned");
            let mut tagged = HashSet::new();
            for entry in &state.configs {
                let tag = entry.config.tag.as_str();
                if !tag.is_empty() && !tagged.insert(tag) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("inbound {tag} already exists"),
                    ));
                }
            }
            state
                .configs
                .iter()
                .map(|entry| (entry.config.tag.clone(), entry.generation))
                .collect::<Vec<_>>()
        };
        let mut rollback = ConfiguredStartGuard::new(Arc::clone(&manager));
        let mut started = 0usize;

        for (tag, expected_generation) in identities {
            if skip_tag == Some(tag.as_str()) {
                continue;
            }
            let _operation_guard = self.operation_lock(&tag).lock().await;
            let prepared = {
                let mut state =
                    self.state.write().expect("inbound manager lock poisoned");
                match state.configs.iter().position(|entry| {
                    entry.config.tag == tag
                        && entry.generation == expected_generation
                }) {
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
            let handles = match start_bound_servers(config, runtime.clone()).await {
                Ok(bound) => bound.into_handles(),
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
        if tag.is_empty() {
            return Err(RemoveInboundError::NotFound);
        }
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

        match start_bound_servers(updated.clone(), runtime.clone()).await {
            Ok(bound) => {
                let handles = bound.into_handles();
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
                match start_bound_servers(original.clone(), runtime).await {
                    Ok(bound) => {
                        let handles = bound.into_handles();
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

        match start_bound_servers(original.clone(), runtime).await {
            Ok(bound) => {
                let handles = bound.into_handles();
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
mod tests;
