use std::sync::{Arc, RwLock};

use tokio::task::JoinHandle;

use super::{InboundInstance, InboundLifecycleState};
#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
use crate::config::server_config::{ServerConfig, ServerProxyConfig};
#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::connection::HysteriaUserStore;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksUserStore;
#[cfg(feature = "trojan")]
use crate::{config::server_config::TrojanUser, handler::trojan::TrojanUserStore};
#[cfg(feature = "vmess")]
use crate::{
    config::server_config::VmessUser, handler::vmess::vmess_handler::VmessUserStore,
};

#[cfg(feature = "vless")]
#[derive(Debug, Clone)]
pub(super) struct VlessUserStore(Arc<RwLock<Vec<VlessUser>>>);

#[cfg(feature = "vless")]
impl VlessUserStore {
    pub(super) fn new(users: Vec<VlessUser>) -> Self {
        Self(Arc::new(RwLock::new(users)))
    }

    pub(super) fn snapshot(&self) -> Vec<VlessUser> {
        self.0
            .read()
            .expect("VLESS user store lock poisoned")
            .clone()
    }

    pub(super) fn update<R, E, F>(&self, update: F) -> Result<R, E>
    where
        F: FnOnce(&mut Vec<VlessUser>) -> Result<R, E>,
    {
        let mut users = self.0.write().expect("VLESS user store lock poisoned");
        update(&mut users)
    }
}

impl InboundInstance {
    pub(super) fn new(generation: u64, config: ServerConfig) -> Self {
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

    pub(super) fn running_with_tasks(
        mut self,
        handles: Vec<JoinHandle<()>>,
    ) -> Self {
        self.lifecycle = InboundLifecycleState::Running;
        self.tasks = Some(handles);
        self
    }

    pub(super) fn config_view(&self) -> ServerConfig {
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
