use super::*;

impl HandlerServiceImpl {
    pub(super) fn parse_alter_inbound_operation(
        &self,
        operation: Option<proto::xray::common::serial::TypedMessage>,
    ) -> Result<AlterInboundOperation, Status> {
        let Some(operation) = operation else {
            // Keep compatibility with existing clients that send an empty operation.
            return Ok(AlterInboundOperation::Noop);
        };

        let op_type = operation.r#type.trim_start_matches('.');
        match op_type {
            TYPE_ADD_USER_OPERATION | TYPE_ADD_USER_OPERATION_V2RAY => {
                let decoded =
                    proto::xray::app::proxyman::command::AddUserOperation::decode(
                        operation.value.as_slice(),
                    )
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid AddUserOperation payload: {err}"
                        ))
                    })?;
                Ok(AlterInboundOperation::AddUser(decoded))
            }
            TYPE_REMOVE_USER_OPERATION | TYPE_REMOVE_USER_OPERATION_V2RAY => {
                let decoded = proto::xray::app::proxyman::command::RemoveUserOperation::decode(
                    operation.value.as_slice(),
                )
                .map_err(|err| {
                    Status::invalid_argument(format!("invalid RemoveUserOperation payload: {err}"))
                })?;
                Ok(AlterInboundOperation::RemoveUser(decoded))
            }
            other => Err(Status::invalid_argument(format!(
                "unsupported inbound operation type: {other}"
            ))),
        }
    }

    pub(super) fn add_vless_user(
        &self,
        users: &mut Vec<VlessUser>,
        user: &proto::xray::common::protocol::User,
    ) -> Result<(), Status> {
        let user = self.parse_vless_user(user)?;
        if users
            .iter()
            .any(|existing| existing.user_label == user.user_label)
        {
            return Err(Status::already_exists(format!(
                "VLESS user {} already exists",
                user.user_label
            )));
        }
        users.push(user);
        Ok(())
    }

    #[cfg(feature = "vless")]
    pub(super) fn remove_vless_user(
        &self,
        users: &mut Vec<VlessUser>,
        email: &str,
    ) -> Result<(), Status> {
        let before = users.len();
        users.retain(|user| user.user_label != email);
        if before == users.len() {
            return Err(Status::not_found(format!("VLESS user {email} not found")));
        }
        Ok(())
    }

    #[cfg(feature = "vless")]
    pub(super) fn apply_vless_runtime_operation(
        &self,
        users: &mut Vec<VlessUser>,
        operation: AlterInboundOperation,
    ) -> Result<bool, Status> {
        match operation {
            AlterInboundOperation::Noop => return Ok(true),
            AlterInboundOperation::AddUser(operation) => {
                let user = operation.user.as_ref().ok_or_else(|| {
                    Status::invalid_argument("AddUserOperation.user is required")
                })?;
                self.add_vless_user(users, user)?;
                let stats = self.runtime.policy_user_stats(user.level);
                if stats.uplink || stats.downlink {
                    register_identity(user.email.clone());
                }
            }
            AlterInboundOperation::RemoveUser(operation) => {
                let email = operation.email.trim();
                if email.is_empty() {
                    return Err(Status::invalid_argument(
                        "RemoveUserOperation.email is required",
                    ));
                }
                self.remove_vless_user(users, email)?;
            }
        }
        Ok(true)
    }

    #[cfg(feature = "vmess")]
    pub(super) fn add_vmess_user(
        &self,
        users: &mut Vec<VmessUser>,
        user: &proto::xray::common::protocol::User,
    ) -> Result<(), Status> {
        let parsed = self.parse_vmess_user(user)?;
        let email = user.email.trim();
        if !email.is_empty()
            && users
                .iter()
                .any(|existing| existing.user_label.eq_ignore_ascii_case(email))
        {
            return Err(Status::already_exists(format!(
                "VMess user {email} already exists"
            )));
        }
        users.push(parsed);
        Ok(())
    }

    #[cfg(feature = "vmess")]
    pub(super) fn remove_vmess_user(
        &self,
        users: &mut Vec<VmessUser>,
        email: &str,
    ) -> Result<(), Status> {
        let Some(index) = users
            .iter()
            .position(|user| user.user_label.eq_ignore_ascii_case(email))
        else {
            return Err(Status::not_found(format!("VMess user {email} not found")));
        };
        users.swap_remove(index);
        Ok(())
    }

    #[cfg(feature = "vmess")]
    pub(super) fn apply_vmess_runtime_operation(
        &self,
        users: &mut Vec<VmessUser>,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(operation) => {
                let user = operation.user.as_ref().ok_or_else(|| {
                    Status::invalid_argument("AddUserOperation.user is required")
                })?;
                self.add_vmess_user(users, user)?;
                let stats = self.runtime.policy_user_stats(user.level);
                if stats.uplink || stats.downlink {
                    register_identity(user.email.clone());
                }
                Ok(())
            }
            AlterInboundOperation::RemoveUser(operation) => {
                let email = operation.email.trim();
                if email.is_empty() {
                    return Err(Status::invalid_argument(
                        "RemoveUserOperation.email is required",
                    ));
                }
                self.remove_vmess_user(users, email)
            }
        }
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn map_shadowsocks_store_error(
        error: ShadowsocksUserStoreError,
    ) -> Status {
        match error {
            ShadowsocksUserStoreError::EmptyEmail => {
                Status::invalid_argument("RemoveUserOperation.email is required")
            }
            ShadowsocksUserStoreError::DuplicateEmail(email) => {
                Status::already_exists(format!(
                    "Shadowsocks user {email} already exists"
                ))
            }
            ShadowsocksUserStoreError::NotFound(email) => {
                Status::not_found(format!("Shadowsocks user {email} not found"))
            }
            ShadowsocksUserStoreError::InvalidUser(error) => {
                Status::invalid_argument(format!(
                    "invalid shadowsocks user: {error}"
                ))
            }
        }
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn apply_shadowsocks_runtime_operation(
        &self,
        store: &ShadowsocksUserStore,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(operation) => {
                let user = operation.user.as_ref().ok_or_else(|| {
                    Status::invalid_argument("AddUserOperation.user is required")
                })?;
                let parsed = self.parse_shadowsocks_user_with_identity_method(
                    store.identity_method(),
                    user,
                )?;
                store
                    .add_user(parsed)
                    .map_err(Self::map_shadowsocks_store_error)?;
                let stats = self.runtime.policy_user_stats(user.level);
                if stats.uplink || stats.downlink {
                    register_identity(user.email.clone());
                }
                Ok(())
            }
            AlterInboundOperation::RemoveUser(operation) => {
                let email = operation.email.trim();
                if email.is_empty() {
                    return Err(Status::invalid_argument(
                        "RemoveUserOperation.email is required",
                    ));
                }
                store
                    .remove_user_by_email(email)
                    .map_err(Self::map_shadowsocks_store_error)
            }
        }
    }

    #[cfg(feature = "trojan")]
    pub(super) fn parse_trojan_password(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<String, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for trojan",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        if account_type != TYPE_PROXY_TROJAN_ACCOUNT
            && account_type != TYPE_PROXY_TROJAN_ACCOUNT_V2RAY
        {
            return Err(Status::invalid_argument(format!(
                "unsupported trojan account type: {account_type}"
            )));
        }

        let payload = TrojanAccountPayload::decode(account.value.as_slice())
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid trojan account payload: {err}"
                ))
            })?;
        Ok(payload.password)
    }

    #[cfg(feature = "trojan")]
    pub(super) fn map_trojan_user_store_error(
        error: TrojanUserStoreError,
    ) -> Status {
        match error {
            TrojanUserStoreError::EmptyEmail => {
                Status::invalid_argument("RemoveUserOperation.email is required")
            }
            TrojanUserStoreError::DuplicateEmail(email) => {
                Status::already_exists(format!("Trojan user {email} already exists"))
            }
            TrojanUserStoreError::NotFound(email) => {
                Status::not_found(format!("Trojan user {email} not found"))
            }
        }
    }

    #[cfg(feature = "trojan")]
    pub(super) fn apply_trojan_runtime_operation(
        &self,
        store: &TrojanUserStore,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(operation) => {
                let user = operation.user.as_ref().ok_or_else(|| {
                    Status::invalid_argument("AddUserOperation.user is required")
                })?;
                let parsed = self.parse_trojan_user(user)?;
                store
                    .add_user(parsed)
                    .map_err(Self::map_trojan_user_store_error)?;
                let stats = self.runtime.policy_user_stats(user.level);
                if stats.uplink || stats.downlink {
                    register_identity(user.email.clone());
                }
                Ok(())
            }
            AlterInboundOperation::RemoveUser(operation) => store
                .remove_user_by_email(&operation.email)
                .map_err(Self::map_trojan_user_store_error),
        }
    }

    #[cfg(feature = "hysteria")]
    pub(super) fn apply_hysteria_runtime_operation(
        &self,
        store: &HysteriaUserStore,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(operation) => {
                let user = operation.user.as_ref().ok_or_else(|| {
                    Status::invalid_argument("AddUserOperation.user is required")
                })?;
                store.add_user(self.parse_hysteria_client(user)?);
                let stats = self.runtime.policy_user_stats(user.level);
                if stats.uplink || stats.downlink {
                    register_identity(user.email.clone());
                }
                Ok(())
            }
            AlterInboundOperation::RemoveUser(operation) => {
                store.remove_user_by_email(&operation.email);
                Ok(())
            }
        }
    }

    #[cfg(feature = "hysteria")]
    pub(super) fn apply_add_user_to_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        user: &proto::xray::common::protocol::User,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                self.add_vless_user(users, user)?;
                Ok(true)
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                self.add_vmess_user(users, user)?;
                Ok(true)
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                let parsed = self.parse_trojan_user(user)?;
                if let Some(email) = parsed.email.as_deref()
                    && users.iter().any(|existing| {
                        existing.email.as_deref().is_some_and(|current| {
                            current.eq_ignore_ascii_case(email)
                        })
                    })
                {
                    return Err(Status::already_exists(format!(
                        "Trojan user {email} already exists"
                    )));
                }
                users.push(parsed);
                Ok(true)
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                let client = self.parse_hysteria_client(user)?;
                // Xray's Hysteria validator is keyed by raw auth, not email.
                // Re-adding the same auth replaces that entry, while multiple
                // auth values with the same email are allowed to coexist. Move
                // replacements to the end so UUID masked-ID lookup remains
                // last-write-wins like Xray's secondary ID map.
                config.clients.retain(|existing| {
                    existing.xray_transport_auth_fallback
                        || existing.password != client.password
                });
                config.clients.push(client);
                Ok(true)
            }
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, identity } => {
                let current = ServerProxyConfig::Shadowsocks {
                    users: users.clone(),
                    identity: identity.clone(),
                };
                let parsed = self.parse_shadowsocks_user(&current, user)?;
                if identity.is_some()
                    && !parsed.email.is_empty()
                    && users.iter().any(|existing| existing.email == parsed.email)
                {
                    return Err(Status::already_exists(format!(
                        "Shadowsocks user {} already exists",
                        parsed.email
                    )));
                }
                users.push(parsed);
                Ok(true)
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
                crate::util::option::OneOrSome::One(target) => {
                    self.apply_add_user_to_protocol(&mut target.protocol, user)
                }
                crate::util::option::OneOrSome::Some(target_list) => {
                    let mut handled = false;
                    for target in target_list.iter_mut() {
                        handled |= self.apply_add_user_to_protocol(
                            &mut target.protocol,
                            user,
                        )?;
                    }
                    Ok(handled)
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.apply_add_user_to_protocol(tls.inner.as_mut(), user)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.apply_add_user_to_protocol(reality.inner.as_mut(), user)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.apply_add_user_to_protocol(inner.as_mut(), user)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.apply_add_user_to_protocol(config.inner.as_mut(), user)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.apply_add_user_to_protocol(config.inner.as_mut(), user)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn apply_add_user_operation(
        &self,
        protocol: &mut ServerProxyConfig,
        operation: proto::xray::app::proxyman::command::AddUserOperation,
    ) -> Result<(), Status> {
        let user = operation.user.ok_or_else(|| {
            Status::invalid_argument("AddUserOperation.user is required")
        })?;
        if self.apply_add_user_to_protocol(protocol, &user)? {
            let stats = self.runtime.policy_user_stats(user.level);
            if stats.uplink || stats.downlink {
                register_identity(user.email.clone());
            }
            return Ok(());
        }

        Err(Status::unknown(ERR_PROXY_NOT_USER_MANAGER))
    }

    pub(super) fn apply_remove_user_from_protocol(
        &self,
        protocol: &mut ServerProxyConfig,
        email: &str,
    ) -> Result<bool, Status> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                self.remove_vless_user(users, email)?;
                Ok(true)
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                self.remove_vmess_user(users, email)?;
                Ok(true)
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => {
                let Some(index) = users.iter().position(|user| {
                    user.email
                        .as_deref()
                        .is_some_and(|current| current.eq_ignore_ascii_case(email))
                }) else {
                    return Err(Status::not_found(format!(
                        "Trojan user {email} not found"
                    )));
                };
                users.swap_remove(index);
                Ok(true)
            }
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                if let Some(index) = config
                    .clients
                    .iter()
                    .position(|client| client.email.as_deref() == Some(email))
                {
                    // Xray DelByEmail resolves one matching user and deletes only
                    // that user's auth key; duplicate emails are not bulk-removed.
                    config.clients.remove(index);
                }
                // Xray's Hysteria DelByEmail is idempotent and returns nil even
                // when no matching email exists. `true` means this protocol did
                // handle the user-manager operation, not that a user was found.
                Ok(true)
            }
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, .. } => {
                let Some(index) = users
                    .iter()
                    .position(|user| user.email.eq_ignore_ascii_case(email))
                else {
                    return Err(Status::not_found(format!(
                        "Shadowsocks user {email} not found"
                    )));
                };
                users.swap_remove(index);
                Ok(true)
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_mut() {
                crate::util::option::OneOrSome::One(target) => {
                    self.apply_remove_user_from_protocol(&mut target.protocol, email)
                }
                crate::util::option::OneOrSome::Some(target_list) => {
                    let mut handled = false;
                    for target in target_list.iter_mut() {
                        handled |= self.apply_remove_user_from_protocol(
                            &mut target.protocol,
                            email,
                        )?;
                    }
                    Ok(handled)
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.apply_remove_user_from_protocol(tls.inner.as_mut(), email)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.apply_remove_user_from_protocol(reality.inner.as_mut(), email)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.apply_remove_user_from_protocol(inner.as_mut(), email)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.apply_remove_user_from_protocol(config.inner.as_mut(), email)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.apply_remove_user_from_protocol(config.inner.as_mut(), email)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn detached_inbound(inbound: &ServerConfig) -> ServerConfig {
        inbound.clone()
    }

    pub(super) fn apply_remove_user_operation(
        &self,
        protocol: &mut ServerProxyConfig,
        operation: proto::xray::app::proxyman::command::RemoveUserOperation,
    ) -> Result<(), Status> {
        let email = operation.email.trim();
        if email.is_empty() {
            return Err(Status::invalid_argument(
                "RemoveUserOperation.email is required",
            ));
        }

        if self.apply_remove_user_from_protocol(protocol, email)? {
            Ok(())
        } else {
            Err(Status::unknown(ERR_PROXY_NOT_USER_MANAGER))
        }
    }

    pub(super) fn apply_alter_inbound_operation(
        &self,
        inbound: &mut crate::config::server_config::ServerConfig,
        operation: AlterInboundOperation,
    ) -> Result<(), Status> {
        match operation {
            AlterInboundOperation::Noop => Ok(()),
            AlterInboundOperation::AddUser(op) => {
                self.apply_add_user_operation(&mut inbound.protocol, op)
            }
            AlterInboundOperation::RemoveUser(op) => {
                self.apply_remove_user_operation(&mut inbound.protocol, op)
            }
        }
    }

    pub(super) fn get_user_manager_identities(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<String>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => Some(
                users
                    .iter()
                    .filter_map(|user| {
                        user.email
                            .as_ref()
                            .filter(|email| !email.is_empty())
                            .cloned()
                    })
                    .collect(),
            ),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| client.email.clone().unwrap_or_default())
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => Some(vec![config.uuid.clone()]),
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut identities = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_identities(&target.protocol)
                        {
                            identities.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_identities(&target.protocol)
                            {
                                identities.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(identities)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.get_user_manager_identities(&tls.inner)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_identities(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_identities(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, .. } => {
                Some(users.iter().map(|user| user.email.clone()).collect())
            }
            ServerProxyConfig::DokodemoDoor { .. } => None,
        }
    }

    pub(super) fn shadowsocks_user_manager(protocol: &ServerProxyConfig) -> bool {
        match protocol {
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { .. } => true,
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
                crate::util::option::OneOrSome::One(target) => {
                    Self::shadowsocks_user_manager(&target.protocol)
                }
                crate::util::option::OneOrSome::Some(targets) => targets
                    .iter()
                    .any(|target| Self::shadowsocks_user_manager(&target.protocol)),
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                Self::shadowsocks_user_manager(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            _ => false,
        }
    }

    pub(super) fn select_user_manager_users(
        users: Vec<proto::xray::common::protocol::User>,
        email: &str,
        case_insensitive: bool,
    ) -> Vec<proto::xray::common::protocol::User> {
        if email.is_empty() {
            users
        } else {
            users
                .into_iter()
                .find(|user| {
                    if case_insensitive {
                        user.email.eq_ignore_ascii_case(email)
                    } else {
                        user.email == email
                    }
                })
                .into_iter()
                .collect()
        }
    }

    pub(super) fn get_user_manager_users(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<proto::xray::common::protocol::User>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => Some(
                users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.user_label.clone(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                            value: VlessAccountPayload {
                                id: user.user_id.clone(),
                                flow: user.flow.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => Some(
                users
                    .iter()
                    .map(|user| {
                        let security_type = match user.cipher.as_str() {
                            "aes-128-gcm" => 3,
                            "chacha20-poly1305" | "chacha20-ietf-poly1305" => 4,
                            _ => 2,
                        };
                        proto::xray::common::protocol::User {
                            level: 0,
                            email: user.user_label.clone(),
                            account: Some(
                                proto::xray::common::serial::TypedMessage {
                                    r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                                    value: VmessAccountPayload {
                                        id: user.user_id.clone(),
                                        security_settings: Some(
                                            VmessSecurityConfigPayload {
                                                r#type: security_type,
                                            },
                                        ),
                                        tests_enabled: String::new(),
                                    }
                                    .encode_to_vec(),
                                },
                            ),
                        }
                    })
                    .collect(),
            ),
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => Some(
                users
                    .iter()
                    .filter(|user| {
                        user.email.as_deref().is_some_and(|email| !email.is_empty())
                    })
                    .map(|user| proto::xray::common::protocol::User {
                        level: user.user_level,
                        email: user.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                            value: TrojanAccountPayload {
                                password: user.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| proto::xray::common::protocol::User {
                        level: client.level,
                        email: client.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                            value: HysteriaAccountPayload {
                                auth: client.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => {
                Some(vec![self.build_user(config.uuid.clone())])
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut users = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_users(&target.protocol)
                        {
                            users.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_users(&target.protocol)
                            {
                                users.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(users)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => self.get_user_manager_users(&tls.inner),
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_users(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_users(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_users(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_users(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, identity } => Some(
                users
                    .iter()
                    .map(|user| {
                        let account = if identity.is_some() {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT,
                                Shadowsocks2022AccountPayload {
                                    key: user.password.clone(),
                                },
                            )
                        } else {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                                ShadowsocksAccountPayload {
                                    password: user.password.clone(),
                                    cipher_type: Self::shadowsocks_cipher_type(
                                        &user.method,
                                    )
                                    .unwrap_or_default(),
                                    iv_check: false,
                                },
                            )
                        };
                        proto::xray::common::protocol::User {
                            level: user.user_level,
                            email: user.email.clone(),
                            account: Some(account),
                        }
                    })
                    .collect(),
            ),
            ServerProxyConfig::DokodemoDoor { .. } => None,
        }
    }
}
