#![cfg(all(test, feature = "user_domain_access"))]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    RuntimeState,
    user_domain_access::{
        AccessAction, AccessTarget, EnforcementMode, PolicySignatureAlgorithm,
        UserDomainAccessConfig, UserDomainAccessSignatureVerifier,
        user_domain_access_checksum, user_domain_access_signature_payload,
    },
};

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "chimera-user-domain-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn config(version: u64, domain: &str) -> UserDomainAccessConfig {
    let mut config: UserDomainAccessConfig =
        serde_json::from_value(serde_json::json!({
        "version": version,
        "generatedAt": format!("revision-{version}"),
        "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "defaultAction": "reject",
        "users": [{
            "userUuid": "11111111-1111-4111-8111-111111111111",
            "mode": "allowlist",
            "unknownTargetAction": "reject",
            "rules": [{
                "id": format!("allow-{version}"),
                "domain": domain,
                "match": "exact",
                "action": "allow"
            }]
        }]
        }))
        .expect("revision config should parse");
    config.checksum = Some(
        user_domain_access_checksum(&config)
            .expect("revision checksum should compute"),
    );
    config
}

fn signed_config(
    key_pair: &Ed25519KeyPair,
    version: u64,
    domain: &str,
) -> UserDomainAccessConfig {
    let mut config = config(version, domain);
    config.signature_algorithm = Some(PolicySignatureAlgorithm::Ed25519);
    config.signing_key_id = Some("release-key".into());
    config.signature = None;
    config.checksum = Some(
        user_domain_access_checksum(&config)
            .expect("signed revision checksum should compute"),
    );
    let payload = user_domain_access_signature_payload(&config)
        .expect("signed revision payload should compute");
    config.signature = Some(STANDARD.encode(key_pair.sign(&payload).as_ref()));
    config
}

fn decision(runtime: &RuntimeState, domain: &str) -> AccessAction {
    let policy = runtime
        .user_domain_access()
        .expect("policy should be installed");
    let user = "11111111-1111-4111-8111-111111111111"
        .parse()
        .expect("valid user UUID");
    let target = AccessTarget::classify(Some(domain)).expect("valid domain");
    policy.decide(user, &target).action
}

#[test]
fn required_signatures_are_verified_before_runtime_replacement() {
    let key_pair = Ed25519KeyPair::generate().expect("generate Ed25519 key");
    let verifier = UserDomainAccessSignatureVerifier::from_base64_keys(
        true,
        [(
            "release-key".into(),
            STANDARD.encode(key_pair.public_key().as_ref()),
        )],
    )
    .expect("signature verifier should configure");
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .configure_user_domain_access_signature_verifier(verifier)
        .expect("signature verifier should install");

    let error = runtime
        .install_user_domain_access(config(1, "unsigned.example"))
        .expect_err("unsigned revision must be rejected");
    assert!(error.contains("signature is required"));
    assert!(runtime.user_domain_access_revision().is_none());

    let signed = signed_config(&key_pair, 1, "signed.example");
    let revision = runtime
        .install_user_domain_access(signed.clone())
        .expect("valid signed revision should install");
    assert_eq!(revision.signing_key_id.as_deref(), Some("release-key"));
    assert_eq!(revision.signature_algorithm.as_deref(), Some("ed25519"));

    let mut tampered = signed;
    tampered.version = 2;
    tampered.users[0].rules[0].domain = "tampered.example".into();
    tampered.checksum = Some(
        user_domain_access_checksum(&tampered)
            .expect("tampered checksum should recompute"),
    );
    let error = runtime
        .install_user_domain_access(tampered)
        .expect_err("stale signature must reject tampered revision");
    assert!(error.contains("signature verification failed"));
    assert_eq!(
        runtime
            .user_domain_access_revision()
            .expect("signed revision should remain active")
            .version,
        1
    );
    assert_eq!(decision(&runtime, "signed.example"), AccessAction::Allow);
}

#[test]
fn installs_only_strictly_newer_revisions() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let first = runtime
        .install_user_domain_access(config(1, "one.example"))
        .expect("version 1 should install");
    assert_eq!(first.version, 1);
    assert_eq!(decision(&runtime, "one.example"), AccessAction::Allow);

    let second = runtime
        .install_user_domain_access(config(2, "two.example"))
        .expect("version 2 should install");
    assert_eq!(second.version, 2);
    assert_eq!(decision(&runtime, "one.example"), AccessAction::Reject);
    assert_eq!(decision(&runtime, "two.example"), AccessAction::Allow);

    let error = runtime
        .install_user_domain_access(config(2, "replayed.example"))
        .expect_err("same version must be rejected");
    assert!(error.contains("not newer"));
    assert_eq!(
        runtime
            .user_domain_access_revision()
            .expect("revision should exist")
            .version,
        2
    );
}

#[test]
fn rollback_keeps_highest_version_replay_protection() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .install_user_domain_access(config(1, "one.example"))
        .unwrap();
    runtime
        .install_user_domain_access(config(2, "two.example"))
        .unwrap();

    let rolled_back = runtime
        .rollback_user_domain_access(1)
        .expect("version 1 should be retained");
    assert_eq!(rolled_back.version, 1);
    assert_eq!(decision(&runtime, "one.example"), AccessAction::Allow);

    let error = runtime
        .install_user_domain_access(config(2, "replayed.example"))
        .expect_err("rolled back runtime must still reject replayed version 2");
    assert!(error.contains("highest installed version 2"));

    runtime
        .install_user_domain_access(config(3, "three.example"))
        .expect("version 3 should install after rollback");
    assert_eq!(decision(&runtime, "three.example"), AccessAction::Allow);
}

#[test]
fn invalid_revision_preserves_active_policy() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .install_user_domain_access(config(7, "stable.example"))
        .unwrap();

    let mut invalid = config(8, "invalid.example");
    invalid.users[0].rules.clear();
    invalid.checksum = Some(user_domain_access_checksum(&invalid).unwrap());
    let error = runtime
        .install_user_domain_access(invalid)
        .expect_err("empty allowlist must fail before replacement");
    assert!(error.contains("allowlist"));
    assert_eq!(decision(&runtime, "stable.example"), AccessAction::Allow);
    assert_eq!(
        runtime
            .user_domain_access_revision()
            .expect("revision should remain installed")
            .version,
        7
    );
}

#[test]
fn decision_metrics_use_fixed_reason_buckets() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .install_user_domain_access(config(1, "allowed.example"))
        .unwrap();
    let policy = runtime.user_domain_access().unwrap();
    let user = "11111111-1111-4111-8111-111111111111".parse().unwrap();

    let allowed = policy.decide(
        user,
        &AccessTarget::classify(Some("allowed.example")).unwrap(),
    );
    runtime.record_user_domain_access_decision(&allowed, EnforcementMode::Enforce);
    let rejected = policy.decide(
        user,
        &AccessTarget::classify(Some("blocked.example")).unwrap(),
    );
    runtime.record_user_domain_access_decision(&rejected, EnforcementMode::Shadow);
    let unknown =
        policy.decide(user, &AccessTarget::IpAddress("192.0.2.1".parse().unwrap()));
    runtime.record_user_domain_access_decision(&unknown, EnforcementMode::Enforce);

    let stats = runtime.user_domain_access_stats();
    assert_eq!(stats.evaluations, 3);
    assert_eq!(stats.allowed, 1);
    assert_eq!(stats.rejected, 2);
    assert_eq!(stats.matched_rule, 1);
    assert_eq!(stats.allowlist_miss, 1);
    assert_eq!(stats.unknown_target, 1);
    assert_eq!(stats.enforced_rejections, 1);
    assert_eq!(stats.shadow_rejections, 1);
}

#[test]
fn target_node_mismatch_preserves_active_revision() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .configure_user_domain_access_target_node(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .unwrap();
    runtime
        .install_user_domain_access(config(1, "stable.example"))
        .unwrap();

    let mut wrong_node = config(2, "wrong.example");
    wrong_node.target_node_uuid =
        Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into());
    wrong_node.checksum = Some(user_domain_access_checksum(&wrong_node).unwrap());
    let error = runtime
        .install_user_domain_access(wrong_node)
        .expect_err("wrong target node must be rejected");
    assert!(error.contains("targets node"));
    assert_eq!(runtime.user_domain_access_revision().unwrap().version, 1);
    assert_eq!(decision(&runtime, "stable.example"), AccessAction::Allow);

    let mut missing_node = config(2, "missing.example");
    missing_node.target_node_uuid = None;
    missing_node.checksum =
        Some(user_domain_access_checksum(&missing_node).unwrap());
    let error = runtime
        .install_user_domain_access(missing_node)
        .expect_err("missing target node must be rejected");
    assert!(error.contains("missing targetNodeUuid"));
    assert_eq!(runtime.user_domain_access_revision().unwrap().version, 1);
}

#[test]
fn installs_and_rolls_back_persisted_revisions_atomically() {
    let directory = temporary_path("persist");
    let store = directory.join("policy.json");
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .configure_user_domain_access_store(store.clone())
        .unwrap();

    let first = config(1, "one.example");
    runtime.install_user_domain_access(first.clone()).unwrap();
    let persisted = crate::runtime::load_user_domain_access_store(&store)
        .unwrap()
        .expect("persisted version 1 missing");
    assert_eq!(persisted.config, first);
    assert_eq!(persisted.highest_seen_version, 1);

    let second = config(2, "two.example");
    runtime.install_user_domain_access(second.clone()).unwrap();
    let persisted = crate::runtime::load_user_domain_access_store(&store)
        .unwrap()
        .expect("persisted version 2 missing");
    assert_eq!(persisted.config, second);
    assert_eq!(persisted.highest_seen_version, 2);
    assert_eq!(persisted.history, vec![first.clone()]);

    runtime.rollback_user_domain_access(1).unwrap();
    let persisted = crate::runtime::load_user_domain_access_store(&store)
        .unwrap()
        .expect("rolled-back version missing");
    assert_eq!(persisted.config, first);
    assert_eq!(persisted.highest_seen_version, 2);
    assert_eq!(persisted.history, vec![second.clone()]);
    assert_eq!(decision(&runtime, "one.example"), AccessAction::Allow);

    let restarted = RuntimeState::new(Vec::new(), Vec::new());
    restarted
        .configure_user_domain_access_store(store.clone())
        .unwrap();
    restarted
        .restore_user_domain_access_persisted_state(
            persisted.highest_seen_version,
            persisted.history,
        )
        .expect("persisted history should restore");
    restarted
        .install_user_domain_access(persisted.config)
        .expect("rolled-back current revision should restore");
    assert_eq!(
        restarted
            .rollback_user_domain_access(2)
            .expect(
                "persisted version 2 should remain rollback-capable after restart"
            )
            .version,
        2
    );
    assert_eq!(decision(&restarted, "two.example"), AccessAction::Allow);
    let replay = restarted
        .install_user_domain_access(config(2, "replayed.example"))
        .expect_err("highest version must survive rollback and restart");
    assert!(replay.contains("highest installed version 2"));
    restarted
        .install_user_domain_access(config(3, "three.example"))
        .expect("strictly newer version should install after restart");

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_persisted_config_restores_its_version_as_replay_floor() {
    let directory = temporary_path("legacy-store");
    fs::create_dir_all(&directory).unwrap();
    let store = directory.join("policy.json");
    let legacy = config(7, "legacy.example");
    fs::write(&store, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

    let loaded = crate::runtime::load_user_domain_access_store(&store)
        .unwrap()
        .expect("legacy store should load");
    assert_eq!(loaded.config, legacy);
    assert_eq!(loaded.highest_seen_version, 7);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn persistence_failure_preserves_active_revision() {
    let directory = temporary_path("persist-failure");
    fs::create_dir_all(&directory).unwrap();
    let parent_file = directory.join("parent-file");
    fs::write(&parent_file, b"not a directory").unwrap();

    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    runtime
        .install_user_domain_access(config(1, "stable.example"))
        .unwrap();
    runtime
        .configure_user_domain_access_store(parent_file.join("policy.json"))
        .unwrap();
    let error = runtime
        .install_user_domain_access(config(2, "new.example"))
        .expect_err("persistence failure must reject replacement");
    assert!(error.contains("store directory"));
    assert_eq!(decision(&runtime, "stable.example"), AccessAction::Allow);
    assert_eq!(decision(&runtime, "new.example"), AccessAction::Reject);
    assert_eq!(runtime.user_domain_access_revision().unwrap().version, 1);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn history_is_bounded() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    for version in 1..=7 {
        runtime
            .install_user_domain_access(config(
                version,
                &format!("v{version}.example"),
            ))
            .unwrap();
    }

    assert!(runtime.rollback_user_domain_access(1).is_err());
    assert_eq!(
        runtime
            .rollback_user_domain_access(2)
            .expect("five prior revisions should be retained")
            .version,
        2
    );
}
