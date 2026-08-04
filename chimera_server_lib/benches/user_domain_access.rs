use std::{hint::black_box, str::FromStr};

use chimera_server_lib::user_domain_access::{
    AccessAction, AccessTarget, DomainMatchKind, EnforcementMode,
    ProtocolIdentityConfig, UserDomainAccessConfig, UserDomainAccessPolicy,
    UserDomainPolicyConfig, UserDomainRuleConfig, UserId, UserPolicyMode,
};
use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};

const USER_COUNTS: [usize; 3] = [1, 100, 10_000];
const RULE_COUNTS: [usize; 4] = [1, 10, 100, 1_000];

fn user_uuid(index: usize) -> String {
    format!("00000000-0000-4000-8000-{index:012x}")
}

fn rule_domain(user_index: usize, rule_index: usize) -> String {
    format!("rule-{rule_index}.user-{user_index}.example.com")
}

fn build_config(
    user_count: usize,
    rules_per_user: usize,
    match_kind: DomainMatchKind,
) -> UserDomainAccessConfig {
    let users = (0..user_count)
        .map(|user_index| UserDomainPolicyConfig {
            user_uuid: user_uuid(user_index),
            protocol_identity: ProtocolIdentityConfig::default(),
            mode: UserPolicyMode::Allowlist,
            unknown_target_action: AccessAction::Reject,
            rules: (0..rules_per_user)
                .map(|rule_index| UserDomainRuleConfig {
                    id: Some(format!("user-{user_index}-rule-{rule_index}")),
                    domain: rule_domain(user_index, rule_index),
                    match_kind,
                    action: AccessAction::Allow,
                    priority: 100,
                })
                .collect(),
        })
        .collect();

    UserDomainAccessConfig {
        version: 1,
        generated_at: None,
        source_backend_version: None,
        target_node_uuid: None,
        checksum: None,
        signature_algorithm: None,
        signing_key_id: None,
        signature: None,
        default_action: AccessAction::Reject,
        enforcement_mode: EnforcementMode::Enforce,
        users,
    }
}

fn compile_policy(
    user_count: usize,
    rules_per_user: usize,
    match_kind: DomainMatchKind,
) -> UserDomainAccessPolicy {
    UserDomainAccessPolicy::compile(build_config(
        user_count,
        rules_per_user,
        match_kind,
    ))
    .expect("benchmark policy should compile")
}

fn target_for(
    user_index: usize,
    rule_index: usize,
    match_kind: DomainMatchKind,
) -> AccessTarget {
    let domain = match match_kind {
        DomainMatchKind::Exact => rule_domain(user_index, rule_index),
        DomainMatchKind::Suffix => {
            format!("api.{}", rule_domain(user_index, rule_index))
        }
    };
    AccessTarget::classify(Some(&domain)).expect("benchmark target should parse")
}

fn user_id(index: usize) -> UserId {
    UserId::from_str(&user_uuid(index)).expect("benchmark user UUID should parse")
}

fn bench_compile_user_scale(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("compile_user_scale");
    for user_count in USER_COUNTS {
        group.throughput(Throughput::Elements(user_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(user_count),
            &user_count,
            |bencher, &count| {
                bencher.iter_batched(
                    || build_config(count, 1, DomainMatchKind::Exact),
                    |config| {
                        black_box(
                            UserDomainAccessPolicy::compile(config)
                                .expect("benchmark policy should compile"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_compile_rule_scale(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("compile_rule_scale");
    for rule_count in RULE_COUNTS {
        group.throughput(Throughput::Elements(rule_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            &rule_count,
            |bencher, &count| {
                bencher.iter_batched(
                    || build_config(1, count, DomainMatchKind::Suffix),
                    |config| {
                        black_box(
                            UserDomainAccessPolicy::compile(config)
                                .expect("benchmark policy should compile"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_decision_user_scale(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decision_user_scale");
    group.throughput(Throughput::Elements(1));
    for user_count in USER_COUNTS {
        let policy = compile_policy(user_count, 1, DomainMatchKind::Exact);
        let user = user_id(user_count - 1);
        let target = target_for(user_count - 1, 0, DomainMatchKind::Exact);
        group.bench_with_input(
            BenchmarkId::from_parameter(user_count),
            &user_count,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(policy.decide(black_box(user), black_box(&target)));
                });
            },
        );
    }
    group.finish();
}

fn bench_decision_rule_scale(
    criterion: &mut Criterion,
    match_kind: DomainMatchKind,
    group_name: &str,
) {
    let mut group = criterion.benchmark_group(group_name);
    group.throughput(Throughput::Elements(1));
    let user = user_id(0);

    for rule_count in RULE_COUNTS {
        let policy = compile_policy(1, rule_count, match_kind);
        let declared_first = target_for(0, 0, match_kind);
        let declared_last = target_for(0, rule_count - 1, match_kind);
        let miss = AccessTarget::classify(Some("not-listed.example.net"))
            .expect("benchmark miss target should parse");

        for (case, target) in [
            ("declared_first", declared_first),
            ("declared_last", declared_last),
            ("miss", miss),
        ] {
            group.bench_with_input(
                BenchmarkId::new(case, rule_count),
                &rule_count,
                |bencher, _| {
                    bencher.iter(|| {
                        black_box(
                            policy.decide(black_box(user), black_box(&target)),
                        );
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_exact_rule_scale(criterion: &mut Criterion) {
    bench_decision_rule_scale(
        criterion,
        DomainMatchKind::Exact,
        "decision_exact_rule_scale",
    );
}

fn bench_suffix_rule_scale(criterion: &mut Criterion) {
    bench_decision_rule_scale(
        criterion,
        DomainMatchKind::Suffix,
        "decision_suffix_rule_scale",
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        bench_compile_user_scale,
        bench_compile_rule_scale,
        bench_decision_user_scale,
        bench_exact_rule_scale,
        bench_suffix_rule_scale
}
criterion_main!(benches);
