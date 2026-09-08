use std::{collections::HashMap, hint::black_box, time::Instant};

const EVENTS: usize = 5_000_000;
const SESSION_ID: u16 = 77;
const TARGET: &str = "benchmark-subdomain.example.invalid";

#[derive(Clone)]
struct SessionState {
    target: String,
}

fn run(compare_before_clone: bool) {
    let mut sessions = HashMap::from([(
        SESSION_ID,
        SessionState {
            target: TARGET.to_owned(),
        },
    )]);
    let incoming_target = TARGET.to_owned();
    let started = Instant::now();
    let mut checksum = 0_u64;

    for event in 0..EVENTS {
        let session = sessions.get_mut(&black_box(SESSION_ID)).expect("known session");
        let target = black_box(&incoming_target);
        if compare_before_clone {
            if session.target != *target {
                session.target = target.clone();
            }
        } else {
            session.target = target.clone();
        }
        checksum = checksum
            .wrapping_add(session.target.len() as u64)
            .wrapping_add(event as u64 & 1);
    }

    let elapsed = started.elapsed();
    println!(
        "mode={} ns_per_frame={:.3} checksum={checksum}",
        if compare_before_clone { "compare" } else { "clone" },
        elapsed.as_nanos() as f64 / EVENTS as f64,
    );
}

fn main() {
    match std::env::var("XUDP_TARGET_UPDATE_BENCH_MODE").as_deref() {
        Ok("clone") => run(false),
        Ok("compare") => run(true),
        _ => panic!("XUDP_TARGET_UPDATE_BENCH_MODE must be clone or compare"),
    }
}
