use std::{collections::HashMap, hint::black_box, time::Instant};

const EVENTS: usize = 5_000_000;
const SESSION_ID: u16 = 77;

#[derive(Clone)]
struct SessionState {
    target: String,
    global_id: Option<[u8; 8]>,
}

fn run(borrowed: bool) {
    let mut sessions = HashMap::new();
    sessions.insert(
        SESSION_ID,
        SessionState {
            target: "benchmark-subdomain.example.invalid".to_owned(),
            global_id: Some([0x5a; 8]),
        },
    );

    let started = Instant::now();
    let mut checksum = 0_u64;
    for event in 0..EVENTS {
        let session_id = black_box(SESSION_ID);
        if borrowed {
            let existing_global_id = sessions.get(&session_id).map(|session| session.global_id);
            let session_known = existing_global_id.is_some();
            let session = sessions.get(&session_id);
            let target = session
                .map(|session| session.target.clone())
                .expect("known session");
            let global_id = session.and_then(|session| session.global_id);
            checksum = checksum
                .wrapping_add(session_known as u64)
                .wrapping_add(target.len() as u64)
                .wrapping_add(global_id.map_or(0, |id| u64::from(id[0])))
                .wrapping_add(event as u64 & 1);
            black_box(target);
        } else {
            let existing_session = sessions.get(&session_id).cloned();
            let session_known = existing_session.is_some();
            let session = sessions.get(&session_id).cloned();
            let target = session
                .as_ref()
                .map(|session| session.target.clone())
                .expect("known session");
            let global_id = session.and_then(|session| session.global_id);
            checksum = checksum
                .wrapping_add(session_known as u64)
                .wrapping_add(target.len() as u64)
                .wrapping_add(global_id.map_or(0, |id| u64::from(id[0])))
                .wrapping_add(event as u64 & 1);
            black_box(existing_session);
            black_box(target);
        }
    }
    let elapsed = started.elapsed();
    println!(
        "mode={} ns_per_frame={:.3} checksum={checksum}",
        if borrowed { "borrowed" } else { "cloned" },
        elapsed.as_nanos() as f64 / EVENTS as f64,
    );
}

fn main() {
    match std::env::var("XUDP_SESSION_BENCH_MODE").as_deref() {
        Ok("cloned") => run(false),
        Ok("borrowed") => run(true),
        _ => panic!("XUDP_SESSION_BENCH_MODE must be cloned or borrowed"),
    }
}
