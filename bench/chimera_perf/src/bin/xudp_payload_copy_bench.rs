use std::hint::black_box;
use std::time::Instant;

use bytes::{Buf, BufMut, BytesMut};

const EVENTS: usize = 2_000_000;
const PAYLOAD_LEN: usize = 1200;

fn run(keep_split: bool) {
    let payload = vec![0x5a_u8; PAYLOAD_LEN];
    let started = Instant::now();
    let mut checksum = 0_u64;

    for _ in 0..EVENTS {
        let mut input = BytesMut::with_capacity(PAYLOAD_LEN + 2);
        input.put_u16(PAYLOAD_LEN as u16);
        input.extend_from_slice(black_box(&payload));
        let payload_len = input.get_u16() as usize;
        let split = input.split_to(payload_len);
        if keep_split {
            checksum = checksum.wrapping_add(black_box(split[0]) as u64);
            black_box(split);
        } else {
            let owned = split.to_vec();
            checksum = checksum.wrapping_add(black_box(owned[0]) as u64);
            black_box(owned);
        }
    }

    let elapsed = started.elapsed();
    println!(
        "mode={} ns_per_payload={:.3} checksum={checksum}",
        if keep_split { "split" } else { "vec" },
        elapsed.as_nanos() as f64 / EVENTS as f64,
    );
}

fn main() {
    match std::env::var("XUDP_PAYLOAD_BENCH_MODE").as_deref() {
        Ok("vec") => run(false),
        Ok("split") => run(true),
        _ => panic!("XUDP_PAYLOAD_BENCH_MODE must be vec or split"),
    }
}
