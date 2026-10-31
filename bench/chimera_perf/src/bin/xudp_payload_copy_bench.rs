use std::hint::black_box;
use std::time::Instant;

use bytes::{Buf, BufMut, BytesMut};

const EVENTS: usize = 2_000_000;
const PAYLOAD_LEN: usize = 1200;
const LEGACY_RECEIVE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Buffered,
    Direct,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Direct => "direct",
        }
    }
}

fn run(mode: Mode) {
    let payload = vec![0x5a_u8; PAYLOAD_LEN];
    let mut receive_buffer = match mode {
        Mode::Buffered => Some(vec![0; LEGACY_RECEIVE_BUFFER_SIZE]),
        Mode::Direct => None,
    };
    let started = Instant::now();
    let mut checksum = 0_u64;

    for _ in 0..EVENTS {
        let mut input = BytesMut::with_capacity(PAYLOAD_LEN + 2);
        input.put_u16(PAYLOAD_LEN as u16);
        input.extend_from_slice(black_box(&payload));
        let payload_len = input.get_u16() as usize;
        let split = input.split_to(payload_len);
        let owned = if mode == Mode::Buffered {
            let buffer = receive_buffer
                .as_mut()
                .expect("buffered mode allocates a receive buffer");
            buffer[..payload_len].copy_from_slice(&split);
            buffer[..payload_len].to_vec()
        } else {
            split.to_vec()
        };
        checksum = checksum.wrapping_add(black_box(owned[0]) as u64);
        black_box(owned);
    }

    let elapsed = started.elapsed();
    println!(
        "mode={} payload_len={PAYLOAD_LEN} events={EVENTS} ns_per_payload={:.3} checksum={checksum}",
        mode.name(),
        elapsed.as_nanos() as f64 / EVENTS as f64,
    );
}

fn main() {
    match std::env::var("XUDP_PAYLOAD_BENCH_MODE").as_deref() {
        Ok("buffered") => run(Mode::Buffered),
        Ok("direct") => run(Mode::Direct),
        _ => panic!("XUDP_PAYLOAD_BENCH_MODE must be buffered or direct"),
    }
}
