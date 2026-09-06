use std::{
    hint::black_box,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use anyhow::{Result, bail};
use chimera_perf::stats::{coefficient_of_variation, median};
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FinishMode {
    RedundantFlush,
    CopyBufFlush,
}

#[derive(Debug, Parser)]
#[command(about = "Microbenchmark TCP relay copy completion flush overhead")]
struct Args {
    #[arg(long, value_enum)]
    mode: FinishMode,

    #[arg(long, default_value_t = 10_000_000)]
    iterations: u64,

    #[arg(long, default_value_t = 2)]
    warmup: usize,

    #[arg(long, default_value_t = 7)]
    runs: usize,
}

#[derive(Default)]
struct CountingWriter {
    writes: u64,
    flushes: u64,
    shutdowns: u64,
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes = self.writes.wrapping_add(1);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.flushes = self.flushes.wrapping_add(1);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.shutdowns = self.shutdowns.wrapping_add(1);
        Poll::Ready(Ok(()))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.iterations == 0 {
        bail!("--iterations must be greater than zero");
    }
    if args.runs == 0 {
        bail!("--runs must be greater than zero");
    }

    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    for _ in 0..args.warmup {
        black_box(runtime.block_on(run_once(args.mode, args.iterations))?);
    }

    let mut samples = Vec::with_capacity(args.runs);
    for run in 0..args.runs {
        let sample = runtime.block_on(run_once(args.mode, args.iterations))?;
        println!(
            "run={run} mode={:?} ns_per_transfer={:.3} writes={} flushes={} shutdowns={}",
            args.mode,
            sample.ns_per_transfer,
            sample.writes,
            sample.flushes,
            sample.shutdowns,
        );
        samples.push(sample.ns_per_transfer);
    }

    println!(
        "summary mode={:?} median_ns_per_transfer={:.3} cv={:.4}",
        args.mode,
        median(&samples),
        coefficient_of_variation(&samples),
    );
    Ok(())
}

struct Sample {
    ns_per_transfer: f64,
    writes: u64,
    flushes: u64,
    shutdowns: u64,
}

async fn run_once(mode: FinishMode, iterations: u64) -> Result<Sample> {
    let payload = [0x5a_u8];
    let mut writer = CountingWriter::default();
    let started = Instant::now();
    for _ in 0..iterations {
        let mut reader = &payload[..];
        tokio::io::copy_buf(black_box(&mut reader), black_box(&mut writer)).await?;
        if matches!(mode, FinishMode::RedundantFlush) {
            writer.flush().await?;
        }
        writer.shutdown().await?;
    }
    let elapsed = started.elapsed();
    let writer = black_box(writer);
    Ok(Sample {
        ns_per_transfer: elapsed.as_nanos() as f64 / iterations as f64,
        writes: writer.writes,
        flushes: writer.flushes,
        shutdowns: writer.shutdowns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_buf_already_flushes_before_completion() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let sample = runtime
            .block_on(run_once(FinishMode::CopyBufFlush, 8))
            .unwrap();
        assert_eq!(sample.writes, 8);
        assert_eq!(sample.flushes, 8);
        assert_eq!(sample.shutdowns, 8);
    }

    #[test]
    fn redundant_mode_adds_exactly_one_flush_per_transfer() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let sample = runtime
            .block_on(run_once(FinishMode::RedundantFlush, 8))
            .unwrap();
        assert_eq!(sample.writes, 8);
        assert_eq!(sample.flushes, 16);
        assert_eq!(sample.shutdowns, 8);
    }
}
