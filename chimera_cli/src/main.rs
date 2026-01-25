use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::{OsRng, RngCore};
use std::fmt::{self, Write};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "chimera-cli", about = "Utility helpers for Chimera Server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate x25519 keypairs in the same style as xray-core
    X25519 {
        /// Number of keypairs to generate
        #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=8))]
        count: u32,

        /// Output format for the keys
        #[arg(short, long, value_enum, default_value_t = KeyFormat::Base64)]
        format: KeyFormat,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum KeyFormat {
    Base64,
    Hex,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::X25519 { count, format } => {
            for i in 0..count {
                if i > 0 {
                    println!();
                }
                let (private, public) = generate_keypair(format);
                println!("Private key ({format}): {private}");
                println!("Public key  ({format}): {public}");
            }
        }
    }

    Ok(())
}

fn generate_keypair(format: KeyFormat) -> (String, String) {
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    (
        encode_key(secret.as_bytes(), format),
        encode_key(public.as_bytes(), format),
    )
}

fn encode_key(bytes: &[u8], format: KeyFormat) -> String {
    match format {
        KeyFormat::Base64 => STANDARD.encode(bytes),
        KeyFormat::Hex => {
            let mut encoded = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(encoded, "{:02x}", byte);
            }
            encoded
        }
    }
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFormat::Base64 => write!(f, "base64"),
            KeyFormat::Hex => write!(f, "hex"),
        }
    }
}
