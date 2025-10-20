#![forbid(unsafe_code)]

use anyhow::Result;
#[cfg(not(feature = "systemd"))]
use anyhow::bail;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
struct Opts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    with_services: bool,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    #[cfg(not(feature = "systemd"))]
    if opts.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    let snap = describe_me::SystemSnapshot::capture_with(describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true,
    })?;

    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
