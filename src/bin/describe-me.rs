#![forbid(unsafe_code)]

use anyhow::{bail, Result};
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

    // Si l'utilisateur demande les services mais que la feature systemd n'est pas compilée.
    #[cfg(not(feature = "systemd"))]
    {
        if opts.with_services {
            bail!("--with-services nécessite la feature `systemd` à la compilation (cargo run --features \"cli systemd\").");
        }
    }

    let options = describe_me::CaptureOptions {
        with_services: opts.with_services,
    };

    let snap = describe_me::SystemSnapshot::capture_with(options)?;
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}

