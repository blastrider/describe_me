#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
use anyhow::Result;
#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
struct Opts {
    /// Affiche aussi la liste des services (Linux/systemd)
    #[arg(long)]
    with_services: bool,
}

#[cfg(feature = "cli")]
fn main() -> Result<()> {
    let _opts = Opts::parse();
    let snap = describe_me::SystemSnapshot::capture()?;
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("Le binaire `describe-me` nécessite la feature `cli`. Lancez `cargo run --features cli --bin describe-me`.");
    std::process::exit(1);
}
