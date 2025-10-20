#![forbid(unsafe_code)]

#[cfg(not(feature = "systemd"))]
use anyhow::bail;
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
struct Opts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    with_services: bool,

    /// Afficher l'usage disque (agrégé + partitions)
    #[arg(long)]
    disks: bool,

    /// Fichier de config TOML (feature `config`)
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    #[cfg(not(feature = "systemd"))]
    if opts.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    if opts.disks {
        let du = describe_me::disk_usage()?;
        println!("Disque total: {} Gio", du.total_bytes as f64 / 1e9);
        for p in du.partitions {
            println!(
                "{}  total={} Gio  dispo={} Gio  fs={:?}",
                p.mount_point,
                p.total_bytes as f64 / 1e9,
                p.available_bytes as f64 / 1e9,
                p.fs_type
            );
        }
        return Ok(());
    }

    // Charge optionnellement la config
    #[cfg(feature = "config")]
    let cfg = if let Some(p) = &opts.config {
        Some(describe_me::load_config_from_path(p)?)
    } else {
        None
    };

    #[cfg(not(feature = "config"))]
    if opts.config.is_some() {
        bail!(
            "--config nécessite la feature `config` (cargo run --features \"cli systemd config\")."
        );
    }

    // Capture snapshot
    #[allow(unused_mut)]
    let mut snap = describe_me::SystemSnapshot::capture_with(describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true,
    })?;

    // Applique le filtrage si demandé + services présents
    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = &cfg {
        snap.services_running =
            describe_me::filter_services(std::mem::take(&mut snap.services_running), cfg);
    }

    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
