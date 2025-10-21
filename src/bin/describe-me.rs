#![forbid(unsafe_code)]

#[cfg(not(feature = "systemd"))]
use anyhow::bail;
use anyhow::Result;
use clap::{ArgAction, Parser};
#[cfg(feature = "cli")]
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
struct Opts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    with_services: bool,

    /// Afficher l'usage disque (agrégé + partitions)
    /// (Note: l'usage disque est de toute façon présent dans le snapshot JSON)
    #[arg(long)]
    disks: bool,

    /// Fichier de config TOML (feature `config`)
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Affiche les sockets d’écoute (TCP/UDP) — nécessite la feature `net`
    #[arg(long = "net-listen", action = ArgAction::SetTrue)]
    net_listen: bool,

    /// Affiche aussi le PID propriétaire (si résolu) — nécessite `--net-listen`
    #[arg(long = "process", requires = "net_listen", action = ArgAction::SetTrue)]
    show_process: bool,

    /// Force la sortie 100% JSON (un seul document)
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,

    /// Mise en forme JSON indentée (implique --json)
    #[arg(long, action = ArgAction::SetTrue)]
    pretty: bool,
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct ListeningSocketOut {
    proto: String,
    addr: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput {
    snapshot: describe_me::SystemSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<Vec<ListeningSocketOut>>,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    #[cfg(not(feature = "systemd"))]
    if opts.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    #[cfg(not(feature = "net"))]
    if opts.net_listen {
        bail!("--net-listen nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    // Charge optionnellement la config (pour filtrage services)
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

    // Capture le snapshot complet
    #[allow(unused_mut)]
    let mut snap = describe_me::SystemSnapshot::capture_with(describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true, // on garde true pour un JSON complet
    })?;

    // Filtre les services si demandé (systemd + config)
    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = &cfg {
        snap.services_running =
            describe_me::filter_services(std::mem::take(&mut snap.services_running), cfg);
    }

    // Récupère les sockets si --net-listen (et map vers struct serialisable locale)
    #[cfg(feature = "net")]
    let net_listen_vec: Option<Vec<ListeningSocketOut>> = if opts.net_listen {
        let socks = describe_me::net_listen()?;
        Some(
            socks
                .into_iter()
                .map(|s| ListeningSocketOut {
                    proto: s.proto,
                    addr: s.addr,
                    port: s.port,
                    pid: s.process,
                })
                .collect(),
        )
    } else {
        None
    };

    // Si JSON demandé: on ne sort qu'un seul document JSON combiné
    if opts.json || opts.pretty {
        #[cfg(feature = "cli")]
        {
            let combined = CombinedOutput {
                snapshot: snap,
                #[cfg(feature = "net")]
                net_listen: net_listen_vec,
                #[cfg(not(feature = "net"))]
                net_listen: None,
            };

            if opts.pretty {
                println!("{}", serde_json::to_string_pretty(&combined)?);
            } else {
                println!("{}", serde_json::to_string(&combined)?);
            }
            return Ok(());
        }
        #[cfg(not(feature = "cli"))]
        {
            // par sécurité, si jamais cli/serde n'est pas activé (mais normalement `cli` l'active).
            println!("{}", serde_json::to_string_pretty(&snap)?);
            return Ok(());
        }
    }

    // --- Mode non-JSON (comportement existant + snapshot JSON à la fin) ---

    // 1) NET — tableau lisible
    #[cfg(feature = "net")]
    if opts.net_listen {
        if opts.show_process {
            println!("{:<5} {:<15} {:<6} {:<6}", "PROTO", "ADDR", "PORT", "PID");
        } else {
            println!("{:<5} {:<15} {:<6}", "PROTO", "ADDR", "PORT");
        }

        if let Some(list) = &net_listen_vec {
            if list.is_empty() {
                println!("(aucune socket d’écoute trouvée)");
            } else {
                for s in list {
                    if opts.show_process {
                        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                        println!("{:<5} {:<15} {:<6} {:<6}", s.proto, s.addr, s.port, pid);
                    } else {
                        println!("{:<5} {:<15} {:<6}", s.proto, s.addr, s.port);
                    }
                }
            }
        }
        println!();
    }

    // 2) DISKS — affichage humain (optionnel)
    if opts.disks {
        if let Some(du) = &snap.disk_usage {
            println!("Disque total: {} Gio", du.total_bytes as f64 / 1e9);
            for p in &du.partitions {
                println!(
                    "{}  total={} Gio  dispo={} Gio  fs={:?}",
                    p.mount_point,
                    p.total_bytes as f64 / 1e9,
                    p.available_bytes as f64 / 1e9,
                    p.fs_type
                );
            }
        } else {
            println!("(usage disque non capturé)");
        }
        println!();
    }

    // 3) Snapshot JSON (comme avant)
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
