#![forbid(unsafe_code)]
#[path = "../cli/opts.rs"]
mod cli_opts;
use anyhow::bail; // <— import inconditionnel
use anyhow::{Context, Result};
use clap::Parser;

#[cfg(feature = "cli")]
use serde::Serialize;

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use cli_opts::Opts;

const CONFIG_MAX_BYTES: u64 = 1_048_576; // 1 MiB

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

/* ==================== Helpers sécurité CLI ==================== */

#[cfg(unix)]
fn is_world_writable(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (md.mode() & 0o022) != 0 // writable par groupe/autres
}

fn expand_home_if_needed(p: PathBuf) -> PathBuf {
    // expansion minimale de "~/..." sur Unix sans dépendance
    if let Some(s) = p.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Ok(home) = env::var("HOME") {
                return Path::new(&home).join(rest);
            }
        }
    }
    p
}

#[cfg(feature = "config")]
fn approved_config_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd);
        v.push(Path::new(".").join("config")); // ./config
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        v.push(Path::new(&xdg).join("describe_me"));
    } else if let Ok(home) = env::var("HOME") {
        v.push(Path::new(&home).join(".config/describe_me"));
    }
    v.push(Path::new("/etc/describe_me").to_path_buf());
    v
}

#[cfg(feature = "config")]
fn path_is_inside(root: &Path, target: &Path) -> bool {
    // compare versions canonisées; si canonisation échoue, considère faux
    if let (Ok(r), Ok(t)) = (root.canonicalize(), target.canonicalize()) {
        t.starts_with(r)
    } else {
        false
    }
}

#[cfg(feature = "config")]
fn validate_config_path(p: &Path, allow_symlink: bool, allow_outside: bool) -> Result<PathBuf> {
    use std::fs;

    // 1) Expansion minimale ~/
    let p = expand_home_if_needed(p.to_path_buf());

    // 2) Lstat pour détecter symlink sans suivre
    let lmd =
        fs::symlink_metadata(&p).with_context(|| format!("read metadata: {}", p.display()))?;
    if lmd.file_type().is_symlink() && !allow_symlink {
        bail!("--config ne doit pas être un lien symbolique (utilisez --config-allow-symlink si vous assumez).");
    }

    // 3) Canonicalise (résout .. et symlinks) pour les contrôles suivants
    let canon = p
        .canonicalize()
        .with_context(|| format!("canonicalize: {}", p.display()))?;

    // 4) Fichier régulier + taille + permissions
    let md = fs::metadata(&canon)?;
    if !md.is_file() {
        bail!("--config doit pointer vers un fichier régulier.");
    }
    if md.len() > CONFIG_MAX_BYTES {
        bail!("fichier --config trop volumineux (> 1 MiB).");
    }
    #[cfg(unix)]
    {
        if is_world_writable(&md) {
            bail!("permissions faibles sur --config (writable par groupe/autres) — durcissez les droits.");
        }
    }

    // 5) Répertoires approuvés (protection anti-traversal/chemins inattendus)
    if !allow_outside {
        let roots = approved_config_roots();
        let inside = roots.iter().any(|r| path_is_inside(r, &canon));
        if !inside {
            bail!("--config en dehors des répertoires approuvés ({}) — utilisez --config-allow-outside si vous assumez.",
                  roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", "));
        }
    }

    Ok(canon)
}

#[cfg(feature = "web")]
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(feature = "web")]
fn validate_bind(addr: &SocketAddr, allow_remote: bool) -> Result<()> {
    if !is_loopback(addr.ip()) && !allow_remote {
        bail!(
            "refus d’écoute non locale: utilisez --web-allow-remote si vous assumez l’exposition."
        );
    }
    Ok(())
}

/* ==================== main ==================== */

fn main() -> Result<()> {
    let opts = Opts::parse();

    // Charge optionnellement la config avec vérifications
    #[cfg(feature = "config")]
    let cfg = if let Some(p) = &opts.config {
        let canon = validate_config_path(p, opts.config_allow_symlink, opts.config_allow_outside)?;
        Some(describe_me::load_config_from_path(&canon).context("chargement config TOML")?)
    } else {
        None
    };

    #[cfg(not(feature = "config"))]
    if opts.config.is_some() {
        bail!(
            "--config nécessite la feature `config` (cargo run --features \"cli systemd config\")."
        );
    }

    // --- Mode serveur web (SSE) --------------------------------------------
    #[cfg(not(feature = "web"))]
    if opts.web.is_some() {
        bail!("--web nécessite la feature `web` (cargo run --features \"cli web\").");
    }

    #[cfg(feature = "web")]
    if let Some(addr) = opts.web {
        // Mode safe: interdit toute exposition non locale, et interdit --web-allow-remote
        if opts.safe_defaults && opts.web_allow_remote {
            bail!("--safe-defaults actif : --web-allow-remote interdit.");
        }
        if opts.safe_defaults && !is_loopback(addr.ip()) {
            bail!("--safe-defaults actif : écoute limitée à 127.0.0.1/::1.");
        }

        // Si l’utilisateur a demandé 0.0.0.0 sans override explicite, on refuse
        validate_bind(&addr, opts.web_allow_remote)?;

        use std::time::Duration;
        let tick = Duration::from_secs(opts.web_interval_secs);

        #[cfg(feature = "config")]
        let cfg_for_web = cfg.clone();

        let web_debug = opts.web_debug;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            describe_me::serve_http(
                addr,
                tick,
                #[cfg(feature = "config")]
                cfg_for_web,
                web_debug,
            )
            .await
        })?;
        return Ok(());
    }
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "systemd"))]
    if opts.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    #[cfg(not(feature = "net"))]
    if opts.net_listen {
        bail!("--net-listen nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    // Capture le snapshot complet
    #[allow(unused_mut)]
    let mut snap = describe_me::SystemSnapshot::capture_with(describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true,
    })?;

    // Filtre les services si demandé (systemd + config)
    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = &cfg {
        snap.services_running =
            describe_me::filter_services(std::mem::take(&mut snap.services_running), cfg);
    }

    // Récupère les sockets si --net-listen
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

    // Sortie JSON unique
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
            println!("{}", serde_json::to_string_pretty(&snap)?);
            return Ok(());
        }
    }

    // --- Mode non-JSON (affichage humain) ----------------------------------

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

    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
