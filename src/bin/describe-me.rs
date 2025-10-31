#![forbid(unsafe_code)]

use anyhow::{bail, Result};
use clap::{ArgAction, Parser};
#[cfg(feature = "net")]
use describe_me::domain::ListeningSocket;
use describe_me::LogEvent;
#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;
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

    /// Affiche un résumé concis sur une ligne (ex: updates=3 reboot=no)
    #[arg(long, action = ArgAction::SetTrue)]
    summary: bool,

    /// Lance un serveur web SSE (HTML/CSS/JS) — nécessite la feature `web`.
    /// Optionnellement préciser l'adresse:port (ex: 127.0.0.1:9000). Par défaut: 127.0.0.1:8080.
    #[arg(
        long = "web",
        value_name = "ADDR:PORT",
        default_missing_value = "127.0.0.1:8080",
        num_args = 0..=1
    )]
    web: Option<String>,

    /// Intervalle d'actualisation (secondes) pour le mode --web (défaut: 2)
    #[arg(long = "web-interval", value_name = "SECS", default_value_t = 2)]
    web_interval_secs: u64,

    /// Affiche également le JSON brut dans l'interface --web
    #[arg(long = "web-debug", action = ArgAction::SetTrue)]
    web_debug: bool,

    /// Jeton d'accès requis pour --web (Authorization: Bearer ou en-tête x-describe-me-token)
    #[arg(long = "web-token", value_name = "TOKEN")]
    web_token: Option<String>,

    /// IP ou réseaux autorisés pour --web (peut être répété, ex: 127.0.0.1, 10.0.0.0/16)
    #[arg(long = "web-allow-ip", value_name = "IP[/PREFIX]", action = ArgAction::Append)]
    web_allow_ip: Vec<String>,

    /// Expose le hostname exact dans le JSON (opt-in, sinon masqué)
    #[arg(long = "expose-hostname", action = ArgAction::SetTrue)]
    expose_hostname: bool,

    /// Expose la version complète de l'OS dans le JSON
    #[arg(long = "expose-os", action = ArgAction::SetTrue)]
    expose_os: bool,

    /// Expose la version complète du noyau dans le JSON
    #[arg(long = "expose-kernel", action = ArgAction::SetTrue)]
    expose_kernel: bool,

    /// Expose la liste détaillée des services dans le JSON
    #[arg(long = "expose-services", action = ArgAction::SetTrue)]
    expose_services: bool,

    /// Expose le détail des partitions disque (points de montage, etc.)
    #[arg(long = "expose-disk-partitions", action = ArgAction::SetTrue)]
    expose_disk_partitions: bool,

    /// Expose le statut des mises à jour (nombre, reboot requis)
    #[arg(long = "expose-updates", action = ArgAction::SetTrue)]
    expose_updates: bool,

    /// Désactive le mode redacted (versions OS/noyau tronquées par défaut).
    #[arg(long = "no-redacted", action = ArgAction::SetTrue)]
    no_redacted: bool,

    /// Active tous les champs sensibles d'un coup (hostname, kernel, services...)
    #[arg(long = "expose-all", action = ArgAction::SetTrue)]
    expose_all: bool,

    /// Expose le hostname côté --web (sinon masqué par défaut)
    #[arg(long = "web-expose-hostname", action = ArgAction::SetTrue)]
    web_expose_hostname: bool,

    /// Expose la version complète de l'OS côté --web
    #[arg(long = "web-expose-os", action = ArgAction::SetTrue)]
    web_expose_os: bool,

    /// Expose la version complète du noyau côté --web
    #[arg(long = "web-expose-kernel", action = ArgAction::SetTrue)]
    web_expose_kernel: bool,

    /// Expose la liste détaillée des services côté --web
    #[arg(long = "web-expose-services", action = ArgAction::SetTrue)]
    web_expose_services: bool,

    /// Expose les partitions disque détaillées côté --web
    #[arg(long = "web-expose-disk-partitions", action = ArgAction::SetTrue)]
    web_expose_disk_partitions: bool,

    /// Expose le statut des mises à jour côté --web
    #[arg(long = "web-expose-updates", action = ArgAction::SetTrue)]
    web_expose_updates: bool,

    /// Active tous les détails sensibles pour --web
    #[arg(long = "web-expose-all", action = ArgAction::SetTrue)]
    web_expose_all: bool,

    /// Vérifications healthcheck (peut être répété). Ex:
    /// --check mem>90%[:warn|:crit]
    /// --check disk(/var)>80%[:warn|:crit]
    /// --check service=nginx.service:running[:warn|:crit]
    #[arg(long = "check", value_name = "EXPR", action = ArgAction::Append)]
    checks: Vec<String>,
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput<'a> {
    snapshot: &'a describe_me::SnapshotView,
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<&'a [ListeningSocket]>,
}

#[cfg(feature = "cli")]
fn print_summary_line(view: &describe_me::SnapshotView) {
    let (pending, reboot) = match view.updates.as_ref() {
        Some(info) => (
            info.pending.to_string(),
            if info.reboot_required { "yes" } else { "no" },
        ),
        None => (String::from("?"), "unknown"),
    };
    println!("updates={pending} reboot={reboot}");
}

#[cfg(unix)]
fn ensure_not_root() -> Result<()> {
    if Uid::current().is_root() {
        bail!(
            "describe-me refuse de tourner en root (UID 0). Lance-le sous un utilisateur non privilégié."
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_not_root() -> Result<()> {
    Ok(())
}

fn main() -> Result<()> {
    let mut opts = Opts::parse();

    // Charge optionnellement la config (pour filtrages, web, ...)
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

    #[cfg(feature = "config")]
    if let Some(cfg) = &cfg {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(value) = runtime.rust_log.as_ref() {
                if std::env::var_os("RUST_LOG").is_none() {
                    std::env::set_var("RUST_LOG", value);
                }
            }
            if let Some(cli) = runtime.cli.as_ref() {
                if opts.web.is_none() {
                    opts.web = cli.web.clone();
                }
                if !opts.with_services {
                    if let Some(true) = cli.with_services {
                        opts.with_services = true;
                    }
                }
                if !opts.web_expose_all {
                    if let Some(true) = cli.web_expose_all {
                        opts.web_expose_all = true;
                    }
                }
                if opts.web_allow_ip.is_empty() && !cli.web_allow_ip.is_empty() {
                    opts.web_allow_ip = cli.web_allow_ip.clone();
                }
            }
        }
    }

    describe_me::init_logging();

    ensure_not_root()?;

    #[cfg(feature = "web")]
    let web_debug = opts.web_debug;

    #[cfg(feature = "web")]
    let mut web_access = describe_me::WebAccess::default();

    let mut exposure = describe_me::Exposure::default();

    #[cfg(all(feature = "web", feature = "config"))]
    if let Some(cfg) = &cfg {
        if let Some(web_cfg) = &cfg.web {
            if let Some(token) = web_cfg.token.as_ref() {
                web_access.token = Some(token.clone());
            }
            if !web_cfg.allow_ips.is_empty() {
                web_access
                    .allow_ips
                    .extend(web_cfg.allow_ips.iter().cloned());
            }
        }
    }

    #[cfg(feature = "web")]
    {
        if let Some(token) = &opts.web_token {
            web_access.token = Some(token.clone());
        }
        if !opts.web_allow_ip.is_empty() {
            web_access
                .allow_ips
                .extend(opts.web_allow_ip.iter().cloned());
        }
    }

    #[cfg(feature = "config")]
    if let Some(cfg) = &cfg {
        if let Some(cfg_exp) = cfg.exposure.as_ref() {
            exposure.merge(describe_me::Exposure::from(cfg_exp));
        }
    }

    if opts.expose_all {
        exposure = describe_me::Exposure::all();
    } else {
        if opts.expose_hostname {
            exposure.hostname = true;
        }
        if opts.expose_os {
            exposure.os = true;
        }
        if opts.expose_kernel {
            exposure.kernel = true;
        }
        if opts.expose_services {
            exposure.services = true;
        }
        if opts.expose_disk_partitions {
            exposure.disk_partitions = true;
        }
        if opts.expose_updates {
            exposure.updates = true;
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }

    exposure.listening_sockets |= opts.net_listen;

    #[cfg(feature = "web")]
    let mut web_exposure = exposure;

    #[cfg(all(feature = "web", feature = "config"))]
    if let Some(cfg) = &cfg {
        if let Some(web_cfg) = &cfg.web {
            if let Some(web_exp) = web_cfg.exposure.as_ref() {
                web_exposure.merge(describe_me::Exposure::from(web_exp));
            }
        }
    }

    #[cfg(feature = "web")]
    if opts.web_expose_all {
        web_exposure = describe_me::Exposure::all();
    } else {
        if opts.web_expose_hostname {
            web_exposure.hostname = true;
        }
        if opts.web_expose_os {
            web_exposure.os = true;
        }
        if opts.web_expose_kernel {
            web_exposure.kernel = true;
        }
        if opts.web_expose_services {
            web_exposure.services = true;
        }
        if opts.web_expose_disk_partitions {
            web_exposure.disk_partitions = true;
        }
        if opts.web_expose_updates {
            web_exposure.updates = true;
        }
    }

    #[cfg(feature = "web")]
    if opts.no_redacted {
        web_exposure.redacted = false;
    }

    #[cfg(feature = "web")]
    {
        web_exposure.listening_sockets |= exposure.listening_sockets;
        web_exposure.updates |= exposure.updates;
    }

    let exposure_all_effective = exposure.is_all();

    #[cfg(feature = "web")]
    let web_expose_all_effective = web_exposure.is_all();
    #[cfg(not(feature = "web"))]
    let web_expose_all_effective = false;

    let mode = if opts.web.is_some() {
        "web"
    } else if opts.pretty {
        "json_pretty"
    } else if opts.json {
        "json"
    } else {
        "cli"
    };

    LogEvent::Startup {
        mode: mode.into(),
        with_services: opts.with_services,
        net_listen: opts.net_listen,
        expose_all: exposure_all_effective,
        web_expose_all: web_expose_all_effective,
        checks: &opts.checks,
    }
    .emit();

    // --- Mode serveur web (SSE) --------------------------------------------
    #[cfg(not(feature = "web"))]
    if opts.web.is_some() {
        bail!("--web nécessite la feature `web` (cargo run --features \"cli web\").");
    }

    #[cfg(feature = "web")]
    if let Some(bind) = &opts.web {
        use std::{net::SocketAddr, time::Duration};

        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("Adresse invalide pour --web: {bind} ({e})"))?;
        let tick = Duration::from_secs(opts.web_interval_secs);

        if web_access.token.is_none() && web_access.allow_ips.is_empty() {
            bail!(
                "--web nécessite la configuration d'un contrôle d'accès (--web-token, --web-allow-ip ou [web] dans la config)."
            );
        }

        #[cfg(feature = "config")]
        let cfg_for_web = cfg.clone();

        let access = web_access;
        let exposure_for_web = web_exposure;

        // runtime tokio local pour ne pas imposer #[tokio::main]
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
                access,
                exposure_for_web,
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
        with_disk_usage: true, // on garde true pour un JSON complet
        with_listening_sockets: opts.net_listen || exposure.listening_sockets,
    })?;

    // Filtre les services si demandé (systemd + config)
    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = &cfg {
        let services_mut = snap.services_running.make_mut();
        let filtered = describe_me::filter_services(std::mem::take(services_mut), cfg);
        *services_mut = filtered;
    }

    // Si JSON demandé: on ne sort qu'un seul document JSON combiné
    if opts.json || opts.pretty {
        #[cfg(feature = "cli")]
        {
            let snapshot_view = describe_me::SnapshotView::new(&snap, exposure);
            if opts.summary {
                print_summary_line(&snapshot_view);
            }
            let combined = CombinedOutput {
                snapshot: &snapshot_view,
                #[cfg(feature = "net")]
                net_listen: snapshot_view
                    .listening_sockets
                    .as_ref()
                    .map(|s| s.as_slice()),
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
            let snapshot_view = describe_me::SnapshotView::new(&snap, exposure);
            println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
            return Ok(());
        }
    }

    let snapshot_view = describe_me::SnapshotView::new(&snap, exposure);

    if opts.summary {
        print_summary_line(&snapshot_view);
    }

    // --- Mode non-JSON (comportement existant + snapshot JSON à la fin) ---

    // 1) NET — tableau lisible
    #[cfg(feature = "net")]
    if opts.net_listen {
        if opts.show_process {
            println!(
                "{:<5} {:<15} {:<6} {:<8} {:<}",
                "PROTO", "ADDR", "PORT", "PID", "PROCESS"
            );
        } else {
            println!("{:<5} {:<15} {:<6}", "PROTO", "ADDR", "PORT");
        }

        if let Some(list) = snapshot_view.listening_sockets.as_ref() {
            let slice = list.as_slice();
            if slice.is_empty() {
                println!("(aucune socket d’écoute trouvée)");
            } else {
                for s in slice {
                    if opts.show_process {
                        let pid = s
                            .process
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        let name = s.process_name.as_deref().unwrap_or("?");
                        println!(
                            "{:<5} {:<15} {:<6} {:<8} {}",
                            s.proto, s.addr, s.port, pid, name
                        );
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
            for p in du.partitions.as_slice() {
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
    println!("{}", serde_json::to_string_pretty(&snapshot_view)?);

    // --- HEALTHCHECK --------------------------------------------------------
    if !opts.checks.is_empty() {
        // On parse TOUTES les expressions d'abord (fail-fast si invalide)
        let mut parsed = Vec::with_capacity(opts.checks.len());
        for e in &opts.checks {
            match describe_me::parse_check(e) {
                Ok(c) => parsed.push(c),
                Err(err) => {
                    eprintln!("[CHECK] parse error pour '{e}': {err}");
                    std::process::exit(2); // parse error => CRIT
                }
            }
        }

        // Évalue sur le snapshot complet
        match describe_me::eval_checks(&snap, &parsed) {
            Ok((max_sev, results)) => {
                for r in results {
                    // message humain lisible sur stderr
                    eprintln!("[CHECK] {}", r.message);
                }
                let code = max_sev as i32; // 0/1/2
                std::process::exit(code);
            }
            Err(err) => {
                eprintln!("[CHECK] evaluation error: {err}");
                std::process::exit(2); // erreur d’éval => CRIT
            }
        }
    }

    Ok(())
    // ------------------------------------------------------------------------
}
