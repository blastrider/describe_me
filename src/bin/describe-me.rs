#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{ArgAction, Parser, ValueEnum};
#[cfg(feature = "net")]
use describe_me::domain::{ListeningSocket, NetworkInterfaceTraffic};
use describe_me::LogEvent;
#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;
use rand_core::OsRng;
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

    /// Affiche le trafic réseau agrégé par interface — nécessite la feature `net`
    #[arg(long = "net-traffic", action = ArgAction::SetTrue)]
    net_traffic: bool,

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

    /// Hash du jeton requis pour --web (Authorization: Bearer ou en-tête x-describe-me-token)
    #[arg(long = "web-token", value_name = "TOKEN")]
    web_token: Option<String>,

    /// IP ou réseaux autorisés pour --web (peut être répété, ex: 127.0.0.1, 10.0.0.0/16)
    #[arg(long = "web-allow-ip", value_name = "IP[/PREFIX]", action = ArgAction::Append)]
    web_allow_ip: Vec<String>,

    /// Origin autorisé pour l'interface web (peut être répété, ex: https://admin.example.com)
    #[arg(
        long = "web-allow-origin",
        value_name = "ORIGIN",
        action = ArgAction::Append
    )]
    web_allow_origin: Vec<String>,

    /// Proxy de confiance fournissant X-Forwarded-For (--web uniquement)
    #[arg(
        long = "web-trusted-proxy",
        value_name = "IP[/PREFIX]",
        action = ArgAction::Append
    )]
    web_trusted_proxy: Vec<String>,

    /// Génère un hash (Argon2id/bcrypt) pour configurer --web-token (helper)
    #[arg(
        long = "hash-web-token",
        value_name = "TOKEN",
        conflicts_with = "hash_web_token_stdin"
    )]
    hash_web_token: Option<String>,

    /// Lit le token depuis stdin et génère un hash (helper)
    #[arg(
        long = "hash-web-token-stdin",
        action = ArgAction::SetTrue,
        conflicts_with = "hash_web_token"
    )]
    hash_web_token_stdin: bool,

    /// Algorithme utilisé avec --hash-web-token (--hash-web-token-stdin)
    #[arg(
        long = "hash-web-token-alg",
        value_enum,
        default_value_t = TokenHashAlgorithm::Argon2id
    )]
    hash_web_token_alg: TokenHashAlgorithm,

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

    /// Expose le trafic réseau par interface dans le JSON
    #[arg(long = "expose-network-traffic", action = ArgAction::SetTrue)]
    expose_network_traffic: bool,

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

    /// Expose le trafic réseau par interface côté --web
    #[arg(long = "web-expose-network-traffic", action = ArgAction::SetTrue)]
    web_expose_network_traffic: bool,

    /// Expose le statut des mises à jour côté --web
    #[arg(long = "web-expose-updates", action = ArgAction::SetTrue)]
    web_expose_updates: bool,

    /// Active tous les détails sensibles pour --web
    #[arg(long = "web-expose-all", action = ArgAction::SetTrue)]
    web_expose_all: bool,

    /// Autorise l'application des drapeaux d'exposition sensibles depuis le fichier de configuration.
    #[arg(long = "allow-config-exposure", action = ArgAction::SetTrue)]
    allow_config_exposure: bool,

    /// Vérifications healthcheck (peut être répété). Ex:
    /// --check mem>90%[:warn|:crit]
    /// --check disk(/var)>80%[:warn|:crit]
    /// --check service=nginx.service:running[:warn|:crit]
    #[arg(long = "check", value_name = "EXPR", action = ArgAction::Append)]
    checks: Vec<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TokenHashAlgorithm {
    #[value(alias = "argon2")]
    Argon2id,
    Bcrypt,
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput<'a> {
    snapshot: &'a describe_me::SnapshotView,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_traffic: Option<&'a [NetworkInterfaceTraffic]>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<&'a [ListeningSocket]>,
}

#[cfg(feature = "cli")]
fn print_summary_line(view: &describe_me::SnapshotView) {
    println!("{}", summary_line(view));
}

fn summary_line(view: &describe_me::SnapshotView) -> String {
    let (pending, reboot) = match view.updates.as_ref() {
        Some(info) => (
            info.pending.to_string(),
            if info.reboot_required { "yes" } else { "no" },
        ),
        None => (String::from("?"), "unknown"),
    };
    format!("updates={pending} reboot={reboot}")
}

fn hash_web_token(token: &str, algorithm: TokenHashAlgorithm) -> Result<String> {
    match algorithm {
        TokenHashAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let params = Params::new(128 * 1024, 4, 1, None)
                .map_err(|err| anyhow!("argon2 params: {err}"))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let hash = argon2
                .hash_password(token.as_bytes(), &salt)
                .map_err(|err| anyhow!("argon2id: {err}"))?;
            Ok(hash.to_string())
        }
        TokenHashAlgorithm::Bcrypt => {
            let hash = bcrypt::hash(token, bcrypt::DEFAULT_COST)?;
            Ok(hash)
        }
    }
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

    if opts.hash_web_token.is_some() || opts.hash_web_token_stdin {
        let token = if let Some(value) = opts.hash_web_token.take() {
            value
        } else {
            use std::io::{self, Read};
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("lecture du token depuis stdin")?;
            buffer.trim_end_matches(&['\n', '\r'][..]).to_owned()
        };

        if token.is_empty() {
            bail!("Le token ne peut pas être vide.");
        }

        let hash = hash_web_token(&token, opts.hash_web_token_alg)?;
        println!("{hash}");
        return Ok(());
    }

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

    let mut allow_config_exposure = opts.allow_config_exposure;
    if !allow_config_exposure {
        if let Ok(value) = std::env::var("DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE") {
            if env_flag_enabled(&value) {
                allow_config_exposure = true;
            }
        }
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
                if opts.web_allow_origin.is_empty() && !cli.web_allow_origin.is_empty() {
                    opts.web_allow_origin = cli.web_allow_origin.clone();
                }
                if opts.web_trusted_proxy.is_empty() && !cli.web_trusted_proxy.is_empty() {
                    opts.web_trusted_proxy = cli.web_trusted_proxy.clone();
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
            if !web_cfg.allow_origins.is_empty() {
                web_access
                    .allow_origins
                    .extend(web_cfg.allow_origins.iter().cloned());
            }
            if !web_cfg.trusted_proxies.is_empty() {
                web_access
                    .trusted_proxies
                    .extend(web_cfg.trusted_proxies.iter().cloned());
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
        if !opts.web_allow_origin.is_empty() {
            web_access
                .allow_origins
                .extend(opts.web_allow_origin.iter().cloned());
        }
        if !opts.web_trusted_proxy.is_empty() {
            web_access
                .trusted_proxies
                .extend(opts.web_trusted_proxy.iter().cloned());
        }
    }

    #[cfg(feature = "config")]
    apply_cli_exposure_flags(&mut exposure, &opts, cfg.as_ref(), allow_config_exposure);
    #[cfg(not(feature = "config"))]
    apply_cli_exposure_flags(&mut exposure, &opts, allow_config_exposure);

    #[cfg(all(feature = "web", feature = "config"))]
    let web_exposure =
        apply_web_exposure_flags(exposure, &opts, cfg.as_ref(), allow_config_exposure);
    #[cfg(all(feature = "web", not(feature = "config")))]
    let web_exposure = apply_web_exposure_flags(exposure, &opts, allow_config_exposure);

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
        net_traffic: opts.net_traffic,
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

    #[cfg(not(feature = "net"))]
    if opts.net_traffic {
        bail!("--net-traffic nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    // Capture le snapshot complet
    let capture_opts = describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true, // on garde true pour un JSON complet
        with_listening_sockets: opts.net_listen || exposure.listening_sockets(),
        resolve_socket_processes: opts.net_listen || exposure.listening_sockets(),
        with_network_traffic: opts.net_traffic || exposure.network_traffic(),
        with_updates: true,
    };

    let (snap, snapshot_view) = describe_me::capture_snapshot_with_view(
        capture_opts,
        exposure,
        #[cfg(feature = "config")]
        cfg.as_ref(),
    )?;

    // Si JSON demandé: on ne sort qu'un seul document JSON combiné
    if opts.json || opts.pretty {
        #[cfg(feature = "cli")]
        {
            if opts.summary {
                print_summary_line(&snapshot_view);
            }
            let combined = CombinedOutput {
                snapshot: &snapshot_view,
                #[cfg(feature = "net")]
                net_traffic: snapshot_view.network_traffic.as_ref().map(|s| s.as_slice()),
                #[cfg(feature = "net")]
                net_listen: snapshot_view
                    .listening_sockets
                    .as_ref()
                    .map(|s| s.as_slice()),
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
            println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
            return Ok(());
        }
    }

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

    #[cfg(feature = "net")]
    if opts.net_traffic {
        println!(
            "{:<10} {:>14} {:>14} {:>12} {:>12} {:>13} {:>13}",
            "IFACE",
            "RX(bytes)",
            "TX(bytes)",
            "RX(pkts)",
            "TX(pkts)",
            "RX(err/drop)",
            "TX(err/drop)"
        );
        if let Some(traffic) = &snap.network_traffic {
            if traffic.is_empty() {
                println!("(aucune interface réseau observée)");
            } else {
                for entry in traffic.as_slice() {
                    println!(
                        "{:<10} {:>14} {:>14} {:>12} {:>12} {:>13} {:>13}",
                        entry.name,
                        entry.rx_bytes,
                        entry.tx_bytes,
                        entry.rx_packets,
                        entry.tx_packets,
                        format!("{}/{}", entry.rx_errors, entry.rx_dropped),
                        format!("{}/{}", entry.tx_errors, entry.tx_dropped),
                    );
                }
            }
        } else {
            println!("(trafic reseau non capture)");
        }
        println!();
    }

    // 3) DISKS — affichage humain (optionnel)
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

#[cfg(feature = "config")]
fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    opts: &Opts,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) {
    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(cfg_exp) = cfg.exposure.as_ref() {
                exposure.merge(describe_me::Exposure::from(cfg_exp));
            }
        }
    }
    apply_cli_flags(exposure, opts);
}

#[cfg(not(feature = "config"))]
fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    opts: &Opts,
    _allow_config_exposure: bool,
) {
    apply_cli_flags(exposure, opts);
}

fn apply_cli_flags(exposure: &mut describe_me::Exposure, opts: &Opts) {
    if opts.expose_all {
        *exposure = describe_me::Exposure::all();
    } else {
        if opts.expose_hostname {
            exposure.set_hostname(true);
        }
        if opts.expose_os {
            exposure.set_os(true);
        }
        if opts.expose_kernel {
            exposure.set_kernel(true);
        }
        if opts.expose_services {
            exposure.set_services(true);
        }
        if opts.expose_disk_partitions {
            exposure.set_disk_partitions(true);
        }
        if opts.expose_network_traffic {
            exposure.set_network_traffic(true);
        }
        if opts.expose_updates {
            exposure.set_updates(true);
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }

    if opts.net_listen {
        exposure.set_listening_sockets(true);
    }
    if opts.net_traffic {
        exposure.set_network_traffic(true);
    }
}

#[cfg(all(feature = "web", feature = "config"))]
fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    opts: &Opts,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut web_exposure = exposure;

    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(web_cfg) = cfg.web.as_ref() {
                if let Some(web_exp) = web_cfg.exposure.as_ref() {
                    web_exposure.merge(describe_me::Exposure::from(web_exp));
                }
            }
        }
    }

    apply_web_flags(&mut web_exposure, opts);
    web_exposure
}

#[cfg(all(feature = "web", not(feature = "config")))]
fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    opts: &Opts,
    _allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut web_exposure = exposure;
    apply_web_flags(&mut web_exposure, opts);
    web_exposure
}

#[cfg(feature = "web")]
fn apply_web_flags(exposure: &mut describe_me::Exposure, opts: &Opts) {
    if opts.web_expose_all {
        *exposure = describe_me::Exposure::all();
    } else {
        if opts.web_expose_hostname {
            exposure.set_hostname(true);
        }
        if opts.web_expose_os {
            exposure.set_os(true);
        }
        if opts.web_expose_kernel {
            exposure.set_kernel(true);
        }
        if opts.web_expose_services {
            exposure.set_services(true);
        }
        if opts.web_expose_disk_partitions {
            exposure.set_disk_partitions(true);
        }
        if opts.web_expose_network_traffic {
            exposure.set_network_traffic(true);
        }
        if opts.web_expose_updates {
            exposure.set_updates(true);
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }
}

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_expose_updates_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-updates"]).unwrap();
        assert!(opts.expose_updates);
        assert!(!opts.web_expose_updates);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-updates"]).unwrap();
        assert!(!opts.expose_updates);
        assert!(opts.web_expose_updates);
    }

    #[test]
    fn parses_expose_network_traffic_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-network-traffic"]).unwrap();
        assert!(opts.expose_network_traffic);
        assert!(!opts.web_expose_network_traffic);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-network-traffic"]).unwrap();
        assert!(!opts.expose_network_traffic);
        assert!(opts.web_expose_network_traffic);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_uses_updates_info() {
        let snapshot = describe_me::SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: describe_me::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            updates: Some(describe_me::UpdatesInfo {
                pending: 5,
                reboot_required: true,
                packages: None,
            }),
        };
        let mut exposure = describe_me::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=5 reboot=yes");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_handles_missing_updates() {
        let snapshot = describe_me::SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: describe_me::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            updates: None,
        };
        let mut exposure = describe_me::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=? reboot=unknown");
    }

    #[test]
    fn argon2_hash_uses_hardened_params() {
        let hash =
            super::hash_web_token("secret", super::TokenHashAlgorithm::Argon2id).expect("hash");
        assert!(
            hash.contains("m=131072"),
            "expected Argon2 memory cost 131072, got {hash}"
        );
        assert!(
            hash.contains("t=4"),
            "expected Argon2 iteration count 4, got {hash}"
        );
    }
}
