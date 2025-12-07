use super::{cmd_history, cmd_logs, cmd_metadata, cmd_plugin};
use anyhow::{bail, Result};
#[cfg(feature = "net")]
use describe_me_lib::domain::{ListeningSocket, NetworkInterfaceTraffic};
use describe_me_lib::{
    paginate_slice, AppContext, HistoryMode, HistoryProfile, HistorySettings, LogEvent, PageRequest,
};
#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;
#[cfg(feature = "cli")]
use serde::Serialize;

#[cfg(feature = "web")]
use super::allowlists::{resolve_web_list, CliListOrigin};
use super::args::{
    self, hash_web_token, read_token_from_stdin, CliCommand, CliConfig, HistoryProfileArg,
    HistorySelection, OutputFormat, WebTokenSource,
};
use super::exposure::apply_cli_exposure_flags;
#[cfg(feature = "web")]
use super::exposure::apply_web_exposure_flags;

const SERVICES_PAGE_MAX: usize = 500;
const SOCKETS_PAGE_MAX: usize = 500;

pub type Cli = CliConfig;

pub fn parse() -> Result<Cli> {
    Ok(args::parse())
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput<'a> {
    snapshot: &'a describe_me_lib::SnapshotView,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_traffic: Option<&'a [NetworkInterfaceTraffic]>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<&'a [ListeningSocket]>,
}

#[cfg(feature = "cli")]
fn print_summary_line(view: &describe_me_lib::SnapshotView) {
    println!("{}", summary_line(view));
}

fn summary_line(view: &describe_me_lib::SnapshotView) -> String {
    let (pending, reboot) = match view.updates.as_ref() {
        Some(info) => (
            info.pending.to_string(),
            if info.reboot_required { "yes" } else { "no" },
        ),
        None => (String::from("?"), "unknown"),
    };
    let containers = view
        .containers
        .as_ref()
        .and_then(|c| c.summary.as_ref())
        .map(|s| format!(" containers={}/{}", s.running, s.total))
        .unwrap_or_default();
    format!("updates={pending} reboot={reboot}{containers}")
}

fn handle_command(cmd: CliCommand, ctx: &AppContext) -> Result<()> {
    match cmd {
        CliCommand::Metadata(metadata) => cmd_metadata::handle_metadata_command(metadata, ctx),
        CliCommand::Plugin(plugin) => cmd_plugin::handle_plugin_command(plugin),
        CliCommand::History(history) => cmd_history::handle_history_command(history, ctx),
        CliCommand::Logs(logs) => cmd_logs::handle_logs_command(logs),
    }
}

fn print_page_hint(total: usize, offset: usize, limit: usize, displayed: usize) {
    if total == 0 || displayed == 0 {
        return;
    }
    if total <= displayed && offset == 0 {
        return;
    }
    let start = offset + 1;
    let end = offset + displayed;
    let page_idx = offset / limit + 1;
    let total_pages = total.div_ceil(limit);
    println!(
        "(page {}/{} — entrées {}-{} sur {})",
        page_idx, total_pages, start, end, total
    );
}

#[cfg(feature = "systemd")]
fn print_services_cli(view: &describe_me_lib::SnapshotView, limit: Option<usize>, offset: usize) {
    println!("{:<38} {:<14} INFO", "SERVICE", "STATUT");

    if let Some(list) = view.services_running.as_ref() {
        let services = list.as_slice();
        if services.is_empty() {
            println!("(aucun service actif rapporté)");
            println!();
            return;
        }

        let fallback_limit = services.len().clamp(1, SERVICES_PAGE_MAX);
        let page = paginate_slice(
            services,
            PageRequest {
                offset,
                limit: limit.unwrap_or(fallback_limit),
            },
            SERVICES_PAGE_MAX,
        );

        for svc in &page.items {
            let summary = svc.summary.as_deref().unwrap_or("");
            if summary.is_empty() {
                println!("{:<38} {:<14}", svc.name, svc.state);
            } else {
                println!("{:<38} {:<14} {}", svc.name, svc.state, summary);
            }
        }
        print_page_hint(page.total, page.offset, page.limit, page.items.len());
    } else if let Some(summary) = view.services_summary.as_ref() {
        println!("{} service(s) observé(s)", summary.total);
        if !summary.by_state.is_empty() {
            let joined = summary
                .by_state
                .iter()
                .map(|item| format!("{}: {}", item.state, item.count))
                .collect::<Vec<_>>()
                .join(" • ");
            println!("Répartition: {joined}");
        }
    } else {
        println!("(services non exposés)");
    }
    println!();
}

fn print_containers_cli(view: &describe_me_lib::SnapshotView) {
    println!(
        "{:<24} {:<10} {:<12} {:<18} IMAGE",
        "CONTAINER", "RUNTIME", "STATE", "IP"
    );

    match view.containers.as_ref() {
        None => {
            println!("(conteneurs non capturés ou non exposés)");
        }
        Some(snapshot) => {
            if let Some(summary) = snapshot.summary.as_ref() {
                println!("Total: {} (running: {})", summary.total, summary.running);
            }
            match snapshot.containers.as_ref() {
                Some(list) => {
                    let containers = list.as_slice();
                    if containers.is_empty() {
                        println!("(aucun conteneur)");
                    } else {
                        for c in containers {
                            let ip = c.ip.as_deref().unwrap_or("-");
                            let image = c.image.as_deref().unwrap_or("-");
                            println!(
                                "{:<24} {:<10} {:<12} {:<18} {}",
                                c.name, c.runtime, c.state, ip, image
                            );
                        }
                    }
                }
                None => {
                    println!("(détails conteneurs non exposés)");
                }
            }
        }
    }
    println!();
}

#[cfg(feature = "net")]
fn print_sockets_cli(
    sockets: &[ListeningSocket],
    show_process: bool,
    limit: Option<usize>,
    offset: usize,
) {
    if show_process {
        println!(
            "{:<5} {:<15} {:<6} {:<8} {:<}",
            "PROTO", "ADDR", "PORT", "PID", "PROCESS"
        );
    } else {
        println!("{:<5} {:<15} {:<6}", "PROTO", "ADDR", "PORT");
    }

    if sockets.is_empty() {
        println!("(aucune socket d’écoute trouvée)");
        println!();
        return;
    }

    let fallback_limit = sockets.len().clamp(1, SOCKETS_PAGE_MAX);
    let page = paginate_slice(
        sockets,
        PageRequest {
            offset,
            limit: limit.unwrap_or(fallback_limit),
        },
        SOCKETS_PAGE_MAX,
    );

    for s in &page.items {
        if show_process {
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
    print_page_hint(page.total, page.offset, page.limit, page.items.len());
    println!();
}

fn print_description_block(desc: &str) {
    if desc.contains('\n') {
        println!("Description :");
        for line in desc.lines() {
            if line.is_empty() {
                println!();
            } else {
                println!("  {line}");
            }
        }
    } else {
        println!("Description : {desc}");
    }
}

fn print_tags_line(tags: &[String]) {
    if tags.is_empty() {
        return;
    }
    println!("Tags : {}", tags.join(", "));
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

pub fn run(mut cli: Cli) -> Result<()> {
    if let Some(hash_req) = cli.web.hash_request() {
        let token = match hash_req.source {
            WebTokenSource::Literal(value) => value,
            WebTokenSource::Stdin => read_token_from_stdin()?,
        };

        if token.is_empty() {
            bail!("Le token ne peut pas être vide.");
        }

        let hash = hash_web_token(&token, hash_req.algorithm)?;
        println!("{hash}");
        return Ok(());
    }

    // Charge optionnellement la config (pour filtrages, web, ...)
    #[cfg(feature = "config")]
    let cfg = if let Some(p) = &cli.config_path {
        Some(describe_me_lib::load_config_from_path(p)?)
    } else {
        None
    };

    #[cfg(not(feature = "config"))]
    if cli.config_path.is_some() {
        bail!(
            "--config nécessite la feature `config` (cargo run --features \"cli systemd config\")."
        );
    }

    #[cfg(feature = "config")]
    if let Some(cfg) = &cfg {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(state_dir) = runtime.state_dir.as_deref() {
                describe_me_lib::override_state_directory(state_dir);
            }
        }
    }

    let ctx = AppContext::new_default()?;

    if let Some(cmd) = cli.command.take() {
        return handle_command(cmd, &ctx);
    }

    let mut allow_config_exposure = cli.allow_config_exposure;
    if !allow_config_exposure {
        if let Ok(value) = std::env::var("DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE") {
            if env_flag_enabled(&value) {
                allow_config_exposure = true;
            }
        }
    }

    #[cfg(feature = "web")]
    let mut web_allow_ip_source = CliListOrigin::from_values(&cli.web.allow_ip);
    #[cfg(feature = "web")]
    let mut web_allow_origin_source = CliListOrigin::from_values(&cli.web.allow_origin);
    #[cfg(feature = "web")]
    let mut web_trusted_proxy_source = CliListOrigin::from_values(&cli.web.trusted_proxy);

    #[cfg(feature = "config")]
    if let Some(cfg) = &cfg {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(value) = runtime.rust_log.as_ref() {
                if std::env::var_os("RUST_LOG").is_none() {
                    std::env::set_var("RUST_LOG", value);
                }
            }
            if let Some(cli_defaults) = runtime.cli.as_ref() {
                if cli.web.bind.is_none() {
                    cli.web.bind = cli_defaults.web.clone();
                }
                if !cli.capture.with_services {
                    if let Some(true) = cli_defaults.with_services {
                        cli.capture.with_services = true;
                    }
                }
                if !cli.capture.with_containers {
                    if let Some(true) = cli_defaults.with_containers {
                        cli.capture.with_containers = true;
                    }
                }
                if !cli.web_exposure.expose_all {
                    if let Some(true) = cli_defaults.web_expose_all {
                        cli.web_exposure.expose_all = true;
                    }
                }
                if cli.web.allow_ip.is_empty() && !cli_defaults.web_allow_ip.is_empty() {
                    cli.web.allow_ip = cli_defaults.web_allow_ip.clone();
                    #[cfg(feature = "web")]
                    {
                        web_allow_ip_source = CliListOrigin::RuntimeDefault;
                    }
                }
                if cli.web.allow_origin.is_empty() && !cli_defaults.web_allow_origin.is_empty() {
                    cli.web.allow_origin = cli_defaults.web_allow_origin.clone();
                    #[cfg(feature = "web")]
                    {
                        web_allow_origin_source = CliListOrigin::RuntimeDefault;
                    }
                }
                if cli.web.trusted_proxy.is_empty() && !cli_defaults.web_trusted_proxy.is_empty() {
                    cli.web.trusted_proxy = cli_defaults.web_trusted_proxy.clone();
                    #[cfg(feature = "web")]
                    {
                        web_trusted_proxy_source = CliListOrigin::RuntimeDefault;
                    }
                }
            }
        }
    }

    describe_me_lib::init_logging();

    ensure_not_root()?;

    #[cfg(feature = "web")]
    let web_debug = cli.web.debug;

    #[cfg(feature = "web")]
    let mut web_access = describe_me_lib::WebAccess::default();

    let mut exposure = describe_me_lib::Exposure::default();

    let mut history_settings = HistorySettings::disabled();

    #[cfg(feature = "config")]
    if let Some(cfg) = cfg.as_ref() {
        if let Some(history_cfg) = cfg.history.as_ref() {
            if history_cfg.enabled {
                let mut profile = history_cfg.profile.unwrap_or(HistoryProfile::Default);
                if history_cfg.paranoid {
                    profile = HistoryProfile::Paranoid;
                }
                history_settings = HistorySettings::for_profile(profile);
                if let Some(retention) = history_cfg.retention_points {
                    history_settings.set_retention_points(retention);
                }
                if let Some(max_window) = history_cfg.max_window_seconds {
                    history_settings.max_window_seconds = max_window;
                }
                if let Some(rounding) = history_cfg.rounding_seconds {
                    history_settings.rounding_seconds = rounding;
                }
                if history_cfg.in_memory_only {
                    history_settings.set_mode(HistoryMode::InMemory);
                }
            }
        }
    }

    match cli.history.selection() {
        HistorySelection::Disabled => history_settings.disable(),
        HistorySelection::Profile(profile) => {
            let resolved = match profile {
                HistoryProfileArg::Default => HistoryProfile::Default,
                HistoryProfileArg::Ops => HistoryProfile::Ops,
                HistoryProfileArg::Paranoid => HistoryProfile::Paranoid,
            };
            history_settings = HistorySettings::for_profile(resolved);
        }
        HistorySelection::ConfigOrDefault => {}
    }

    if let Some(retention) = cli.history.retention {
        history_settings.set_retention_points(retention);
    }

    ctx.history().configure(history_settings)?;

    #[cfg(all(feature = "web", feature = "config"))]
    let web_cfg = cfg.as_ref().and_then(|cfg| cfg.web.as_ref());

    #[cfg(all(feature = "web", feature = "config"))]
    if let Some(web_cfg) = web_cfg {
        if let Some(token) = web_cfg.token.as_ref() {
            web_access.token = Some(token.clone());
        }
        if let Some(tls_cfg) = web_cfg.tls.as_ref() {
            if !tls_cfg.cert_path.is_empty() && !tls_cfg.key_path.is_empty() {
                web_access.tls = Some(describe_me_lib::WebTlsConfig {
                    cert_path: tls_cfg.cert_path.clone(),
                    key_path: tls_cfg.key_path.clone(),
                });
            }
        }
        if web_cfg.dev_insecure_session_cookie {
            web_access.session_cookie_secure = false;
        }
    }

    #[cfg(feature = "web")]
    {
        if let Some(token) = &cli.web.token {
            web_access.token = Some(token.clone());
        }
        #[cfg(feature = "config")]
        let config_allow_ips = web_cfg.map(|cfg| cfg.allow_ips.as_slice());
        #[cfg(not(feature = "config"))]
        let config_allow_ips: Option<&[String]> = None;

        #[cfg(feature = "config")]
        let config_allow_origins = web_cfg.map(|cfg| cfg.allow_origins.as_slice());
        #[cfg(not(feature = "config"))]
        let config_allow_origins: Option<&[String]> = None;

        #[cfg(feature = "config")]
        let config_trusted_proxies = web_cfg.map(|cfg| cfg.trusted_proxies.as_slice());
        #[cfg(not(feature = "config"))]
        let config_trusted_proxies: Option<&[String]> = None;

        web_access.allow_ips = resolve_web_list(
            web_allow_ip_source.cli_slice(&cli.web.allow_ip),
            config_allow_ips,
            web_allow_ip_source.runtime_slice(&cli.web.allow_ip),
        );
        web_access.allow_origins = resolve_web_list(
            web_allow_origin_source.cli_slice(&cli.web.allow_origin),
            config_allow_origins,
            web_allow_origin_source.runtime_slice(&cli.web.allow_origin),
        );
        web_access.trusted_proxies = resolve_web_list(
            web_trusted_proxy_source.cli_slice(&cli.web.trusted_proxy),
            config_trusted_proxies,
            web_trusted_proxy_source.runtime_slice(&cli.web.trusted_proxy),
        );

        if cli.web.dev_mode {
            web_access.session_cookie_secure = false;
        }
    }

    #[cfg(feature = "config")]
    apply_cli_exposure_flags(&mut exposure, &cli, cfg.as_ref(), allow_config_exposure);
    #[cfg(not(feature = "config"))]
    apply_cli_exposure_flags(&mut exposure, &cli, allow_config_exposure);

    #[cfg(all(feature = "web", feature = "config"))]
    let web_exposure =
        apply_web_exposure_flags(exposure, &cli, cfg.as_ref(), allow_config_exposure);
    #[cfg(all(feature = "web", not(feature = "config")))]
    let web_exposure = apply_web_exposure_flags(exposure, &cli, allow_config_exposure);

    let exposure_all_effective = exposure.is_all();

    #[cfg(feature = "web")]
    let web_expose_all_effective = web_exposure.is_all();
    #[cfg(not(feature = "web"))]
    let web_expose_all_effective = false;
    let with_containers_effective =
        cli.capture.with_containers || cli.capture.containers || exposure.containers_summary();

    let mode = if cli.web.bind.is_some() {
        "web"
    } else {
        match cli.output.format() {
            OutputFormat::JsonPretty => "json_pretty",
            OutputFormat::Json => "json",
            OutputFormat::Cli => "cli",
        }
    };

    LogEvent::Startup {
        mode: mode.into(),
        with_services: cli.capture.with_services,
        with_containers: with_containers_effective,
        net_listen: cli.capture.net_listen,
        net_traffic: cli.capture.net_traffic,
        expose_all: exposure_all_effective,
        web_expose_all: web_expose_all_effective,
        checks: &cli.checks,
    }
    .emit();

    // --- Mode serveur web (SSE) --------------------------------------------
    #[cfg(not(feature = "web"))]
    if cli.web.bind.is_some() {
        bail!("--web nécessite la feature `web` (cargo run --features \"cli web\").");
    }

    #[cfg(feature = "web")]
    if let Some(bind) = &cli.web.bind {
        use std::{net::SocketAddr, time::Duration};

        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("Adresse invalide pour --web: {bind} ({e})"))?;
        let tick = Duration::from_secs(cli.web.interval_secs);

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
            describe_me_lib::serve_http(
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
    if cli.capture.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    #[cfg(not(feature = "net"))]
    if cli.capture.net_listen {
        bail!("--net-listen nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    #[cfg(not(feature = "net"))]
    if cli.capture.net_traffic {
        bail!("--net-traffic nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    // Capture le snapshot complet
    let capture_opts = describe_me_lib::CaptureOptions {
        with_services: cli.capture.with_services,
        with_disk_usage: true, // on garde true pour un JSON complet
        with_listening_sockets: cli.capture.net_listen || exposure.listening_sockets(),
        resolve_socket_processes: cli.capture.net_listen || exposure.listening_sockets(),
        with_network_traffic: cli.capture.net_traffic || exposure.network_traffic(),
        with_updates: true,
        with_containers: with_containers_effective,
    };

    let (snap, snapshot_view) = describe_me_lib::capture_snapshot_with_view(
        capture_opts,
        exposure,
        #[cfg(feature = "config")]
        cfg.as_ref(),
        &ctx,
    )?;

    let output_format = cli.output.format();

    // Si JSON demandé: on ne sort qu'un seul document JSON combiné
    if matches!(output_format, OutputFormat::Json | OutputFormat::JsonPretty) {
        #[cfg(feature = "cli")]
        {
            if cli.output.summary {
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

            match output_format {
                OutputFormat::JsonPretty => {
                    println!("{}", serde_json::to_string_pretty(&combined)?);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string(&combined)?);
                }
                OutputFormat::Cli => unreachable!(),
            }
            return Ok(());
        }
        #[cfg(not(feature = "cli"))]
        {
            println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
            return Ok(());
        }
    }

    if cli.output.summary {
        print_summary_line(&snapshot_view);
    }

    if let Some(desc) = snapshot_view.server_description.as_deref() {
        print_description_block(desc);
        println!();
    }
    if !snapshot_view.server_tags.is_empty() {
        print_tags_line(&snapshot_view.server_tags);
        println!();
    }

    #[cfg(feature = "systemd")]
    if cli.capture.with_services {
        print_services_cli(
            &snapshot_view,
            cli.capture.services_limit,
            cli.capture.services_offset,
        );
    }

    if cli.capture.containers {
        print_containers_cli(&snapshot_view);
    }

    // --- Mode non-JSON (comportement existant + snapshot JSON à la fin) ---

    // 1) NET — tableau lisible
    #[cfg(feature = "net")]
    if cli.capture.net_listen {
        if let Some(list) = snapshot_view.listening_sockets.as_ref() {
            print_sockets_cli(
                list.as_slice(),
                cli.capture.show_process,
                cli.capture.sockets_limit,
                cli.capture.sockets_offset,
            );
        } else {
            println!("(listening sockets non exposées)");
            println!();
        }
    }

    #[cfg(feature = "net")]
    if cli.capture.net_traffic {
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
    if cli.capture.disks {
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
    if !cli.checks.is_empty() {
        // On parse TOUTES les expressions d'abord (fail-fast si invalide)
        let mut parsed = Vec::with_capacity(cli.checks.len());
        for e in &cli.checks {
            match describe_me_lib::parse_check(e) {
                Ok(c) => parsed.push(c),
                Err(err) => {
                    eprintln!("[CHECK] parse error pour '{e}': {err}");
                    std::process::exit(2); // parse error => CRIT
                }
            }
        }

        // Évalue sur le snapshot complet
        match describe_me_lib::eval_checks(&snap, &parsed) {
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

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_uses_updates_info() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: Some(describe_me_lib::UpdatesInfo {
                pending: 5,
                reboot_required: true,
                packages: None,
            }),
            extensions: None,
        };
        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=5 reboot=yes");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_handles_missing_updates() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: None,
            extensions: None,
        };
        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=? reboot=unknown");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_includes_containers_counts_when_present() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: Some(describe_me_lib::ContainersSnapshot {
                summary: Some(describe_me_lib::ContainersSummary {
                    total: 3,
                    running: 2,
                }),
                containers: None,
            }),
            updates: Some(describe_me_lib::UpdatesInfo {
                pending: 0,
                reboot_required: false,
                packages: None,
            }),
            extensions: None,
        };

        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        exposure.set_containers_summary(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(
            super::summary_line(&view),
            "updates=0 reboot=no containers=2/3"
        );
    }
}
