#![forbid(unsafe_code)]

#[path = "describe_me/allowlists.rs"]
mod allowlists;
#[path = "describe_me/args.rs"]
mod args;
#[path = "describe_me/exposure.rs"]
mod exposure_cfg;

use anyhow::{bail, Result};
#[cfg(feature = "net")]
use describe_me::domain::{ListeningSocket, NetworkInterfaceTraffic};
use describe_me::{
    paginate_slice, HistoryMode, HistoryProfile, HistorySettings, LogEvent, PageRequest,
};
#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;
#[cfg(feature = "cli")]
use serde::Serialize;
use std::borrow::Cow;
use std::time::Duration;

const PLUGIN_DIR: &str = "/usr/lib/describe_me/plugins/";
const PLUGIN_BINARY_PREFIX: &str = "describe-me-plugin-";
const SERVICES_PAGE_MAX: usize = 500;
const SOCKETS_PAGE_MAX: usize = 500;

#[cfg(feature = "web")]
use allowlists::{resolve_web_list, CliListOrigin};
use args::{
    hash_web_token, parse as parse_opts, read_token_from_stdin, CliCommand, DescriptionCommand,
    HistoryCommand, HistoryProfileArg, MetadataCommand, PluginCommand, PluginRunCommand,
    TagsCommand,
};
use exposure_cfg::apply_cli_exposure_flags;
#[cfg(feature = "web")]
use exposure_cfg::apply_web_exposure_flags;
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

fn handle_command(cmd: CliCommand) -> Result<()> {
    match cmd {
        CliCommand::Metadata(metadata) => handle_metadata_command(metadata),
        CliCommand::Plugin(plugin) => handle_plugin_command(plugin),
        CliCommand::History(history) => handle_history_command(history),
    }
}

fn handle_metadata_command(cmd: MetadataCommand) -> Result<()> {
    match cmd {
        MetadataCommand::Description(action) => handle_description_command(action),
        MetadataCommand::Tags(action) => handle_tags_command(action),
    }
}

fn handle_plugin_command(cmd: PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::Run(run) => run_plugin(run),
    }
}

fn handle_description_command(cmd: DescriptionCommand) -> Result<()> {
    match cmd {
        DescriptionCommand::Show => {
            if let Some(desc) = describe_me::load_server_description()? {
                println!("{desc}");
            } else {
                println!("(aucune description stockée)");
            }
        }
        DescriptionCommand::Set { text } => {
            describe_me::set_server_description(&text)?;
            println!("Description enregistrée.");
        }
        DescriptionCommand::Clear => {
            describe_me::clear_server_description()?;
            println!("Description supprimée.");
        }
    }
    Ok(())
}

fn handle_tags_command(cmd: TagsCommand) -> Result<()> {
    match cmd {
        TagsCommand::Show => {
            let tags = describe_me::load_server_tags()?;
            if tags.is_empty() {
                println!("(aucun tag configuré)");
            } else {
                println!("{}", tags.join(", "));
            }
        }
        TagsCommand::Set { tags } => {
            let normalized = describe_me::set_server_tags(&tags)?;
            if normalized.is_empty() {
                println!("Aucun tag valide fourni, liste nettoyée.");
            } else {
                println!("Tags définis: {}", normalized.join(", "));
            }
        }
        TagsCommand::Add { tags } => {
            let normalized = describe_me::add_server_tags(&tags)?;
            println!("Tags actuels: {}", normalized.join(", "));
        }
        TagsCommand::Remove { tags } => {
            let normalized = describe_me::remove_server_tags(&tags)?;
            if normalized.is_empty() {
                println!("Plus aucun tag défini.");
            } else {
                println!("Tags restants: {}", normalized.join(", "));
            }
        }
        TagsCommand::Clear => {
            describe_me::clear_server_tags()?;
            println!("Tags supprimés.");
        }
    }
    Ok(())
}

fn handle_history_command(cmd: HistoryCommand) -> Result<()> {
    let settings = describe_me::history_settings_snapshot();
    if !settings.is_active() {
        bail!("L'historique n'est pas activé sur cette instance.");
    }

    let server_id = if let Some(id) = cmd.server {
        id
    } else if let Some(default_id) = describe_me::history_default_server_id() {
        default_id
    } else {
        bail!("Aucun identifiant serveur n'est disponible (aucun snapshot capturé ?).");
    };

    let window_secs = cmd.window.max(1);
    let rounding = settings.rounding_seconds.max(1);
    let retention_cap = settings.retention_points.max(16) as usize;
    let default_limit = retention_cap.min(256);
    let limit = cmd
        .limit
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
        .min(retention_cap)
        .max(1);

    let series = match describe_me::history_query_series(
        &server_id,
        Duration::from_secs(window_secs),
        limit,
        rounding,
    ) {
        Ok(series) => series,
        Err(describe_me::HistoryQueryError::Disabled) => {
            bail!("L'historique n'est plus actif ou a été désactivé.");
        }
        Err(describe_me::HistoryQueryError::InvalidLimit) => {
            bail!("La limite demandée n'est pas valide.");
        }
        Err(describe_me::HistoryQueryError::InvalidServer) => {
            bail!("Identifiant de serveur invalide.");
        }
        Err(describe_me::HistoryQueryError::NotFound) => {
            println!("Aucune donnée historique disponible pour ce serveur.");
            return Ok(());
        }
        Err(describe_me::HistoryQueryError::Storage(err)) => {
            bail!("Lecture de l'historique impossible: {err}");
        }
    };

    print_history_series(&series);
    Ok(())
}

fn print_history_series(series: &describe_me::HistorySeries) {
    println!(
        "Serveur: {}\nFenêtre: {}s | Points: {} | Bucket: {}s | Agrégé: {} | Tronqué: {}",
        series.server_id,
        series.window_seconds,
        series.points.len(),
        series.bucket_seconds,
        if series.aggregated { "oui" } else { "non" },
        if series.truncated { "oui" } else { "non" }
    );
    println!(
        "{:>20}  {:>18}  {:>18}  {:>18}",
        "timestamp", "cpu avg/min/max", "mem avg/min/max", "disk avg/min/max"
    );
    for point in &series.points {
        println!(
            "{:>20}  {:>18}  {:>18}  {:>18}",
            point.timestamp,
            format_metric(&point.cpu),
            format_metric(&point.mem),
            format_metric(&point.disk),
        );
    }
}

fn format_metric(metric: &describe_me::MetricAggregate) -> String {
    match metric.avg {
        Some(avg) => {
            let min = metric.min.unwrap_or(avg);
            let max = metric.max.unwrap_or(avg);
            if approx_equal(min, avg) && approx_equal(max, avg) {
                format!("{avg:>6.1}%")
            } else {
                format!("{avg:>5.1}% ({min:>4.1}-{max:>4.1})")
            }
        }
        None => String::from("    --"),
    }
}

fn approx_equal(a: f32, b: f32) -> bool {
    (a - b).abs() < 0.05
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
fn print_services_cli(view: &describe_me::SnapshotView, limit: Option<usize>, offset: usize) {
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

fn run_plugin(cmd: PluginRunCommand) -> Result<()> {
    validate_plugin_name(&cmd.name)?;
    let timeout = Duration::from_secs(cmd.timeout_secs.max(1));
    let binary = format!("{PLUGIN_DIR}{PLUGIN_BINARY_PREFIX}{}", cmd.name);
    let output = describe_me::run_ad_hoc_plugin(&binary, &cmd.name, &cmd.args, timeout)?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn validate_plugin_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("Le nom du plugin ne peut pas être vide.");
    }
    if name
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
    {
        Ok(())
    } else {
        bail!("Le nom du plugin doit uniquement contenir [a-z0-9_-].");
    }
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

fn main() -> Result<()> {
    let mut opts = parse_opts();

    if opts.hash_web_token.is_some() || opts.hash_web_token_stdin {
        let token = if let Some(value) = opts.hash_web_token.take() {
            value
        } else {
            read_token_from_stdin()?
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

    #[cfg(feature = "config")]
    if let Some(cfg) = &cfg {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(state_dir) = runtime.state_dir.as_deref() {
                describe_me::override_state_directory(state_dir);
            }
        }
    }

    if let Some(cmd) = opts.command.take() {
        return handle_command(cmd);
    }

    let mut allow_config_exposure = opts.allow_config_exposure;
    if !allow_config_exposure {
        if let Ok(value) = std::env::var("DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE") {
            if env_flag_enabled(&value) {
                allow_config_exposure = true;
            }
        }
    }

    #[cfg(feature = "web")]
    let mut web_allow_ip_source = CliListOrigin::from_values(&opts.web_allow_ip);
    #[cfg(feature = "web")]
    let mut web_allow_origin_source = CliListOrigin::from_values(&opts.web_allow_origin);
    #[cfg(feature = "web")]
    let mut web_trusted_proxy_source = CliListOrigin::from_values(&opts.web_trusted_proxy);

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
                if !opts.capture_logs {
                    if let Some(true) = cli.capture_logs {
                        opts.capture_logs = true;
                    }
                }
                if !opts.web_expose_all {
                    if let Some(true) = cli.web_expose_all {
                        opts.web_expose_all = true;
                    }
                }
                if opts.web_allow_ip.is_empty() && !cli.web_allow_ip.is_empty() {
                    opts.web_allow_ip = cli.web_allow_ip.clone();
                    #[cfg(feature = "web")]
                    {
                        web_allow_ip_source = CliListOrigin::RuntimeDefault;
                    }
                }
                if opts.web_allow_origin.is_empty() && !cli.web_allow_origin.is_empty() {
                    opts.web_allow_origin = cli.web_allow_origin.clone();
                    #[cfg(feature = "web")]
                    {
                        web_allow_origin_source = CliListOrigin::RuntimeDefault;
                    }
                }
                if opts.web_trusted_proxy.is_empty() && !cli.web_trusted_proxy.is_empty() {
                    opts.web_trusted_proxy = cli.web_trusted_proxy.clone();
                    #[cfg(feature = "web")]
                    {
                        web_trusted_proxy_source = CliListOrigin::RuntimeDefault;
                    }
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

    if opts.history_disabled {
        history_settings.disable();
    }

    if let Some(profile) = opts.history_profile {
        let resolved = match profile {
            HistoryProfileArg::Default => HistoryProfile::Default,
            HistoryProfileArg::Ops => HistoryProfile::Ops,
            HistoryProfileArg::Paranoid => HistoryProfile::Paranoid,
        };
        history_settings = HistorySettings::for_profile(resolved);
    }

    if let Some(retention) = opts.history_retention {
        history_settings.set_retention_points(retention);
    }

    describe_me::configure_history(history_settings)?;

    #[cfg(all(feature = "web", feature = "config"))]
    let web_cfg = cfg.as_ref().and_then(|cfg| cfg.web.as_ref());

    #[cfg(all(feature = "web", feature = "config"))]
    if let Some(web_cfg) = web_cfg {
        if let Some(token) = web_cfg.token.as_ref() {
            web_access.token = Some(token.clone());
        }
        if let Some(tls_cfg) = web_cfg.tls.as_ref() {
            if !tls_cfg.cert_path.is_empty() && !tls_cfg.key_path.is_empty() {
                web_access.tls = Some(describe_me::WebTlsConfig {
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
        if let Some(token) = &opts.web_token {
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
            web_allow_ip_source.cli_slice(&opts.web_allow_ip),
            config_allow_ips,
            web_allow_ip_source.runtime_slice(&opts.web_allow_ip),
        );
        web_access.allow_origins = resolve_web_list(
            web_allow_origin_source.cli_slice(&opts.web_allow_origin),
            config_allow_origins,
            web_allow_origin_source.runtime_slice(&opts.web_allow_origin),
        );
        web_access.trusted_proxies = resolve_web_list(
            web_trusted_proxy_source.cli_slice(&opts.web_trusted_proxy),
            config_trusted_proxies,
            web_trusted_proxy_source.runtime_slice(&opts.web_trusted_proxy),
        );

        if opts.web_dev {
            web_access.session_cookie_secure = false;
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

    let execution_scope = describe_me::execution_scope();
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
        execution_scope: execution_scope.as_str().into(),
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
                opts.capture_logs,
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
        with_logs: opts.capture_logs,
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

    println!("Version : {}", snapshot_view.version);
    if let Some(info) = snapshot_view.container_info.as_ref() {
        println!(
            "Container : {}{}{}",
            info.runtime,
            info.container_id
                .as_deref()
                .map(|id| format!(" ({id})"))
                .unwrap_or_default(),
            info.orchestrator
                .as_deref()
                .map(|o| format!(", orchestrateur: {o}"))
                .unwrap_or_default()
        );
    }
    println!();

    if let Some(desc) = snapshot_view.server_description.as_deref() {
        print_description_block(desc);
        println!();
    }
    if !snapshot_view.server_tags.is_empty() {
        print_tags_line(&snapshot_view.server_tags);
        println!();
    }

    if opts.capture_logs {
        match describe_me::capture_logs(execution_scope) {
            Ok(logs) => eprintln!("{logs}"),
            Err(err) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("capture_logs"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
            }
        }
    }

    #[cfg(feature = "systemd")]
    if opts.with_services {
        print_services_cli(&snapshot_view, opts.services_limit, opts.services_offset);
    }

    // --- Mode non-JSON (comportement existant + snapshot JSON à la fin) ---

    // 1) NET — tableau lisible
    #[cfg(feature = "net")]
    if opts.net_listen {
        if let Some(list) = snapshot_view.listening_sockets.as_ref() {
            print_sockets_cli(
                list.as_slice(),
                opts.show_process,
                opts.sockets_limit,
                opts.sockets_offset,
            );
        } else {
            println!("(listening sockets non exposées)");
            println!();
        }
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
        let snapshot = describe_me::SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            version: "0.0.0".into(),
            execution_scope: describe_me::ExecutionScope::Host,
            logs: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            container_info: None,
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
            extensions: None,
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
            version: "0.0.0".into(),
            execution_scope: describe_me::ExecutionScope::Host,
            logs: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            container_info: None,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: describe_me::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            updates: None,
            extensions: None,
        };
        let mut exposure = describe_me::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=? reboot=unknown");
    }

    #[test]
    fn validates_plugin_name_rules() {
        super::validate_plugin_name("certificates").unwrap();
        super::validate_plugin_name("inventory_v2").unwrap();
    }

    #[test]
    fn rejects_invalid_plugin_names() {
        assert!(super::validate_plugin_name("").is_err());
        assert!(super::validate_plugin_name("Bad/Name").is_err());
        assert!(super::validate_plugin_name("UPPERCASE").is_err());
    }
}
