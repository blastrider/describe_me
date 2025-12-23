use super::{cmd_history, cmd_logs, cmd_metadata, cmd_plugin};
use anyhow::{bail, Result};
#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;
#[cfg(feature = "cli")]
use serde::Serialize;

#[cfg(feature = "web")]
use super::allowlists::{resolve_web_list, CliListOrigin};
use super::args::{
    hash_web_token, read_token_from_stdin, CliCommand, CliConfig, HistoryProfileArg,
    HistorySelection, OutputFormat, WebTokenSource,
};
use super::exposure::{apply_cli_exposure_flags, apply_web_exposure_flags};
#[cfg(feature = "config")]
use describe_me_lib::history_settings_from_config;
use describe_me_lib::{
    apply_history_settings, paginate_slice, AppContext, CaptureOptions, DescribeConfig,
    DescribeError, HistoryProfile, HistorySettings, LogEvent, PageRequest,
};

#[cfg(feature = "web")]
use describe_me_lib::{WebAccess, WebTlsConfig};

/// Orchestration entrypoint invoked by `cli.rs`.
pub fn execute(mut cli: CliConfig) -> Result<()> {
    if maybe_handle_hash_request(&cli)? {
        return Ok(());
    }

    let config = resolve_config(&mut cli)?;
    let ctx = AppContext::new_default()?;

    if let Some(cmd) = cli.command.take() {
        return handle_command(cmd, &ctx);
    }

    describe_me_lib::init_logging();
    ensure_not_root()?;

    let history_settings = resolve_history_settings(&cli, config.config());
    apply_history_settings(&ctx, history_settings)?;

    #[cfg(feature = "web")]
    let web_debug = cli.web.debug;
    #[cfg(feature = "web")]
    let web_access = build_web_access(&cli, config.config(), config.web_list_origins());

    let mut exposure = describe_me_lib::Exposure::default();
    #[cfg(feature = "config")]
    apply_cli_exposure_flags(
        &mut exposure,
        &cli,
        config.config(),
        config.allow_config_exposure,
    );
    #[cfg(not(feature = "config"))]
    apply_cli_exposure_flags(&mut exposure, &cli, config.allow_config_exposure);

    #[cfg(feature = "web")]
    let web_exposure = build_web_exposure(
        exposure,
        &cli,
        config.config(),
        config.allow_config_exposure,
    );
    #[cfg(not(feature = "web"))]
    let web_exposure = exposure;

    let exposure_all_effective = exposure.is_all();
    #[cfg(feature = "web")]
    let web_expose_all_effective = web_exposure.is_all();
    #[cfg(not(feature = "web"))]
    let web_expose_all_effective = false;
    let with_containers_effective =
        cli.capture.with_containers || cli.capture.containers || exposure.containers_summary();

    let mode = resolve_mode(&cli);

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

    #[cfg(feature = "web")]
    if let Some(bind) = &cli.web.bind {
        return start_web_server(
            bind,
            cli.web.interval_secs,
            web_access,
            web_exposure,
            config.config().cloned(),
            web_debug,
            ctx,
        );
    }

    validate_feature_flags(&cli)?;

    let capture_opts = build_capture_opts(&cli, exposure, with_containers_effective);
    let (snap, snapshot_view) = execute_capture(capture_opts, exposure, config.config(), &ctx)?;

    render_output(&cli, &snap, &snapshot_view)?;

    match evaluate_healthchecks(&cli.checks, &snap) {
        HealthOutcome::Skip => {}
        HealthOutcome::ParseError { message } | HealthOutcome::EvalError { message } => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        HealthOutcome::Result {
            exit_code,
            messages,
        } => {
            for m in messages {
                eprintln!("{m}");
            }
            std::process::exit(exit_code);
        }
    }

    Ok(())
}

fn maybe_handle_hash_request(cli: &CliConfig) -> Result<bool> {
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
        return Ok(true);
    }
    Ok(false)
}

struct ConfigResolution {
    #[cfg(feature = "config")]
    config: Option<DescribeConfig>,
    allow_config_exposure: bool,
    #[cfg(feature = "web")]
    web_list_origins: WebListOrigins,
}

impl ConfigResolution {
    #[cfg(feature = "config")]
    fn config(&self) -> Option<&DescribeConfig> {
        self.config.as_ref()
    }

    #[cfg(not(feature = "config"))]
    fn config(&self) -> Option<&DescribeConfig> {
        None
    }

    #[cfg(feature = "web")]
    fn web_list_origins(&self) -> &WebListOrigins {
        &self.web_list_origins
    }
}

fn resolve_config(cli: &mut CliConfig) -> Result<ConfigResolution> {
    let allow_config_exposure = resolve_allow_config_exposure(cli.allow_config_exposure);

    #[cfg(feature = "web")]
    let mut web_list_origins = WebListOrigins::from_cli(cli);

    #[cfg(feature = "config")]
    let config = {
        let cfg = load_config(cli)?;
        if let Some(cfg_ref) = cfg.as_ref() {
            apply_runtime_overrides(
                cli,
                cfg_ref,
                #[cfg(feature = "web")]
                &mut web_list_origins,
            );
        }
        cfg
    };

    #[cfg(not(feature = "config"))]
    if cli.config_path.is_some() {
        bail!(
            "--config nécessite la feature `config` (cargo run --features \"cli systemd config\")."
        );
    }

    Ok(ConfigResolution {
        #[cfg(feature = "config")]
        config,
        allow_config_exposure,
        #[cfg(feature = "web")]
        web_list_origins,
    })
}

fn resolve_allow_config_exposure(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    if let Ok(value) = std::env::var("DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE") {
        if env_flag_enabled(&value) {
            return true;
        }
    }
    false
}

#[cfg(feature = "config")]
fn load_config(cli: &CliConfig) -> Result<Option<DescribeConfig>> {
    if let Some(p) = &cli.config_path {
        let cfg = describe_me_lib::load_config_from_path(p)?;
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(state_dir) = runtime.state_dir.as_deref() {
                describe_me_lib::override_state_directory(state_dir);
            }
            if let Some(value) = runtime.rust_log.as_ref() {
                if std::env::var_os("RUST_LOG").is_none() {
                    std::env::set_var("RUST_LOG", value);
                }
            }
        }
        Ok(Some(cfg))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "config")]
fn apply_runtime_overrides(
    cli: &mut CliConfig,
    cfg: &DescribeConfig,
    #[cfg(feature = "web")] web_list_origins: &mut WebListOrigins,
) {
    if let Some(runtime) = cfg.runtime.as_ref() {
        if let Some(cli_defaults) = runtime.cli.as_ref() {
            apply_cli_defaults(
                cli,
                cli_defaults,
                #[cfg(feature = "web")]
                web_list_origins,
            );
        }
    }
}

#[cfg(feature = "config")]
fn apply_cli_defaults(
    cli: &mut CliConfig,
    cli_defaults: &describe_me_lib::domain::CliDefaults,
    #[cfg(feature = "web")] web_list_origins: &mut WebListOrigins,
) {
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
    #[cfg(feature = "web")]
    {
        if cli.web.allow_ip.is_empty() && !cli_defaults.web_allow_ip.is_empty() {
            cli.web.allow_ip = cli_defaults.web_allow_ip.clone();
            web_list_origins.mark_allow_ip_runtime_default();
        }
        if cli.web.allow_origin.is_empty() && !cli_defaults.web_allow_origin.is_empty() {
            cli.web.allow_origin = cli_defaults.web_allow_origin.clone();
            web_list_origins.mark_allow_origin_runtime_default();
        }
        if cli.web.trusted_proxy.is_empty() && !cli_defaults.web_trusted_proxy.is_empty() {
            cli.web.trusted_proxy = cli_defaults.web_trusted_proxy.clone();
            web_list_origins.mark_trusted_proxy_runtime_default();
        }
    }
}

#[cfg(feature = "web")]
#[derive(Clone)]
struct WebListOrigins {
    allow_ip: CliListOrigin,
    allow_origin: CliListOrigin,
    trusted_proxy: CliListOrigin,
}

#[cfg(feature = "web")]
impl WebListOrigins {
    fn from_cli(cli: &CliConfig) -> Self {
        Self {
            allow_ip: CliListOrigin::from_values(&cli.web.allow_ip),
            allow_origin: CliListOrigin::from_values(&cli.web.allow_origin),
            trusted_proxy: CliListOrigin::from_values(&cli.web.trusted_proxy),
        }
    }

    fn mark_allow_ip_runtime_default(&mut self) {
        self.allow_ip = CliListOrigin::RuntimeDefault;
    }

    fn mark_allow_origin_runtime_default(&mut self) {
        self.allow_origin = CliListOrigin::RuntimeDefault;
    }

    fn mark_trusted_proxy_runtime_default(&mut self) {
        self.trusted_proxy = CliListOrigin::RuntimeDefault;
    }
}

fn resolve_history_settings(cli: &CliConfig, cfg: Option<&DescribeConfig>) -> HistorySettings {
    #[cfg(not(feature = "config"))]
    let _ = cfg;
    #[cfg(feature = "config")]
    let from_config = cfg
        .and_then(history_settings_from_config)
        .unwrap_or_else(HistorySettings::disabled);
    #[cfg(not(feature = "config"))]
    let from_config = HistorySettings::disabled();

    apply_cli_history_overrides(cli, from_config)
}

fn apply_cli_history_overrides(
    cli: &CliConfig,
    mut history_settings: HistorySettings,
) -> HistorySettings {
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

    history_settings
}

#[cfg(feature = "web")]
fn build_web_access(
    cli: &CliConfig,
    cfg: Option<&DescribeConfig>,
    origins: &WebListOrigins,
) -> WebAccess {
    let mut web_access = WebAccess::default();

    let web_cfg = cfg.and_then(|cfg| cfg.web.as_ref());
    if let Some(web_cfg) = web_cfg {
        if let Some(token) = web_cfg.token.as_ref() {
            web_access.token = Some(token.clone());
        }
        if let Some(tls_cfg) = web_cfg.tls.as_ref() {
            if !tls_cfg.cert_path.is_empty() && !tls_cfg.key_path.is_empty() {
                web_access.tls = Some(WebTlsConfig {
                    cert_path: tls_cfg.cert_path.clone(),
                    key_path: tls_cfg.key_path.clone(),
                });
            }
        }
        if web_cfg.dev_insecure_session_cookie {
            web_access.session_cookie_secure = false;
        }
    }

    if let Some(token) = &cli.web.token {
        web_access.token = Some(token.clone());
    }

    let config_allow_ips = web_cfg.map(|cfg| cfg.allow_ips.as_slice());
    let config_allow_origins = web_cfg.map(|cfg| cfg.allow_origins.as_slice());
    let config_trusted_proxies = web_cfg.map(|cfg| cfg.trusted_proxies.as_slice());

    web_access.allow_ips = resolve_web_list(
        origins.allow_ip.cli_slice(&cli.web.allow_ip),
        config_allow_ips,
        origins.allow_ip.runtime_slice(&cli.web.allow_ip),
    );
    web_access.allow_origins = resolve_web_list(
        origins.allow_origin.cli_slice(&cli.web.allow_origin),
        config_allow_origins,
        origins.allow_origin.runtime_slice(&cli.web.allow_origin),
    );
    web_access.trusted_proxies = resolve_web_list(
        origins.trusted_proxy.cli_slice(&cli.web.trusted_proxy),
        config_trusted_proxies,
        origins.trusted_proxy.runtime_slice(&cli.web.trusted_proxy),
    );

    if cli.web.dev_mode {
        web_access.session_cookie_secure = false;
    }

    web_access
}

#[cfg(all(feature = "web", feature = "config"))]
fn build_web_exposure(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    apply_web_exposure_flags(exposure, cli, cfg, allow_config_exposure)
}

#[cfg(all(feature = "web", not(feature = "config")))]
fn build_web_exposure(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    _cfg: Option<&DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    let _ = _cfg;
    apply_web_exposure_flags(exposure, cli, allow_config_exposure)
}

fn resolve_mode(cli: &CliConfig) -> &'static str {
    if cli.web.bind.is_some() {
        "web"
    } else {
        match cli.output.format() {
            OutputFormat::JsonPretty => "json_pretty",
            OutputFormat::Json => "json",
            OutputFormat::Cli => "cli",
        }
    }
}

#[cfg(feature = "web")]
fn start_web_server(
    bind: &str,
    interval_secs: u64,
    web_access: WebAccess,
    web_exposure: describe_me_lib::Exposure,
    cfg: Option<DescribeConfig>,
    web_debug: bool,
    ctx: AppContext,
) -> Result<()> {
    use std::net::SocketAddr;

    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("Adresse invalide pour --web: {bind} ({e})"))?;
    let tick = std::time::Duration::from_secs(interval_secs);

    if web_access.token.is_none() && web_access.allow_ips.is_empty() {
        bail!(
            "--web nécessite la configuration d'un contrôle d'accès (--web-token, --web-allow-ip ou [web] dans la config)."
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        describe_me_lib::serve_http_with_context(
            addr,
            tick,
            #[cfg(feature = "config")]
            cfg,
            web_debug,
            web_access,
            web_exposure,
            ctx,
        )
        .await
    })?;
    Ok(())
}

fn validate_feature_flags(_cli: &CliConfig) -> Result<()> {
    #[cfg(not(feature = "systemd"))]
    if _cli.capture.with_services {
        bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    #[cfg(not(feature = "net"))]
    if _cli.capture.net_listen {
        bail!("--net-listen nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    #[cfg(not(feature = "net"))]
    if _cli.capture.net_traffic {
        bail!("--net-traffic nécessite la feature `net` (cargo run --features \"cli net\").");
    }
    Ok(())
}

fn build_capture_opts(
    cli: &CliConfig,
    exposure: describe_me_lib::Exposure,
    with_containers_effective: bool,
) -> CaptureOptions {
    CaptureOptions {
        with_services: cli.capture.with_services,
        with_disk_usage: true, // on garde true pour un JSON complet
        with_listening_sockets: cli.capture.net_listen || exposure.listening_sockets(),
        resolve_socket_processes: cli.capture.net_listen || exposure.listening_sockets(),
        with_network_traffic: cli.capture.net_traffic || exposure.network_traffic(),
        with_updates: true,
        with_containers: with_containers_effective,
    }
}

fn execute_capture(
    capture_opts: CaptureOptions,
    exposure: describe_me_lib::Exposure,
    cfg: Option<&DescribeConfig>,
    ctx: &AppContext,
) -> Result<
    (
        describe_me_lib::SystemSnapshot,
        describe_me_lib::SnapshotView,
    ),
    DescribeError,
> {
    #[cfg(feature = "config")]
    {
        describe_me_lib::capture_snapshot_with_view(capture_opts, exposure, cfg, ctx)
    }
    #[cfg(not(feature = "config"))]
    {
        let _ = cfg;
        describe_me_lib::capture_snapshot_with_view(capture_opts, exposure, ctx)
    }
}

fn render_output(
    cli: &CliConfig,
    snap: &describe_me_lib::SystemSnapshot,
    snapshot_view: &describe_me_lib::SnapshotView,
) -> Result<()> {
    let output_format = cli.output.format();

    if matches!(output_format, OutputFormat::Json | OutputFormat::JsonPretty) {
        #[cfg(feature = "cli")]
        {
            if cli.output.summary {
                print_summary_line(snapshot_view);
            }
            let combined = CombinedOutput {
                snapshot: snapshot_view,
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
        print_summary_line(snapshot_view);
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
            snapshot_view,
            cli.capture.services_limit,
            cli.capture.services_offset,
        );
    }

    if cli.capture.containers {
        print_containers_cli(snapshot_view);
    }

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

    println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
    Ok(())
}

#[derive(Debug)]
enum HealthOutcome {
    Skip,
    ParseError {
        message: String,
    },
    EvalError {
        message: String,
    },
    Result {
        exit_code: i32,
        messages: Vec<String>,
    },
}

fn evaluate_healthchecks(
    checks: &[String],
    snap: &describe_me_lib::SystemSnapshot,
) -> HealthOutcome {
    if checks.is_empty() {
        return HealthOutcome::Skip;
    }

    let mut parsed = Vec::with_capacity(checks.len());
    for e in checks {
        match describe_me_lib::parse_check(e) {
            Ok(c) => parsed.push(c),
            Err(err) => {
                return HealthOutcome::ParseError {
                    message: format!("[CHECK] parse error pour '{e}': {err}"),
                };
            }
        }
    }

    match describe_me_lib::eval_checks(snap, &parsed) {
        Ok((max_sev, results)) => {
            let messages = results
                .into_iter()
                .map(|r| format!("[CHECK] {}", r.message))
                .collect::<Vec<_>>();
            HealthOutcome::Result {
                exit_code: max_sev as i32,
                messages,
            }
        }
        Err(err) => HealthOutcome::EvalError {
            message: format!("[CHECK] evaluation error: {err}"),
        },
    }
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
    sockets: &[describe_me_lib::domain::ListeningSocket],
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

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput<'a> {
    snapshot: &'a describe_me_lib::SnapshotView,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_traffic: Option<&'a [describe_me_lib::domain::NetworkInterfaceTraffic]>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<&'a [describe_me_lib::domain::ListeningSocket]>,
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

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

const SERVICES_PAGE_MAX: usize = 500;
const SOCKETS_PAGE_MAX: usize = 500;

#[cfg(test)]
mod tests {
    use super::*;
    use describe_me_lib::ContainersSnapshot;

    #[test]
    fn env_flag_enabled_accepts_truthy_strings() {
        assert!(env_flag_enabled("1"));
        assert!(env_flag_enabled("true"));
        assert!(env_flag_enabled(" Yes "));
        assert!(!env_flag_enabled("0"));
        assert!(!env_flag_enabled("nope"));
    }

    #[cfg(feature = "web")]
    #[test]
    fn healthcheck_parse_error_is_reported() {
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

        let outcome = evaluate_healthchecks(&["???".into()], &snapshot);
        match outcome {
            HealthOutcome::ParseError { message } => {
                assert!(message.contains("parse error"))
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

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
            containers: Some(ContainersSnapshot {
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
