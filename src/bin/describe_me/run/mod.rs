mod capture;
mod config;
mod health;
mod render;
#[cfg(feature = "web")]
mod web;

use anyhow::{bail, Result};
use describe_me_lib::{apply_history_settings, AppContext, LogEvent};

use super::args::{CliCommand, CliConfig, WebTokenSource};
use super::exposure::apply_cli_exposure_flags;
use super::{cmd_history, cmd_logs, cmd_metadata, cmd_plugin};

#[cfg(all(unix, feature = "cli"))]
use nix::unistd::Uid;

pub use health::HealthcheckOutcome;

#[derive(Debug)]
pub enum RunOutcome {
    Completed,
    Exit { code: i32, messages: Vec<String> },
}

pub fn execute(mut cli: CliConfig) -> Result<RunOutcome> {
    if maybe_handle_hash_request(&cli)? {
        return Ok(RunOutcome::Completed);
    }

    let config = config::resolve_config(&mut cli)?;
    let ctx = AppContext::new_default()?;

    if let Some(cmd) = cli.command.take() {
        handle_command(cmd, &ctx)?;
        return Ok(RunOutcome::Completed);
    }

    describe_me_lib::init_logging();
    ensure_not_root()?;

    let history_settings = config::resolve_history_settings(&cli, config.config());
    apply_history_settings(&ctx, history_settings)?;

    #[cfg(feature = "web")]
    let web_access = web::build_web_access(&cli, config.config(), config.web_list_origins());

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
    let web_exposure = web::build_web_exposure(
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

    let mode = render::resolve_mode(&cli);

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

    #[cfg(not(feature = "web"))]
    if cli.web.bind.is_some() {
        bail!("--web nécessite la feature `web` (cargo run --features \"cli web\").");
    }

    #[cfg(feature = "web")]
    if let Some(bind) = &cli.web.bind {
        web::start_web_server(
            bind,
            cli.web.interval_secs,
            web_access,
            web_exposure,
            config.config().cloned(),
            cli.web.debug,
            ctx,
        )?;
        return Ok(RunOutcome::Completed);
    }

    capture::validate_feature_flags(&cli)?;

    let capture_opts = capture::build_capture_opts(&cli, exposure, with_containers_effective);
    let (snap, snapshot_view) =
        capture::execute_capture(capture_opts, exposure, config.config(), &ctx)?;

    render::render_output(&cli, &snap, &snapshot_view)?;

    match health::evaluate_healthchecks(&cli.checks, &snap) {
        HealthcheckOutcome::Skip => Ok(RunOutcome::Completed),
        HealthcheckOutcome::Exit {
            exit_code,
            messages,
        } => Ok(RunOutcome::Exit {
            code: exit_code,
            messages,
        }),
    }
}

fn maybe_handle_hash_request(cli: &CliConfig) -> Result<bool> {
    if let Some(hash_req) = cli.web.hash_request() {
        let token = match hash_req.source {
            WebTokenSource::Literal(value) => value,
            WebTokenSource::Stdin => super::args::read_token_from_stdin()?,
        };

        if token.is_empty() {
            bail!("Le token ne peut pas être vide.");
        }

        let hash = super::args::hash_web_token(&token, hash_req.algorithm)?;
        println!("{hash}");
        return Ok(true);
    }
    Ok(false)
}

fn handle_command(cmd: CliCommand, ctx: &AppContext) -> Result<()> {
    match cmd {
        CliCommand::Metadata(metadata) => cmd_metadata::handle_metadata_command(metadata, ctx),
        CliCommand::Plugin(plugin) => cmd_plugin::handle_plugin_command(plugin),
        CliCommand::History(history) => cmd_history::handle_history_command(history, ctx),
        CliCommand::Logs(logs) => cmd_logs::handle_logs_command(logs),
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
