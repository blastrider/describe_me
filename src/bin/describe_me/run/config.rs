use anyhow::Result;
use describe_me_lib::{DescribeConfig, HistoryProfile, HistorySettings};

#[cfg(feature = "config")]
use describe_me_lib::history_settings_from_config;

use crate::describe_me::args::{CliConfig, HistoryProfileArg, HistorySelection};

#[cfg(feature = "web")]
use crate::describe_me::allowlists::CliListOrigin;

pub struct ConfigResolution {
    #[cfg(feature = "config")]
    config: Option<DescribeConfig>,
    pub allow_config_exposure: bool,
    #[cfg(feature = "web")]
    web_list_origins: WebListOrigins,
}

impl ConfigResolution {
    #[cfg(feature = "config")]
    pub fn config(&self) -> Option<&DescribeConfig> {
        self.config.as_ref()
    }

    #[cfg(not(feature = "config"))]
    pub fn config(&self) -> Option<&DescribeConfig> {
        None
    }

    #[cfg(feature = "web")]
    pub fn web_list_origins(&self) -> &WebListOrigins {
        &self.web_list_origins
    }
}

pub fn resolve_config(cli: &mut CliConfig) -> Result<ConfigResolution> {
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
        anyhow::bail!(
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

pub fn resolve_history_settings(cli: &CliConfig, cfg: Option<&DescribeConfig>) -> HistorySettings {
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

fn env_flag_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(feature = "web")]
#[derive(Clone)]
pub struct WebListOrigins {
    allow_ip: CliListOrigin,
    allow_origin: CliListOrigin,
    trusted_proxy: CliListOrigin,
}

#[cfg(feature = "web")]
impl WebListOrigins {
    pub fn from_cli(cli: &CliConfig) -> Self {
        Self {
            allow_ip: CliListOrigin::from_values(&cli.web.allow_ip),
            allow_origin: CliListOrigin::from_values(&cli.web.allow_origin),
            trusted_proxy: CliListOrigin::from_values(&cli.web.trusted_proxy),
        }
    }

    pub fn mark_allow_ip_runtime_default(&mut self) {
        self.allow_ip = CliListOrigin::RuntimeDefault;
    }

    pub fn mark_allow_origin_runtime_default(&mut self) {
        self.allow_origin = CliListOrigin::RuntimeDefault;
    }

    pub fn mark_trusted_proxy_runtime_default(&mut self) {
        self.trusted_proxy = CliListOrigin::RuntimeDefault;
    }

    pub fn allow_ip(&self) -> CliListOrigin {
        self.allow_ip
    }

    pub fn allow_origin(&self) -> CliListOrigin {
        self.allow_origin
    }

    pub fn trusted_proxy(&self) -> CliListOrigin {
        self.trusted_proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::describe_me::args;
    use clap::Parser;

    fn base_cli() -> CliConfig {
        args::Opts::parse_from(["describe-me"]).into()
    }

    #[test]
    fn env_flag_enabled_accepts_truthy_strings() {
        assert!(env_flag_enabled("1"));
        assert!(env_flag_enabled("true"));
        assert!(env_flag_enabled(" Yes "));
        assert!(!env_flag_enabled("0"));
        assert!(!env_flag_enabled("nope"));
    }

    #[cfg(all(test, feature = "web", feature = "config"))]
    #[test]
    fn apply_cli_defaults_preserves_explicit_cli_values() {
        let mut cli = base_cli();
        cli.web.allow_ip = vec!["10.0.0.1".into()];

        let cli_defaults = describe_me_lib::domain::CliDefaults {
            web: None,
            with_services: None,
            with_containers: None,
            web_expose_all: None,
            web_allow_ip: vec!["192.0.2.5".into()],
            web_allow_origin: Vec::new(),
            web_trusted_proxy: Vec::new(),
        };

        let mut origins = WebListOrigins::from_cli(&cli);
        apply_cli_defaults(&mut cli, &cli_defaults, &mut origins);

        assert_eq!(cli.web.allow_ip, vec!["10.0.0.1".to_string()]);
        assert_eq!(origins.allow_ip(), CliListOrigin::ExplicitCli);
    }

    #[cfg(all(test, feature = "web", feature = "config"))]
    #[test]
    fn apply_cli_defaults_fill_missing_web_lists() {
        let mut cli = base_cli();
        let cli_defaults = describe_me_lib::domain::CliDefaults {
            web: None,
            with_services: None,
            with_containers: None,
            web_expose_all: None,
            web_allow_ip: vec!["192.0.2.5".into()],
            web_allow_origin: vec!["https://admin.example.com".into()],
            web_trusted_proxy: vec!["10.0.0.0/8".into()],
        };

        let mut origins = WebListOrigins::from_cli(&cli);
        apply_cli_defaults(&mut cli, &cli_defaults, &mut origins);

        assert_eq!(cli.web.allow_ip, vec!["192.0.2.5".to_string()]);
        assert_eq!(
            cli.web.allow_origin,
            vec!["https://admin.example.com".to_string()]
        );
        assert_eq!(cli.web.trusted_proxy, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(origins.allow_ip(), CliListOrigin::RuntimeDefault);
        assert_eq!(origins.allow_origin(), CliListOrigin::RuntimeDefault);
        assert_eq!(origins.trusted_proxy(), CliListOrigin::RuntimeDefault);
    }
}
