use std::time::Duration;

use anyhow::{bail, Result};
use describe_me_lib::domain::validate_plugin_name as validate_plugin_name_rule;
#[cfg(feature = "config")]
use describe_me_lib::domain::DescribeConfig;
use describe_me_lib::plugins::PluginPolicy;
#[cfg(not(feature = "config"))]
type DescribeConfig = ();

use crate::describe_me::args::{PluginCommand, PluginRunCommand};

pub fn handle_plugin_command(cmd: PluginCommand, cfg: Option<&DescribeConfig>) -> Result<()> {
    match cmd {
        PluginCommand::Run(run) => run_plugin(run, cfg),
    }
}

pub fn run_plugin(cmd: PluginRunCommand, cfg: Option<&DescribeConfig>) -> Result<()> {
    validate_plugin_name(&cmd.name)?;
    let timeout = Duration::from_secs(cmd.timeout_secs.max(1));
    let policy = resolve_policy(&cmd, cfg)?;
    let binary = policy.binary_path_for(&cmd.name);
    let binary_str = binary.to_string_lossy();
    let output = describe_me_lib::run_ad_hoc_plugin_with_policy(
        binary_str.as_ref(),
        &cmd.name,
        &cmd.args,
        timeout,
        &policy,
    )?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn validate_plugin_name(name: &str) -> Result<()> {
    validate_plugin_name_rule(name).map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn resolve_policy(cmd: &PluginRunCommand, cfg: Option<&DescribeConfig>) -> Result<PluginPolicy> {
    let expected_sha256 = resolve_expected_sha256(cmd, cfg)?;
    Ok(PluginPolicy::default().with_expected_sha256(Some(expected_sha256)))
}

fn resolve_expected_sha256(cmd: &PluginRunCommand, cfg: Option<&DescribeConfig>) -> Result<String> {
    if let Some(cli) = cmd.sha256.as_deref() {
        let normalized = cli.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            bail!("--sha256 ne peut pas être vide");
        }
        return Ok(normalized);
    }

    #[cfg(feature = "config")]
    {
        if let Some(from_config) = cfg.and_then(|cfg| cfg.extensions.as_ref()).and_then(|ext| {
            ext.plugins
                .iter()
                .find(|plugin| plugin.name == cmd.name)
                .map(|plugin| plugin.sha256.trim().to_ascii_lowercase())
        }) {
            if from_config.is_empty() {
                bail!("config.extensions.plugins.sha256 ne peut pas être vide");
            }
            return Ok(from_config);
        }
    }
    #[cfg(not(feature = "config"))]
    let _ = cfg;

    bail!("empreinte SHA-256 requise (--sha256 ou config.extensions.plugins[].sha256)");
}

#[cfg(all(test, feature = "config"))]
mod tests {
    use super::{resolve_expected_sha256, validate_plugin_name};
    use describe_me_lib::domain::{DescribeConfig, ExtensionsConfig, PluginDefinition};

    #[test]
    fn validates_plugin_name_rules() {
        validate_plugin_name("certificates").unwrap();
        validate_plugin_name("inventory_v2").unwrap();
    }

    #[test]
    fn rejects_invalid_plugin_names() {
        assert!(validate_plugin_name("").is_err());
        assert!(validate_plugin_name("Bad/Name").is_err());
        assert!(validate_plugin_name("UPPERCASE").is_err());
        let long_name = "a".repeat(describe_me_lib::domain::PLUGIN_NAME_MAX_LEN + 1);
        assert!(validate_plugin_name(&long_name).is_err());
    }

    #[test]
    fn resolve_sha256_prefers_cli_flag() {
        let mut cmd = PluginCommandBuilder::new("inventory");
        cmd.sha256 = Some("ABCDEF".to_string());

        let cfg = Some(DescribeConfig {
            extensions: Some(ExtensionsConfig {
                plugins: vec![PluginDefinition::new(
                    "inventory",
                    "/usr/lib/describe_me/plugins/describe-me-plugin-inventory",
                    "1234",
                )],
            }),
            ..DescribeConfig::default()
        });

        let sha = resolve_expected_sha256(&cmd.build(), cfg.as_ref()).unwrap();
        assert_eq!(sha, "abcdef");
    }

    #[test]
    fn resolve_sha256_falls_back_to_config() {
        let cfg = DescribeConfig {
            extensions: Some(ExtensionsConfig {
                plugins: vec![PluginDefinition::new(
                    "certificates",
                    "/usr/lib/describe_me/plugins/describe-me-plugin-certificates",
                    "aabbcc",
                )],
            }),
            ..DescribeConfig::default()
        };

        let cmd = PluginCommandBuilder::new("certificates").build();
        let sha = resolve_expected_sha256(&cmd, Some(&cfg)).unwrap();
        assert_eq!(sha, "aabbcc");
    }

    #[test]
    fn resolve_sha256_rejects_missing_value() {
        let cmd = PluginCommandBuilder::new("inventory").build();
        let err = resolve_expected_sha256(&cmd, None).unwrap_err();
        assert!(err.to_string().contains("empreinte SHA-256"));
    }

    #[derive(Default)]
    struct PluginCommandBuilder {
        name: String,
        sha256: Option<String>,
    }

    impl PluginCommandBuilder {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                sha256: None,
            }
        }

        fn build(self) -> super::PluginRunCommand {
            super::PluginRunCommand {
                name: self.name,
                sha256: self.sha256,
                args: Vec::new(),
                timeout_secs: 10,
            }
        }
    }
}
