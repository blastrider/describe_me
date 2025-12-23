use std::time::Duration;

use anyhow::Result;
use describe_me_lib::domain::validate_plugin_name as validate_plugin_name_rule;
use describe_me_lib::plugins::PluginPolicy;

use crate::describe_me::args::{PluginCommand, PluginRunCommand};

pub fn handle_plugin_command(cmd: PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::Run(run) => run_plugin(run),
    }
}

pub fn run_plugin(cmd: PluginRunCommand) -> Result<()> {
    validate_plugin_name(&cmd.name)?;
    let timeout = Duration::from_secs(cmd.timeout_secs.max(1));
    let policy = PluginPolicy::default();
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

#[cfg(test)]
mod tests {
    use super::validate_plugin_name;

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
}
