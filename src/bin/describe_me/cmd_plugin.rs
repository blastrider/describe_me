use std::time::Duration;

use anyhow::{bail, Result};

use crate::describe_me::args::{PluginCommand, PluginRunCommand};

const PLUGIN_DIR: &str = "/usr/lib/describe_me/plugins/";
const PLUGIN_BINARY_PREFIX: &str = "describe-me-plugin-";

pub fn handle_plugin_command(cmd: PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::Run(run) => run_plugin(run),
    }
}

pub fn run_plugin(cmd: PluginRunCommand) -> Result<()> {
    validate_plugin_name(&cmd.name)?;
    let timeout = Duration::from_secs(cmd.timeout_secs.max(1));
    let binary = format!("{PLUGIN_DIR}{PLUGIN_BINARY_PREFIX}{}", cmd.name);
    let output = describe_me_lib::run_ad_hoc_plugin(&binary, &cmd.name, &cmd.args, timeout)?;
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
    }
}
