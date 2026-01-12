use super::super::error::DescribeError;
use super::super::plugin::validate_plugin_name;
use super::DescribeConfig;
use std::collections::HashMap;
use std::path::Path;

impl DescribeConfig {
    pub fn validate(&self) -> Result<(), DescribeError> {
        self.validate_plugin_names()?;
        self.validate_runtime()?;
        Ok(())
    }

    pub fn validate_plugin_names(&self) -> Result<(), DescribeError> {
        let Some(extensions) = self.extensions.as_ref() else {
            return Ok(());
        };
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (idx, plugin) in extensions.plugins.iter().enumerate() {
            validate_plugin_name(plugin.name.as_str()).map_err(|err| {
                DescribeError::Config(format!("extensions.plugins[{idx}].name: {err}"))
            })?;
            if let Some(previous) = seen.insert(plugin.name.clone(), idx) {
                return Err(DescribeError::Config(format!(
                    "extensions.plugins[{idx}].name: nom dupliqué \"{}\" (déjà présent à l'index {previous})",
                    plugin.name
                )));
            }
        }
        Ok(())
    }

    pub fn validate_runtime(&self) -> Result<(), DescribeError> {
        if let Some(runtime) = self.runtime.as_ref() {
            if let Some(state_dir) = runtime.state_dir.as_deref() {
                if state_dir.is_empty() {
                    return Err(DescribeError::Config(
                        "runtime.state_dir ne peut pas être vide".into(),
                    ));
                }
                let path = Path::new(state_dir);
                if !path.is_absolute() {
                    return Err(DescribeError::Config(
                        "runtime.state_dir doit être un chemin absolu".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}
