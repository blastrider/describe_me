#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginNameError {
    Empty,
    TooLong { max: usize },
    InvalidChars,
}

impl std::fmt::Display for PluginNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginNameError::Empty => write!(f, "Le nom du plugin ne peut pas être vide."),
            PluginNameError::TooLong { max } => {
                write!(f, "Le nom du plugin doit faire au plus {max} caractères.")
            }
            PluginNameError::InvalidChars => {
                write!(f, "Le nom du plugin doit uniquement contenir [a-z0-9_-].")
            }
        }
    }
}

pub const PLUGIN_NAME_MAX_LEN: usize = 64;

pub fn validate_plugin_name(name: &str) -> Result<(), PluginNameError> {
    if name.is_empty() {
        return Err(PluginNameError::Empty);
    }
    if name.len() > PLUGIN_NAME_MAX_LEN {
        return Err(PluginNameError::TooLong {
            max: PLUGIN_NAME_MAX_LEN,
        });
    }
    if !name
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
    {
        return Err(PluginNameError::InvalidChars);
    }
    Ok(())
}

pub fn is_valid_plugin_name(name: &str) -> bool {
    validate_plugin_name(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_plugin_names() {
        assert!(validate_plugin_name("certificates").is_ok());
        assert!(validate_plugin_name("inventory_v2").is_ok());
        assert!(validate_plugin_name("a-1").is_ok());
    }

    #[test]
    fn rejects_empty_plugin_name() {
        assert_eq!(validate_plugin_name(""), Err(PluginNameError::Empty));
    }

    #[test]
    fn rejects_invalid_chars() {
        assert_eq!(
            validate_plugin_name("Bad/Name"),
            Err(PluginNameError::InvalidChars)
        );
        assert_eq!(
            validate_plugin_name("UPPERCASE"),
            Err(PluginNameError::InvalidChars)
        );
        assert_eq!(
            validate_plugin_name("with space"),
            Err(PluginNameError::InvalidChars)
        );
    }

    #[test]
    fn rejects_names_too_long() {
        let name = "a".repeat(PLUGIN_NAME_MAX_LEN + 1);
        assert_eq!(
            validate_plugin_name(&name),
            Err(PluginNameError::TooLong {
                max: PLUGIN_NAME_MAX_LEN
            })
        );
    }
}
