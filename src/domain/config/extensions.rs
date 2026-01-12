use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::Deserialize;

/// Configuration des collecteurs externes.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ExtensionsConfig {
    /// Liste des plugins exécutés à chaque snapshot.
    pub plugins: Vec<PluginDefinition>,
}

/// Plugin externe lancé durant les captures.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[non_exhaustive]
pub struct PluginDefinition {
    /// Nom stable affiché côté UI/JSON (namespacing).
    pub name: String,
    /// Chemin absolu vers le binaire autorisé.
    pub path: String,
    /// Arguments optionnels transmis au binaire.
    #[cfg_attr(feature = "serde", serde(default))]
    pub args: Vec<String>,
    /// Timeout (secondes) avant de tuer le processus.
    #[cfg_attr(feature = "serde", serde(default))]
    pub timeout_secs: Option<u64>,
    /// Empreinte SHA-256 hexadécimale attendue pour le binaire.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_sha256"))]
    pub sha256: String,
    /// Allowlist d'ENV transmis au plugin (vide => allowlist par défaut).
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_env: Vec<String>,
    /// ENV additionnels injectés (override explicite).
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_env: BTreeMap<String, String>,
}

impl PluginDefinition {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            sha256: sha256.into(),
            ..Self::default()
        }
    }
}

#[cfg(feature = "serde")]
fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value = Option::<String>::deserialize(deserializer)?;
    let Some(v) = value else {
        return Err(serde::de::Error::missing_field("sha256"));
    };

    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Err(serde::de::Error::custom("sha256 ne peut pas être vide"));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if normalized.len() != 64 {
        return Err(serde::de::Error::custom(
            "sha256 doit contenir 64 caractères hexadécimaux",
        ));
    }
    if !normalized
        .chars()
        .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    {
        return Err(serde::de::Error::custom(
            "sha256 doit être une valeur hexadécimale (0-9, a-f)",
        ));
    }

    Ok(normalized)
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use crate::domain::config::DescribeConfig;
    use crate::domain::DescribeError;

    #[test]
    fn validate_plugin_names_rejects_duplicates() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"

[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo2"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .expect("deserialize config");

        let err = cfg.validate_plugin_names().expect_err("duplicate name");
        assert!(matches!(err, DescribeError::Config(msg) if msg.contains("nom dupliqué")));
    }

    #[test]
    fn validate_plugin_names_accepts_unique() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"

[[extensions.plugins]]
name = "demo2"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo2"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .expect("deserialize config");

        cfg.validate_plugin_names().expect("valid plugin names");
    }

    #[test]
    fn plugin_sha256_rejects_invalid_length() {
        let err: Result<DescribeConfig, _> = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "abc"
"#,
        );
        let err = err.expect_err("sha256 length rejected");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn plugin_sha256_rejects_non_hex_chars() {
        let err: Result<DescribeConfig, _> = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "zz51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"
"#,
        );
        let err = err.expect_err("sha256 hex rejected");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn plugin_sha256_is_normalized_to_lowercase() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
"#,
        )
        .expect("deserialize config");

        assert_eq!(
            cfg.extensions.unwrap().plugins[0].sha256,
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
    }

    #[test]
    fn validate_plugin_names_rejects_invalid_chars() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo bad"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"
"#,
        )
        .expect("deserialize config");

        let err = cfg.validate_plugin_names().expect_err("invalid name");
        assert!(
            matches!(err, DescribeError::Config(msg) if msg.contains("extensions.plugins[0].name"))
        );
    }
}
