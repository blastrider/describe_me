use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Emplacement par défaut des plugins système.
pub const DEFAULT_PLUGIN_ROOT: &str = "/usr/lib/describe_me/plugins/";
/// Préfixe binaire attendu pour les plugins packagés.
pub const DEFAULT_PLUGIN_PREFIX: &str = "describe-me-plugin-";

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PluginPolicy {
    pub root: PathBuf,
    pub require_exec: bool,
    pub expected_sha256: Option<String>,
    /// Allowlist of host env vars forwarded to the plugin (empty => defaults).
    pub allowed_env: Vec<String>,
    /// Extra env vars injected for the plugin (explicit override).
    pub extra_env: BTreeMap<String, String>,
}

impl Default for PluginPolicy {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_PLUGIN_ROOT),
            require_exec: true,
            expected_sha256: None,
            allowed_env: Vec::new(),
            extra_env: BTreeMap::new(),
        }
    }
}

impl PluginPolicy {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            ..Self::default()
        }
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self::new(root)
    }

    pub fn with_exec_check(mut self, require_exec: bool) -> Self {
        self.require_exec = require_exec;
        self
    }

    pub fn with_expected_sha256(mut self, sha256: impl Into<Option<String>>) -> Self {
        self.expected_sha256 = sha256.into();
        self
    }

    pub fn with_allowed_env<I, S>(mut self, allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_env = allowed.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_extra_env<I, K, V>(mut self, extra: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.extra_env = extra
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    pub fn binary_path_for(&self, plugin_name: &str) -> PathBuf {
        self.root
            .join(format!("{DEFAULT_PLUGIN_PREFIX}{plugin_name}"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
