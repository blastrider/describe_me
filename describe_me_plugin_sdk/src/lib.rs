#![forbid(unsafe_code)]

//! SDK minimal pour construire des extensions `describe-me`.
//!
//! # Exemple
//! ```
//! use describe_me_plugin_sdk::{describe_me_plugin_main, Plugin, PluginError, PluginOutput};
//!
//! #[derive(Default)]
//! struct Demo;
//!
//! impl Plugin for Demo {
//!     fn name(&self) -> &'static str {
//!         "demo"
//!     }
//!
//!     fn collect(&self) -> Result<PluginOutput, PluginError> {
//!         let mut out = PluginOutput::new();
//!         out.insert("status", "ok");
//!         Ok(out)
//!     }
//! }
//!
//! describe_me_plugin_main!(Demo);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use thiserror::Error;

/// Objet sérialisable renvoyé par un plugin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginOutput {
    values: BTreeMap<String, Value>,
}

impl PluginOutput {
    /// Crée une sortie vide.
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Nombre de paires clé/valeur.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Indique si la sortie est vide.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Ajoute ou remplace une entrée arbitraire.
    pub fn insert<V>(&mut self, key: impl Into<String>, value: V)
    where
        V: Into<Value>,
    {
        self.values.insert(key.into(), value.into());
    }

    /// Fusionne une autre sortie (les dernières valeurs gagnent).
    pub fn extend(&mut self, other: impl IntoIterator<Item = (String, Value)>) {
        self.values.extend(other);
    }

    /// Accès lecture seule à la carte interne.
    pub fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.values
    }
}

impl FromIterator<(String, Value)> for PluginOutput {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        let mut out = PluginOutput::new();
        out.extend(iter);
        out
    }
}

/// Contexte injecté via les variables d'environnement par `describe-me`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchContext {
    pub host: String,
    pub plugin_name: String,
    pub token: String,
    pub proto: String,
}

impl LaunchContext {
    /// Charge le contexte à partir des variables d'environnement obligatoires.
    pub fn from_env() -> Result<Self, PluginError> {
        Ok(Self {
            host: read_launch_var("DESCRIBE_ME_HOST")?,
            plugin_name: read_launch_var("DESCRIBE_ME_PLUGIN_NAME")?,
            token: read_launch_var("DESCRIBE_ME_PLUGIN_TOKEN")?,
            proto: read_launch_var("DESCRIBE_ME_PLUGIN_PROTO")?,
        })
    }

    fn validate_for(&self, plugin_name: &str) -> Result<(), PluginError> {
        if self.host != "describe_me" {
            return Err(PluginError::msg("lançeur inconnu"));
        }
        if self.proto != "v1" {
            return Err(PluginError::msg("proto plugin non supporté"));
        }
        if self.token.is_empty() {
            return Err(PluginError::msg("jeton d'initialisation manquant"));
        }
        if self.plugin_name != plugin_name {
            return Err(PluginError::msg("nom de plugin inattendu"));
        }
        Ok(())
    }
}

fn read_launch_var(key: &str) -> Result<String, PluginError> {
    env::var(key).map_err(|_| PluginError::msg(format!("{key} requis")))
}

/// Erreur déclarée par un plugin durant `collect`.
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("{0}")]
    Message(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl PluginError {
    /// Crée une erreur textuelle simple.
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

/// Trait minimal à implémenter pour exposer un plugin.
pub trait Plugin {
    /// Nom du plugin (utilisé côté describe-me pour namespacer la sortie).
    fn name(&self) -> &'static str;

    /// Collecte les métriques et renvoie un résultat sérialisable.
    fn collect(&self) -> Result<PluginOutput, PluginError>;
}

/// Erreur retournée par le lanceur/macro si la collecte échoue.
#[derive(Debug, Error)]
pub enum PluginRuntimeError {
    #[error("{0}")]
    Collect(#[from] PluginError),
    #[error("plugin launch error: {0}")]
    Launch(String),
    #[error("write error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

fn run_plugin_instance<P: Plugin>(plugin: P) -> Result<(), PluginRuntimeError> {
    let ctx = LaunchContext::from_env()
        .map_err(|err| PluginRuntimeError::Launch(err.to_string()))?;
    let plugin_name = plugin.name();
    ctx.validate_for(plugin_name)
        .map_err(|err| PluginRuntimeError::Launch(err.to_string()))?;
    let output = plugin.collect()?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    stdout.flush()?;
    Ok(())
}

fn report_and_exit(error: PluginRuntimeError) -> ! {
    eprintln!("describe-me plugin error: {error}");
    std::process::exit(1);
}

#[doc(hidden)]
pub fn launch_plugin<P, F>(factory: F) -> !
where
    P: Plugin,
    F: FnOnce() -> P,
{
    let plugin = factory();
    match run_plugin_instance(plugin) {
        Ok(()) => std::process::exit(0),
        Err(err) => report_and_exit(err),
    }
}

/// Macro pour générer un `main` minimal autour d'un plugin.
///
/// Deux formes sont disponibles :
/// - `describe_me_plugin_main!(MyPlugin)` : instancie `MyPlugin::default()`
/// - `describe_me_plugin_main!(|| MyPlugin::new(arg))` : expression qui renvoie un plugin.
#[macro_export]
macro_rules! describe_me_plugin_main {
    ($plugin_ty:ty) => {
        fn main() {
            $crate::launch_plugin::<$plugin_ty, _>(|| <$plugin_ty>::default());
        }
    };
    ($factory:expr) => {
        fn main() {
            $crate::launch_plugin::<_, _>($factory);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct DemoPlugin;

    impl Plugin for DemoPlugin {
        fn name(&self) -> &'static str {
            "demo"
        }

        fn collect(&self) -> Result<PluginOutput, PluginError> {
            let mut output = PluginOutput::new();
            output.insert("status", "ok");
            output.insert("count", 2);
            Ok(output)
        }
    }

    #[test]
    fn plugin_output_serializes_in_key_order() {
        let mut output = PluginOutput::new();
        output.insert("zeta", 1);
        output.insert("alpha", 2);
        let json = serde_json::to_string(&output).expect("serialize");
        assert_eq!(json, r#"{"alpha":2,"zeta":1}"#);
    }

    #[test]
    fn run_plugin_instance_writes_json() {
        let plugin = DemoPlugin::default();
        let json = serde_json::to_string(&plugin.collect().unwrap()).unwrap();
        assert!(json.contains("\"status\""));
    }

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn with_launch_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_GUARD.lock().unwrap();
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), std::env::var(key).ok()))
            .collect();
        for (key, value) in vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (key, value) in saved {
            if let Some(val) = value {
                std::env::set_var(&key, val);
            } else {
                std::env::remove_var(&key);
            }
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn launch_context_reads_env() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("describe_me")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", Some("deadbeef")),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                let ctx = LaunchContext::from_env().unwrap();
                assert_eq!(ctx.plugin_name, "demo");
            },
        );
    }

    #[test]
    fn launch_context_errors_when_missing_var() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("describe_me")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", None),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                assert!(LaunchContext::from_env().is_err());
            },
        );
    }

    #[test]
    fn run_plugin_instance_rejects_missing_handshake() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", None),
                ("DESCRIBE_ME_PLUGIN_NAME", None),
                ("DESCRIBE_ME_PLUGIN_TOKEN", None),
                ("DESCRIBE_ME_PLUGIN_PROTO", None),
            ],
            || {
                let err = run_plugin_instance(DemoPlugin::default()).unwrap_err();
                assert!(matches!(err, PluginRuntimeError::Launch(_)));
            },
        );
    }

    #[test]
    fn run_plugin_instance_accepts_valid_handshake() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("describe_me")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", Some("0123456789abcdef")),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                run_plugin_instance(DemoPlugin::default()).unwrap();
            },
        );
    }
}
