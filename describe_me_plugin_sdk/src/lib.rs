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
    #[error("write error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

fn run_plugin_instance<P: Plugin>(plugin: P) -> Result<(), PluginRuntimeError> {
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
}
