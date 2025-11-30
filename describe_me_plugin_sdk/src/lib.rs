#![forbid(unsafe_code)]

//! SDK minimal pour construire des extensions `describe-me`.
//!
//! # Exemple rapide (entrée unique)
//! ```no_run
//! use describe_me_plugin_sdk::{run_plugin, PluginConfig, PluginOutput, PluginResult};
//!
//! fn main() {
//!     run_plugin(PluginConfig::new("demo"), |_ctx| {
//!         // |_ctx| contient le LaunchContext validé (env DESCRIBE_ME_*).
//!         Ok(PluginOutput::new().with("status", "ok"))
//!     });
//! }
//! ```
//!
//! L’API historique `Plugin` + `describe_me_plugin_main!` reste disponible, mais
//! `run_plugin` est le chemin recommandé pour écrire un plugin Rust minimal.
//!
//! ## Protocole minimal (interopération autre langage)
//! - Le lanceur `describe_me` fournit via l’environnement : `DESCRIBE_ME_HOST`
//!   (toujours `describe_me`), `DESCRIBE_ME_PLUGIN_NAME`, `DESCRIBE_ME_PLUGIN_PROTO`
//!   (`v1`) et `DESCRIBE_ME_PLUGIN_TOKEN` (non vide).
//! - Le plugin répond sur `stdout` avec un objet JSON (clé/valeur) dont le
//!   contenu est libre et namespacé par le nom du plugin côté host.
//! - Toute erreur doit être écrite sur `stderr` et provoque un code de sortie
//!   non nul ; les plugins peuvent personnaliser ce code pour signaler des cas
//!   « soft » ou « hard ».

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use thiserror::Error;

/// Objet sérialisable renvoyé par un plugin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
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

    /// Ajoute une entrée et renvoie `self` pour chaîner les appels.
    pub fn with<V>(mut self, key: impl Into<String>, value: V) -> Self
    where
        V: Into<Value>,
    {
        self.insert(key, value);
        self
    }

    /// Sérialise une structure arbitraire et l'ajoute sous une clé dédiée.
    pub fn try_with_serialized<T>(
        mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<Self, serde_json::Error>
    where
        T: Serialize,
    {
        self.insert(key, serde_json::to_value(value)?);
        Ok(self)
    }

    /// Raccourci pour publier une version de contrat.
    pub fn with_version(mut self, version: impl Into<Value>) -> Self {
        self.insert("version", version);
        self
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

/// Paramétrage minimal attendu lors du lancement d’un plugin.
#[derive(Debug, Clone, Copy)]
pub struct PluginConfig<'a> {
    pub expected_host: &'a str,
    pub expected_proto: &'a str,
    pub expected_name: &'a str,
    pub require_token: bool,
    pub error_prefix: &'a str,
    pub default_exit_code: i32,
}

impl<'a> PluginConfig<'a> {
    /// Construit une configuration avec les valeurs par défaut de `describe-me`.
    pub fn new(expected_name: &'a str) -> Self {
        Self {
            expected_host: "describe_me",
            expected_proto: "v1",
            expected_name,
            require_token: true,
            error_prefix: expected_name,
            default_exit_code: 1,
        }
    }

    /// Personnalise le préfixe des erreurs écrites sur stderr.
    pub fn with_error_prefix(mut self, prefix: &'a str) -> Self {
        self.error_prefix = prefix;
        self
    }

    /// Autorise (ou non) l’absence de token.
    pub fn with_require_token(mut self, require_token: bool) -> Self {
        self.require_token = require_token;
        self
    }

    /// Définit le code de sortie utilisé pour les erreurs « infrastructure » (handshake, I/O).
    pub fn with_default_exit_code(mut self, exit_code: i32) -> Self {
        self.default_exit_code = exit_code;
        self
    }
}

/// Résultat standard d'une collecte de plugin.
pub type PluginResult<T> = Result<T, PluginErrorReport>;

/// Rapport d'erreur prêt à être converti en code de sortie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginErrorReport {
    message: String,
    exit_code: i32,
}

impl PluginErrorReport {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = exit_code;
        self
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl<E> From<E> for PluginErrorReport
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(err: E) -> Self {
        PluginErrorReport::new(err.to_string())
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

/// Erreurs détectées lors de la validation du contexte d’exécution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LaunchError {
    #[error("lançeur inconnu (attendu {expected}, reçu {found})")]
    UnexpectedHost { expected: String, found: String },
    #[error("proto plugin non supporté (attendu {expected}, reçu {found})")]
    UnexpectedProto { expected: String, found: String },
    #[error("jeton d'initialisation manquant")]
    MissingToken,
    #[error("nom de plugin inattendu (attendu {expected}, reçu {found})")]
    UnexpectedName { expected: String, found: String },
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

    /// Valide le contexte selon une configuration d’attentes.
    pub fn validate(&self, cfg: &PluginConfig<'_>) -> Result<(), LaunchError> {
        if self.host != cfg.expected_host {
            return Err(LaunchError::UnexpectedHost {
                expected: cfg.expected_host.to_string(),
                found: self.host.clone(),
            });
        }
        if self.proto != cfg.expected_proto {
            return Err(LaunchError::UnexpectedProto {
                expected: cfg.expected_proto.to_string(),
                found: self.proto.clone(),
            });
        }
        if cfg.require_token && self.token.trim().is_empty() {
            return Err(LaunchError::MissingToken);
        }
        if self.plugin_name != cfg.expected_name {
            return Err(LaunchError::UnexpectedName {
                expected: cfg.expected_name.to_string(),
                found: self.plugin_name.clone(),
            });
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

fn serialize_payload<T: Serialize>(value: T) -> Result<Vec<u8>, PluginErrorReport> {
    serde_json::to_vec(&value).map_err(PluginErrorReport::from)
}

fn run_plugin_once<F, T>(config: PluginConfig<'_>, handler: F) -> Result<Vec<u8>, PluginErrorReport>
where
    F: FnOnce(LaunchContext) -> PluginResult<T>,
    T: Serialize,
{
    let ctx = LaunchContext::from_env()
        .map_err(|err| PluginErrorReport::new(err.to_string()).with_exit_code(config.default_exit_code))?;
    ctx.validate(&config)
        .map_err(|err| PluginErrorReport::new(err.to_string()).with_exit_code(config.default_exit_code))?;
    let payload = handler(ctx)?;
    serialize_payload(payload).map_err(|err| err.with_exit_code(config.default_exit_code))
}

fn run_plugin_with_io<F, T, W, E>(
    config: PluginConfig<'_>,
    handler: F,
    mut stdout: W,
    mut stderr: E,
) -> i32
where
    F: FnOnce(LaunchContext) -> PluginResult<T>,
    T: Serialize,
    W: Write,
    E: Write,
{
    match run_plugin_once(config, handler) {
        Ok(bytes) => {
            if let Err(err) = stdout.write_all(&bytes) {
                let _ = writeln!(stderr, "{}: {}", config.error_prefix, err);
                return config.default_exit_code;
            }
            if let Err(err) = stdout.flush() {
                let _ = writeln!(stderr, "{}: {}", config.error_prefix, err);
                return config.default_exit_code;
            }
            0
        }
        Err(report) => {
            let _ = writeln!(stderr, "{}: {}", config.error_prefix, report.message());
            report.exit_code()
        }
    }
}

/// Entrée standard d’un plugin Rust : lit/valide le contexte puis sérialise la sortie sur stdout.
pub fn run_plugin<F, T>(config: PluginConfig<'_>, handler: F) -> !
where
    F: FnOnce(LaunchContext) -> PluginResult<T>,
    T: Serialize,
{
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = run_plugin_with_io(config, handler, &mut stdout, &mut stderr);
    std::process::exit(code);
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
    ctx.validate(&PluginConfig::new(plugin_name))
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
    fn plugin_output_helpers_chain_values() {
        let output = PluginOutput::new()
            .with_version(2)
            .with("status", "ok")
            .try_with_serialized("nested", serde_json::json!({"a": 1}))
            .expect("serialize nested");
        let map = output.as_map();
        assert_eq!(map.get("version").cloned(), Some(serde_json::json!(2)));
        assert_eq!(map.get("status").cloned(), Some(serde_json::json!("ok")));
        assert_eq!(
            map.get("nested").cloned(),
            Some(serde_json::json!({"a": 1}))
        );
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
    fn launch_context_validation_detects_mismatch() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("describe_me")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", Some("deadbeef")),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                let ctx = LaunchContext::from_env().unwrap();
                assert!(ctx.validate(&PluginConfig::new("demo")).is_ok());
                let err = ctx.validate(&PluginConfig::new("other")).unwrap_err();
                assert!(matches!(err, LaunchError::UnexpectedName { .. }));
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

    #[test]
    fn run_plugin_reports_validation_error() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("other")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", Some("deadbeef")),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code = run_plugin_with_io(
                    PluginConfig::new("demo"),
                    |_ctx| Ok(PluginOutput::new().with("status", "ok")),
                    &mut stdout,
                    &mut stderr,
                );
                assert_eq!(code, 1);
                assert!(stdout.is_empty());
                let stderr_str = String::from_utf8_lossy(&stderr);
                assert!(stderr_str.contains("lançeur inconnu"));
            },
        );
    }

    #[test]
    fn run_plugin_writes_json_on_success() {
        with_launch_env(
            &[
                ("DESCRIBE_ME_HOST", Some("describe_me")),
                ("DESCRIBE_ME_PLUGIN_NAME", Some("demo")),
                ("DESCRIBE_ME_PLUGIN_TOKEN", Some("deadbeef")),
                ("DESCRIBE_ME_PLUGIN_PROTO", Some("v1")),
            ],
            || {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code = run_plugin_with_io(
                    PluginConfig::new("demo").with_error_prefix("demo"),
                    |_ctx| Ok(PluginOutput::new().with("status", "ok")),
                    &mut stdout,
                    &mut stderr,
                );
                assert_eq!(code, 0);
                assert!(stderr.is_empty());
                let json: serde_json::Value =
                    serde_json::from_slice(&stdout).expect("valid json");
                assert_eq!(json["status"], "ok");
            },
        );
    }
}
