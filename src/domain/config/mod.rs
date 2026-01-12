#[cfg(feature = "serde")]
use serde::Deserialize;

mod exposure;
mod extensions;
mod history;
mod limits;
mod runtime;
mod validate;
mod web;

pub use exposure::ExposureConfig;
pub use extensions::{ExtensionsConfig, PluginDefinition};
pub use history::HistoryConfig;
pub use limits::{
    BruteForceConfig, RouteLimitConfig, SessionCookieSameSite, SseLimitConfig, WebSecurityConfig,
};
pub use runtime::{CliDefaults, RuntimeConfig};
pub use web::{WebAccessConfig, WebTlsOptions};

/// Configuration haut-niveau.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct DescribeConfig {
    /// Sélection des services à afficher (si `with_services = true`).
    pub services: Option<ServiceSelection>,
    /// Contrôles d'accès pour le mode web (--web).
    pub web: Option<WebAccessConfig>,
    /// Exposition des champs sensibles pour la sortie JSON.
    pub exposure: Option<ExposureConfig>,
    /// Paramètres runtime (logging, valeurs par défaut CLI).
    pub runtime: Option<RuntimeConfig>,
    /// Plugins/collecteurs additionnels à exécuter sur chaque snapshot.
    pub extensions: Option<ExtensionsConfig>,
    /// Paramétrage de l'historique local (mini time-series).
    pub history: Option<HistoryConfig>,
}

/// Sélection des services (liste blanche simple).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ServiceSelection {
    /// Noms exacts systemd à inclure (ex: "sshd.service").
    pub include: Vec<String>,
}
