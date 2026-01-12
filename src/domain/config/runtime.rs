#[cfg(feature = "serde")]
use serde::Deserialize;

/// Paramètres runtime supplémentaires (logging, CLI).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RuntimeConfig {
    /// Valeur à appliquer pour la variable d'environnement RUST_LOG.
    pub rust_log: Option<String>,
    /// Valeurs par défaut pour la CLI.
    pub cli: Option<CliDefaults>,
    /// Autorise l'application des drapeaux `expose-*`/`web-expose-*` depuis la configuration.
    /// Priorité: CLI > runtime.allow_config_exposure > ENV DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE.
    pub allow_config_exposure: bool,
    /// Répertoire personnalisé pour les données persistées (metadata.redb).
    pub state_dir: Option<String>,
}

/// Valeurs par défaut pour la CLI.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct CliDefaults {
    /// Valeur par défaut pour --web (ADDR:PORT).
    pub web: Option<String>,
    /// Active --with-services si true.
    pub with_services: Option<bool>,
    /// Active --with-containers si true.
    pub with_containers: Option<bool>,
    /// Active --web-expose-all si true.
    pub web_expose_all: Option<bool>,
    /// Valeurs par défaut pour --web-allow-ip.
    pub web_allow_ip: Vec<String>,
    /// Valeurs par défaut pour --web-allow-origin.
    pub web_allow_origin: Vec<String>,
    /// Valeurs par défaut pour --web-trusted-proxy.
    pub web_trusted_proxy: Vec<String>,
}
