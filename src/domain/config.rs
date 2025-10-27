#[cfg(feature = "serde")]
use serde::Deserialize;

/// Configuration haut-niveau.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct DescribeConfig {
    /// Sélection des services à afficher (si `with_services = true`).
    pub services: Option<ServiceSelection>,
    /// Contrôles d'accès pour le mode web (--web).
    pub web: Option<WebAccessConfig>,
}

/// Sélection des services (liste blanche simple).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ServiceSelection {
    /// Noms exacts systemd à inclure (ex: "sshd.service").
    pub include: Vec<String>,
}

/// Contrôles d'accès pour le mode web (--web).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct WebAccessConfig {
    /// Jeton requis (Authorization Bearer ou paramètre `token`).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: "192.0.2.5", "10.0.0.0/16", "::1").
    pub allow_ips: Vec<String>,
}
