#[cfg(feature = "serde")]
use serde::Deserialize;

/// Configuration haut-niveau.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct DescribeConfig {
    /// Sélection des services à afficher (si `with_services = true`).
    pub services: Option<ServiceSelection>,
}

/// Sélection des services (liste blanche simple).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ServiceSelection {
    /// Noms exacts systemd à inclure (ex: "sshd.service").
    pub include: Vec<String>,
}
