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
    /// Exposition des champs sensibles pour la sortie JSON.
    pub exposure: Option<ExposureConfig>,
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
    /// Jeton requis (Authorization: Bearer ou en-tête `x-describe-me-token`).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: "192.0.2.5", "10.0.0.0/16", "::1").
    pub allow_ips: Vec<String>,
    /// Exposition des champs sensibles côté web (--web).
    pub exposure: Option<ExposureConfig>,
}

/// Contrôle fin des champs JSON sensibles.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ExposureConfig {
    /// Autoriser l'exposition du hostname exact.
    pub expose_hostname: bool,
    /// Autoriser l'exposition des informations d'OS.
    pub expose_os: bool,
    /// Autoriser l'exposition de la version complète du noyau.
    pub expose_kernel: bool,
    /// Autoriser la liste détaillée des services systemd.
    pub expose_services: bool,
    /// Autoriser le détail des partitions disque (points de montage, fs, ...).
    pub expose_disk_partitions: bool,
}
