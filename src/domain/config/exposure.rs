#[cfg(feature = "serde")]
use serde::Deserialize;

/// Contrôle fin des champs JSON sensibles.
#[derive(Debug, Clone)]
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
    /// Autoriser la liste des sockets en écoute.
    pub expose_listening_sockets: bool,
    /// Autoriser l'exposition du trafic réseau par interface.
    pub expose_network_traffic: bool,
    /// Autoriser le résumé des conteneurs (totaux).
    pub expose_containers_summary: bool,
    /// Autoriser le détail des conteneurs (nom, IP, image).
    pub expose_containers_details: bool,
    /// Autoriser l'exposition des informations de mises à jour.
    pub expose_updates: bool,
    /// Autoriser l'exposition des extensions/plugins.
    pub expose_extensions: bool,
    /// Fournir des valeurs masquées (versions tronquées) lorsque l'exposition complète est désactivée.
    /// Safe by default; mettre à `false` expose davantage d'informations potentiellement sensibles.
    #[cfg_attr(feature = "serde", serde(default = "ExposureConfig::default_redacted"))]
    pub redacted: bool,
}

impl ExposureConfig {
    const fn default_redacted() -> bool {
        true
    }
}

impl Default for ExposureConfig {
    fn default() -> Self {
        Self {
            expose_hostname: false,
            expose_os: false,
            expose_kernel: false,
            expose_services: false,
            expose_disk_partitions: false,
            expose_listening_sockets: false,
            expose_network_traffic: false,
            expose_containers_summary: false,
            expose_containers_details: false,
            expose_updates: false,
            expose_extensions: false,
            redacted: true,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn expose_updates_defaults_to_false() {
        let cfg: ExposureConfig = toml::from_str("").expect("deserialize default exposure");
        assert!(!cfg.expose_updates);
    }

    #[test]
    fn expose_updates_can_be_enabled() {
        let cfg: ExposureConfig =
            toml::from_str("expose_updates = true").expect("deserialize exposure");
        assert!(cfg.expose_updates);
    }

    #[test]
    fn expose_extensions_defaults_to_false() {
        let cfg: ExposureConfig = toml::from_str("").expect("deserialize default exposure");
        assert!(!cfg.expose_extensions);
    }

    #[test]
    fn expose_extensions_can_be_enabled() {
        let cfg: ExposureConfig =
            toml::from_str("expose_extensions = true").expect("deserialize exposure");
        assert!(cfg.expose_extensions);
    }
}
