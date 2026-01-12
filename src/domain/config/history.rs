#[cfg(feature = "serde")]
use serde::Deserialize;

use super::super::history_profile::HistoryProfile;

/// Configuration de l'historique persistant (mini time-series).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct HistoryConfig {
    /// Active l'enregistrement des snapshots dans l'historique.
    pub enabled: bool,
    /// Profil préconfiguré (default, ops, paranoid).
    pub profile: Option<HistoryProfile>,
    /// Nombre maximal de points conservés par serveur.
    pub retention_points: Option<u32>,
    /// Fenêtre maximale autorisée par requête (secondes).
    pub max_window_seconds: Option<u32>,
    /// Arrondi appliqué aux timestamps pour les tendances (secondes).
    pub rounding_seconds: Option<u64>,
    /// Force un stockage purement mémoire (pas d'écriture disque).
    pub in_memory_only: bool,
    /// Applique les garde-fous paranoïaques (quotas réduits, pas d'exposition UI).
    pub paranoid: bool,
}
