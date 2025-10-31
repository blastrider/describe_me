#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServiceInfo {
    pub name: String,
    pub state: String,
    pub summary: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SystemSnapshot {
    pub hostname: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub uptime_seconds: u64,
    pub cpu_count: usize,
    pub load_average: (f64, f64, f64),
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    /// Usage disque agrégé + détail (optionnel pour limiter le coût).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub disk_usage: Option<DiskUsage>,
    #[cfg(feature = "systemd")]
    pub services_running: Vec<crate::domain::model::ServiceInfo>,
    #[cfg(feature = "net")]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub listening_sockets: Option<Vec<crate::domain::ListeningSocket>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureOptions {
    pub with_services: bool,
    pub with_disk_usage: bool,
    pub with_listening_sockets: bool,
}

/// Une partition/point de montage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DiskPartition {
    /// Point de montage (ex: `/`, `/home`…)
    pub mount_point: String,
    /// Type de FS si disponible (ex: `ext4`, `xfs`…)
    pub fs_type: Option<String>,
    /// Espace total en octets.
    pub total_bytes: u64,
    /// Espace disponible pour l’utilisateur en octets.
    pub available_bytes: u64,
}

/// Agrégat d’espace disque.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DiskUsage {
    /// Somme des partitions visibles.
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    /// Détail par partition.
    pub partitions: Vec<DiskPartition>,
}
