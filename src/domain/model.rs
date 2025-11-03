use crate::SharedSlice;
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
pub struct UpdatesInfo {
    pub pending: u32,
    pub reboot_required: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub packages: Option<SharedSlice<UpdatePackage>>,
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
    pub services_running: SharedSlice<crate::domain::model::ServiceInfo>,
    #[cfg(feature = "net")]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub listening_sockets: Option<SharedSlice<crate::domain::ListeningSocket>>,
    #[cfg(feature = "net")]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub network_traffic: Option<SharedSlice<crate::domain::NetworkInterfaceTraffic>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub updates: Option<UpdatesInfo>,
}

#[derive(Debug, Clone, Copy)]
pub struct CaptureOptions {
    pub with_services: bool,
    pub with_disk_usage: bool,
    pub with_listening_sockets: bool,
    pub with_network_traffic: bool,
    pub with_updates: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            with_services: false,
            with_disk_usage: false,
            with_listening_sockets: false,
            with_network_traffic: false,
            with_updates: true,
        }
    }
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
    pub partitions: SharedSlice<DiskPartition>,
}

/// Trafic réseau pour une interface donnée.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetworkInterfaceTraffic {
    /// Nom de l'interface (ex: eth0, enp3s0, lo).
    pub name: String,
    /// Octets reçus depuis le démarrage.
    pub rx_bytes: u64,
    /// Paquets reçus.
    pub rx_packets: u64,
    /// Paquets reçus en erreur.
    pub rx_errors: u64,
    /// Paquets reçus et abandonnés.
    pub rx_dropped: u64,
    /// Octets émis.
    pub tx_bytes: u64,
    /// Paquets émis.
    pub tx_packets: u64,
    /// Paquets émis en erreur.
    pub tx_errors: u64,
    /// Paquets émis abandonnés.
    pub tx_dropped: u64,
}

/// Détail d’une mise à jour disponible.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UpdatePackage {
    pub name: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub current_version: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub available_version: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub repository: Option<String>,
}
