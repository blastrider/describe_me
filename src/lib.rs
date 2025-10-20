//! describe_me — bibliothèque pour décrire rapidement un serveur.
//!
//! # Examples
//! ```rust
//! use describe_me::SystemSnapshot;
//! let snap = SystemSnapshot::capture().expect("snapshot");
//! assert!(snap.cpu_count >= 1);
//! ```

#![forbid(unsafe_code)]

mod application;
pub mod domain;
mod infrastructure;

pub use domain::{
    CaptureOptions,
    DescribeError,
    DiskPartition,
    DiskUsage, // <-- NEW
    ServiceInfo,
    SystemSnapshot,
};

#[cfg(feature = "config")]
pub use domain::{DescribeConfig, ServiceSelection};

// API fonctionnelle pour l’espace disque
pub use application::disk_usage;

#[cfg(feature = "config")]
pub use application::{filter_services, load_config_from_path};

// Outils de test/fuzz internes
#[cfg(all(feature = "systemd", any(test, feature = "internals")))]
pub mod internals {
    pub use crate::infrastructure::systemd::__parse_systemctl_line_for_tests;
}
