//! describe_me — bibliothèque pour décrire rapidement un serveur.
//!
//! # Examples
//! ```rust
//! use describe_me::SystemSnapshot;
//! let snap = SystemSnapshot::capture().expect("snapshot");
//! assert!(snap.cpu_count >= 1);
//! ```

#![forbid(unsafe_code)]

pub mod domain;
mod application;
mod infrastructure;

pub use domain::{
    CaptureOptions, DescribeError, ServiceInfo, SystemSnapshot,
    DiskPartition, DiskUsage, // <-- NEW
};

// API fonctionnelle pour l’espace disque
pub use application::disk_usage;

// Outils de test/fuzz internes
#[cfg(all(feature = "systemd", any(test, feature = "internals")))]
pub mod internals {
    pub use crate::infrastructure::systemd::__parse_systemctl_line_for_tests;
}
