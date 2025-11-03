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
mod shared;

pub use domain::{
    CaptureOptions, DescribeError, DiskPartition, DiskUsage, NetworkInterfaceTraffic, ServiceInfo,
    SystemSnapshot, UpdatePackage, UpdatesInfo,
};

#[cfg(feature = "config")]
pub use domain::{DescribeConfig, ServiceSelection};

// API fonctionnelle
pub use application::disk_usage;

#[cfg(feature = "config")]
pub use application::{filter_services, load_config_from_path};

#[cfg(feature = "net")]
pub use application::{net_listen, network_traffic}; // <— NEW

// Outils de test/fuzz internes
#[cfg(all(feature = "systemd", any(test, feature = "internals")))]
pub mod internals {
    pub use crate::infrastructure::systemd::__parse_systemctl_line_for_tests;
}

#[cfg(feature = "web")]
pub use application::web::{serve_http, WebAccess};

pub use application::health::{eval_checks, parse_check, Severity};

pub use application::exposure::Exposure;

pub use application::logging::{init_logging, LogEvent};

#[cfg(feature = "serde")]
pub use application::capture_snapshot_with_view;
#[cfg(feature = "serde")]
pub use application::exposure::SnapshotView;

pub use shared::SharedSlice;
