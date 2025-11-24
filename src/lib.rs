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

pub use describe_me_plugin_sdk::PluginOutput;
pub use domain::{
    CaptureOptions, DescribeError, DiskPartition, DiskUsage, NetworkInterfaceTraffic, ServiceInfo,
    SystemSnapshot, UpdatePackage, UpdatesInfo,
};

pub use domain::HistoryProfile;
#[cfg(feature = "config")]
pub use domain::{DescribeConfig, ServiceSelection};

// API fonctionnelle
pub use application::disk_usage;
pub use application::history::{
    configure_history, default_server_id as history_default_server_id,
    query_series as history_query_series, settings_snapshot as history_settings_snapshot,
    HistoryMode, HistoryPoint, HistoryQueryError, HistorySeries, HistorySettings, MetricAggregate,
};
pub use application::pagination::{paginate_slice, Page, PageRequest};

#[cfg(feature = "config")]
pub use application::{filter_services, load_config_from_path};

#[cfg(feature = "net")]
pub use application::{net_listen, network_traffic}; // <— NEW

// Outils de test/fuzz internes
#[cfg(any(test, feature = "internals"))]
pub mod internals {
    #[cfg(all(feature = "net", target_os = "linux"))]
    pub use crate::infrastructure::net::linux::parse_table_from_str;
    pub use crate::infrastructure::sysinfo::parse_mountinfo_for_tests;
    #[cfg(feature = "systemd")]
    pub use crate::infrastructure::systemd::__parse_systemctl_line_for_tests;
    #[cfg(target_os = "linux")]
    pub use crate::infrastructure::updates::{
        count_apk_updates_for_tests, count_dnf_updates_for_tests,
        parse_apt_upgradable_line_for_tests,
    };
}

#[cfg(feature = "web")]
pub use application::web::{serve_http, WebAccess, WebTlsConfig};

pub use application::health::{eval_checks, parse_check, Severity};

pub use application::exposure::Exposure;
pub use application::extensions::{run_ad_hoc_plugin, PluginExecutionError};

pub use application::logs::{tail_host_logs, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES};

pub use application::logging::{init_logging, LogEvent};

pub use application::metadata::{
    add_server_tags, clear_server_description, clear_server_tags, load_server_description,
    load_server_tags, override_state_directory, remove_server_tags, set_server_description,
    set_server_tags,
};

#[cfg(feature = "serde")]
pub use application::capture_snapshot_with_view;
#[cfg(feature = "serde")]
pub use application::exposure::SnapshotView;

pub use shared::SharedSlice;
