//! Façade officielle de l’API publique du crate.
//! Import recommandé : `use describe_me::api::*;`.
//! Les autres modules peuvent évoluer sans préavis.

pub use crate::application::disk_usage;
pub use crate::application::AppContext;
#[cfg(feature = "config")]
pub use crate::application::{filter_services, load_config_from_path};

#[cfg(feature = "net")]
pub use crate::domain::ListeningSocket;
pub use crate::domain::{
    CaptureOptions, ContainerInfo, ContainersSnapshot, ContainersSummary, DescribeError,
    DiskPartition, DiskUsage, HistoryProfile, HostLogEntry, HostLogsPage, NetworkInterfaceTraffic,
    ServiceInfo, SystemSnapshot, UpdatePackage, UpdatesInfo,
};
#[cfg(feature = "config")]
pub use crate::domain::{DescribeConfig, ServiceSelection};

pub use crate::shared::SharedSlice;
pub use describe_me_plugin_sdk::PluginOutput;

pub use crate::application::history::{
    HistoryMode, HistoryPoint, HistoryQueryError, HistorySeries, HistoryService, HistorySettings,
    MetricAggregate,
};

#[cfg(feature = "serde")]
pub use crate::application::capture_snapshot_with_view;
#[cfg(feature = "serde")]
pub use crate::application::exposure::SnapshotView;
pub use crate::application::exposure::{
    Exposure, ExposureBuilder, ExposureCaptureContext, ExposureOverrides,
};

pub use crate::application::metadata::{
    add_server_tags_with, clear_server_description_with, clear_server_tags_with,
    load_server_description_with, load_server_tags_with, override_state_directory,
    remove_server_tags_with, set_server_description_with, set_server_tags_with,
};

pub use crate::application::health::{eval_checks, parse_check, Severity};

pub use crate::application::logs::{tail_host_logs, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES};

pub use crate::application::logging::{init_logging, LogEvent};

#[cfg(feature = "net")]
pub use crate::application::{net_listen, network_traffic};

#[cfg(feature = "web")]
pub use crate::application::web::{serve_http, WebAccess, WebTlsConfig};

#[cfg(feature = "serde")]
pub use crate::application::containers::{parse_plugin_output, ContainersContractError};
pub use crate::application::containers::{
    ContainersPluginExitCode, CONTAINERS_CONTRACT_VERSION, CONTAINERS_PLUGIN_TIMEOUT,
};
pub use crate::application::extensions::{run_ad_hoc_plugin, PluginExecutionError};

pub use crate::application::pagination::{paginate_slice, Page, PageRequest};
