#[cfg(feature = "config")]
pub mod config;
pub mod error;
pub mod history_dto;
pub mod history_profile;
pub mod model;
pub mod plugin;
pub mod server_metadata;

#[cfg(feature = "config")]
pub use config::{
    BruteForceConfig, CliDefaults, DescribeConfig, ExposureConfig, ExtensionsConfig, HistoryConfig,
    PluginDefinition, RouteLimitConfig, RuntimeConfig, ServiceSelection, SessionCookieSameSite,
    SseLimitConfig, WebAccessConfig, WebSecurityConfig,
};
pub use error::DescribeError;
pub use history_dto::{HistoryMetricDto, HistoryPointDto, HistorySeriesDto};
pub use history_profile::HistoryProfile;
pub use model::{
    CaptureOptions, ContainerInfo, ContainersSnapshot, ContainersSummary, DiskPartition, DiskUsage,
    HostLogEntry, HostLogsPage, NetworkInterfaceTraffic, ServiceInfo, SystemSnapshot,
    UpdatePackage, UpdatesInfo,
};
pub use plugin::{
    is_valid_plugin_name, validate_plugin_name, PluginNameError, PLUGIN_NAME_MAX_LEN,
};
pub use server_metadata::{
    MetadataValidationError, ServerDescription, ServerTag, TagsBatch, DESCRIPTION_MAX_BYTES,
    TAGS_MAX_PER_REQUEST, TAG_LENGTH_LIMIT,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(not(feature = "config"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum SessionCookieSameSite {
    #[default]
    Lax,
    Strict,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ListeningSocket {
    /// "tcp" ou "udp"
    pub proto: String,
    /// Adresse locale (ex: "127.0.0.1" ou "0.0.0.0")
    pub addr: String,
    /// Port local
    pub port: u16,
    /// PID propriétaire si résolu
    pub process: Option<u32>,
    /// Nom du processus si résolu
    pub process_name: Option<String>,
}

impl fmt::Display for ListeningSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pid) = self.process {
            write!(
                f,
                "{} {}:{} (pid {})",
                self.proto, self.addr, self.port, pid
            )
        } else {
            write!(f, "{} {}:{}", self.proto, self.addr, self.port)
        }
    }
}
