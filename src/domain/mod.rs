#[cfg(feature = "config")]
pub mod config;
pub mod error;
pub mod model;

#[cfg(feature = "config")]
pub use config::{
    BruteForceConfig, DescribeConfig, ExposureConfig, RouteLimitConfig, ServiceSelection,
    SseLimitConfig, WebAccessConfig, WebSecurityConfig,
};
pub use error::DescribeError;
pub use model::{
    CaptureOptions,
    DiskPartition,
    DiskUsage, // <-- NEW
    ServiceInfo,
    SystemSnapshot,
};

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    /// "tcp" ou "udp"
    pub proto: String,
    /// Adresse locale (ex: "127.0.0.1" ou "0.0.0.0")
    pub addr: String,
    /// Port local
    pub port: u16,
    /// PID propriétaire si résolu
    pub process: Option<u32>,
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
