#[cfg(feature = "config")]
pub mod config;
pub mod error;
pub mod model;

#[cfg(feature = "config")]
pub use config::{DescribeConfig, ServiceSelection};
pub use error::DescribeError;
pub use model::{
    CaptureOptions,
    DiskPartition,
    DiskUsage, // <-- NEW
    ServiceInfo,
    SystemSnapshot,
};
