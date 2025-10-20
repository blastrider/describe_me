pub mod model;
pub mod error;

pub use error::DescribeError;
pub use model::{
    CaptureOptions, ServiceInfo, SystemSnapshot,
    DiskPartition, DiskUsage, // <-- NEW
};