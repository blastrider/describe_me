use crate::application::AppContext;
use crate::domain::{DescribeError, DiskUsage};

#[cfg(target_os = "linux")]
use crate::infrastructure::sysinfo::{gather, gather_disks, SysinfoSnapshot};

/// Base metrics for the host (hostname, load, memory...).
#[cfg(target_os = "linux")]
pub(crate) type SystemMetrics = SysinfoSnapshot;

/// Placeholder type for future non-Linux backends.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct SystemMetrics {
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
}

/// Collects system-level metrics using the platform backend.
pub(crate) fn collect_system_metrics(ctx: &AppContext) -> Result<SystemMetrics, DescribeError> {
    #[cfg(target_os = "linux")]
    {
        let _ = ctx;
        gather()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "system metrics collection not implemented for this OS",
        ))
    }
}

/// Collects disk usage/partitions.
pub(crate) fn collect_disks(ctx: &AppContext) -> Result<DiskUsage, DescribeError> {
    #[cfg(target_os = "linux")]
    {
        let _ = ctx;
        // Linux-only: relies on sysinfo + /proc/self/mountinfo for deduplication.
        gather_disks()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "disk usage collection not implemented for this OS",
        ))
    }
}
