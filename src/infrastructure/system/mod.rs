use crate::application::AppContext;
use crate::domain::{DescribeError, DiskUsage};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::infrastructure::sysinfo::{gather, gather_disks, SysinfoSnapshot};

/// Base metrics for the host (hostname, load, memory...).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) type SystemMetrics = SysinfoSnapshot;

/// Placeholder type for future non-Linux/FreeBSD backends.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
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
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let _ = ctx;
        gather()
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = ctx;
        Err(crate::unsupported_feature!("system_metrics"))
    }
}

/// Collects disk usage/partitions.
pub(crate) fn collect_disks(ctx: &AppContext) -> Result<DiskUsage, DescribeError> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let _ = ctx;
        gather_disks()
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = ctx;
        Err(crate::unsupported_feature!("disk_usage"))
    }
}
