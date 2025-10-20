use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot, DiskUsage};
#[cfg(feature = "systemd")]
use crate::domain::ServiceInfo;

impl SystemSnapshot {
    pub fn capture() -> Result<Self, DescribeError> {
        Self::capture_with(CaptureOptions::default())
    }

    pub fn capture_with(opts: CaptureOptions) -> Result<Self, DescribeError> {
        let base = crate::infrastructure::sysinfo::gather()?;
        let disk_usage = if opts.with_disk_usage {
            Some(crate::infrastructure::sysinfo::gather_disks()?)
        } else {
            None
        };

        #[cfg(feature = "systemd")]
        let services_running: Vec<ServiceInfo> = if opts.with_services {
            crate::infrastructure::systemd::list_systemd_services()?
        } else {
            Vec::new()
        };

        Ok(SystemSnapshot {
            hostname: base.hostname,
            os: base.os,
            kernel: base.kernel,
            uptime_seconds: base.uptime_seconds,
            cpu_count: base.cpu_count,
            load_average: base.load_average,
            total_memory_bytes: base.total_memory_bytes,
            used_memory_bytes: base.used_memory_bytes,
            total_swap_bytes: base.total_swap_bytes,
            used_swap_bytes: base.used_swap_bytes,
            disk_usage,
            #[cfg(feature = "systemd")]
            services_running,
        })
    }
}

/// Calcule l’espace disque agrégé + détail par partition.
pub fn disk_usage() -> Result<DiskUsage, DescribeError> {
    crate::infrastructure::sysinfo::gather_disks()
}
