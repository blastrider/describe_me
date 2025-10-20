#[cfg(any(feature = "systemd", feature = "config"))]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, DiskUsage, SystemSnapshot};

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

/// Calcule l’espace disque agrégé + partitions.
pub fn disk_usage() -> Result<DiskUsage, DescribeError> {
    crate::infrastructure::sysinfo::gather_disks()
}

#[cfg(feature = "config")]
use crate::domain::DescribeConfig;

#[cfg(feature = "config")]
pub fn load_config_from_path<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<DescribeConfig, DescribeError> {
    let data = std::fs::read_to_string(path.as_ref())
        .map_err(|e| DescribeError::Config(format!("read {}: {e}", path.as_ref().display())))?;
    toml::from_str::<DescribeConfig>(&data)
        .map_err(|e| DescribeError::Config(format!("toml parse: {e}")))
}

/// Filtre une liste de services selon la config.
/// Si pas de config ou pas de `services.include`, retourne la liste telle quelle.
#[cfg(feature = "config")]
pub fn filter_services(mut services: Vec<ServiceInfo>, cfg: &DescribeConfig) -> Vec<ServiceInfo> {
    if let Some(sel) = &cfg.services {
        if !sel.include.is_empty() {
            let allow: std::collections::HashSet<_> =
                sel.include.iter().map(|s| s.as_str()).collect();
            services.retain(|s| allow.contains(s.name.as_str()));
        }
    }
    services
}
