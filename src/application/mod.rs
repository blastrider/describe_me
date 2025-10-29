#[cfg(any(feature = "systemd", feature = "config"))]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, DiskUsage, SystemSnapshot};
use std::time::Instant;
use tracing::{debug, error};

impl SystemSnapshot {
    pub fn capture() -> Result<Self, DescribeError> {
        Self::capture_with(CaptureOptions::default())
    }

    pub fn capture_with(opts: CaptureOptions) -> Result<Self, DescribeError> {
        let started_at = Instant::now();
        let base = crate::infrastructure::sysinfo::gather().map_err(|err| {
            error!(r#where = "gather", error = %err, "system_error");
            err
        })?;
        let disk_usage = if opts.with_disk_usage {
            Some(
                crate::infrastructure::sysinfo::gather_disks().map_err(|err| {
                    error!(r#where = "gather_disks", error = %err, "system_error");
                    err
                })?,
            )
        } else {
            None
        };

        #[cfg(feature = "systemd")]
        let services_running: Vec<ServiceInfo> = if opts.with_services {
            crate::infrastructure::systemd::list_systemd_services().map_err(|err| {
                error!(r#where = "systemctl", error = %err, "system_error");
                err
            })?
        } else {
            Vec::new()
        };

        let snapshot = SystemSnapshot {
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
        };

        let duration = started_at.elapsed();
        let disk = snapshot.disk_usage.as_ref();
        debug!(
            duration_ms = duration.as_millis(),
            cpu = snapshot.cpu_count,
            mem_used = snapshot.used_memory_bytes,
            mem_total = snapshot.total_memory_bytes,
            disk_total = disk.map(|du| du.total_bytes),
            disk_avail = disk.map(|du| du.available_bytes),
            disk_partitions = disk.map(|du| du.partitions.len()),
            "snapshot_captured"
        );

        Ok(snapshot)
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
    let path_ref = path.as_ref();
    let data = std::fs::read_to_string(path_ref).map_err(|e| {
        tracing::error!(
            path = %path_ref.display(),
            error = %e,
            "config_error"
        );
        DescribeError::Config(format!("read {}: {e}", path_ref.display()))
    })?;
    toml::from_str::<DescribeConfig>(&data).map_err(|e| {
        tracing::error!(
            path = %path_ref.display(),
            error = %e,
            "config_error"
        );
        DescribeError::Config(format!("toml parse: {e}"))
    })
}

/// Filtre une liste de services selon la config.
/// Si pas de config ou pas de `services.include`, retourne la liste telle quelle.
#[cfg(feature = "config")]
pub fn filter_services(services: Vec<ServiceInfo>, cfg: &DescribeConfig) -> Vec<ServiceInfo> {
    if let Some(sel) = &cfg.services {
        if !sel.include.is_empty() {
            use std::collections::HashMap;

            let mut by_name: HashMap<String, ServiceInfo> = services
                .into_iter()
                .map(|svc| (svc.name.clone(), svc))
                .collect();
            let mut filtered = Vec::with_capacity(sel.include.len());

            for name in &sel.include {
                if let Some(svc) = by_name.remove(name) {
                    filtered.push(svc);
                } else {
                    filtered.push(ServiceInfo {
                        name: name.clone(),
                        state: "inactif".into(),
                        summary: None,
                    });
                }
            }
            return filtered;
        }
    }
    services
}

#[cfg(feature = "net")]
mod net;

#[cfg(feature = "net")]
pub use net::net_listen;

#[cfg(feature = "web")]
pub mod web;

pub mod health;

pub mod exposure;
pub mod logging;
