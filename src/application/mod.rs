#[cfg(feature = "serde")]
use crate::application::exposure::{Exposure, SnapshotView};
use crate::application::logging::LogEvent;
#[cfg(feature = "config")]
use crate::domain::DescribeConfig;
#[cfg(any(feature = "systemd", feature = "config"))]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, DiskUsage, SystemSnapshot};
#[cfg(any(feature = "systemd", feature = "net"))]
use crate::SharedSlice;
use std::borrow::Cow;
use std::time::Instant;
use tracing::debug;

impl SystemSnapshot {
    pub fn capture() -> Result<Self, DescribeError> {
        Self::capture_with(CaptureOptions::default())
    }

    pub fn capture_with(opts: CaptureOptions) -> Result<Self, DescribeError> {
        let started_at = Instant::now();
        let base = crate::infrastructure::sysinfo::gather().inspect_err(|err| {
            LogEvent::SystemError {
                location: Cow::Borrowed("gather"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
        })?;
        let disk_usage = if opts.with_disk_usage {
            Some(
                crate::infrastructure::sysinfo::gather_disks().inspect_err(|err| {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("gather_disks"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                })?,
            )
        } else {
            None
        };

        #[cfg(feature = "systemd")]
        let services_running = if opts.with_services {
            let list =
                crate::infrastructure::systemd::list_systemd_services().inspect_err(|err| {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("systemctl"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                })?;
            SharedSlice::from_vec(list)
        } else {
            SharedSlice::from_vec(Vec::new())
        };

        #[cfg(feature = "net")]
        let listening_sockets = if opts.with_listening_sockets {
            Some(SharedSlice::from_vec(
                crate::application::net::net_listen().inspect_err(|err| {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("net_listen"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                })?,
            ))
        } else {
            None
        };

        #[cfg(feature = "net")]
        let network_traffic = if opts.with_network_traffic {
            Some(SharedSlice::from_vec(
                crate::application::net::network_traffic().inspect_err(|err| {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("net_traffic"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                })?,
            ))
        } else {
            None
        };

        let updates = if opts.with_updates {
            crate::infrastructure::updates::gather_updates()
        } else {
            None
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
            #[cfg(feature = "net")]
            listening_sockets,
            #[cfg(feature = "net")]
            network_traffic,
            updates,
        };

        let duration = started_at.elapsed();
        let disk = snapshot.disk_usage.as_ref();
        #[cfg(feature = "net")]
        let net_sockets = snapshot.listening_sockets.as_ref().map(|s| s.len());
        #[cfg(not(feature = "net"))]
        let net_sockets: Option<usize> = None;
        #[cfg(feature = "net")]
        let net_interfaces = snapshot.network_traffic.as_ref().map(|t| t.len());
        #[cfg(not(feature = "net"))]
        let net_interfaces: Option<usize> = None;
        let updates_pending = snapshot.updates.as_ref().map(|u| u.pending);
        let updates_reboot = snapshot.updates.as_ref().map(|u| u.reboot_required);
        let updates_packages = snapshot
            .updates
            .as_ref()
            .and_then(|u| u.packages.as_ref().map(|p| p.len()));
        debug!(
            duration_ms = duration.as_millis(),
            cpu = snapshot.cpu_count,
            mem_used = snapshot.used_memory_bytes,
            mem_total = snapshot.total_memory_bytes,
            disk_total = disk.map(|du| du.total_bytes),
            disk_avail = disk.map(|du| du.available_bytes),
            disk_partitions = disk.map(|du| du.partitions.len()),
            net_sockets,
            net_interfaces,
            updates_pending,
            updates_reboot,
            updates_packages,
            "snapshot_captured"
        );

        Ok(snapshot)
    }
}

/// Calcule l’espace disque agrégé + partitions.
pub fn disk_usage() -> Result<DiskUsage, DescribeError> {
    crate::infrastructure::sysinfo::gather_disks()
}

#[cfg(feature = "serde")]
pub fn capture_snapshot_with_view(
    opts: CaptureOptions,
    exposure: Exposure,
    #[cfg(feature = "config")] _cfg: Option<&DescribeConfig>,
) -> Result<(SystemSnapshot, SnapshotView), DescribeError> {
    #[cfg_attr(not(all(feature = "systemd", feature = "config")), allow(unused_mut))]
    let mut snapshot = SystemSnapshot::capture_with(opts)?;

    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = _cfg {
        let services_mut = snapshot.services_running.make_mut();
        let filtered = filter_services(std::mem::take(services_mut), cfg);
        *services_mut = filtered;
    }

    let view = SnapshotView::new(&snapshot, exposure);
    Ok((snapshot, view))
}

#[cfg(feature = "config")]
pub fn load_config_from_path<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<DescribeConfig, DescribeError> {
    let path_ref = path.as_ref();
    let data = std::fs::read_to_string(path_ref).map_err(|e| {
        let msg = e.to_string();
        LogEvent::ConfigError {
            path: Cow::Owned(path_ref.display().to_string()),
            error: Cow::Owned(msg),
        }
        .emit();
        DescribeError::Config(format!("read {}: {e}", path_ref.display()))
    })?;
    toml::from_str::<DescribeConfig>(&data).map_err(|e| {
        let msg = e.to_string();
        LogEvent::ConfigError {
            path: Cow::Owned(path_ref.display().to_string()),
            error: Cow::Owned(msg),
        }
        .emit();
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
pub use net::{net_listen, network_traffic};

#[cfg(feature = "web")]
pub mod web;

pub mod health;

pub mod exposure;
pub mod logging;
