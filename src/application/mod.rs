mod collectors;
#[cfg(feature = "config")]
pub mod config;
mod context;
mod history_config;
#[cfg(feature = "systemd")]
pub(crate) mod services;
pub(crate) mod shared;
pub mod sync;
#[cfg(test)]
pub mod test_support;

use crate::application::collectors::{default_collectors, CoreCollector};
#[cfg(feature = "serde")]
use crate::application::exposure::{Exposure, SnapshotView};
pub use crate::application::history_config::apply_history_settings;
#[cfg(feature = "config")]
pub use crate::application::history_config::history_settings_from_config;
#[cfg(feature = "serde")]
use crate::application::logging::LogEvent;
#[cfg(feature = "config")]
use crate::domain::DescribeConfig;
#[cfg(any(feature = "systemd", feature = "config"))]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, DiskUsage, SystemSnapshot};
pub use context::{AppContext, MetadataStoreHealth};
#[cfg(feature = "serde")]
use std::borrow::Cow;
use std::time::Instant;
use tracing::debug;

impl SystemSnapshot {
    pub fn capture() -> Result<Self, DescribeError> {
        let ctx = AppContext::new_default()?;
        Self::capture_with(CaptureOptions::default(), &ctx)
    }

    pub fn capture_with(opts: CaptureOptions, ctx: &AppContext) -> Result<Self, DescribeError> {
        Self::capture_with_ctx(opts, ctx)
    }

    pub fn capture_with_ctx(opts: CaptureOptions, ctx: &AppContext) -> Result<Self, DescribeError> {
        let started_at = Instant::now();
        let mut snapshot = CoreCollector.capture_base(&opts, ctx)?;

        for collector in default_collectors() {
            collector.collect(&mut snapshot, &opts, ctx)?;
        }

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

        ctx.history().record_snapshot(&snapshot);
        Ok(snapshot)
    }
}

/// Calcule l’espace disque agrégé + partitions.
pub fn disk_usage() -> Result<DiskUsage, DescribeError> {
    crate::infrastructure::system::collect_disks(&AppContext::in_memory())
}

#[cfg(feature = "serde")]
pub fn capture_snapshot_with_view(
    opts: CaptureOptions,
    exposure: Exposure,
    #[cfg(feature = "config")] _cfg: Option<&DescribeConfig>,
    ctx: &AppContext,
) -> Result<(SystemSnapshot, SnapshotView), DescribeError> {
    #[cfg_attr(not(all(feature = "systemd", feature = "config")), allow(unused_mut))]
    let mut snapshot = SystemSnapshot::capture_with_ctx(opts, ctx)?;

    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = _cfg {
        let services_mut = snapshot.services_running.make_mut();
        let filtered = filter_services(std::mem::take(services_mut), cfg);
        *services_mut = filtered;
    }

    #[cfg(feature = "config")]
    if let Some(cfg) = _cfg {
        let (extensions_map, failures) = extensions::execute_configured_plugins(cfg);
        if !extensions_map.is_empty() {
            snapshot.extensions = Some(extensions_map);
        }
        extensions::log_failures(&failures);
    }

    let mut view = SnapshotView::new(&snapshot, exposure);
    match crate::application::metadata::load_server_description_with(ctx) {
        Ok(desc) => {
            view.server_description = desc;
        }
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("server_description_load"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
        }
    }
    match crate::application::metadata::load_server_tags_with(ctx) {
        Ok(tags) => {
            view.server_tags = tags;
        }
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("server_tags_load"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
        }
    }
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
    let cfg = toml::from_str::<DescribeConfig>(&data).map_err(|e| {
        let msg = e.to_string();
        LogEvent::ConfigError {
            path: Cow::Owned(path_ref.display().to_string()),
            error: Cow::Owned(msg),
        }
        .emit();
        DescribeError::Config(format!("toml parse: {e}"))
    })?;
    if let Err(err) = cfg.validate_plugin_names() {
        LogEvent::ConfigError {
            path: Cow::Owned(path_ref.display().to_string()),
            error: Cow::Owned(err.to_string()),
        }
        .emit();
        return Err(err);
    }
    Ok(cfg)
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
pub(crate) mod net;

#[cfg(feature = "net")]
pub use net::{net_listen, network_traffic};

#[cfg(feature = "web")]
pub mod web;

pub mod health;

pub mod containers;
#[cfg(feature = "serde")]
pub mod error;
pub mod exposure;
#[cfg(feature = "serde")]
pub mod extensions;
pub mod history;
pub mod logging;
pub mod logs;
pub mod metadata;
#[cfg(feature = "serde")]
pub mod metrics;
pub mod pagination;
