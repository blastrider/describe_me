//! Exposition des champs sensibles/optionnels pour la CLI, le web et l'API.
//!
//! - `Exposure` porte l'etat courant (flags + `redacted` safe-by-default) utilise pour
//!   filtrer les snapshots (`SnapshotView`).
//! - `ExposureBuilder` agregre les sources : config TOML (`ExposureConfig`), overrides
//!   explicites (CLI `ExposureOpts`, web), et contexte de capture (sockets, trafic, conteneurs).
//! - `ExposureOverrides`/`ExposureCaptureContext` rendent explicite ce qui force l'exposition
//!   (ex: `--net-listen` active les sockets, `--no-redacted` leve les masques).
//! - Semantique `redacted` : masquage par defaut des indices sensibles (hostname, kernel, OS);
//!   desactivation volontaire via config/CLI/web expose davantage de details.
#[cfg(feature = "serde")]
use std::collections::BTreeMap;

#[cfg(all(feature = "systemd", feature = "serde"))]
use crate::domain::ServiceInfo;
#[cfg(feature = "serde")]
use crate::domain::{ContainersSnapshot, DiskPartition, SystemSnapshot, UpdatesInfo};
#[cfg(all(feature = "serde", feature = "net"))]
use crate::domain::{ListeningSocket, NetworkInterfaceTraffic};
#[cfg(feature = "serde")]
use crate::SharedSlice;
#[cfg(feature = "serde")]
use describe_me_plugin_sdk::PluginOutput;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct ExposureFlags: u16 {
        const HOSTNAME = 1 << 0;
        const OS = 1 << 1;
        const KERNEL = 1 << 2;
        const SERVICES = 1 << 3;
        const DISK = 1 << 4;
        const SOCKETS = 1 << 5;
        const UPDATES = 1 << 6;
        const NETWORK = 1 << 7;
        const EXTENSIONS = 1 << 8;
        const CONTAINERS_SUMMARY = 1 << 9;
        const CONTAINERS_DETAILS = 1 << 10;
        const ALL = Self::HOSTNAME.bits()
            | Self::OS.bits()
            | Self::KERNEL.bits()
            | Self::SERVICES.bits()
            | Self::DISK.bits()
            | Self::SOCKETS.bits()
            | Self::UPDATES.bits()
            | Self::NETWORK.bits()
            | Self::EXTENSIONS.bits()
            | Self::CONTAINERS_SUMMARY.bits()
            | Self::CONTAINERS_DETAILS.bits();
    }
}

/// Builder centralisant l'agrégation des différentes sources (config, CLI, web) vers une [`Exposure`].
#[derive(Debug, Clone)]
pub struct ExposureBuilder {
    flags: ExposureFlags,
    redacted: bool,
}

impl ExposureBuilder {
    pub fn new() -> Self {
        Self {
            flags: ExposureFlags::empty(),
            redacted: true,
        }
    }

    pub fn from_exposure(exposure: Exposure) -> Self {
        Self {
            flags: exposure.flags,
            redacted: exposure.redacted,
        }
    }

    #[cfg(feature = "config")]
    pub fn from_config(cfg: &crate::domain::ExposureConfig) -> Self {
        let mut builder = Self::new();
        builder.apply_config(cfg);
        builder
    }

    #[cfg(feature = "config")]
    pub fn apply_config(&mut self, cfg: &crate::domain::ExposureConfig) {
        let overrides = ExposureOverrides::from_flags(cfg);
        self.apply_overrides(&overrides);
        self.redacted &= cfg.redacted;
    }

    /// Applique des overrides explicites (CLI, Web…).
    pub fn apply_overrides(&mut self, overrides: &ExposureOverrides) {
        if overrides.expose_all {
            self.flags = ExposureFlags::ALL;
            self.redacted = false;
            return;
        }

        self.flags
            .set(ExposureFlags::HOSTNAME, overrides.expose_hostname);
        self.flags.set(ExposureFlags::OS, overrides.expose_os);
        self.flags
            .set(ExposureFlags::KERNEL, overrides.expose_kernel);
        self.flags
            .set(ExposureFlags::SERVICES, overrides.expose_services);
        self.flags
            .set(ExposureFlags::DISK, overrides.expose_disk_partitions);
        self.flags
            .set(ExposureFlags::NETWORK, overrides.expose_network_traffic);
        self.flags.set(
            ExposureFlags::CONTAINERS_SUMMARY,
            overrides.expose_containers_summary,
        );
        if overrides.expose_containers_details {
            self.flags.insert(ExposureFlags::CONTAINERS_DETAILS);
            self.flags.insert(ExposureFlags::CONTAINERS_SUMMARY);
        }
        self.flags
            .set(ExposureFlags::UPDATES, overrides.expose_updates);
        self.flags
            .set(ExposureFlags::EXTENSIONS, overrides.expose_extensions);
        self.flags
            .set(ExposureFlags::SOCKETS, overrides.expose_listening_sockets);

        if overrides.no_redacted {
            self.redacted = false;
        }
    }

    /// Applique les implications liées au mode capture (collecte sockets, réseau, conteneurs...).
    pub fn apply_capture(&mut self, ctx: ExposureCaptureContext) {
        if ctx.net_listen {
            self.flags.insert(ExposureFlags::SOCKETS);
        }
        if ctx.net_traffic {
            self.flags.insert(ExposureFlags::NETWORK);
        }
        if ctx.containers {
            self.flags.insert(ExposureFlags::CONTAINERS_DETAILS);
            self.flags.insert(ExposureFlags::CONTAINERS_SUMMARY);
        }
    }

    pub fn build(self) -> Exposure {
        Exposure {
            flags: self.flags,
            redacted: self.redacted,
        }
    }
}

impl Default for ExposureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Overrides explicites d'exposition (flags CLI/Web).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExposureOverrides {
    pub expose_hostname: bool,
    pub expose_os: bool,
    pub expose_kernel: bool,
    pub expose_services: bool,
    pub expose_disk_partitions: bool,
    pub expose_network_traffic: bool,
    pub expose_containers_summary: bool,
    pub expose_containers_details: bool,
    pub expose_updates: bool,
    pub expose_extensions: bool,
    pub expose_all: bool,
    pub no_redacted: bool,
    pub expose_listening_sockets: bool,
}

/// Source commune des drapeaux d'exposition (CLI, web, config…).
pub trait ExposureFlagSource {
    fn expose_hostname(&self) -> bool;
    fn expose_os(&self) -> bool;
    fn expose_kernel(&self) -> bool;
    fn expose_services(&self) -> bool;
    fn expose_disk_partitions(&self) -> bool;
    fn expose_network_traffic(&self) -> bool;
    fn expose_containers_summary(&self) -> bool;
    fn expose_containers_details(&self) -> bool;
    fn expose_updates(&self) -> bool;
    fn expose_extensions(&self) -> bool;
    fn expose_all(&self) -> bool;
    fn no_redacted(&self) -> bool {
        false
    }
    fn expose_listening_sockets(&self) -> bool {
        false
    }
}

impl ExposureOverrides {
    /// Construit des overrides explicites à partir d'un fournisseur de flags (CLI, web...).
    pub fn from_flags(flags: &impl ExposureFlagSource) -> Self {
        Self {
            expose_hostname: flags.expose_hostname(),
            expose_os: flags.expose_os(),
            expose_kernel: flags.expose_kernel(),
            expose_services: flags.expose_services(),
            expose_disk_partitions: flags.expose_disk_partitions(),
            expose_network_traffic: flags.expose_network_traffic(),
            expose_containers_summary: flags.expose_containers_summary(),
            expose_containers_details: flags.expose_containers_details(),
            expose_updates: flags.expose_updates(),
            expose_extensions: flags.expose_extensions(),
            expose_all: flags.expose_all(),
            no_redacted: flags.no_redacted(),
            expose_listening_sockets: flags.expose_listening_sockets(),
        }
    }
}

#[cfg(feature = "config")]
impl ExposureFlagSource for crate::domain::ExposureConfig {
    fn expose_hostname(&self) -> bool {
        self.expose_hostname
    }

    fn expose_os(&self) -> bool {
        self.expose_os
    }

    fn expose_kernel(&self) -> bool {
        self.expose_kernel
    }

    fn expose_services(&self) -> bool {
        self.expose_services
    }

    fn expose_disk_partitions(&self) -> bool {
        self.expose_disk_partitions
    }

    fn expose_network_traffic(&self) -> bool {
        self.expose_network_traffic
    }

    fn expose_containers_summary(&self) -> bool {
        self.expose_containers_summary
    }

    fn expose_containers_details(&self) -> bool {
        self.expose_containers_details
    }

    fn expose_updates(&self) -> bool {
        self.expose_updates
    }

    fn expose_extensions(&self) -> bool {
        self.expose_extensions
    }

    fn expose_all(&self) -> bool {
        false
    }

    fn no_redacted(&self) -> bool {
        !self.redacted
    }

    fn expose_listening_sockets(&self) -> bool {
        self.expose_listening_sockets
    }
}

/// Contexte de capture qui force certains champs (sockets, trafic, conteneurs).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExposureCaptureContext {
    pub net_listen: bool,
    pub net_traffic: bool,
    pub containers: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct Exposure {
    flags: ExposureFlags,
    /// When `true`, sensitive fields are redacted (safe-by-default). Can be opted-out explicitly,
    /// which may leak hostname, kernel version or service names.
    pub redacted: bool,
}

impl Default for Exposure {
    fn default() -> Self {
        Self {
            flags: ExposureFlags::empty(),
            redacted: true,
        }
    }
}

impl Exposure {
    pub fn all() -> Self {
        Self {
            flags: ExposureFlags::ALL,
            redacted: false,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.flags |= other.flags;
        self.redacted |= other.redacted;
    }

    pub fn is_all(&self) -> bool {
        self.flags.contains(ExposureFlags::ALL)
    }

    pub fn hostname(&self) -> bool {
        self.flags.contains(ExposureFlags::HOSTNAME)
    }

    pub fn set_hostname(&mut self, value: bool) {
        self.flags.set(ExposureFlags::HOSTNAME, value);
    }

    pub fn os(&self) -> bool {
        self.flags.contains(ExposureFlags::OS)
    }

    pub fn set_os(&mut self, value: bool) {
        self.flags.set(ExposureFlags::OS, value);
    }

    pub fn kernel(&self) -> bool {
        self.flags.contains(ExposureFlags::KERNEL)
    }

    pub fn set_kernel(&mut self, value: bool) {
        self.flags.set(ExposureFlags::KERNEL, value);
    }

    pub fn services(&self) -> bool {
        self.flags.contains(ExposureFlags::SERVICES)
    }

    pub fn set_services(&mut self, value: bool) {
        self.flags.set(ExposureFlags::SERVICES, value);
    }

    pub fn disk_partitions(&self) -> bool {
        self.flags.contains(ExposureFlags::DISK)
    }

    pub fn set_disk_partitions(&mut self, value: bool) {
        self.flags.set(ExposureFlags::DISK, value);
    }

    pub fn listening_sockets(&self) -> bool {
        self.flags.contains(ExposureFlags::SOCKETS)
    }

    pub fn set_listening_sockets(&mut self, value: bool) {
        self.flags.set(ExposureFlags::SOCKETS, value);
    }

    pub fn updates(&self) -> bool {
        self.flags.contains(ExposureFlags::UPDATES)
    }

    pub fn set_updates(&mut self, value: bool) {
        self.flags.set(ExposureFlags::UPDATES, value);
    }

    pub fn network_traffic(&self) -> bool {
        self.flags.contains(ExposureFlags::NETWORK)
    }

    pub fn set_network_traffic(&mut self, value: bool) {
        self.flags.set(ExposureFlags::NETWORK, value);
    }

    pub fn containers_summary(&self) -> bool {
        self.flags.contains(ExposureFlags::CONTAINERS_SUMMARY)
            || self.flags.contains(ExposureFlags::CONTAINERS_DETAILS)
    }

    pub fn set_containers_summary(&mut self, value: bool) {
        self.flags.set(ExposureFlags::CONTAINERS_SUMMARY, value);
    }

    pub fn containers_details(&self) -> bool {
        self.flags.contains(ExposureFlags::CONTAINERS_DETAILS)
    }

    pub fn set_containers_details(&mut self, value: bool) {
        self.flags.set(ExposureFlags::CONTAINERS_DETAILS, value);
        if value {
            self.set_containers_summary(true);
        }
    }

    pub fn extensions(&self) -> bool {
        self.flags.contains(ExposureFlags::EXTENSIONS)
    }

    pub fn set_extensions(&mut self, value: bool) {
        self.flags.set(ExposureFlags::EXTENSIONS, value);
    }
}

#[cfg(feature = "config")]
impl From<&crate::domain::ExposureConfig> for Exposure {
    fn from(cfg: &crate::domain::ExposureConfig) -> Self {
        ExposureBuilder::from_config(cfg).build()
    }
}

#[cfg(feature = "serde")]
use serde::Serialize;

#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotView {
    #[serde(skip_serializing_if = "is_false")]
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    pub uptime_seconds: u64,
    pub cpu_count: usize,
    pub load_average: (f64, f64, f64),
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub server_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage: Option<DiskUsageView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listening_sockets: Option<SharedSlice<ListeningSocket>>,
    #[cfg(feature = "systemd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_running: Option<SharedSlice<ServiceInfo>>,
    #[cfg(feature = "systemd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_summary: Option<ServiceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<ContainersSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates: Option<UpdatesInfo>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_traffic: Option<SharedSlice<NetworkInterfaceTraffic>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<BTreeMap<String, PluginOutput>>,
}

#[cfg(feature = "serde")]
impl SnapshotView {
    pub fn new(snapshot: &SystemSnapshot, exposure: Exposure) -> Self {
        let disk_usage = DiskUsageView::from_snapshot(snapshot, &exposure);

        #[cfg(feature = "systemd")]
        let services_summary = compute_service_summary(&snapshot.services_running);

        let (os, os_name, os_redacted) = build_sensitive_field(
            &snapshot.os,
            exposure.os(),
            exposure.redacted,
            sanitize_os_hint,
        );

        let (kernel, kernel_release, kernel_redacted) = build_sensitive_field(
            &snapshot.kernel,
            exposure.kernel(),
            exposure.redacted,
            sanitize_kernel_hint,
        );

        let redacted = os_redacted || kernel_redacted;

        let containers = match snapshot.containers.as_ref() {
            None => None,
            Some(data) => {
                if exposure.containers_details() {
                    Some(data.clone())
                } else if exposure.containers_summary() {
                    Some(ContainersSnapshot {
                        summary: data.summary.clone(),
                        containers: None,
                    })
                } else {
                    None
                }
            }
        };

        Self {
            redacted,
            hostname: exposure.hostname().then(|| snapshot.hostname.clone()),
            os,
            kernel,
            uptime_seconds: snapshot.uptime_seconds,
            cpu_count: snapshot.cpu_count,
            load_average: snapshot.load_average,
            total_memory_bytes: snapshot.total_memory_bytes,
            used_memory_bytes: snapshot.used_memory_bytes,
            total_swap_bytes: snapshot.total_swap_bytes,
            used_swap_bytes: snapshot.used_swap_bytes,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage,
            os_name,
            kernel_release,
            #[cfg(feature = "net")]
            listening_sockets: if exposure.listening_sockets() {
                snapshot.listening_sockets.clone()
            } else {
                None
            },
            #[cfg(feature = "systemd")]
            services_running: exposure
                .services()
                .then(|| snapshot.services_running.clone()),
            #[cfg(feature = "systemd")]
            services_summary,
            containers,
            updates: if exposure.updates() {
                snapshot.updates.clone()
            } else {
                None
            },
            #[cfg(feature = "net")]
            network_traffic: if exposure.network_traffic() {
                snapshot.network_traffic.clone()
            } else {
                None
            },
            extensions: if exposure.extensions() {
                snapshot.extensions.clone()
            } else {
                None
            },
        }
    }
}

#[cfg(feature = "serde")]
fn build_sensitive_field<F>(
    raw: &Option<String>,
    allow_full: bool,
    allow_redacted: bool,
    hint_fn: F,
) -> (Option<String>, Option<String>, bool)
where
    F: Fn(&str) -> Option<String>,
{
    let hint = raw.as_ref().and_then(|value| hint_fn(value));
    let mut used_redaction = false;

    let value = if allow_full {
        raw.clone()
    } else if allow_redacted {
        if hint.is_some() {
            used_redaction = true;
        }
        hint.clone()
    } else {
        None
    };

    let hint_for_view = if allow_redacted || allow_full {
        hint
    } else {
        None
    };

    (value, hint_for_view, used_redaction)
}

#[cfg(feature = "serde")]
fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(feature = "serde")]
fn sanitize_os_hint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut base = trimmed.to_string();
    for delim in ['(', '[', '{'] {
        if let Some(idx) = base.find(delim) {
            base = base[..idx].trim().to_string();
        }
    }
    if base.is_empty() {
        return None;
    }

    let mut words = base.split_whitespace();
    let vendor = words.next()?;
    let version_token = find_version_token(&base);

    let mut result = String::from(vendor);
    if let Some(token) = version_token {
        if let Some(version) = truncate_version(&token) {
            if !version.is_empty() {
                result.push(' ');
                result.push_str(&version);
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(feature = "serde")]
fn sanitize_kernel_hint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let version_token = find_version_token(trimmed)?;
    truncate_version(&version_token)
}

#[cfg(feature = "serde")]
fn find_version_token(text: &str) -> Option<String> {
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            current.push(ch);
        } else if !current.is_empty() {
            break;
        }
    }
    if current.is_empty() {
        None
    } else {
        Some(current)
    }
}

#[cfg(feature = "serde")]
fn truncate_version(token: &str) -> Option<String> {
    let segments: Vec<&str> = token.split('.').filter(|seg| !seg.is_empty()).collect();
    match segments.len() {
        0 => None,
        1 => Some(segments[0].to_string()),
        _ => Some(format!("{}.{}", segments[0], segments[1])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::domain::{
        ContainerInfo, ContainersSnapshot, ContainersSummary, SystemSnapshot, UpdatesInfo,
    };
    #[cfg(feature = "serde")]
    use crate::shared::SharedSlice;

    #[test]
    fn updates_hidden_when_not_exposed() {
        let exposure = Exposure::default();

        #[cfg(feature = "serde")]
        {
            let snapshot = SystemSnapshot {
                hostname: "host".into(),
                os: None,
                kernel: None,
                uptime_seconds: 0,
                cpu_count: 1,
                load_average: (0.0, 0.0, 0.0),
                total_memory_bytes: 0,
                used_memory_bytes: 0,
                total_swap_bytes: 0,
                used_swap_bytes: 0,
                disk_usage: None,
                #[cfg(feature = "systemd")]
                services_running: crate::shared::SharedSlice::from_vec(Vec::new()),
                #[cfg(feature = "net")]
                listening_sockets: None,
                #[cfg(feature = "net")]
                network_traffic: None,
                containers: None,
                updates: Some(UpdatesInfo {
                    pending: 3,
                    reboot_required: true,
                    packages: None,
                }),
                extensions: None,
            };
            let view = SnapshotView::new(&snapshot, exposure);
            assert!(view.updates.is_none());
        }
        #[cfg(not(feature = "serde"))]
        {
            // When serde is disabled SnapshotView is unavailable; ensure the flag stays false.
            assert!(!exposure.updates());
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn updates_retained_when_exposed() {
        let snapshot = SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: crate::shared::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: Some(UpdatesInfo {
                pending: 2,
                reboot_required: false,
                packages: None,
            }),
            extensions: None,
        };

        let mut exposure = Exposure::default();
        exposure.set_updates(true);
        let view = SnapshotView::new(&snapshot, exposure);
        let info = view.updates.expect("updates should be present");
        assert_eq!(info.pending, 2);
        assert!(!info.reboot_required);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn containers_follow_exposure_flags() {
        let containers = SharedSlice::from_vec(vec![ContainerInfo {
            name: "web".into(),
            runtime: "docker".into(),
            ip: Some("10.0.0.2".into()),
            state: "running".into(),
            image: Some("nginx:latest".into()),
        }]);
        let snapshot = SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: crate::shared::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: Some(ContainersSnapshot {
                summary: Some(ContainersSummary {
                    total: 1,
                    running: 1,
                }),
                containers: Some(containers.clone()),
            }),
            updates: None,
            extensions: None,
        };

        let view_none = SnapshotView::new(&snapshot, Exposure::default());
        assert!(view_none.containers.is_none());

        let mut summary_only = Exposure::default();
        summary_only.set_containers_summary(true);
        let view_summary = SnapshotView::new(&snapshot, summary_only);
        let containers_summary = view_summary
            .containers
            .expect("containers summary should be present");
        assert!(containers_summary.containers.is_none());
        assert_eq!(containers_summary.summary.as_ref().unwrap().running, 1);

        let mut details = Exposure::default();
        details.set_containers_details(true);
        let view_details = SnapshotView::new(&snapshot, details);
        let containers_details = view_details
            .containers
            .expect("containers should be present");
        let list = containers_details.containers.expect("container list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "web");
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct DiskUsageView {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partitions: Option<SharedSlice<DiskPartition>>,
}

#[cfg(feature = "serde")]
impl DiskUsageView {
    fn from_snapshot(snapshot: &SystemSnapshot, exposure: &Exposure) -> Option<Self> {
        let du = snapshot.disk_usage.as_ref()?;
        let partitions = exposure.disk_partitions().then(|| du.partitions.clone());
        Some(Self {
            total_bytes: du.total_bytes,
            available_bytes: du.available_bytes,
            used_bytes: du.used_bytes,
            partitions,
        })
    }
}

#[cfg(feature = "systemd")]
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct ServiceSummary {
    pub total: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub by_state: Vec<ServiceStateCount>,
}

#[cfg(feature = "systemd")]
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct ServiceStateCount {
    pub state: String,
    pub count: usize,
}

#[cfg(feature = "systemd")]
#[cfg(feature = "serde")]
fn compute_service_summary(services: &[ServiceInfo]) -> Option<ServiceSummary> {
    if services.is_empty() {
        return None;
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for svc in services {
        *counts.entry(svc.state.as_str()).or_default() += 1;
    }

    Some(ServiceSummary {
        total: services.len(),
        by_state: counts
            .into_iter()
            .map(|(state, count)| ServiceStateCount {
                state: state.to_string(),
                count,
            })
            .collect(),
    })
}
