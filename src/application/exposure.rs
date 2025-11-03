#[cfg(all(feature = "systemd", feature = "serde"))]
use std::collections::BTreeMap;

#[cfg(all(feature = "systemd", feature = "serde"))]
use crate::domain::ServiceInfo;
#[cfg(feature = "serde")]
use crate::domain::{DiskPartition, SystemSnapshot, UpdatesInfo};
#[cfg(all(feature = "serde", feature = "net"))]
use crate::domain::{ListeningSocket, NetworkInterfaceTraffic};
#[cfg(feature = "serde")]
use crate::SharedSlice;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ExposureFlags(u16);

impl ExposureFlags {
    const HOSTNAME: Self = Self(1 << 0);
    const OS: Self = Self(1 << 1);
    const KERNEL: Self = Self(1 << 2);
    const SERVICES: Self = Self(1 << 3);
    const DISK: Self = Self(1 << 4);
    const SOCKETS: Self = Self(1 << 5);
    const UPDATES: Self = Self(1 << 6);
    const NETWORK: Self = Self(1 << 7);
    const ALL: Self = Self(
        Self::HOSTNAME.0
            | Self::OS.0
            | Self::KERNEL.0
            | Self::SERVICES.0
            | Self::DISK.0
            | Self::SOCKETS.0
            | Self::UPDATES.0
            | Self::NETWORK.0,
    );

    const fn empty() -> Self {
        Self(0)
    }

    fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    fn remove(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    fn set(&mut self, flag: Self, value: bool) {
        if value {
            self.insert(flag);
        } else {
            self.remove(flag);
        }
    }
}

impl Default for ExposureFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::BitOr for ExposureFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ExposureFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Exposure {
    flags: ExposureFlags,
    /// Affiche des valeurs masquées (ex: versions tronquées) lorsque les détails complets sont interdits.
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
}

#[cfg(feature = "config")]
impl From<&crate::domain::ExposureConfig> for Exposure {
    fn from(cfg: &crate::domain::ExposureConfig) -> Self {
        let mut exposure = Exposure::default();
        exposure.set_hostname(cfg.expose_hostname);
        exposure.set_os(cfg.expose_os);
        exposure.set_kernel(cfg.expose_kernel);
        exposure.set_services(cfg.expose_services);
        exposure.set_disk_partitions(cfg.expose_disk_partitions);
        exposure.set_listening_sockets(cfg.expose_listening_sockets);
        exposure.set_updates(cfg.expose_updates);
        exposure.set_network_traffic(cfg.expose_network_traffic);
        exposure.redacted = cfg.redacted;
        exposure
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
    pub updates: Option<UpdatesInfo>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_traffic: Option<SharedSlice<NetworkInterfaceTraffic>>,
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
    use crate::domain::{SystemSnapshot, UpdatesInfo};

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
                updates: Some(UpdatesInfo {
                    pending: 3,
                    reboot_required: true,
                    packages: None,
                }),
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
            updates: Some(UpdatesInfo {
                pending: 2,
                reboot_required: false,
                packages: None,
            }),
        };

        let mut exposure = Exposure::default();
        exposure.set_updates(true);
        let view = SnapshotView::new(&snapshot, exposure);
        let info = view.updates.expect("updates should be present");
        assert_eq!(info.pending, 2);
        assert!(!info.reboot_required);
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
