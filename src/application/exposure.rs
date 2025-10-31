#[cfg(all(feature = "systemd", feature = "serde"))]
use std::collections::BTreeMap;

#[cfg(all(feature = "serde", feature = "net"))]
use crate::domain::ListeningSocket;
#[cfg(all(feature = "systemd", feature = "serde"))]
use crate::domain::ServiceInfo;
#[cfg(feature = "serde")]
use crate::domain::{DiskPartition, SystemSnapshot};

#[derive(Debug, Copy, Clone)]
pub struct Exposure {
    pub hostname: bool,
    pub os: bool,
    pub kernel: bool,
    pub services: bool,
    pub disk_partitions: bool,
    pub listening_sockets: bool,
    /// Affiche des valeurs masquées (ex: versions tronquées) lorsque les détails complets sont interdits.
    pub redacted: bool,
}

impl Default for Exposure {
    fn default() -> Self {
        Self {
            hostname: false,
            os: false,
            kernel: false,
            services: false,
            disk_partitions: false,
            listening_sockets: false,
            redacted: true,
        }
    }
}

impl Exposure {
    pub fn all() -> Self {
        Self {
            hostname: true,
            os: true,
            kernel: true,
            services: true,
            disk_partitions: true,
            listening_sockets: true,
            redacted: false,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.hostname |= other.hostname;
        self.os |= other.os;
        self.kernel |= other.kernel;
        self.services |= other.services;
        self.disk_partitions |= other.disk_partitions;
        self.listening_sockets |= other.listening_sockets;
        self.redacted |= other.redacted;
    }

    pub fn is_all(&self) -> bool {
        self.hostname
            && self.os
            && self.kernel
            && self.services
            && self.disk_partitions
            && self.listening_sockets
    }
}

#[cfg(feature = "config")]
impl From<&crate::domain::ExposureConfig> for Exposure {
    fn from(cfg: &crate::domain::ExposureConfig) -> Self {
        Self {
            hostname: cfg.expose_hostname,
            os: cfg.expose_os,
            kernel: cfg.expose_kernel,
            services: cfg.expose_services,
            disk_partitions: cfg.expose_disk_partitions,
            listening_sockets: cfg.expose_listening_sockets,
            redacted: cfg.redacted,
        }
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
    pub listening_sockets: Option<Vec<ListeningSocket>>,
    #[cfg(feature = "systemd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_running: Option<Vec<ServiceInfo>>,
    #[cfg(feature = "systemd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_summary: Option<ServiceSummary>,
}

#[cfg(feature = "serde")]
impl SnapshotView {
    pub fn new(snapshot: &SystemSnapshot, exposure: Exposure) -> Self {
        let disk_usage = DiskUsageView::from_snapshot(snapshot, &exposure);

        #[cfg(feature = "systemd")]
        let services_summary = compute_service_summary(&snapshot.services_running);

        let (os, os_name, os_redacted) = build_sensitive_field(
            &snapshot.os,
            exposure.os,
            exposure.redacted,
            sanitize_os_hint,
        );

        let (kernel, kernel_release, kernel_redacted) = build_sensitive_field(
            &snapshot.kernel,
            exposure.kernel,
            exposure.redacted,
            sanitize_kernel_hint,
        );

        let redacted = os_redacted || kernel_redacted;

        Self {
            redacted,
            hostname: exposure.hostname.then(|| snapshot.hostname.clone()),
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
            listening_sockets: if exposure.listening_sockets {
                snapshot.listening_sockets.clone()
            } else {
                None
            },
            #[cfg(feature = "systemd")]
            services_running: if exposure.services {
                Some(snapshot.services_running.clone())
            } else {
                None
            },
            #[cfg(feature = "systemd")]
            services_summary,
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

fn is_false(value: &bool) -> bool {
    !*value
}

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

fn sanitize_kernel_hint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let version_token = find_version_token(trimmed)?;
    truncate_version(&version_token)
}

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

fn truncate_version(token: &str) -> Option<String> {
    let segments: Vec<&str> = token.split('.').filter(|seg| !seg.is_empty()).collect();
    match segments.len() {
        0 => None,
        1 => Some(segments[0].to_string()),
        _ => Some(format!("{}.{}", segments[0], segments[1])),
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct DiskUsageView {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partitions: Option<Vec<DiskPartition>>,
}

#[cfg(feature = "serde")]
impl DiskUsageView {
    fn from_snapshot(snapshot: &SystemSnapshot, exposure: &Exposure) -> Option<Self> {
        let du = snapshot.disk_usage.as_ref()?;
        let partitions = if exposure.disk_partitions {
            Some(du.partitions.clone())
        } else {
            None
        };
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
