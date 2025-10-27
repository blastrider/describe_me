#[cfg(all(feature = "systemd", feature = "serde"))]
use std::collections::BTreeMap;

#[cfg(all(feature = "systemd", feature = "serde"))]
use crate::domain::ServiceInfo;
#[cfg(feature = "serde")]
use crate::domain::{DiskPartition, SystemSnapshot};

#[derive(Debug, Copy, Clone, Default)]
pub struct Exposure {
    pub hostname: bool,
    pub os: bool,
    pub kernel: bool,
    pub services: bool,
    pub disk_partitions: bool,
}

impl Exposure {
    pub fn all() -> Self {
        Self {
            hostname: true,
            os: true,
            kernel: true,
            services: true,
            disk_partitions: true,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.hostname |= other.hostname;
        self.os |= other.os;
        self.kernel |= other.kernel;
        self.services |= other.services;
        self.disk_partitions |= other.disk_partitions;
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
        }
    }
}

#[cfg(feature = "serde")]
use serde::Serialize;

#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotView {
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
        let disk_usage = snapshot.disk_usage.as_ref().map(|du| DiskUsageView {
            total_bytes: du.total_bytes,
            available_bytes: du.available_bytes,
            used_bytes: du.used_bytes,
            partitions: if exposure.disk_partitions {
                Some(du.partitions.clone())
            } else {
                None
            },
        });

        #[cfg(feature = "systemd")]
        let services_summary = compute_service_summary(&snapshot.services_running);
        Self {
            hostname: exposure.hostname.then(|| snapshot.hostname.clone()),
            os: if exposure.os {
                snapshot.os.clone()
            } else {
                None
            },
            kernel: if exposure.kernel {
                snapshot.kernel.clone()
            } else {
                None
            },
            uptime_seconds: snapshot.uptime_seconds,
            cpu_count: snapshot.cpu_count,
            load_average: snapshot.load_average,
            total_memory_bytes: snapshot.total_memory_bytes,
            used_memory_bytes: snapshot.used_memory_bytes,
            total_swap_bytes: snapshot.total_swap_bytes,
            used_swap_bytes: snapshot.used_swap_bytes,
            disk_usage,
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
#[derive(Debug, Clone, Serialize)]
pub struct DiskUsageView {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partitions: Option<Vec<DiskPartition>>,
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
