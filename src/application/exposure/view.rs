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

#[cfg(feature = "serde")]
use super::sanitize::{sanitize_kernel_hint, sanitize_os_hint};
use super::Exposure;

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
