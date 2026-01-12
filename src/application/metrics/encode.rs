use std::fmt::Write;

use crate::application::exposure::SnapshotView;

use super::extensions::{write_extension_metrics, ExtensionMetricsState};
use super::snapshot::write_snapshot_metrics;

/// Variante avec état pour comptabiliser les métriques cumulatives.
///
/// Si `state` vaut `None`, le compteur `describe_me_extension_dropped_total`
/// n'est pas émis (les compteurs cumulés nécessitent un état partagé).
pub fn render_prometheus_metrics_with_state(
    view: &SnapshotView,
    snapshot_age_secs: u64,
    state: Option<&ExtensionMetricsState>,
) -> String {
    let mut out = String::new();

    write_snapshot_metrics(&mut out, view, snapshot_age_secs);
    write_extension_metrics(&mut out, view, state);

    out
}

pub(super) fn write_metric<T: std::fmt::Display>(
    out: &mut String,
    name: &str,
    help: &str,
    metric_type: &str,
    value: T,
) {
    write_metric_header(out, name, help, metric_type);
    write_metric_sample(out, name, None, value);
}

pub(super) fn write_metric_bool(
    out: &mut String,
    name: &str,
    help: &str,
    metric_type: &str,
    value: bool,
) {
    write_metric(out, name, help, metric_type, if value { 1 } else { 0 });
}

pub(super) fn write_metric_header(out: &mut String, name: &str, help: &str, metric_type: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

pub(super) fn write_metric_sample<T: std::fmt::Display>(
    out: &mut String,
    name: &str,
    labels: Option<&str>,
    value: T,
) {
    match labels {
        Some(labels) => {
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        }
        None => {
            let _ = writeln!(out, "{name} {value}");
        }
    }
}

pub(super) fn escape_label_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{escape_label_value, render_prometheus_metrics_with_state};
    use crate::application::exposure::view::DiskUsageView;
    use crate::application::exposure::SnapshotView;
    #[cfg(feature = "net")]
    use crate::domain::NetworkInterfaceTraffic;
    use crate::domain::{ContainersSnapshot, ContainersSummary, UpdatesInfo};
    #[cfg(feature = "net")]
    use crate::shared::SharedSlice;

    #[test]
    fn renders_core_metrics() {
        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 42,
            cpu_count: 4,
            load_average: (0.1, 0.2, 0.3),
            total_memory_bytes: 2048,
            used_memory_bytes: 1024,
            total_swap_bytes: 512,
            used_swap_bytes: 128,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: Some(DiskUsageView {
                total_bytes: 10_000,
                available_bytes: 4_000,
                used_bytes: 6_000,
                partitions: None,
            }),
            os_name: None,
            kernel_release: None,
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: Some(ContainersSnapshot {
                summary: Some(ContainersSummary {
                    total: 3,
                    running: 2,
                }),
                containers: None,
            }),
            updates: Some(UpdatesInfo {
                pending: 2,
                reboot_required: true,
                packages: None,
            }),
            #[cfg(feature = "net")]
            network_traffic: None,
            extensions: None,
        };

        let rendered = render_prometheus_metrics_with_state(&view, 7, None);
        assert!(
            rendered.contains("describe_me_up 1"),
            "up metric missing: {rendered}"
        );
        assert!(rendered.contains("# TYPE describe_me_load1 gauge"));
        assert!(rendered.contains("describe_me_load15 0.3"));
        assert!(rendered.contains("describe_me_memory_bytes_free 1024"));
        assert!(rendered.contains("describe_me_disk_bytes_used 6000"));
        assert!(rendered.contains("describe_me_updates_pending 2"));
        assert!(rendered.contains("describe_me_containers_running 2"));
        assert!(rendered.contains("describe_me_snapshot_age_seconds 7"));
    }

    #[cfg(feature = "net")]
    #[test]
    fn renders_network_metrics_with_labels() {
        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: None,
            os_name: None,
            kernel_release: None,
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: None,
            updates: None,
            network_traffic: Some(SharedSlice::from_vec(vec![NetworkInterfaceTraffic {
                name: r#"eth0"test"#.into(),
                rx_bytes: 10,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 20,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            }])),
            extensions: None,
        };

        let rendered = render_prometheus_metrics_with_state(&view, 0, None);
        assert!(rendered.contains("# TYPE describe_me_net_rx_bytes_total counter"));
        assert!(rendered.contains("describe_me_net_rx_bytes_total{iface=\"eth0\\\"test\"} 10"));
        assert!(rendered.contains("describe_me_net_tx_bytes_total{iface=\"eth0\\\"test\"} 20"));
    }

    #[test]
    fn escape_label_value_filters_control_chars() {
        let raw = "alpha\rbravo\ncharlie\t\"delta\"\\echo\u{001b}end";
        let escaped = escape_label_value(raw);
        assert_eq!(escaped, "alpha bravo\\ncharlie \\\"delta\\\"\\\\echo end");
    }
}
