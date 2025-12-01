//! Conversion d'un `SnapshotView` en exposition texte Prometheus.
//!
//! Le rendu repose uniquement sur le dernier snapshot mis en cache (aucune
//! recapture) et couvre les familles de métriques stables du projet. Un point
//! d'extension (`write_extension_metrics`) est prévu pour exposer à terme des
//! valeurs numériques issues des plugins SDK sans exploser la cardinalité.

use std::fmt::Write;

use crate::application::exposure::SnapshotView;
use crate::domain::ContainersSnapshot;
#[cfg(feature = "net")]
use crate::domain::NetworkInterfaceTraffic;

/// Rendu principal des métriques en texte Prometheus (version 0.0.4).
pub fn render_prometheus_metrics(view: &SnapshotView, snapshot_age_secs: u64) -> String {
    let mut out = String::new();

    write_metric(
        &mut out,
        "describe_me_up",
        "1 if last snapshot is available",
        "gauge",
        1,
    );
    write_metric(
        &mut out,
        "describe_me_snapshot_age_seconds",
        "Age of the last collected snapshot",
        "gauge",
        snapshot_age_secs,
    );
    write_metric(
        &mut out,
        "describe_me_uptime_seconds",
        "System uptime in seconds",
        "gauge",
        view.uptime_seconds,
    );

    write_metric(
        &mut out,
        "describe_me_cpu_count",
        "Number of logical CPUs detected",
        "gauge",
        view.cpu_count,
    );
    let (load1, load5, load15) = view.load_average;
    write_metric(
        &mut out,
        "describe_me_load1",
        "System load average over 1 minute",
        "gauge",
        load1,
    );
    write_metric(
        &mut out,
        "describe_me_load5",
        "System load average over 5 minutes",
        "gauge",
        load5,
    );
    write_metric(
        &mut out,
        "describe_me_load15",
        "System load average over 15 minutes",
        "gauge",
        load15,
    );

    let free_memory = view
        .total_memory_bytes
        .saturating_sub(view.used_memory_bytes);
    write_metric(
        &mut out,
        "describe_me_memory_bytes_total",
        "Total memory in bytes",
        "gauge",
        view.total_memory_bytes,
    );
    write_metric(
        &mut out,
        "describe_me_memory_bytes_used",
        "Used memory in bytes",
        "gauge",
        view.used_memory_bytes,
    );
    write_metric(
        &mut out,
        "describe_me_memory_bytes_free",
        "Free memory in bytes",
        "gauge",
        free_memory,
    );

    write_metric(
        &mut out,
        "describe_me_swap_bytes_total",
        "Total swap space in bytes",
        "gauge",
        view.total_swap_bytes,
    );
    write_metric(
        &mut out,
        "describe_me_swap_bytes_used",
        "Used swap space in bytes",
        "gauge",
        view.used_swap_bytes,
    );

    if let Some(disk) = view.disk_usage.as_ref() {
        write_metric(
            &mut out,
            "describe_me_disk_bytes_total",
            "Total disk space in bytes",
            "gauge",
            disk.total_bytes,
        );
        write_metric(
            &mut out,
            "describe_me_disk_bytes_available",
            "Available disk space in bytes",
            "gauge",
            disk.available_bytes,
        );
        write_metric(
            &mut out,
            "describe_me_disk_bytes_used",
            "Used disk space in bytes",
            "gauge",
            disk.used_bytes,
        );
    }

    if let Some(updates) = view.updates.as_ref() {
        write_metric(
            &mut out,
            "describe_me_updates_pending",
            "Number of pending system updates",
            "gauge",
            updates.pending,
        );
        write_metric_bool(
            &mut out,
            "describe_me_updates_reboot_required",
            "1 if a reboot is required to apply updates",
            "gauge",
            updates.reboot_required,
        );
    }

    if let Some(containers) = view.containers.as_ref() {
        if let Some(total) = containers_total(containers) {
            write_metric(
                &mut out,
                "describe_me_containers_total",
                "Number of detected containers",
                "gauge",
                total,
            );
        }
        if let Some(running) = containers_running(containers) {
            write_metric(
                &mut out,
                "describe_me_containers_running",
                "Number of running containers",
                "gauge",
                running,
            );
        }
    }

    #[cfg(feature = "net")]
    if let Some(traffic) = view.network_traffic.as_ref() {
        write_network_metrics(&mut out, traffic.as_slice());
    }

    write_extension_metrics(&mut out, view);

    out
}

fn write_metric<T: std::fmt::Display>(
    out: &mut String,
    name: &str,
    help: &str,
    metric_type: &str,
    value: T,
) {
    write_metric_header(out, name, help, metric_type);
    write_metric_sample(out, name, None, value);
}

fn write_metric_bool(out: &mut String, name: &str, help: &str, metric_type: &str, value: bool) {
    write_metric(out, name, help, metric_type, if value { 1 } else { 0 });
}

fn write_metric_header(out: &mut String, name: &str, help: &str, metric_type: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

fn write_metric_sample<T: std::fmt::Display>(
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

fn containers_total(containers: &ContainersSnapshot) -> Option<usize> {
    if let Some(summary) = containers.summary.as_ref() {
        Some(summary.total)
    } else {
        containers.containers.as_ref().map(|list| list.len())
    }
}

fn containers_running(containers: &ContainersSnapshot) -> Option<usize> {
    if let Some(summary) = containers.summary.as_ref() {
        Some(summary.running)
    } else {
        containers.containers.as_ref().map(|list| {
            list.iter()
                .filter(|c| c.state.eq_ignore_ascii_case("running"))
                .count()
        })
    }
}

#[cfg(feature = "net")]
fn write_network_metrics(out: &mut String, traffic: &[NetworkInterfaceTraffic]) {
    if traffic.is_empty() {
        return;
    }

    write_metric_header(
        out,
        "describe_me_net_rx_bytes_total",
        "Total received bytes by interface",
        "counter",
    );
    write_metric_header(
        out,
        "describe_me_net_tx_bytes_total",
        "Total transmitted bytes by interface",
        "counter",
    );

    for iface in traffic {
        let label = format!("iface=\"{}\"", escape_label_value(&iface.name));
        write_metric_sample(
            out,
            "describe_me_net_rx_bytes_total",
            Some(&label),
            iface.rx_bytes,
        );
        write_metric_sample(
            out,
            "describe_me_net_tx_bytes_total",
            Some(&label),
            iface.tx_bytes,
        );
    }
}

fn write_extension_metrics(out: &mut String, view: &SnapshotView) {
    if view.extensions.as_ref().is_none_or(|map| map.is_empty()) {
        return;
    }
    // TODO(codex): exposer des métriques plugin génériques.
    //
    // Idée: parcourir `extensions` et publier les valeurs numériques simples
    // sous forme `describe_me_extension_value{plugin="<name>", key="<path>"}`.
    // Cette conversion doit être opt-in et limiter la cardinalité (ex: liste
    // blanche de clés ou aplatissement partiel). Rien n'est exporté par défaut
    // pour éviter les surprises.
    let _ = out;
}

fn escape_label_value(raw: &str) -> String {
    raw.chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            _ => vec![c],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::exposure::DiskUsageView;
    use crate::domain::{ContainersSummary, UpdatesInfo};
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

        let rendered = render_prometheus_metrics(&view, 7);
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

        let rendered = render_prometheus_metrics(&view, 0);
        assert!(rendered.contains("# TYPE describe_me_net_rx_bytes_total counter"));
        assert!(rendered.contains("describe_me_net_rx_bytes_total{iface=\"eth0\\\"test\"} 10"));
        assert!(rendered.contains("describe_me_net_tx_bytes_total{iface=\"eth0\\\"test\"} 20"));
    }
}
