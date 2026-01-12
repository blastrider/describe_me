use crate::application::exposure::SnapshotView;
use crate::domain::ContainersSnapshot;
#[cfg(feature = "net")]
use crate::domain::NetworkInterfaceTraffic;

#[cfg(feature = "net")]
use super::encode::{escape_label_value, write_metric_header, write_metric_sample};
use super::encode::{write_metric, write_metric_bool};

pub(super) fn write_snapshot_metrics(
    out: &mut String,
    view: &SnapshotView,
    snapshot_age_secs: u64,
) {
    write_metric(
        out,
        "describe_me_up",
        "1 if last snapshot is available",
        "gauge",
        1,
    );
    write_metric(
        out,
        "describe_me_snapshot_age_seconds",
        "Age of the last collected snapshot",
        "gauge",
        snapshot_age_secs,
    );
    write_metric(
        out,
        "describe_me_uptime_seconds",
        "System uptime in seconds",
        "gauge",
        view.uptime_seconds,
    );

    write_metric(
        out,
        "describe_me_cpu_count",
        "Number of logical CPUs detected",
        "gauge",
        view.cpu_count,
    );
    let (load1, load5, load15) = view.load_average;
    write_metric(
        out,
        "describe_me_load1",
        "System load average over 1 minute",
        "gauge",
        load1,
    );
    write_metric(
        out,
        "describe_me_load5",
        "System load average over 5 minutes",
        "gauge",
        load5,
    );
    write_metric(
        out,
        "describe_me_load15",
        "System load average over 15 minutes",
        "gauge",
        load15,
    );

    let free_memory = view
        .total_memory_bytes
        .saturating_sub(view.used_memory_bytes);
    write_metric(
        out,
        "describe_me_memory_bytes_total",
        "Total memory in bytes",
        "gauge",
        view.total_memory_bytes,
    );
    write_metric(
        out,
        "describe_me_memory_bytes_used",
        "Used memory in bytes",
        "gauge",
        view.used_memory_bytes,
    );
    write_metric(
        out,
        "describe_me_memory_bytes_free",
        "Free memory in bytes",
        "gauge",
        free_memory,
    );

    write_metric(
        out,
        "describe_me_swap_bytes_total",
        "Total swap space in bytes",
        "gauge",
        view.total_swap_bytes,
    );
    write_metric(
        out,
        "describe_me_swap_bytes_used",
        "Used swap space in bytes",
        "gauge",
        view.used_swap_bytes,
    );

    if let Some(disk) = view.disk_usage.as_ref() {
        write_metric(
            out,
            "describe_me_disk_bytes_total",
            "Total disk space in bytes",
            "gauge",
            disk.total_bytes,
        );
        write_metric(
            out,
            "describe_me_disk_bytes_available",
            "Available disk space in bytes",
            "gauge",
            disk.available_bytes,
        );
        write_metric(
            out,
            "describe_me_disk_bytes_used",
            "Used disk space in bytes",
            "gauge",
            disk.used_bytes,
        );
    }

    if let Some(updates) = view.updates.as_ref() {
        write_metric(
            out,
            "describe_me_updates_pending",
            "Number of pending system updates",
            "gauge",
            updates.pending,
        );
        write_metric_bool(
            out,
            "describe_me_updates_reboot_required",
            "1 if a reboot is required to apply updates",
            "gauge",
            updates.reboot_required,
        );
    }

    if let Some(containers) = view.containers.as_ref() {
        if let Some(total) = containers_total(containers) {
            write_metric(
                out,
                "describe_me_containers_total",
                "Number of detected containers",
                "gauge",
                total,
            );
        }
        if let Some(running) = containers_running(containers) {
            write_metric(
                out,
                "describe_me_containers_running",
                "Number of running containers",
                "gauge",
                running,
            );
        }
    }

    #[cfg(feature = "net")]
    if let Some(traffic) = view.network_traffic.as_ref() {
        write_network_metrics(out, traffic.as_slice());
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
