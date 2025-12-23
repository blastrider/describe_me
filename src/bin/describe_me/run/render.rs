use anyhow::Result;
#[cfg(feature = "cli")]
use serde::Serialize;

use describe_me_lib::{paginate_slice, PageRequest};

use crate::describe_me::args::{CliConfig, OutputFormat};

#[cfg(feature = "net")]
use describe_me_lib::domain::{ListeningSocket, NetworkInterfaceTraffic};

pub fn resolve_mode(cli: &CliConfig) -> &'static str {
    if cli.web.bind.is_some() {
        "web"
    } else {
        match cli.output.format() {
            OutputFormat::JsonPretty => "json_pretty",
            OutputFormat::Json => "json",
            OutputFormat::Cli => "cli",
        }
    }
}

pub fn render_output(
    cli: &CliConfig,
    snap: &describe_me_lib::SystemSnapshot,
    snapshot_view: &describe_me_lib::SnapshotView,
) -> Result<()> {
    let output_format = cli.output.format();

    if matches!(output_format, OutputFormat::Json | OutputFormat::JsonPretty) {
        #[cfg(feature = "cli")]
        {
            if cli.output.summary {
                print_summary_line(snapshot_view);
            }
            let combined = CombinedOutput {
                snapshot: snapshot_view,
                #[cfg(feature = "net")]
                net_traffic: snapshot_view.network_traffic.as_ref().map(|s| s.as_slice()),
                #[cfg(feature = "net")]
                net_listen: snapshot_view
                    .listening_sockets
                    .as_ref()
                    .map(|s| s.as_slice()),
            };

            match output_format {
                OutputFormat::JsonPretty => {
                    println!("{}", serde_json::to_string_pretty(&combined)?);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string(&combined)?);
                }
                OutputFormat::Cli => unreachable!(),
            }
            return Ok(());
        }
        #[cfg(not(feature = "cli"))]
        {
            println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
            return Ok(());
        }
    }

    if cli.output.summary {
        print_summary_line(snapshot_view);
    }

    if let Some(desc) = snapshot_view.server_description.as_deref() {
        print_description_block(desc);
        println!();
    }
    if !snapshot_view.server_tags.is_empty() {
        print_tags_line(&snapshot_view.server_tags);
        println!();
    }

    #[cfg(feature = "systemd")]
    if cli.capture.with_services {
        print_services_cli(
            snapshot_view,
            cli.capture.services_limit,
            cli.capture.services_offset,
        );
    }

    if cli.capture.containers {
        print_containers_cli(snapshot_view);
    }

    #[cfg(feature = "net")]
    if cli.capture.net_listen {
        if let Some(list) = snapshot_view.listening_sockets.as_ref() {
            print_sockets_cli(
                list.as_slice(),
                cli.capture.show_process,
                cli.capture.sockets_limit,
                cli.capture.sockets_offset,
            );
        } else {
            println!("(listening sockets non exposées)");
            println!();
        }
    }

    #[cfg(feature = "net")]
    if cli.capture.net_traffic {
        println!(
            "{:<10} {:>14} {:>14} {:>12} {:>12} {:>13} {:>13}",
            "IFACE",
            "RX(bytes)",
            "TX(bytes)",
            "RX(pkts)",
            "TX(pkts)",
            "RX(err/drop)",
            "TX(err/drop)"
        );
        if let Some(traffic) = &snap.network_traffic {
            if traffic.is_empty() {
                println!("(aucune interface réseau observée)");
            } else {
                for entry in traffic.as_slice() {
                    println!(
                        "{:<10} {:>14} {:>14} {:>12} {:>12} {:>13} {:>13}",
                        entry.name,
                        entry.rx_bytes,
                        entry.tx_bytes,
                        entry.rx_packets,
                        entry.tx_packets,
                        format!("{}/{}", entry.rx_errors, entry.rx_dropped),
                        format!("{}/{}", entry.tx_errors, entry.tx_dropped),
                    );
                }
            }
        } else {
            println!("(trafic reseau non capture)");
        }
        println!();
    }

    if cli.capture.disks {
        if let Some(du) = &snap.disk_usage {
            println!("Disque total: {} Gio", du.total_bytes as f64 / 1e9);
            for p in du.partitions.as_slice() {
                println!(
                    "{}  total={} Gio  dispo={} Gio  fs={:?}",
                    p.mount_point,
                    p.total_bytes as f64 / 1e9,
                    p.available_bytes as f64 / 1e9,
                    p.fs_type
                );
            }
        } else {
            println!("(usage disque non capturé)");
        }
        println!();
    }

    println!("{}", serde_json::to_string_pretty(&snapshot_view)?);
    Ok(())
}

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput<'a> {
    snapshot: &'a describe_me_lib::SnapshotView,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_traffic: Option<&'a [NetworkInterfaceTraffic]>,
    #[cfg(feature = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<&'a [ListeningSocket]>,
}

#[cfg(feature = "cli")]
fn print_summary_line(view: &describe_me_lib::SnapshotView) {
    println!("{}", summary_line(view));
}

fn summary_line(view: &describe_me_lib::SnapshotView) -> String {
    let (pending, reboot) = match view.updates.as_ref() {
        Some(info) => (
            info.pending.to_string(),
            if info.reboot_required { "yes" } else { "no" },
        ),
        None => (String::from("?"), "unknown"),
    };
    let containers = view
        .containers
        .as_ref()
        .and_then(|c| c.summary.as_ref())
        .map(|s| format!(" containers={}/{}", s.running, s.total))
        .unwrap_or_default();
    format!("updates={pending} reboot={reboot}{containers}")
}

fn print_description_block(desc: &str) {
    if desc.contains('\n') {
        println!("Description :");
        for line in desc.lines() {
            if line.is_empty() {
                println!();
            } else {
                println!("  {line}");
            }
        }
    } else {
        println!("Description : {desc}");
    }
}

fn print_tags_line(tags: &[String]) {
    if tags.is_empty() {
        return;
    }
    println!("Tags : {}", tags.join(", "));
}

#[cfg(feature = "systemd")]
fn print_services_cli(view: &describe_me_lib::SnapshotView, limit: Option<usize>, offset: usize) {
    println!("{:<38} {:<14} INFO", "SERVICE", "STATUT");

    if let Some(list) = view.services_running.as_ref() {
        let services = list.as_slice();
        if services.is_empty() {
            println!("(aucun service actif rapporté)");
            println!();
            return;
        }

        let fallback_limit = services.len().clamp(1, SERVICES_PAGE_MAX);
        let page = paginate_slice(
            services,
            PageRequest {
                offset,
                limit: limit.unwrap_or(fallback_limit),
            },
            SERVICES_PAGE_MAX,
        );

        for svc in &page.items {
            let summary = svc.summary.as_deref().unwrap_or("");
            if summary.is_empty() {
                println!("{:<38} {:<14}", svc.name, svc.state);
            } else {
                println!("{:<38} {:<14} {}", svc.name, svc.state, summary);
            }
        }
        print_page_hint(page.total, page.offset, page.limit, page.items.len());
    } else if let Some(summary) = view.services_summary.as_ref() {
        println!("{} service(s) observé(s)", summary.total);
        if !summary.by_state.is_empty() {
            let joined = summary
                .by_state
                .iter()
                .map(|item| format!("{}: {}", item.state, item.count))
                .collect::<Vec<_>>()
                .join(" • ");
            println!("Répartition: {joined}");
        }
    } else {
        println!("(services non exposés)");
    }
    println!();
}

fn print_containers_cli(view: &describe_me_lib::SnapshotView) {
    println!(
        "{:<24} {:<10} {:<12} {:<18} IMAGE",
        "CONTAINER", "RUNTIME", "STATE", "IP"
    );

    match view.containers.as_ref() {
        None => {
            println!("(conteneurs non capturés ou non exposés)");
        }
        Some(snapshot) => {
            if let Some(summary) = snapshot.summary.as_ref() {
                println!("Total: {} (running: {})", summary.total, summary.running);
            }
            match snapshot.containers.as_ref() {
                Some(list) => {
                    let containers = list.as_slice();
                    if containers.is_empty() {
                        println!("(aucun conteneur)");
                    } else {
                        for c in containers {
                            let ip = c.ip.as_deref().unwrap_or("-");
                            let image = c.image.as_deref().unwrap_or("-");
                            println!(
                                "{:<24} {:<10} {:<12} {:<18} {}",
                                c.name, c.runtime, c.state, ip, image
                            );
                        }
                    }
                }
                None => {
                    println!("(détails conteneurs non exposés)");
                }
            }
        }
    }
    println!();
}

#[cfg(feature = "net")]
fn print_sockets_cli(
    sockets: &[ListeningSocket],
    show_process: bool,
    limit: Option<usize>,
    offset: usize,
) {
    if show_process {
        println!(
            "{:<5} {:<15} {:<6} {:<8} {:<}",
            "PROTO", "ADDR", "PORT", "PID", "PROCESS"
        );
    } else {
        println!("{:<5} {:<15} {:<6}", "PROTO", "ADDR", "PORT");
    }

    if sockets.is_empty() {
        println!("(aucune socket d’écoute trouvée)");
        println!();
        return;
    }

    let fallback_limit = sockets.len().clamp(1, SOCKETS_PAGE_MAX);
    let page = paginate_slice(
        sockets,
        PageRequest {
            offset,
            limit: limit.unwrap_or(fallback_limit),
        },
        SOCKETS_PAGE_MAX,
    );

    for s in &page.items {
        if show_process {
            let pid = s
                .process
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into());
            let name = s.process_name.as_deref().unwrap_or("?");
            println!(
                "{:<5} {:<15} {:<6} {:<8} {}",
                s.proto, s.addr, s.port, pid, name
            );
        } else {
            println!("{:<5} {:<15} {:<6}", s.proto, s.addr, s.port);
        }
    }
    print_page_hint(page.total, page.offset, page.limit, page.items.len());
    println!();
}

fn print_page_hint(total: usize, offset: usize, limit: usize, displayed: usize) {
    if total == 0 || displayed == 0 {
        return;
    }
    if total <= displayed && offset == 0 {
        return;
    }
    let start = offset + 1;
    let end = offset + displayed;
    let page_idx = offset / limit + 1;
    let total_pages = total.div_ceil(limit);
    println!(
        "(page {}/{} — entrées {}-{} sur {})",
        page_idx, total_pages, start, end, total
    );
}

const SERVICES_PAGE_MAX: usize = 500;
const SOCKETS_PAGE_MAX: usize = 500;

#[cfg(test)]
mod tests {
    use describe_me_lib::ContainersSnapshot;

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_uses_updates_info() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: Some(describe_me_lib::UpdatesInfo {
                pending: 5,
                reboot_required: true,
                packages: None,
            }),
            extensions: None,
        };
        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=5 reboot=yes");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_handles_missing_updates() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: None,
            extensions: None,
        };
        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(super::summary_line(&view), "updates=? reboot=unknown");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn summary_line_includes_containers_counts_when_present() {
        let snapshot = describe_me_lib::SystemSnapshot {
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
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: Some(ContainersSnapshot {
                summary: Some(describe_me_lib::ContainersSummary {
                    total: 3,
                    running: 2,
                }),
                containers: None,
            }),
            updates: Some(describe_me_lib::UpdatesInfo {
                pending: 0,
                reboot_required: false,
                packages: None,
            }),
            extensions: None,
        };

        let mut exposure = describe_me_lib::Exposure::default();
        exposure.set_updates(true);
        exposure.set_containers_summary(true);
        let view = describe_me_lib::SnapshotView::new(&snapshot, exposure);
        assert_eq!(
            super::summary_line(&view),
            "updates=0 reboot=no containers=2/3"
        );
    }
}
