use anyhow::Result;
#[cfg(feature = "cli")]
use serde::Serialize;

#[cfg(feature = "cli")]
#[derive(Serialize)]
struct CombinedOutput {
    snapshot: describe_me::SystemSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    net_listen: Option<Vec<ListeningSocketOut>>,
}

#[cfg_attr(feature = "cli", derive(Serialize))]
#[derive(Clone)]
pub(crate) struct ListeningSocketOut {
    pub(crate) proto: String,
    pub(crate) addr: String,
    pub(crate) port: u16,
    pub(crate) pid: Option<u32>,
}

#[cfg(feature = "net")]
pub(crate) fn collect_net_listen() -> Result<Vec<ListeningSocketOut>> {
    let socks = describe_me::net_listen()?;
    Ok(socks
        .into_iter()
        .map(|s| ListeningSocketOut {
            proto: s.proto,
            addr: s.addr,
            port: s.port,
            pid: s.process,
        })
        .collect())
}

#[cfg(feature = "net")]
pub(crate) fn print_net_table(list: Option<&[ListeningSocketOut]>, show_process: bool) {
    if show_process {
        println!("{:<5} {:<15} {:<6} {:<6}", "PROTO", "ADDR", "PORT", "PID");
    } else {
        println!("{:<5} {:<15} {:<6}", "PROTO", "ADDR", "PORT");
    }

    if let Some(entries) = list {
        if entries.is_empty() {
            println!("(aucune socket d’écoute trouvée)");
        } else {
            for s in entries {
                if show_process {
                    let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                    println!("{:<5} {:<15} {:<6} {:<6}", s.proto, s.addr, s.port, pid);
                } else {
                    println!("{:<5} {:<15} {:<6}", s.proto, s.addr, s.port);
                }
            }
        }
    }
}

pub(crate) fn print_disks(snapshot: &describe_me::SystemSnapshot) {
    if let Some(du) = &snapshot.disk_usage {
        println!("Disque total: {} Gio", du.total_bytes as f64 / 1e9);
        for p in &du.partitions {
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
}

#[cfg(feature = "cli")]
pub(crate) fn emit_json(
    snap: describe_me::SystemSnapshot,
    pretty: bool,
    #[cfg(feature = "net")] net_listen: Option<Vec<ListeningSocketOut>>,
) -> Result<()> {
    let combined = CombinedOutput {
        snapshot: snap,
        net_listen: {
            #[cfg(feature = "net")]
            {
                net_listen
            }
            #[cfg(not(feature = "net"))]
            {
                None
            }
        },
    };

    if pretty {
        println!("{}", serde_json::to_string_pretty(&combined)?);
    } else {
        println!("{}", serde_json::to_string(&combined)?);
    }
    Ok(())
}

#[cfg(not(feature = "cli"))]
pub(crate) fn emit_json(snap: describe_me::SystemSnapshot, pretty: bool) -> Result<()> {
    if pretty {
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        println!("{}", serde_json::to_string(&snap)?);
    }
    Ok(())
}

pub(crate) fn print_snapshot(snapshot: &describe_me::SystemSnapshot) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(snapshot)?);
    Ok(())
}
