use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct CounterMap {
    pub rx_bytes: usize,
    pub rx_packets: usize,
    pub rx_errors: usize,
    pub rx_dropped: Option<usize>,
    pub tx_bytes: usize,
    pub tx_packets: usize,
    pub tx_errors: usize,
    pub tx_dropped: Option<usize>,
}

#[cfg_attr(not(any(test, target_os = "freebsd")), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub enum Aggregation {
    Append,
    MaxPerInterface,
}

#[cfg_attr(not(any(test, target_os = "freebsd")), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub struct ListeningRowSpec {
    #[allow(dead_code)]
    pub proto_col: Option<usize>,
    #[allow(dead_code)]
    pub local_addr_col: Option<usize>,
    #[allow(dead_code)]
    pub local_port_col: Option<usize>,
    pub local_combined_col: Option<usize>,
    pub remote_col: Option<usize>,
    pub state_col: Option<usize>,
    pub pid_col: Option<usize>,
    pub cmd_col: Option<usize>,
    pub inode_col: Option<usize>,
}

pub fn parse_listening_table<FS, FP, PR>(
    raw: &str,
    skip_line: FS,
    row_predicate: FP,
    mut parse_row: PR,
) -> Vec<ListeningSocket>
where
    FS: Fn(&str, usize) -> bool,
    FP: Fn(&[&str]) -> bool,
    PR: FnMut(&[&str]) -> Option<ListeningSocket>,
{
    let mut sockets = Vec::new();

    for (idx, line) in raw.lines().enumerate() {
        if skip_line(line, idx) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if !row_predicate(&cols) {
            continue;
        }

        if let Some(sock) = parse_row(&cols) {
            sockets.push(sock);
        }
    }

    sockets
}

pub fn parse_listening_row<FP, FL, FR>(
    cols: &[&str],
    spec: &ListeningRowSpec,
    parse_proto: FP,
    parse_local: FL,
    mut resolve_process: FR,
) -> Option<ListeningSocket>
where
    FP: Fn(&[&str], &ListeningRowSpec) -> Option<String>,
    FL: Fn(&[&str], &ListeningRowSpec) -> Option<(String, u16)>,
    FR: FnMut(&[&str], &ListeningRowSpec) -> (Option<u32>, Option<String>),
{
    let proto = parse_proto(cols, spec)?;
    let (addr, port) = parse_local(cols, spec)?;
    let (process, process_name) = resolve_process(cols, spec);

    Some(ListeningSocket {
        proto,
        addr,
        port,
        process,
        process_name,
    })
}

pub fn parse_interface_counters_table<'a, FSkip, FSplit, FParse>(
    raw: &'a str,
    skip_line: FSkip,
    mut split_row: FSplit,
    map: CounterMap,
    mut parse_value: FParse,
    aggregation: Aggregation,
) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError>
where
    FSkip: Fn(&str, usize) -> bool,
    FSplit: FnMut(&'a str) -> Option<(String, Vec<&'a str>)>,
    FParse: Fn(&str, &str) -> Result<Option<u64>, DescribeError>,
{
    let mut appended: Vec<NetworkInterfaceTraffic> = Vec::new();
    let mut dedup: HashMap<String, NetworkInterfaceTraffic> = HashMap::new();

    for (idx, line) in raw.lines().enumerate() {
        if skip_line(line, idx) {
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (name, fields) = match split_row(trimmed) {
            Some(v) => v,
            None => continue,
        };

        if !has_required_fields(&fields, &map) {
            continue;
        }

        let counters = InterfaceCounters::from_fields(&name, &fields, &map, &mut parse_value)?;

        match aggregation {
            Aggregation::Append => appended.push(counters.into_entry(name)),
            Aggregation::MaxPerInterface => {
                let entry = dedup
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterfaceTraffic {
                        name,
                        rx_bytes: 0,
                        rx_packets: 0,
                        rx_errors: 0,
                        rx_dropped: 0,
                        tx_bytes: 0,
                        tx_packets: 0,
                        tx_errors: 0,
                        tx_dropped: 0,
                    });
                counters.apply_max(entry);
            }
        }
    }

    Ok(match aggregation {
        Aggregation::Append => appended,
        Aggregation::MaxPerInterface => dedup.into_values().collect::<Vec<_>>(),
    })
}

fn has_required_fields(fields: &[&str], map: &CounterMap) -> bool {
    let required = [
        map.rx_bytes,
        map.rx_packets,
        map.rx_errors,
        map.tx_bytes,
        map.tx_packets,
        map.tx_errors,
    ];
    required.iter().all(|idx| fields.get(*idx).is_some())
}

#[derive(Debug)]
struct InterfaceCounters {
    rx_bytes: Option<u64>,
    rx_packets: Option<u64>,
    rx_errors: Option<u64>,
    rx_dropped: Option<u64>,
    tx_bytes: Option<u64>,
    tx_packets: Option<u64>,
    tx_errors: Option<u64>,
    tx_dropped: Option<u64>,
}

impl InterfaceCounters {
    fn from_fields<FParse>(
        name: &str,
        fields: &[&str],
        map: &CounterMap,
        parse_value: &mut FParse,
    ) -> Result<Self, DescribeError>
    where
        FParse: Fn(&str, &str) -> Result<Option<u64>, DescribeError>,
    {
        let rx_bytes = parse_value(fields[map.rx_bytes], name)?;
        let rx_packets = parse_value(fields[map.rx_packets], name)?;
        let rx_errors = parse_value(fields[map.rx_errors], name)?;
        let tx_bytes = parse_value(fields[map.tx_bytes], name)?;
        let tx_packets = parse_value(fields[map.tx_packets], name)?;
        let tx_errors = parse_value(fields[map.tx_errors], name)?;

        let rx_dropped = map
            .rx_dropped
            .and_then(|idx| fields.get(idx))
            .map(|val| parse_value(val, name))
            .transpose()?
            .flatten();
        let tx_dropped = map
            .tx_dropped
            .and_then(|idx| fields.get(idx))
            .map(|val| parse_value(val, name))
            .transpose()?
            .flatten();

        Ok(Self {
            rx_bytes,
            rx_packets,
            rx_errors,
            rx_dropped,
            tx_bytes,
            tx_packets,
            tx_errors,
            tx_dropped,
        })
    }

    fn into_entry(self, name: String) -> NetworkInterfaceTraffic {
        NetworkInterfaceTraffic {
            name,
            rx_bytes: self.rx_bytes.unwrap_or(0),
            rx_packets: self.rx_packets.unwrap_or(0),
            rx_errors: self.rx_errors.unwrap_or(0),
            rx_dropped: self.rx_dropped.unwrap_or(0),
            tx_bytes: self.tx_bytes.unwrap_or(0),
            tx_packets: self.tx_packets.unwrap_or(0),
            tx_errors: self.tx_errors.unwrap_or(0),
            tx_dropped: self.tx_dropped.unwrap_or(0),
        }
    }

    fn apply_max(&self, entry: &mut NetworkInterfaceTraffic) {
        if let Some(v) = self.rx_bytes {
            entry.rx_bytes = entry.rx_bytes.max(v);
        }
        if let Some(v) = self.rx_packets {
            entry.rx_packets = entry.rx_packets.max(v);
        }
        if let Some(v) = self.rx_errors {
            entry.rx_errors = entry.rx_errors.max(v);
        }
        if let Some(v) = self.rx_dropped {
            entry.rx_dropped = entry.rx_dropped.max(v);
        }
        if let Some(v) = self.tx_bytes {
            entry.tx_bytes = entry.tx_bytes.max(v);
        }
        if let Some(v) = self.tx_packets {
            entry.tx_packets = entry.tx_packets.max(v);
        }
        if let Some(v) = self.tx_errors {
            entry.tx_errors = entry.tx_errors.max(v);
        }
        if let Some(v) = self.tx_dropped {
            entry.tx_dropped = entry.tx_dropped.max(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_linux_like_table() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
eth0: 100 10 1 2 0 0 0 0 200 20 2 3 0 0 0 0";

        let map = CounterMap {
            rx_bytes: 0,
            rx_packets: 1,
            rx_errors: 2,
            rx_dropped: Some(3),
            tx_bytes: 8,
            tx_packets: 9,
            tx_errors: 10,
            tx_dropped: Some(11),
        };

        let result = parse_interface_counters_table(
            sample,
            |_, idx| idx < 2,
            |line| {
                let (iface_raw, stats_raw) = line.split_once(':')?;
                let name = iface_raw.trim();
                if name.is_empty() {
                    return None;
                }
                let fields: Vec<&str> = stats_raw.split_whitespace().collect();
                if fields.len() < 16 {
                    return None;
                }
                Some((name.to_string(), fields))
            },
            map,
            |val, iface| {
                val.parse::<u64>().map(Some).map_err(|err| {
                    DescribeError::Parse(format!(
                        "invalid counter '{val}' for interface {iface}: {err}"
                    ))
                })
            },
            Aggregation::Append,
        )
        .expect("parsed");

        assert_eq!(result.len(), 1);
        let iface = &result[0];
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.rx_bytes, 100);
        assert_eq!(iface.rx_packets, 10);
        assert_eq!(iface.rx_errors, 1);
        assert_eq!(iface.rx_dropped, 2);
        assert_eq!(iface.tx_bytes, 200);
        assert_eq!(iface.tx_packets, 20);
        assert_eq!(iface.tx_errors, 2);
        assert_eq!(iface.tx_dropped, 3);
    }

    #[test]
    fn parse_freebsd_like_table() {
        let sample = "\
Name    Mtu Network       Address            Ipkts Ierrs Ibytes    Opkts Oerrs Obytes  Coll Drop
em0     1500 <Link#1>     00:11:22:33:44:55  100   1     1000      200   2     3000   0    3";

        let map = CounterMap {
            rx_bytes: 5,
            rx_packets: 3,
            rx_errors: 4,
            rx_dropped: Some(10),
            tx_bytes: 8,
            tx_packets: 6,
            tx_errors: 7,
            tx_dropped: Some(10),
        };

        let result = parse_interface_counters_table(
            sample,
            |line, _| {
                let trimmed = line.trim();
                trimmed.is_empty() || trimmed.starts_with("Name")
            },
            |line| {
                let mut cols = line.split_whitespace();
                let name = cols.next()?.trim();
                if name.is_empty() {
                    return None;
                }
                let rest: Vec<&str> = cols.collect();
                if rest.len() < 9 {
                    return None;
                }
                Some((name.to_string(), rest))
            },
            map,
            |val, _iface| {
                if val.is_empty() || val == "-" {
                    return Ok(None);
                }
                Ok(val.parse::<u64>().ok())
            },
            Aggregation::MaxPerInterface,
        )
        .expect("parsed");

        assert_eq!(result.len(), 1);
        let iface = &result[0];
        assert_eq!(iface.name, "em0");
        assert_eq!(iface.rx_packets, 100);
        assert_eq!(iface.tx_packets, 200);
        assert_eq!(iface.rx_bytes, 1000);
        assert_eq!(iface.tx_bytes, 3000);
        assert_eq!(iface.rx_dropped, 3);
        assert_eq!(iface.tx_dropped, 3);
    }

    #[test]
    fn skips_lines_with_missing_columns() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
eth0: 100 10";

        let map = CounterMap {
            rx_bytes: 0,
            rx_packets: 1,
            rx_errors: 2,
            rx_dropped: Some(3),
            tx_bytes: 8,
            tx_packets: 9,
            tx_errors: 10,
            tx_dropped: Some(11),
        };

        let result = parse_interface_counters_table(
            sample,
            |_, idx| idx < 2,
            |line| {
                let (iface_raw, stats_raw) = line.split_once(':')?;
                let name = iface_raw.trim();
                if name.is_empty() {
                    return None;
                }
                let fields: Vec<&str> = stats_raw.split_whitespace().collect();
                if fields.len() < 16 {
                    return None;
                }
                Some((name.to_string(), fields))
            },
            map,
            |val, iface| {
                val.parse::<u64>().map(Some).map_err(|err| {
                    DescribeError::Parse(format!(
                        "invalid counter '{val}' for interface {iface}: {err}"
                    ))
                })
            },
            Aggregation::Append,
        )
        .expect("parsed");

        assert!(result.is_empty());
    }

    #[test]
    fn parse_listening_table_filters_non_listening_linux_like() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 12345
  1: 0100007F:1F91 00000000:0000 01 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 12346";

        let spec = ListeningRowSpec {
            proto_col: None,
            local_addr_col: None,
            local_port_col: None,
            local_combined_col: Some(1),
            remote_col: Some(2),
            state_col: Some(3),
            pid_col: None,
            cmd_col: None,
            inode_col: Some(11),
        };

        let sockets = parse_listening_table(
            sample,
            |_, idx| idx == 0,
            |cols| cols.len() >= 12 && cols[3] == "0A",
            |cols| {
                parse_listening_row(
                    cols,
                    &spec,
                    |_, _| Some("tcp".to_string()),
                    |cols, spec| {
                        let raw = spec.local_combined_col.and_then(|idx| cols.get(idx))?;
                        let (addr_hex, port_hex) = raw.split_once(':')?;
                        let ip = u32::from_str_radix(addr_hex, 16).ok()?;
                        let bytes = ip.to_le_bytes();
                        let addr = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
                        let port = u16::from_str_radix(port_hex, 16).ok()?;
                        Some((addr, port))
                    },
                    |cols, spec| {
                        let pid = spec
                            .inode_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| raw.parse::<u32>().ok());
                        (pid, None)
                    },
                )
            },
        );

        assert_eq!(sockets.len(), 1);
        let sock = &sockets[0];
        assert_eq!(sock.proto, "tcp");
        assert_eq!(sock.addr, "127.0.0.1");
        assert_eq!(sock.port, 8080);
    }

    #[test]
    fn parse_listening_table_handles_freebsd_sockstat_like() {
        let sample = "\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     sshd       1028  4  tcp4   0.0.0.0:22            *:*";

        let spec = ListeningRowSpec {
            proto_col: Some(4),
            local_addr_col: None,
            local_port_col: None,
            local_combined_col: Some(5),
            remote_col: None,
            state_col: None,
            pid_col: Some(2),
            cmd_col: Some(1),
            inode_col: None,
        };

        let sockets = parse_listening_table(
            sample,
            |_, idx| idx == 0,
            |cols| cols.len() >= 6,
            |cols| {
                parse_listening_row(
                    cols,
                    &spec,
                    |cols, spec| {
                        spec.proto_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| {
                                if raw.starts_with("tcp") {
                                    Some("tcp".to_string())
                                } else if raw.starts_with("udp") {
                                    Some("udp".to_string())
                                } else {
                                    None
                                }
                            })
                    },
                    |cols, spec| {
                        spec.local_combined_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| {
                                let (host, port_raw) = raw.rsplit_once(':')?;
                                let port = port_raw.parse::<u16>().ok()?;
                                let addr = host.trim_matches(|c| c == '[' || c == ']');
                                if addr.is_empty() {
                                    return None;
                                }
                                Some((addr.to_string(), port))
                            })
                    },
                    |cols, spec| {
                        let pid = spec
                            .pid_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| raw.parse::<u32>().ok());
                        let process_name = spec
                            .cmd_col
                            .and_then(|idx| cols.get(idx))
                            .map(|s| s.to_string());
                        (pid, process_name)
                    },
                )
            },
        );

        assert_eq!(sockets.len(), 1);
        let sock = &sockets[0];
        assert_eq!(sock.proto, "tcp");
        assert_eq!(sock.addr, "0.0.0.0");
        assert_eq!(sock.port, 22);
        assert_eq!(sock.process, Some(1028));
        assert_eq!(sock.process_name.as_deref(), Some("sshd"));
    }

    #[test]
    fn parse_listening_table_skips_invalid_ports() {
        let sample = "\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     sshd       1028  4  tcp4   0.0.0.0:bad            *:*";

        let spec = ListeningRowSpec {
            proto_col: Some(4),
            local_addr_col: None,
            local_port_col: None,
            local_combined_col: Some(5),
            remote_col: None,
            state_col: None,
            pid_col: Some(2),
            cmd_col: Some(1),
            inode_col: None,
        };

        let sockets = parse_listening_table(
            sample,
            |_, idx| idx == 0,
            |cols| cols.len() >= 6,
            |cols| {
                parse_listening_row(
                    cols,
                    &spec,
                    |cols, spec| {
                        spec.proto_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| {
                                if raw.starts_with("tcp") {
                                    Some("tcp".to_string())
                                } else if raw.starts_with("udp") {
                                    Some("udp".to_string())
                                } else {
                                    None
                                }
                            })
                    },
                    |cols, spec| {
                        spec.local_combined_col
                            .and_then(|idx| cols.get(idx))
                            .and_then(|raw| {
                                let (host, port_raw) = raw.rsplit_once(':')?;
                                let port = port_raw.parse::<u16>().ok()?;
                                let addr = host.trim_matches(|c| c == '[' || c == ']');
                                if addr.is_empty() {
                                    return None;
                                }
                                Some((addr.to_string(), port))
                            })
                    },
                    |_, _| (None, None),
                )
            },
        );

        assert!(sockets.is_empty());
    }
}
