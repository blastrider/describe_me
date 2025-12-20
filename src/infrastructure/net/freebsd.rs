use crate::application::net::{NetBackend, NetCollectionParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};
use crate::infrastructure::freebsd::command::run_command;
use crate::infrastructure::net::common::{
    parse_interface_counters_table, parse_listening_row, parse_listening_table, Aggregation,
    CounterMap, ListeningRowSpec,
};

/// FreeBSD backend relying on `sockstat` and `netstat`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreeBsdNetBackend;

impl NetBackend for FreeBsdNetBackend {
    fn collect_listening_sockets(
        &self,
        _ctx: &AppContext,
        params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError> {
        collect_listening_sockets_freebsd(params.resolve_processes)
    }

    fn collect_network_traffic(
        &self,
        _ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
        collect_network_traffic_freebsd()
    }
}

fn collect_listening_sockets_freebsd(
    resolve_processes: bool,
) -> Result<Vec<ListeningSocket>, DescribeError> {
    let output = run_command("sockstat", ["-l", "-4", "-6"], "sockstat")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_sockstat_output(&stdout, resolve_processes))
}

fn parse_sockstat_output(content: &str, resolve_processes: bool) -> Vec<ListeningSocket> {
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

    parse_listening_table(
        content,
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
                        .and_then(|val| parse_host_port(val))
                },
                |cols, spec| {
                    if !resolve_processes {
                        return (None, None);
                    }
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
    )
}

fn parse_host_port(raw: &str) -> Option<(String, u16)> {
    // sockstat uses "addr:port" with IPv6 allowed; split on last ':'.
    let (host, port_raw) = raw.rsplit_once(':')?;
    let port = port_raw.parse::<u16>().ok()?;
    let addr = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    if addr.is_empty() {
        return None;
    }
    Some((addr, port))
}

fn collect_network_traffic_freebsd() -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
    let output = run_command("netstat", ["-ibn"], "netstat -ibn")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_netstat_ibn_output(&stdout))
}

fn parse_netstat_ibn_output(content: &str) -> Vec<NetworkInterfaceTraffic> {
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

    parse_interface_counters_table(
        content,
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
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sockstat_handles_ipv4_and_ipv6() {
        let sample = "\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     sshd       1028  4  tcp4   0.0.0.0:22            *:*
root     ntpd       1051  20 udp6   ::1:123               *:*";
        let sockets = parse_sockstat_output(sample, true);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].proto, "tcp");
        assert_eq!(sockets[0].addr, "0.0.0.0");
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].process, Some(1028));
        assert_eq!(sockets[0].process_name.as_deref(), Some("sshd"));

        assert_eq!(sockets[1].proto, "udp");
        assert_eq!(sockets[1].addr, "::1");
        assert_eq!(sockets[1].port, 123);
    }

    #[test]
    fn parse_sockstat_skips_unparsable_lines() {
        let sample = "\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     syslogd    -     5  dgram  /var/run/log          *:*";
        let sockets = parse_sockstat_output(sample, true);
        assert!(sockets.is_empty());
    }

    #[test]
    fn parse_netstat_ibn_takes_max_per_interface() {
        let sample = "\
Name    Mtu Network       Address            Ipkts Ierrs Ibytes    Opkts Oerrs Obytes  Coll Drop
em0     1500 <Link#1>     00:11:22:33:44:55  100   1     1000      200   2     3000   0    3
em0     1500 192.168.0.0  192.168.0.2        90    0     900       180   0     2500   0    1
lo0     16384 <Link#2>    lo0                10    0     800       10    0     800    0    0";
        let interfaces = parse_netstat_ibn_output(sample);
        assert_eq!(interfaces.len(), 2);

        let em0 = interfaces.iter().find(|it| it.name == "em0").unwrap();
        assert_eq!(em0.rx_packets, 100);
        assert_eq!(em0.tx_packets, 200);
        assert_eq!(em0.rx_bytes, 1000);
        assert_eq!(em0.tx_bytes, 3000);
        assert_eq!(em0.rx_dropped, 3);
        assert_eq!(em0.tx_dropped, 3);

        let lo0 = interfaces.iter().find(|it| it.name == "lo0").unwrap();
        assert_eq!(lo0.rx_bytes, 800);
        assert_eq!(lo0.tx_bytes, 800);
    }
}
