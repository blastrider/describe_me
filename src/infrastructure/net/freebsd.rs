use crate::application::net::{NetBackend, NetCollectionParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};
use std::collections::HashMap;
use std::process::{Command, Stdio};

const NET_COMMAND_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    let mut cmd = Command::new("sockstat");
    cmd.args(["-l", "-4", "-6"])
        .env_clear()
        .env("PATH", NET_COMMAND_PATH)
        .stdin(Stdio::null());

    let output = cmd
        .output()
        .map_err(|err| DescribeError::External(format!("sockstat: {err}")))?;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "sockstat exited with {status}",
            status = output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_sockstat_output(&stdout, resolve_processes))
}

fn parse_sockstat_output(content: &str, resolve_processes: bool) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue; // header
        }

        let mut cols = line.split_whitespace();
        let _user = cols.next();
        let command = cols.next();
        let pid_raw = cols.next();
        let _fd = cols.next();
        let proto_raw = cols.next().unwrap_or_default();
        let proto = match proto_raw {
            p if p.starts_with("tcp") => "tcp",
            p if p.starts_with("udp") => "udp",
            _ => continue,
        }
        .to_string();

        let local = match cols.next() {
            Some(val) if !val.is_empty() => val,
            _ => continue,
        };

        let (addr, port) = match parse_host_port(local) {
            Some(t) => t,
            None => continue,
        };

        let pid = if resolve_processes {
            pid_raw.and_then(|p| p.parse::<u32>().ok())
        } else {
            None
        };
        let process_name = if resolve_processes {
            command.map(|s| s.to_string())
        } else {
            None
        };

        sockets.push(ListeningSocket {
            proto,
            addr,
            port,
            process: pid,
            process_name,
        });
    }

    sockets
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
    let mut cmd = Command::new("netstat");
    cmd.args(["-ibn"])
        .env_clear()
        .env("PATH", NET_COMMAND_PATH)
        .stdin(Stdio::null());

    let output = cmd
        .output()
        .map_err(|err| DescribeError::External(format!("netstat -ibn: {err}")))?;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "netstat -ibn exited with {status}",
            status = output.status
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_netstat_ibn_output(&stdout))
}

fn parse_netstat_ibn_output(content: &str) -> Vec<NetworkInterfaceTraffic> {
    let mut interfaces: HashMap<String, NetworkInterfaceTraffic> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Name") {
            continue;
        }

        let mut cols = trimmed.split_whitespace();
        let name = match cols.next() {
            Some(name) => name,
            None => continue,
        };
        if name.is_empty() {
            continue;
        }

        let _mtu = cols.next();
        let _network = cols.next();
        let _address = cols.next();
        let (
            Some(rx_packets_raw),
            Some(rx_errors_raw),
            Some(rx_bytes_raw),
            Some(tx_packets_raw),
            Some(tx_errors_raw),
            Some(tx_bytes_raw),
        ) = (
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
        )
        else {
            continue;
        };
        let _coll = cols.next();
        let drops_raw = cols.next(); // Column may be missing; `None` if so.

        let rx_packets = parse_counter(Some(rx_packets_raw));
        let rx_errors = parse_counter(Some(rx_errors_raw));
        let rx_bytes = parse_counter(Some(rx_bytes_raw));
        let tx_packets = parse_counter(Some(tx_packets_raw));
        let tx_errors = parse_counter(Some(tx_errors_raw));
        let tx_bytes = parse_counter(Some(tx_bytes_raw));
        let drops = parse_counter(drops_raw);

        let entry = interfaces
            .entry(name.to_string())
            .or_insert_with(|| NetworkInterfaceTraffic {
                name: name.to_string(),
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            });

        if let Some(v) = rx_bytes {
            entry.rx_bytes = entry.rx_bytes.max(v);
        }
        if let Some(v) = rx_packets {
            entry.rx_packets = entry.rx_packets.max(v);
        }
        if let Some(v) = rx_errors {
            entry.rx_errors = entry.rx_errors.max(v);
        }
        if let Some(v) = tx_bytes {
            entry.tx_bytes = entry.tx_bytes.max(v);
        }
        if let Some(v) = tx_packets {
            entry.tx_packets = entry.tx_packets.max(v);
        }
        if let Some(v) = tx_errors {
            entry.tx_errors = entry.tx_errors.max(v);
        }
        if let Some(v) = drops {
            entry.rx_dropped = entry.rx_dropped.max(v);
            // netstat does not provide separate TX drops; reuse best-effort value.
            entry.tx_dropped = entry.tx_dropped.max(v);
        }
    }

    interfaces.into_values().collect()
}

fn parse_counter(raw: Option<&str>) -> Option<u64> {
    match raw {
        Some(val) if !val.is_empty() && val != "-" => val.parse::<u64>().ok(),
        _ => None,
    }
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
