use crate::application::net::{NetBackend, NetCollectionParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};
use tracing::debug;

const PROC_ROOT: &str = "/proc";

/// Linux backend for network collection (procfs-based).
///
/// Linux-only: relies on `/proc/net/*` tables and `/proc/<pid>/fd` inode resolution.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxNetBackend;

impl NetBackend for LinuxNetBackend {
    fn collect_listening_sockets(
        &self,
        _ctx: &AppContext,
        params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError> {
        collect_listening_sockets_linux(params.resolve_processes)
    }

    fn collect_network_traffic(
        &self,
        _ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
        collect_network_traffic_linux()
    }
}

pub(crate) fn collect_listening_sockets_linux(
    resolve_processes: bool,
) -> Result<Vec<ListeningSocket>, DescribeError> {
    collect_listening_sockets_from_root(Path::new(PROC_ROOT), resolve_processes)
}

fn collect_listening_sockets_from_root(
    proc_root: &Path,
    resolve_processes: bool,
) -> Result<Vec<ListeningSocket>, DescribeError> {
    let net_dir = proc_root.join("net");
    if !net_dir.is_dir() {
        debug!(
            proc_root = %proc_root.display(),
            "procfs absent or /proc/net missing; returning empty listening sockets"
        );
        return Ok(Vec::new());
    }

    // Map inode -> pid (meilleur-effort)
    let inode_to_pid = if resolve_processes {
        build_inode_pid_map_from_root(proc_root).unwrap_or_else(|err| {
            debug!(
                proc_root = %proc_root.display(),
                error = %err,
                "failed to build inode map; continuing without process resolution"
            );
            HashMap::new()
        })
    } else {
        HashMap::new()
    };
    let mut pid_cache: HashMap<u32, Option<String>> = HashMap::new();

    let mut out = Vec::new();

    let tables = [
        ("tcp", TableParseOpts::tcp(AddressKind::V4)),
        ("tcp6", TableParseOpts::tcp(AddressKind::V6)),
        ("udp", TableParseOpts::udp(AddressKind::V4)),
        ("udp6", TableParseOpts::udp(AddressKind::V6)),
    ];

    for (file, opts) in tables {
        let path = net_dir.join(file);
        if opts.proto == "udp" {
            debug_assert!(
                opts.require_wildcard_remote,
                "UDP listening requires wildcard remote to avoid client sockets"
            );
        }
        match parse_table(
            &path,
            opts,
            &inode_to_pid,
            &mut pid_cache,
            resolve_processes,
        ) {
            Ok(mut v) => out.append(&mut v),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::trace!(path = %path.display(), "listening table missing (likely IPv4-only system)");
            }
            Err(err) => debug!(path = %path.display(), error = %err, "skip listening table"),
        }
    }

    Ok(out)
}

fn parse_table(
    path: &Path,
    opts: TableParseOpts<'_>,
    inode_to_pid: &HashMap<u64, u32>,
    pid_cache: &mut HashMap<u32, Option<String>>,
    resolve_processes: bool,
) -> io::Result<Vec<ListeningSocket>> {
    // Linux-only: procfs socket tables (/proc/net/{tcp,udp}).
    let content = fs::read_to_string(path)?;
    Ok(parse_table_content(
        &content,
        opts,
        inode_to_pid,
        pid_cache,
        resolve_processes,
    ))
}

fn parse_table_content(
    content: &str,
    opts: TableParseOpts<'_>,
    inode_to_pid: &HashMap<u64, u32>,
    pid_cache: &mut HashMap<u32, Option<String>>,
    resolve_processes: bool,
) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue; // skip header
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 12 {
            continue;
        }
        let local = cols[1]; // "HHHHHHHH:PPPP" (IPv4) or "HH..HH:PPPP" (IPv6)
        let remote = cols[2];
        let st = cols[3]; // "0A" LISTEN (tcp) / "07" UNCONN (udp)
        let inode_str = cols[11]; // inode

        if let Some(req) = opts.required_state_hex {
            if st != req {
                continue;
            }
        }

        if opts.require_wildcard_remote && !is_wildcard_remote(remote, opts.addr_kind) {
            continue;
        }

        let (addr, port) = match parse_host_port(local, opts.addr_kind) {
            Some(x) => x,
            None => continue,
        };

        // Inode -> PID
        let pid = if resolve_processes {
            inode_str
                .parse::<u64>()
                .ok()
                .and_then(|ino| inode_to_pid.get(&ino).copied())
        } else {
            None
        };
        let process_name = if resolve_processes {
            pid.and_then(|p| resolve_process_name(p, pid_cache))
        } else {
            None
        };

        sockets.push(ListeningSocket {
            proto: opts.proto.to_string(),
            addr,
            port,
            process: pid,
            process_name,
        });
    }

    sockets
}

#[cfg(any(test, feature = "internals"))]
pub fn parse_table_from_str(
    content: &str,
    opts: TableParseOpts<'_>,
    inode_to_pid: &HashMap<u64, u32>,
    resolve_processes: bool,
) -> Vec<ListeningSocket> {
    let mut cache = HashMap::new();
    parse_table_content(content, opts, inode_to_pid, &mut cache, resolve_processes)
}

fn parse_ipv4_host_port(spec: &str) -> Option<(String, u16)> {
    // spec: "0100007F:1F90"
    let (hex_ip, hex_port) = spec.split_once(':')?;
    if hex_ip.len() != 8 {
        return None;
    }
    let ip_u32 = u32::from_str_radix(hex_ip, 16).ok()?;
    let bytes = ip_u32.to_le_bytes(); // /proc/net est little-endian
    let addr = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);

    let port = u16::from_str_radix(hex_port, 16).ok()?;
    Some((addr, port))
}

fn decode_procnet_ipv6(hex_ip: &str) -> Option<std::net::Ipv6Addr> {
    if hex_ip.len() != 32 {
        return None;
    }
    // Linux /proc/net/{tcp6,udp6}: IPv6 stored as 4x32-bit little-endian words
    // (bytes reversed inside each 32-bit chunk, word order preserved).
    // See fs/proc/net.c in the kernel for the layout.
    let mut raw = [0u8; 16];
    for (i, chunk) in hex_ip.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        raw[i] = u8::from_str_radix(hex, 16).ok()?;
    }

    // /proc/net/*6 encodes IPv6 addresses in little-endian per 32-bit word.
    let mut reordered = [0u8; 16];
    for (chunk_idx, chunk) in raw.chunks_exact(4).enumerate() {
        let base = chunk_idx * 4;
        reordered[base] = chunk[3];
        reordered[base + 1] = chunk[2];
        reordered[base + 2] = chunk[1];
        reordered[base + 3] = chunk[0];
    }

    Some(std::net::Ipv6Addr::from(reordered))
}

fn parse_ipv6_host_port(spec: &str) -> Option<(String, u16)> {
    let (hex_ip, hex_port) = spec.split_once(':')?;
    let addr = decode_procnet_ipv6(hex_ip)?.to_string();
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    Some((addr, port))
}

fn parse_host_port(spec: &str, kind: AddressKind) -> Option<(String, u16)> {
    match kind {
        AddressKind::V4 => parse_ipv4_host_port(spec),
        AddressKind::V6 => parse_ipv6_host_port(spec),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy)]
pub struct TableParseOpts<'a> {
    proto: &'a str,
    required_state_hex: Option<&'a str>,
    require_wildcard_remote: bool,
    addr_kind: AddressKind,
}

impl<'a> TableParseOpts<'a> {
    fn tcp(addr_kind: AddressKind) -> Self {
        Self {
            proto: "tcp",
            required_state_hex: Some("0A"),
            require_wildcard_remote: false,
            addr_kind,
        }
    }

    fn udp(addr_kind: AddressKind) -> Self {
        Self {
            proto: "udp",
            required_state_hex: Some("07"),
            require_wildcard_remote: true,
            addr_kind,
        }
    }
}

#[cfg(any(test, feature = "internals"))]
pub fn table_parse_opts_tcp(kind: AddressKind) -> TableParseOpts<'static> {
    TableParseOpts::tcp(kind)
}

#[cfg(any(test, feature = "internals"))]
pub fn table_parse_opts_udp(kind: AddressKind) -> TableParseOpts<'static> {
    TableParseOpts::udp(kind)
}

fn is_wildcard_remote(remote: &str, kind: AddressKind) -> bool {
    match kind {
        AddressKind::V4 => remote == "00000000:0000",
        AddressKind::V6 => remote == "00000000000000000000000000000000:0000",
    }
}

fn build_inode_pid_map_from_root(proc_root: &Path) -> io::Result<HashMap<u64, u32>> {
    // Linux-only: scans /proc/<pid>/fd to map socket inodes to owning PIDs.
    let mut map = HashMap::new();
    if !proc_root.is_dir() {
        return Ok(map);
    }

    for entry in fs::read_dir(proc_root)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let pid: u32 = match file_name.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // pas de droits ⇒ ignore
        };

        for fd in fds {
            let fd = match fd {
                Ok(f) => f,
                Err(_) => continue,
            };
            let target = match fs::read_link(fd.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let s = target.to_string_lossy();
            // Exemple: "socket:[123456]"
            if let Some(ino) = s
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                if let Ok(v) = ino.parse::<u64>() {
                    // Premier PID suffisant (peut y en avoir plusieurs — meilleure-effort)
                    map.entry(v).or_insert(pid);
                }
            }
        }
    }
    Ok(map)
}

fn resolve_process_name(pid: u32, cache: &mut HashMap<u32, Option<String>>) -> Option<String> {
    if let Some(entry) = cache.get(&pid) {
        return entry.clone();
    }

    let name = read_process_name(pid);
    cache.insert(pid, name.clone());
    name
}

fn read_process_name(pid: u32) -> Option<String> {
    let mut path = PathBuf::from("/proc");
    path.push(pid.to_string());
    path.push("comm");
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|name| !name.is_empty())
}

pub(crate) fn collect_network_traffic_linux() -> Result<Vec<NetworkInterfaceTraffic>, DescribeError>
{
    let default_path = Path::new(PROC_ROOT).join("net/dev");
    collect_network_traffic_from_path(&default_path)
}

fn collect_network_traffic_from_path(
    path: &Path,
) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
    let content = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) {
                debug!(
                    path = %path.display(),
                    "procfs not available for network traffic; returning empty list"
                );
                return Ok(Vec::new());
            }
            return Err(DescribeError::System(format!(
                "read {}: {err}",
                path.display()
            )));
        }
    };

    let mut interfaces = Vec::new();

    for line in content.lines().skip(2) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (iface_raw, stats_raw) = match trimmed.split_once(':') {
            Some(parts) => parts,
            None => continue,
        };

        let name = iface_raw.trim();
        if name.is_empty() {
            continue;
        }

        let fields: Vec<&str> = stats_raw.split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }

        let parse_field = |idx: usize| -> Result<u64, DescribeError> {
            fields[idx].parse::<u64>().map_err(|err| {
                DescribeError::Parse(format!(
                    "invalid counter '{}' for interface {name}: {err}",
                    fields[idx]
                ))
            })
        };

        let entry = NetworkInterfaceTraffic {
            name: name.to_string(),
            rx_bytes: parse_field(0)?,
            rx_packets: parse_field(1)?,
            rx_errors: parse_field(2)?,
            rx_dropped: parse_field(3)?,
            tx_bytes: parse_field(8)?,
            tx_packets: parse_field(9)?,
            tx_errors: parse_field(10)?,
            tx_dropped: parse_field(11)?,
        };

        interfaces.push(entry);
    }

    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use tempfile::NamedTempFile;

    fn write_sample_table() -> (NamedTempFile, PathBuf) {
        let mut file = NamedTempFile::new().expect("create temp file");
        writeln!(
            file,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
        )
        .unwrap();
        writeln!(
            file,
            "  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 12345"
        )
        .unwrap();
        file.flush().unwrap();
        let path = file.path().to_path_buf();
        (file, path)
    }

    #[test]
    fn parse_table_returns_socket_without_process_when_disabled() {
        let (_file, path) = write_sample_table();
        let sockets = parse_table(
            &path,
            TableParseOpts::tcp(AddressKind::V4),
            &HashMap::new(),
            &mut HashMap::new(),
            false,
        )
        .expect("parse table");
        assert_eq!(sockets.len(), 1);
        let sock = &sockets[0];
        assert_eq!(sock.addr, "127.0.0.1");
        assert_eq!(sock.port, 8080);
        assert!(sock.process.is_none());
        assert!(sock.process_name.is_none());
    }

    #[test]
    fn parse_table_sets_process_when_enabled() {
        let (_file, path) = write_sample_table();
        let mut inode_to_pid = HashMap::new();
        inode_to_pid.insert(12345, 4242);
        let mut cache = HashMap::new();

        let sockets = parse_table(
            &path,
            TableParseOpts::tcp(AddressKind::V4),
            &inode_to_pid,
            &mut cache,
            true,
        )
        .expect("parse table");
        assert_eq!(sockets.len(), 1);
        let sock = &sockets[0];
        assert_eq!(sock.process, Some(4242));
    }

    #[test]
    fn collect_listening_sockets_handles_missing_proc() {
        let sockets =
            collect_listening_sockets_from_root(Path::new("/nonexistent/proc"), false).unwrap();
        assert!(sockets.is_empty());
    }

    #[test]
    fn collect_network_traffic_handles_missing_proc() {
        let traffic =
            collect_network_traffic_from_path(Path::new("/nonexistent/proc/net/dev")).unwrap();
        assert!(traffic.is_empty());
    }

    #[test]
    fn parse_udp_filters_non_wildcard_remote() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: 0100007F:1F90 0100007F:0035 07 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 12345
  1: 00000000:1F91 00000000:0000 07 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 12346";
        let sockets = parse_table_from_str(
            content,
            TableParseOpts::udp(AddressKind::V4),
            &HashMap::new(),
            false,
        );
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 8081);
    }

    #[test]
    fn parse_tcp6_includes_ipv6_entries() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 11111";
        let sockets = parse_table_from_str(
            content,
            TableParseOpts::tcp(AddressKind::V6),
            &HashMap::new(),
            false,
        );
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].addr, "::");
        assert_eq!(sockets[0].port, 8080);
    }

    #[test]
    fn parse_udp6_filters_remote_and_parses_ipv6() {
        let loopback_hex = "00000000000000000000000001000000";
        let other_hex = "00000000000000000000000002000000";
        let content = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: {loopback}:1F92 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 11112
  1: {other}:1F93 {loopback}:0035 07 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 11113",
            loopback = loopback_hex,
            other = other_hex
        );
        let sockets = parse_table_from_str(
            &content,
            TableParseOpts::udp(AddressKind::V6),
            &HashMap::new(),
            false,
        );
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].addr, "::1");
        assert_eq!(sockets[0].port, 8082);
    }

    #[test]
    fn parse_tcp6_parses_non_zero_ipv6() {
        // procfs encodes 2001:db8::1 with per-word little endian order.
        let encoded = "B80D0120000000000000000001000000";
        let content = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: {encoded}:1F94 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 22222"
        );
        let sockets = parse_table_from_str(
            &content,
            TableParseOpts::tcp(AddressKind::V6),
            &HashMap::new(),
            false,
        );
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].addr, "2001:db8::1");
        assert_eq!(sockets[0].port, 8084);
    }

    #[test]
    fn decode_procnet_ipv6_loopback() {
        let addr = decode_procnet_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(addr.to_string(), "::1");
    }

    #[test]
    fn decode_procnet_ipv6_roundtrip_known_address() {
        use std::net::Ipv6Addr;
        let target = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let encoded = "B80D0120000000000000000001000000";
        let decoded = decode_procnet_ipv6(encoded).unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn parse_tcp6_line_matches_expected_ipv6() {
        // Ground truth: local 2001:db8::1 port 0050 (80), remote wildcard.
        // procfs encodes each 32-bit word little-endian, word order preserved.
        // 2001:0db8::1 in words: 2001 0db8 0000 0000 0000 0000 0000 0001
        // Hex with per-word LE: B80D0120 00000000 00000000 01000000 => concatenated:
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
  0: B80D0120000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 33333";
        let sockets = parse_table_from_str(
            content,
            TableParseOpts::tcp(AddressKind::V6),
            &HashMap::new(),
            false,
        );
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].addr, "2001:db8::1");
        assert_eq!(sockets[0].port, 80);
    }

    // Helper used only inside tests to build procfs-encoded hex from an IPv6 address.
    #[allow(dead_code)]
    fn encode_procnet_ipv6(addr: std::net::Ipv6Addr) -> String {
        let octets = addr.octets();
        let mut encoded = String::new();
        for chunk in octets.chunks(4) {
            for b in chunk.iter().rev() {
                encoded.push_str(&format!("{:02X}", b));
            }
        }
        encoded
    }

    proptest! {
        #[test]
        fn parse_ipv4_roundtrip(addr_bytes in any::<[u8;4]>(), port in any::<u16>()) {
            let spec = format!("{:08X}:{:04X}", u32::from_le_bytes(addr_bytes), port);
            let parsed = parse_ipv4_host_port(&spec).expect("parsed");
            let expected_addr = format!("{}.{}.{}.{}", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
            prop_assert_eq!(parsed.0, expected_addr);
            prop_assert_eq!(parsed.1, port);
        }

        #[test]
        fn parse_table_handles_random_rows(entries in prop::collection::vec((any::<[u8;4]>(), any::<u16>()), 0..16)) {
            let mut content = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n");
            for (idx, (addr_bytes, port)) in entries.iter().enumerate() {
                let hex_ip = format!("{:08X}", u32::from_le_bytes(*addr_bytes));
                let hex_port = format!("{:04X}", port);
                let inode = 1000 + idx as u64;
                content.push_str(&format!(
                    "{:4}: {}:{} 00000000:0000 0A 00000000:00000000 00:00000000 00:00000000 00000000 00000000 00000000 00000000 {}\n",
                    idx,
                    hex_ip,
                    hex_port,
                    inode
                ));
            }

            let parsed = parse_table_from_str(
                &content,
                TableParseOpts::tcp(AddressKind::V4),
                &HashMap::new(),
                false,
            );
            prop_assert_eq!(parsed.len(), entries.len());
            for (parsed_sock, (addr_bytes, port)) in parsed.iter().zip(entries.iter()) {
                let expected_addr =
                    format!("{}.{}.{}.{}", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
                prop_assert_eq!(parsed_sock.addr.as_str(), expected_addr.as_str());
                prop_assert_eq!(parsed_sock.port, *port);
            }
        }
    }
}
