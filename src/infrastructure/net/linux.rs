use crate::domain::{DescribeError, ListeningSocket};
use std::{collections::HashMap, fs, io, path::Path};

pub fn collect_listening_sockets() -> Result<Vec<ListeningSocket>, DescribeError> {
    // Map inode -> pid (meilleur-effort)
    let inode_to_pid = build_inode_pid_map().unwrap_or_default();

    let mut out = Vec::new();

    // TCPv4 LISTEN (st == "0A")
    if let Ok(mut v) = parse_table("/proc/net/tcp", "tcp", Some("0A"), &inode_to_pid) {
        out.append(&mut v);
    }
    // UDPv4 "UNCONN" (st == "07") — sockets en attente (équivalent "listening" pour UDP)
    if let Ok(mut v) = parse_table("/proc/net/udp", "udp", Some("07"), &inode_to_pid) {
        out.append(&mut v);
    }

    // NOTE: on pourra ajouter tcp6/udp6 plus tard (parsing IPv6), ici Linux v4 d’abord (risque parité OS indiqué).
    Ok(out)
}

fn parse_table(
    path: &str,
    proto: &str,
    required_state_hex: Option<&str>,
    inode_to_pid: &HashMap<u64, u32>,
) -> io::Result<Vec<ListeningSocket>> {
    let content = fs::read_to_string(path)?;
    let mut sockets = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue; // skip header
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 12 {
            continue;
        }
        let local = cols[1]; // "HHHHHHHH:PPPP"
        let _remote = cols[2];
        let st = cols[3]; // "0A" LISTEN (tcp) / "07" UNCONN (udp)
        let inode_str = cols[11]; // inode

        if let Some(req) = required_state_hex {
            if st != req {
                continue;
            }
        }

        let (addr, port) = match parse_ipv4_host_port(local) {
            Some(x) => x,
            None => continue,
        };

        // Inode -> PID
        let pid = inode_str
            .parse::<u64>()
            .ok()
            .and_then(|ino| inode_to_pid.get(&ino).copied());

        sockets.push(ListeningSocket {
            proto: proto.to_string(),
            addr,
            port,
            process: pid,
        });
    }

    Ok(sockets)
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

fn build_inode_pid_map() -> io::Result<HashMap<u64, u32>> {
    let mut map = HashMap::new();
    let proc = Path::new("/proc");
    for entry in fs::read_dir(proc)? {
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
