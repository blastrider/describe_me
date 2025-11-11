use crate::domain::{DescribeError, DiskPartition, DiskUsage};
use crate::SharedSlice;
use std::os::unix::fs::MetadataExt;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};
use tracing::debug;

pub(crate) struct SysinfoSnapshot {
    pub hostname: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub uptime_seconds: u64,
    pub cpu_count: usize,
    pub load_average: (f64, f64, f64),
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
}

pub(crate) fn gather() -> Result<SysinfoSnapshot, DescribeError> {
    let mut sys = System::new();
    sys.refresh_specifics(
        RefreshKind::new()
            .with_memory(MemoryRefreshKind::new().with_ram().with_swap())
            .with_cpu(CpuRefreshKind::everything()),
    );

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os = System::long_os_version();
    let kernel = System::kernel_version();
    let uptime_seconds = System::uptime();

    let cpu_count = sys.cpus().len();
    let la = System::load_average();

    let total_memory_bytes = sys.total_memory();
    let used_memory_bytes = sys.used_memory();
    let total_swap_bytes = sys.total_swap();
    let used_swap_bytes = sys.used_swap();

    Ok(SysinfoSnapshot {
        hostname,
        os,
        kernel,
        uptime_seconds,
        cpu_count,
        load_average: (la.one, la.five, la.fifteen),
        total_memory_bytes,
        used_memory_bytes,
        total_swap_bytes,
        used_swap_bytes,
    })
}

// -------- Disks --------

use std::{
    collections::{HashMap, HashSet},
    fs,
    process::Command,
};
/// Parse /proc/self/mountinfo → map: mount_point -> (maj:min, source)
fn parse_mountinfo() -> HashMap<String, (String, String)> {
    let Ok(txt) = fs::read_to_string("/proc/self/mountinfo") else {
        return HashMap::new();
    };
    parse_mountinfo_from_str(&txt)
}

fn parse_mountinfo_from_str(content: &str) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    for line in content.lines() {
        // format: ID parent maj:min root mount_point opts - fstype source superopts
        // on split sur " - " pour séparer les 1ères et 2nd parties
        if let Some((left, right)) = line.split_once(" - ") {
            let mut l = left.split_whitespace();
            let _id = l.next();
            let _parent = l.next();
            let majmin = l.next().unwrap_or_default().to_string();
            // root
            let _root = l.next();
            let mnt = l.next().unwrap_or_default().to_string();
            // right: fstype source superopts
            let mut r = right.split_whitespace();
            let _fstype = r.next();
            let source = r.next().unwrap_or_default().to_string();
            map.insert(mnt, (majmin, source));
        }
    }
    map
}

#[cfg(any(test, feature = "internals"))]
pub fn parse_mountinfo_for_tests(content: &str) -> HashMap<String, (String, String)> {
    parse_mountinfo_from_str(content)
}

fn is_pseudo_fs(fs: Option<&str>) -> bool {
    matches!(
        fs,
        Some(
            "tmpfs"
                | "ramfs"
                | "devtmpfs"
                | "proc"
                | "sysfs"
                | "cgroup2"
                | "cgroup"
                | "overlay"
                | "squashfs"
        )
    )
}

struct BtrfsUsage {
    data_total: u64,
    data_used: u64,
    unallocated: u64,
}

fn read_btrfs_usage(mount_point: &str) -> Option<BtrfsUsage> {
    let output = Command::new("btrfs")
        .args(["filesystem", "df", "-b", mount_point])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut data_total = 0u64;
    let mut data_used = 0u64;
    let mut unallocated = 0u64;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Unallocated:") {
            if let Some(value) = parse_btrfs_unallocated_line(trimmed) {
                unallocated = value;
            }
            continue;
        }
        if trimmed.starts_with("Data") {
            if let Some((line_total, line_used)) = parse_btrfs_data_line(trimmed) {
                data_total = data_total.saturating_add(line_total);
                data_used = data_used.saturating_add(line_used);
            }
        }
    }
    if data_total == 0 {
        None
    } else {
        Some(BtrfsUsage {
            data_total,
            data_used: data_used.min(data_total),
            unallocated,
        })
    }
}

fn parse_btrfs_data_line(line: &str) -> Option<(u64, u64)> {
    let mut total = None;
    let mut used = None;
    for token in line.split_whitespace() {
        let clean = token.trim().trim_end_matches(',');
        if total.is_none() {
            if let Some(value) = clean.strip_prefix("total=") {
                total = value.parse::<u64>().ok();
                continue;
            }
        }
        if used.is_none() {
            if let Some(value) = clean.strip_prefix("used=") {
                used = value.parse::<u64>().ok();
            }
        }
    }
    match (total, used) {
        (Some(t), Some(u)) => Some((t, u)),
        _ => None,
    }
}

fn parse_btrfs_unallocated_line(line: &str) -> Option<u64> {
    let value = line.split(':').nth(1)?.split_whitespace().next()?;
    value.parse::<u64>().ok()
}

pub(crate) fn usage_percent_from_bytes(total_bytes: u64, available_bytes: u64) -> f64 {
    if total_bytes == 0 {
        return 0.0;
    }
    let total = total_bytes as f64;
    let available = available_bytes.min(total_bytes) as f64;
    let ratio = 1.0 - (available / total);
    (ratio * 100.0).clamp(0.0, 100.0)
}
pub(crate) fn gather_disks() -> Result<DiskUsage, DescribeError> {
    let mut disks = Disks::new_with_refreshed_list();
    disks.refresh();

    let mountinfo = parse_mountinfo();

    let mut partitions = Vec::new();
    let mut total = 0u64;
    let mut avail = 0u64;

    #[derive(Hash, PartialEq, Eq)]
    enum AggregateKey {
        Device(u64),
        Source(String),
    }

    // Déduplication stricte par point de stockage physique.
    let mut counted_devs: HashSet<AggregateKey> = HashSet::new();

    for d in disks.list() {
        let mount = d.mount_point().to_string_lossy().into_owned();
        let fs_type = d.file_system().to_str().map(|s| s.to_string());

        let mut total_space = d.total_space();
        let mut available_space = d.available_space();

        if let Some("btrfs") = fs_type.as_deref() {
            if let Some(stats) = read_btrfs_usage(&mount) {
                let logical_total = stats
                    .data_total
                    .saturating_add(stats.unallocated)
                    .max(total_space);
                let used = stats.data_used.min(logical_total);
                total_space = logical_total;
                available_space = logical_total.saturating_sub(used);
            }
        }

        // Agrégat: ignorer pseudo-FS ET ne compter qu’UNE fois par device
        if !is_pseudo_fs(fs_type.as_deref()) {
            let metadata = fs::metadata(&mount).ok();
            let mount_entry = mountinfo.get(&mount);

            let key = match fs_type.as_deref() {
                // Btrfs peut exposer plusieurs sous-volumes (/, /home, …) partageant
                // le même espace physique. On déduplique via la source remontée
                // dans /proc/self/mountinfo (UUID=…, /dev/…).
                Some("btrfs") => {
                    if let Some((majmin, source)) = mount_entry {
                        if !source.is_empty() && source != "none" {
                            Some(AggregateKey::Source(format!("btrfs:src:{source}")))
                        } else {
                            Some(AggregateKey::Source(format!("btrfs:majmin:{majmin}")))
                        }
                    } else {
                        metadata.as_ref().map(|md| AggregateKey::Device(md.dev()))
                    }
                }
                _ => metadata.as_ref().map(|md| AggregateKey::Device(md.dev())),
            };

            if let Some(key) = key {
                if counted_devs.insert(key) {
                    total = total.saturating_add(total_space);
                    avail = avail.saturating_add(available_space);
                }
            }
        }

        partitions.push(DiskPartition {
            mount_point: mount,
            fs_type,
            total_bytes: total_space,
            available_bytes: available_space,
        });
    }

    let used = total.saturating_sub(avail);
    let used_pct = usage_percent_from_bytes(total, avail);

    debug!(
        partitions = partitions.len(),
        counted_devices = counted_devs.len(),
        total_bytes = total,
        available_bytes = avail,
        used_bytes = used,
        used_percent = used_pct,
        "disk_aggregate"
    );

    Ok(DiskUsage {
        total_bytes: total,
        available_bytes: avail,
        used_bytes: used,
        partitions: SharedSlice::from_vec(partitions),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_mountinfo_reconstructs_entries(
            entries in prop::collection::vec(
                (
                    1u32..10_000,
                    1u32..10_000,
                    proptest::string::string_regex("[A-Za-z0-9._-]{1,12}").unwrap(),
                    proptest::string::string_regex("[A-Za-z0-9./_-]{1,12}").unwrap()
                ),
                0..12
            )
        ) {
            let mut content = String::new();
            let mut expected = HashMap::new();

            for (idx, (id, parent, mount_part, source_part)) in entries.iter().enumerate() {
                let maj = id % 255;
                let min = parent % 255;
                let mount_path = format!("/{mount_part}");
                let source = format!("/dev/{source_part}");
                if idx > 0 {
                    content.push('\n');
                }
                content.push_str(&format!(
                    "{id} {parent} {maj}:{min} / {mount_path} rw - ext4 {source} rw"
                ));
                expected.insert(
                    mount_path.clone(),
                    (format!("{maj}:{min}"), source.clone()),
                );
            }

            let parsed = parse_mountinfo_for_tests(&content);
            for (mount, data) in expected {
                prop_assert_eq!(parsed.get(&mount), Some(&data));
            }
        }

        #[test]
        fn parse_mountinfo_tolerates_garbage(data: Vec<u8>) {
            let text = String::from_utf8_lossy(&data);
            let _ = parse_mountinfo_for_tests(&text);
        }
    }

    #[test]
    fn usage_percent_handles_regular_case() {
        let pct = usage_percent_from_bytes(1_000, 250);
        assert!((pct - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn usage_percent_handles_zero_total() {
        assert_eq!(usage_percent_from_bytes(0, 0), 0.0);
    }

    #[test]
    fn parse_btrfs_data_line_extracts_values() {
        let line = "Data, single: total=1073741824, used=536870912";
        let parsed = parse_btrfs_data_line(line).expect("parsed");
        assert_eq!(parsed.0, 1_073_741_824);
        assert_eq!(parsed.1, 536_870_912);
    }

    #[test]
    fn parse_btrfs_unallocated_line_extracts_value() {
        let line = "Unallocated:             330677329920";
        let value = parse_btrfs_unallocated_line(line).expect("value");
        assert_eq!(value, 330_677_329_920);
    }
}
