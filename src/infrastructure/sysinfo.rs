use crate::domain::DescribeError;
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

use crate::domain::{DiskPartition, DiskUsage};
use std::{
    collections::{HashMap, HashSet},
    fs,
};
/// Parse /proc/self/mountinfo → map: mount_point -> (maj:min, source)
fn parse_mountinfo() -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    let Ok(txt) = fs::read_to_string("/proc/self/mountinfo") else {
        return map;
    };
    for line in txt.lines() {
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

        let t = d.total_space();
        let a = d.available_space();

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
                    total = total.saturating_add(t);
                    avail = avail.saturating_add(a);
                }
            }
        }

        partitions.push(DiskPartition {
            mount_point: mount,
            fs_type,
            total_bytes: t,
            available_bytes: a,
        });
    }

    let used = total.saturating_sub(avail);

    debug!(
        partitions = partitions.len(),
        counted_devices = counted_devs.len(),
        total_bytes = total,
        available_bytes = avail,
        used_bytes = used,
        "disk_aggregate"
    );

    Ok(DiskUsage {
        total_bytes: total,
        available_bytes: avail,
        used_bytes: used,
        partitions,
    })
}
