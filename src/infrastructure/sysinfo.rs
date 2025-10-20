use crate::domain::DescribeError;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};

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

pub(crate) fn gather_disks() -> Result<DiskUsage, DescribeError> {
    // On utilise une instance dédiée pour rafraîchir la liste des disques.
    let mut disks = Disks::new_with_refreshed_list();
    disks.refresh();

    let mut partitions = Vec::new();
    let mut total = 0u64;
    let mut avail = 0u64;

    for d in disks.list() {
        // mount point
        let mount = d.mount_point().to_string_lossy().into_owned();
        // fs type (OsStr -> Option<String> si UTF-8 valide)
        let fs_type = d.file_system().to_str().map(|s| s.to_string());

        let t = d.total_space();
        let a = d.available_space();

        total = total.saturating_add(t);
        avail = avail.saturating_add(a);

        partitions.push(DiskPartition {
            mount_point: mount,
            fs_type,
            total_bytes: t,
            available_bytes: a,
        });
    }

    let used = total.saturating_sub(avail);

    Ok(DiskUsage {
        total_bytes: total,
        available_bytes: avail,
        used_bytes: used,
        partitions,
    })
}
