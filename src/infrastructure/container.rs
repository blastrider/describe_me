use crate::domain::{ContainerInfo, ExecutionScope, VolumeMount};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use tracing::debug;

const SCOPE_ENV: &str = "DESCRIBE_ME_SCOPE";
const LEGACY_CONTAINER_ENV: &str = "DESCRIBE_ME_CONTAINER";

pub(crate) fn detect_execution_scope() -> ExecutionScope {
    if let Some(forced) = forced_scope_from_env() {
        debug!(scope = forced.as_str(), "execution_scope_forced");
        return forced;
    }

    #[cfg(not(target_os = "linux"))]
    {
        return ExecutionScope::Host;
    }

    #[cfg(target_os = "linux")]
    {
        let has_dockerenv = Path::new("/.dockerenv").exists();
        let env_container = env_container_flag();
        let kube_hint = kube_hint();
        let cgroup_hits = cgroup_mentions_container();
        let mount_hits = mountinfo_mentions_container();
        let pid1_suspect = pid1_suggests_container();

        let in_container = has_dockerenv
            || env_container
            || kube_hint
            || cgroup_hits
            || mount_hits
            || pid1_suspect;

        if !in_container {
            return ExecutionScope::Host;
        }

        if host_visibility_signals() {
            ExecutionScope::HostFromContainer
        } else {
            ExecutionScope::ContainerSelf
        }
    }
}

pub(crate) fn detect_container_info(scope: ExecutionScope) -> Option<ContainerInfo> {
    if matches!(scope, ExecutionScope::Host) {
        return None;
    }

    #[cfg(not(target_os = "linux"))]
    {
        return Some(ContainerInfo {
            runtime: "unknown".into(),
            container_id: None,
            image: None,
            container_name: hostname_fallback(),
            orchestrator: None,
            k8s_namespace: None,
            k8s_pod: None,
            isolated_namespaces: Vec::new(),
            mounted_volumes: Vec::new(),
            capabilities: Vec::new(),
        });
    }

    #[cfg(target_os = "linux")]
    {
        let cgroup_content = fs::read_to_string("/proc/1/cgroup")
            .unwrap_or_else(|_| fs::read_to_string("/proc/self/cgroup").unwrap_or_default());
        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let hostname = hostname_fallback();
        let env_container = std::env::var("container").ok();
        let kube_env = kube_hint();

        let mut runtime = runtime_from_env(env_container.as_deref());
        let mut orchestrator = if kube_env {
            Some("Kubernetes".to_string())
        } else {
            None
        };

        if runtime.is_none() && cgroup_content.contains("libpod") {
            runtime = Some("podman".into());
        }
        if runtime.is_none()
            && (cgroup_content.contains("/docker/")
                || mountinfo.contains("/docker/containers/")
                || cgroup_content.contains("docker-")
                || cgroup_content.contains("docker.slice"))
        {
            runtime = Some("docker".into());
        }
        if runtime.is_none() && cgroup_content.contains("/kubepods/") {
            runtime = Some("containerd".into());
            orchestrator = Some("Kubernetes".into());
        }
        if runtime.is_none() && cgroup_content.contains("/crio/") {
            runtime = Some("cri-o".into());
        }
        if runtime.is_none() && mountinfo.contains("/libpod-") {
            runtime = Some("podman".into());
        }
        if runtime.is_none() && mountinfo.contains("/lxc/") {
            runtime = Some("lxc".into());
        }

        let container_id =
            detect_container_id(&cgroup_content, &mountinfo).or_else(|| hostname.clone());

        let (k8s_namespace, k8s_pod) = if orchestrator.is_some() {
            let pod = hostname.clone();
            let ns = std::env::var("POD_NAMESPACE")
                .ok()
                .or_else(|| std::env::var("K8S_NAMESPACE").ok());
            (ns, pod)
        } else {
            (None, None)
        };

        let container_name = hostname.clone();
        let image = image_from_env();
        let isolated_namespaces = detect_namespaces();
        let mounted_volumes = list_container_volumes();
        let capabilities = list_capabilities();

        Some(ContainerInfo {
            runtime: runtime.unwrap_or_else(|| "unknown".into()),
            container_id,
            image,
            container_name,
            orchestrator,
            k8s_namespace,
            k8s_pod,
            isolated_namespaces,
            mounted_volumes,
            capabilities,
        })
    }
}

fn forced_scope_from_env() -> Option<ExecutionScope> {
    if let Ok(val) = std::env::var(SCOPE_ENV) {
        if let Ok(scope) = ExecutionScope::from_str(&val) {
            return Some(scope);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn env_container_flag() -> bool {
    if let Ok(val) = std::env::var("container") {
        let normalized = val.to_ascii_lowercase();
        if !normalized.is_empty() {
            return true;
        }
    }
    if let Ok(val) = std::env::var(LEGACY_CONTAINER_ENV) {
        let normalized = val.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes") {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn kube_hint() -> bool {
    std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
        || Path::new("/var/run/secrets/kubernetes.io/serviceaccount").exists()
}

#[cfg(target_os = "linux")]
fn cgroup_mentions_container() -> bool {
    let paths = ["/proc/1/cgroup", "/proc/self/cgroup"];
    for path in paths {
        if let Ok(content) = fs::read_to_string(path) {
            if content.contains("/docker/")
                || content.contains("/kubepods/")
                || content.contains("libpod-")
                || content.contains("/containerd/")
                || content.contains("/lxc/")
                || content.contains(".scope")
            {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn mountinfo_mentions_container() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/self/mountinfo") {
        for line in content.lines() {
            if line.contains("/docker/containers/")
                || line.contains("/kubepods/")
                || line.contains("containers/docker")
            {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn pid1_suggests_container() -> bool {
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let name = comm.trim().to_ascii_lowercase();
        if !(name == "systemd" || name == "init") {
            return true;
        }
    }
    if let Ok(sched) = fs::read_to_string("/proc/1/sched") {
        if let Some(first) = sched.lines().next() {
            let name = first
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !(name == "systemd" || name == "init") {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn host_visibility_signals() -> bool {
    let many_processes = process_count_above(128);
    let hosty_network = hostlike_interfaces();
    many_processes || hosty_network
}

#[cfg(target_os = "linux")]
fn process_count_above(threshold: usize) -> bool {
    if let Ok(entries) = fs::read_dir("/proc") {
        let mut count = 0usize;
        for entry in entries.flatten() {
            if count > threshold {
                return true;
            }
            if let Some(name) = entry.file_name().to_str() {
                if name.chars().all(|c| c.is_ascii_digit()) {
                    count += 1;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn hostlike_interfaces() -> bool {
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return false;
    };
    let mut interfaces = 0usize;
    let mut hostish_seen = false;
    for line in content.lines().skip(2) {
        if let Some(name) = line.split(':').next() {
            let iface = name.trim();
            if iface.is_empty() {
                continue;
            }
            interfaces += 1;
            if iface.starts_with("docker")
                || iface.starts_with("br-")
                || iface.starts_with("veth")
                || iface.starts_with("cali")
                || iface.starts_with("en")
                || iface.starts_with("wl")
                || iface.starts_with("wlan")
                || iface.starts_with("cbr")
            {
                hostish_seen = true;
            }
        }
    }

    interfaces > 3 || hostish_seen
}

fn runtime_from_env(val: Option<&str>) -> Option<String> {
    let normalized = val.unwrap_or_default().to_ascii_lowercase();
    match normalized.as_str() {
        "podman" | "libpod" => Some("podman".into()),
        "docker" => Some("docker".into()),
        "lxc" => Some("lxc".into()),
        "systemd-nspawn" => Some("systemd-nspawn".into()),
        "" => None,
        other => Some(other.to_string()),
    }
}

fn hostname_fallback() -> Option<String> {
    fs::read_to_string("/etc/hostname").ok().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn detect_container_id(cgroup: &str, mountinfo: &str) -> Option<String> {
    let mut best: Option<String> = None;

    for line in cgroup.lines() {
        if let Some(candidate) = extract_id_candidate(line) {
            best = choose_best(best, candidate);
        }
    }

    if let Some(idx) = mountinfo.find("/docker/containers/") {
        let slice = &mountinfo[idx + "/docker/containers/".len()..];
        if let Some(id) = slice.split('/').next() {
            if let Some(candidate) = extract_id_candidate(id) {
                best = choose_best(best, candidate);
            }
        }
    }

    for line in mountinfo.lines() {
        if let Some(candidate) = extract_id_candidate(line) {
            best = choose_best(best, candidate);
        }
    }

    best
}

fn extract_id_candidate(input: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for token in input.split(|c: char| !c.is_ascii_alphanumeric()) {
        let len = token.len();
        if len >= 12 && token.chars().all(|c| c.is_ascii_alphanumeric()) {
            best = choose_best(best, token.to_string());
        }
    }
    best
}

fn choose_best(current: Option<String>, candidate: String) -> Option<String> {
    match current {
        Some(cur) => {
            if candidate.len() > cur.len() {
                Some(candidate)
            } else {
                Some(cur)
            }
        }
        None => Some(candidate),
    }
}

fn image_from_env() -> Option<String> {
    const KEYS: [&str; 4] = [
        "CONTAINER_IMAGE",
        "IMAGE",
        "DOCKER_IMAGE",
        "K8S_CONTAINER_IMAGE",
    ];
    for key in KEYS {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_namespaces() -> Vec<String> {
    const NAMES: [&str; 6] = ["pid", "net", "ipc", "mnt", "uts", "user"];
    let mut isolated = Vec::new();
    for name in NAMES {
        let self_ns = read_ns_inode("/proc/self/ns", name);
        let init_ns = read_ns_inode("/proc/1/ns", name);
        if let (Some(a), Some(b)) = (self_ns, init_ns) {
            if a != b {
                isolated.push(name.to_string());
            }
        }
    }
    isolated
}

#[cfg(not(target_os = "linux"))]
fn detect_namespaces() -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn read_ns_inode(base: &str, name: &str) -> Option<u64> {
    let path = format!("{}/{}", base, name);
    let link = std::fs::read_link(path).ok()?;
    let txt = link.to_string_lossy();
    let start = txt.find('[')? + 1;
    let end = txt.find(']')?;
    txt[start..end].parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn list_container_volumes() -> Vec<VolumeMount> {
    let Ok(content) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    let mut vols = Vec::new();
    for line in content.lines() {
        if let Some((target, fstype, source)) = parse_mountinfo_line(line) {
            if is_pseudo_fs(fstype.as_deref()) {
                continue;
            }
            vols.push(VolumeMount {
                source: source.unwrap_or_else(|| "-".to_string()),
                target,
            });
        }
    }
    vols
}

#[cfg(not(target_os = "linux"))]
fn list_container_volumes() -> Vec<VolumeMount> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_mountinfo_line(line: &str) -> Option<(String, Option<String>, Option<String>)> {
    // ID parent maj:min root mount_point opts - fstype source superopts
    let (left, right) = line.split_once(" - ")?;
    let mut l = left.split_whitespace();
    let _id = l.next()?;
    let _parent = l.next()?;
    let _majmin = l.next()?;
    let _root = l.next()?;
    let mount_point = l.next()?.to_string();

    let mut r = right.split_whitespace();
    let fstype = r.next().map(|s| s.to_string());
    let source = r.next().map(|s| s.to_string());
    Some((mount_point, fstype, source))
}

#[cfg(target_os = "linux")]
fn is_pseudo_fs(fs: Option<&str>) -> bool {
    matches!(
        fs,
        Some(
            "proc"
                | "sysfs"
                | "tmpfs"
                | "devtmpfs"
                | "devpts"
                | "cgroup"
                | "cgroup2"
                | "overlay"
                | "mqueue"
                | "pstore"
                | "autofs"
                | "securityfs"
        )
    )
}

#[cfg(target_os = "linux")]
fn list_capabilities() -> Vec<String> {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return Vec::new();
    };
    let mut capeff_hex = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            capeff_hex = rest.split_whitespace().next().map(|s| s.to_string());
            break;
        }
    }
    let Some(hex_str) = capeff_hex else {
        return Vec::new();
    };
    let Ok(mask) = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16) else {
        return Vec::new();
    };

    const CAPS: [&str; 41] = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ];

    let mut res = Vec::new();
    for (i, name) in CAPS.iter().enumerate() {
        if mask & (1u64 << i) != 0 {
            res.push(name.to_string());
        }
    }
    res
}

#[cfg(not(target_os = "linux"))]
fn list_capabilities() -> Vec<String> {
    Vec::new()
}
