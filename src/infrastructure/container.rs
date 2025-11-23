use crate::domain::ExecutionScope;
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
