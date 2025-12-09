use describe_me::{
    ContainersPluginExitCode, CONTAINERS_CONTRACT_VERSION, CONTAINERS_PLUGIN_TIMEOUT,
};
use describe_me_plugin_sdk::{
    run_plugin, PluginConfig, PluginErrorReport, PluginOutput, PluginResult,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

const MAX_CONTAINERS: usize = 200;
const INSPECT_BATCH: usize = 48;
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const PODMAN_SOCKET: &str = "/run/podman/podman.sock";
const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

#[derive(Debug, Clone)]
struct RuntimeSpec {
    name: &'static str,
    program: &'static str,
    socket: &'static str,
    env: &'static [(&'static str, &'static str)],
}

#[derive(Debug, Clone, Deserialize)]
struct ContainerLine {
    id: String,
    name: String,
    state: String,
    image: String,
    ip: Option<String>,
}

#[derive(Debug)]
struct RuntimeContainers {
    total: usize,
    running: usize,
    containers: Vec<ContainerLine>,
}

#[derive(Debug)]
enum CollectError {
    NoRuntime,
    Permission(String),
    Unavailable(String),
    Unexpected(String),
}

impl From<CollectError> for PluginErrorReport {
    fn from(err: CollectError) -> Self {
        match err {
            CollectError::NoRuntime => PluginErrorReport::new("aucun runtime détecté")
                .with_exit_code(ContainersPluginExitCode::NoRuntime.as_i32()),
            CollectError::Permission(msg) => PluginErrorReport::new(msg)
                .with_exit_code(ContainersPluginExitCode::PermissionDenied.as_i32()),
            CollectError::Unavailable(msg) => PluginErrorReport::new(msg)
                .with_exit_code(ContainersPluginExitCode::RuntimeUnavailable.as_i32()),
            CollectError::Unexpected(msg) => PluginErrorReport::new(msg)
                .with_exit_code(ContainersPluginExitCode::Unexpected.as_i32()),
        }
    }
}

fn main() {
    let config = PluginConfig::new("containers")
        .with_error_prefix("describe-me-plugin-containers")
        .with_default_exit_code(ContainersPluginExitCode::Unexpected.as_i32());
    run_plugin(config, |_ctx| collect());
}

fn collect() -> PluginResult<PluginOutput> {
    ensure_non_root()?;
    collect_all_runtimes().map_err(PluginErrorReport::from)
}

fn collect_all_runtimes() -> Result<PluginOutput, CollectError> {
    let mut total = 0_usize;
    let mut running = 0_usize;
    let mut entries = Vec::new();
    let mut last_failure: Option<CollectError> = None;

    for runtime in runtimes() {
        if !socket_exists(runtime.socket) {
            continue;
        }
        match collect_runtime(&runtime) {
            Ok(rt) => {
                total += rt.total;
                running += rt.running;
                for container in rt.containers {
                    entries.push((runtime.name, container));
                }
            }
            Err(err) => {
                last_failure = Some(err);
            }
        }
    }

    if total == 0 {
        return Err(last_failure.unwrap_or(CollectError::NoRuntime));
    }

    let mut containers_json = Vec::new();
    for (idx, (runtime, c)) in entries.into_iter().enumerate() {
        if idx >= MAX_CONTAINERS {
            break;
        }
        let mut value = json!({
            "name": c.name,
            "runtime": runtime,
            "state": c.state,
            "image": c.image,
        });
        if let Some(ip) = c.ip.as_deref() {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("ip".into(), json!(ip));
            }
        }
        containers_json.push(value);
    }

    Ok(PluginOutput::new()
        .with_version(CONTAINERS_CONTRACT_VERSION)
        .with("summary", json!({"total": total, "running": running}))
        .with("containers", json!(containers_json)))
}

fn collect_runtime(rt: &RuntimeSpec) -> Result<RuntimeContainers, CollectError> {
    let list = list_containers(rt)?;
    if list.is_empty() {
        return Ok(RuntimeContainers {
            total: 0,
            running: 0,
            containers: Vec::new(),
        });
    }

    let inspect_scope = &list[..list.len().min(MAX_CONTAINERS)];
    let ip_map = inspect_ips(rt, inspect_scope)?;
    let mut running = 0;
    let mut containers = Vec::with_capacity(list.len());
    for mut entry in list {
        if entry.state == "running" {
            running += 1;
        }
        entry.ip = ip_map.get(&entry.id).cloned();
        containers.push(entry);
    }

    Ok(RuntimeContainers {
        total: containers.len(),
        running,
        containers,
    })
}

fn list_containers(rt: &RuntimeSpec) -> Result<Vec<ContainerLine>, CollectError> {
    let output = run_command(
        rt.program,
        &[
            "ps",
            "-a",
            "--no-trunc",
            "--format",
            "{{.ID}}|{{.Names}}|{{.State}}|{{.Image}}|{{.Status}}",
        ],
        rt.env,
    )?;

    Ok(parse_ps_output(&output))
}

fn inspect_ips(
    rt: &RuntimeSpec,
    containers: &[ContainerLine],
) -> Result<HashMap<String, String>, CollectError> {
    let mut map = HashMap::new();
    let mut batch = Vec::with_capacity(INSPECT_BATCH + 3);

    for chunk in containers.chunks(INSPECT_BATCH) {
        batch.clear();
        batch.extend(
            [
                "inspect",
                "--format",
                "{{.Id}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            ]
            .iter()
            .copied(),
        );
        for c in chunk {
            batch.push(&c.id);
        }

        let output = run_command(rt.program, &batch, rt.env)?;
        map.extend(parse_inspect_output(&output));
    }
    Ok(map)
}

fn run_command(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<String, CollectError> {
    run_command_with_timeout(program, args, env, CONTAINERS_PLUGIN_TIMEOUT)
}

fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<String, CollectError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in env {
        cmd.env(key, value);
    }

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|e| spawn_error(program, e))?;
    let status = match child
        .wait_timeout(timeout)
        .map_err(|e| CollectError::Unavailable(format!("attente {program}: {e}")))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CollectError::Unavailable(format!(
                "timeout {program} après {:?}",
                timeout
            )));
        }
    };

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout)
            .map_err(|e| CollectError::Unexpected(format!("stdout {program}: {e}")))?;
    }
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr)
            .map_err(|e| CollectError::Unexpected(format!("stderr {program}: {e}")))?;
    }

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        let message = format!(
            "{program} a échoué (code {code}) en {:?}: {}",
            start.elapsed(),
            stderr.trim()
        );
        if is_permission_error(code, &stderr) {
            return Err(CollectError::Permission(message));
        }
        return Err(CollectError::Unavailable(message));
    }

    Ok(stdout)
}

fn runtimes() -> Vec<RuntimeSpec> {
    vec![
        RuntimeSpec {
            name: "docker",
            program: "docker",
            socket: DOCKER_SOCKET,
            env: &[
                ("DOCKER_HOST", "unix:///var/run/docker.sock"),
                ("DOCKER_HIDE_LEGACY_COMMANDS", "1"),
            ],
        },
        RuntimeSpec {
            name: "podman",
            program: "podman",
            socket: PODMAN_SOCKET,
            env: &[("PODMAN_HOST", "unix:///run/podman/podman.sock")],
        },
        RuntimeSpec {
            name: "containerd",
            program: "nerdctl",
            socket: CONTAINERD_SOCKET,
            env: &[
                (
                    "CONTAINERD_ADDRESS",
                    "unix:///run/containerd/containerd.sock",
                ),
                ("CONTAINERD_NAMESPACE", "k8s.io"),
            ],
        },
    ]
}

fn socket_exists(path: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.file_type().is_socket()
}

fn spawn_error(program: &str, err: io::Error) -> CollectError {
    if err.kind() == io::ErrorKind::NotFound {
        CollectError::NoRuntime
    } else {
        CollectError::Unexpected(format!("spawn {program}: {err}"))
    }
}

fn is_permission_error(code: i32, stderr: &str) -> bool {
    code == 13 || stderr.to_ascii_lowercase().contains("permission denied")
}

fn normalize_state(raw_state: &str, status: &str) -> String {
    let raw = raw_state.trim();
    let lower = raw.to_ascii_lowercase();
    for prefix in [
        "running", "up", "exited", "stopped", "created", "paused", "dead",
    ] {
        if lower.starts_with(prefix) {
            return prefix.to_string();
        }
    }
    if let Some(first) = status.split_whitespace().next() {
        let lowered = first.to_ascii_lowercase();
        if !lowered.is_empty() {
            return lowered;
        }
    }
    lower
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn parse_ps_output(output: &str) -> Vec<ContainerLine> {
    let mut lines = Vec::new();
    for raw in output.lines() {
        let mut parts = raw.split('|');
        let (id, name, state, image, status) = match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (Some(id), Some(name), Some(state), Some(image), Some(status)) => {
                (id, name, state, image, status)
            }
            _ => continue,
        };
        let normalized_state = normalize_state(state, status);
        lines.push(ContainerLine {
            id: id.trim().to_string(),
            name: name.trim().trim_start_matches('/').to_string(),
            state: normalized_state,
            image: image.trim().to_string(),
            ip: None,
        });
    }
    lines
}

fn parse_inspect_output(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let mut parts = line.splitn(2, '|');
        let (id, ips_raw) = match (parts.next(), parts.next()) {
            (Some(id), Some(rest)) => (id.trim(), rest.trim()),
            _ => continue,
        };
        if id.is_empty() {
            continue;
        }
        if let Some(ip) = ips_raw.split_whitespace().find(|s| !s.is_empty()) {
            map.entry(id.to_string()).or_insert_with(|| ip.to_string());
        }
    }
    map
}

fn ensure_non_root() -> Result<(), CollectError> {
    #[cfg(target_os = "linux")]
    {
        // Linux-only: procfs Uid detection to avoid running containers probe as root.
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    let mut parts = rest.split_whitespace();
                    if let Some(euid) = parts.next() {
                        if euid == "0" {
                            return Err(CollectError::Permission(
                                "exécution en root interdite".to_string(),
                            ));
                        }
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_state_prefers_known_prefixes() {
        assert_eq!(normalize_state("Running", "Up 3 seconds"), "running");
        assert_eq!(normalize_state("up", ""), "up");
        assert_eq!(normalize_state("Exited (0)", ""), "exited");
        assert_eq!(normalize_state("weird", "Paused (with logs)"), "paused");
        assert_eq!(normalize_state("unknown", "customstate"), "customstate");
    }

    #[test]
    fn parse_ps_output_extracts_fields() {
        let input = "123|/web|Running|nginx:latest|Up 2 minutes\n456|db|Exited (1)|postgres:15|Exited (1) 5s ago\n";
        let parsed = parse_ps_output(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "123");
        assert_eq!(parsed[0].name, "web");
        assert_eq!(parsed[0].state, "running");
        assert_eq!(parsed[0].image, "nginx:latest");
        assert_eq!(parsed[1].name, "db");
        assert_eq!(parsed[1].state, "exited");
    }

    #[test]
    fn parse_inspect_output_maps_first_ip() {
        let input = "abc|10.0.0.2 172.18.0.5 \nxyz| \nabc|10.0.0.3\n";
        let map = parse_inspect_output(input);
        assert_eq!(map.get("abc").map(|s| s.as_str()), Some("10.0.0.2"));
        assert!(!map.contains_key("xyz"));
    }
}
