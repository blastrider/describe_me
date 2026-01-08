use crate::application::services::ServiceBackend;
use crate::application::AppContext;
use crate::domain::{DescribeError, ServiceInfo};
use crate::infrastructure::command;
use crate::security;
use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::warn;

// Linux-only: shells out to /usr/bin/systemctl and inspects /proc to guard root usage.
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const SYSTEMCTL_SAFE_PATH: &str = "/usr/bin:/bin";
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMCTL_MAX_OUTPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdBackend;

impl ServiceBackend for SystemdBackend {
    fn collect_services(&self, ctx: &AppContext) -> Result<Vec<ServiceInfo>, DescribeError> {
        let _ = ctx;
        list_systemd_services()
    }
}

pub(crate) fn list_systemd_services() -> Result<Vec<ServiceInfo>, DescribeError> {
    ensure_systemctl_allowed()?;

    if !Path::new(SYSTEMCTL_PATH).exists() {
        if container_mode_enabled() {
            warn!("systemctl introuvable (mode conteneur actif) : skip des services systemd");
            return Ok(Vec::new());
        }
        return Err(DescribeError::External(format!(
            "systemctl introuvable à l'emplacement attendu ({SYSTEMCTL_PATH})"
        )));
    }

    // systemctl list-units --type=service --state=running --no-legend --plain
    let mut cmd = Command::new(SYSTEMCTL_PATH);
    cmd.args([
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--plain",
    ])
    .env_clear()
    .env("PATH", SYSTEMCTL_SAFE_PATH)
    .env("LC_ALL", "C")
    .env("SYSTEMD_COLORS", "0")
    .stdin(Stdio::null());

    let output = command::run_command_with_timeout(
        cmd,
        SYSTEMCTL_TIMEOUT,
        SYSTEMCTL_MAX_OUTPUT,
        "systemctl list-units",
    )
    .map_err(|e| DescribeError::External(e.to_string()))?;
    if output.stdout_truncated || output.stderr_truncated {
        return Err(DescribeError::External(
            "systemctl output exceeded limit".into(),
        ));
    }
    let output = output.output;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "systemctl exit code: {}",
            output.status
        )));
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|e| DescribeError::Parse(format!("utf8: {e}")))?;

    Ok(stdout
        .lines()
        .filter_map(|line| parse_systemctl_line(line).ok())
        .collect())
}

fn parse_systemctl_line(line: &str) -> Result<ServiceInfo, DescribeError> {
    // "<name> <load> <active> <sub> <description...>"
    let mut parts = line.split_whitespace();
    let name = parts
        .next()
        .ok_or_else(|| DescribeError::Parse("missing name".into()))?
        .to_string();
    let _load = parts
        .next()
        .ok_or_else(|| DescribeError::Parse("missing load".into()))?;
    let active = parts
        .next()
        .ok_or_else(|| DescribeError::Parse("missing active".into()))?;
    let sub = parts
        .next()
        .ok_or_else(|| DescribeError::Parse("missing sub".into()))?;

    let rest = parts.collect::<Vec<_>>().join(" ");
    let summary = if rest.is_empty() { None } else { Some(rest) };

    let state = if active == "active" {
        sub.to_string()
    } else {
        active.to_string()
    };
    Ok(ServiceInfo {
        name,
        state,
        summary,
    })
}

/// Wrapper public pour tests/fuzz (feature-gated).
#[cfg(any(test, feature = "internals"))]
#[doc(hidden)]
pub fn __parse_systemctl_line_for_tests(line: &str) -> Result<ServiceInfo, DescribeError> {
    parse_systemctl_line(line)
}

fn ensure_systemctl_allowed() -> Result<(), DescribeError> {
    if security::running_as_root() && !allow_root_systemctl() {
        return Err(DescribeError::External(
            "refus d'exécuter /usr/bin/systemctl en root (exporter DESCRIBE_ME_ALLOW_ROOT_SYSTEMCTL=1 pour forcer)"
                .into(),
        ));
    }
    Ok(())
}

fn allow_root_systemctl() -> bool {
    match env::var("DESCRIBE_ME_ALLOW_ROOT_SYSTEMCTL") {
        Ok(val) => {
            let normalized = val.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes")
        }
        Err(_) => false,
    }
}

fn container_mode_enabled() -> bool {
    match env::var("DESCRIBE_ME_CONTAINER") {
        Ok(val) => {
            let normalized = val.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes")
        }
        Err(_) => false,
    }
}
