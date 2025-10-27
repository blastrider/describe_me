#[cfg(feature = "systemd")]
use std::env;
#[cfg(feature = "systemd")]
use std::path::Path;
#[cfg(feature = "systemd")]
use std::process::{Command, Stdio};

use crate::domain::{DescribeError, ServiceInfo};

#[cfg(feature = "systemd")]
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
#[cfg(feature = "systemd")]
const SYSTEMCTL_SAFE_PATH: &str = "/usr/bin:/bin";

#[cfg(feature = "systemd")]
pub(crate) fn list_systemd_services() -> Result<Vec<ServiceInfo>, DescribeError> {
    ensure_systemctl_allowed()?;

    if !Path::new(SYSTEMCTL_PATH).exists() {
        return Err(DescribeError::External(format!(
            "systemctl introuvable à l'emplacement attendu ({SYSTEMCTL_PATH})"
        )));
    }

    // systemctl list-units --type=service --state=running --no-legend --plain
    let output = Command::new(SYSTEMCTL_PATH)
        .args([
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
        .stdin(Stdio::null())
        .output()
        .map_err(|e| DescribeError::External(e.to_string()))?;

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

#[cfg(feature = "systemd")]
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
#[cfg(all(feature = "systemd", any(test, feature = "internals")))]
#[doc(hidden)]
pub fn __parse_systemctl_line_for_tests(line: &str) -> Result<ServiceInfo, DescribeError> {
    parse_systemctl_line(line)
}

#[cfg(feature = "systemd")]
fn ensure_systemctl_allowed() -> Result<(), DescribeError> {
    if running_as_root() && !allow_root_systemctl() {
        return Err(DescribeError::External(
            "refus d'exécuter /usr/bin/systemctl en root (exporter DESCRIBE_ME_ALLOW_ROOT_SYSTEMCTL=1 pour forcer)"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "systemd")]
fn allow_root_systemctl() -> bool {
    match env::var("DESCRIBE_ME_ALLOW_ROOT_SYSTEMCTL") {
        Ok(val) => {
            let normalized = val.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes")
        }
        Err(_) => false,
    }
}

#[cfg(feature = "systemd")]
fn running_as_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(uid_str) = rest.split_whitespace().next() {
                        if let Ok(uid) = uid_str.parse::<u32>() {
                            return uid == 0;
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
