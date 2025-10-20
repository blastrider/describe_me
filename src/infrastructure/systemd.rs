#[cfg(feature = "systemd")]
use std::process::Command;

use crate::domain::{DescribeError, ServiceInfo};

#[cfg(feature = "systemd")]
pub(crate) fn list_systemd_services() -> Result<Vec<ServiceInfo>, DescribeError> {
    // systemctl list-units --type=service --state=running --no-legend --plain
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ])
        .output()
        .map_err(|e| DescribeError::External(e.to_string()))?;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "systemctl exit code: {}",
            output.status
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| DescribeError::Parse(format!("utf8: {e}")))?;

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

    let state = if active == "active" { sub.to_string() } else { active.to_string() };
    Ok(ServiceInfo { name, state, summary })
}

/// Wrapper public pour tests/fuzz (feature-gated).
#[cfg(all(feature = "systemd", any(test, feature = "internals")))]
#[doc(hidden)]
pub fn __parse_systemctl_line_for_tests(line: &str) -> Result<ServiceInfo, DescribeError> {
    parse_systemctl_line(line)
}
