use crate::domain::{UpdatePackage, UpdatesInfo};
use crate::SharedSlice;
use std::path::Path;
use std::time::Duration;
use tracing::debug;

use super::common::{hardened_command, run_command, run_command_with_timeout};

pub(super) fn gather_pacman_updates() -> Option<UpdatesInfo> {
    let mut cmd = hardened_command("pacman");
    cmd.args(["-Qu"]);
    cmd.env("LC_ALL", "C");
    let output = match run_command(cmd, "pacman -Qu") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                debug!(error = %err, "pacman -Qu failed");
            }
            return None;
        }
    };
    match output.status.code() {
        Some(1) => {
            return Some(UpdatesInfo {
                pending: 0,
                reboot_required: false,
                packages: None,
            })
        }
        Some(0) => {}
        _ => {
            debug!(status = ?output.status, "pacman -Qu returned unexpected status");
            return None;
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages_vec = Vec::new();
    for line in stdout.lines() {
        if let Some(pkg) = parse_pacman_update_line(line) {
            packages_vec.push(pkg);
        }
    }
    let pending = packages_vec.len() as u32;
    let packages = if packages_vec.is_empty() {
        None
    } else {
        Some(SharedSlice::from_vec(packages_vec))
    };
    Some(UpdatesInfo {
        pending,
        reboot_required: false,
        packages,
    })
}

pub(super) fn gather_checkupdates() -> Option<UpdatesInfo> {
    let cmd = hardened_command("checkupdates");
    let output = match run_command_with_timeout(cmd, Duration::from_secs(10), "checkupdates") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                debug!(error = %err, "checkupdates failed");
            }
            return None;
        }
    };
    let status = output.status.code();
    if status == Some(2) {
        debug!("checkupdates returned status 2 (error)");
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pending = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    let pending = if status == Some(0) {
        pending.max(1)
    } else {
        pending
    };
    let reboot_required = Path::new("/var/run/reboot-required").exists()
        || Path::new("/run/reboot-required").exists();
    Some(UpdatesInfo {
        pending,
        reboot_required,
        packages: None,
    })
}

pub(super) fn parse_pacman_update_line(line: &str) -> Option<UpdatePackage> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("::") {
        return None;
    }
    let arrow_idx = trimmed.find("->")?;
    let (left, right) = trimmed.split_at(arrow_idx);
    let right = right.trim_start_matches("->").trim();
    if right.is_empty() {
        return None;
    }
    let mut left_parts = left.split_whitespace();
    let name = left_parts.next()?.to_string();
    let current_version = left_parts.next().map(|s| s.to_string());
    let available_version = right.split_whitespace().next().map(|s| s.to_string());
    Some(UpdatePackage {
        name,
        current_version,
        available_version,
        repository: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_line_parses_versions() {
        let sample = "bash 5.1.16.1-1 -> 5.1.16.2-1";
        let pkg = parse_pacman_update_line(sample).expect("parsed pacman line");
        assert_eq!(pkg.name, "bash");
        assert_eq!(pkg.current_version.as_deref(), Some("5.1.16.1-1"));
        assert_eq!(pkg.available_version.as_deref(), Some("5.1.16.2-1"));
    }
}
