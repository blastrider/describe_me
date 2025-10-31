use crate::domain::UpdatesInfo;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::debug;

#[cfg(target_os = "linux")]
pub fn gather_updates() -> Option<UpdatesInfo> {
    gather_linux_updates()
}

#[cfg(target_os = "freebsd")]
pub fn gather_updates() -> Option<UpdatesInfo> {
    gather_freebsd_updates()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn gather_updates() -> Option<UpdatesInfo> {
    None
}

#[cfg(target_os = "linux")]
fn gather_linux_updates() -> Option<UpdatesInfo> {
    gather_apt_updates()
        .or_else(gather_dnf_updates)
        .or_else(gather_checkupdates)
        .or_else(gather_apk_updates)
}

#[cfg(target_os = "freebsd")]
fn gather_freebsd_updates() -> Option<UpdatesInfo> {
    gather_freebsd_pkg_updates()
}

#[cfg(target_os = "linux")]
fn gather_apt_updates() -> Option<UpdatesInfo> {
    let mut cmd = Command::new("apt-get");
    cmd.args(["-s", "upgrade"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "apt-get simulation failed");
            }
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = ?output.status, "apt-get simulation returned non-zero status");
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pending = count_apt_lines(&stdout) as u32;
    let reboot_required = Path::new("/var/run/reboot-required").exists()
        || Path::new("/run/reboot-required").exists();
    Some(UpdatesInfo {
        pending,
        reboot_required,
    })
}

#[cfg(target_os = "linux")]
fn gather_dnf_updates() -> Option<UpdatesInfo> {
    let mut cmd = Command::new("dnf");
    cmd.args(["-q", "check-update"]).stdin(Stdio::null());
    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "dnf check-update failed");
            }
            return None;
        }
    };
    let status = output.status.code();
    match status {
        Some(0) | Some(100) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut pending = count_dnf_updates(&stdout);
            if pending == 0 && status == Some(100) {
                pending = 1; // dnf indicates updates but parsing failed, assume 1
            }
            let reboot_required = detect_needs_restarting().unwrap_or(false)
                || Path::new("/var/run/reboot-required").exists()
                || Path::new("/run/reboot-required").exists();
            Some(UpdatesInfo {
                pending: pending as u32,
                reboot_required,
            })
        }
        Some(1) => {
            debug!(status = ?output.status, "dnf check-update reported an error (exit 1)");
            None
        }
        _ => {
            debug!(status = ?output.status, "dnf check-update returned unexpected status");
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn gather_checkupdates() -> Option<UpdatesInfo> {
    let mut cmd = Command::new("checkupdates");
    cmd.stdin(Stdio::null());
    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
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
    })
}

#[cfg(target_os = "linux")]
fn gather_apk_updates() -> Option<UpdatesInfo> {
    let mut cmd = Command::new("apk");
    cmd.args(["version", "-l", "<"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "apk version -l '<' failed");
            }
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = ?output.status, "apk version returned non-zero status");
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pending = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    if pending == 0 {
        return Some(UpdatesInfo {
            pending: 0,
            reboot_required: Path::new("/run/reboot-required").exists(),
        });
    }
    Some(UpdatesInfo {
        pending,
        reboot_required: Path::new("/run/reboot-required").exists(),
    })
}

#[cfg(target_os = "freebsd")]
fn gather_freebsd_pkg_updates() -> Option<UpdatesInfo> {
    let mut cmd = Command::new("pkg");
    cmd.args(["version", "-l", "<"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "pkg version -l '<' failed");
            }
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = ?output.status, "pkg version returned non-zero status");
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pending = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    Some(UpdatesInfo {
        pending,
        reboot_required: false,
    })
}

fn count_apt_lines(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.starts_with("Inst "))
        .count()
}

#[cfg(target_os = "linux")]
fn count_dnf_updates(output: &str) -> usize {
    let mut count = 0;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Last metadata expiration check")
            || trimmed.starts_with("Obsoleting Packages")
            || trimmed.starts_with("Updated Packages")
            || trimmed.starts_with("Available Packages")
            || trimmed.starts_with("Name ")
            || trimmed.starts_with("Package ")
            || trimmed.starts_with("Security:")
        {
            continue;
        }
        if trimmed
            .chars()
            .next()
            .map(|c| !c.is_whitespace())
            .unwrap_or(false)
        {
            count += 1;
        }
    }
    count
}

#[cfg(target_os = "linux")]
fn detect_needs_restarting() -> Option<bool> {
    let mut cmd = Command::new("needs-restarting");
    cmd.arg("-r").stdin(Stdio::null());
    match cmd.status() {
        Ok(status) => match status.code() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => {
                debug!(status = ?status, "needs-restarting returned unexpected status");
                None
            }
        },
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "needs-restarting invocation failed");
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_counts_inst_lines() {
        let sample = "\
Inst bash [5.1-2] (5.1-3 Debian:11/main)
Inst libc6 [2.31-0ubuntu9.9] (2.31-0ubuntu9.10 Ubuntu:20.04/focal-updates)
Conf linux-image-5.15.0-41-generic (5.15.0-41.44 500)
Inst openssl [1.1.1f-1ubuntu2.16] (1.1.1f-1ubuntu2.17 Ubuntu:20.04/focal-updates)";
        assert_eq!(count_apt_lines(sample), 3);
    }

    #[test]
    fn apt_ignores_non_inst_lines() {
        let sample = "\
Reading package lists... Done
Building dependency tree       
Reading state information... Done
Calculating upgrade... Done";
        assert_eq!(count_apt_lines(sample), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dnf_counts_package_lines() {
        let sample = "\
Last metadata expiration check: 0:10:00 ago on Tue 12 Sep 2023 10:00:00 AM UTC.
kernel.x86_64                 5.14.0-370.el9_1      @baseos
openssl.x86_64                1:3.0.7-16.el9_1      @appstream
Obsoleting Packages
foo.noarch                    1-2.el9               @appstream";
        assert_eq!(count_dnf_updates(sample), 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dnf_skips_section_headers() {
        let sample = "\
Security:
    kernel.x86_64 5.14.0-370.el9_1";
        assert_eq!(count_dnf_updates(sample), 1);
    }
}
