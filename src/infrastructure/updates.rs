use crate::domain::{UpdatePackage, UpdatesInfo};
use crate::SharedSlice;
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
    let reboot_required = Path::new("/var/run/reboot-required").exists()
        || Path::new("/run/reboot-required").exists();

    match apt_list_upgradable() {
        Ok(packages) => {
            let pending = packages.len() as u32;
            let packages = if packages.is_empty() {
                None
            } else {
                Some(SharedSlice::from_vec(packages))
            };
            return Some(UpdatesInfo {
                pending,
                reboot_required,
                packages,
            });
        }
        Err(AptListError::NotAvailable) => {
            // fallback to apt-get simulation below
        }
        Err(AptListError::Failed) => {
            // Command exists but failed — fallback to apt-get simulation.
        }
    }

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
    Some(UpdatesInfo {
        pending,
        reboot_required,
        packages: None,
    })
}

#[cfg(target_os = "linux")]
enum AptListError {
    NotAvailable,
    Failed,
}

#[cfg(target_os = "linux")]
fn apt_list_upgradable() -> Result<Vec<UpdatePackage>, AptListError> {
    let mut cmd = Command::new("apt");
    cmd.args(["list", "--upgradable"])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                return Err(AptListError::NotAvailable);
            }
            debug!(error = %err, "apt list --upgradable invocation failed");
            return Err(AptListError::Failed);
        }
    };

    if !output.status.success() {
        debug!(status = ?output.status, stderr = %String::from_utf8_lossy(&output.stderr), "apt list --upgradable returned non-zero status");
        return Err(AptListError::Failed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Listing...")
            || trimmed.starts_with("WARNING:")
        {
            continue;
        }
        if let Some(pkg) = parse_apt_upgradable_line(trimmed) {
            packages.push(pkg);
        }
    }

    Ok(packages)
}

#[cfg(target_os = "linux")]
fn parse_apt_upgradable_line(line: &str) -> Option<UpdatePackage> {
    let (main, bracket) = if let Some(idx) = line.find('[') {
        (line[..idx].trim(), Some(&line[idx + 1..]))
    } else {
        (line.trim(), None)
    };

    let mut tokens = main.split_whitespace();
    let pkg_token = tokens.next()?;
    let available_version = tokens.next().map(|s| s.to_string());
    let arch_token = tokens.next();

    let (name, mut repository): (String, Option<String>) = match pkg_token.split_once('/') {
        Some((n, repo)) => (n.to_string(), Some(repo.to_string())),
        None => (pkg_token.to_string(), None),
    };

    if let Some(arch) = arch_token {
        if let Some(repo) = &mut repository {
            if !arch.is_empty() {
                repo.push(' ');
                repo.push_str(arch);
            }
        } else if !arch.is_empty() {
            repository = Some(arch.to_string());
        }
    }

    let current_version = bracket
        .and_then(|raw| raw.trim().strip_suffix(']'))
        .and_then(|inner| inner.strip_prefix("upgradable from:"))
        .map(|v| v.trim().to_string());

    Some(UpdatePackage {
        name,
        current_version,
        available_version,
        repository,
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
                packages: None,
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
        packages: None,
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
            packages: None,
        });
    }
    Some(UpdatesInfo {
        pending,
        reboot_required: Path::new("/run/reboot-required").exists(),
        packages: None,
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
        packages: None,
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
    fn parse_apt_line_extracts_details() {
        let line =
            "openssl/focal-updates 1.1.1f-1ubuntu2.19 amd64 [upgradable from: 1.1.1f-1ubuntu2.18]";
        let parsed = parse_apt_upgradable_line(line).expect("parsed");
        assert_eq!(parsed.name, "openssl");
        assert_eq!(
            parsed.available_version.as_deref(),
            Some("1.1.1f-1ubuntu2.19")
        );
        assert_eq!(
            parsed.current_version.as_deref(),
            Some("1.1.1f-1ubuntu2.18")
        );
        assert_eq!(parsed.repository.as_deref(), Some("focal-updates amd64"));
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
