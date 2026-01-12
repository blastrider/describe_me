#[cfg(any(target_os = "freebsd", test))]
use crate::domain::UpdatePackage;
#[cfg(target_os = "freebsd")]
use crate::domain::UpdatesInfo;
#[cfg(target_os = "freebsd")]
use crate::SharedSlice;

#[cfg(target_os = "freebsd")]
use std::io;
#[cfg(target_os = "freebsd")]
use tracing::debug;

#[cfg(target_os = "freebsd")]
use super::common::{hardened_command, run_command};

#[cfg(target_os = "freebsd")]
pub(super) fn gather_freebsd_pkg_updates() -> Option<UpdatesInfo> {
    let reboot_required = detect_freebsd_reboot().unwrap_or(false);
    match pkg_version_upgrades() {
        Ok(packages) => {
            let pending = packages.len() as u32;
            let packages = if packages.is_empty() {
                None
            } else {
                Some(SharedSlice::from_vec(packages))
            };
            Some(UpdatesInfo {
                pending,
                reboot_required,
                packages,
            })
        }
        Err(FreebsdPkgError::NotAvailable) => Some(UpdatesInfo {
            pending: 0,
            reboot_required,
            packages: None,
        }),
        Err(FreebsdPkgError::Failed) => None,
    }
}

#[cfg(target_os = "freebsd")]
enum FreebsdPkgError {
    NotAvailable,
    Failed,
}

#[cfg(target_os = "freebsd")]
fn pkg_version_upgrades() -> Result<Vec<UpdatePackage>, FreebsdPkgError> {
    let mut cmd = hardened_command("pkg");
    cmd.args(["version", "-l", "<"]);
    let output = match run_command(cmd, "pkg version -l <") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                return Err(FreebsdPkgError::NotAvailable);
            }
            debug!(error = %err, "pkg version -l '<' failed");
            return Err(FreebsdPkgError::Failed);
        }
    };
    if !output.status.success() {
        debug!(
            status = ?output.status,
            stderr = %String::from_utf8_lossy(&output.stderr),
            "pkg version returned non-zero status"
        );
        return Err(FreebsdPkgError::Failed);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_pkg_version_output(&stdout))
}

#[cfg(target_os = "freebsd")]
fn detect_freebsd_reboot() -> Option<bool> {
    let kernel = read_freebsd_version(&["-k"])?;
    let userland = read_freebsd_version(&["-u"]).or_else(|| read_freebsd_version(&[]))?;
    Some(kernel != userland)
}

#[cfg(target_os = "freebsd")]
fn read_freebsd_version(args: &[&str]) -> Option<String> {
    let mut cmd = hardened_command("freebsd-version");
    cmd.args(args);
    let output = match run_command(cmd, "freebsd-version") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(error = %err, "freebsd-version invocation failed");
            }
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = ?output.status, "freebsd-version returned non-zero status");
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(super) fn parse_pkg_version_output(output: &str) -> Vec<UpdatePackage> {
    output.lines().filter_map(parse_pkg_version_line).collect()
}

pub(super) fn parse_pkg_version_line(line: &str) -> Option<UpdatePackage> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ident = trimmed.split_whitespace().next()?;
    let (name, current_version) = ident.rsplit_once('-')?;

    let available_version = extract_pkg_available_version(trimmed);

    Some(UpdatePackage {
        name: name.to_string(),
        current_version: Some(current_version.to_string()),
        available_version,
        repository: None,
    })
}

pub(super) fn extract_pkg_available_version(line: &str) -> Option<String> {
    let marker = "(index has";
    let idx = line.find(marker)?;
    let rest = line[idx + marker.len()..].trim_start();
    let end = rest.find(')')?;
    let version = rest[..end].trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pkg_version_line_extracts_versions() {
        let line = "openssl-1.1.1_2           <   needs updating (index has 1.1.1_3)";
        let pkg = parse_pkg_version_line(line).expect("parsed");
        assert_eq!(pkg.name, "openssl");
        assert_eq!(pkg.current_version.as_deref(), Some("1.1.1_2"));
        assert_eq!(pkg.available_version.as_deref(), Some("1.1.1_3"));
    }

    #[test]
    fn parse_pkg_version_output_ignores_empty() {
        let sample = "\nfoo-1.0 < needs updating (index has 1.1)\n \n";
        let pkgs = parse_pkg_version_output(sample);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "foo");
    }

    #[test]
    fn parse_pkg_version_line_handles_missing_available() {
        let line = "bar-2.0 < ? unknown source";
        let pkg = parse_pkg_version_line(line).expect("parsed");
        assert_eq!(pkg.name, "bar");
        assert_eq!(pkg.available_version, None);
    }
}
