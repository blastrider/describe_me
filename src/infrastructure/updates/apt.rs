use crate::domain::{UpdatePackage, UpdatesInfo};
use crate::SharedSlice;
use std::io;
use std::path::Path;
use tracing::debug;

use super::common::{hardened_command, run_command};

pub(super) fn gather_apt_updates() -> Option<UpdatesInfo> {
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

    let mut cmd = hardened_command("apt-get");
    cmd.args(["-s", "upgrade"])
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive");
    let output = match run_command(cmd, "apt-get -s upgrade") {
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

enum AptListError {
    NotAvailable,
    Failed,
}

fn apt_list_upgradable() -> Result<Vec<UpdatePackage>, AptListError> {
    let mut cmd = hardened_command("apt");
    cmd.args(["list", "--upgradable"]).env("LC_ALL", "C");

    let output = match run_command(cmd, "apt list --upgradable") {
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

pub(super) fn parse_apt_upgradable_line(line: &str) -> Option<UpdatePackage> {
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

fn count_apt_lines(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.starts_with("Inst "))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    proptest! {
        #[test]
        fn parse_apt_line_roundtrip(
            name in proptest::string::string_regex("[A-Za-z0-9._+-]{1,16}").unwrap(),
            repo in proptest::option::of(proptest::string::string_regex("[A-Za-z0-9._+-]{1,16}").unwrap()),
            available in proptest::option::of(proptest::string::string_regex("[A-Za-z0-9.:~+-]{1,24}").unwrap()),
            arch in proptest::option::of(proptest::string::string_regex("[A-Za-z0-9_.-]{1,16}").unwrap()),
            current in proptest::option::of(proptest::string::string_regex("[A-Za-z0-9.:~+-]{1,24}").unwrap()),
            leading_ws in proptest::bool::ANY,
            trailing_ws in proptest::bool::ANY,
        ) {
            let pkg_token = if let Some(repo_val) = &repo {
                format!("{name}/{repo_val}")
            } else {
                name.clone()
            };

            let arch_token = if available.is_some() { arch.clone() } else { None };

            let mut tokens = vec![pkg_token];
            if let Some(av) = &available {
                tokens.push(av.clone());
            }
            if let Some(arch_tok) = &arch_token {
                tokens.push(arch_tok.clone());
            }

            let mut line = tokens.join(" ");
            if let Some(cur) = &current {
                line.push_str(" [upgradable from: ");
                line.push_str(cur);
                line.push(']');
            }
            if leading_ws {
                line = format!("  {line}");
            }
            if trailing_ws {
                line.push_str("   ");
            }

            let parsed = parse_apt_upgradable_line(&line).expect("should parse");
            prop_assert_eq!(parsed.name, name);
            prop_assert_eq!(parsed.available_version, available);

            let expected_repo = match (repo.clone(), arch_token.clone()) {
                (Some(r), Some(a)) if !a.is_empty() => Some(format!("{r} {a}")),
                (Some(r), _) => Some(r),
                (None, Some(a)) if !a.is_empty() => Some(a),
                _ => None,
            };
            prop_assert_eq!(parsed.repository, expected_repo);
            prop_assert_eq!(parsed.current_version, current);
        }
    }
}
