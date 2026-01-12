use crate::domain::{UpdatePackage, UpdatesInfo};
use crate::SharedSlice;
use std::io;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, trace};

use super::common::{
    hardened_command, prepare_temp_xdg, preview_str, run_command, run_command_with_timeout,
};

pub(super) fn gather_dnf_updates() -> Option<UpdatesInfo> {
    // Try several variants for Fedora and dnf5 compatibility.
    let attempts: &[(&str, &[&str], &str)] = &[
        ("dnf", &["-q", "check-upgrade"], "dnf -q check-upgrade"),
        ("dnf", &["-q", "check-update"], "dnf -q check-update"),
        ("dnf5", &["-q", "check-upgrade"], "dnf5 -q check-upgrade"),
        ("dnf5", &["-q", "check-update"], "dnf5 -q check-update"),
    ];

    let xdg = prepare_temp_xdg("describe_me-dnf");
    for (prog, args, label) in attempts {
        let mut cmd = hardened_command(prog);
        cmd.args(*args).env("LC_ALL", "C");
        if let Some(xdg) = &xdg {
            cmd.env("HOME", &xdg.home)
                .env("XDG_STATE_HOME", &xdg.state)
                .env("XDG_CACHE_HOME", &xdg.cache)
                .env("XDG_CONFIG_HOME", &xdg.config);
        }
        debug!(
            "dnf_like_attempt command={} home={:?} xdg_state={:?} xdg_cache={:?}",
            *label,
            xdg.as_ref().map(|x| x.home.display().to_string()),
            xdg.as_ref().map(|x| x.state.display().to_string()),
            xdg.as_ref().map(|x| x.cache.display().to_string())
        );
        let output = match run_command(cmd, label) {
            Ok(out) => out,
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    debug!(error = %err, command = *label, "dnf-like invocation failed");
                }
                continue;
            }
        };

        let status = output.status.code();
        let stdout_len = output.stdout.len();
        let stderr_len = output.stderr.len();
        let stdout_preview = preview_str(&output.stdout, 600);
        let stderr_preview = preview_str(&output.stderr, 600);
        debug!(
            "dnf_like_output command={} exit={:?} stdout_len={} stderr_len={} stdout_preview={} stderr_preview={}",
            *label, status, stdout_len, stderr_len, stdout_preview, stderr_preview
        );
        trace!(
            command = *label,
            full_stdout = %String::from_utf8_lossy(&output.stdout),
            full_stderr = %String::from_utf8_lossy(&output.stderr),
            "dnf_like_full_output"
        );
        match status {
            Some(0) | Some(100) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut packages_vec: Vec<UpdatePackage> = Vec::new();
                for line in stdout.lines() {
                    if let Some(pkg) = parse_dnf_update_line(line) {
                        packages_vec.push(pkg);
                    }
                }
                let parse_hits = packages_vec.len();
                let mut pending = parse_hits;
                if pending == 0 {
                    // fallback to counter if parsing missed something
                    pending = count_dnf_updates(&stdout);
                }
                if pending == 0 && status == Some(100) {
                    pending = 1; // indicates updates but parsing failed, assume 1
                }
                debug!(
                    "dnf_like_parsed command={} parse_hits={} counted={}",
                    *label, parse_hits, pending
                );
                let reboot_required = detect_needs_restarting().unwrap_or(false)
                    || Path::new("/var/run/reboot-required").exists()
                    || Path::new("/run/reboot-required").exists();
                let packages = if packages_vec.is_empty() {
                    None
                } else {
                    Some(SharedSlice::from_vec(packages_vec))
                };
                return Some(UpdatesInfo {
                    pending: pending as u32,
                    reboot_required,
                    packages,
                });
            }
            Some(1) => {
                debug!(
                    "dnf_like_next command={} exit=1 (error), trying next",
                    *label
                );
                continue;
            }
            _ => {
                debug!(
                    "dnf_like_next command={} exit={:?} (unexpected), trying next",
                    *label, status
                );
                continue;
            }
        }
    }

    None
}

pub(super) fn count_dnf_updates(output: &str) -> usize {
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

fn parse_dnf_update_line(line: &str) -> Option<UpdatePackage> {
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
        return None;
    }
    // Expect columns: NAME[.arch]  VERSION  REPO
    // Collapse multiple spaces/tabs by splitting on whitespace.
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    let (name, arch) = match first.rsplit_once('.') {
        Some((n, a)) if !n.is_empty() && !a.is_empty() => (n.to_string(), Some(a.to_string())),
        _ => (first.to_string(), None),
    };
    let available_version = parts.next().map(|s| s.to_string());
    // Remaining tokens form the repository name, sometimes prefixed with '@'
    let repo_tokens: Vec<&str> = parts.collect();
    let mut repository: Option<String> = if repo_tokens.is_empty() {
        None
    } else {
        let mut text = repo_tokens.join(" ");
        if let Some(stripped) = text.strip_prefix('@') {
            text = stripped.to_string();
        }
        Some(text)
    };
    // Preserve arch by appending it to the repository (consistent with apt parser that keeps arch)
    if let (Some(a), Some(repo)) = (arch.as_deref(), repository.as_mut()) {
        if !a.is_empty() {
            repo.push(' ');
            repo.push_str(a);
        }
    }
    Some(UpdatePackage {
        name,
        current_version: None,
        available_version,
        repository,
    })
}

fn detect_needs_restarting() -> Option<bool> {
    let mut cmd = hardened_command("needs-restarting");
    cmd.arg("-r");
    match run_command_with_timeout(cmd, Duration::from_secs(5), "needs-restarting -r") {
        Ok(output) => match output.status.code() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => {
                debug!(status = ?output.status, "needs-restarting returned unexpected status");
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
    use proptest::prelude::*;

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

    #[test]
    fn dnf_skips_section_headers() {
        let sample = "\
Security:
    kernel.x86_64 5.14.0-370.el9_1";
        assert_eq!(count_dnf_updates(sample), 1);
    }

    proptest! {
        #[test]
        fn count_dnf_updates_matches_expected(lines in proptest::collection::vec(
            proptest::sample::select(vec![
                "package",
                "header",
                "blank",
            ]), 0..32)) {
            let header_prefixes = [
                "Last metadata expiration check",
                "Obsoleting Packages",
                "Updated Packages",
                "Available Packages",
                "Name ",
                "Package ",
                "Security:",
            ];

            let mut expected = 0usize;
            let mut rendered = Vec::new();
            for (idx, kind) in lines.iter().enumerate() {
                match *kind {
                    "package" => {
                        expected += 1;
                        rendered.push(format!("pkg{idx}.arch 1.0 repo"));
                    }
                    "header" => {
                        let prefix = header_prefixes[idx % header_prefixes.len()];
                        rendered.push(format!("{prefix} anything"));
                    }
                    _ => {
                        rendered.push(String::new());
                    }
                }
            }
            let text = rendered.join("\n");
            prop_assert_eq!(count_dnf_updates(&text), expected);
        }
    }
}
