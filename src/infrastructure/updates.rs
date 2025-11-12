use crate::domain::{UpdatePackage, UpdatesInfo};
use crate::SharedSlice;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};
use tracing::{debug, trace, warn};

const UPDATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const UPDATE_COMMAND_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
        .or_else(gather_pacman_updates)
        .or_else(gather_checkupdates)
        .or_else(gather_apk_updates)
}

#[cfg(target_os = "freebsd")]
fn gather_freebsd_updates() -> Option<UpdatesInfo> {
    gather_freebsd_pkg_updates()
}

fn hardened_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear();
    cmd.env("PATH", UPDATE_COMMAND_PATH);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd
}

fn run_command(cmd: Command, label: &str) -> io::Result<Output> {
    run_command_with_timeout(cmd, UPDATE_COMMAND_TIMEOUT, label)
}

fn run_command_with_timeout(cmd: Command, timeout: Duration, label: &str) -> io::Result<Output> {
    let mut cmd = cmd;
    let start = Instant::now();
    let mut child = cmd.spawn()?;
    loop {
        match child.try_wait()? {
            Some(_) => {
                let output = child.wait_with_output()?;
                let elapsed = start.elapsed();
                debug!(
                    "update_command_completed command={} status={} duration_ms={}",
                    label,
                    output.status,
                    elapsed.as_millis()
                );
                return Ok(output);
            }
            None => {
                if start.elapsed() >= timeout {
                    warn!(
                        "update_command_timeout command={} timeout_s={}",
                        label,
                        timeout.as_secs()
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"));
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Prépare des répertoires XDG temporaires et renvoie (home, state, cache, config) en String.
fn prepare_temp_xdg(prefix: &str) -> Option<(String, String, String, String)> {
    let base = env::temp_dir().join(prefix);
    let state = base.join("state");
    let cache = base.join("cache");
    let config = base.join("config");
    for dir in [&base, &state, &cache, &config] {
        if let Err(err) = fs::create_dir_all(dir) {
            debug!("xdg_prepare_failed path={} err={}", dir.display(), err);
            return None;
        }
        #[cfg(unix)]
        if let Err(err) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
            debug!("xdg_chmod_failed path={} err={}", dir.display(), err);
        }
    }
    Some((
        base.display().to_string(),
        state.display().to_string(),
        cache.display().to_string(),
        config.display().to_string(),
    ))
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

    let mut cmd = hardened_command("apt-get");
    cmd.args(["-s", "upgrade"])
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

#[cfg(target_os = "linux")]
enum AptListError {
    NotAvailable,
    Failed,
}

#[cfg(target_os = "linux")]
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
fn preview_str(data: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(data);
    if text.len() <= limit {
        return text.into_owned();
    }
    text.chars().take(limit).collect()
}

#[cfg(target_os = "linux")]
fn gather_dnf_updates() -> Option<UpdatesInfo> {
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
        if let Some((home, state, cache, config)) = &xdg {
            cmd.env("HOME", home)
                .env("XDG_STATE_HOME", state)
                .env("XDG_CACHE_HOME", cache)
                .env("XDG_CONFIG_HOME", config);
        }
        debug!(
            "dnf_like_attempt command={} home={:?} xdg_state={:?} xdg_cache={:?}",
            *label,
            xdg.as_ref().map(|x| &x.0),
            xdg.as_ref().map(|x| &x.1),
            xdg.as_ref().map(|x| &x.2)
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

#[cfg(target_os = "linux")]
fn gather_pacman_updates() -> Option<UpdatesInfo> {
    let mut cmd = hardened_command("pacman");
    cmd.args(["-Qu"]);
    cmd.env("LC_ALL", "C");
    let output = match run_command(cmd, "pacman -Qu") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
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

#[cfg(target_os = "linux")]
fn gather_checkupdates() -> Option<UpdatesInfo> {
    let cmd = hardened_command("checkupdates");
    let output = match run_command_with_timeout(cmd, Duration::from_secs(10), "checkupdates") {
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
fn parse_pacman_update_line(line: &str) -> Option<UpdatePackage> {
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

#[cfg(target_os = "linux")]
fn gather_apk_updates() -> Option<UpdatesInfo> {
    let mut cmd = hardened_command("apk");
    cmd.args(["version", "-l", "<"]);
    let output = match run_command(cmd, "apk version -l <") {
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
    let pending = count_apk_updates(&stdout) as u32;
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

#[cfg(target_os = "linux")]
fn count_apk_updates(output: &str) -> usize {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn parse_apt_upgradable_line_for_tests(line: &str) -> Option<UpdatePackage> {
    parse_apt_upgradable_line(line)
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn count_dnf_updates_for_tests(output: &str) -> usize {
    count_dnf_updates(output)
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn count_apk_updates_for_tests(output: &str) -> usize {
    count_apk_updates(output)
}

#[cfg(target_os = "freebsd")]
fn gather_freebsd_pkg_updates() -> Option<UpdatesInfo> {
    let mut cmd = hardened_command("pkg");
    cmd.args(["version", "-l", "<"]);
    let output = match run_command(cmd, "pkg version -l <") {
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

#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

        #[test]
        fn count_apk_updates_counts_non_empty(lines in proptest::collection::vec(
            proptest::string::string_regex("[A-Za-z0-9\\s./-]{0,24}").unwrap(),
            0..32
        )) {
            let text = lines.join("\n");
            let expected = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            prop_assert_eq!(count_apk_updates(&text), expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pacman_line_parses_versions() {
        let sample = "bash 5.1.16.1-1 -> 5.1.16.2-1";
        let pkg = parse_pacman_update_line(sample).expect("parsed pacman line");
        assert_eq!(pkg.name, "bash");
        assert_eq!(pkg.current_version.as_deref(), Some("5.1.16.1-1"));
        assert_eq!(pkg.available_version.as_deref(), Some("5.1.16.2-1"));
    }
}
