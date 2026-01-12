use std::io;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

const UPDATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const UPDATE_COMMAND_MAX_OUTPUT: usize = 8 * 1024 * 1024;
const UPDATE_COMMAND_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub(super) fn hardened_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear();
    cmd.env("PATH", UPDATE_COMMAND_PATH);
    cmd.env("LC_ALL", "C");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd
}

pub(super) fn run_command(cmd: Command, label: &str) -> io::Result<Output> {
    run_command_with_timeout(cmd, UPDATE_COMMAND_TIMEOUT, label)
}

pub(super) fn run_command_with_timeout(
    cmd: Command,
    timeout: Duration,
    label: &str,
) -> io::Result<Output> {
    let result = crate::infrastructure::command::run_command_with_timeout(
        cmd,
        timeout,
        UPDATE_COMMAND_MAX_OUTPUT,
        label,
    )?;
    if result.stdout_truncated || result.stderr_truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "command output exceeded limit",
        ));
    }
    Ok(result.output)
}

#[cfg(target_os = "linux")]
pub(super) fn preview_str(data: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(data);
    if text.len() <= limit {
        return text.into_owned();
    }
    text.chars().take(limit).collect()
}

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use tempfile::TempDir;

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
pub(super) struct TempXdg {
    _root: TempDir,
    pub(super) home: PathBuf,
    pub(super) state: PathBuf,
    pub(super) cache: PathBuf,
    pub(super) config: PathBuf,
}

/// Prepare per-run XDG directories for dnf-like tools.
#[cfg(target_os = "linux")]
pub(super) fn prepare_temp_xdg(prefix: &str) -> Option<TempXdg> {
    let root = tempfile::Builder::new().prefix(prefix).tempdir().ok()?;
    let base = root.path().to_path_buf();
    let state = base.join("state");
    let cache = base.join("cache");
    let config = base.join("config");
    for dir in [&base, &state, &cache, &config] {
        if let Err(err) = fs::create_dir_all(dir) {
            tracing::debug!("xdg_prepare_failed path={} err={}", dir.display(), err);
            return None;
        }
        if let Err(err) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
            tracing::debug!("xdg_chmod_failed path={} err={}", dir.display(), err);
        }
    }
    Some(TempXdg {
        _root: root,
        home: base,
        state,
        cache,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use tempfile::NamedTempFile;

    #[cfg(unix)]
    #[test]
    fn run_command_handles_large_output_without_timeout() {
        let mut tmp = NamedTempFile::new().expect("temp payload");
        let payload = vec![b'x'; 100_000];
        tmp.write_all(&payload).expect("write payload");
        tmp.flush().expect("flush payload");

        let mut cmd = hardened_command("sh");
        cmd.arg("-c")
            .arg("cat \"$PAYLOAD\" && cat \"$PAYLOAD\" 1>&2")
            .env("PAYLOAD", tmp.path());

        let output = run_command_with_timeout(cmd, Duration::from_secs(2), "cat-payload")
            .expect("command should complete");

        assert!(
            output.status.success(),
            "command exited with {:?}",
            output.status
        );
        assert_eq!(output.stdout, payload);
        assert_eq!(output.stderr, payload);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temp_xdg_uses_unique_dirs() {
        let first = prepare_temp_xdg("describe_me-dnf").expect("temp xdg");
        let second = prepare_temp_xdg("describe_me-dnf").expect("temp xdg");
        assert_ne!(first.home, second.home);
    }
}
