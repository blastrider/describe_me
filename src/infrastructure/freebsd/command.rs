use crate::domain::DescribeError;
use std::ffi::OsStr;
use std::process::{Command, Output, Stdio};

pub(crate) const FREEBSD_COMMAND_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub(crate) fn default_command_path() -> &'static str {
    FREEBSD_COMMAND_PATH
}

pub(crate) fn base_command(binary: &str) -> Command {
    base_command_with_path(binary, FREEBSD_COMMAND_PATH)
}

pub(crate) fn base_command_with_path(binary: &str, path: &str) -> Command {
    let mut cmd = Command::new(binary);
    cmd.env_clear();
    cmd.env("PATH", path);
    cmd.stdin(Stdio::null());
    cmd
}

pub(crate) fn run_command(
    binary: &str,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    label: &str,
) -> Result<Output, DescribeError> {
    run_command_with_path(binary, args, label, FREEBSD_COMMAND_PATH)
}

pub(crate) fn run_command_with_path(
    binary: &str,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    label: &str,
    path: &str,
) -> Result<Output, DescribeError> {
    let mut cmd = base_command_with_path(binary, path);
    cmd.args(args);
    execute_command(cmd, label, binary)
}

fn execute_command(mut cmd: Command, label: &str, binary: &str) -> Result<Output, DescribeError> {
    let display_label = command_label(label, binary, cmd.get_args());
    let output = cmd
        .output()
        .map_err(|err| DescribeError::External(format!("{display_label}: {err}")))?;

    if !output.status.success() {
        let stderr = format_stderr(&output.stderr);
        let status = output.status;
        let message = if stderr.is_empty() {
            format!("{display_label} exited with {status}")
        } else {
            format!("{display_label} exited with {status}: {stderr}")
        };
        return Err(DescribeError::External(message));
    }

    Ok(output)
}

fn command_label<'a>(
    label: &'a str,
    binary: &'a str,
    args: impl Iterator<Item = &'a OsStr>,
) -> String {
    let arg_list = args
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");

    let command_repr = if arg_list.is_empty() {
        binary.to_string()
    } else {
        format!("{binary} {arg_list}")
    };

    if label.is_empty() {
        command_repr
    } else if label == command_repr {
        command_repr
    } else {
        format!("{label} ({command_repr})")
    }
}

fn format_stderr(stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stderr).trim().to_string();
    const MAX_LEN: usize = 200;
    if text.len() > MAX_LEN {
        text.truncate(MAX_LEN);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_matches_expected() {
        assert_eq!(
            default_command_path(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
    }

    #[test]
    fn command_label_renders_binary_and_args() {
        let label = command_label("sockstat", "sockstat", ["-l", "-4"].iter().map(OsStr::new));
        assert_eq!(label, "sockstat (sockstat -l -4)");

        let fallback = command_label("", "service", std::iter::empty());
        assert_eq!(fallback, "service");
    }

    #[test]
    fn command_label_does_not_duplicate_identical_label() {
        let label = command_label("netstat -ibn", "netstat", ["-ibn"].iter().map(OsStr::new));
        assert_eq!(label, "netstat -ibn");
    }

    #[test]
    fn format_stderr_truncates_long_messages() {
        let long = "a".repeat(210);
        let formatted = format_stderr(long.as_bytes());
        assert_eq!(formatted.len(), 200);
    }
}
