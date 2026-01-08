use crate::application::logs::{HostLogBackend, TailParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, HostLogEntry, HostLogsPage};
use crate::infrastructure::command;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Journald backend executed via `journalctl`.
///
/// Linux-only: shells out to `journalctl` and expects systemd/journald to be present.
#[derive(Debug, Clone)]
pub struct JournaldBackend {
    path: PathBuf,
    base_env: Vec<(String, String)>,
}

const JOURNALCTL_TIMEOUT: Duration = Duration::from_secs(5);
const JOURNALCTL_MIN_OUTPUT: usize = 128 * 1024;
const JOURNALCTL_MAX_OUTPUT: usize = 2 * 1024 * 1024;
const JOURNALCTL_BYTES_PER_LINE: usize = 2048;

impl Default for JournaldBackend {
    fn default() -> Self {
        Self::new_from_env()
    }
}

impl JournaldBackend {
    /// Construit un backend en lisant éventuellement `DESCRIBE_ME_JOURNALCTL`, sinon `journalctl`.
    pub fn new_from_env() -> Self {
        let path = std::env::var("DESCRIBE_ME_JOURNALCTL")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("journalctl"));
        let base_env = vec![
            ("SYSTEMD_COLORS".into(), "0".into()),
            ("LANG".into(), "C".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ];
        Self { path, base_env }
    }

    fn tail_raw(&self, lines: usize) -> Result<HostLogsPage, DescribeError> {
        if lines == 0 {
            return Ok(HostLogsPage {
                entries: Vec::new(),
                truncated: false,
            });
        }

        if self.path.is_absolute() && !self.path.exists() {
            return Err(DescribeError::External(format!(
                "journalctl introuvable ({})",
                self.path.display()
            )));
        }

        let mut cmd = Command::new(&self.path);
        cmd.args([
            "--no-pager",
            "--output=short-iso-precise",
            "--lines",
            &lines.to_string(),
        ])
        .stdin(Stdio::null());

        cmd.env_clear();
        for (k, v) in &self.base_env {
            cmd.env(k, v);
        }

        let max_output = lines
            .saturating_mul(JOURNALCTL_BYTES_PER_LINE)
            .clamp(JOURNALCTL_MIN_OUTPUT, JOURNALCTL_MAX_OUTPUT);
        let output =
            command::run_command_with_timeout(cmd, JOURNALCTL_TIMEOUT, max_output, "journalctl")
                .map_err(|err| DescribeError::External(format!("journalctl: {err}")))?;
        if output.stdout_truncated || output.stderr_truncated {
            return Err(DescribeError::External(
                "journalctl output exceeded limit".into(),
            ));
        }
        let output = output.output;

        if !output.status.success() {
            return Err(DescribeError::External(format!(
                "journalctl a renvoyé {status}",
                status = output.status
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut raw_lines = 0usize;
        let entries = stdout
            .lines()
            .filter_map(|line| {
                raw_lines += 1;
                parse_line(line)
            })
            .collect::<Vec<_>>();

        Ok(HostLogsPage {
            truncated: raw_lines >= lines,
            entries,
        })
    }
}

impl HostLogBackend for JournaldBackend {
    fn tail(&self, ctx: &AppContext, params: TailParams) -> Result<HostLogsPage, DescribeError> {
        let _ = ctx;
        self.tail_raw(params.lines)
    }
}

fn parse_line(line: &str) -> Option<HostLogEntry> {
    let mut idx = 0usize;
    let date = next_token(line, &mut idx)?;
    let time = next_token(line, &mut idx)?;
    let third = next_token(line, &mut idx)?;

    let (tz, host) = if is_timezone_token(third) {
        let host = next_token(line, &mut idx)?;
        (Some(third), host)
    } else {
        (None, third)
    };

    if host.is_empty() {
        return None;
    }

    let rest = line[idx..].trim_start();
    if rest.is_empty() {
        return None;
    }

    let timestamp = if let Some(tz) = tz {
        format!("{date} {time} {tz}")
    } else {
        format!("{date} {time}")
    };

    let (source, message) = if let Some((src, msg)) = rest.split_once(": ") {
        (Some(src.trim().to_string()), msg.trim().to_string())
    } else {
        (None, rest.to_string())
    };

    Some(HostLogEntry {
        timestamp,
        source,
        message,
    })
}

fn next_token<'a>(line: &'a str, idx: &mut usize) -> Option<&'a str> {
    let bytes = line.as_bytes();
    while *idx < bytes.len() && bytes[*idx].is_ascii_whitespace() {
        *idx += 1;
    }
    if *idx >= bytes.len() {
        return None;
    }
    let start = *idx;
    while *idx < bytes.len() && !bytes[*idx].is_ascii_whitespace() {
        *idx += 1;
    }
    Some(&line[start..*idx])
}

fn is_timezone_token(token: &str) -> bool {
    if token.eq_ignore_ascii_case("utc") || token == "Z" {
        return true;
    }
    let mut chars = token.chars();
    match chars.next() {
        Some('+') | Some('-') => chars.all(|c| c.is_ascii_digit() || c == ':'),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_line, JournaldBackend};

    #[test]
    fn backend_uses_env_override() {
        std::env::set_var("DESCRIBE_ME_JOURNALCTL", "/tmp/custom-journalctl");
        let backend = JournaldBackend::new_from_env();
        assert_eq!(backend.path.display().to_string(), "/tmp/custom-journalctl");
        std::env::remove_var("DESCRIBE_ME_JOURNALCTL");
    }

    #[test]
    fn parse_line_handles_inline_timezone() {
        let line = "2025-01-27 12:34:56.123456+0100 host sshd[42]: login ok";
        let entry = parse_line(line).expect("parsed");
        assert_eq!(entry.timestamp, "2025-01-27 12:34:56.123456+0100");
        assert_eq!(entry.source.as_deref(), Some("sshd[42]"));
        assert_eq!(entry.message, "login ok");
    }

    #[test]
    fn parse_line_handles_separate_timezone() {
        let line = "2025-01-27 12:34:56.123456 +0100 host kernel: boot";
        let entry = parse_line(line).expect("parsed");
        assert_eq!(entry.timestamp, "2025-01-27 12:34:56.123456 +0100");
        assert_eq!(entry.source.as_deref(), Some("kernel"));
        assert_eq!(entry.message, "boot");
    }
}
