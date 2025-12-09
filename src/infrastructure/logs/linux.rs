use crate::application::logs::{HostLogBackend, TailParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, HostLogEntry, HostLogsPage};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Journald backend executed via `journalctl`.
///
/// Linux-only: shells out to `journalctl` and expects systemd/journald to be present.
#[derive(Debug, Clone)]
pub struct JournaldBackend {
    path: PathBuf,
    base_env: Vec<(String, String)>,
}

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

        if !self.path.exists() {
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

        let output = cmd
            .output()
            .map_err(|err| DescribeError::External(format!("journalctl: {err}")))?;

        if !output.status.success() {
            return Err(DescribeError::External(format!(
                "journalctl a renvoyé {status}",
                status = output.status
            )));
        }

        let stdout = String::from_utf8(output.stdout)
            .map_err(|err| DescribeError::Parse(format!("journalctl utf8: {err}")))?;

        let entries = stdout.lines().filter_map(parse_line).collect::<Vec<_>>();

        Ok(HostLogsPage {
            truncated: entries.len() >= lines,
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
    let mut parts = line.splitn(3, ' ');
    let timestamp = parts.next()?.trim();
    let _host = parts.next()?; // on ignore l'hostname pour l'affichage
    let rest = parts.next().unwrap_or("").trim_start();

    if timestamp.is_empty() || rest.is_empty() {
        return None;
    }

    let (source, message) = if let Some((src, msg)) = rest.split_once(": ") {
        (Some(src.trim().to_string()), msg.trim().to_string())
    } else {
        (None, rest.to_string())
    };

    Some(HostLogEntry {
        timestamp: timestamp.to_string(),
        source,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::JournaldBackend;

    #[test]
    fn backend_uses_env_override() {
        std::env::set_var("DESCRIBE_ME_JOURNALCTL", "/tmp/custom-journalctl");
        let backend = JournaldBackend::new_from_env();
        assert_eq!(backend.path.display().to_string(), "/tmp/custom-journalctl");
        std::env::remove_var("DESCRIBE_ME_JOURNALCTL");
    }
}
