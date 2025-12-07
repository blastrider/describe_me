#[cfg(feature = "journald")]
use std::path::PathBuf;
#[cfg(feature = "journald")]
use std::process::{Command, Stdio};

#[cfg(feature = "journald")]
use crate::domain::{DescribeError, HostLogEntry, HostLogsPage};

/// Exécuteur dédié à `journalctl`, configurable via l'environnement.
#[cfg(feature = "journald")]
pub struct JournalctlRunner {
    path: PathBuf,
    base_env: Vec<(String, String)>,
}

#[cfg(feature = "journald")]
impl JournalctlRunner {
    /// Construit un runner en lisant éventuellement `DESCRIBE_ME_JOURNALCTL`, sinon `journalctl`.
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

    /// Lit les dernières `lines` entrées journald et les parse en `HostLogsPage`.
    pub fn tail(&self, lines: usize) -> Result<HostLogsPage, DescribeError> {
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

#[cfg(feature = "journald")]
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

#[cfg(all(test, feature = "journald"))]
mod tests {
    use super::JournalctlRunner;

    #[test]
    fn runner_uses_env_override() {
        std::env::set_var("DESCRIBE_ME_JOURNALCTL", "/tmp/custom-journalctl");
        let runner = JournalctlRunner::new_from_env();
        assert_eq!(runner.path.display().to_string(), "/tmp/custom-journalctl");
        std::env::remove_var("DESCRIBE_ME_JOURNALCTL");
    }
}
