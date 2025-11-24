#[cfg(feature = "journald")]
use std::process::{Command, Stdio};

#[cfg(feature = "journald")]
use crate::domain::{DescribeError, HostLogEntry, HostLogsPage};

#[cfg(feature = "journald")]
const JOURNALCTL_PATH: &str = "/usr/bin/journalctl";

#[cfg(feature = "journald")]
pub(crate) fn tail_journald(lines: usize) -> Result<HostLogsPage, DescribeError> {
    if lines == 0 {
        return Ok(HostLogsPage {
            entries: Vec::new(),
            truncated: false,
        });
    }

    let journalctl = std::env::var("DESCRIBE_ME_JOURNALCTL")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| JOURNALCTL_PATH.to_string());

    if !std::path::Path::new(&journalctl).exists() {
        return Err(DescribeError::External(format!(
            "journalctl introuvable ({journalctl})"
        )));
    }

    let output = Command::new(&journalctl)
        .args([
            "--no-pager",
            "--output=short-iso-precise",
            "--lines",
            &lines.to_string(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
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
