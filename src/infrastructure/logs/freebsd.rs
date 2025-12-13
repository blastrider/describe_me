use crate::application::logs::{HostLogBackend, TailParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, HostLogEntry, HostLogsPage};
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const DEFAULT_SYSLOG_PATH: &str = "/var/log/messages";

/// FreeBSD backend reading syslog-style text logs.
#[derive(Debug, Clone)]
pub struct FreebsdSyslogBackend {
    path: PathBuf,
}

impl Default for FreebsdSyslogBackend {
    fn default() -> Self {
        Self::new_from_env()
    }
}

impl FreebsdSyslogBackend {
    pub fn new_from_env() -> Self {
        let path = env::var("DESCRIBE_ME_SYSLOG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SYSLOG_PATH));
        Self { path }
    }

    fn tail_raw(&self, lines: usize) -> Result<HostLogsPage, DescribeError> {
        if lines == 0 {
            return Ok(HostLogsPage {
                entries: Vec::new(),
                truncated: false,
            });
        }

        let file = File::open(&self.path).map_err(|err| {
            DescribeError::External(format!("open {}: {err}", self.path.display()))
        })?;
        let mut reader = BufReader::new(file);

        let mut buffer = Vec::new();
        let mut ring = VecDeque::with_capacity(lines);
        let mut seen = 0usize;

        loop {
            buffer.clear();
            let n = reader.read_until(b'\n', &mut buffer).map_err(|err| {
                DescribeError::System(format!("read {}: {err}", self.path.display()))
            })?;
            if n == 0 {
                break;
            }

            while buffer
                .last()
                .map(|b| *b == b'\n' || *b == b'\r')
                .unwrap_or(false)
            {
                buffer.pop();
            }

            let line = String::from_utf8_lossy(&buffer).to_string();
            if ring.len() == lines {
                ring.pop_front();
            }
            ring.push_back(line);
            seen += 1;
        }

        let entries = ring
            .into_iter()
            .filter_map(parse_syslog_line)
            .collect::<Vec<_>>();

        Ok(HostLogsPage {
            truncated: seen > lines,
            entries,
        })
    }
}

impl HostLogBackend for FreebsdSyslogBackend {
    fn tail(&self, ctx: &AppContext, params: TailParams) -> Result<HostLogsPage, DescribeError> {
        let _ = ctx;
        self.tail_raw(params.lines)
    }
}

fn parse_syslog_line(line: String) -> Option<HostLogEntry> {
    let mut fields = line.split_whitespace();
    let month = fields.next()?;
    let day = fields.next()?;
    let time = fields.next()?;
    let _host = fields.next()?;

    // Determine the remainder after the first four tokens by scanning the original line.
    let mut tokens_seen = 0usize;
    let mut idx = 0usize;
    let bytes = line.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    while tokens_seen < 4 && idx < bytes.len() {
        while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        tokens_seen += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
    }

    let rest = line[idx..].trim();
    if rest.is_empty() {
        return None;
    }

    let timestamp = format!("{month} {day} {time}");
    let (source, message) = if let Some((src, msg)) = rest.split_once(": ") {
        (Some(src.trim().to_string()), msg.trim().to_string())
    } else if let Some((src, msg)) = rest.split_once(':') {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_syslog_line_extracts_fields() {
        let entry = parse_syslog_line("Jan  3 12:34:56 myhost sshd[123]: started".to_string())
            .expect("parsed");
        assert_eq!(entry.timestamp, "Jan 3 12:34:56");
        assert_eq!(entry.source.as_deref(), Some("sshd[123]"));
        assert_eq!(entry.message, "started");
    }

    #[test]
    fn tail_raw_keeps_last_lines_and_is_lossy() {
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "Jan  3 12:00:00 host kernel: ready").unwrap();
        writeln!(file, "Jan  3 12:01:00 host sshd[1]: ok").unwrap();
        // Invalid UTF-8 sequence will be replaced.
        file.write_all(b"Jan  3 12:02:00 host test: hi\xff\n")
            .unwrap();
        file.flush().unwrap();

        let backend = FreebsdSyslogBackend {
            path: file.path().to_path_buf(),
        };
        let page = backend.tail_raw(2).expect("tail");
        assert!(page.truncated);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].message, "ok");
        assert_eq!(page.entries[1].message, "hi�");
    }
}
