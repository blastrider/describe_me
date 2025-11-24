use crate::domain::{DescribeError, HostLogsPage};

pub const HOST_LOGS_DEFAULT_LINES: usize = 200;
pub const HOST_LOGS_MAX_LINES: usize = 1000;

pub fn tail_host_logs(lines: usize) -> Result<HostLogsPage, DescribeError> {
    let bounded = lines.clamp(1, HOST_LOGS_MAX_LINES);

    #[cfg(feature = "journald")]
    {
        let mut page = crate::infrastructure::logs::tail_journald(bounded)?;
        // Considère qu'on pourrait avoir plus d'entrées si on atteint la borne.
        page.truncated = page.truncated || page.entries.len() >= bounded;
        Ok(page)
    }

    #[cfg(not(feature = "journald"))]
    {
        let _ = bounded;
        Err(DescribeError::Unsupported(
            "journald indisponible (feature `journald` désactivée)",
        ))
    }
}
