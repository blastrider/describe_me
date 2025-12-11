use crate::application::context::AppContext;
use crate::domain::{DescribeError, HostLogsPage};

pub const HOST_LOGS_DEFAULT_LINES: usize = 200;
pub const HOST_LOGS_MAX_LINES: usize = 1000;

/// Parameters for host log tailing.
#[derive(Clone, Copy, Debug)]
pub struct TailParams {
    pub lines: usize,
}

/// Backend abstraction for host logs (journald or platform-specific).
pub trait HostLogBackend: Send + Sync {
    fn tail(&self, ctx: &AppContext, params: TailParams) -> Result<HostLogsPage, DescribeError>;
}

type DefaultLogsBackend = crate::infrastructure::logs::PlatformLogsBackend;

/// Selects the default host logs backend for the current platform.
pub fn default_logs_backend() -> DefaultLogsBackend {
    crate::infrastructure::logs::default_logs_backend()
}

pub fn tail_host_logs(lines: usize) -> Result<HostLogsPage, DescribeError> {
    let ctx = AppContext::in_memory();
    tail_host_logs_with_ctx(&ctx, lines)
}

/// Tail host logs with an explicit application context.
pub fn tail_host_logs_with_ctx(
    ctx: &AppContext,
    lines: usize,
) -> Result<HostLogsPage, DescribeError> {
    let bounded = lines.clamp(1, HOST_LOGS_MAX_LINES);
    let mut page = default_logs_backend().tail(ctx, TailParams { lines: bounded })?;
    // Considère qu'on pourrait avoir plus d'entrées si on atteint la borne.
    page.truncated = page.truncated || page.entries.len() >= bounded;
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name;

    #[cfg(all(feature = "journald", target_os = "linux"))]
    #[test]
    fn selects_journald_backend_on_linux() {
        let name = type_name::<DefaultLogsBackend>();
        assert!(
            name.contains("JournaldBackend"),
            "expected journald backend, got {name}"
        );
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn selects_syslog_backend_on_freebsd() {
        let name = type_name::<DefaultLogsBackend>();
        assert!(
            name.contains("FreebsdSyslogBackend"),
            "expected syslog backend, got {name}"
        );
    }
}
