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

#[cfg(all(feature = "journald", target_os = "linux"))]
type DefaultLogsBackend = crate::infrastructure::logs::linux::JournaldBackend;
#[cfg(not(all(feature = "journald", target_os = "linux")))]
type DefaultLogsBackend = UnsupportedLogsBackend;

#[cfg(not(all(feature = "journald", target_os = "linux")))]
#[derive(Default, Debug)]
struct UnsupportedLogsBackend;

#[cfg(not(all(feature = "journald", target_os = "linux")))]
impl HostLogBackend for UnsupportedLogsBackend {
    fn tail(&self, ctx: &AppContext, params: TailParams) -> Result<HostLogsPage, DescribeError> {
        let _ = (ctx, params);
        Err(DescribeError::Unsupported(
            "host logs backend unavailable on this platform",
        ))
    }
}

/// Selects the default host logs backend for the current platform.
pub fn default_logs_backend() -> DefaultLogsBackend {
    DefaultLogsBackend::default()
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
