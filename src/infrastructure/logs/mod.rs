#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
use crate::application::logs::{HostLogBackend, TailParams};
#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
use crate::application::AppContext;
#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
use crate::domain::{DescribeError, HostLogsPage};

#[cfg(all(feature = "journald", target_os = "linux"))]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(all(feature = "journald", target_os = "linux"))]
#[allow(unused_imports)]
pub use linux::JournaldBackend;

#[cfg(target_os = "freebsd")]
#[allow(unused_imports)]
pub use freebsd::FreebsdSyslogBackend;

#[cfg(all(feature = "journald", target_os = "linux"))]
pub type PlatformLogsBackend = linux::JournaldBackend;

#[cfg(target_os = "freebsd")]
pub type PlatformLogsBackend = freebsd::FreebsdSyslogBackend;

#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
pub type PlatformLogsBackend = UnsupportedLogsBackend;

/// Fabrique centralisée pour le backend de logs hôte.
pub fn default_logs_backend() -> PlatformLogsBackend {
    PlatformLogsBackend::default()
}

#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
#[derive(Default, Debug)]
pub struct UnsupportedLogsBackend;

#[cfg(not(any(all(feature = "journald", target_os = "linux"), target_os = "freebsd")))]
impl HostLogBackend for UnsupportedLogsBackend {
    fn tail(&self, ctx: &AppContext, params: TailParams) -> Result<HostLogsPage, DescribeError> {
        let _ = (ctx, params);
        Err(DescribeError::Unsupported(
            "host logs backend unavailable on this platform",
        ))
    }
}
