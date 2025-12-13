#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::application::services::ServiceBackend;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::application::AppContext;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::domain::{DescribeError, ServiceInfo};

#[cfg(target_os = "linux")]
pub mod systemd;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use systemd::SystemdBackend;

#[cfg(target_os = "freebsd")]
#[allow(unused_imports)]
pub use freebsd::RcServiceBackend;

#[cfg(target_os = "linux")]
pub type PlatformServiceBackend = systemd::SystemdBackend;

#[cfg(target_os = "freebsd")]
pub type PlatformServiceBackend = freebsd::RcServiceBackend;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub type PlatformServiceBackend = UnsupportedServiceBackend;

/// Fabrique centralisée pour le backend services.
pub fn default_service_backend() -> PlatformServiceBackend {
    PlatformServiceBackend::default()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedServiceBackend;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
impl ServiceBackend for UnsupportedServiceBackend {
    fn collect_services(&self, ctx: &AppContext) -> Result<Vec<ServiceInfo>, DescribeError> {
        let _ = ctx;
        Ok(Vec::new())
    }
}
