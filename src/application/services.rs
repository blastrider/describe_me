#[cfg(feature = "systemd")]
use crate::application::context::AppContext;
#[cfg(feature = "systemd")]
use crate::domain::{DescribeError, ServiceInfo};

/// Backend abstraction for service listing (systemd or platform-specific).
#[cfg(feature = "systemd")]
pub trait ServiceBackend: Send + Sync {
    fn list_services(&self, ctx: &AppContext) -> Result<Vec<ServiceInfo>, DescribeError>;
}

#[cfg(all(feature = "systemd", target_os = "linux"))]
type DefaultServiceBackend = crate::infrastructure::services::systemd::SystemdBackend;
#[cfg(all(feature = "systemd", target_os = "freebsd"))]
type DefaultServiceBackend = crate::infrastructure::services::freebsd::RcServiceBackend;
#[cfg(all(
    feature = "systemd",
    not(any(target_os = "linux", target_os = "freebsd"))
))]
type DefaultServiceBackend = UnsupportedServiceBackend;

#[cfg(all(
    feature = "systemd",
    not(any(target_os = "linux", target_os = "freebsd"))
))]
#[derive(Default, Debug, Clone, Copy)]
struct UnsupportedServiceBackend;

#[cfg(all(
    feature = "systemd",
    not(any(target_os = "linux", target_os = "freebsd"))
))]
impl ServiceBackend for UnsupportedServiceBackend {
    fn list_services(&self, ctx: &AppContext) -> Result<Vec<ServiceInfo>, DescribeError> {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "service backend not available on this platform",
        ))
    }
}

/// Selects the default service backend for the current platform.
#[cfg(feature = "systemd")]
pub fn default_service_backend() -> Option<DefaultServiceBackend> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        Some(DefaultServiceBackend::default())
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        None
    }
}
