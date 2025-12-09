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

/// Selects the default service backend for the current platform.
#[cfg(feature = "systemd")]
pub fn default_service_backend() -> Option<DefaultServiceBackend> {
    #[cfg(target_os = "linux")]
    {
        Some(DefaultServiceBackend::default())
    }
    #[cfg(target_os = "freebsd")]
    {
        // TODO: implement a FreeBSD service backend (rc.d ?)
        let _ = ();
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        None
    }
}
