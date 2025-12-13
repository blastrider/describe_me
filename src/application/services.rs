#[cfg(feature = "systemd")]
use crate::application::context::AppContext;
#[cfg(feature = "systemd")]
use crate::domain::{DescribeError, ServiceInfo};

/// Alias pour faciliter la lecture des résultats de backend services.
#[cfg(feature = "systemd")]
pub type ServicesSnapshot = Vec<ServiceInfo>;

/// Backend abstraction for service listing (systemd ou spécifique plateforme).
#[cfg(feature = "systemd")]
pub trait ServiceBackend: Send + Sync {
    fn collect_services(&self, ctx: &AppContext) -> Result<ServicesSnapshot, DescribeError>;
}

#[cfg(feature = "systemd")]
type DefaultServiceBackend = crate::infrastructure::services::PlatformServiceBackend;

/// Selects the default service backend for the current platform.
#[cfg(feature = "systemd")]
pub fn default_service_backend() -> DefaultServiceBackend {
    crate::infrastructure::services::default_service_backend()
}

#[cfg(all(test, feature = "systemd"))]
mod tests {
    use super::*;
    use std::any::type_name;

    #[test]
    fn default_backend_matches_target_os() {
        let name = type_name::<DefaultServiceBackend>();

        #[cfg(target_os = "linux")]
        assert!(
            name.contains("SystemdBackend"),
            "expected systemd backend, got {name}"
        );

        #[cfg(target_os = "freebsd")]
        assert!(
            name.contains("RcServiceBackend"),
            "expected rc.d backend, got {name}"
        );

        #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
        assert!(
            name.contains("UnsupportedServiceBackend"),
            "expected noop backend, got {name}"
        );
    }
}
