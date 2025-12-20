#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::application::net::{NetBackend, NetCollectionParams};
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::application::AppContext;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

pub mod common;

#[cfg(target_os = "linux")]
pub type PlatformNetBackend = linux::LinuxNetBackend;

#[cfg(target_os = "freebsd")]
pub type PlatformNetBackend = freebsd::FreeBsdNetBackend;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub type PlatformNetBackend = UnsupportedNetBackend;

/// Fabrique centralisée pour le backend réseau.
pub fn default_net_backend() -> PlatformNetBackend {
    PlatformNetBackend::default()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedNetBackend;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
impl NetBackend for UnsupportedNetBackend {
    fn collect_listening_sockets(
        &self,
        ctx: &AppContext,
        _params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError> {
        let _ = ctx;
        Ok(Vec::new())
    }

    fn collect_network_traffic(
        &self,
        ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
        let _ = ctx;
        Ok(Vec::new())
    }
}
