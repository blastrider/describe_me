#[cfg(feature = "net")]
use crate::application::context::AppContext;
#[cfg(feature = "net")]
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};

/// Params for listening sockets collection.
#[cfg(feature = "net")]
#[derive(Clone, Copy, Debug)]
pub struct NetCollectionParams {
    pub resolve_processes: bool,
}

#[cfg(feature = "net")]
impl Default for NetCollectionParams {
    fn default() -> Self {
        Self {
            resolve_processes: true,
        }
    }
}

/// Backend abstraction for network collection (listening sockets, interface counters).
#[cfg(feature = "net")]
pub trait NetBackend: Send + Sync {
    fn collect_listening_sockets(
        &self,
        ctx: &AppContext,
        params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError>;

    fn collect_network_traffic(
        &self,
        ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError>;
}

#[cfg(feature = "net")]
type DefaultNetBackend = crate::infrastructure::net::PlatformNetBackend;

/// Selects the platform net backend.
#[cfg(feature = "net")]
pub fn default_net_backend() -> DefaultNetBackend {
    crate::infrastructure::net::default_net_backend()
}

#[cfg(feature = "net")]
pub fn net_listen() -> Result<Vec<ListeningSocket>, DescribeError> {
    net_listen_with_processes(true)
}

#[cfg(feature = "net")]
pub fn net_listen_with_processes(
    resolve_processes: bool,
) -> Result<Vec<ListeningSocket>, DescribeError> {
    let ctx = AppContext::in_memory();
    net_listen_with_context(&ctx, NetCollectionParams { resolve_processes })
}

/// Entry point used by collectors with an explicit context.
#[cfg(feature = "net")]
pub fn net_listen_with_context(
    ctx: &AppContext,
    params: NetCollectionParams,
) -> Result<Vec<ListeningSocket>, DescribeError> {
    default_net_backend().collect_listening_sockets(ctx, params)
}

#[cfg(feature = "net")]
pub fn network_traffic() -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
    let ctx = AppContext::in_memory();
    network_traffic_with_context(&ctx)
}

/// Entry point used by collectors with an explicit context.
#[cfg(feature = "net")]
pub fn network_traffic_with_context(
    ctx: &AppContext,
) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
    default_net_backend().collect_network_traffic(ctx)
}

#[cfg(all(test, feature = "net"))]
mod tests {
    use super::*;
    use std::any::type_name;

    #[test]
    fn default_backend_matches_target_os() {
        let name = type_name::<DefaultNetBackend>();

        #[cfg(target_os = "linux")]
        assert!(
            name.contains("LinuxNetBackend"),
            "expected Linux backend, got {name}"
        );

        #[cfg(target_os = "freebsd")]
        assert!(
            name.contains("FreeBsdNetBackend"),
            "expected FreeBSD backend, got {name}"
        );

        #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
        assert!(
            name.contains("UnsupportedNetBackend"),
            "expected noop backend, got {name}"
        );
    }
}
