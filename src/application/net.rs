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

#[cfg(all(feature = "net", target_os = "linux"))]
type DefaultNetBackend = crate::infrastructure::net::linux::LinuxNetBackend;
#[cfg(all(feature = "net", target_os = "freebsd"))]
// TODO: plug FreeBSD implementation once available.
type DefaultNetBackend = crate::infrastructure::net::freebsd::FreeBsdNetBackend;
#[cfg(all(feature = "net", not(any(target_os = "linux", target_os = "freebsd"))))]
type DefaultNetBackend = UnsupportedNetBackend;

/// Selects the platform net backend.
#[cfg(feature = "net")]
pub fn default_net_backend() -> DefaultNetBackend {
    DefaultNetBackend::default()
}

#[cfg(all(feature = "net", not(any(target_os = "linux", target_os = "freebsd"))))]
#[derive(Debug, Default, Clone, Copy)]
struct UnsupportedNetBackend;

#[cfg(all(feature = "net", not(any(target_os = "linux", target_os = "freebsd"))))]
impl NetBackend for UnsupportedNetBackend {
    fn collect_listening_sockets(
        &self,
        ctx: &AppContext,
        _params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError> {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "listening sockets collection not implemented for this OS",
        ))
    }

    fn collect_network_traffic(
        &self,
        ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "network traffic collection not implemented for this OS",
        ))
    }
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
