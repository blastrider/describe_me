use crate::application::net::{NetBackend, NetCollectionParams};
use crate::application::AppContext;
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};

/// Placeholder backend for FreeBSD (to be implemented).
#[derive(Debug, Default, Clone, Copy)]
pub struct FreeBsdNetBackend;

impl NetBackend for FreeBsdNetBackend {
    fn collect_listening_sockets(
        &self,
        ctx: &AppContext,
        _params: NetCollectionParams,
    ) -> Result<Vec<ListeningSocket>, DescribeError> {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "net_listen not implemented on FreeBSD yet",
        ))
    }

    fn collect_network_traffic(
        &self,
        ctx: &AppContext,
    ) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
        let _ = ctx;
        Err(DescribeError::Unsupported(
            "network_traffic not implemented on FreeBSD yet",
        ))
    }
}
