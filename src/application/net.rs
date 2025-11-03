#[cfg(feature = "net")]
use crate::domain::{DescribeError, ListeningSocket, NetworkInterfaceTraffic};

#[cfg(feature = "net")]
pub fn net_listen() -> Result<Vec<ListeningSocket>, DescribeError> {
    #[cfg(target_os = "linux")]
    {
        crate::infrastructure::net::linux::collect_listening_sockets()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(DescribeError::Unsupported(
            "net_listen is only supported on Linux for now",
        ))
    }
}

#[cfg(feature = "net")]
pub fn network_traffic() -> Result<Vec<NetworkInterfaceTraffic>, DescribeError> {
    #[cfg(target_os = "linux")]
    {
        crate::infrastructure::net::linux::collect_network_traffic()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(DescribeError::Unsupported(
            "network_traffic is only supported on Linux for now",
        ))
    }
}
