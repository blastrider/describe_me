#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Portée d'exécution détectée pour describe-me.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExecutionScope {
    Host,
    ContainerSelf,
    HostFromContainer,
}

impl ExecutionScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionScope::Host => "host",
            ExecutionScope::ContainerSelf => "container",
            ExecutionScope::HostFromContainer => "host_from_container",
        }
    }
}

impl fmt::Display for ExecutionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ExecutionScope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "host" => Ok(ExecutionScope::Host),
            "container" | "container_self" | "container-self" => Ok(ExecutionScope::ContainerSelf),
            "host_from_container" | "host-from-container" | "hostfromcontainer" | "host_from" => {
                Ok(ExecutionScope::HostFromContainer)
            }
            _ => Err(()),
        }
    }
}
