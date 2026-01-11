pub mod command;
pub mod sysinfo;
pub mod system;

#[cfg(feature = "systemd")]
pub mod services;

#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod systemd {
    pub use super::services::systemd::*;
}

#[cfg(all(feature = "systemd", target_os = "freebsd"))]
pub mod rc {
    pub use super::services::freebsd::*;
}

pub mod logs;

#[cfg(feature = "net")]
pub mod net;

pub mod history;
pub mod storage;
pub mod updates;
