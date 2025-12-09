pub mod sysinfo;
pub mod system;

#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod services;

#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod systemd {
    #[allow(unused_imports)]
    pub use super::services::systemd::*;
}

#[cfg(feature = "journald")]
pub mod logs;

#[cfg(feature = "net")]
pub mod net;

pub mod history;
pub mod storage;
pub mod updates;
