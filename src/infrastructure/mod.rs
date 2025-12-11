pub mod sysinfo;
pub mod system;

#[cfg(all(feature = "systemd", any(target_os = "linux", target_os = "freebsd")))]
pub mod services;

#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod systemd {
    #[allow(unused_imports)]
    pub use super::services::systemd::*;
}

#[cfg(all(feature = "systemd", target_os = "freebsd"))]
pub mod rc {
    #[allow(unused_imports)]
    pub use super::services::freebsd::*;
}

#[cfg(any(feature = "journald", target_os = "freebsd"))]
pub mod logs;

#[cfg(feature = "net")]
pub mod net;

pub mod history;
pub mod storage;
pub mod updates;
