pub mod sysinfo;
pub mod system;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(feature = "systemd")]
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

pub mod logs;

pub(crate) mod process;

#[cfg(feature = "net")]
pub mod net;

pub mod history;
pub mod storage;
pub mod updates;
