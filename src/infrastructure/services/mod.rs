#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod systemd;

#[cfg(all(feature = "systemd", target_os = "freebsd"))]
pub mod freebsd;

#[cfg(all(feature = "systemd", target_os = "linux"))]
#[allow(unused_imports)]
pub use systemd::SystemdBackend;

#[cfg(all(feature = "systemd", target_os = "freebsd"))]
#[allow(unused_imports)]
pub use freebsd::RcServiceBackend;
