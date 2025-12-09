#[cfg(all(feature = "systemd", target_os = "linux"))]
pub mod systemd;

#[cfg(all(feature = "systemd", target_os = "linux"))]
#[allow(unused_imports)]
pub use systemd::SystemdBackend;
