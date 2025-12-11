#[cfg(all(feature = "journald", target_os = "linux"))]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(all(feature = "journald", target_os = "linux"))]
#[allow(unused_imports)]
pub use linux::JournaldBackend;

#[cfg(target_os = "freebsd")]
#[allow(unused_imports)]
pub use freebsd::FreebsdSyslogBackend;
