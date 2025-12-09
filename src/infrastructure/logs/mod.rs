#[cfg(all(feature = "journald", target_os = "linux"))]
pub mod linux;

#[cfg(all(feature = "journald", target_os = "linux"))]
#[allow(unused_imports)]
pub use linux::JournaldBackend;
