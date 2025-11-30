use crate::{
    application::context::AppContext,
    domain::{CaptureOptions, DescribeError, SystemSnapshot},
};

#[cfg(any(feature = "systemd", feature = "net"))]
use crate::application::logging::LogEvent;
#[cfg(any(feature = "systemd", feature = "net"))]
use std::borrow::Cow;

pub trait SnapshotCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError>;
}

mod core;
pub use core::CoreCollector;

mod updates;
pub use updates::UpdatesCollector;

#[cfg(feature = "systemd")]
mod services;
#[cfg(feature = "systemd")]
pub use services::ServicesCollector;

#[cfg(feature = "net")]
mod net;
#[cfg(feature = "net")]
pub use net::NetCollector;

#[cfg(feature = "serde")]
mod containers;
#[cfg(feature = "serde")]
pub use containers::ContainersCollector;

#[allow(clippy::vec_init_then_push)]
pub fn default_collectors() -> Vec<Box<dyn SnapshotCollector>> {
    let mut collectors: Vec<Box<dyn SnapshotCollector>> = Vec::new();

    #[cfg(feature = "systemd")]
    collectors.push(Box::new(ServicesCollector));

    #[cfg(feature = "net")]
    collectors.push(Box::new(NetCollector));

    collectors.push(Box::new(UpdatesCollector));

    #[cfg(feature = "serde")]
    collectors.push(Box::new(ContainersCollector));

    collectors
}

#[cfg(any(feature = "systemd", feature = "net"))]
pub(crate) fn log_system_error(location: &'static str, err: &DescribeError) {
    LogEvent::SystemError {
        location: Cow::Borrowed(location),
        error: Cow::Owned(err.to_string()),
    }
    .emit();
}
