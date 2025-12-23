use crate::{
    application::context::AppContext,
    application::logging::LogEvent,
    domain::{CaptureOptions, DescribeError, SystemSnapshot},
};
use std::{borrow::Cow, fmt::Display};

/// Collecteur participant à la construction d'un [`SystemSnapshot`].
///
/// Contrat :
/// - ne doit jamais paniquer ;
/// - journalise ses erreurs via [`log_system_error`] afin de ne pas perdre de signal ;
/// - ne bloque pas indéfiniment (échoue proprement plutôt que de figer la capture) ;
/// - n'écrase pas les parties du snapshot qu'il ne gère pas explicitement.
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

/// Helper centralisé pour loguer une erreur de collecte sans faire échouer la capture globale.
pub(crate) fn log_system_error(location: &'static str, err: &(impl Display + ?Sized)) {
    LogEvent::SystemError {
        location: Cow::Borrowed(location),
        error: Cow::Owned(err.to_string()),
    }
    .emit();
}

#[cfg(all(test, any(feature = "net", feature = "systemd")))]
pub(crate) mod tests_common;
