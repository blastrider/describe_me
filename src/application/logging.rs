use tracing::dispatcher;
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initialise le logging :
/// - journald si présent (/run/systemd/journal/socket)
/// - sinon fallback sur stderr (fmt)
pub fn init_logging() {
    if dispatcher::has_been_set() {
        return;
    }

    let filter = EnvFilter::try_from_env("RUST_LOG")
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    #[cfg(feature = "journald")]
    if std::path::Path::new("/run/systemd/journal/socket").exists() {
        // Envoie structuré vers journald
        if let Ok(layer) = tracing_journald::layer() {
            if tracing_subscriber::registry()
                .with(filter.clone())
                .with(layer)
                .try_init()
                .is_ok()
            {
                return;
            }
        }
    }

    // Fallback: stderr lisible (pas d’ANSI forcé)
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_writer(std::io::stderr);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}
