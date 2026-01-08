//! Logging helpers for the `describe_me` application layer.
//!
//! This module exposes [`init_logging`] to configure `tracing` and the
//! [`LogEvent`] enum which centralises every structured log the CLI emits.
//! Developers should prefer constructing a [`LogEvent`] variant and calling
//! [`LogEvent::emit`] instead of using raw `info!`/`error!` macros. Doing so
//! keeps field names consistent (critical for journald), makes the log
//! catalogue discoverable, and simplifies future additions. See
//! `docs/logging.md` for usage guidelines and examples.

use crate::application::history::HistoryMode;
use crate::domain::HistoryProfile;
use std::borrow::Cow;
use tracing::dispatcher;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initialise le logging :
/// - journald si présent (/run/systemd/journal/socket)
/// - sinon fallback sur stderr (fmt)
pub fn init_logging() {
    if dispatcher::has_been_set() {
        return;
    }

    #[allow(unused_variables)]
    let log_to_stderr = std::env::var_os("DESCRIBE_ME_LOG_STDERR").is_some()
        || std::env::var_os("DESCRIBE_ME_CONTAINER").is_some();

    let filter = EnvFilter::try_from_env("RUST_LOG")
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    #[cfg(feature = "journald")]
    let filter = match try_init_journald(filter, log_to_stderr) {
        Some(filter) => filter,
        None => return,
    };

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

#[cfg(feature = "journald")]
fn try_init_journald(filter: EnvFilter, log_to_stderr: bool) -> Option<EnvFilter> {
    if !std::path::Path::new("/run/systemd/journal/socket").exists() {
        return Some(filter);
    }

    let Ok(layer) = tracing_journald::layer() else {
        return Some(filter);
    };

    if log_to_stderr {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_writer(std::io::stderr);

        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .with(fmt_layer)
            .try_init();
        return None;
    }

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
    None
}

/// Énumération centralisée des événements de log applicatifs.
pub enum LogEvent<'a> {
    Startup {
        mode: Cow<'a, str>,
        with_services: bool,
        with_containers: bool,
        net_listen: bool,
        net_traffic: bool,
        expose_all: bool,
        web_expose_all: bool,
        checks: &'a [String],
    },
    HttpServerStarted {
        addr: Cow<'a, str>,
        interval_s: f64,
        tls: bool,
    },
    HttpServerShutdown {
        signal: Cow<'a, str>,
    },
    HttpBindFailed {
        addr: Cow<'a, str>,
        error: Cow<'a, str>,
    },
    SystemError {
        location: Cow<'a, str>,
        error: Cow<'a, str>,
    },
    ConfigError {
        path: Cow<'a, str>,
        error: Cow<'a, str>,
    },
    MetadataStoreRetryFailed {
        error: Cow<'a, str>,
    },
    MetadataStoreUpgraded {
        migrated_description: bool,
        migrated_tags: bool,
    },
    SseStreamOpen {
        ip: Cow<'a, str>,
        token: Cow<'a, str>,
        min_interval_ms: u64,
        max_payload: usize,
        max_stream_s: u64,
        max_stream_bytes: usize,
    },
    SseStreamClosed {
        ip: Cow<'a, str>,
        token: Cow<'a, str>,
        events: u64,
        duration_s: f64,
        reason: Cow<'a, str>,
        bytes: u64,
    },
    SseTick {
        payload_bytes: usize,
        services_count: Option<usize>,
        partitions: Option<usize>,
    },
    SsePayloadOversize {
        size: usize,
        limit: usize,
    },
    AuthOk {
        ip: Cow<'a, str>,
        route: Cow<'a, str>,
    },
    SecurityIncident {
        category: Cow<'a, str>,
        route: Cow<'a, str>,
        request_path: Option<Cow<'a, str>>,
        ip: Option<Cow<'a, str>>,
        token: Option<Cow<'a, str>>,
        detail: Option<Cow<'a, str>>,
    },
    PluginError {
        plugin: Cow<'a, str>,
        command: Cow<'a, str>,
        error: Cow<'a, str>,
    },
    HistoryQuery {
        ip: Cow<'a, str>,
        token: Cow<'a, str>,
        server: Cow<'a, str>,
        points: u32,
        window_seconds: u64,
        truncated: bool,
    },
    HistoryConfig {
        enabled: bool,
        profile: HistoryProfile,
        mode: HistoryMode,
        retention_points: u32,
        max_window_seconds: u32,
        rounding_seconds: u64,
        paranoid: bool,
    },
}

impl LogEvent<'_> {
    pub fn emit(self) {
        match self {
            LogEvent::Startup {
                mode,
                with_services,
                with_containers,
                net_listen,
                net_traffic,
                expose_all,
                web_expose_all,
                checks,
            } => {
                info!(
                    mode = mode.as_ref(),
                    with_services,
                    with_containers,
                    net_listen,
                    net_traffic,
                    expose_all,
                    web_expose_all,
                    checks = ?checks,
                    "startup mode={} with_services={} with_containers={} net_listen={} net_traffic={} expose_all={} web_expose_all={} checks={:?}",
                    mode,
                    with_services,
                    with_containers,
                    net_listen,
                    net_traffic,
                    expose_all,
                    web_expose_all,
                    checks
                );
            }
            LogEvent::HttpServerStarted {
                addr,
                interval_s,
                tls,
            } => {
                info!(
                    addr = addr.as_ref(),
                    interval_s,
                    tls,
                    "http_server_started addr={} interval_s={} tls={}",
                    addr,
                    interval_s,
                    tls
                );
            }
            LogEvent::HttpServerShutdown { signal } => {
                info!(
                    signal = signal.as_ref(),
                    "http_server_shutdown signal={}", signal
                );
            }
            LogEvent::HttpBindFailed { addr, error } => {
                error!(
                    addr = addr.as_ref(),
                    error = error.as_ref(),
                    msg = error.as_ref(),
                    "http_bind_failed addr={} error={}",
                    addr,
                    error
                );
            }
            LogEvent::SystemError { location, error } => {
                error!(
                    r#where = location.as_ref(),
                    error = error.as_ref(),
                    "system_error where={} error={}",
                    location,
                    error
                );
            }
            LogEvent::ConfigError { path, error } => {
                error!(
                    path = path.as_ref(),
                    error = error.as_ref(),
                    "config_error path={} error={}",
                    path,
                    error
                );
            }
            LogEvent::MetadataStoreRetryFailed { error } => {
                warn!(
                    error = error.as_ref(),
                    "metadata_store_retry_failed error={}", error
                );
            }
            LogEvent::MetadataStoreUpgraded {
                migrated_description,
                migrated_tags,
            } => {
                info!(
                    migrated_description,
                    migrated_tags,
                    "metadata_store_upgraded migrated_description={} migrated_tags={}",
                    migrated_description,
                    migrated_tags
                );
            }
            LogEvent::SseStreamOpen {
                ip,
                token,
                min_interval_ms,
                max_payload,
                max_stream_s,
                max_stream_bytes,
            } => {
                info!(
                    ip = ip.as_ref(),
                    token = token.as_ref(),
                    min_interval_ms,
                    max_payload,
                    max_stream_s,
                    max_stream_bytes,
                    "sse_stream_open ip={} token={} min_interval_ms={} max_payload={} max_stream_s={} max_stream_bytes={}",
                    ip,
                    token,
                    min_interval_ms,
                    max_payload,
                    max_stream_s,
                    max_stream_bytes
                );
            }
            LogEvent::SseStreamClosed {
                ip,
                token,
                events,
                duration_s,
                reason,
                bytes,
            } => {
                info!(
                    ip = ip.as_ref(),
                    token = token.as_ref(),
                    events,
                    duration_s,
                    reason = reason.as_ref(),
                    bytes,
                    "sse_stream_closed ip={} token={} events={} duration_s={} reason={} bytes={}",
                    ip,
                    token,
                    events,
                    duration_s,
                    reason,
                    bytes
                );
            }
            LogEvent::SseTick {
                payload_bytes,
                services_count,
                partitions,
            } => {
                debug!(
                    payload_bytes,
                    services_count = ?services_count,
                    partitions = ?partitions,
                    "sse_tick payload_bytes={} services_count={:?} partitions={:?}",
                    payload_bytes,
                    services_count,
                    partitions
                );
            }
            LogEvent::SsePayloadOversize { size, limit } => {
                warn!(
                    size,
                    limit, "sse_payload_oversize size={} limit={}", size, limit
                );
            }
            LogEvent::AuthOk { ip, route } => {
                trace!(
                    ip = ip.as_ref(),
                    route = route.as_ref(),
                    "auth_ok ip={} route={}",
                    ip,
                    route
                );
            }
            LogEvent::SecurityIncident {
                category,
                route,
                request_path,
                ip,
                token,
                detail,
            } => {
                warn!(
                    category = category.as_ref(),
                    route = route.as_ref(),
                    request_path = request_path.as_ref().map(|s| s.as_ref()),
                    ip = ip.as_ref().map(|s| s.as_ref()),
                    token = token.as_ref().map(|s| s.as_ref()),
                    detail = detail.as_ref().map(|s| s.as_ref()),
                    "security_incident category={} route={} request_path={:?} ip={:?} token={:?} detail={:?}",
                    category,
                    route,
                    request_path,
                    ip,
                    token,
                    detail
                );
            }
            LogEvent::PluginError {
                plugin,
                command,
                error,
            } => {
                warn!(
                    plugin = plugin.as_ref(),
                    command = command.as_ref(),
                    error = error.as_ref(),
                    "plugin_error plugin={} command={} error={}",
                    plugin,
                    command,
                    error
                );
            }
            LogEvent::HistoryQuery {
                ip,
                token,
                server,
                points,
                window_seconds,
                truncated,
            } => {
                info!(
                    ip = ip.as_ref(),
                    token = token.as_ref(),
                    server = server.as_ref(),
                    points,
                    window_seconds,
                    truncated,
                    "history_query ip={} token={} server={} points={} window_seconds={} truncated={}",
                    ip,
                    token,
                    server,
                    points,
                    window_seconds,
                    truncated
                );
            }
            LogEvent::HistoryConfig {
                enabled,
                profile,
                mode,
                retention_points,
                max_window_seconds,
                rounding_seconds,
                paranoid,
            } => {
                info!(
                    enabled,
                    profile = ?profile,
                    mode = ?mode,
                    retention_points,
                    max_window_seconds,
                    rounding_seconds,
                    paranoid,
                    "history_config enabled={} profile={:?} mode={:?} retention_points={} max_window_seconds={} rounding_seconds={} paranoid={}",
                    enabled,
                    profile,
                    mode,
                    retention_points,
                    max_window_seconds,
                    rounding_seconds,
                    paranoid
                );
            }
        }
    }
}
