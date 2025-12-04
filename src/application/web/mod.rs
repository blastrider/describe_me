//! Module web: sert une page HTML avec mise à jour temps réel via SSE.
//!
//! Endpoints :
//!   GET /         -> page HTML (CSS + JS vanilla)
//!   GET /sse      -> flux SSE (JSON) envoyant SystemSnapshot périodiquement
//!
//! Usage (ex. depuis un binaire) :
//!   describe_me::serve_http(
//!       ([0,0,0,0], 8080),
//!       std::time::Duration::from_secs(2),
//!       #[cfg(feature = "config")]
//!       None,
//!       false,
//!       describe_me::WebAccess {
//!           token: Some("$argon2id$v=19$m=19456,t=2,p=1$MFDNn+4xkNMOFXaKzJLXmw$8cHenB/55bhNt1vZoGILR6F0yaEtKrnArXwdQhU8cBA".into()),
//!           allow_ips: vec!["127.0.0.1".into()],
//!           allow_origins: vec![],
//!           trusted_proxies: vec![],
//!       },
//!       describe_me::Exposure::all(),
//!   ).await?;

mod assets;
mod auth;
mod csp;
mod handlers;
mod origin;
mod security;
mod sse;
mod state;
mod template;
mod updates_cache;
mod views;

pub(crate) use csp::SecurityHeadersLayer;
pub(crate) use origin::{OriginCheckLayer, OriginPolicy};
pub(crate) use state::{AppState, LogoAsset, RuntimeState, StaticWebConfig};

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    http::{header, HeaderMap, HeaderValue},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::Notify;
use tracing::warn;

use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
use crate::application::logging::LogEvent;
#[cfg(feature = "config")]
use crate::application::metadata::override_state_directory;
use crate::domain::DescribeError;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, WebSecurityConfig};

use handlers::{
    containers_api, containers_page, history_series, host_logs, index, logo_asset, logs_page,
    metrics_export, update_description, update_tags, updates_page,
};
use security::WebSecurity;
use sse::sse_stream;
use updates_cache::UpdatesCache;

#[cfg(unix)]
use std::future::pending;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};

pub(crate) use auth::{clear_session_cookie, set_session_cookie, SESSION_COOKIE_NAME};
const UPDATES_CACHE_SUCCESS_TTL: Duration = Duration::from_secs(300);
const UPDATES_CACHE_FAILURE_RETRY: Duration = Duration::from_secs(60);
const DESCRIPTION_MAX_BYTES: usize = 2048;
const TAGS_MAX_PER_REQUEST: usize = 64;
const TAG_LENGTH_LIMIT: usize = 48;
pub(crate) const WEB_SESSION_SECONDS: u64 = 7 * 24 * 3600;

#[cfg(feature = "config")]
const LOGO_MAX_BYTES: u64 = 128 * 1024;

#[cfg(feature = "config")]
fn duration_from_secs_or_default(value: u64, default: Duration) -> Duration {
    if value == 0 {
        default
    } else {
        Duration::from_secs(value)
    }
}

type AxumRequest = axum::extract::Request;

#[derive(Debug, Clone)]
pub struct WebAccess {
    /// Hash du jeton d'accès (Argon2id ou bcrypt).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: 192.0.2.10, 10.0.0.0/24, ::1).
    pub allow_ips: Vec<String>,
    /// Origins autorisés (ex: https://admin.example.com) pour contourner les proxys terminant TLS.
    pub allow_origins: Vec<String>,
    /// Proxys de confiance dont on accepte l'en-tête X-Forwarded-For.
    pub trusted_proxies: Vec<String>,
    /// Paramètres TLS optionnels.
    pub tls: Option<WebTlsConfig>,
    /// Force l'attribut Secure sur les cookies de session (désactivable en dev HTTP).
    pub session_cookie_secure: bool,
}

impl Default for WebAccess {
    fn default() -> Self {
        Self {
            token: None,
            allow_ips: Vec::new(),
            allow_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            tls: None,
            session_cookie_secure: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

fn mark_response_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

pub async fn serve_http<A: Into<SocketAddr>>(
    addr: A,
    interval: Duration,
    #[cfg(feature = "config")] config: Option<DescribeConfig>,
    web_debug: bool,
    access: WebAccess,
    exposure: Exposure,
) -> Result<(), DescribeError> {
    let ctx = AppContext::new_default()?;
    serve_http_with_context(
        addr,
        interval,
        #[cfg(feature = "config")]
        config,
        web_debug,
        access,
        exposure,
        ctx,
    )
    .await
}

pub async fn serve_http_with_context<A: Into<SocketAddr>>(
    addr: A,
    interval: Duration,
    #[cfg(feature = "config")] config: Option<DescribeConfig>,
    web_debug: bool,
    access: WebAccess,
    exposure: Exposure,
    ctx: AppContext,
) -> Result<(), DescribeError> {
    let origin_policy = OriginPolicy::from_allowlist(access.allow_origins.clone())?;
    let tls_settings = access.tls.clone();
    let session_cookie_secure = access.session_cookie_secure && tls_settings.is_some();
    #[cfg(feature = "config")]
    let security_config: Option<WebSecurityConfig> = config
        .as_ref()
        .and_then(|cfg| cfg.web.as_ref())
        .and_then(|web| web.security.clone());

    let security = Arc::new(WebSecurity::build(
        access,
        #[cfg(feature = "config")]
        security_config,
    )?);

    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_for_state = shutdown_notify.clone();
    let shutdown_for_task = shutdown_notify.clone();
    #[cfg(feature = "config")]
    let updates_refresh_ttl = config
        .as_ref()
        .and_then(|cfg| cfg.web.as_ref())
        .and_then(|web| web.updates_refresh_seconds)
        .map(|secs| duration_from_secs_or_default(secs, UPDATES_CACHE_SUCCESS_TTL))
        .unwrap_or(UPDATES_CACHE_SUCCESS_TTL);
    #[cfg(not(feature = "config"))]
    let updates_refresh_ttl = UPDATES_CACHE_SUCCESS_TTL;
    let updates_cache = UpdatesCache::new(updates_refresh_ttl, UPDATES_CACHE_FAILURE_RETRY);
    let snapshot_cache = Arc::new(RwLock::new(None));

    #[cfg(feature = "config")]
    if let Some(cfg) = config.as_ref() {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(dir) = runtime.state_dir.as_deref() {
                override_state_directory(dir);
            }
        }
    }

    #[cfg(feature = "config")]
    let logo = LogoAsset::from_optional_path(
        config
            .as_ref()
            .and_then(|cfg| cfg.web.as_ref())
            .and_then(|web| web.logo_path.as_deref()),
    )?;
    #[cfg(not(feature = "config"))]
    let logo = LogoAsset::default();

    let static_cfg = StaticWebConfig {
        interval,
        #[cfg(feature = "config")]
        config,
        web_debug,
        security: security.clone(),
        exposure,
        logo,
        session_cookie_secure,
        session_ttl: security.session_ttl(),
    };

    let runtime = RuntimeState {
        shutdown: shutdown_for_state,
        updates_cache,
        snapshot_cache: snapshot_cache.clone(),
    };

    let app_state = AppState::new(Arc::new(ctx), static_cfg, runtime);

    let router = Router::new()
        .route("/", get(index))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/assets/logo.svg", get(logo_asset))
        .route("/updates", get(updates_page))
        .route("/container", get(containers_page))
        .route("/logs", get(logs_page))
        .route("/sse", get(sse_stream))
        .route("/metrics", get(metrics_export))
        .route("/api/containers", get(containers_api))
        .route("/api/history", get(history_series))
        .route("/api/logs", get(host_logs))
        .route("/api/description", post(update_description))
        .route("/api/tags", post(update_tags))
        .layer(OriginCheckLayer::new(origin_policy))
        .layer(SecurityHeadersLayer::new())
        .with_state(app_state);

    let bind_addr: SocketAddr = addr.into();
    let interval_secs = interval.as_secs_f64();

    if let Some(tls) = tls_settings {
        let rustls = build_rustls_config(&tls).await?;
        LogEvent::HttpServerStarted {
            addr: Cow::Owned(format!("https://{}", bind_addr)),
            interval_s: interval_secs,
            tls: true,
        }
        .emit();
        let handle = axum_server::Handle::new();
        let notify = shutdown_for_task.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_task = tokio::spawn({
            let handle = handle.clone();
            async move {
                tokio::select! {
                    _ = wait_for_shutdown(notify) => {
                        handle.shutdown();
                    }
                    _ = shutdown_rx => {}
                }
            }
        });
        let result = axum_server::bind_rustls(bind_addr, rustls)
            .handle(handle)
            .serve(
                router
                    .clone()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        let _ = shutdown_tx.send(());
        let _ = shutdown_task.await;
        result.map_err(map_io)?;
    } else {
        let listener = match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(l) => l,
            Err(err) => {
                let msg = err.to_string();
                LogEvent::HttpBindFailed {
                    addr: Cow::Owned(bind_addr.to_string()),
                    error: Cow::Owned(msg),
                }
                .emit();
                return Err(map_io(err));
            }
        };
        let actual = listener.local_addr().unwrap_or(bind_addr);
        LogEvent::HttpServerStarted {
            addr: Cow::Owned(format!("http://{}", actual)),
            interval_s: interval_secs,
            tls: false,
        }
        .emit();
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown_for_task.clone()))
        .await
        .map_err(map_io)?;
    }

    Ok(())
}

async fn wait_for_shutdown(notify: Arc<Notify>) {
    let signal = wait_for_shutdown_signal().await;
    LogEvent::HttpServerShutdown {
        signal: Cow::Owned(signal.to_string()),
    }
    .emit();
    notify.notify_waiters();
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> &'static str {
    let mut sigterm = unix_signal(SignalKind::terminate()).ok();
    let mut sighup = unix_signal(SignalKind::hangup()).ok();

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            match res {
                Ok(()) => "ctrl_c",
                Err(err) => {
                    warn!(error = ?err, "ctrl_c_wait_failed");
                    "ctrl_c_error"
                }
            }
        }
        _ = async {
            if let Some(signal) = sigterm.as_mut() {
                signal.recv().await;
            } else {
                pending::<()>().await;
            }
        } => "sigterm",
        _ = async {
            if let Some(signal) = sighup.as_mut() {
                signal.recv().await;
            } else {
                pending::<()>().await;
            }
        } => "sighup",
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> &'static str {
    match tokio::signal::ctrl_c().await {
        Ok(()) => "ctrl_c",
        Err(err) => {
            warn!(error = ?err, "ctrl_c_wait_failed");
            "ctrl_c_error"
        }
    }
}

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}

async fn build_rustls_config(cfg: &WebTlsConfig) -> Result<RustlsConfig, DescribeError> {
    let cert = cfg.cert_path.trim();
    let key = cfg.key_path.trim();
    if cert.is_empty() || key.is_empty() {
        return Err(DescribeError::Config(
            "web.tls nécessite cert_path et key_path".into(),
        ));
    }
    RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|err| DescribeError::Config(format!("chargement TLS {cert}/{key}: {err}")))
}

#[cfg(test)]
mod tests;
