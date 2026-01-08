//! Couche web Axum (pages HTML + SSE) branchée sur l'`AppContext`.
//!
//! - Entrées principales : `serve_http`/`serve_http_with_context` démarrent le serveur
//!   avec un `AppState` qui encapsule le contexte applicatif, la config statique (intervalle,
//!   exposition) et l'état runtime (cache snapshots, updates, shutdown).
//! - Routage : pages HTML (`/`, `/logs`, `/container`, `/updates`), API/SSE (`/sse`,
//!   `/api/*` pour history/logs/containers/description/tags, `/metrics`).
//! - Sécurité : couches `OriginCheckLayer` + `SecurityHeadersLayer` et moteur `WebSecurity`
//!   (token Argon2/bcrypt, affinité, rate limiting, brute force guard, session cookies).
//! - Sous-modules notables : `handlers` (routes), `sse` (stream des snapshots), `state`
//!   (AppState et caches), `auth`, `csp`, `origin`, `security`, `updates_cache`.
//! - Mode web vs CLI : la logique métier reste dans les services applicatifs (collecte,
//!   historique, exposable via `Exposure`) tandis que cette couche ne gère que HTTP/SSE
//!   et les garde-fous liés.

pub mod assets;
mod auth;
mod csp;
mod error;
mod handlers;
mod origin;
mod security;
mod services;
mod sse;
pub mod state;
mod template;
mod tls;
pub mod updates_cache;
mod views;

pub(crate) use csp::SecurityHeadersLayer;
#[allow(unused_imports)]
pub(crate) use error::{json_error, WebError};
pub(crate) use origin::{OriginCheckLayer, OriginPolicy};
pub(crate) use security::WebSecurity;
#[allow(unused_imports)]
pub(crate) use security::{clear_session_cookie, set_session_cookie, SESSION_COOKIE_NAME};
pub(crate) use state::{AppState, LogoAsset, RuntimeState, StaticWebConfig};
use tls::{build_tls_config, serve};

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderMap, HeaderValue},
    routing::{get, post},
    Router,
};
use tokio::sync::{Notify, RwLock};

use crate::application::apply_history_settings;
#[cfg(feature = "config")]
use crate::application::config::runtime::{HistoryConfigExt, WebAccessConfigExt};
use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
#[cfg(feature = "config")]
use crate::application::metadata::override_state_directory;
#[cfg(feature = "config")]
use crate::domain::DescribeConfig;
use crate::domain::{DescribeError, SessionCookieSameSite};

use handlers::{
    containers_api, containers_page, history_series, host_logs, index, logo_asset, logs_page,
    metrics_export, update_description, update_tags, updates_page,
};
use sse::sse_stream;
use updates_cache::UpdatesCache;

pub(crate) const UPDATES_CACHE_SUCCESS_TTL: Duration = Duration::from_secs(300);
const UPDATES_CACHE_FAILURE_RETRY: Duration = Duration::from_secs(60);
pub(crate) const WEB_SESSION_SECONDS: u64 = 7 * 24 * 3600;
const DESCRIPTION_BODY_LIMIT: usize = 8 * 1024;
const TAGS_BODY_LIMIT: usize = 16 * 1024;

#[cfg(feature = "config")]
const LOGO_MAX_BYTES: u64 = 128 * 1024;

type AxumRequest = axum::extract::Request;

#[derive(Debug, Clone)]
pub struct WebAccess {
    /// Hash du jeton d'accès (Argon2id ou bcrypt).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: 192.0.2.10, 10.0.0.0/24, ::1).
    pub allow_ips: Vec<String>,
    /// Origins autorisés (ex: <https://admin.example.com>) pour contourner les proxys terminant TLS.
    pub allow_origins: Vec<String>,
    /// Proxys de confiance dont on accepte l'en-tête X-Forwarded-For.
    pub trusted_proxies: Vec<String>,
    /// Paramètres TLS optionnels.
    pub tls: Option<WebTlsConfig>,
    /// Active l'attribut Secure sur les cookies de session.
    /// Secure est effectif si TLS est local ou si `trusted_proxies` est configuré (TLS terminé par proxy),
    /// sauf override via `dev_insecure_session_cookie`.
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

pub(crate) fn effective_session_cookie_secure(access: &WebAccess, dev_insecure: bool) -> bool {
    if dev_insecure {
        return false;
    }
    access.session_cookie_secure && (access.tls.is_some() || !access.trusted_proxies.is_empty())
}

#[derive(Debug, Clone)]
pub struct WebTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

fn mark_response_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn build_default_web_runtime(
    access: WebAccess,
    exposure: Exposure,
    interval: Duration,
    web_debug: bool,
    session_cookie_secure: bool,
) -> Result<(StaticWebConfig, Arc<WebSecurity>, LogoAsset), DescribeError> {
    let tls_enabled = access.tls.is_some();
    #[cfg(feature = "config")]
    let security = WebSecurity::build(access, None)?;
    #[cfg(not(feature = "config"))]
    let security = WebSecurity::build(access)?;
    let security_arc = Arc::new(security);
    let logo = LogoAsset::default();
    let static_cfg = StaticWebConfig {
        interval,
        #[cfg(feature = "config")]
        config: None,
        web_debug,
        security: security_arc.clone(),
        exposure,
        logo: logo.clone(),
        session_cookie_secure,
        session_cookie_same_site: SessionCookieSameSite::Lax,
        session_ttl: security_arc.session_ttl(),
        updates_refresh_ttl: UPDATES_CACHE_SUCCESS_TTL,
        tls_enabled,
    };
    Ok((static_cfg, security_arc, logo))
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
    #[cfg(feature = "config")]
    if let Some(cfg) = config.as_ref() {
        if let Some(history_cfg) = cfg.history.as_ref() {
            let settings = history_cfg.to_settings();
            apply_history_settings(&ctx, settings)?;
        }
    }
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
    let origin_policy = OriginPolicy::from_access(&access)?;
    let tls_settings = access.tls.clone();
    let session_cookie_secure = effective_session_cookie_secure(&access, false);

    let shutdown = Arc::new(Notify::new());
    #[cfg(feature = "config")]
    if let Some(cfg) = config.as_ref() {
        if let Some(runtime) = cfg.runtime.as_ref() {
            if let Some(dir) = runtime.state_dir.as_deref() {
                override_state_directory(dir);
            }
        }
    }

    #[cfg(feature = "config")]
    let (static_cfg, _security, _logo) = if let Some(cfg) = config.as_ref() {
        if let Some(web_cfg) = cfg.web.as_ref() {
            web_cfg.to_runtime(&ctx, &access, exposure, interval, config.clone(), web_debug)?
        } else {
            build_default_web_runtime(
                access.clone(),
                exposure,
                interval,
                web_debug,
                session_cookie_secure,
            )?
        }
    } else {
        build_default_web_runtime(
            access.clone(),
            exposure,
            interval,
            web_debug,
            session_cookie_secure,
        )?
    };
    #[cfg(not(feature = "config"))]
    let (static_cfg, _security, _logo) = build_default_web_runtime(
        access.clone(),
        exposure,
        interval,
        web_debug,
        session_cookie_secure,
    )?;
    let updates_refresh_ttl = static_cfg.updates_refresh_ttl;
    let runtime = build_runtime_state(shutdown.clone(), updates_refresh_ttl);
    let app_state = AppState::new(Arc::new(ctx), static_cfg, runtime);
    let router = build_router(app_state, origin_policy);

    let bind_addr: SocketAddr = addr.into();
    let interval_secs = interval.as_secs_f64();
    let tls_cfg = build_tls_config(bind_addr, tls_settings.as_ref()).await?;
    serve(router, tls_cfg, interval_secs, shutdown).await?;

    Ok(())
}

fn build_runtime_state(shutdown: Arc<Notify>, updates_refresh_ttl: Duration) -> RuntimeState {
    let updates_cache = UpdatesCache::new(updates_refresh_ttl, UPDATES_CACHE_FAILURE_RETRY);
    let snapshot_cache = Arc::new(RwLock::new(None));
    let snapshot_refresh = Arc::new(tokio::sync::Mutex::new(()));
    let extension_metrics = Arc::new(crate::application::metrics::ExtensionMetricsState::new());

    RuntimeState {
        shutdown,
        updates_cache,
        snapshot_cache,
        snapshot_refresh,
        extension_metrics,
    }
}

fn build_router(app_state: AppState, origin_policy: OriginPolicy) -> Router {
    let cors_allowlist = origin_policy.cors_allowlist();
    Router::new()
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
        .route(
            "/api/description",
            post(update_description).layer(DefaultBodyLimit::max(DESCRIPTION_BODY_LIMIT)),
        )
        .route(
            "/api/tags",
            post(update_tags).layer(DefaultBodyLimit::max(TAGS_BODY_LIMIT)),
        )
        .layer(OriginCheckLayer::new(origin_policy))
        .layer(SecurityHeadersLayer::new(
            app_state.static_cfg.clone(),
            cors_allowlist,
        ))
        .with_state(app_state)
}

#[cfg(test)]
mod tests;
