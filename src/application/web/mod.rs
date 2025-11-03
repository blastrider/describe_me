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
//!       },
//!       describe_me::Exposure::all(),
//!   ).await?;

mod assets;
mod security;
mod sse;
mod template;
mod updates_cache;

use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{Extension, State},
    http::{
        header,
        header::{HeaderName, HeaderValue, ORIGIN},
        HeaderMap, StatusCode, Uri,
    },
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use tokio::sync::Notify;
use tracing::warn;

use crate::application::exposure::Exposure;
use crate::application::logging::LogEvent;
use crate::domain::DescribeError;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, WebSecurityConfig};

use security::{AuthGuard, WebSecurity};
use sse::sse_stream;
use template::{render_index, render_updates_page};
use updates_cache::UpdatesCache;

#[cfg(unix)]
use std::future::pending;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};

pub(crate) const TOKEN_COOKIE_NAME: &str = "describe_me_token";
const TOKEN_COOKIE_MAX_AGE: u32 = 7 * 24 * 3600;
const UPDATES_CACHE_SUCCESS_TTL: Duration = Duration::from_secs(300);
const UPDATES_CACHE_FAILURE_RETRY: Duration = Duration::from_secs(60);

#[cfg(feature = "config")]
fn duration_from_secs_or_default(value: u64, default: Duration) -> Duration {
    if value == 0 {
        default
    } else {
        Duration::from_secs(value)
    }
}

const HEADER_CONTENT_SECURITY_POLICY: HeaderName =
    HeaderName::from_static("content-security-policy");
const HEADER_REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const HEADER_X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const HEADER_CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

type AxumRequest = axum::extract::Request;

#[derive(Debug, Clone, Default)]
pub struct WebAccess {
    /// Hash du jeton d'accès (Argon2id ou bcrypt).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: 192.0.2.10, 10.0.0.0/24, ::1).
    pub allow_ips: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    interval: Duration,
    #[cfg(feature = "config")]
    config: Option<DescribeConfig>,
    web_debug: bool,
    security: Arc<WebSecurity>,
    exposure: Exposure,
    shutdown: Arc<Notify>,
    updates_cache: UpdatesCache,
}

#[derive(Clone)]
struct CspNonce(Arc<str>);

impl CspNonce {
    fn new(value: String) -> Self {
        Self(Arc::<str>::from(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

async fn http_security_layer(mut req: AxumRequest, next: Next) -> Response {
    let nonce_value = generate_csp_nonce();
    let csp_nonce = CspNonce::new(nonce_value);

    if !is_origin_allowed(&req) {
        let mut response = (
            StatusCode::FORBIDDEN,
            "Requête bloquée par la politique CORS (origin non autorisée).",
        )
            .into_response();
        apply_security_headers(response.headers_mut(), &csp_nonce);
        return response;
    }

    req.extensions_mut().insert(csp_nonce.clone());

    let mut response = next.run(req).await;
    apply_security_headers(response.headers_mut(), &csp_nonce);
    response
}

fn generate_csp_nonce() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut nonce = String::with_capacity(32);
    for _ in 0..32 {
        let idx = fastrand::usize(..CHARSET.len());
        nonce.push(CHARSET[idx] as char);
    }
    nonce
}

fn apply_security_headers(headers: &mut HeaderMap, nonce: &CspNonce) {
    let csp_value = format!(
        "default-src 'none'; connect-src 'self'; img-src 'self'; font-src 'self'; \
         style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'; object-src 'none'",
        nonce = nonce.as_str()
    );

    if let Ok(value) = HeaderValue::from_str(&csp_value) {
        headers.insert(HEADER_CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(
        HEADER_REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(HEADER_X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HEADER_X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_RESOURCE_POLICY,
        HeaderValue::from_static("same-origin"),
    );
}

fn is_origin_allowed(req: &AxumRequest) -> bool {
    let origin = match req.headers().get(ORIGIN) {
        Some(origin) => origin,
        None => return true,
    };

    let host_header = match req.headers().get(header::HOST) {
        Some(host) => host,
        None => return false,
    };

    let origin_str = match origin.to_str() {
        Ok(value) => value,
        Err(_) => return false,
    };

    if origin_str.eq_ignore_ascii_case("null") {
        return false;
    }

    let host_str = match host_header.to_str() {
        Ok(value) => value,
        Err(_) => return false,
    };

    let origin_uri: Uri = match origin_str.parse() {
        Ok(uri) => uri,
        Err(_) => return false,
    };

    let host_authority: axum::http::uri::Authority = match host_str.parse() {
        Ok(authority) => authority,
        Err(_) => return false,
    };

    let origin_host = match origin_uri.host() {
        Some(host) => host,
        None => return false,
    };

    if !origin_host.eq_ignore_ascii_case(host_authority.host()) {
        return false;
    }

    let origin_port = origin_uri
        .port_u16()
        .or_else(|| default_port(origin_uri.scheme_str()));
    let host_port = host_authority
        .port_u16()
        .or_else(|| default_port(origin_uri.scheme_str()));

    origin_port == host_port
}

fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}

pub async fn serve_http<A: Into<SocketAddr>>(
    addr: A,
    interval: Duration,
    #[cfg(feature = "config")] config: Option<DescribeConfig>,
    web_debug: bool,
    access: WebAccess,
    exposure: Exposure,
) -> Result<(), DescribeError> {
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

    let app_state = AppState {
        interval,
        #[cfg(feature = "config")]
        config,
        web_debug,
        security: security.clone(),
        exposure,
        shutdown: shutdown_for_state,
        updates_cache,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/updates", get(updates_page))
        .route("/sse", get(sse_stream))
        .layer(middleware::from_fn(http_security_layer))
        .with_state(app_state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let bind_addr: SocketAddr = addr.into();
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
    let bind_addr = listener.local_addr().unwrap_or(bind_addr);
    let interval_secs = interval.as_secs_f64();
    LogEvent::HttpServerStarted {
        addr: Cow::Owned(bind_addr.to_string()),
        interval_s: interval_secs,
    }
    .emit();

    let shutdown = async move {
        let signal = wait_for_shutdown_signal().await;
        LogEvent::HttpServerShutdown {
            signal: Cow::Owned(signal.to_string()),
        }
        .emit();
        shutdown_for_task.notify_waiters();
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(map_io)?;

    Ok(())
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

async fn index(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let mut response = Html(render_index(state.web_debug, csp_nonce.as_str())).into_response();
    if let Some(token) = session.provided_token() {
        set_token_cookie(response.headers_mut(), token);
    }
    response
}

async fn updates_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let cookie_token = session.provided_token().map(str::to_owned);

    if !state.exposure.updates() {
        let message = "L'exposition des mises à jour est désactivée pour cette instance.";
        let html = render_updates_page(None, Some(message), csp_nonce.as_str());
        let mut response = Html(html).into_response();
        if let Some(token) = cookie_token.as_deref() {
            set_token_cookie(response.headers_mut(), token);
        }
        return response;
    }

    state.updates_cache.ensure_fresh().await;
    let updates = match state.updates_cache.peek().await {
        Some(info) => Some(info),
        None => state.updates_cache.refresh_blocking().await,
    };

    let html = render_updates_page(updates.as_ref(), None, csp_nonce.as_str());
    let mut response = Html(html).into_response();
    if let Some(token) = cookie_token.as_deref() {
        set_token_cookie(response.headers_mut(), token);
    }
    response
}

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}

pub(super) fn set_token_cookie(headers: &mut HeaderMap, token: &str) {
    if token.is_empty() {
        return;
    }
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded = utf8_percent_encode(token, NON_ALPHANUMERIC).to_string();
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict",
        name = TOKEN_COOKIE_NAME,
        value = encoded,
        max_age = TOKEN_COOKIE_MAX_AGE
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(crate) fn clear_token_cookie(headers: &mut HeaderMap) {
    let cookie = format!(
        "{name}=deleted; Path=/; Max-Age=0; SameSite=Strict",
        name = TOKEN_COOKIE_NAME
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}
