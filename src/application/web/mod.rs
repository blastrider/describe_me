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
//!           token: Some("super-secret".into()),
//!           allow_ips: vec!["127.0.0.1".into()],
//!       },
//!       describe_me::Exposure::all(),
//!   ).await?;

mod assets;
mod security;
mod sse;
mod template;

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

use crate::application::capture_snapshot_with_view;
use crate::application::exposure::Exposure;
use crate::application::logging::LogEvent;
use crate::domain::CaptureOptions;
use crate::domain::DescribeError;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, WebSecurityConfig};

use security::{AuthGuard, WebSecurity};
use sse::sse_stream;
use template::{render_index, render_updates_page};

#[cfg(unix)]
use std::future::pending;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};

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
    /// Jeton d'accès (Authorization: Bearer ou en-tête `x-describe-me-token`).
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

    let app_state = AppState {
        interval,
        #[cfg(feature = "config")]
        config,
        web_debug,
        security: security.clone(),
        exposure,
        shutdown: shutdown_for_state,
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
    _guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    Html(render_index(state.web_debug, csp_nonce.as_str()))
}

async fn updates_page(
    State(state): State<AppState>,
    _guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    if !state.exposure.updates() {
        let message = "L'exposition des mises à jour est désactivée pour cette instance.";
        let html = render_updates_page(None, Some(message), csp_nonce.as_str());
        return Html(html).into_response();
    }

    let capture_opts = CaptureOptions {
        with_services: false,
        with_disk_usage: false,
        with_listening_sockets: false,
        with_network_traffic: false,
    };

    #[cfg(feature = "config")]
    let config = state.config.as_ref();

    match capture_snapshot_with_view(
        capture_opts,
        state.exposure,
        #[cfg(feature = "config")]
        config,
    ) {
        Ok((_snapshot, view)) => {
            let updates = view.updates;
            let html = render_updates_page(updates.as_ref(), None, csp_nonce.as_str());
            Html(html).into_response()
        }
        Err(err) => {
            let message = format!("Erreur lors de la collecte: {err}");
            let html = render_updates_page(None, Some(&message), csp_nonce.as_str());
            (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
        }
    }
}

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}
