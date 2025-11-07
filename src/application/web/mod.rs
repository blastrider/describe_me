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
mod security;
mod sse;
mod template;
mod updates_cache;

use std::{borrow::Cow, collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
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

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};

pub(crate) const TOKEN_COOKIE_NAME: &str = "describe_me_token";
const TOKEN_COOKIE_MAX_AGE: u32 = 7 * 24 * 3600;
const UPDATES_CACHE_SUCCESS_TTL: Duration = Duration::from_secs(300);
const UPDATES_CACHE_FAILURE_RETRY: Duration = Duration::from_secs(60);

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

const HEADER_CONTENT_SECURITY_POLICY: HeaderName =
    HeaderName::from_static("content-security-policy");
const HEADER_REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const HEADER_X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const HEADER_CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");
const HEADER_PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const HEADER_STRICT_TRANSPORT_SECURITY: HeaderName =
    HeaderName::from_static("strict-transport-security");
const HEADER_CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const HEADER_CROSS_ORIGIN_EMBEDDER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-embedder-policy");

type AxumRequest = axum::extract::Request;

#[derive(Debug, Clone, Default)]
pub struct WebAccess {
    /// Hash du jeton d'accès (Argon2id ou bcrypt).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: 192.0.2.10, 10.0.0.0/24, ::1).
    pub allow_ips: Vec<String>,
    /// Origins autorisés (ex: https://admin.example.com) pour contourner les proxys terminant TLS.
    pub allow_origins: Vec<String>,
    /// Proxys de confiance dont on accepte l'en-tête X-Forwarded-For.
    pub trusted_proxies: Vec<String>,
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
    logo: LogoAsset,
}

#[derive(Clone)]
struct LogoAsset {
    bytes: Bytes,
}

impl LogoAsset {
    fn default() -> Self {
        Self {
            bytes: Bytes::from_static(assets::LOGO_SVG),
        }
    }

    fn response(&self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            )
            .body(Body::from(self.bytes.clone()))
            .expect("logo response")
    }

    #[cfg(feature = "config")]
    fn from_optional_path(path: Option<&str>) -> Result<Self, DescribeError> {
        match path {
            Some(raw) => Self::from_path(raw),
            None => Ok(Self::default()),
        }
    }

    #[cfg(feature = "config")]
    fn from_path(raw: &str) -> Result<Self, DescribeError> {
        use std::fs;
        use std::path::Path;

        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" doit être un chemin absolu",
                path.display()
            )));
        }

        let canonical = fs::canonicalize(path).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", path.display()))
        })?;
        let metadata = fs::metadata(&canonical).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", canonical.display()))
        })?;
        if !metadata.is_file() {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" n'est pas un fichier",
                canonical.display()
            )));
        }
        if metadata.len() > LOGO_MAX_BYTES {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" dépasse la limite de {LOGO_MAX_BYTES} octets",
                canonical.display()
            )));
        }

        let data = fs::read(&canonical).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", canonical.display()))
        })?;

        validate_logo_bytes(&data).map_err(|reason| {
            DescribeError::Config(format!(
                "web.logo_path \"{}\" invalide: {reason}",
                canonical.display()
            ))
        })?;

        Ok(Self {
            bytes: Bytes::from(data),
        })
    }
}

#[cfg(feature = "config")]
fn validate_logo_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("le fichier est vide".into());
    }
    if (bytes.len() as u64) > LOGO_MAX_BYTES {
        return Err(format!(
            "le fichier dépasse la limite de {LOGO_MAX_BYTES} octets"
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "le logo doit être un SVG encodé en UTF-8".to_string())?;
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") {
        return Err("balise <svg> introuvable".into());
    }
    if lower.contains("<script") {
        return Err("les balises <script> sont interdites".into());
    }
    for attr in ["onload", "onerror", "onclick", "onfocus", "onmouseover"] {
        if lower.contains(&format!("{attr}=")) {
            return Err(format!("l'attribut {attr}= est interdit"));
        }
    }
    if lower.contains("javascript:") {
        return Err("les URLs javascript: sont interdites".into());
    }
    Ok(())
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

async fn http_security_layer(
    State(origin_policy): State<OriginPolicy>,
    mut req: AxumRequest,
    next: Next,
) -> Response {
    let nonce_value = generate_csp_nonce();
    let csp_nonce = CspNonce::new(nonce_value);

    if !is_origin_allowed(&req, &origin_policy) {
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
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone, Debug, Default)]
struct OriginPolicy {
    allowed: Arc<[AllowedOrigin]>,
}

impl OriginPolicy {
    fn from_allowlist(raw: Vec<String>) -> Result<Self, DescribeError> {
        if raw.is_empty() {
            return Ok(Self::default());
        }
        let mut seen = HashSet::new();
        let mut allow = Vec::with_capacity(raw.len());
        for value in raw {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }
            let origin = AllowedOrigin::parse(trimmed)
                .map_err(|err| DescribeError::Config(format!("origin \"{trimmed}\": {err}")))?;
            if seen.insert(origin.clone()) {
                allow.push(origin);
            }
        }
        Ok(Self {
            allowed: allow.into(),
        })
    }

    fn allows(&self, req: &AxumRequest) -> bool {
        let origin_header = match req.headers().get(ORIGIN) {
            Some(origin) => origin,
            None => return true,
        };
        let origin_str = match origin_header.to_str() {
            Ok(value) => value,
            Err(_) => return false,
        };
        if origin_str.eq_ignore_ascii_case("null") {
            return false;
        }
        let origin_uri: Uri = match origin_str.parse() {
            Ok(uri) => uri,
            Err(_) => return false,
        };

        if !self.allowed.is_empty() {
            return self
                .allowed
                .iter()
                .any(|allowed| allowed.matches(&origin_uri));
        }

        let host_header = match req.headers().get(header::HOST) {
            Some(host) => host,
            None => return false,
        };
        let host_str = match host_header.to_str() {
            Ok(value) => value,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AllowedOrigin {
    scheme: OriginScheme,
    host: String,
    port: Option<u16>,
}

impl AllowedOrigin {
    fn parse(input: &str) -> Result<Self, String> {
        let uri: Uri = input.parse::<Uri>().map_err(|err| err.to_string())?;
        let scheme = match uri.scheme_str() {
            Some(value) => OriginScheme::parse(value)
                .ok_or_else(|| format!("schéma non supporté: {value} (attendu http ou https)"))?,
            None => {
                return Err("origin incomplet: schéma requis (http ou https)".into());
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| "origin incomplet: hôte requis".to_string())?
            .to_owned();
        let port = uri.port_u16();
        if uri.path() != "/" && !uri.path().is_empty() {
            return Err("origin ne doit pas contenir de chemin".into());
        }
        if uri.query().is_some() {
            return Err("origin ne doit pas contenir de query string".into());
        }
        Ok(Self { scheme, host, port })
    }

    fn matches(&self, candidate: &Uri) -> bool {
        let Some(host) = candidate.host() else {
            return false;
        };
        if !host.eq_ignore_ascii_case(&self.host) {
            return false;
        }
        match candidate.scheme_str() {
            Some(value) if self.scheme.matches(value) => {}
            _ => return false,
        }
        let candidate_port = candidate
            .port_u16()
            .or_else(|| default_port(candidate.scheme_str()));
        match self.port {
            Some(port) => candidate_port == Some(port),
            None => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum OriginScheme {
    Http,
    Https,
}

impl OriginScheme {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "http" | "HTTP" => Some(OriginScheme::Http),
            "https" | "HTTPS" => Some(OriginScheme::Https),
            _ => None,
        }
    }

    fn matches(&self, other: &str) -> bool {
        match self {
            OriginScheme::Http => other.eq_ignore_ascii_case("http"),
            OriginScheme::Https => other.eq_ignore_ascii_case("https"),
        }
    }
}

fn apply_security_headers(headers: &mut HeaderMap, nonce: &CspNonce) {
    let csp_value = format!(
        "default-src 'none'; connect-src 'self'; img-src 'self'; font-src 'self'; \
         style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; script-src-attr 'none'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'; object-src 'none'; block-all-mixed-content; upgrade-insecure-requests",
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
    headers.insert(
        HEADER_PERMISSIONS_POLICY,
        HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );
    headers.insert(
        HEADER_STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_OPENER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_EMBEDDER_POLICY,
        HeaderValue::from_static("require-corp"),
    );
}

fn mark_response_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn is_origin_allowed(req: &AxumRequest, policy: &OriginPolicy) -> bool {
    policy.allows(req)
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
    let origin_policy = OriginPolicy::from_allowlist(access.allow_origins.clone())?;
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

    #[cfg(feature = "config")]
    let logo = LogoAsset::from_optional_path(
        config
            .as_ref()
            .and_then(|cfg| cfg.web.as_ref())
            .and_then(|web| web.logo_path.as_deref()),
    )?;
    #[cfg(not(feature = "config"))]
    let logo = LogoAsset::default();

    let app_state = AppState {
        interval,
        #[cfg(feature = "config")]
        config,
        web_debug,
        security: security.clone(),
        exposure,
        shutdown: shutdown_for_state,
        updates_cache,
        logo,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/assets/logo.svg", get(logo_asset))
        .route("/updates", get(updates_page))
        .route("/sse", get(sse_stream))
        .layer(middleware::from_fn_with_state(
            origin_policy,
            http_security_layer,
        ))
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

async fn logo_asset(State(state): State<AppState>) -> Response {
    state.logo.response()
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
    if let Some(token) = session.session_cookie() {
        set_session_cookie(response.headers_mut(), token);
    }
    mark_response_no_store(response.headers_mut());
    response
}

async fn updates_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let cookie_token = session.session_cookie().map(str::to_owned);

    if !state.exposure.updates() {
        let message = "L'exposition des mises à jour est désactivée pour cette instance.";
        let html = render_updates_page(None, Some(message), csp_nonce.as_str());
        let mut response = Html(html).into_response();
        if let Some(token) = cookie_token.as_deref() {
            set_session_cookie(response.headers_mut(), token);
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
        set_session_cookie(response.headers_mut(), token);
    }
    response
}

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}

pub(super) fn set_session_cookie(headers: &mut HeaderMap, value: &str) {
    if value.is_empty() {
        return;
    }
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let suffix = "; HttpOnly; Secure";
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict{suffix}",
        name = TOKEN_COOKIE_NAME,
        value = encoded,
        max_age = TOKEN_COOKIE_MAX_AGE,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(crate) fn clear_token_cookie(headers: &mut HeaderMap) {
    let suffix = "; HttpOnly; Secure";
    let cookie = format!(
        "{name}=deleted; Path=/; Max-Age=0; SameSite=Strict{suffix}",
        name = TOKEN_COOKIE_NAME,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::header::SET_COOKIE;

    fn build_request_with_headers(origin: Option<&str>, host: &str) -> AxumRequest {
        let mut builder = axum::http::Request::builder()
            .uri("http://internal/")
            .header(header::HOST, host);
        if let Some(origin_value) = origin {
            builder = builder.header(ORIGIN, origin_value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn nonce_is_inserted_in_csp_header() {
        let mut headers = HeaderMap::new();
        let nonce = CspNonce::new("abcd1234".into());
        apply_security_headers(&mut headers, &nonce);
        let value = headers
            .get(HEADER_CONTENT_SECURITY_POLICY)
            .and_then(|val| val.to_str().ok())
            .unwrap();
        assert!(value.contains("style-src 'nonce-abcd1234'"));
        assert!(value.contains("script-src 'nonce-abcd1234'"));
        let permissions = headers
            .get(HEADER_PERMISSIONS_POLICY)
            .and_then(|val| val.to_str().ok())
            .unwrap();
        assert_eq!(permissions, "geolocation=(), camera=(), microphone=()");
        let coop = headers
            .get(HEADER_CROSS_ORIGIN_OPENER_POLICY)
            .and_then(|val| val.to_str().ok())
            .unwrap();
        assert_eq!(coop, "same-origin");
        let coep = headers
            .get(HEADER_CROSS_ORIGIN_EMBEDDER_POLICY)
            .and_then(|val| val.to_str().ok())
            .unwrap();
        assert_eq!(coep, "require-corp");
    }

    #[test]
    fn origin_allowlist_accepts_configured_origin() {
        let request = build_request_with_headers(
            Some("https://public.example.com"),
            "internal.example.lan:8080",
        );
        let policy = OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
        assert!(is_origin_allowed(&request, &policy));
    }

    #[test]
    fn origin_allowlist_blocks_unlisted_origin() {
        let request = build_request_with_headers(Some("https://evil.example.com"), "internal:8080");
        let policy = OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
        assert!(!is_origin_allowed(&request, &policy));
    }

    #[test]
    fn origin_defaults_to_same_host_port() {
        let request = build_request_with_headers(Some("http://internal:8080"), "internal:8080");
        let policy = OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
        assert!(is_origin_allowed(&request, &policy));
    }

    #[test]
    fn set_session_cookie_includes_http_only() {
        let mut headers = HeaderMap::new();
        set_session_cookie(&mut headers, "sess:v1:test");
        let value = headers.get(SET_COOKIE).expect("set-cookie");
        let text = value.to_str().expect("utf8");
        assert!(
            text.contains("; HttpOnly"),
            "cookie missing HttpOnly: {text}"
        );
        assert!(
            text.contains("SameSite=Strict"),
            "cookie missing SameSite=Strict: {text}"
        );
    }

    #[test]
    fn clear_token_cookie_includes_http_only() {
        let mut headers = HeaderMap::new();
        clear_token_cookie(&mut headers);
        let value = headers.get(SET_COOKIE).expect("set-cookie");
        let text = value.to_str().expect("utf8");
        assert!(
            text.contains("; HttpOnly"),
            "clear cookie missing HttpOnly: {text}"
        );
    }

    #[test]
    fn session_cookies_include_secure() {
        let mut headers = HeaderMap::new();
        set_session_cookie(&mut headers, "sess:v1:test");
        let value = headers.get(SET_COOKIE).expect("set-cookie");
        let text = value.to_str().expect("utf8");
        assert!(
            text.contains("; Secure"),
            "cookie missing Secure attribute: {text}"
        );

        let mut headers = HeaderMap::new();
        clear_token_cookie(&mut headers);
        let value = headers.get(SET_COOKIE).expect("set-cookie");
        let text = value.to_str().expect("utf8");
        assert!(
            text.contains("; Secure"),
            "clear cookie missing Secure attribute: {text}"
        );
    }

    #[test]
    fn response_marked_no_store_sets_cache_header() {
        let mut headers = HeaderMap::new();
        mark_response_no_store(&mut headers);
        let value = headers
            .get(header::CACHE_CONTROL)
            .expect("Cache-Control header");
        assert_eq!(value, HeaderValue::from_static("no-store"));
    }

    #[test]
    fn hsts_header_is_added() {
        let mut headers = HeaderMap::new();
        let nonce = CspNonce::new("abc".into());
        apply_security_headers(&mut headers, &nonce);
        let value = headers
            .get(HEADER_STRICT_TRANSPORT_SECURITY)
            .expect("Strict-Transport-Security header");
        assert_eq!(
            value.to_str().unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn logo_asset_is_static_svg() {
        let asset = LogoAsset::default();
        let response = asset.response();
        let (parts, body) = response.into_parts();

        let content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("content-type header");
        assert_eq!(content_type, "image/svg+xml");

        let body = to_bytes(body, usize::MAX).await.expect("body bytes");
        assert_eq!(body.as_ref(), asset.bytes.as_ref());
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn custom_logo_path_is_loaded_and_validated() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let logo_path = dir.path().join("logo.svg");
        fs::write(
            &logo_path,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><text>OK</text></svg>"#,
        )
        .expect("write logo");

        let asset =
            LogoAsset::from_optional_path(logo_path.to_str()).expect("logo from config path");
        let response = asset.response();
        let (_, body) = response.into_parts();
        let body = to_bytes(body, usize::MAX).await.expect("body bytes");
        assert_eq!(body.as_ref(), asset.bytes.as_ref());
    }

    #[cfg(feature = "config")]
    #[test]
    fn custom_logo_rejects_script() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let logo_path = dir.path().join("logo.svg");
        fs::write(
            &logo_path,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
        )
        .expect("write logo");

        let err = LogoAsset::from_optional_path(logo_path.to_str());
        assert!(matches!(err, Err(DescribeError::Config(msg)) if msg.contains("script")));
    }
}
