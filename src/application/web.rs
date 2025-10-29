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

use std::borrow::Cow;
use std::convert::Infallible;
#[cfg(unix)]
use std::future::pending;
use std::future::Future;
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use crate::application::logging::LogEvent;
use axum::http::uri::Authority;
use axum::middleware::Next;
use axum::response::sse::Event;
use axum::{
    extract::{Extension, State},
    http::{
        header,
        header::{HeaderName, HeaderValue, ORIGIN},
        HeaderMap, StatusCode, Uri,
    },
    middleware,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{stream::StreamExt, Stream};
use pin_project::{pin_project, pinned_drop};
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::sync::Notify;
use tokio_stream::wrappers::IntervalStream;
use tracing::warn;

use super::exposure::{Exposure, SnapshotView};

use security::{AuthGuard, WebSecurity};

#[derive(Debug, Clone, Default)]
pub struct WebAccess {
    /// Jeton d'accès (Authorization: Bearer ou en-tête `x-describe-me-token`).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: 192.0.2.10, 10.0.0.0/24, ::1).
    pub allow_ips: Vec<String>,
}

#[cfg(all(feature = "config", feature = "systemd"))]
use super::filter_services;
use crate::domain::CaptureOptions;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, WebSecurityConfig};
use crate::domain::{DescribeError, SystemSnapshot};

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

const HEADER_CONTENT_SECURITY_POLICY: HeaderName =
    HeaderName::from_static("content-security-policy");
const HEADER_REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const HEADER_X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const HEADER_CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

type AxumRequest = axum::extract::Request;

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

    let host_authority: Authority = match host_str.parse() {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SseCloseReason {
    Natural,
    Limit,
    Error,
}

impl SseCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            SseCloseReason::Natural => "natural",
            SseCloseReason::Limit => "limit",
            SseCloseReason::Error => "error",
        }
    }
}

struct StreamPayload {
    event: axum::response::sse::Event,
    close_after: Option<SseCloseReason>,
}

struct SseMetrics {
    start: Instant,
    max_duration: Duration,
    ip: IpAddr,
    token: security::TokenKey,
    events: AtomicU64,
    reason: AtomicU8,
}

impl SseMetrics {
    fn new(ip: IpAddr, token: security::TokenKey, max_duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            max_duration,
            ip,
            token,
            events: AtomicU64::new(0),
            reason: AtomicU8::new(SseCloseReason::Natural as u8),
        }
    }

    fn record_event(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn set_reason(&self, reason: SseCloseReason) {
        let _ = self.reason.compare_exchange(
            SseCloseReason::Natural as u8,
            reason as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    fn limit_exceeded(&self) -> bool {
        if self.max_duration.is_zero() {
            return false;
        }
        if self.start.elapsed() >= self.max_duration {
            self.set_reason(SseCloseReason::Limit);
            return true;
        }
        false
    }

    fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn duration_seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn reason(&self) -> SseCloseReason {
        match self.reason.load(Ordering::Relaxed) {
            x if x == SseCloseReason::Limit as u8 => SseCloseReason::Limit,
            x if x == SseCloseReason::Error as u8 => SseCloseReason::Error,
            _ => SseCloseReason::Natural,
        }
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }

    fn token(&self) -> security::TokenKey {
        self.token
    }
}

#[pin_project(PinnedDrop)]
struct MetricsStream<S> {
    #[pin]
    inner: S,
    metrics: Arc<SseMetrics>,
    pending_close: Option<SseCloseReason>,
    permit: Option<security::SsePermit>,
    #[pin]
    shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    shutdown_triggered: bool,
}

impl<S> MetricsStream<S> {
    fn new(
        inner: S,
        metrics: Arc<SseMetrics>,
        permit: Option<security::SsePermit>,
        shutdown: Arc<Notify>,
    ) -> Self {
        let shutdown_clone = shutdown.clone();
        let shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>> =
            Box::pin(async move {
                shutdown_clone.notified().await;
            });
        Self {
            inner,
            metrics,
            pending_close: None,
            permit,
            shutdown_fut,
            shutdown_triggered: false,
        }
    }
}

impl<S> Stream for MetricsStream<S>
where
    S: Stream<Item = Result<StreamPayload, Infallible>>,
{
    type Item = Result<Event, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if !*this.shutdown_triggered {
            if this.shutdown_fut.as_mut().poll(cx).is_ready() {
                *this.shutdown_triggered = true;
                this.metrics.set_reason(SseCloseReason::Limit);
                return Poll::Ready(None);
            }
        } else {
            return Poll::Ready(None);
        }

        if let Some(reason) = this.pending_close.take() {
            this.metrics.set_reason(reason);
            return Poll::Ready(None);
        }

        if this.metrics.limit_exceeded() {
            return Poll::Ready(None);
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(payload))) => {
                this.metrics.record_event();
                if let Some(reason) = payload.close_after {
                    this.metrics.set_reason(reason);
                    *this.pending_close = Some(reason);
                }
                Poll::Ready(Some(Ok(payload.event)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pinned_drop]
impl<S> PinnedDrop for MetricsStream<S> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        let metrics = this.metrics;
        let reason = metrics.reason();
        LogEvent::SseStreamClosed {
            ip: Cow::Owned(metrics.ip().to_string()),
            token: Cow::Owned(metrics.token().to_string()),
            events: metrics.events(),
            duration_s: metrics.duration_seconds(),
            reason: Cow::Borrowed(reason.as_str()),
        }
        .emit();
    }
}

async fn sse_stream(State(state): State<AppState>, guard: AuthGuard) -> impl IntoResponse {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio::time::{self, MissedTickBehavior};

    // compile-time: services seulement si feature systemd
    #[cfg(feature = "systemd")]
    let with_services = true;
    #[cfg(not(feature = "systemd"))]
    let with_services = false;

    let mut session = guard.into_session();
    let client_ip = session.ip();
    let token_key = session.token_key();
    let permit = session.take_sse_permit();
    let policy = state.security.policy();
    let shutdown_notify = state.shutdown.clone();

    // Tick périodique en respectant la cadence minimale
    let mut interval = state.interval;
    let min_interval = policy.sse_min_event_interval();
    if interval < min_interval {
        interval = min_interval;
    }

    let max_payload = policy.sse_max_payload_bytes();
    let max_duration = policy.sse_max_stream_duration();
    let min_interval_ms = min_interval.as_millis().min(u128::from(u64::MAX)) as u64;
    let max_stream_s = max_duration.as_secs();

    let metrics = Arc::new(SseMetrics::new(client_ip, token_key, max_duration));
    let metrics_for_stream = metrics.clone();

    LogEvent::SseStreamOpen {
        ip: Cow::Owned(client_ip.to_string()),
        token: Cow::Owned(token_key.to_string()),
        min_interval_ms,
        max_payload,
        max_stream_s,
    }
    .emit();

    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    #[cfg(feature = "config")]
    let config = state.config.clone();
    let exposure = state.exposure;

    let stream = IntervalStream::new(ticker).then(move |_| {
        #[cfg(feature = "config")]
        let config = config.clone();
        let exposure = exposure;
        let max_payload = max_payload;
        let metrics = metrics_for_stream.clone();

        async move {
            let (payload, services_count, partitions_count, close_after) =
                match SystemSnapshot::capture_with(CaptureOptions {
                    with_services,
                    with_disk_usage: true,
                }) {
                    #[allow(unused_mut)]
                    Ok(mut s) => {
                        #[cfg(all(feature = "systemd", feature = "config"))]
                        if let Some(cfg) = config.as_ref() {
                            s.services_running =
                                filter_services(std::mem::take(&mut s.services_running), cfg);
                        }
                        let view = SnapshotView::new(&s, exposure);
                        #[cfg(feature = "systemd")]
                        let services_count = view
                            .services_running
                            .as_ref()
                            .map(|services| services.len());
                        #[cfg(not(feature = "systemd"))]
                        let services_count = None::<usize>;
                        let partitions_count = view
                            .disk_usage
                            .as_ref()
                            .and_then(|du| du.partitions.as_ref().map(|p| p.len()));
                        (
                            serde_json::to_string(&view)
                                .unwrap_or_else(|e| json_err(e.to_string())),
                            services_count,
                            partitions_count,
                            None,
                        )
                    }
                    Err(e) => (
                        json_err(e.to_string()),
                        None,
                        None,
                        Some(SseCloseReason::Error),
                    ),
                };
            let payload_len = payload.len();

            LogEvent::SseTick {
                payload_bytes: payload_len,
                services_count,
                partitions: partitions_count,
            }
            .emit();

            let event = if payload_len > max_payload {
                LogEvent::SsePayloadOversize {
                    size: payload_len,
                    limit: max_payload,
                }
                .emit();
                Event::default().data(json_err("payload SSE trop volumineux"))
            } else {
                Event::default().data(payload)
            };

            if let Some(reason) = close_after {
                metrics.set_reason(reason);
            }

            Ok::<StreamPayload, Infallible>(StreamPayload { event, close_after })
        }
    });

    let stream = MetricsStream::new(stream, metrics, permit, shutdown_notify);

    Sse::new(stream).keep_alive(KeepAlive::default())
}

mod security {
    #[cfg(feature = "config")]
    use super::WebSecurityConfig;
    use super::{AppState, DescribeError, WebAccess};
    use crate::application::logging::LogEvent;
    use axum::{
        async_trait,
        extract::{ConnectInfo, FromRequestParts},
        http::{header::AUTHORIZATION, request::Parts, HeaderValue, StatusCode},
        response::{IntoResponse, Response},
    };
    use std::{
        borrow::Cow,
        collections::{HashMap, HashSet, VecDeque},
        fmt,
        hash::{Hash, Hasher},
        net::{IpAddr, SocketAddr},
        sync::{Arc, Mutex as StdMutex},
        time::{Duration, Instant},
    };
    use subtle::ConstantTimeEq;
    use tokio::sync::Mutex;
    use tracing::warn;

    const GENERIC_AUTH_MESSAGE: &str = "authentification requise";
    const GENERIC_RATE_LIMIT_MESSAGE: &str = "trop de requêtes, réessayez plus tard";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WebRoute {
        Html,
        Sse,
    }

    impl WebRoute {
        pub fn from_path(path: &str) -> Self {
            if path == "/sse" {
                WebRoute::Sse
            } else {
                WebRoute::Html
            }
        }

        pub fn as_str(&self) -> &'static str {
            match self {
                WebRoute::Html => "/",
                WebRoute::Sse => "/sse",
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[derive(Debug)]
    pub struct AuthSession {
        route: WebRoute,
        #[allow(dead_code)]
        ip: IpAddr,
        #[allow(dead_code)]
        token: TokenKey,
        sse_permit: Option<SsePermit>,
    }

    impl AuthSession {
        #[cfg(test)]
        pub fn route(&self) -> WebRoute {
            self.route
        }

        pub fn ip(&self) -> IpAddr {
            self.ip
        }

        pub fn token_key(&self) -> TokenKey {
            self.token
        }

        pub fn take_sse_permit(&mut self) -> Option<SsePermit> {
            self.sse_permit.take()
        }
    }

    pub struct AuthGuard {
        session: AuthSession,
    }

    impl AuthGuard {
        pub fn into_session(self) -> AuthSession {
            self.session
        }
    }

    #[async_trait]
    impl FromRequestParts<AppState> for AuthGuard {
        type Rejection = Response;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &AppState,
        ) -> Result<Self, Self::Rejection> {
            let route = WebRoute::from_path(parts.uri.path());
            match state.security.authorize(parts, route).await {
                Ok(session) => Ok(AuthGuard { session }),
                Err(rejection) => Err(rejection.into_response()),
            }
        }
    }

    #[derive(Debug)]
    pub struct WebSecurity {
        token: Option<String>,
        allow: Vec<IpMatcher>,
        policy: SecurityPolicy,
        state: Arc<SecurityState>,
    }

    impl WebSecurity {
        pub fn build(
            access: WebAccess,
            #[cfg(feature = "config")] override_cfg: Option<WebSecurityConfig>,
        ) -> Result<Self, DescribeError> {
            let token = access.token.and_then(|t| {
                let trimmed = t.trim().to_owned();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            });

            let mut allow = Vec::new();
            for raw in access.allow_ips {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let rule = IpMatcher::parse(trimmed)
                    .map_err(|err| DescribeError::Config(format!("web.allow_ips: {err}")))?;
                if !allow.contains(&rule) {
                    allow.push(rule);
                }
            }

            #[cfg(feature = "config")]
            let policy = override_cfg
                .as_ref()
                .map(SecurityPolicy::from_config)
                .unwrap_or_else(SecurityPolicy::default);
            #[cfg(not(feature = "config"))]
            let policy = SecurityPolicy::default();

            let state = Arc::new(SecurityState::new());

            Ok(Self {
                token,
                allow,
                policy,
                state,
            })
        }

        pub fn policy(&self) -> &SecurityPolicy {
            &self.policy
        }

        pub async fn authorize(
            &self,
            parts: &Parts,
            route: WebRoute,
        ) -> Result<AuthSession, SecurityRejection> {
            let now = Instant::now();
            let remote_ip = parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
                .ok_or_else(|| {
                    warn!(
                        route = route.as_str(),
                        "Connexion sans adresse distante (ConnectInfo absent)"
                    );
                    SecurityRejection::missing_ip()
                })?;

            let trusted_ip = if self.allow.is_empty() {
                false
            } else {
                self.allow.iter().any(|rule| rule.matches(remote_ip))
            };

            if !self.allow.is_empty() && !trusted_ip {
                warn!(ip = %remote_ip, route = route.as_str(), "IP refusée par la allowlist");
                return Err(SecurityRejection::forbidden_ip());
            }

            let provided_token = extract_token(parts);
            let token_key = provided_token
                .as_ref()
                .map(|value| TokenKey::from_value(value))
                .unwrap_or(TokenKey::Anonymous);
            let require_token = route != WebRoute::Html;

            if let Some(delay) = self
                .state
                .check_existing_block(remote_ip, token_key, now)
                .await
            {
                let delay = self.policy.adjust_retry(route, delay);
                warn!(
                    ip = %remote_ip,
                    route = route.as_str(),
                    retry_after = %delay.as_secs_f32(),
                    "Refus (cooldown en cours)"
                );
                return Err(SecurityRejection::cooldown(delay));
            }

            if let Some(expected) = &self.token {
                let auth_ok = provided_token
                    .as_deref()
                    .map(|provided| tokens_match(expected, provided))
                    .unwrap_or(false);

                let missing = provided_token.is_none();
                let missing_allowed = missing && !require_token;

                if !(auth_ok || missing_allowed) {
                    let failure = self
                        .state
                        .note_failure(remote_ip, token_key, now, &self.policy, route)
                        .await;
                    if let Some(delay) = failure.retry_after {
                        warn!(
                            ip = %remote_ip,
                            route = route.as_str(),
                            token = %token_key,
                            retry_after = %delay.as_secs_f32(),
                            "Echec authentification (backoff)"
                        );
                        return Err(SecurityRejection::unauthorized(Some(delay)));
                    } else {
                        warn!(
                            ip = %remote_ip,
                            route = route.as_str(),
                            token = %token_key,
                            "Echec authentification"
                        );
                        return Err(SecurityRejection::unauthorized(None));
                    }
                }
            }

            if let Some(delay) = self
                .state
                .register_ip_hit(route, remote_ip, &self.policy, trusted_ip, now)
                .await
            {
                let delay = self.policy.adjust_retry(route, delay);
                warn!(
                    ip = %remote_ip,
                    route = route.as_str(),
                    retry_after = %delay.as_secs_f32(),
                    "Rate limit IP dépassé"
                );
                return Err(SecurityRejection::rate_limited(delay));
            }

            if let Some(delay) = self
                .state
                .register_token_hit(route, token_key, &self.policy, now)
                .await
            {
                let delay = self.policy.adjust_retry(route, delay);
                warn!(
                    ip = %remote_ip,
                    route = route.as_str(),
                    token = %token_key,
                    retry_after = %delay.as_secs_f32(),
                    "Rate limit token dépassé"
                );
                return Err(SecurityRejection::rate_limited(delay));
            }

            let sse_permit = if route == WebRoute::Sse {
                match self.state.acquire_sse(remote_ip, token_key, &self.policy) {
                    Ok(permit) => permit,
                    Err(delay) => {
                        let delay = self.policy.adjust_retry(route, delay);
                        warn!(
                            ip = %remote_ip,
                            route = route.as_str(),
                            token = %token_key,
                            retry_after = %delay.as_secs_f32(),
                            "Limite de connexions SSE atteinte"
                        );
                        return Err(SecurityRejection::rate_limited(delay));
                    }
                }
            } else {
                None
            };

            self.state.note_success(remote_ip, token_key).await;

            LogEvent::AuthOk {
                ip: Cow::Owned(remote_ip.to_string()),
                route: Cow::Owned(route.as_str().to_string()),
                token: Cow::Owned(token_key.to_string()),
            }
            .emit();

            Ok(AuthSession {
                route,
                ip: remote_ip,
                token: token_key,
                sse_permit,
            })
        }
    }

    #[derive(Debug)]
    pub struct SecurityPolicy {
        html: RoutePolicy,
        sse: SsePolicy,
        allow_multiplier: u32,
        brute_force: BruteForcePolicy,
    }

    impl SecurityPolicy {
        fn default() -> Self {
            Self {
                html: RoutePolicy::new(Duration::from_secs(60), 60, 15),
                sse: SsePolicy::default(),
                allow_multiplier: 4,
                brute_force: BruteForcePolicy::default(),
            }
        }

        #[cfg(feature = "config")]
        fn from_config(cfg: &WebSecurityConfig) -> Self {
            let html = RoutePolicy::new(
                duration_from_secs(cfg.html.window_seconds, 60),
                cfg.html.per_ip,
                cfg.html.per_token,
            );
            let sse = SsePolicy::from_config(&cfg.sse);
            let brute_force = BruteForcePolicy::from_config(&cfg.brute_force);

            Self {
                html,
                sse,
                allow_multiplier: cfg.allowlist_multiplier.max(1),
                brute_force,
            }
        }

        fn route_policy(&self, route: WebRoute) -> &RoutePolicy {
            match route {
                WebRoute::Html => &self.html,
                WebRoute::Sse => &self.sse.route,
            }
        }

        fn brute_force(&self) -> &BruteForcePolicy {
            &self.brute_force
        }

        fn allow_multiplier(&self) -> u32 {
            self.allow_multiplier.max(1)
        }

        fn adjust_retry(&self, route: WebRoute, mut delay: Duration) -> Duration {
            if route == WebRoute::Sse {
                let min = self.brute_force.sse_min_retry;
                if min > Duration::ZERO && delay < min {
                    delay = min;
                }
            }
            if delay < Duration::from_millis(250) {
                delay = Duration::from_secs(1);
            }
            delay
        }

        pub fn sse_min_event_interval(&self) -> Duration {
            self.sse.min_event_interval()
        }

        pub fn sse_max_payload_bytes(&self) -> usize {
            self.sse.max_payload_bytes()
        }

        pub fn sse_max_stream_duration(&self) -> Duration {
            self.sse.max_stream()
        }
    }

    #[derive(Debug, Clone)]
    struct RoutePolicy {
        window: Duration,
        per_ip: u32,
        per_token: u32,
    }

    impl RoutePolicy {
        fn new(window: Duration, per_ip: u32, per_token: u32) -> Self {
            Self {
                window: if window.is_zero() {
                    Duration::from_secs(1)
                } else {
                    window
                },
                per_ip,
                per_token,
            }
        }

        fn ip_limit(&self, multiplier: u32, trusted: bool) -> u32 {
            if self.per_ip == 0 {
                return 0;
            }
            if trusted {
                self.per_ip.saturating_mul(multiplier.max(1))
            } else {
                self.per_ip
            }
        }

        fn token_limit(&self) -> u32 {
            self.per_token
        }
    }

    #[derive(Debug, Clone)]
    struct SsePolicy {
        route: RoutePolicy,
        max_active_per_ip: u32,
        max_active_per_token: u32,
        max_stream: Duration,
        min_event_interval: Duration,
        max_payload_bytes: usize,
    }

    impl SsePolicy {
        fn default() -> Self {
            Self {
                route: RoutePolicy::new(Duration::from_secs(60), 20, 12),
                max_active_per_ip: 2,
                max_active_per_token: 2,
                max_stream: Duration::from_secs(20 * 60),
                min_event_interval: Duration::from_secs(1),
                max_payload_bytes: 48 * 1024,
            }
        }

        #[cfg(feature = "config")]
        fn from_config(cfg: &crate::domain::SseLimitConfig) -> Self {
            Self {
                route: RoutePolicy::new(
                    duration_from_secs(cfg.window_seconds, 60),
                    cfg.per_ip,
                    cfg.per_token,
                ),
                max_active_per_ip: cfg.max_active_per_ip,
                max_active_per_token: cfg.max_active_per_token,
                max_stream: duration_from_secs(cfg.max_stream_seconds, 20 * 60),
                min_event_interval: duration_from_millis(cfg.min_event_interval_ms, 1000),
                max_payload_bytes: cfg.max_payload_bytes as usize,
            }
        }

        pub fn min_event_interval(&self) -> Duration {
            self.min_event_interval
        }

        pub fn max_payload_bytes(&self) -> usize {
            self.max_payload_bytes
        }

        pub fn max_stream(&self) -> Duration {
            self.max_stream
        }
    }

    #[derive(Debug, Clone)]
    struct BruteForcePolicy {
        window: Duration,
        threshold: u32,
        initial_backoff: Duration,
        multiplier: f32,
        ceiling: Duration,
        quarantine: Duration,
        token_failure_threshold: u32,
        token_ip_spread: u32,
        sse_min_retry: Duration,
    }

    impl BruteForcePolicy {
        fn default() -> Self {
            Self {
                window: Duration::from_secs(300),
                threshold: 5,
                initial_backoff: Duration::from_secs(5),
                multiplier: 2.0,
                ceiling: Duration::from_secs(60),
                quarantine: Duration::from_secs(20 * 60),
                token_failure_threshold: 12,
                token_ip_spread: 3,
                sse_min_retry: Duration::from_secs(2),
            }
        }

        #[cfg(feature = "config")]
        fn from_config(cfg: &crate::domain::BruteForceConfig) -> Self {
            Self {
                window: duration_from_secs(cfg.window_seconds, 300),
                threshold: cfg.threshold,
                initial_backoff: duration_from_secs(cfg.initial_backoff_seconds, 5),
                multiplier: if cfg.backoff_multiplier <= 1.0 {
                    2.0
                } else {
                    cfg.backoff_multiplier
                },
                ceiling: duration_from_secs(cfg.backoff_ceiling_seconds, 60),
                quarantine: duration_from_secs(cfg.quarantine_seconds, 20 * 60),
                token_failure_threshold: cfg.token_failure_threshold,
                token_ip_spread: cfg.token_ip_spread,
                sse_min_retry: duration_from_secs(cfg.sse_min_retry_seconds, 2),
            }
        }
    }

    #[derive(Debug)]
    struct SecurityState {
        html_ip: Mutex<HashMap<IpAddr, RateCounter>>,
        sse_ip: Mutex<HashMap<IpAddr, RateCounter>>,
        html_token: Mutex<HashMap<TokenKey, RateCounter>>,
        sse_token: Mutex<HashMap<TokenKey, RateCounter>>,
        failures_ip: Mutex<HashMap<IpAddr, FailureRecord>>,
        failures_token: Mutex<HashMap<TokenKey, FailureRecord>>,
        token_spread: Mutex<HashMap<TokenKey, TokenSpread>>,
        sse_active: Arc<ActiveSseState>,
    }

    impl SecurityState {
        fn new() -> Self {
            Self {
                html_ip: Mutex::new(HashMap::new()),
                sse_ip: Mutex::new(HashMap::new()),
                html_token: Mutex::new(HashMap::new()),
                sse_token: Mutex::new(HashMap::new()),
                failures_ip: Mutex::new(HashMap::new()),
                failures_token: Mutex::new(HashMap::new()),
                token_spread: Mutex::new(HashMap::new()),
                sse_active: ActiveSseState::new(),
            }
        }

        async fn register_ip_hit(
            &self,
            route: WebRoute,
            ip: IpAddr,
            policy: &SecurityPolicy,
            trusted: bool,
            now: Instant,
        ) -> Option<Duration> {
            let limits = policy.route_policy(route);
            let cap = limits.ip_limit(policy.allow_multiplier(), trusted);
            if cap == 0 {
                return None;
            }
            let window = limits.window;
            let map = match route {
                WebRoute::Html => &self.html_ip,
                WebRoute::Sse => &self.sse_ip,
            };
            let mut guard = map.lock().await;
            let counter = guard.entry(ip).or_default();
            let wait = counter.register(now, window, cap);
            if counter.is_empty() {
                guard.remove(&ip);
            }
            wait
        }

        async fn register_token_hit(
            &self,
            route: WebRoute,
            token: TokenKey,
            policy: &SecurityPolicy,
            now: Instant,
        ) -> Option<Duration> {
            let limits = policy.route_policy(route);
            let cap = limits.token_limit();
            if cap == 0 {
                return None;
            }
            let window = limits.window;
            let map = match route {
                WebRoute::Html => &self.html_token,
                WebRoute::Sse => &self.sse_token,
            };
            let mut guard = map.lock().await;
            let counter = guard.entry(token).or_default();
            let wait = counter.register(now, window, cap);
            if counter.is_empty() {
                guard.remove(&token);
            }
            wait
        }

        async fn check_existing_block(
            &self,
            ip: IpAddr,
            token: TokenKey,
            now: Instant,
        ) -> Option<Duration> {
            let mut delay = None;

            {
                let guard = self.failures_ip.lock().await;
                if let Some(record) = guard.get(&ip) {
                    if let Some(until) = record.blocked_until {
                        if until > now {
                            delay = combine_delay(delay, until.saturating_duration_since(now));
                        }
                    }
                }
            }

            if token != TokenKey::Anonymous {
                {
                    let guard = self.failures_token.lock().await;
                    if let Some(record) = guard.get(&token) {
                        if let Some(until) = record.blocked_until {
                            if until > now {
                                delay = combine_delay(delay, until.saturating_duration_since(now));
                            }
                        }
                    }
                }
                {
                    let guard = self.token_spread.lock().await;
                    if let Some(spread) = guard.get(&token) {
                        if let Some(until) = spread.locked_until {
                            if until > now {
                                delay = combine_delay(delay, until.saturating_duration_since(now));
                            }
                        }
                    }
                }
            }

            delay
        }

        async fn note_failure(
            &self,
            ip: IpAddr,
            token: TokenKey,
            now: Instant,
            policy: &SecurityPolicy,
            route: WebRoute,
        ) -> FailureOutcome {
            let mut delay = None;

            {
                let mut guard = self.failures_ip.lock().await;
                let record = guard.entry(ip).or_default();
                if let Some(until) = record.register(now, policy.brute_force()) {
                    delay = combine_delay(delay, until.saturating_duration_since(now));
                }
                if record.is_clear() {
                    guard.remove(&ip);
                }
            }

            if token != TokenKey::Anonymous {
                {
                    let mut guard = self.failures_token.lock().await;
                    let record = guard.entry(token).or_default();
                    if let Some(until) = record.register(now, policy.brute_force()) {
                        delay = combine_delay(delay, until.saturating_duration_since(now));
                    }
                    if record.is_clear() {
                        guard.remove(&token);
                    }
                }

                {
                    let mut guard = self.token_spread.lock().await;
                    let spread = guard.entry(token).or_default();
                    if let Some(until) = spread.register(ip, now, policy.brute_force()) {
                        delay = combine_delay(delay, until.saturating_duration_since(now));
                    }
                    if spread.is_clear() {
                        guard.remove(&token);
                    }
                }
            }

            FailureOutcome {
                retry_after: delay.map(|d| policy.adjust_retry(route, d)),
            }
        }

        async fn note_success(&self, ip: IpAddr, token: TokenKey) {
            {
                let mut guard = self.failures_ip.lock().await;
                guard.remove(&ip);
            }
            if token != TokenKey::Anonymous {
                {
                    let mut guard = self.failures_token.lock().await;
                    guard.remove(&token);
                }
                {
                    let mut guard = self.token_spread.lock().await;
                    guard.remove(&token);
                }
            }
        }

        fn acquire_sse(
            &self,
            ip: IpAddr,
            token: TokenKey,
            policy: &SecurityPolicy,
        ) -> Result<Option<SsePermit>, Duration> {
            self.sse_active.try_acquire(ip, token, &policy.sse)
        }
    }

    struct FailureOutcome {
        retry_after: Option<Duration>,
    }

    #[derive(Debug, Default)]
    struct RateCounter {
        hits: VecDeque<Instant>,
    }

    impl RateCounter {
        fn register(&mut self, now: Instant, window: Duration, limit: u32) -> Option<Duration> {
            if limit == 0 {
                return None;
            }
            while let Some(front) = self.hits.front() {
                if now.duration_since(*front) >= window {
                    self.hits.pop_front();
                } else {
                    break;
                }
            }
            if self.hits.len() as u32 >= limit {
                if let Some(oldest) = self.hits.front() {
                    let elapsed = now.duration_since(*oldest);
                    let wait = window.saturating_sub(elapsed);
                    return Some(wait);
                }
                return Some(window);
            }
            self.hits.push_back(now);
            None
        }

        fn is_empty(&self) -> bool {
            self.hits.is_empty()
        }
    }

    #[derive(Debug, Default)]
    struct FailureRecord {
        attempts: VecDeque<Instant>,
        blocked_until: Option<Instant>,
        current_backoff: Duration,
    }

    impl FailureRecord {
        fn register(&mut self, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
            self.purge(now, policy.window);
            if let Some(until) = self.blocked_until {
                if until > now {
                    return Some(until);
                } else {
                    self.blocked_until = None;
                }
            }

            self.attempts.push_back(now);
            if self.attempts.len() as u32 >= policy.threshold {
                return self.apply_penalty(now, policy);
            }
            None
        }

        fn apply_penalty(&mut self, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
            if let Some(until) = self.blocked_until {
                if until > now {
                    return Some(until);
                }
            }

            if !self.current_backoff.is_zero() && self.current_backoff >= policy.ceiling {
                let until = now + policy.quarantine;
                self.blocked_until = Some(until);
                self.current_backoff = policy.initial_backoff;
                self.attempts.clear();
                return Some(until);
            }

            let next_backoff = if self.current_backoff.is_zero() {
                policy.initial_backoff
            } else {
                let scaled = (self.current_backoff.as_secs_f32() * policy.multiplier).ceil() as u64;
                let base = policy.initial_backoff.as_secs().max(1);
                Duration::from_secs(scaled.max(base)).min(policy.ceiling)
            };

            if next_backoff.is_zero() {
                return None;
            }

            self.current_backoff = next_backoff;
            let until = now + next_backoff;
            self.blocked_until = Some(until);
            Some(until)
        }

        fn purge(&mut self, now: Instant, window: Duration) {
            while let Some(front) = self.attempts.front() {
                if now.duration_since(*front) >= window {
                    self.attempts.pop_front();
                } else {
                    break;
                }
            }
        }

        fn is_clear(&self) -> bool {
            self.attempts.is_empty() && self.blocked_until.is_none()
        }
    }

    #[derive(Debug, Default)]
    struct TokenSpread {
        ips: HashSet<IpAddr>,
        failure_count: u32,
        locked_until: Option<Instant>,
    }

    impl TokenSpread {
        fn register(
            &mut self,
            ip: IpAddr,
            now: Instant,
            policy: &BruteForcePolicy,
        ) -> Option<Instant> {
            if let Some(until) = self.locked_until {
                if until > now {
                    return Some(until);
                } else {
                    self.locked_until = None;
                    self.failure_count = 0;
                    self.ips.clear();
                }
            }

            self.failure_count = self.failure_count.saturating_add(1);
            self.ips.insert(ip);
            if self.ips.len() > 32 {
                if let Some(first) = self.ips.iter().next().copied() {
                    self.ips.remove(&first);
                }
            }

            if self.failure_count >= policy.token_failure_threshold
                && self.ips.len() as u32 >= policy.token_ip_spread
            {
                let until = now + policy.quarantine;
                self.locked_until = Some(until);
                return Some(until);
            }
            None
        }

        fn is_clear(&self) -> bool {
            self.failure_count == 0 && self.locked_until.is_none()
        }
    }

    #[derive(Debug, Default)]
    struct ActiveSse {
        per_ip: HashMap<IpAddr, u32>,
        per_token: HashMap<TokenKey, u32>,
    }

    #[derive(Debug)]
    struct ActiveSseState {
        inner: StdMutex<ActiveSse>,
    }

    impl ActiveSseState {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: StdMutex::new(ActiveSse::default()),
            })
        }

        fn try_acquire(
            self: &Arc<Self>,
            ip: IpAddr,
            token: TokenKey,
            limits: &SsePolicy,
        ) -> Result<Option<SsePermit>, Duration> {
            if limits.max_active_per_ip == 0 && limits.max_active_per_token == 0 {
                return Ok(None);
            }

            let mut inner = self.inner.lock().expect("SSE mutex poisoned");

            if limits.max_active_per_ip > 0 {
                let current = inner.per_ip.get(&ip).copied().unwrap_or(0);
                if current >= limits.max_active_per_ip {
                    return Err(Duration::from_secs(0));
                }
            }

            if limits.max_active_per_token > 0 {
                let current = inner.per_token.get(&token).copied().unwrap_or(0);
                if current >= limits.max_active_per_token {
                    return Err(Duration::from_secs(0));
                }
            }

            let mut track_ip = false;
            if limits.max_active_per_ip > 0 {
                let entry = inner.per_ip.entry(ip).or_insert(0);
                *entry += 1;
                track_ip = true;
            }

            let mut track_token = false;
            if limits.max_active_per_token > 0 {
                let entry = inner.per_token.entry(token).or_insert(0);
                *entry += 1;
                track_token = true;
            }

            Ok(Some(SsePermit {
                state: Arc::clone(self),
                ip,
                token,
                track_ip,
                track_token,
            }))
        }

        fn release(&self, ip: IpAddr, token: TokenKey, track_ip: bool, track_token: bool) {
            let mut inner = self.inner.lock().expect("SSE mutex poisoned");
            if track_ip {
                if let Some(count) = inner.per_ip.get_mut(&ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        inner.per_ip.remove(&ip);
                    }
                }
            }
            if track_token {
                if let Some(count) = inner.per_token.get_mut(&token) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        inner.per_token.remove(&token);
                    }
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct SsePermit {
        state: Arc<ActiveSseState>,
        ip: IpAddr,
        token: TokenKey,
        track_ip: bool,
        track_token: bool,
    }

    impl Drop for SsePermit {
        fn drop(&mut self) {
            self.state
                .release(self.ip, self.token, self.track_ip, self.track_token);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum TokenKey {
        Anonymous,
        Fingerprint(u64),
    }

    impl TokenKey {
        fn from_value(token: &str) -> Self {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            token.hash(&mut hasher);
            TokenKey::Fingerprint(hasher.finish())
        }
    }

    impl fmt::Display for TokenKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TokenKey::Anonymous => f.write_str("anon"),
                TokenKey::Fingerprint(fp) => write!(f, "fp:{fp:016x}"),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum IpMatcher {
        Exact(IpAddr),
        Ipv4 { network: u32, mask: u32 },
        Ipv6 { network: u128, mask: u128 },
    }

    impl IpMatcher {
        fn parse(raw: &str) -> Result<Self, String> {
            if raw.is_empty() {
                return Err("entrée vide".into());
            }

            if let Some((addr_part, prefix_part)) = raw.split_once('/') {
                let base_ip: IpAddr = addr_part
                    .parse()
                    .map_err(|_| format!("adresse IP invalide: '{addr_part}'"))?;
                let prefix: u8 = prefix_part
                    .parse()
                    .map_err(|_| format!("préfixe CIDR invalide: '{prefix_part}'"))?;

                match base_ip {
                    IpAddr::V4(base) => {
                        if prefix > 32 {
                            return Err(format!("préfixe IPv4 invalide: {prefix} (max 32)"));
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u32::MAX.checked_shl((32 - prefix) as u32).unwrap_or(0)
                        };
                        let network = u32::from(base) & mask;
                        Ok(IpMatcher::Ipv4 { network, mask })
                    }
                    IpAddr::V6(base) => {
                        if prefix > 128 {
                            return Err(format!("préfixe IPv6 invalide: {prefix} (max 128)"));
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX.checked_shl((128 - prefix) as u32).unwrap_or(0)
                        };
                        let network = u128::from(base) & mask;
                        Ok(IpMatcher::Ipv6 { network, mask })
                    }
                }
            } else {
                let ip: IpAddr = raw
                    .parse()
                    .map_err(|_| format!("adresse IP invalide: '{raw}'"))?;
                Ok(IpMatcher::Exact(ip))
            }
        }

        fn matches(&self, addr: IpAddr) -> bool {
            match (self, addr) {
                (IpMatcher::Exact(expected), current) => *expected == current,
                (IpMatcher::Ipv4 { network, mask }, IpAddr::V4(current)) => {
                    (u32::from(current) & mask) == *network
                }
                (IpMatcher::Ipv6 { network, mask }, IpAddr::V6(current)) => {
                    (u128::from(current) & mask) == *network
                }
                _ => false,
            }
        }
    }

    #[derive(Debug)]
    pub(crate) struct SecurityRejection {
        status: StatusCode,
        body: &'static str,
        retry_after: Option<Duration>,
    }

    impl SecurityRejection {
        fn missing_ip() -> Self {
            Self {
                status: StatusCode::FORBIDDEN,
                body: GENERIC_AUTH_MESSAGE,
                retry_after: None,
            }
        }

        fn forbidden_ip() -> Self {
            Self {
                status: StatusCode::FORBIDDEN,
                body: GENERIC_AUTH_MESSAGE,
                retry_after: None,
            }
        }

        fn unauthorized(retry: Option<Duration>) -> Self {
            Self {
                status: StatusCode::UNAUTHORIZED,
                body: GENERIC_AUTH_MESSAGE,
                retry_after: retry,
            }
        }

        fn rate_limited(retry: Duration) -> Self {
            Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: GENERIC_RATE_LIMIT_MESSAGE,
                retry_after: Some(retry),
            }
        }

        fn cooldown(retry: Duration) -> Self {
            Self::rate_limited(retry)
        }

        fn into_response(self) -> Response {
            let mut response = (self.status, self.body).into_response();
            if let Some(delay) = self.retry_after {
                let jittered = jitter(delay);
                let secs = retry_after_seconds(jittered);
                if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                    response.headers_mut().insert("Retry-After", value);
                }
            }
            response
        }
    }

    fn jitter(delay: Duration) -> Duration {
        let extra = Duration::from_millis(fastrand::u32(0..=750) as u64);
        delay.saturating_add(extra)
    }

    fn retry_after_seconds(delay: Duration) -> u64 {
        let secs = delay.as_secs();
        let mut total = if secs == 0 && delay.subsec_nanos() > 0 {
            1
        } else if delay.subsec_nanos() > 0 {
            secs.saturating_add(1)
        } else {
            secs
        };
        if total == 0 {
            total = 1;
        }
        total
    }

    fn combine_delay(current: Option<Duration>, new_delay: Duration) -> Option<Duration> {
        if new_delay.is_zero() {
            return current;
        }
        Some(match current {
            Some(existing) => existing.max(new_delay),
            None => new_delay,
        })
    }

    #[cfg(feature = "config")]
    fn duration_from_secs(value: u64, fallback: u64) -> Duration {
        let secs = if value == 0 { fallback } else { value };
        Duration::from_secs(secs.max(1))
    }

    #[cfg(feature = "config")]
    fn duration_from_millis(value: u64, fallback: u64) -> Duration {
        let ms = if value == 0 { fallback } else { value };
        Duration::from_millis(ms.max(1))
    }

    fn extract_token(parts: &Parts) -> Option<String> {
        if let Some(header_value) = parts.headers.get(AUTHORIZATION) {
            if let Ok(value) = header_value.to_str() {
                let trimmed = value.trim();
                if let Some((scheme, token)) = trimmed.split_once(' ') {
                    if scheme.eq_ignore_ascii_case("bearer") {
                        let token = token.trim();
                        if !token.is_empty() {
                            return Some(token.to_owned());
                        }
                    }
                }
            }
        }

        if let Some(header_value) = parts.headers.get("x-describe-me-token") {
            if let Ok(value) = header_value.to_str() {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_owned());
                }
            }
        }

        None
    }

    fn tokens_match(expected: &str, provided: &str) -> bool {
        let expected_bytes = expected.as_bytes();
        let provided_bytes = provided.as_bytes();
        expected_bytes.len() == provided_bytes.len() && expected_bytes.ct_eq(provided_bytes).into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use axum::http::Request;
        use std::net::{IpAddr, Ipv4Addr};

        fn make_access(token: Option<&str>) -> WebAccess {
            WebAccess {
                token: token.map(|t| t.to_string()),
                allow_ips: Vec::new(),
            }
        }

        #[cfg(feature = "config")]
        fn build_security(token: Option<&str>) -> WebSecurity {
            WebSecurity::build(make_access(token), None).unwrap()
        }

        #[cfg(not(feature = "config"))]
        fn build_security(token: Option<&str>) -> WebSecurity {
            WebSecurity::build(make_access(token)).unwrap()
        }

        fn make_parts(path: &str, ip: IpAddr, token: Option<&str>) -> Parts {
            let request = Request::builder().uri(path).body(()).unwrap();
            let (mut parts, _) = request.into_parts();
            if let Some(token) = token {
                parts
                    .headers
                    .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
            }
            parts
                .extensions
                .insert(ConnectInfo(std::net::SocketAddr::from((ip, 4242))));
            parts
        }

        #[tokio::test]
        async fn rate_limit_ip_html() {
            let security = build_security(None);
            let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);

            let mut ok = 0u32;
            loop {
                match security.authorize(&parts, WebRoute::Html).await {
                    Ok(_) => ok += 1,
                    Err(err) => {
                        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
                        assert!(err.retry_after.is_some());
                        break;
                    }
                }
            }

            // Anon tokens are limited more aggressively (15/minute by default).
            assert_eq!(ok, 15);
        }

        #[tokio::test]
        async fn auth_backoff_after_failures() {
            let security = build_security(Some("secret"));
            let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("wrong"));

            for attempt in 0..6 {
                let res = security.authorize(&parts, WebRoute::Html).await;
                if attempt < 5 {
                    assert!(res.is_err());
                } else {
                    let err = res.expect_err("backoff expected");
                    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
                    assert!(err.retry_after.is_some());
                }
            }
        }

        #[tokio::test]
        async fn sse_concurrency_limited() {
            let security = build_security(Some("secret"));
            let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));

            let session1 = security
                .authorize(&parts, WebRoute::Sse)
                .await
                .expect("first SSE");
            let session2 = security
                .authorize(&parts, WebRoute::Sse)
                .await
                .expect("second SSE");

            assert_eq!(session1.route(), WebRoute::Sse);
            assert_eq!(session2.route(), WebRoute::Sse);
            assert_eq!(session1.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(session2.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(session1.token_key(), TokenKey::from_value("secret"));

            let err = security
                .authorize(&parts, WebRoute::Sse)
                .await
                .expect_err("should block third");
            assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
            assert!(err.retry_after.is_some());

            drop(session1);
            drop(session2);

            security
                .authorize(&parts, WebRoute::Sse)
                .await
                .expect("slot released");
        }
    }
}

// Echappement ultra simple pour quotes et backslashes
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json_err(msg: impl AsRef<str>) -> String {
    format!(r#"{{"error":"{}"}}"#, escape_json(msg.as_ref()))
}

fn render_index(web_debug: bool, csp_nonce: &str) -> String {
    INDEX_HTML
        .replace("__WEB_DEBUG__", if web_debug { "true" } else { "false" })
        .replace("__CSP_NONCE__", csp_nonce)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>describe_me — Live</title>
  <style nonce="__CSP_NONCE__">
    :root {
      --bg: #0f1115;
      --card: #151923;
      --text: #e6eef8;
      --muted: #a8b3c3;
      --ok: #3ad29f;
      --warn: #ffd166;
      --err: #ff6b6b;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0; background: var(--bg); color: var(--text);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
    }
    header {
      padding: 16px 20px; border-bottom: 1px solid #222838;
      display: flex; align-items: center; gap: 10px;
    }
    .dot {
      width: 10px; height: 10px; border-radius: 999px; background: var(--warn);
      box-shadow: 0 0 8px var(--warn);
      display: inline-block; flex-shrink: 0;
    }
    .ok { background: var(--ok); box-shadow: 0 0 8px var(--ok); }
    .dot.err { background: var(--err); box-shadow: 0 0 8px var(--err); }
    main { padding: 20px; display: grid; gap: 16px; max-width: 1200px; margin: 0 auto; }
    .grid {
      display: grid; gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }
    .card {
      background: var(--card); border: 1px solid #222838; border-radius: 10px;
      padding: 16px; box-shadow: 0 4px 12px rgba(0,0,0,.2);
    }
    h1 { font-size: 18px; margin: 0; }
    h2 { font-size: 16px; margin: 0 0 10px; color: var(--muted); }
    .k { color: var(--muted); }
    .v { font-family: var(--mono); }
    .mono { font-family: var(--mono); font-size: 14px; }
    .row { display: flex; justify-content: space-between; gap: 10px; margin: 6px 0; }
    .badge { padding: 2px 8px; border-radius: 999px; background: #1d2333; border: 1px solid #2a3147; }
    .footer { opacity: .7; font-size: 13px; text-align: center; padding: 10px 0 30px; }
    .error { color: var(--err); }
    .link-button {
      background: none; border: none; color: inherit; font: inherit;
      text-decoration: underline; cursor: pointer; padding: 0;
    }
    .link-button:hover { text-decoration: none; }
    @media (prefers-color-scheme: light) {
      :root { --bg:#f6f7fb; --card:#ffffff; --text:#1d2330; --muted:#5b667a; }
      body { background: var(--bg); color: var(--text); }
      .card { border-color: #e4e8f1; }
    }
     .bar { position: relative; height: 10px; background: #1d2333; border:1px solid #2a3147; border-radius:6px; overflow:hidden; }
     .bar > span { position:absolute; left:0; top:0; bottom:0; background:#3ad29f55; border-right:2px solid #3ad29f; }
     .mono .line { margin: 6px 0 10px; }
    .services-list { display: flex; flex-direction: column; gap: 10px; }
    .service-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 8px 10px; border-radius: 8px; background: #1d2333; border: 1px solid #2a3147;
    }
    .service-dot { margin-top: 4px; }
    .service-name { font-weight: 600; }
    .service-meta { margin-top: 2px; font-size: 13px; color: var(--muted); }
    .service-empty { color: var(--muted); font-style: italic; }
    @media (prefers-color-scheme: light) {
      .service-row { background: #f0f2fb; border-color: #d6dbeb; }
    }
    .token-overlay {
      position: fixed; inset: 0;
      background: rgba(15, 17, 21, 0.92);
      display: none; align-items: center; justify-content: center;
      padding: 20px; z-index: 100;
    }
    .token-overlay.visible { display: flex; }
    .token-dialog {
      background: var(--card); border: 1px solid #222838; border-radius: 10px;
      padding: 24px; max-width: 360px; width: 100%;
      box-shadow: 0 8px 24px rgba(0,0,0,.35);
    }
    .token-dialog h2 { margin: 0 0 12px; font-size: 18px; color: var(--text); }
    .token-dialog p { margin: 0 0 16px; color: var(--muted); font-size: 14px; }
    .token-dialog form { display: flex; flex-direction: column; gap: 10px; }
    .token-dialog input {
      padding: 10px 12px; border-radius: 6px; border: 1px solid #2a3147;
      background: #0f1115; color: var(--text); font-size: 15px;
    }
    .token-dialog .actions {
      display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap;
    }
    .token-dialog button {
      flex: 1 1 auto; padding: 10px 12px; border-radius: 6px; border: none;
      background: #3ad29f; color: #0f1115; font-weight: 600; cursor: pointer;
    }
    .token-dialog button.secondary {
      background: transparent; border: 1px solid #2a3147; color: var(--text);
    }
    .token-error { margin-top: 12px; font-size: 13px; color: var(--err); }
    @media (prefers-color-scheme: light) {
      .token-dialog { background: #ffffff; border-color: #d6dbeb; }
      .token-dialog input { background: #ffffff; border-color: #d0d6e5; color: #1d2330; }
      .token-dialog button.secondary { border-color: #d0d6e5; color: #1d2330; }
    }

  </style>
</head>
<body>
  <header>
    <div id="statusDot" class="dot"></div>
    <h1>describe_me — informations en direct</h1>
    <span class="badge" id="lastUpdate">—</span>
  </header>

  <main>
    <div class="grid">
      <section class="card">
        <h2>Système</h2>
        <div class="row"><span class="k">Hostname</span><span class="v" id="hostname">—</span></div>
        <div class="row"><span class="k">OS</span><span class="v" id="os">—</span></div>
        <div class="row"><span class="k">Kernel</span><span class="v" id="kernel">—</span></div>
        <div class="row"><span class="k">Uptime</span><span class="v" id="uptime">—</span></div>
        <div class="row"><span class="k">CPU(s)</span><span class="v" id="cpus">—</span></div>
      </section>

      <section class="card">
        <h2>Mémoire</h2>
        <div class="row"><span class="k">Total</span><span class="v" id="memTotal">—</span></div>
        <div class="row"><span class="k">Utilisée</span><span class="v" id="memUsed">—</span></div>
      </section>

      <section class="card">
        <h2>Disque</h2>
        <div class="row"><span class="k">Total</span><span class="v" id="diskTotal">—</span></div>
        <div class="row"><span class="k">Libre</span><span class="v" id="diskAvail">—</span></div>
        <div class="line">
          <div class="bar"><span id="diskBar" style="width:0%"></span></div>
        </div>
        <div class="mono" id="partitions">—</div>
      </section>
    </div>

    <section class="card" id="servicesCard" style="display:none">
      <h2>Services actifs</h2>
      <div class="services-list" id="servicesList">
        <div class="service-empty">—</div>
      </div>
    </section>

    <section class="card" id="rawCard" style="display:none">
      <h2>JSON brut</h2>
      <pre class="mono" id="raw">—</pre>
      <div id="error" class="error mono"></div>
    </section>
  </main>
  <div id="tokenOverlay" class="token-overlay">
    <div class="token-dialog">
      <h2>Jeton requis</h2>
      <p>Ce serveur nécessite un jeton pour accéder aux métriques en direct.</p>
      <form id="tokenForm">
        <input id="tokenInput" type="password" placeholder="Jeton d'accès" autocomplete="off" />
        <div class="actions">
          <button type="submit">Valider</button>
          <button type="button" id="tokenForget" class="secondary">Effacer</button>
        </div>
      </form>
      <div id="tokenError" class="token-error" role="alert"></div>
    </div>
  </div>
  <div class="footer">
    Actualisation en direct via SSE (stream fetch) • Pas de framework frontend •
    <button id="tokenOpen" class="link-button" type="button">Modifier le jeton</button>
  </div>

  <script nonce="__CSP_NONCE__">
    const WEB_DEBUG = __WEB_DEBUG__;
    const dot = document.getElementById('statusDot');
    const raw = document.getElementById('raw');
    const err = document.getElementById('error');
    const last = document.getElementById('lastUpdate');
    const rawCard = document.getElementById('rawCard');

    const tokenOverlay = document.getElementById('tokenOverlay');
    const tokenForm = document.getElementById('tokenForm');
    const tokenInput = document.getElementById('tokenInput');
    const tokenErrorEl = document.getElementById('tokenError');
    const tokenForget = document.getElementById('tokenForget');
    const tokenOpen = document.getElementById('tokenOpen');

    const pct = (used, total) => total > 0 ? Math.max(0, Math.min(100, (used/total)*100)) : 0;
    const num = (value) => {
      const n = Number(value);
      return Number.isFinite(n) ? n : 0;
    };

    if (WEB_DEBUG && rawCard) {
      rawCard.style.display = "block";
    }

    const el = (id) => document.getElementById(id);
    const fmtBytes = (n) => {
      const units = ["o","Ko","Mo","Go","To","Po"]; let i = 0, x = Number(n)||0;
      while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
      return x.toFixed(1) + " " + units[i];
    };
    const fmtSecs = (s) => {
      s = Number(s)||0;
      const d = Math.floor(s/86400); s%=86400;
      const h = Math.floor(s/3600); s%=3600;
      const m = Math.floor(s/60); s%=60;
      const parts = [];
      if (d) parts.push(d+"j"); if (h) parts.push(h+"h"); if (m) parts.push(m+"m"); if (s) parts.push(s+"s");
      return parts.join(" ") || "0s";
    };
    const esc = (value) => {
      const s = value ?? "";
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    };
    const serviceStateClass = (state) => {
      const val = (state || "").toLowerCase();
      if (!val) return "err";
      const okTokens = ["running", "listening", "online", "active"];
      return okTokens.some((token) => val.includes(token)) ? "ok" : "err";
    };

    let currentToken = sessionStorage.getItem('describe_me_token') || "";
    if (currentToken) {
      tokenInput.value = currentToken;
    }
    let abortController = null;
    let reconnectTimer = null;

    tokenForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = tokenInput.value.trim();
      if (!value) {
        tokenErrorEl.textContent = "Merci de renseigner un jeton.";
        tokenInput.focus();
        return;
      }
      currentToken = value;
      sessionStorage.setItem('describe_me_token', currentToken);
      hideTokenPrompt();
      restartStream();
    });

    tokenForget.addEventListener('click', () => {
      sessionStorage.removeItem('describe_me_token');
      currentToken = "";
      tokenInput.value = "";
      tokenErrorEl.textContent = "";
      showTokenPrompt("");
    });

    if (tokenOpen) {
      tokenOpen.addEventListener('click', () => {
        tokenInput.value = currentToken;
        tokenErrorEl.textContent = "";
        if (abortController) {
          abortController.abort();
          abortController = null;
        }
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
        showTokenPrompt("");
      });
    }

    function showTokenPrompt(message) {
      if (typeof message === "string" && message) {
        tokenErrorEl.textContent = message;
      }
      tokenOverlay.classList.add('visible');
      setTimeout(() => tokenInput.focus(), 0);
    }

    function hideTokenPrompt() {
      tokenOverlay.classList.remove('visible');
      tokenErrorEl.textContent = "";
    }

    function restartStream() {
      if (abortController) {
        abortController.abort();
        abortController = null;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      connectSse();
    }

    async function connectSse() {
      if (abortController) {
        abortController.abort();
      }
      abortController = new AbortController();
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }

      try {
        const headers = {};
        if (currentToken) {
          headers["Authorization"] = `Bearer ${currentToken}`;
        }

        const response = await fetch('/sse', {
          method: 'GET',
          headers,
          signal: abortController.signal,
        });

        if (response.status === 401) {
          const message = await readErrorMessage(response);
          sessionStorage.removeItem('describe_me_token');
          currentToken = "";
          tokenInput.value = "";
          showError(message || "Jeton requis pour accéder aux métriques.");
          showTokenPrompt(message || "Jeton requis pour accéder aux métriques.");
          return;
        }

        if (response.status === 403) {
          const message = await readErrorMessage(response);
          showError(message || "Adresse IP non autorisée.");
          scheduleReconnect();
          return;
        }

        if (!response.ok || !response.body) {
          showError(`Flux SSE indisponible (HTTP ${response.status}).`);
          scheduleReconnect();
          return;
        }

        hideTokenPrompt();
        await consumeSse(response.body);
        abortController = null;
        scheduleReconnect();
      } catch (err) {
        if (err && err.name === 'AbortError') {
          return;
        }
        showError("Flux SSE interrompu (nouvelle tentative dans quelques secondes).");
        scheduleReconnect();
      }
    }

    async function readErrorMessage(response) {
      try {
        const text = await response.text();
        if (!text) return "";
        const data = JSON.parse(text);
        if (data && typeof data.error === "string") {
          return data.error;
        }
        return text;
      } catch (_) {
        return "";
      }
    }

    async function consumeSse(body) {
      const reader = body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          buffer = processSseBuffer(buffer, true);
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        buffer = processSseBuffer(buffer, false);
      }
    }

    function processSseBuffer(buffer, flush) {
      let index;
      while ((index = buffer.indexOf('\n\n')) !== -1) {
        const chunk = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        handleSseEvent(chunk);
      }
      if (flush && buffer.trim() !== "") {
        handleSseEvent(buffer);
        return "";
      }
      return buffer;
    }

    function handleSseEvent(rawEvent) {
      const lines = rawEvent.split(/\r?\n/);
      const dataLines = [];
      for (const line of lines) {
        if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
      if (dataLines.length === 0) {
        return;
      }
      const payload = dataLines.join('\n');
      try {
        const parsed = JSON.parse(payload);
        if (parsed && parsed.error) {
          showError(parsed.error);
          return;
        }
        updateUI(parsed);
      } catch (e) {
        showError("Erreur de parsing JSON: " + (e && e.message ? e.message : e));
      }
    }

    function scheduleReconnect(delay = 4000) {
      if (tokenOverlay.classList.contains('visible')) {
        return;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectSse();
      }, delay);
    }

    function updateUI(data) {
      err.textContent = "";

      el('hostname').textContent = data.hostname || "—";
      el('os').textContent = data.os || data.os_name || "—";
      el('kernel').textContent = data.kernel || "—";
      el('uptime').textContent = fmtSecs(data.uptime_seconds || 0);
      el('cpus').textContent = data.cpu_count ?? "—";

      el('memTotal').textContent = fmtBytes(data.total_memory_bytes || 0);
      el('memUsed').textContent = fmtBytes(data.used_memory_bytes || 0);

      const du = data.disk_usage || {};
      const total = num(du.total_bytes);
      const avail = num(du.available_bytes);
      let used = du.used_bytes != null ? num(du.used_bytes) : Math.max(0, total - avail);
      if (total > 0 && used > total) {
        used = total;
      }

      el('diskTotal').textContent = fmtBytes(total);
      el('diskAvail').textContent = fmtBytes(avail);
      el('diskBar').style.width = pct(used, total).toFixed(1) + "%";

      const partitions = Array.isArray(du.partitions) ? du.partitions : [];
      const partsHtml = partitions.map(p => {
        const pt = num(p.total_bytes);
        const pa = num(p.available_bytes);
        const usedPart = Math.max(0, Math.min(pt, pt - pa));
        const w = pct(usedPart, pt).toFixed(1) + "%";
        const mp = esc(p.mount_point || "?");
        const fs = esc(p.fs_type || "—");
        return [
          `${mp}  (fs: ${fs}) — total: ${fmtBytes(pt)}, libre: ${fmtBytes(pa)}`,
          `<div class="bar"><span style="width:${w}"></span></div>`
        ].join("\n");
      }).join("\n");

      el('partitions').innerHTML = partsHtml || "—";

      const servicesCard = document.getElementById('servicesCard');
      const servicesList = document.getElementById('servicesList');
      if (servicesCard && servicesList) {
        const services = Array.isArray(data.services_running) ? data.services_running : [];
        const summary = data.services_summary;
        if (services.length > 0) {
          servicesCard.style.display = "block";
          servicesList.innerHTML = services.map((svc) => {
            const name = esc(svc?.name || "Service");
            const stateRaw = svc?.state || "";
            const state = stateRaw ? esc(stateRaw) : "";
            const summaryText = svc?.summary ? esc(svc.summary) : "";
            const dotClass = serviceStateClass(stateRaw);
            const metaParts = [];
            if (state) metaParts.push(state);
            if (summaryText) metaParts.push(summaryText);
            const meta = metaParts.join(" • ");
            return `
              <div class="service-row">
                <span class="dot service-dot ${dotClass}"></span>
                <div>
                  <div class="service-name">${name}</div>
                  ${meta ? `<div class="service-meta">${meta}</div>` : ""}
                </div>
              </div>
            `;
          }).join("");
        } else if (summary && typeof summary.total === 'number') {
          servicesCard.style.display = "block";
          const items = Array.isArray(summary.by_state) ? summary.by_state : [];
          const breakdown = items
            .map(item => `<span class="badge">${item.state}: ${item.count}</span>`)
            .join(" ");
          servicesList.innerHTML = `
            <div class="service-row">
              <span class="dot service-dot"></span>
              <div>
                <div class="service-name">${summary.total} service(s) observé(s)</div>
                <div class="service-meta">${breakdown || "Aucune donnée détaillée"}</div>
              </div>
            </div>
          `;
        } else if ('services_running' in data) {
          servicesCard.style.display = "block";
          servicesList.innerHTML = `<div class="service-empty">Aucun service actif rapporté</div>`;
        } else {
          servicesCard.style.display = "none";
          servicesList.innerHTML = "";
        }
      }

      raw.textContent = JSON.stringify(data, null, 2);
      last.textContent = new Date().toLocaleTimeString();
      dot.classList.add('ok');
    }

    function showError(message) {
      err.textContent = message;
      dot.classList.remove('ok');
    }

    connectSse();
  </script>
</body>
</html>
"#;

fn map_io(e: impl std::error::Error + Send + Sync + 'static) -> DescribeError {
    DescribeError::System(format!("I/O/Serve error: {e}"))
}
