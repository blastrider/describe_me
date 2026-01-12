//! Web security stack orchestrating authentication, rate limits, brute-force protection,
//! token affinity and SSE admission.
//!
//! Key roles:
//! - `SecurityPolicy`: configuration of thresholds, windows, cooldowns and limits per route.
//! - `SecurityState`: in-memory counters and trackers updated for each request.
//! - `WebSecurity`: Axum-facing facade (auth guards, hooks, SSE permits, logging).
//!
//! Typical request flow:
//! ```text
//! Request -> Auth -> RateLimit -> BruteForce -> TokenAffinity -> GlobalSlots -> Decision
//! ```
//! Note: `GlobalSlots` enforces per-route concurrency caps; SSE keeps a slot for the stream lifetime.
//! This module is structured to keep these concerns isolated while staying extensible.

mod auth;
mod http;
mod incidents;
mod limits;
mod session;
mod sse;
mod types;

pub(crate) use limits::GlobalPermit;
pub(crate) use session::{
    clear_session_cookie, set_session_cookie, WebSession, SESSION_COOKIE_NAME,
};
pub(crate) use types::IpMatcher;
pub(super) use types::{TokenFingerprint, TokenKey};

use super::{template, AppState, WebAccess};
use crate::application::web::csp::CspNonce;
use auth::{build_request, verify_token, AuthRequest, CredentialOverride, TokenVerifier};
use http::{accepts_html, jitter, retry_after_seconds, uniform_auth_delay};
use incidents::emit_security_incident;
use limits::{enforce_rate_limits, ensure_not_blocked, SecurityPolicy, SecurityState};
use session::SessionManager;
use sse::acquire_permit;

use crate::application::logging::LogEvent;
use crate::domain::DescribeError;
use crate::domain::SessionCookieSameSite;
#[cfg(feature = "config")]
use crate::domain::WebSecurityConfig;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, header::HeaderValue, request::Parts, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
pub(crate) use sse::SsePermit;
use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Duration};
use tracing::info;

#[derive(Debug)]
pub(super) struct AuthSession {
    #[cfg(test)]
    route: WebRoute,
    ip: IpAddr,
    token: TokenKey,
    sse_permit: Option<SsePermit>,
    session_cookie: Option<Arc<str>>,
    purge_session_cookie: bool,
    global_permit: Option<limits::GlobalPermit>,
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

    pub fn session_cookie(&self) -> Option<&str> {
        self.session_cookie.as_deref()
    }

    pub fn take_sse_permit(&mut self) -> Option<SsePermit> {
        self.sse_permit.take()
    }

    pub fn take_global_permit(&mut self) -> Option<limits::GlobalPermit> {
        self.global_permit.take()
    }
}

pub(super) struct AuthGuard {
    session: AuthSession,
}

impl AuthGuard {
    pub fn into_session(self) -> AuthSession {
        self.session
    }
}

pub(super) fn attach_session_cookie(
    headers: &mut HeaderMap,
    session: &AuthSession,
    state: &AppState,
) {
    if let Some(cookie) = session.session_cookie() {
        set_session_cookie(
            headers,
            cookie,
            state.session_ttl(),
            state.session_cookie_secure(),
            state.session_cookie_same_site(),
        );
    } else if session.purge_session_cookie {
        clear_session_cookie(
            headers,
            state.session_cookie_secure(),
            state.session_cookie_same_site(),
        );
    }
}

#[cfg(test)]
pub(super) fn make_test_guard(route: WebRoute) -> AuthGuard {
    use std::net::Ipv4Addr;

    AuthGuard {
        session: AuthSession {
            route,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            token: TokenKey::Anonymous,
            sse_permit: None,
            session_cookie: None,
            purge_session_cookie: false,
            global_permit: None,
        },
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
        match state.security().authorize(parts, route).await {
            Ok(session) => Ok(AuthGuard { session }),
            Err(rejection) => {
                let wants_styled_html = matches!(route, WebRoute::Html | WebRoute::Logs)
                    && rejection.is_auth_failure()
                    && accepts_html(parts, route);
                let html_body = if wants_styled_html {
                    let nonce = parts
                        .extensions
                        .get::<CspNonce>()
                        .map(|value| value.as_str())
                        .unwrap_or_default();
                    Some(template::render_auth_required(rejection.body, nonce))
                } else {
                    None
                };
                Err(rejection.into_response(
                    state.session_cookie_secure(),
                    state.session_cookie_same_site(),
                    html_body,
                ))
            }
        }
    }
}

#[derive(Debug)]
pub struct WebSecurity {
    token: Option<TokenVerifier>,
    allow: Vec<IpMatcher>,
    trusted_proxies: Vec<IpMatcher>,
    policy: SecurityPolicy,
    state: Arc<SecurityState>,
    sessions: SessionManager,
}

impl WebSecurity {
    pub fn build(
        access: WebAccess,
        #[cfg(feature = "config")] override_cfg: Option<WebSecurityConfig>,
    ) -> Result<Self, DescribeError> {
        let WebAccess {
            token: raw_token,
            allow_ips,
            trusted_proxies,
            ..
        } = access;

        let token = match raw_token {
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(DescribeError::Config(
                        "web.token is empty/whitespace; refusing to start".into(),
                    ));
                }
                Some(
                    TokenVerifier::parse(trimmed)
                        .map_err(|err| DescribeError::Config(format!("web.token: {err}")))?,
                )
            }
            None => {
                info!("auth disabled by config (web.token not set)");
                None
            }
        };

        let mut allow = Vec::new();
        for raw in allow_ips {
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

        let mut trusted = Vec::new();
        for raw in trusted_proxies {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rule = IpMatcher::parse(trimmed)
                .map_err(|err| DescribeError::Config(format!("web.trusted_proxies: {err}")))?;
            if !trusted.contains(&rule) {
                trusted.push(rule);
            }
        }

        #[cfg(feature = "config")]
        let policy = override_cfg
            .as_ref()
            .map(SecurityPolicy::from_config)
            .unwrap_or_else(SecurityPolicy::default);
        #[cfg(not(feature = "config"))]
        let policy = SecurityPolicy::default();
        #[cfg(feature = "config")]
        let session_ttl_override = override_cfg
            .as_ref()
            .and_then(|cfg| cfg.session_ttl_seconds)
            .map(Duration::from_secs);
        #[cfg(not(feature = "config"))]
        let session_ttl_override: Option<Duration> = None;

        let state = Arc::new(SecurityState::new());
        let sessions = session_ttl_override
            .map(SessionManager::with_ttl)
            .unwrap_or_else(SessionManager::new);

        Ok(Self {
            token,
            allow,
            trusted_proxies: trusted,
            policy,
            state,
            sessions,
        })
    }

    pub(super) fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    pub fn session_ttl(&self) -> Duration {
        self.sessions.ttl()
    }

    pub(crate) fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|rule| rule.matches(ip))
    }

    pub(super) fn session_manager(&self) -> &SessionManager {
        &self.sessions
    }

    pub(super) fn token_fingerprint(&self) -> Option<TokenFingerprint> {
        self.token.as_ref().map(|token| token.fingerprint())
    }

    pub(super) fn client_claim(
        &self,
        ip: IpAddr,
        user_agent: Option<&str>,
    ) -> Option<session::ClientClaim> {
        self.sessions.client_claim(ip, user_agent)
    }

    fn log_incident(&self, category: &'static str, request: &AuthRequest, detail: Option<String>) {
        emit_security_incident(category, request, detail);
    }

    fn log_rejection(
        &self,
        category: &'static str,
        request: &AuthRequest,
        rejection: &SecurityRejection,
    ) {
        let mut parts = vec![format!("status={}", rejection.status)];
        if let Some(delay) = rejection.retry_after {
            parts.push(format!("retry_after_s={:.3}", delay.as_secs_f32()));
        }
        self.log_incident(category, request, Some(parts.join(" ")));
    }

    async fn reject_token_affinity_violation(
        &self,
        request: &AuthRequest,
        now: std::time::Instant,
    ) -> SecurityRejection {
        if let Err(rejection) = enforce_rate_limits(&self.state, &self.policy, request, now).await {
            self.log_rejection("rate_limit", request, &rejection);
            return rejection;
        }

        let failure = self
            .state
            .note_failure(
                request.remote_ip,
                request.token_key,
                now,
                &self.policy,
                request.route,
            )
            .await;

        uniform_auth_delay().await;
        SecurityRejection::unauthorized(failure.retry_after())
    }

    pub(super) async fn authorize(
        &self,
        parts: &Parts,
        route: WebRoute,
    ) -> Result<AuthSession, SecurityRejection> {
        let now = std::time::Instant::now();
        let request = match self.build_request(parts, route, now, None).await {
            Ok(req) => req,
            Err(rejection) => {
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };
        let global_permit = match self
            .state
            .acquire_global_permit(request.route, &self.policy)
        {
            Ok(permit) => permit,
            Err(rejection) => {
                self.log_rejection("rate_limit_global", &request, &rejection);
                return Err(rejection);
            }
        };
        if let Err(rejection) = ensure_not_blocked(&self.state, &self.policy, &request, now).await {
            self.log_rejection("cooldown_active", &request, &rejection);
            if rejection.is_auth_failure() {
                uniform_auth_delay().await;
            }
            return Err(rejection);
        }
        let session_cookie = match self.verify_request(&request, now).await {
            Ok(cookie) => cookie,
            Err(rejection) => {
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };
        let authenticated = session_cookie.is_some();
        if !self
            .state
            .ensure_token_affinity(
                request.route,
                request.token_key,
                request.remote_ip,
                &self.policy,
                request.trusted_ip,
                now,
            )
            .await
        {
            self.log_incident(
                "token_affinity_violation",
                &request,
                Some(format!(
                    "limit={}",
                    self.policy.token_affinity_limit(request.trusted_ip)
                )),
            );
            return Err(self.reject_token_affinity_violation(&request, now).await);
        }
        if let Err(rejection) = enforce_rate_limits(&self.state, &self.policy, &request, now).await
        {
            self.log_rejection("rate_limit", &request, &rejection);
            return Err(rejection);
        }
        let sse_permit = match acquire_permit(&self.state, &self.policy, &request).await {
            Ok(permit) => permit,
            Err(rejection) => {
                self.log_rejection("sse_permit_denied", &request, &rejection);
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };

        if authenticated {
            self.state
                .note_success(request.remote_ip, request.token_key)
                .await;
        }

        LogEvent::AuthOk {
            ip: Cow::Owned(request.remote_ip.to_string()),
            route: Cow::Borrowed(request.route.as_str()),
        }
        .emit();

        let purge_session_cookie = request.purge_session_cookie && session_cookie.is_none();
        Ok(AuthSession {
            #[cfg(test)]
            route: request.route,
            ip: request.remote_ip,
            token: request.token_key,
            sse_permit,
            session_cookie: session_cookie.map(|value| Arc::<str>::from(value.into_boxed_str())),
            purge_session_cookie,
            global_permit,
        })
    }

    pub(super) async fn login(
        &self,
        parts: &Parts,
        token: &str,
        route: WebRoute,
    ) -> Result<AuthSession, SecurityRejection> {
        let now = std::time::Instant::now();
        let request = match self
            .build_request(
                parts,
                route,
                now,
                Some(CredentialOverride::RawToken(token.to_owned())),
            )
            .await
        {
            Ok(req) => req,
            Err(rejection) => return Err(rejection),
        };

        let global_permit = match self
            .state
            .acquire_global_permit(request.route, &self.policy)
        {
            Ok(permit) => permit,
            Err(rejection) => {
                self.log_rejection("rate_limit_global", &request, &rejection);
                return Err(rejection);
            }
        };

        if let Err(rejection) = ensure_not_blocked(&self.state, &self.policy, &request, now).await {
            self.log_rejection("cooldown_active", &request, &rejection);
            if rejection.is_auth_failure() {
                uniform_auth_delay().await;
            }
            return Err(rejection);
        }

        let session_cookie = match self.verify_request(&request, now).await {
            Ok(cookie) => cookie,
            Err(rejection) => {
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };
        let authenticated = session_cookie.is_some();

        if !self
            .state
            .ensure_token_affinity(
                request.route,
                request.token_key,
                request.remote_ip,
                &self.policy,
                request.trusted_ip,
                now,
            )
            .await
        {
            self.log_incident(
                "token_affinity_violation",
                &request,
                Some(format!(
                    "limit={}",
                    self.policy.token_affinity_limit(request.trusted_ip)
                )),
            );
            return Err(self.reject_token_affinity_violation(&request, now).await);
        }

        if let Err(rejection) = enforce_rate_limits(&self.state, &self.policy, &request, now).await
        {
            self.log_rejection("rate_limit", &request, &rejection);
            return Err(rejection);
        }

        if authenticated {
            self.state
                .note_success(request.remote_ip, request.token_key)
                .await;
        }

        LogEvent::AuthOk {
            ip: Cow::Owned(request.remote_ip.to_string()),
            route: Cow::Borrowed(request.route.as_str()),
        }
        .emit();

        let purge_session_cookie = request.purge_session_cookie && session_cookie.is_none();
        Ok(AuthSession {
            #[cfg(test)]
            route: request.route,
            ip: request.remote_ip,
            token: request.token_key,
            sse_permit: None,
            session_cookie: session_cookie.map(|value| Arc::<str>::from(value.into_boxed_str())),
            purge_session_cookie,
            global_permit,
        })
    }

    async fn build_request(
        &self,
        parts: &Parts,
        route: WebRoute,
        now: std::time::Instant,
        credential_override: Option<CredentialOverride>,
    ) -> Result<AuthRequest, SecurityRejection> {
        build_request(
            &self.allow,
            &self.trusted_proxies,
            &self.sessions,
            self.token.is_some(),
            self.token.as_ref().map(|token| token.fingerprint()),
            parts,
            route,
            now,
            credential_override,
        )
        .await
    }

    async fn verify_request(
        &self,
        request: &AuthRequest,
        now: std::time::Instant,
    ) -> Result<Option<String>, SecurityRejection> {
        let session_cookie = match verify_token(
            &self.state,
            &self.policy,
            self.token.as_ref(),
            &self.sessions,
            request,
            now,
        )
        .await
        {
            Ok(cookie) => cookie,
            Err(rejection) => {
                self.log_rejection("token_verification_failed", request, &rejection);
                return Err(rejection);
            }
        };
        Ok(session_cookie)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebRoute {
    Html,
    Sse,
    History,
    Logs,
    Metrics,
}

impl WebRoute {
    pub fn from_path(path: &str) -> Self {
        if path == "/sse" {
            WebRoute::Sse
        } else if path == "/metrics" {
            WebRoute::Metrics
        } else if path.starts_with("/api/logs") || path == "/logs" {
            WebRoute::Logs
        } else if path.starts_with("/api/history") {
            WebRoute::History
        } else if path == "/updates" || path == "/container" {
            WebRoute::Logs
        } else if path.starts_with("/api/") {
            WebRoute::History
        } else {
            WebRoute::Html
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WebRoute::Html => "/",
            WebRoute::Sse => "/sse",
            WebRoute::History => "/api/history",
            WebRoute::Logs => "/api/logs",
            WebRoute::Metrics => "/metrics",
        }
    }

    pub fn requires_token(&self) -> bool {
        !matches!(self, WebRoute::Html)
    }
}

const GENERIC_AUTH_MESSAGE: &str = "authentification requise";
const GENERIC_FORBIDDEN_MESSAGE: &str = "accès interdit";
const GENERIC_RATE_LIMIT_MESSAGE: &str = "trop de requêtes, réessayez plus tard";
const WWW_AUTHENTICATE_BEARER: &str = "Bearer realm=\"describe_me\"";

#[derive(Debug)]
pub(super) struct SecurityRejection {
    status: StatusCode,
    body: &'static str,
    retry_after: Option<Duration>,
}

impl SecurityRejection {
    pub(super) fn missing_ip() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: GENERIC_AUTH_MESSAGE,
            retry_after: None,
        }
    }

    pub(super) fn forbidden_ip() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: GENERIC_FORBIDDEN_MESSAGE,
            retry_after: None,
        }
    }

    pub(super) fn unauthorized(retry: Option<Duration>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: GENERIC_AUTH_MESSAGE,
            retry_after: retry,
        }
    }

    pub(super) fn rate_limited(retry: Duration) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: GENERIC_RATE_LIMIT_MESSAGE,
            retry_after: Some(retry),
        }
    }

    pub(super) fn cooldown(retry: Duration) -> Self {
        Self::rate_limited(retry)
    }

    pub(super) fn into_response(
        self,
        secure_cookie: bool,
        same_site: SessionCookieSameSite,
        html_body: Option<String>,
    ) -> Response {
        let mut response = match html_body {
            Some(html) => (self.status, Html(html)).into_response(),
            None => (self.status, self.body).into_response(),
        };
        if matches!(
            self.status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ) {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        if let Some(delay) = self.retry_after {
            let jittered = jitter(delay);
            let secs = retry_after_seconds(jittered);
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(WWW_AUTHENTICATE_BEARER),
            );
            clear_session_cookie(response.headers_mut(), secure_cookie, same_site);
        }
        response
    }

    pub(super) fn is_auth_failure(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED
    }
}

#[cfg(test)]
mod tests_auth;
#[cfg(test)]
mod tests_bruteforce;
#[cfg(test)]
mod tests_common;
#[cfg(test)]
mod tests_token_affinity;
#[cfg(test)]
mod tests_token_key;
