mod auth;
mod limits;
mod session;
mod sse;

pub(crate) use limits::GlobalPermit;

use super::clear_token_cookie;
use auth::{build_request, verify_token, AuthRequest, TokenVerifier};
use limits::{enforce_rate_limits, ensure_not_blocked, SecurityPolicy, SecurityState};
use session::SessionManager;
use sse::acquire_permit;

use super::{AppState, WebAccess};
use crate::application::logging::LogEvent;
use crate::domain::DescribeError;
#[cfg(feature = "config")]
use crate::domain::WebSecurityConfig;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::HeaderValue, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
pub(crate) use sse::SsePermit;
use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;

#[derive(Debug)]
pub(super) struct AuthSession {
    #[cfg_attr(not(test), allow(dead_code))]
    route: WebRoute,
    ip: IpAddr,
    token: TokenKey,
    sse_permit: Option<SsePermit>,
    session_cookie: Option<Arc<str>>,
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
pub(super) struct WebSecurity {
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
                    None
                } else {
                    Some(
                        TokenVerifier::parse(trimmed)
                            .map_err(|err| DescribeError::Config(format!("web.token: {err}")))?,
                    )
                }
            }
            None => None,
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

        let state = Arc::new(SecurityState::new());

        Ok(Self {
            token,
            allow,
            trusted_proxies: trusted,
            policy,
            state,
            sessions: SessionManager::new(),
        })
    }

    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    fn log_incident(&self, category: &'static str, request: &AuthRequest, detail: Option<String>) {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed(category),
            route: Cow::Owned(request.route.as_str().to_string()),
            ip: Some(Cow::Owned(request.remote_ip.to_string())),
            token: Some(Cow::Owned(request.token_key.to_string())),
            detail: detail.map(Cow::Owned),
        }
        .emit();
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

    pub async fn authorize(
        &self,
        parts: &Parts,
        route: WebRoute,
    ) -> Result<AuthSession, SecurityRejection> {
        let now = std::time::Instant::now();
        let request = match build_request(
            &self.allow,
            &self.trusted_proxies,
            &self.sessions,
            self.token.is_some(),
            parts,
            route,
            now,
        ) {
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
        let session_cookie = match verify_token(
            &self.state,
            &self.policy,
            self.token.as_ref(),
            &self.sessions,
            &request,
            now,
        )
        .await
        {
            Ok(cookie) => cookie,
            Err(rejection) => {
                self.log_rejection("token_verification_failed", &request, &rejection);
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };
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
            uniform_auth_delay().await;
            return Err(SecurityRejection::unauthorized(None));
        }
        if let Err(rejection) = enforce_rate_limits(&self.state, &self.policy, &request, now).await
        {
            self.log_rejection("rate_limit", &request, &rejection);
            return Err(rejection);
        }
        let sse_permit = match acquire_permit(&self.state, &self.policy, &request) {
            Ok(permit) => permit,
            Err(rejection) => {
                self.log_rejection("sse_permit_denied", &request, &rejection);
                if rejection.is_auth_failure() {
                    uniform_auth_delay().await;
                }
                return Err(rejection);
            }
        };

        self.state
            .note_success(request.remote_ip, request.token_key)
            .await;

        LogEvent::AuthOk {
            ip: Cow::Owned(request.remote_ip.to_string()),
            route: Cow::Owned(request.route.as_str().to_string()),
            token: Cow::Owned(request.token_key.to_string()),
        }
        .emit();

        Ok(AuthSession {
            route: request.route,
            ip: request.remote_ip,
            token: request.token_key,
            sse_permit,
            session_cookie: session_cookie.map(|value| Arc::<str>::from(value.into_boxed_str())),
            global_permit,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WebRoute {
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

const GENERIC_AUTH_MESSAGE: &str = "authentification requise";
const GENERIC_RATE_LIMIT_MESSAGE: &str = "trop de requêtes, réessayez plus tard";

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
            status: StatusCode::UNAUTHORIZED,
            body: GENERIC_AUTH_MESSAGE,
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

    fn into_response(self) -> Response {
        let mut response = (self.status, self.body).into_response();
        if let Some(delay) = self.retry_after {
            let jittered = jitter(delay);
            let secs = retry_after_seconds(jittered);
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        if self.status == StatusCode::UNAUTHORIZED {
            clear_token_cookie(response.headers_mut());
        }
        response
    }

    pub(super) fn is_auth_failure(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED
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

async fn uniform_auth_delay() {
    let base = 120;
    let jitter = fastrand::u64(0..=120);
    sleep(Duration::from_millis(base + jitter)).await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TokenKey {
    Anonymous,
    Fingerprint(u64),
}

impl TokenKey {
    pub(super) fn from_value(token: &str) -> Self {
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
pub(super) enum IpMatcher {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::OnceLock;

    fn make_access(token: Option<&str>) -> WebAccess {
        WebAccess {
            token: token.map(|t| t.to_string()),
            allow_ips: Vec::new(),
            allow_origins: Vec::new(),
            trusted_proxies: Vec::new(),
        }
    }

    fn bcrypt_hash(token: &str) -> String {
        bcrypt::hash(token, bcrypt::DEFAULT_COST).expect("bcrypt hash")
    }

    fn cached_hash() -> &'static str {
        static HASH: OnceLock<String> = OnceLock::new();
        HASH.get_or_init(|| bcrypt_hash("secret"))
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
            parts.headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
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

        assert_eq!(ok, 10);
    }

    #[tokio::test]
    async fn auth_backoff_after_failures() {
        let security = build_security(Some(cached_hash()));
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
        let hash = cached_hash();
        let security = build_security(Some(hash));
        let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));

        let session1 = security
            .authorize(&parts, WebRoute::Sse)
            .await
            .expect("first SSE");
        let err = security
            .authorize(&parts, WebRoute::Sse)
            .await
            .expect_err("second SSE should be blocked");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(err.retry_after.is_some());

        drop(session1);

        let session2 = security
            .authorize(&parts, WebRoute::Sse)
            .await
            .expect("slot released");
        assert_eq!(session2.route(), WebRoute::Sse);
        assert_eq!(session2.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(session2.token_key(), TokenKey::from_value("secret"));
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tracing::{field::Visit, Event};
    use tracing_subscriber::{layer::Context, prelude::*, registry::LookupSpan, Layer, Registry};

    #[derive(Clone, Default)]
    struct RecordingLayer {
        events: Arc<Mutex<Vec<HashMap<String, String>>>>,
    }

    impl RecordingLayer {
        fn new() -> Self {
            Self::default()
        }

        fn records(&self) -> Vec<HashMap<String, String>> {
            self.events.lock().unwrap().clone()
        }

        fn clear(&self) {
            self.events.lock().unwrap().clear();
        }
    }

    impl<S> Layer<S> for RecordingLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldRecorder::default();
            event.record(&mut visitor);
            let mut record = visitor.finish();
            record.insert(
                "level".into(),
                event.metadata().level().as_str().to_string(),
            );
            record.insert("target".into(), event.metadata().target().to_string());
            self.events.lock().unwrap().push(record);
        }
    }

    #[derive(Default)]
    struct FieldRecorder {
        fields: HashMap<String, String>,
    }

    impl FieldRecorder {
        fn finish(self) -> HashMap<String, String> {
            self.fields
        }
    }

    impl Visit for FieldRecorder {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{:?}", value));
        }
    }

    #[tokio::test]
    async fn logs_token_affinity_violation() {
        let layer = RecordingLayer::new();
        let subscriber = Registry::default().with(layer.clone());
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        LogEvent::SecurityIncident {
            category: Cow::Borrowed("test"),
            route: Cow::Borrowed("/"),
            ip: None,
            token: None,
            detail: None,
        }
        .emit();
        assert!(
            !layer.records().is_empty(),
            "recording layer inactive before test"
        );
        layer.clear();

        let hash = cached_hash();
        let security = build_security(Some(hash));
        let token = "secret";

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));

        let parts1 = make_parts("/", ip1, Some(token));
        let parts2 = make_parts("/", ip2, Some(token));
        let parts3 = make_parts("/", ip3, Some(token));

        let session1 = security
            .authorize(&parts1, WebRoute::Html)
            .await
            .expect("first request should succeed");
        let session2 = security
            .authorize(&parts2, WebRoute::Html)
            .await
            .expect("second request should succeed");

        let err = security
            .authorize(&parts3, WebRoute::Html)
            .await
            .expect_err("third request should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        drop(session1);
        drop(session2);

        tokio::task::yield_now().await;
        let mut found = false;
        let mut records_snapshot = Vec::new();
        for _ in 0..10 {
            let records = layer.records();
            if records.iter().any(|record| {
                record
                    .get("category")
                    .map(|value| value == "token_affinity_violation")
                    .unwrap_or(false)
            }) {
                records_snapshot = records;
                found = true;
                break;
            }
            records_snapshot = records;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(guard);
        assert!(
            found,
            "expected token_affinity_violation log, got {records_snapshot:?}"
        );
    }
}
