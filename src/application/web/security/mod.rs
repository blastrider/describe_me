mod auth;
mod limits;
mod sse;

use auth::{build_request, verify_token};
use limits::{enforce_rate_limits, ensure_not_blocked, SecurityPolicy, SecurityState};
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

#[derive(Debug)]
pub(super) struct AuthSession {
    #[cfg_attr(not(test), allow(dead_code))]
    route: WebRoute,
    ip: IpAddr,
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
        let now = std::time::Instant::now();
        let request = build_request(&self.allow, parts, route)?;
        ensure_not_blocked(&self.state, &self.policy, &request, now).await?;
        verify_token(
            &self.state,
            &self.policy,
            self.token.as_deref(),
            &request,
            now,
        )
        .await?;
        enforce_rate_limits(&self.state, &self.policy, &request, now).await?;
        let sse_permit = acquire_permit(&self.state, &self.policy, &request)?;

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
            status: StatusCode::FORBIDDEN,
            body: GENERIC_AUTH_MESSAGE,
            retry_after: None,
        }
    }

    pub(super) fn forbidden_ip() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
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
