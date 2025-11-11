use super::{
    limits::{SecurityPolicy, SecurityState},
    session::{SessionCandidate, SessionError, SessionManager},
    IpMatcher, SecurityRejection, TokenKey, WebRoute,
};
use crate::application::logging::LogEvent;
use crate::application::web::{SESSION_COOKIE_NAME, TOKEN_COOKIE_NAME};
use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHashString, PasswordVerifier,
    },
    Algorithm, Argon2,
};
use axum::{
    extract::ConnectInfo,
    http::{
        header::{AUTHORIZATION, COOKIE},
        request::Parts,
    },
};
use percent_encoding::percent_decode_str;
use std::{borrow::Cow, net::SocketAddr, time::Instant};
use tracing::error;

#[derive(Debug, Clone)]
pub(super) struct AuthRequest {
    pub(super) route: WebRoute,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) credential: Credential,
    pub(super) token_key: TokenKey,
    pub(super) require_token: bool,
    pub(super) trusted_ip: bool,
}

#[derive(Debug, Clone)]
pub(super) enum Credential {
    None,
    RawToken(String),
    Session(SessionCandidate),
}

#[derive(Clone)]
pub(super) struct TokenVerifier {
    inner: TokenVerifierInner,
}

#[derive(Clone)]
enum TokenVerifierInner {
    Argon2id { hash: PasswordHashString },
    Bcrypt { hash: String },
}

impl TokenVerifier {
    pub(super) fn parse(encoded: &str) -> Result<Self, String> {
        let trimmed = encoded.trim();
        if trimmed.is_empty() {
            return Err("hash de jeton vide".into());
        }

        if trimmed.starts_with("$argon2id$") {
            let hash = PasswordHashString::new(trimmed)
                .map_err(|err| format!("hash Argon2id invalide: {err}"))?;
            let algo = hash.password_hash().algorithm;
            if algo != Algorithm::Argon2id.into() {
                return Err(format!(
                    "algorithme Argon2 non supporté: {algo:?} (attendu Argon2id)"
                ));
            }
            return Ok(TokenVerifier {
                inner: TokenVerifierInner::Argon2id { hash },
            });
        }

        if trimmed.starts_with("$2") {
            match bcrypt::verify("", trimmed) {
                Ok(_) => {
                    return Ok(TokenVerifier {
                        inner: TokenVerifierInner::Bcrypt {
                            hash: trimmed.to_owned(),
                        },
                    });
                }
                Err(err) => {
                    return Err(format!("hash bcrypt invalide: {err}"));
                }
            }
        }

        Err("format de hash non supporté (attendu Argon2id ou bcrypt)".into())
    }

    pub(super) fn verify(&self, candidate: &str) -> Result<bool, TokenVerifyError> {
        match &self.inner {
            TokenVerifierInner::Argon2id { hash } => {
                let parsed: PasswordHash<'_> = hash.password_hash();
                match Argon2::default().verify_password(candidate.as_bytes(), &parsed) {
                    Ok(()) => Ok(true),
                    Err(PasswordHashError::Password) => Ok(false),
                    Err(err) => Err(TokenVerifyError::InvalidHash(err.to_string())),
                }
            }
            TokenVerifierInner::Bcrypt { hash } => match bcrypt::verify(candidate, hash) {
                Ok(result) => Ok(result),
                Err(err) => Err(TokenVerifyError::InvalidHash(err.to_string())),
            },
        }
    }

    pub(super) fn algorithm(&self) -> &'static str {
        match self.inner {
            TokenVerifierInner::Argon2id { .. } => "argon2id",
            TokenVerifierInner::Bcrypt { .. } => "bcrypt",
        }
    }
}

impl std::fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenVerifier")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

#[derive(Debug)]
pub(super) enum TokenVerifyError {
    InvalidHash(String),
}

pub(super) fn build_request(
    allow: &[IpMatcher],
    trusted_proxies: &[IpMatcher],
    sessions: &SessionManager,
    sessions_enabled: bool,
    parts: &Parts,
    route: WebRoute,
    now: Instant,
) -> Result<AuthRequest, SecurityRejection> {
    let remote_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .ok_or_else(|| {
            LogEvent::SecurityIncident {
                category: Cow::Borrowed("missing_remote_ip"),
                route: Cow::Borrowed(route.as_str()),
                ip: None,
                token: None,
                detail: Some(Cow::Borrowed("connect_info_absent")),
            }
            .emit();
            SecurityRejection::missing_ip()
        })?;

    let source_ip = remote_ip;
    let (remote_ip, forwarded) = resolve_client_ip(remote_ip, trusted_proxies, parts, route);

    let trusted_ip = if allow.is_empty() {
        false
    } else {
        allow.iter().any(|rule| rule.matches(remote_ip))
    };

    if !allow.is_empty() && !trusted_ip {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed("ip_not_allowlisted"),
            route: Cow::Borrowed(route.as_str()),
            ip: Some(Cow::Owned(remote_ip.to_string())),
            token: None,
            detail: None,
        }
        .emit();
        return Err(SecurityRejection::forbidden_ip());
    }

    if forwarded {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed("forwarded_for_applied"),
            route: Cow::Borrowed(route.as_str()),
            ip: Some(Cow::Owned(remote_ip.to_string())),
            token: None,
            detail: Some(Cow::Owned(format!("source={source_ip}"))),
        }
        .emit();
    }

    let (credential, token_key) =
        extract_credential(parts, sessions, sessions_enabled, route, remote_ip, now)?;

    Ok(AuthRequest {
        route,
        remote_ip,
        credential,
        token_key,
        require_token: route != WebRoute::Html,
        trusted_ip,
    })
}

pub(super) async fn verify_token(
    state: &SecurityState,
    policy: &SecurityPolicy,
    expected_token: Option<&TokenVerifier>,
    sessions: &SessionManager,
    request: &AuthRequest,
    now: Instant,
) -> Result<Option<String>, SecurityRejection> {
    let Some(expected) = expected_token else {
        return Ok(None);
    };

    match request.credential.clone() {
        Credential::Session(candidate) => {
            sessions.consume(candidate.id(), now).map_err(|err| {
                log_session_error(&err, request);
                SecurityRejection::unauthorized(None)
            })?;
            Ok(Some(sessions.issue(request.token_key, now)))
        }
        Credential::RawToken(token) => {
            let auth_ok = match expected.verify(&token) {
                Ok(true) => true,
                Ok(false) => false,
                Err(err) => {
                    error!(
                        route = request.route.as_str(),
                        algorithm = expected.algorithm(),
                        error = %err_string(&err),
                        "Echec verification hash token"
                    );
                    LogEvent::SecurityIncident {
                        category: Cow::Borrowed("token_hash_error"),
                        route: Cow::Borrowed(request.route.as_str()),
                        ip: Some(Cow::Owned(request.remote_ip.to_string())),
                        token: Some(Cow::Owned(request.token_key.to_string())),
                        detail: Some(Cow::Owned(err_string(&err).to_string())),
                    }
                    .emit();
                    false
                }
            };

            if auth_ok {
                Ok(Some(sessions.issue(request.token_key, now)))
            } else {
                Err(build_failure_rejection(state, policy, request, now, "auth_failure").await)
            }
        }
        Credential::None => {
            if !request.require_token {
                Ok(None)
            } else {
                Err(
                    build_failure_rejection(state, policy, request, now, "auth_missing_token")
                        .await,
                )
            }
        }
    }
}

fn extract_credential(
    parts: &Parts,
    sessions: &SessionManager,
    sessions_enabled: bool,
    route: WebRoute,
    remote_ip: std::net::IpAddr,
    now: Instant,
) -> Result<(Credential, TokenKey), SecurityRejection> {
    if let Some(header_value) = parts.headers.get(AUTHORIZATION) {
        if let Ok(value) = header_value.to_str() {
            let trimmed = value.trim();
            if let Some((scheme, token)) = trimmed.split_once(' ') {
                if scheme.eq_ignore_ascii_case("bearer") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Ok((
                            Credential::RawToken(token.to_owned()),
                            TokenKey::from_value(token),
                        ));
                    }
                }
            }
        }
    }

    if let Some(header_value) = parts.headers.get("x-describe-me-token") {
        if let Ok(value) = header_value.to_str() {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok((
                    Credential::RawToken(trimmed.to_owned()),
                    TokenKey::from_value(trimmed),
                ));
            }
        }
    }

    let mut encoded_session_cookie = None;
    let mut raw_cookie = None;
    if let Some(cookie_header) = parts.headers.get(COOKIE) {
        if let Ok(value) = cookie_header.to_str() {
            for pair in value.split(';') {
                let mut kv = pair.trim().splitn(2, '=');
                let name = kv.next().map(str::trim);
                let Some(raw_value) = kv.next() else {
                    continue;
                };
                let trimmed = raw_value.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if sessions_enabled
                    && encoded_session_cookie.is_none()
                    && name == Some(SESSION_COOKIE_NAME)
                {
                    encoded_session_cookie = Some(trimmed.to_owned());
                    continue;
                }
                if raw_cookie.is_none() && name == Some(TOKEN_COOKIE_NAME) {
                    raw_cookie = Some(trimmed.to_owned());
                }
            }
        }
    }

    if let Some(encoded) = encoded_session_cookie {
        let decoded = match percent_decode_str(&encoded).decode_utf8() {
            Ok(value) => value.into_owned(),
            Err(_) => {
                log_session_error_raw(
                    &SessionError::InvalidFormat,
                    route,
                    remote_ip,
                    TokenKey::Anonymous,
                );
                return Err(SecurityRejection::unauthorized(None));
            }
        };
        match sessions.lookup(&decoded, now) {
            Ok(candidate) => {
                let token_key = candidate.token_key();
                return Ok((Credential::Session(candidate), token_key));
            }
            Err(err) => {
                log_session_error_raw(&err, route, remote_ip, TokenKey::Anonymous);
                return Err(SecurityRejection::unauthorized(None));
            }
        }
    }

    if let Some(raw_value) = raw_cookie {
        let decoded = percent_decode_str(&raw_value)
            .decode_utf8()
            .map(|cow| cow.into_owned())
            .unwrap_or_else(|_| raw_value);
        if !decoded.is_empty() {
            return Ok((
                Credential::RawToken(decoded.clone()),
                TokenKey::from_value(&decoded),
            ));
        }
    }

    Ok((Credential::None, TokenKey::Anonymous))
}

fn resolve_client_ip(
    source_ip: std::net::IpAddr,
    trusted: &[IpMatcher],
    parts: &Parts,
    route: WebRoute,
) -> (std::net::IpAddr, bool) {
    if trusted.is_empty() || !ip_matches(source_ip, trusted) {
        return (source_ip, false);
    }

    let header_value = match parts.headers.get("x-forwarded-for") {
        Some(value) => value,
        None => return (source_ip, false),
    };

    let Ok(header_str) = header_value.to_str() else {
        log_forwarded_error("forwarded_for_invalid", route, source_ip, "non_utf8");
        return (source_ip, false);
    };

    let mut ip_chain = Vec::new();
    for segment in header_str.split(',') {
        let token = segment.trim();
        if token.is_empty() {
            continue;
        }
        match token.parse::<std::net::IpAddr>() {
            Ok(ip) => ip_chain.push(ip),
            Err(_) => {
                log_forwarded_error("forwarded_for_invalid", route, source_ip, token);
                return (source_ip, false);
            }
        }
    }

    if ip_chain.is_empty() {
        return (source_ip, false);
    }

    if ip_chain.iter().skip(1).any(|ip| !ip_matches(*ip, trusted)) {
        log_forwarded_error(
            "forwarded_for_untrusted_chain",
            route,
            source_ip,
            header_str,
        );
        return (source_ip, false);
    }

    let client_ip = ip_chain[0];
    (client_ip, true)
}

fn ip_matches(ip: std::net::IpAddr, rules: &[IpMatcher]) -> bool {
    rules.iter().any(|rule| rule.matches(ip))
}

fn log_forwarded_error(
    category: &'static str,
    route: WebRoute,
    source_ip: std::net::IpAddr,
    detail: &str,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        ip: Some(Cow::Owned(source_ip.to_string())),
        token: None,
        detail: Some(Cow::Owned(detail.to_string())),
    }
    .emit();
}

async fn build_failure_rejection(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
    now: Instant,
    category: &'static str,
) -> SecurityRejection {
    let failure = state
        .note_failure(
            request.remote_ip,
            request.token_key,
            now,
            policy,
            request.route,
        )
        .await;
    if let Some(delay) = failure.retry_after {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed("auth_failure_backoff"),
            route: Cow::Borrowed(request.route.as_str()),
            ip: Some(Cow::Owned(request.remote_ip.to_string())),
            token: Some(Cow::Owned(request.token_key.to_string())),
            detail: Some(Cow::Owned(format!(
                "retry_after_s={:.3}",
                delay.as_secs_f32()
            ))),
        }
        .emit();
        SecurityRejection::unauthorized(Some(delay))
    } else {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed(category),
            route: Cow::Borrowed(request.route.as_str()),
            ip: Some(Cow::Owned(request.remote_ip.to_string())),
            token: Some(Cow::Owned(request.token_key.to_string())),
            detail: None,
        }
        .emit();
        SecurityRejection::unauthorized(None)
    }
}

fn log_session_error(err: &SessionError, request: &AuthRequest) {
    log_session_error_raw(err, request.route, request.remote_ip, request.token_key);
}

fn log_session_error_raw(
    err: &SessionError,
    route: WebRoute,
    ip: std::net::IpAddr,
    token: TokenKey,
) {
    let category = match err {
        SessionError::InvalidFormat => "session_invalid_format",
        SessionError::Unknown => "session_unknown",
        SessionError::Expired => "session_expired",
        SessionError::Replay => "session_replay",
    };
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        ip: Some(Cow::Owned(ip.to_string())),
        token: Some(Cow::Owned(token.to_string())),
        detail: None,
    }
    .emit();
}
fn err_string(err: &TokenVerifyError) -> &str {
    match err {
        TokenVerifyError::InvalidHash(msg) => msg.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::web::security::{
        limits::{SecurityPolicy, SecurityState},
        session::SessionManager,
        WebRoute,
    };
    use axum::http::{header::COOKIE, Request, StatusCode};
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::OnceLock;

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

    fn argon2_hash(secret: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut rand_core::OsRng);
        Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .expect("hash password")
            .to_string()
    }

    fn cached_argon2() -> &'static str {
        static HASH: OnceLock<String> = OnceLock::new();
        HASH.get_or_init(|| argon2_hash("secret"))
    }

    #[tokio::test]
    async fn verify_token_accepts_valid_bearer() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));
        let now = Instant::now();
        let request =
            build_request(&[], &[], &sessions, true, &parts, WebRoute::Html, now).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
            .await
            .expect("token should be accepted");
    }

    #[tokio::test]
    async fn verify_token_rejects_missing_when_required() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let now = Instant::now();
        let request = build_request(&[], &[], &sessions, true, &parts, WebRoute::Sse, now).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        let err = verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
            .await
            .expect_err("missing token should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_token_allows_missing_for_html() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let now = Instant::now();
        let request =
            build_request(&[], &[], &sessions, true, &parts, WebRoute::Html, now).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
            .await
            .expect("html route should allow missing token");
    }

    #[tokio::test]
    async fn verify_token_accepts_cookie() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let request = Request::builder().uri("/sse").body(()).unwrap();
        let (mut parts, _) = request.into_parts();
        parts.headers.insert(
            COOKIE,
            format!("{TOKEN_COOKIE_NAME}=secret").parse().unwrap(),
        );
        parts
            .extensions
            .insert(ConnectInfo(std::net::SocketAddr::from((
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                4242,
            ))));

        let now = Instant::now();
        let auth_request =
            build_request(&[], &[], &sessions, true, &parts, WebRoute::Sse, now).unwrap();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(
            &state,
            &policy,
            Some(&verifier),
            &sessions,
            &auth_request,
            now,
        )
        .await
        .expect("cookie token should be accepted");
    }

    #[tokio::test]
    async fn verify_token_accepts_session_cookie() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();

        let token_key = TokenKey::from_value("secret");
        let now = Instant::now();
        let cookie_value = sessions.issue(token_key, now);
        let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

        let request = Request::builder().uri("/sse").body(()).unwrap();
        let (mut parts, _) = request.into_parts();
        parts.headers.insert(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
        );
        parts
            .extensions
            .insert(ConnectInfo(std::net::SocketAddr::from((
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                4242,
            ))));

        let auth_request =
            build_request(&[], &[], &sessions, true, &parts, WebRoute::Sse, now).unwrap();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(
            &state,
            &policy,
            Some(&verifier),
            &sessions,
            &auth_request,
            now,
        )
        .await
        .expect("session cookie should be accepted");
    }

    #[tokio::test]
    async fn trusted_proxy_overrides_client_ip() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
        parts.headers.insert(
            "x-forwarded-for",
            "198.51.100.25, 192.0.2.10".parse().unwrap(),
        );
        let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
        let now = Instant::now();
        let request =
            build_request(&[], &trusted, &sessions, true, &parts, WebRoute::Html, now).unwrap();
        assert_eq!(
            request.remote_ip,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
        );
        assert_ne!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[tokio::test]
    async fn untrusted_proxy_header_is_ignored() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), None);
        parts
            .headers
            .insert("x-forwarded-for", "198.51.100.25".parse().unwrap());
        let now = Instant::now();
        let request =
            build_request(&[], &[], &sessions, true, &parts, WebRoute::Html, now).unwrap();
        assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn parse_rejects_plaintext() {
        let err = TokenVerifier::parse("not-a-hash").expect_err("plaintext should be rejected");
        assert!(err.contains("non supporté"));
    }
}
