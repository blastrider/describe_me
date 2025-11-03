use super::{
    limits::{SecurityPolicy, SecurityState},
    IpMatcher, SecurityRejection, TokenKey, WebRoute,
};
use crate::application::web::TOKEN_COOKIE_NAME;
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
use std::{net::SocketAddr, time::Instant};
use tracing::{error, warn};

#[derive(Debug, Clone)]
pub(super) struct AuthRequest {
    pub(super) route: WebRoute,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) provided_token: Option<String>,
    pub(super) token_key: TokenKey,
    pub(super) require_token: bool,
    pub(super) trusted_ip: bool,
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
    parts: &Parts,
    route: WebRoute,
) -> Result<AuthRequest, SecurityRejection> {
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

    let trusted_ip = if allow.is_empty() {
        false
    } else {
        allow.iter().any(|rule| rule.matches(remote_ip))
    };

    if !allow.is_empty() && !trusted_ip {
        warn!(
            ip = %remote_ip,
            route = route.as_str(),
            "IP refusée par la allowlist"
        );
        return Err(SecurityRejection::forbidden_ip());
    }

    let provided_token = extract_token(parts);
    let token_key = provided_token
        .as_ref()
        .map(|value| TokenKey::from_value(value))
        .unwrap_or(TokenKey::Anonymous);

    Ok(AuthRequest {
        route,
        remote_ip,
        provided_token,
        token_key,
        require_token: route != WebRoute::Html,
        trusted_ip,
    })
}

pub(super) async fn verify_token(
    state: &SecurityState,
    policy: &SecurityPolicy,
    expected_token: Option<&TokenVerifier>,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    let Some(expected) = expected_token else {
        return Ok(());
    };

    let auth_ok = request
        .provided_token
        .as_deref()
        .map(|provided| match expected.verify(provided) {
            Ok(true) => true,
            Ok(false) => false,
            Err(err) => {
                error!(
                    route = request.route.as_str(),
                    algorithm = expected.algorithm(),
                    error = %err_string(&err),
                    "Echec verification hash token"
                );
                false
            }
        })
        .unwrap_or(false);

    let missing = request.provided_token.is_none();
    let missing_allowed = missing && !request.require_token;

    if auth_ok || missing_allowed {
        return Ok(());
    }

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
        warn!(
            ip = %request.remote_ip,
            route = request.route.as_str(),
            token = %request.token_key,
            retry_after = %delay.as_secs_f32(),
            "Echec authentification (backoff)"
        );
        Err(SecurityRejection::unauthorized(Some(delay)))
    } else {
        warn!(
            ip = %request.remote_ip,
            route = request.route.as_str(),
            token = %request.token_key,
            "Echec authentification"
        );
        Err(SecurityRejection::unauthorized(None))
    }
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

    if let Some(cookie_header) = parts.headers.get(COOKIE) {
        if let Ok(value) = cookie_header.to_str() {
            for pair in value.split(';') {
                let mut kv = pair.trim().splitn(2, '=');
                let name = kv.next().map(str::trim);
                if name != Some(TOKEN_COOKIE_NAME) {
                    continue;
                }
                if let Some(raw_value) = kv.next() {
                    let trimmed = raw_value.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let decoded = percent_decode_str(trimmed)
                        .decode_utf8()
                        .map(|cow| cow.into_owned())
                        .unwrap_or_else(|_| trimmed.to_owned());
                    if !decoded.is_empty() {
                        return Some(decoded);
                    }
                }
            }
        }
    }

    None
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
        WebRoute,
    };
    use axum::http::{header::COOKIE, Request, StatusCode};
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
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));
        let request = build_request(&[], &parts, WebRoute::Html).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(&state, &policy, Some(&verifier), &request, Instant::now())
            .await
            .expect("token should be accepted");
    }

    #[tokio::test]
    async fn verify_token_rejects_missing_when_required() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let request = build_request(&[], &parts, WebRoute::Sse).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        let err = verify_token(&state, &policy, Some(&verifier), &request, Instant::now())
            .await
            .expect_err("missing token should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_token_allows_missing_for_html() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let request = build_request(&[], &parts, WebRoute::Html).unwrap();

        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(&state, &policy, Some(&verifier), &request, Instant::now())
            .await
            .expect("html route should allow missing token");
    }

    #[tokio::test]
    async fn verify_token_accepts_cookie() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
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

        let auth_request = build_request(&[], &parts, WebRoute::Sse).unwrap();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        verify_token(
            &state,
            &policy,
            Some(&verifier),
            &auth_request,
            Instant::now(),
        )
        .await
        .expect("cookie token should be accepted");
    }

    #[test]
    fn parse_rejects_plaintext() {
        let err = TokenVerifier::parse("not-a-hash").expect_err("plaintext should be rejected");
        assert!(err.contains("non supporté"));
    }
}
