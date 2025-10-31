use super::{
    limits::{SecurityPolicy, SecurityState},
    IpMatcher, SecurityRejection, TokenKey, WebRoute,
};
use axum::{
    extract::ConnectInfo,
    http::{header::AUTHORIZATION, request::Parts},
};
use std::{net::SocketAddr, time::Instant};
use subtle::ConstantTimeEq;
use tracing::warn;

#[derive(Debug, Clone)]
pub(super) struct AuthRequest {
    pub(super) route: WebRoute,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) provided_token: Option<String>,
    pub(super) token_key: TokenKey,
    pub(super) require_token: bool,
    pub(super) trusted_ip: bool,
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
    expected_token: Option<&str>,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    let Some(expected) = expected_token else {
        return Ok(());
    };

    let auth_ok = request
        .provided_token
        .as_deref()
        .map(|provided| tokens_match(expected, provided))
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
    use crate::application::web::security::{
        limits::{SecurityPolicy, SecurityState},
        WebRoute,
    };
    use axum::http::{Request, StatusCode};
    use std::net::{IpAddr, Ipv4Addr};

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
    async fn verify_token_accepts_valid_bearer() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));
        let request = build_request(&[], &parts, WebRoute::Html).unwrap();

        verify_token(&state, &policy, Some("secret"), &request, Instant::now())
            .await
            .expect("token should be accepted");
    }

    #[tokio::test]
    async fn verify_token_rejects_missing_when_required() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let request = build_request(&[], &parts, WebRoute::Sse).unwrap();

        let err = verify_token(&state, &policy, Some("secret"), &request, Instant::now())
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

        verify_token(&state, &policy, Some("secret"), &request, Instant::now())
            .await
            .expect("html route should allow missing token");
    }
}
