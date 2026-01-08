use super::session::SESSION_COOKIE_PREFIX;
use super::{
    limits::{SecurityPolicy, SecurityState},
    session::{ClientClaim, SessionCandidate, SessionError, SessionManager},
    IpMatcher, SecurityRejection, TokenFingerprint, TokenKey, WebRoute,
};
use crate::application::logging::LogEvent;
use crate::application::web::SESSION_COOKIE_NAME;
use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHashString, PasswordVerifier,
    },
    Algorithm, Argon2,
};
use axum::{
    extract::ConnectInfo,
    http::{
        header::{AUTHORIZATION, COOKIE, FORWARDED, USER_AGENT},
        request::Parts,
    },
};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Instant};
use tracing::error;

const MAX_FORWARDED_HEADER_LEN: usize = 1024;
const MAX_FORWARDED_HOPS: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct AuthRequest {
    pub(super) route: WebRoute,
    pub(super) request_path: Arc<str>,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) credential: Credential,
    pub(super) token_key: TokenKey,
    pub(super) require_token: bool,
    pub(super) trusted_ip: bool,
    pub(super) purge_session_cookie: bool,
    pub(super) client_claim: Option<ClientClaim>,
}

#[derive(Debug, Clone)]
pub(super) enum Credential {
    None,
    RawToken(String),
    Session(SessionCandidate),
}

#[derive(Debug, Clone)]
struct CredentialExtraction {
    credential: Credential,
    token_key: TokenKey,
    purge_session_cookie: bool,
}

#[derive(Clone)]
pub(super) struct TokenVerifier {
    inner: TokenVerifierInner,
    fingerprint: TokenFingerprint,
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

        let fingerprint = fingerprint_token(trimmed);
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
                fingerprint,
            });
        }

        if trimmed.starts_with("$2") {
            match bcrypt::verify("", trimmed) {
                Ok(_) => {
                    return Ok(TokenVerifier {
                        inner: TokenVerifierInner::Bcrypt {
                            hash: trimmed.to_owned(),
                        },
                        fingerprint,
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

    pub(super) fn fingerprint(&self) -> TokenFingerprint {
        self.fingerprint
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

#[derive(Debug, Clone)]
pub(super) enum CredentialOverride {
    RawToken(String),
}

fn fingerprint_token(value: &str) -> TokenFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut fingerprint = [0u8; 16];
    fingerprint.copy_from_slice(&digest[..16]);
    fingerprint
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn build_request(
    allow: &[IpMatcher],
    trusted_proxies: &[IpMatcher],
    sessions: &SessionManager,
    sessions_enabled: bool,
    expected_fingerprint: Option<TokenFingerprint>,
    parts: &Parts,
    route: WebRoute,
    now: Instant,
    credential_override: Option<CredentialOverride>,
) -> Result<AuthRequest, SecurityRejection> {
    let request_path: Arc<str> = parts.uri.path().to_owned().into();
    let remote_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .ok_or_else(|| {
            LogEvent::SecurityIncident {
                category: Cow::Borrowed("missing_remote_ip"),
                route: Cow::Borrowed(route.as_str()),
                request_path: Some(Cow::Borrowed(request_path.as_ref())),
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
            request_path: Some(Cow::Borrowed(request_path.as_ref())),
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
            request_path: Some(Cow::Borrowed(request_path.as_ref())),
            ip: Some(Cow::Owned(remote_ip.to_string())),
            token: None,
            detail: Some(Cow::Owned(format!("source={source_ip}"))),
        }
        .emit();
    }

    let user_agent = parts
        .headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let client_claim = if sessions_enabled {
        sessions.client_claim(remote_ip, user_agent)
    } else {
        None
    };

    let has_override = credential_override.is_some();
    let extraction = match credential_override.as_ref() {
        Some(CredentialOverride::RawToken(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(SecurityRejection::unauthorized(None));
            }
            CredentialExtraction {
                credential: Credential::RawToken(trimmed.to_owned()),
                token_key: TokenKey::from_value(trimmed),
                purge_session_cookie: false,
            }
        }
        None => {
            extract_credential(
                parts,
                sessions,
                sessions_enabled,
                expected_fingerprint,
                client_claim,
                route,
                request_path.as_ref(),
                remote_ip,
                now,
            )
            .await?
        }
    };

    Ok(AuthRequest {
        route,
        request_path,
        remote_ip,
        credential: extraction.credential,
        token_key: extraction.token_key,
        require_token: has_override || route.requires_token(),
        trusted_ip,
        purge_session_cookie: extraction.purge_session_cookie,
        client_claim,
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
            sessions.consume(candidate.id(), now).await.map_err(|err| {
                log_session_error(&err, request);
                SecurityRejection::unauthorized(None)
            })?;
            Ok(Some(format!("{SESSION_COOKIE_PREFIX}{}", candidate.id())))
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
                        request_path: Some(Cow::Borrowed(request.request_path.as_ref())),
                        ip: Some(Cow::Owned(request.remote_ip.to_string())),
                        token: Some(Cow::Owned(request.token_key.to_string())),
                        detail: Some(Cow::Owned(err_string(&err).to_string())),
                    }
                    .emit();
                    false
                }
            };

            if auth_ok {
                Ok(Some(
                    sessions
                        .issue(
                            request.token_key,
                            expected.fingerprint(),
                            request.client_claim,
                            now,
                        )
                        .await,
                ))
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

#[allow(clippy::too_many_arguments)]
async fn extract_credential(
    parts: &Parts,
    sessions: &SessionManager,
    sessions_enabled: bool,
    expected_fingerprint: Option<TokenFingerprint>,
    client_claim: Option<ClientClaim>,
    route: WebRoute,
    request_path: &str,
    remote_ip: std::net::IpAddr,
    now: Instant,
) -> Result<CredentialExtraction, SecurityRejection> {
    let mut purge_session_cookie = false;

    if sessions_enabled {
        let mut encoded_session_cookie = None;
        let mut saw_session_cookie = false;
        if let Some(cookie_header) = parts.headers.get(COOKIE) {
            if let Ok(value) = cookie_header.to_str() {
                for pair in value.split(';') {
                    let mut kv = pair.trim().splitn(2, '=');
                    let name = kv.next().map(str::trim);
                    let Some(raw_value) = kv.next() else {
                        continue;
                    };
                    if name != Some(SESSION_COOKIE_NAME) {
                        continue;
                    }
                    saw_session_cookie = true;
                    let trimmed = raw_value.trim();
                    if trimmed.is_empty() {
                        purge_session_cookie = true;
                        log_session_error_raw(
                            &SessionError::InvalidFormat,
                            route,
                            Some(request_path),
                            remote_ip,
                            TokenKey::Anonymous,
                        );
                        continue;
                    }
                    if encoded_session_cookie.is_none() {
                        encoded_session_cookie = Some(trimmed.to_owned());
                    }
                }
            }
        }

        if saw_session_cookie && encoded_session_cookie.is_none() && !purge_session_cookie {
            purge_session_cookie = true;
            log_session_error_raw(
                &SessionError::InvalidFormat,
                route,
                Some(request_path),
                remote_ip,
                TokenKey::Anonymous,
            );
        }

        if let Some(encoded) = encoded_session_cookie {
            let decoded = match percent_decode_str(&encoded).decode_utf8() {
                Ok(value) => value.into_owned(),
                Err(_) => {
                    log_session_error_raw(
                        &SessionError::InvalidFormat,
                        route,
                        Some(request_path),
                        remote_ip,
                        TokenKey::Anonymous,
                    );
                    String::new()
                }
            };
            if decoded.is_empty() {
                purge_session_cookie = true;
            } else {
                match sessions.lookup(&decoded, client_claim, now).await {
                    Ok(candidate) => {
                        if expected_fingerprint
                            .is_none_or(|expected| candidate.token_fingerprint() != expected)
                        {
                            purge_session_cookie = true;
                            sessions.revoke(candidate.id()).await;
                            log_session_token_mismatch(route, Some(request_path), remote_ip);
                        } else {
                            let token_key = candidate.token_key();
                            return Ok(CredentialExtraction {
                                credential: Credential::Session(candidate),
                                token_key,
                                purge_session_cookie: false,
                            });
                        }
                    }
                    Err(err) => {
                        purge_session_cookie = true;
                        log_session_error_raw(
                            &err,
                            route,
                            Some(request_path),
                            remote_ip,
                            TokenKey::Anonymous,
                        );
                    }
                }
            }
            // Invalid session cookie: logged above, fall through to other credentials.
        }
    }

    if let Some(header_value) = parts.headers.get(AUTHORIZATION) {
        if let Ok(value) = header_value.to_str() {
            let trimmed = value.trim();
            if let Some((scheme, token)) = trimmed.split_once(' ') {
                if scheme.eq_ignore_ascii_case("bearer") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Ok(CredentialExtraction {
                            credential: Credential::RawToken(token.to_owned()),
                            token_key: TokenKey::from_value(token),
                            purge_session_cookie,
                        });
                    }
                }
            }
        }
    }

    if let Some(header_value) = parts.headers.get("x-describe-me-token") {
        if let Ok(value) = header_value.to_str() {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(CredentialExtraction {
                    credential: Credential::RawToken(trimmed.to_owned()),
                    token_key: TokenKey::from_value(trimmed),
                    purge_session_cookie,
                });
            }
        }
    }

    Ok(CredentialExtraction {
        credential: Credential::None,
        token_key: TokenKey::Anonymous,
        purge_session_cookie,
    })
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

    if let Some(header_value) = parts.headers.get("x-forwarded-for") {
        let Ok(header_str) = header_value.to_str() else {
            log_forwarded_error(
                "forwarded_for_invalid",
                route,
                Some(parts.uri.path()),
                source_ip,
                "non_utf8",
            );
            return (source_ip, false);
        };
        if header_str.len() > MAX_FORWARDED_HEADER_LEN {
            log_forwarded_error(
                "forwarded_for_too_long",
                route,
                Some(parts.uri.path()),
                source_ip,
                "too_long",
            );
            return (source_ip, false);
        }

        let mut ip_chain = Vec::new();
        for segment in header_str.split(',') {
            let token = segment.trim();
            if token.is_empty() {
                continue;
            }
            if ip_chain.len() >= MAX_FORWARDED_HOPS {
                log_forwarded_error(
                    "forwarded_for_too_many",
                    route,
                    Some(parts.uri.path()),
                    source_ip,
                    "too_many_hops",
                );
                return (source_ip, false);
            }
            match token.parse::<std::net::IpAddr>() {
                Ok(ip) => ip_chain.push(ip),
                Err(_) => {
                    log_forwarded_error(
                        "forwarded_for_invalid",
                        route,
                        Some(parts.uri.path()),
                        source_ip,
                        token,
                    );
                    return (source_ip, false);
                }
            }
        }

        if ip_chain.is_empty() {
            return (source_ip, false);
        }

        if ip_chain.last() != Some(&source_ip) {
            log_forwarded_error(
                "forwarded_for_source_mismatch",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }

        if ip_chain.iter().skip(1).any(|ip| !ip_matches(*ip, trusted)) {
            log_forwarded_error(
                "forwarded_for_untrusted_chain",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }

        let client_ip = ip_chain[0];
        return (client_ip, true);
    }

    let header_value = match parts.headers.get(FORWARDED) {
        Some(value) => value,
        None => return (source_ip, false),
    };

    let Ok(header_str) = header_value.to_str() else {
        log_forwarded_error(
            "forwarded_header_invalid",
            route,
            Some(parts.uri.path()),
            source_ip,
            "non_utf8",
        );
        return (source_ip, false);
    };
    if header_str.len() > MAX_FORWARDED_HEADER_LEN {
        log_forwarded_error(
            "forwarded_header_too_long",
            route,
            Some(parts.uri.path()),
            source_ip,
            "too_long",
        );
        return (source_ip, false);
    }

    let (ip_chain, by_ip) = match parse_forwarded_chain(header_str, MAX_FORWARDED_HOPS) {
        Ok(value) => value,
        Err(detail) => {
            log_forwarded_error(
                "forwarded_header_invalid",
                route,
                Some(parts.uri.path()),
                source_ip,
                &detail,
            );
            return (source_ip, false);
        }
    };

    if ip_chain.is_empty() {
        return (source_ip, false);
    }

    if let Some(by_ip) = by_ip {
        if by_ip != source_ip {
            log_forwarded_error(
                "forwarded_header_source_mismatch",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }
    }

    if ip_chain.iter().skip(1).any(|ip| !ip_matches(*ip, trusted)) {
        log_forwarded_error(
            "forwarded_header_untrusted_chain",
            route,
            Some(parts.uri.path()),
            source_ip,
            header_str,
        );
        return (source_ip, false);
    }

    let client_ip = ip_chain[0];
    (client_ip, true)
}

fn parse_forwarded_chain(
    header_str: &str,
    max_hops: usize,
) -> Result<(Vec<std::net::IpAddr>, Option<std::net::IpAddr>), String> {
    let mut chain = Vec::new();
    let mut last_by = None;

    for segment in header_str.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if chain.len() >= max_hops {
            return Err("too_many_hops".to_string());
        }

        let mut for_ip = None;
        let mut by_ip = None;
        for directive in segment.split(';') {
            let mut kv = directive.splitn(2, '=');
            let key = kv.next().map(str::trim);
            let Some(raw_val) = kv.next() else {
                continue;
            };
            let raw_val = raw_val.trim();
            if raw_val.is_empty() {
                continue;
            }

            if key.map(|value| value.eq_ignore_ascii_case("for")) == Some(true) {
                let ip = parse_forwarded_ip(raw_val).ok_or_else(|| raw_val.to_string())?;
                for_ip = Some(ip);
            } else if key.map(|value| value.eq_ignore_ascii_case("by")) == Some(true) {
                if let Some(ip) = parse_forwarded_ip(raw_val) {
                    by_ip = Some(ip);
                }
            }
        }

        let Some(ip) = for_ip else {
            return Err(segment.to_string());
        };
        chain.push(ip);
        last_by = by_ip;
    }

    if chain.is_empty() {
        return Err(header_str.trim().to_string());
    }

    Ok((chain, last_by))
}

fn parse_forwarded_ip(raw: &str) -> Option<std::net::IpAddr> {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") || trimmed.starts_with('_') {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip_str = &rest[..end];
        return ip_str.parse().ok();
    }

    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(ip);
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        return host.parse::<std::net::IpAddr>().ok();
    }

    None
}

fn ip_matches(ip: std::net::IpAddr, rules: &[IpMatcher]) -> bool {
    rules.iter().any(|rule| rule.matches(ip))
}

fn log_forwarded_error(
    category: &'static str,
    route: WebRoute,
    request_path: Option<&str>,
    source_ip: std::net::IpAddr,
    detail: &str,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
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
    if let Some(delay) = failure.retry_after() {
        LogEvent::SecurityIncident {
            category: Cow::Borrowed("auth_failure_backoff"),
            route: Cow::Borrowed(request.route.as_str()),
            request_path: Some(Cow::Borrowed(request.request_path.as_ref())),
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
            request_path: Some(Cow::Borrowed(request.request_path.as_ref())),
            ip: Some(Cow::Owned(request.remote_ip.to_string())),
            token: Some(Cow::Owned(request.token_key.to_string())),
            detail: None,
        }
        .emit();
        SecurityRejection::unauthorized(None)
    }
}

fn log_session_error(err: &SessionError, request: &AuthRequest) {
    log_session_error_raw(
        err,
        request.route,
        Some(request.request_path.as_ref()),
        request.remote_ip,
        request.token_key,
    );
}

fn log_session_error_raw(
    err: &SessionError,
    route: WebRoute,
    request_path: Option<&str>,
    ip: std::net::IpAddr,
    token: TokenKey,
) {
    let (category, include_details) = match err {
        SessionError::InvalidFormat => ("session_invalid_format", true),
        SessionError::Unknown => ("session_unknown", true),
        SessionError::Expired => ("session_expired", true),
        SessionError::BindingMismatch => ("session_binding_mismatch", false),
    };
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
        ip: if include_details {
            Some(Cow::Owned(ip.to_string()))
        } else {
            None
        },
        token: if include_details {
            Some(Cow::Owned(token.to_string()))
        } else {
            None
        },
        detail: None,
    }
    .emit();
}

fn log_session_token_mismatch(route: WebRoute, request_path: Option<&str>, ip: std::net::IpAddr) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed("session_token_mismatch"),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
        ip: Some(Cow::Owned(ip.to_string())),
        token: None,
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
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));
        let now = Instant::now();
        let request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier.fingerprint()),
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();

        verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
            .await
            .expect("token should be accepted");
    }

    #[tokio::test]
    async fn verify_token_rejects_missing_when_required() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let now = Instant::now();
        let request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier.fingerprint()),
            &parts,
            WebRoute::Sse,
            now,
            None,
        )
        .await
        .unwrap();

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
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let now = Instant::now();
        let request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier.fingerprint()),
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();

        verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
            .await
            .expect("html route should allow missing token");
    }

    #[tokio::test]
    async fn verify_token_accepts_session_cookie() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");

        let token_key = TokenKey::from_value("secret");
        let now = Instant::now();
        let cookie_value = sessions
            .issue(token_key, verifier.fingerprint(), None, now)
            .await;
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

        let auth_request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier.fingerprint()),
            &parts,
            WebRoute::Sse,
            now,
            None,
        )
        .await
        .unwrap();
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
    async fn session_cookie_rejected_on_token_rotation() {
        let sessions = SessionManager::new();
        let verifier_v1 = TokenVerifier::parse(cached_argon2()).expect("parse hash v1");
        let verifier_v2 = TokenVerifier::parse(&argon2_hash("rotated")).expect("parse hash v2");

        let token_key = TokenKey::from_value("secret");
        let now = Instant::now();
        let cookie_value = sessions
            .issue(token_key, verifier_v1.fingerprint(), None, now)
            .await;
        let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

        let request = Request::builder().uri("/").body(()).unwrap();
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

        let auth_request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier_v2.fingerprint()),
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(auth_request.credential, Credential::None));
        assert_eq!(auth_request.token_key, TokenKey::Anonymous);
        assert!(auth_request.purge_session_cookie);
    }

    #[tokio::test]
    async fn session_cookie_is_ignored_when_sessions_disabled() {
        let sessions = SessionManager::new();
        let token_key = TokenKey::from_value("secret");
        let now = Instant::now();
        let cookie_value = sessions.issue(token_key, [0u8; 16], None, now).await;
        let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

        let request = Request::builder().uri("/").body(()).unwrap();
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

        let auth_request = build_request(
            &[],
            &[],
            &sessions,
            false,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(auth_request.credential, Credential::None));
        assert_eq!(auth_request.token_key, TokenKey::Anonymous);
    }

    #[tokio::test]
    async fn invalid_session_cookie_logs_and_rejects() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let sessions = SessionManager::new();
        let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");

        let request = Request::builder().uri("/sse").body(()).unwrap();
        let (mut parts, _) = request.into_parts();
        parts.headers.insert(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=not-a-session")
                .parse()
                .unwrap(),
        );
        parts
            .extensions
            .insert(ConnectInfo(std::net::SocketAddr::from((
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                4242,
            ))));

        let now = Instant::now();
        let auth_request = build_request(
            &[],
            &[],
            &sessions,
            true,
            Some(verifier.fingerprint()),
            &parts,
            WebRoute::Sse,
            now,
            None,
        )
        .await
        .unwrap();
        let err = verify_token(
            &state,
            &policy,
            Some(&verifier),
            &sessions,
            &auth_request,
            now,
        )
        .await
        .expect_err("invalid session cookie should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allowlist_rejects_ip_with_forbidden_status() {
        let sessions = SessionManager::new();
        let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
        let allow = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
        let now = Instant::now();

        let err = build_request(
            &allow,
            &[],
            &sessions,
            false,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .expect_err("unlisted ip should be rejected");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(!err.is_auth_failure());
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
        let request = build_request(
            &[],
            &trusted,
            &sessions,
            true,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            request.remote_ip,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
        );
        assert_ne!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[tokio::test]
    async fn trusted_proxy_header_requires_source_hop() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
        parts
            .headers
            .insert("x-forwarded-for", "198.51.100.25".parse().unwrap());
        let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
        let now = Instant::now();
        let request = build_request(
            &[],
            &trusted,
            &sessions,
            true,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[tokio::test]
    async fn trusted_proxy_overrides_client_ip_with_forwarded_header() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
        parts.headers.insert(
            "forwarded",
            "for=198.51.100.25;proto=https".parse().unwrap(),
        );
        let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
        let now = Instant::now();
        let request = build_request(
            &[],
            &trusted,
            &sessions,
            true,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            request.remote_ip,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
        );
    }

    #[tokio::test]
    async fn forwarded_header_mismatched_by_is_ignored() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
        parts.headers.insert(
            "forwarded",
            "for=198.51.100.25;by=203.0.113.5".parse().unwrap(),
        );
        let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
        let now = Instant::now();
        let request = build_request(
            &[],
            &trusted,
            &sessions,
            true,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[tokio::test]
    async fn untrusted_proxy_header_is_ignored() {
        let sessions = SessionManager::new();
        let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), None);
        parts
            .headers
            .insert("x-forwarded-for", "198.51.100.25".parse().unwrap());
        let now = Instant::now();
        let request = build_request(
            &[],
            &[],
            &sessions,
            true,
            None,
            &parts,
            WebRoute::Html,
            now,
            None,
        )
        .await
        .unwrap();
        assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn parse_rejects_plaintext() {
        let err = TokenVerifier::parse("not-a-hash").expect_err("plaintext should be rejected");
        assert!(err.contains("non supporté"));
    }
}
