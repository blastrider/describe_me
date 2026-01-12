use super::super::{
    session::{ClientClaim, SessionCandidate, SessionError, SessionManager},
    IpMatcher, SecurityRejection, TokenFingerprint, TokenKey, WebRoute,
};
use super::forwarded::resolve_client_ip;
use super::logging::{log_session_error_raw, log_session_token_mismatch};
use crate::application::logging::LogEvent;
use crate::application::web::SESSION_COOKIE_NAME;
use axum::{
    extract::ConnectInfo,
    http::{
        header::{AUTHORIZATION, COOKIE, USER_AGENT},
        request::Parts,
    },
};
use percent_encoding::percent_decode_str;
use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Instant};

#[derive(Debug, Clone)]
pub(in crate::application::web::security) struct AuthRequest {
    pub(in crate::application::web::security) route: WebRoute,
    pub(in crate::application::web::security) request_path: Arc<str>,
    pub(in crate::application::web::security) remote_ip: std::net::IpAddr,
    pub(in crate::application::web::security) credential: Credential,
    pub(in crate::application::web::security) token_key: TokenKey,
    pub(in crate::application::web::security) require_token: bool,
    pub(in crate::application::web::security) trusted_ip: bool,
    pub(in crate::application::web::security) purge_session_cookie: bool,
    pub(in crate::application::web::security) client_claim: Option<ClientClaim>,
}

#[derive(Debug, Clone)]
pub(in crate::application::web::security) enum Credential {
    None,
    RawToken(String),
    Session(SessionCandidate),
}

#[derive(Debug, Clone)]
pub(in crate::application::web::security) enum CredentialOverride {
    RawToken(String),
}

#[derive(Debug, Clone)]
struct CredentialExtraction {
    credential: Credential,
    token_key: TokenKey,
    purge_session_cookie: bool,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::application::web::security) async fn build_request(
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
