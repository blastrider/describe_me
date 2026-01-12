mod forwarded;
mod logging;
mod request;

#[cfg(test)]
mod tests;

pub(super) use request::{build_request, AuthRequest, Credential, CredentialOverride};

use super::session::SESSION_COOKIE_PREFIX;
use super::{
    limits::{SecurityPolicy, SecurityState},
    session::SessionManager,
    SecurityRejection, TokenFingerprint,
};
use crate::application::logging::LogEvent;
use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHashString, PasswordVerifier,
    },
    Algorithm, Argon2,
};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, time::Instant};
use tracing::error;

use logging::log_session_error;

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

fn fingerprint_token(value: &str) -> TokenFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut fingerprint = [0u8; 16];
    fingerprint.copy_from_slice(&digest[..16]);
    fingerprint
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

fn err_string(err: &TokenVerifyError) -> &str {
    match err {
        TokenVerifyError::InvalidHash(msg) => msg.as_str(),
    }
}
