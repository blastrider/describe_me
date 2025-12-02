use axum::{
    body::to_bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;

use super::{
    security::{attach_session_cookie, SecurityRejection, WebRoute},
    AppState, AxumRequest,
};

pub(crate) const SESSION_COOKIE_NAME: &str = "describe_me_session";

pub(crate) fn set_session_cookie(
    headers: &mut HeaderMap,
    value: &str,
    max_age: std::time::Duration,
    secure: bool,
) {
    if value.is_empty() {
        return;
    }

    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let mut suffix = String::from("; HttpOnly; SameSite=Lax");
    if secure {
        suffix.push_str("; Secure");
    }
    let max_age_secs = max_age.as_secs().clamp(1, u64::from(u32::MAX));
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}{suffix}",
        name = SESSION_COOKIE_NAME,
        value = encoded,
        max_age = max_age_secs,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(crate) fn clear_session_cookie(headers: &mut HeaderMap, secure: bool) {
    let mut suffix = String::from("; HttpOnly; SameSite=Lax");
    if secure {
        suffix.push_str("; Secure");
    }
    let cookie = format!(
        "{name}=deleted; Path=/; Max-Age=0{suffix}",
        name = SESSION_COOKIE_NAME,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

#[derive(Deserialize)]
pub(super) struct TokenPayload {
    token: String,
}

pub(super) async fn login(State(state): State<AppState>, request: AxumRequest) -> Response {
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, 8 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Requête invalide." })),
            )
                .into_response();
        }
    };

    let token = match extract_token(&body_bytes) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Merci de fournir un jeton." })),
            )
                .into_response();
        }
    };

    match state.security.login(&parts, &token, WebRoute::Html).await {
        Ok(session) => {
            let mut response = Redirect::to("/").into_response();
            attach_session_cookie(response.headers_mut(), &session, &state);
            response
        }
        Err(rejection) => auth_error_response(rejection, state.session_cookie_secure),
    }
}

pub(super) async fn logout(State(state): State<AppState>) -> Response {
    let mut response = Redirect::to("/").into_response();
    clear_session_cookie(response.headers_mut(), state.session_cookie_secure);
    response
}

fn extract_token(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }

    if let Ok(payload) = serde_json::from_slice::<TokenPayload>(body) {
        let trimmed = payload.token.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }

    if let Ok(payload) = serde_urlencoded::from_bytes::<TokenPayload>(body) {
        let trimmed = payload.token.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }

    None
}

fn auth_error_response(rejection: SecurityRejection, secure_cookie: bool) -> Response {
    rejection.into_response(secure_cookie, None)
}
