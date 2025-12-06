use axum::{
    body::to_bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;

use super::{
    security::{SecurityRejection, WebRoute, WebSession},
    AppState, AxumRequest,
};

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

    match state.security().login(&parts, &token, WebRoute::Html).await {
        Ok(session) => {
            let mut response = Redirect::to("/").into_response();
            let security = state.security();
            let web_session = WebSession {
                manager: security.session_manager(),
            };
            web_session.issue_for(
                session.token_key(),
                response.headers_mut(),
                std::time::Instant::now(),
                state.session_cookie_secure(),
            );
            response
        }
        Err(rejection) => auth_error_response(rejection, state.session_cookie_secure()),
    }
}

pub(super) async fn logout(State(state): State<AppState>) -> Response {
    let mut response = Redirect::to("/").into_response();
    let security = state.security();
    let web_session = WebSession {
        manager: security.session_manager(),
    };
    web_session.clear(response.headers_mut(), state.session_cookie_secure());
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
