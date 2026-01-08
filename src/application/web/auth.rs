use axum::{
    body::to_bytes,
    extract::{ConnectInfo, State},
    http::{
        header::{COOKIE, ORIGIN, USER_AGENT},
        StatusCode,
    },
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;
use std::{borrow::Cow, net::SocketAddr, time::Instant};

use crate::application::{error::ErrorBody, logging::LogEvent};
use crate::domain::SessionCookieSameSite;

use super::{
    security::{SecurityRejection, WebRoute, WebSession, SESSION_COOKIE_NAME},
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
                Json(ErrorBody {
                    error: "Requête invalide.".into(),
                }),
            )
                .into_response();
        }
    };

    let token = match extract_token(&body_bytes) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "Merci de fournir un jeton.".into(),
                }),
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
            if let Some(fingerprint) = security.token_fingerprint() {
                let user_agent = parts
                    .headers
                    .get(USER_AGENT)
                    .and_then(|value| value.to_str().ok());
                let client_claim = security.client_claim(session.ip(), user_agent);
                web_session
                    .issue_for(
                        session.token_key(),
                        fingerprint,
                        client_claim,
                        response.headers_mut(),
                        std::time::Instant::now(),
                        state.session_cookie_secure(),
                        state.session_cookie_same_site(),
                    )
                    .await;
            }
            response
        }
        Err(rejection) => auth_error_response(
            rejection,
            state.session_cookie_secure(),
            state.session_cookie_same_site(),
        ),
    }
}

pub(super) async fn logout(State(state): State<AppState>, request: AxumRequest) -> Response {
    let (parts, _) = request.into_parts();
    let origin = parts
        .headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok());
    let fetch_site = parts
        .headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    if !has_same_origin_signal(origin, fetch_site) {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip().to_string());
        let origin_value = origin.unwrap_or("<none>");
        let fetch_site_value = fetch_site.unwrap_or("<none>");
        LogEvent::SecurityIncident {
            category: Cow::Borrowed("csrf_logout_missing_signal"),
            route: Cow::Owned(parts.uri.path().to_string()),
            request_path: Some(Cow::Owned(parts.uri.path().to_string())),
            ip: ip.map(Cow::Owned),
            token: None,
            detail: Some(Cow::Owned(format!(
                "origin={origin_value} sec_fetch_site={fetch_site_value}"
            ))),
        }
        .emit();
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut response = Redirect::to("/").into_response();
    let security = state.security();
    let web_session = WebSession {
        manager: security.session_manager(),
    };
    let mut should_clear = false;
    if let Some(cookie_header) = parts
        .headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        should_clear = has_session_cookie(cookie_header);
        if should_clear {
            web_session
                .revoke_from_cookie_header(cookie_header, Instant::now())
                .await;
        }
    }
    if should_clear {
        web_session.clear(
            response.headers_mut(),
            state.session_cookie_secure(),
            state.session_cookie_same_site(),
        );
    }
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

fn has_same_origin_signal(origin: Option<&str>, fetch_site: Option<&str>) -> bool {
    if let Some(origin) = origin {
        let trimmed = origin.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("null") {
            return true;
        }
    }
    if let Some(fetch_site) = fetch_site {
        let trimmed = fetch_site.trim();
        if trimmed.eq_ignore_ascii_case("same-origin") || trimmed.eq_ignore_ascii_case("same-site")
        {
            return true;
        }
    }
    false
}

fn has_session_cookie(cookie_header: &str) -> bool {
    for pair in cookie_header.split(';') {
        let mut kv = pair.trim().splitn(2, '=');
        let name = kv.next().map(str::trim);
        if name == Some(SESSION_COOKIE_NAME) {
            return true;
        }
    }
    false
}

fn auth_error_response(
    rejection: SecurityRejection,
    secure_cookie: bool,
    same_site: SessionCookieSameSite,
) -> Response {
    rejection.into_response(secure_cookie, same_site, None)
}
