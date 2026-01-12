use super::super::{
    auth, clear_session_cookie, effective_session_cookie_secure, security, set_session_cookie,
    WebAccess, WebTlsConfig, SESSION_COOKIE_NAME,
};
use crate::application::exposure::Exposure;
use crate::application::test_support::make_secured_app_state;
use crate::domain::SessionCookieSameSite;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::{header, HeaderMap, StatusCode};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

#[test]
fn set_session_cookie_includes_http_only() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        true,
        SessionCookieSameSite::Lax,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("; HttpOnly"),
        "cookie missing HttpOnly: {text}"
    );
    assert!(
        text.contains("SameSite=Lax"),
        "cookie missing SameSite=Lax: {text}"
    );
}

#[test]
fn clear_session_cookie_includes_http_only() {
    let mut headers = HeaderMap::new();
    clear_session_cookie(&mut headers, true, SessionCookieSameSite::Lax);
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("; HttpOnly"),
        "clear cookie missing HttpOnly: {text}"
    );
}

#[test]
fn session_cookies_include_secure() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        true,
        SessionCookieSameSite::Lax,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("; Secure"),
        "cookie missing Secure attribute: {text}"
    );
}

#[test]
fn session_cookie_secure_flag_can_be_disabled() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        false,
        SessionCookieSameSite::Lax,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        !text.contains("; Secure"),
        "insecure cookies should skip Secure: {text}"
    );
}

#[test]
fn set_session_cookie_supports_samesite_strict() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        true,
        SessionCookieSameSite::Strict,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("SameSite=Strict"),
        "cookie missing SameSite=Strict: {text}"
    );
}

#[test]
fn set_session_cookie_supports_samesite_none() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        true,
        SessionCookieSameSite::None,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("SameSite=None"),
        "cookie missing SameSite=None: {text}"
    );
    assert!(
        text.contains("; Secure"),
        "SameSite=None should include Secure when requested: {text}"
    );
}

#[test]
fn effective_session_cookie_secure_disabled_on_http_direct() {
    let access = WebAccess {
        session_cookie_secure: true,
        ..WebAccess::default()
    };
    assert!(!effective_session_cookie_secure(&access, false));
}

#[test]
fn effective_session_cookie_secure_enabled_with_tls() {
    let access = WebAccess {
        session_cookie_secure: true,
        tls: Some(WebTlsConfig {
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
        }),
        ..WebAccess::default()
    };
    assert!(effective_session_cookie_secure(&access, false));
}

#[test]
fn effective_session_cookie_secure_enabled_with_trusted_proxy() {
    let access = WebAccess {
        session_cookie_secure: true,
        trusted_proxies: vec!["10.0.0.1".into()],
        ..WebAccess::default()
    };
    assert!(effective_session_cookie_secure(&access, false));
}

#[test]
fn effective_session_cookie_secure_respects_dev_insecure() {
    let access = WebAccess {
        session_cookie_secure: true,
        tls: Some(WebTlsConfig {
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
        }),
        trusted_proxies: vec!["10.0.0.1".into()],
        ..WebAccess::default()
    };
    assert!(!effective_session_cookie_secure(&access, true));
}

#[test]
fn session_cookie_max_age_matches_ttl() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(120),
        true,
        SessionCookieSameSite::Lax,
    );
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("Max-Age=120"),
        "cookie max-age should reflect session ttl: {text}"
    );
}

#[test]
fn clear_session_cookie_includes_secure() {
    let mut headers = HeaderMap::new();
    clear_session_cookie(&mut headers, true, SessionCookieSameSite::Lax);
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("; Secure"),
        "clear cookie missing Secure attribute: {text}"
    );
}

#[test]
fn clear_session_cookie_respects_insecure_flag() {
    let mut headers = HeaderMap::new();
    clear_session_cookie(&mut headers, false, SessionCookieSameSite::Lax);
    let value = headers.get(header::SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        !text.contains("; Secure"),
        "insecure clear cookie should skip Secure: {text}"
    );
}

#[cfg(target_os = "freebsd")]
#[test]
fn freebsd_builds_secured_app_state() {
    let state = make_secured_app_state(Exposure::all());
    assert!(state.session_ttl().as_secs() > 0);
    assert!(!state.session_cookie_secure());
    let security = state.security();
    assert!(security.session_ttl().as_secs() > 0);
}

#[cfg(target_os = "freebsd")]
#[tokio::test]
async fn freebsd_login_and_reads_logs() {
    use super::super::handlers;
    use axum::extract::State;
    use axum::{body::to_bytes, response::IntoResponse};
    use tempfile::NamedTempFile;

    let tmp = NamedTempFile::new().expect("temp syslog");
    std::fs::write(
        tmp.path(),
        "Jan  1 00:00:01 host describe_me: started\nJan  1 00:00:02 host sshd[1]: ok\n",
    )
    .expect("write syslog sample");

    let prev = std::env::var("DESCRIBE_ME_SYSLOG_PATH").ok();
    std::env::set_var("DESCRIBE_ME_SYSLOG_PATH", tmp.path());

    let exposure = Exposure::all();
    let state = make_secured_app_state(exposure);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"token":"secret"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            8080,
        ))));

    let response = auth::login(State(state.clone()), request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .expect("session cookie");

    let mut logs_req = axum::http::Request::builder()
        .uri("/logs?lines=4")
        .body(axum::body::Body::empty())
        .unwrap();
    logs_req
        .headers_mut()
        .insert(axum::http::header::COOKIE, cookie);
    logs_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            8080,
        ))));

    let (mut parts, body) = logs_req.into_parts();
    let guard = security::AuthGuard::from_request_parts(&mut parts, &state)
        .await
        .expect("cookie auth");
    let query =
        axum::extract::Query::<handlers::LogsRequestQuery>::from_request_parts(&mut parts, &state)
            .await
            .expect("query");
    let response = handlers::host_logs(State(state.clone()), guard, query)
        .await
        .expect("logs handler")
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let page: crate::domain::HostLogsPage = serde_json::from_slice(&body).expect("logs payload");
    assert!(!page.entries.is_empty());

    if let Some(prev) = prev {
        std::env::set_var("DESCRIBE_ME_SYSLOG_PATH", prev);
    } else {
        std::env::remove_var("DESCRIBE_ME_SYSLOG_PATH");
    }
}

#[tokio::test]
async fn login_endpoint_sets_cookie_and_redirects() {
    let exposure = Exposure::all();
    let state = make_secured_app_state(exposure);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"token":"secret"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));

    let response = auth::login(State(state.clone()), request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response.headers().get(header::SET_COOKIE).cloned();
    assert!(cookie.is_some(), "expected session cookie");

    // reuse cookie on a protected route
    let mut next_req = axum::http::Request::builder()
        .uri("/logs")
        .body(axum::body::Body::empty())
        .unwrap();
    if let Some(value) = cookie {
        next_req
            .headers_mut()
            .insert(axum::http::header::COOKIE, value);
    }
    next_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));
    let (mut parts, _) = next_req.into_parts();
    let guard = security::AuthGuard::from_request_parts(&mut parts, &state)
        .await
        .expect("cookie should authenticate");
    assert_eq!(
        guard.into_session().token_key(),
        security::TokenKey::from_value("secret")
    );
}

#[tokio::test]
async fn logout_revokes_server_session() {
    let exposure = Exposure::all();
    let state = make_secured_app_state(exposure);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"token":"secret"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));

    let response = auth::login(State(state.clone()), request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .expect("session cookie");

    let mut logout_req = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header(header::ORIGIN, "http://localhost")
        .body(axum::body::Body::empty())
        .unwrap();
    logout_req
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let response = auth::logout(State(state.clone()), logout_req).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let mut next_req = axum::http::Request::builder()
        .uri("/logs")
        .body(axum::body::Body::empty())
        .unwrap();
    next_req.headers_mut().insert(header::COOKIE, cookie);
    next_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));
    let (mut parts, _) = next_req.into_parts();
    match security::AuthGuard::from_request_parts(&mut parts, &state).await {
        Ok(_) => panic!("revoked session should be rejected"),
        Err(err) => assert_eq!(err.status(), StatusCode::UNAUTHORIZED),
    }
}

#[tokio::test]
async fn logout_rejects_missing_origin_or_fetch_site() {
    let exposure = Exposure::all();
    let state = make_secured_app_state(exposure);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"token":"secret"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));

    let response = auth::login(State(state.clone()), request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .expect("session cookie");

    let mut logout_req = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .body(axum::body::Body::empty())
        .unwrap();
    logout_req
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let response = auth::logout(State(state.clone()), logout_req).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "expected no purge cookie"
    );

    let mut next_req = axum::http::Request::builder()
        .uri("/logs")
        .body(axum::body::Body::empty())
        .unwrap();
    next_req.headers_mut().insert(header::COOKIE, cookie);
    next_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));
    let (mut parts, _) = next_req.into_parts();
    let guard = security::AuthGuard::from_request_parts(&mut parts, &state)
        .await
        .expect("session should still be valid");
    assert_eq!(
        guard.into_session().token_key(),
        security::TokenKey::from_value("secret")
    );
}

#[tokio::test]
async fn logout_accepts_fetch_site_same_origin() {
    let exposure = Exposure::all();
    let state = make_secured_app_state(exposure);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"token":"secret"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));

    let response = auth::login(State(state.clone()), request).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .cloned()
        .expect("session cookie");

    let mut logout_req = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::empty())
        .unwrap();
    logout_req
        .headers_mut()
        .insert(header::COOKIE, cookie.clone());
    let response = auth::logout(State(state.clone()), logout_req).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let mut next_req = axum::http::Request::builder()
        .uri("/logs")
        .body(axum::body::Body::empty())
        .unwrap();
    next_req.headers_mut().insert(header::COOKIE, cookie);
    next_req
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            4242,
        ))));
    let (mut parts, _) = next_req.into_parts();
    match security::AuthGuard::from_request_parts(&mut parts, &state).await {
        Ok(_) => panic!("revoked session should be rejected"),
        Err(err) => assert_eq!(err.status(), StatusCode::UNAUTHORIZED),
    }
}

#[tokio::test]
async fn invalid_session_cookie_is_purged_on_html() {
    let state = make_secured_app_state(Exposure::all());
    let mut request = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    request.headers_mut().insert(
        header::COOKIE,
        format!("{SESSION_COOKIE_NAME}=invalid").parse().unwrap(),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242))));

    let (mut parts, _) = request.into_parts();
    let guard = security::AuthGuard::from_request_parts(&mut parts, &state)
        .await
        .expect("html should allow anonymous access");
    let session = guard.into_session();

    let mut headers = HeaderMap::new();
    security::attach_session_cookie(&mut headers, &session, &state);
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("set-cookie should be present");
    assert!(set_cookie.contains(SESSION_COOKIE_NAME));
    assert!(set_cookie.contains("Max-Age=0"));
}

#[tokio::test]
async fn unauthenticated_requests_to_sensitive_routes_are_401_when_token_configured() {
    let state = make_secured_app_state(Exposure::all());
    let mut request = axum::http::Request::builder()
        .uri("/api/containers")
        .body(axum::body::Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242))));

    let (mut parts, _) = request.into_parts();
    match security::AuthGuard::from_request_parts(&mut parts, &state).await {
        Ok(_) => panic!("missing token should be rejected"),
        Err(err) => assert_eq!(err.status(), StatusCode::UNAUTHORIZED),
    }
}

#[tokio::test]
async fn unauthenticated_html_sensitive_pages_are_401_when_token_configured() {
    let state = make_secured_app_state(Exposure::all());
    for path in ["/container", "/updates"] {
        let mut request = axum::http::Request::builder()
            .uri(path)
            .header(header::ACCEPT, "text/html")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 4242))));

        let (mut parts, _) = request.into_parts();
        match security::AuthGuard::from_request_parts(&mut parts, &state).await {
            Ok(_) => panic!("missing token should be rejected for {path}"),
            Err(err) => assert_eq!(err.status(), StatusCode::UNAUTHORIZED, "path {path}"),
        }
    }
}
