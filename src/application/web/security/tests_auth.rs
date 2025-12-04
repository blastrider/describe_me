use super::tests_common::*;
use super::*;
use crate::application::web::SESSION_COOKIE_NAME;
#[cfg(feature = "config")]
use crate::application::web::WEB_SESSION_SECONDS;
#[cfg(feature = "config")]
use crate::domain::WebSecurityConfig;
use axum::http::StatusCode;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[tokio::test]
async fn rate_limit_ip_html() {
    let security = build_security(None);
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);

    let mut ok = 0u32;
    loop {
        match security.authorize(&parts, WebRoute::Html).await {
            Ok(_) => ok += 1,
            Err(err) => {
                assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
                assert!(err.retry_after.is_some());
                break;
            }
        }
    }

    assert_eq!(ok, 10);
}

#[cfg(feature = "config")]
fn security_with_session_ttl(secs: u64) -> WebSecurity {
    let cfg = WebSecurityConfig {
        session_ttl_seconds: Some(secs),
        ..WebSecurityConfig::default()
    };
    WebSecurity::build(make_access(None), Some(cfg)).expect("build security")
}

#[cfg(feature = "config")]
#[test]
fn session_ttl_override_is_clamped() {
    let normal = security_with_session_ttl(900);
    assert_eq!(normal.sessions.ttl_for_tests(), Duration::from_secs(900));

    let low = security_with_session_ttl(10);
    assert_eq!(low.sessions.ttl_for_tests(), Duration::from_secs(60));

    let high = security_with_session_ttl(7200);
    assert_eq!(high.sessions.ttl_for_tests(), Duration::from_secs(7200));

    let capped = security_with_session_ttl(1_000_000);
    assert_eq!(
        capped.sessions.ttl_for_tests(),
        Duration::from_secs(WEB_SESSION_SECONDS)
    );
}

#[tokio::test]
async fn sse_concurrency_limited() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));

    let session1 = security
        .authorize(&parts, WebRoute::Sse)
        .await
        .expect("first SSE");
    let err = security
        .authorize(&parts, WebRoute::Sse)
        .await
        .expect_err("second SSE should be blocked");
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(err.retry_after.is_some());

    drop(session1);

    let session2 = security
        .authorize(&parts, WebRoute::Sse)
        .await
        .expect("slot released");
    assert_eq!(session2.route(), WebRoute::Sse);
    assert_eq!(session2.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(session2.token_key(), TokenKey::from_value("secret"));
}

#[tokio::test]
async fn login_issues_session_cookie() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    parts.uri = "/auth/login".parse().unwrap();

    let session = security
        .login(&parts, "secret", WebRoute::Html)
        .await
        .expect("login should succeed");
    let cookie = session
        .session_cookie()
        .expect("session cookie issued")
        .to_string();

    let encoded = utf8_percent_encode(&cookie, NON_ALPHANUMERIC).to_string();
    let mut next = make_parts("/logs", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    next.headers.insert(
        axum::http::header::COOKIE,
        format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
    );

    let guard = security
        .authorize(&next, WebRoute::Logs)
        .await
        .expect("cookie should be accepted");
    assert_eq!(guard.token_key(), TokenKey::from_value("secret"));
}

#[tokio::test]
async fn login_rejects_wrong_token() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);

    let err = security
        .login(&parts, "invalid", WebRoute::Html)
        .await
        .expect_err("login should fail");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_requires_token_without_cookie() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let parts = make_parts("/logs", IpAddr::V4(Ipv4Addr::LOCALHOST), None);

    let err = security
        .authorize(&parts, WebRoute::Logs)
        .await
        .expect_err("missing token should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_rejects_invalid_session_cookie() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let mut parts = make_parts("/logs", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    parts.headers.insert(
        axum::http::header::COOKIE,
        format!("{SESSION_COOKIE_NAME}=invalid").parse().unwrap(),
    );

    let err = security
        .authorize(&parts, WebRoute::Logs)
        .await
        .expect_err("invalid session should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_accepts_session_cookie_on_sse() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let login_parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    let session = security
        .login(&login_parts, "secret", WebRoute::Html)
        .await
        .expect("login should succeed");
    let cookie = session
        .session_cookie()
        .expect("session cookie issued")
        .to_string();
    let encoded = utf8_percent_encode(&cookie, NON_ALPHANUMERIC).to_string();

    let mut sse_parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    sse_parts.headers.insert(
        axum::http::header::COOKIE,
        format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
    );

    let guard = security
        .authorize(&sse_parts, WebRoute::Sse)
        .await
        .expect("session cookie should authenticate SSE");
    assert_eq!(guard.token_key(), TokenKey::from_value("secret"));
}
