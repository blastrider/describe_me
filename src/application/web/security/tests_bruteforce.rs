use super::tests_common::*;
use super::*;
use axum::http::StatusCode;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn auth_backoff_after_failures() {
    let security = build_security(Some(cached_hash()));
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("wrong"));

    for attempt in 0..6 {
        let res = security.authorize(&parts, WebRoute::Html).await;
        if attempt < 5 {
            assert!(res.is_err());
        } else {
            let err = res.expect_err("backoff expected");
            assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
            assert!(err.retry_after.is_some());
        }
    }
}

#[tokio::test]
async fn public_html_does_not_clear_bruteforce_counters() {
    let security = build_security(Some(cached_hash()));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let parts_logs = make_parts("/api/logs", ip, None);
    let parts_html = make_parts("/", ip, None);

    for _ in 0..2 {
        let err = security
            .authorize(&parts_logs, WebRoute::Logs)
            .await
            .expect_err("missing token should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.retry_after.is_none());
    }

    let _ = security
        .authorize(&parts_html, WebRoute::Html)
        .await
        .expect("public html should succeed");

    let err = security
        .authorize(&parts_logs, WebRoute::Logs)
        .await
        .expect_err("third failure should trigger backoff");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(err.retry_after.is_some());
}

#[tokio::test]
async fn authenticated_request_resets_bruteforce_counters() {
    let security = build_security(Some(cached_hash()));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
    let parts_logs = make_parts("/api/logs", ip, None);
    let parts_logs_auth = make_parts("/api/logs", ip, Some("secret"));

    for _ in 0..2 {
        let err = security
            .authorize(&parts_logs, WebRoute::Logs)
            .await
            .expect_err("missing token should be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.retry_after.is_none());
    }

    let _ = security
        .authorize(&parts_logs_auth, WebRoute::Logs)
        .await
        .expect("valid token should succeed");

    let err = security
        .authorize(&parts_logs, WebRoute::Logs)
        .await
        .expect_err("missing token should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(err.retry_after.is_none());
}
