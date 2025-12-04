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
