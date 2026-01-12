use super::super::{csp, mark_response_no_store, origin, WebAccess};
use super::fixtures::{build_request, build_request_with_headers, test_static_cfg};
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Method};
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn nonce_is_inserted_in_csp_header() {
    let mut headers = HeaderMap::new();
    let nonce = csp::CspNonce::new("abcd1234".into());
    csp::apply_security_headers(&mut headers, &nonce, true, &[]);
    let value = headers
        .get(csp::HEADER_CONTENT_SECURITY_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert!(value.contains("style-src 'nonce-abcd1234'"));
    assert!(value.contains("script-src 'nonce-abcd1234'"));
    assert!(value.contains("form-action 'self'"));
    let permissions = headers
        .get(csp::HEADER_PERMISSIONS_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(permissions, "geolocation=(), camera=(), microphone=()");
    let coop = headers
        .get(csp::HEADER_CROSS_ORIGIN_OPENER_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(coop, "same-origin");
    let coep = headers
        .get(csp::HEADER_CROSS_ORIGIN_EMBEDDER_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(coep, "require-corp");
}

#[test]
fn csp_connect_src_includes_allowed_origins() {
    let mut headers = HeaderMap::new();
    let nonce = csp::CspNonce::new("abcd1234".into());
    let allowlist = vec![
        "https://public.example.com".to_string(),
        "http://internal:8080".to_string(),
    ];
    csp::apply_security_headers(&mut headers, &nonce, true, &allowlist);
    let value = headers
        .get(csp::HEADER_CONTENT_SECURITY_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert!(value.contains("connect-src 'self'"));
    assert!(value.contains("https://public.example.com"));
    assert!(value.contains("http://internal:8080"));
}

#[test]
fn csp_relaxes_coep_coop_corp_with_allowlist() {
    let mut headers = HeaderMap::new();
    let nonce = csp::CspNonce::new("abcd1234".into());
    let allowlist = vec!["https://public.example.com".to_string()];
    csp::apply_security_headers(&mut headers, &nonce, true, &allowlist);
    assert!(headers
        .get(csp::HEADER_CROSS_ORIGIN_RESOURCE_POLICY)
        .is_none());
    assert!(headers
        .get(csp::HEADER_CROSS_ORIGIN_OPENER_POLICY)
        .is_none());
    assert!(headers
        .get(csp::HEADER_CROSS_ORIGIN_EMBEDDER_POLICY)
        .is_none());
}

#[test]
fn origin_allowlist_accepts_configured_origin() {
    let request = build_request_with_headers(
        Some("https://public.example.com"),
        "internal.example.lan:8080",
        "https",
    );
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allowlist_rejects_non_default_port_when_missing_in_allowlist() {
    let request = build_request_with_headers(
        Some("https://public.example.com:8443"),
        "internal.example.lan:8080",
        "https",
    );
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allowlist_blocks_unlisted_origin() {
    let request =
        build_request_with_headers(Some("https://evil.example.com"), "internal:8080", "https");
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_rejects_missing_origin_for_non_idempotent_request() {
    let request = build_request(None, "internal:8080", "/api/x", Method::POST);
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allows_missing_origin_for_idempotent_request() {
    let request = build_request(None, "internal:8080", "/api/x", Method::GET);
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_defaults_to_same_host_port() {
    let request = build_request_with_headers(Some("http://internal:8080"), "internal:8080", "http");
    let policy = origin::OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allows_origin_form_same_origin_without_scheme() {
    let request = build_request(Some("http://internal"), "internal", "/api/x", Method::POST);
    let policy = origin::OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allowlist_blocks_same_origin_when_unlisted() {
    let request = build_request_with_headers(
        Some("https://internal.example.lan:18443"),
        "internal.example.lan:18443",
        "https",
    );
    let policy =
        origin::OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
            .expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_rejects_scheme_mismatch() {
    let request =
        build_request_with_headers(Some("https://internal:8080"), "internal:8080", "http");
    let policy = origin::OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_ignores_forwarded_proto_without_trusted_proxy() {
    let mut request = build_request(Some("https://internal"), "internal", "/api/x", Method::POST);
    request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    let policy = origin::OriginPolicy::from_access(&WebAccess::default()).expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_accepts_forwarded_proto_from_trusted_proxy() {
    let mut request = build_request(Some("https://internal"), "internal", "/api/x", Method::PUT);
    request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((
            Ipv4Addr::new(203, 0, 113, 5),
            4242,
        ))));
    let access = WebAccess {
        trusted_proxies: vec!["203.0.113.5".to_string()],
        ..WebAccess::default()
    };
    let policy = origin::OriginPolicy::from_access(&access).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_ignores_forwarded_host_without_trusted_proxy() {
    let mut request =
        build_request_with_headers(Some("https://public.example.com"), "internal:8080", "https");
    request.headers_mut().insert(
        "x-forwarded-host",
        HeaderValue::from_static("public.example.com"),
    );
    let policy = origin::OriginPolicy::from_access(&WebAccess::default()).expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_accepts_forwarded_host_from_trusted_proxy() {
    let mut request =
        build_request_with_headers(Some("https://public.example.com"), "internal:8080", "https");
    request.headers_mut().insert(
        "x-forwarded-host",
        HeaderValue::from_static("public.example.com"),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((
            Ipv4Addr::new(203, 0, 113, 5),
            4242,
        ))));
    let access = WebAccess {
        trusted_proxies: vec!["203.0.113.5".to_string()],
        ..WebAccess::default()
    };
    let policy = origin::OriginPolicy::from_access(&access).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_accepts_forwarded_host_from_forwarded_header() {
    let mut request =
        build_request_with_headers(Some("https://public.example.com"), "internal:8080", "https");
    request.headers_mut().insert(
        header::FORWARDED,
        HeaderValue::from_static("host=public.example.com"),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((
            Ipv4Addr::new(203, 0, 113, 5),
            4242,
        ))));
    let access = WebAccess {
        trusted_proxies: vec!["203.0.113.5".to_string()],
        ..WebAccess::default()
    };
    let policy = origin::OriginPolicy::from_access(&access).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allows_implicit_port_for_scheme() {
    let request = build_request_with_headers(Some("https://internal"), "internal", "https");
    let policy = origin::OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(origin::is_origin_allowed(&request, &policy));
}

#[test]
fn origin_rejects_implicit_port_with_scheme_mismatch() {
    let request = build_request_with_headers(Some("https://internal"), "internal", "http");
    let policy = origin::OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(!origin::is_origin_allowed(&request, &policy));
}

#[test]
fn response_marked_no_store_sets_cache_header() {
    let mut headers = HeaderMap::new();
    mark_response_no_store(&mut headers);
    let value = headers
        .get(header::CACHE_CONTROL)
        .expect("Cache-Control header");
    assert_eq!(value, HeaderValue::from_static("no-store"));
}

#[test]
fn hsts_header_is_added() {
    let mut headers = HeaderMap::new();
    let nonce = csp::CspNonce::new("abc".into());
    csp::apply_security_headers(&mut headers, &nonce, true, &[]);
    let value = headers
        .get(csp::HEADER_STRICT_TRANSPORT_SECURITY)
        .expect("Strict-Transport-Security header");
    assert_eq!(
        value.to_str().unwrap(),
        "max-age=31536000; includeSubDomains"
    );
}

#[test]
fn hsts_header_skipped_on_plain_http() {
    let mut headers = HeaderMap::new();
    let nonce = csp::CspNonce::new("abc".into());
    csp::apply_security_headers(&mut headers, &nonce, false, &[]);
    assert!(
        headers.get(csp::HEADER_STRICT_TRANSPORT_SECURITY).is_none(),
        "HSTS should not be set on HTTP"
    );
}

#[test]
fn is_request_https_accepts_tls_mode_without_headers() {
    let cfg = test_static_cfg(Vec::new(), true);
    let req = axum::http::Request::builder()
        .uri("http://internal/")
        .body(axum::body::Body::empty())
        .unwrap();
    assert!(csp::is_request_https(&req, &cfg));
}

#[test]
fn is_request_https_rejects_untrusted_forwarded_proto() {
    let cfg = test_static_cfg(Vec::new(), false);
    let mut req = axum::http::Request::builder()
        .uri("http://internal/")
        .body(axum::body::Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::new(198, 51, 100, 10),
            8080,
        ))));
    req.headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    assert!(!csp::is_request_https(&req, &cfg));
}

#[test]
fn is_request_https_accepts_trusted_forwarded_proto() {
    let cfg = test_static_cfg(vec!["127.0.0.1".into()], false);
    let mut req = axum::http::Request::builder()
        .uri("http://internal/")
        .body(axum::body::Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))));
    req.headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    assert!(csp::is_request_https(&req, &cfg));
}

#[test]
fn is_request_https_reads_forwarded_proto() {
    let cfg = test_static_cfg(vec!["192.0.2.10".into()], false);
    let mut req = axum::http::Request::builder()
        .uri("http://internal/")
        .body(axum::body::Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [192, 0, 2, 10],
            8080,
        ))));
    req.headers_mut().insert(
        header::FORWARDED,
        HeaderValue::from_static("for=1.1.1.1;proto=https"),
    );
    assert!(csp::is_request_https(&req, &cfg));
}
