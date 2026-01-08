use super::{csp, handlers, origin, *};
use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
use crate::application::test_support::{
    dummy_snapshot, make_app_state_with_ctx, make_secured_app_state, make_test_app_state,
};
use crate::application::web::csp::{
    apply_security_headers, is_request_https, CspNonce, HEADER_STRICT_TRANSPORT_SECURITY,
};
use crate::application::web::state::StaticWebConfig;
use crate::application::web::{LogoAsset, WebAccess, WebSecurity};
use crate::domain::{
    MetadataValidationError, ServerDescription, SessionCookieSameSite, DESCRIPTION_MAX_BYTES,
};
use axum::body::to_bytes;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::header::{ORIGIN, SET_COOKIE};
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn build_request(origin: Option<&str>, host: &str, uri: &str, method: Method) -> AxumRequest {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host);
    if let Some(origin_value) = origin {
        builder = builder.header(ORIGIN, origin_value);
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

fn build_request_with_headers(origin: Option<&str>, host: &str, scheme: &str) -> AxumRequest {
    build_request(origin, host, &format!("{scheme}://internal/"), Method::GET)
}

fn test_static_cfg(trusted_proxies: Vec<String>, tls_enabled: bool) -> Arc<StaticWebConfig> {
    let access = WebAccess {
        trusted_proxies,
        ..WebAccess::default()
    };
    let security = WebSecurity::build(
        access,
        #[cfg(feature = "config")]
        None,
    )
    .expect("security");

    Arc::new(StaticWebConfig {
        interval: Duration::from_secs(1),
        #[cfg(feature = "config")]
        config: None,
        web_debug: false,
        security: Arc::new(security),
        exposure: Exposure::all(),
        logo: LogoAsset::default(),
        session_cookie_secure: false,
        session_cookie_same_site: SessionCookieSameSite::Lax,
        session_ttl: Duration::from_secs(60),
        updates_refresh_ttl: Duration::from_secs(60),
        tls_enabled,
    })
}

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
fn set_session_cookie_includes_http_only() {
    let mut headers = HeaderMap::new();
    set_session_cookie(
        &mut headers,
        "sess:v1:test",
        Duration::from_secs(60),
        true,
        SessionCookieSameSite::Lax,
    );
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
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
    let value = headers.get(SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        !text.contains("; Secure"),
        "insecure clear cookie should skip Secure: {text}"
    );
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
    let nonce = CspNonce::new("abc".into());
    apply_security_headers(&mut headers, &nonce, true, &[]);
    let value = headers
        .get(HEADER_STRICT_TRANSPORT_SECURITY)
        .expect("Strict-Transport-Security header");
    assert_eq!(
        value.to_str().unwrap(),
        "max-age=31536000; includeSubDomains"
    );
}

#[test]
fn hsts_header_skipped_on_plain_http() {
    let mut headers = HeaderMap::new();
    let nonce = CspNonce::new("abc".into());
    apply_security_headers(&mut headers, &nonce, false, &[]);
    assert!(
        headers.get(HEADER_STRICT_TRANSPORT_SECURITY).is_none(),
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
    assert!(is_request_https(&req, &cfg));
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
    assert!(!is_request_https(&req, &cfg));
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
    assert!(is_request_https(&req, &cfg));
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
    assert!(is_request_https(&req, &cfg));
}

#[test]
fn normalize_description_replaces_carriage_returns() {
    let normalized =
        ServerDescription::try_from("hello\r\nworld\rgoodbye").expect("description allowed");
    assert_eq!(normalized.as_ref(), "hello\nworld\ngoodbye");
}

#[test]
fn normalize_description_enforces_limit() {
    let long = "x".repeat(DESCRIPTION_MAX_BYTES + 1);
    let err = ServerDescription::try_from(long.as_str()).unwrap_err();
    assert_eq!(
        err,
        MetadataValidationError::DescriptionTooLong(DESCRIPTION_MAX_BYTES)
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
    use axum::extract::State;
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
        .get(SET_COOKIE)
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
    let cookie = response.headers().get(SET_COOKIE).cloned();
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
        .get(SET_COOKIE)
        .cloned()
        .expect("session cookie");

    let mut logout_req = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header(ORIGIN, "http://localhost")
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
        .get(SET_COOKIE)
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
        response.headers().get(SET_COOKIE).is_none(),
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
        .get(SET_COOKIE)
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
        .get(SET_COOKIE)
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

#[tokio::test]
async fn containers_api_returns_cached_snapshot() {
    use crate::application::exposure::SnapshotView;
    use crate::domain::{ContainerInfo, ContainersSnapshot, ContainersSummary, SystemSnapshot};
    use crate::shared::SharedSlice;

    let mut exposure = Exposure::default();
    exposure.set_containers_details(true);

    let snapshot = SystemSnapshot {
        hostname: "host".into(),
        os: None,
        kernel: None,
        uptime_seconds: 0,
        cpu_count: 1,
        load_average: (0.0, 0.0, 0.0),
        total_memory_bytes: 0,
        used_memory_bytes: 0,
        total_swap_bytes: 0,
        used_swap_bytes: 0,
        disk_usage: None,
        #[cfg(feature = "systemd")]
        services_running: SharedSlice::from_vec(Vec::new()),
        #[cfg(feature = "net")]
        listening_sockets: None,
        #[cfg(feature = "net")]
        network_traffic: None,
        containers: Some(ContainersSnapshot {
            summary: Some(ContainersSummary {
                total: 2,
                running: 1,
            }),
            containers: Some(SharedSlice::from_vec(vec![
                ContainerInfo {
                    name: "web".into(),
                    runtime: "docker".into(),
                    ip: Some("10.0.0.2".into()),
                    state: "running".into(),
                    image: Some("nginx:latest".into()),
                },
                ContainerInfo {
                    name: "db".into(),
                    runtime: "podman".into(),
                    ip: None,
                    state: "exited".into(),
                    image: Some("postgres:15".into()),
                },
            ])),
        }),
        updates: None,
        extensions: None,
    };

    let mut view = SnapshotView::new(&snapshot, exposure);
    view.server_description = None;
    let state = make_test_app_state(exposure);
    state.cache_snapshot(view).await;

    let guard = super::security::make_test_guard(super::security::WebRoute::Html);

    let response = handlers::containers_api(State(state), guard)
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        value
            .pointer("/containers/summary/total")
            .and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        value
            .pointer("/containers/containers/0/name")
            .and_then(|v| v.as_str()),
        Some("web")
    );
}

#[tokio::test]
async fn metrics_return_snapshot_when_missing_cache() {
    let exposure = Exposure::all();
    let state = make_test_app_state(exposure);
    let guard = super::security::make_test_guard(super::security::WebRoute::Logs);

    let response = handlers::metrics_export(State(state), guard)
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let text = std::str::from_utf8(&body).expect("utf8");
    assert!(text.contains("describe_me_up 1"));
}

#[tokio::test]
async fn metrics_return_cached_snapshot() {
    use crate::application::exposure::SnapshotView;
    use crate::domain::{DiskUsage, SystemSnapshot};
    use crate::shared::SharedSlice;

    let exposure = Exposure::all();
    let snapshot = SystemSnapshot {
        hostname: "host".into(),
        os: None,
        kernel: None,
        uptime_seconds: 100,
        cpu_count: 4,
        load_average: (1.0, 0.5, 0.25),
        total_memory_bytes: 1024,
        used_memory_bytes: 256,
        total_swap_bytes: 128,
        used_swap_bytes: 32,
        disk_usage: Some(DiskUsage {
            total_bytes: 10_000,
            available_bytes: 6_000,
            used_bytes: 4_000,
            partitions: SharedSlice::from_vec(Vec::new()),
        }),
        #[cfg(feature = "systemd")]
        services_running: SharedSlice::from_vec(Vec::new()),
        #[cfg(feature = "net")]
        listening_sockets: None,
        #[cfg(feature = "net")]
        network_traffic: None,
        containers: None,
        updates: None,
        extensions: None,
    };

    let mut view = SnapshotView::new(&snapshot, exposure);
    view.server_description = None;

    let state = make_test_app_state(exposure);
    state.cache_snapshot(view).await;

    let guard = super::security::make_test_guard(super::security::WebRoute::Logs);
    let response = handlers::metrics_export(State(state), guard)
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let text = std::str::from_utf8(&body).expect("utf8");
    assert!(text.contains("describe_me_cpu_count 4"));
    assert!(text.contains("describe_me_snapshot_age_seconds"));
    assert!(text.contains("describe_me_disk_bytes_total 10000"));
}

#[tokio::test]
async fn history_endpoint_available_when_enabled() {
    let ctx = AppContext::in_memory();
    ctx.history().record_snapshot(&dummy_snapshot());

    let exposure = Exposure::all();
    let security = WebSecurity::build(
        WebAccess::default(),
        #[cfg(feature = "config")]
        None,
    )
    .expect("security");
    let state = make_app_state_with_ctx(exposure, security, true, ctx);

    let params = super::services::HistoryQueryParams {
        server: None,
        window: Some(60),
        limit: Some(32),
        ip: "127.0.0.1".into(),
        token: "test".into(),
    };

    let dto = super::services::build_history_series_response(&state, params)
        .await
        .expect("history service");
    assert!(
        !dto.points.is_empty(),
        "expected at least one history point when enabled"
    );
}

#[tokio::test]
async fn history_endpoint_returns_503_when_disabled() {
    let ctx = AppContext::in_memory();
    ctx.history()
        .configure(crate::application::history::HistorySettings::disabled())
        .expect("disable history");

    let exposure = Exposure::all();
    let security = WebSecurity::build(
        WebAccess::default(),
        #[cfg(feature = "config")]
        None,
    )
    .expect("security");
    let state = make_app_state_with_ctx(exposure, security, true, ctx);
    let params = super::services::HistoryQueryParams {
        server: None,
        window: None,
        limit: None,
        ip: "127.0.0.1".into(),
        token: "test".into(),
    };

    let status = match super::services::build_history_series_response(&state, params).await {
        Ok(_) => StatusCode::OK,
        Err(err) => err.into_response().status(),
    };
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn containers_page_renders_html() {
    let exposure = Exposure::all();
    let state = make_test_app_state(exposure);
    let guard = super::security::make_test_guard(super::security::WebRoute::Html);
    let response = handlers::containers_page(
        State(state),
        guard,
        Extension(CspNonce::new("nonce".into())),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let html = std::str::from_utf8(&body).expect("utf8");
    assert!(
        html.contains("Conteneurs"),
        "expected containers page content"
    );
}

#[tokio::test]
async fn logo_asset_is_static_svg() {
    let asset = LogoAsset::default();
    let response = asset.response();
    let (parts, body) = response.into_parts();

    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content-type header");
    assert_eq!(content_type, "image/svg+xml");

    let body = to_bytes(body, usize::MAX).await.expect("body bytes");
    assert_eq!(body.as_ref(), asset.bytes.as_ref());
}

#[cfg(feature = "config")]
#[tokio::test]
async fn custom_logo_path_is_loaded_and_validated() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let logo_path = dir.path().join("logo.svg");
    fs::write(
        &logo_path,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><text>OK</text></svg>"#,
    )
    .expect("write logo");

    let asset = LogoAsset::from_optional_path(logo_path.to_str()).expect("logo from config path");
    let response = asset.response();
    let (_, body) = response.into_parts();
    let body = to_bytes(body, usize::MAX).await.expect("body bytes");
    assert_eq!(body.as_ref(), asset.bytes.as_ref());
}

#[cfg(feature = "config")]
#[test]
fn custom_logo_rejects_script() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let logo_path = dir.path().join("logo.svg");
    fs::write(
        &logo_path,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
    )
    .expect("write logo");

    let err = LogoAsset::from_optional_path(logo_path.to_str());
    assert!(matches!(err, Err(DescribeError::Config(msg)) if msg.contains("script")));
}

#[cfg(feature = "config")]
#[test]
fn custom_logo_rejects_event_handler() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let logo_path = dir.path().join("logo.svg");
    fs::write(
        &logo_path,
        r#"<svg xmlns="http://www.w3.org/2000/svg" onload = "alert(1)"></svg>"#,
    )
    .expect("write logo");

    let err = LogoAsset::from_optional_path(logo_path.to_str());
    assert!(matches!(err, Err(DescribeError::Config(msg)) if msg.contains("onload")));
}

#[cfg(feature = "config")]
#[test]
fn custom_logo_rejects_external_href() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let logo_path = dir.path().join("logo.svg");
    fs::write(
        &logo_path,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.example.com/x.svg#logo"/></svg>"#,
    )
    .expect("write logo");

    let err = LogoAsset::from_optional_path(logo_path.to_str());
    assert!(matches!(err, Err(DescribeError::Config(msg)) if msg.contains("href")));
}
