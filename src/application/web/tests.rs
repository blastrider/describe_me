use super::{handlers, *};
use axum::body::to_bytes;
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::Extension;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn build_request_with_headers(origin: Option<&str>, host: &str) -> AxumRequest {
    let mut builder = axum::http::Request::builder()
        .uri("http://internal/")
        .header(header::HOST, host);
    if let Some(origin_value) = origin {
        builder = builder.header(ORIGIN, origin_value);
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

#[test]
fn nonce_is_inserted_in_csp_header() {
    let mut headers = HeaderMap::new();
    let nonce = CspNonce::new("abcd1234".into());
    apply_security_headers(&mut headers, &nonce);
    let value = headers
        .get(HEADER_CONTENT_SECURITY_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert!(value.contains("style-src 'nonce-abcd1234'"));
    assert!(value.contains("script-src 'nonce-abcd1234'"));
    let permissions = headers
        .get(HEADER_PERMISSIONS_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(permissions, "geolocation=(), camera=(), microphone=()");
    let coop = headers
        .get(HEADER_CROSS_ORIGIN_OPENER_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(coop, "same-origin");
    let coep = headers
        .get(HEADER_CROSS_ORIGIN_EMBEDDER_POLICY)
        .and_then(|val| val.to_str().ok())
        .unwrap();
    assert_eq!(coep, "require-corp");
}

#[test]
fn origin_allowlist_accepts_configured_origin() {
    let request = build_request_with_headers(
        Some("https://public.example.com"),
        "internal.example.lan:8080",
    );
    let policy = OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
        .expect("origin policy");
    assert!(is_origin_allowed(&request, &policy));
}

#[test]
fn origin_allowlist_blocks_unlisted_origin() {
    let request = build_request_with_headers(Some("https://evil.example.com"), "internal:8080");
    let policy = OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
        .expect("origin policy");
    assert!(!is_origin_allowed(&request, &policy));
}

#[test]
fn origin_defaults_to_same_host_port() {
    let request = build_request_with_headers(Some("http://internal:8080"), "internal:8080");
    let policy = OriginPolicy::from_allowlist(Vec::new()).expect("origin policy");
    assert!(is_origin_allowed(&request, &policy));
}

#[test]
fn set_session_cookie_includes_http_only() {
    let mut headers = HeaderMap::new();
    set_session_cookie(&mut headers, "sess:v1:test", true);
    let value = headers.get(SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        text.contains("; HttpOnly"),
        "cookie missing HttpOnly: {text}"
    );
    assert!(
        text.contains("SameSite=Strict"),
        "cookie missing SameSite=Strict: {text}"
    );
}

#[test]
fn clear_session_cookie_includes_http_only() {
    let mut headers = HeaderMap::new();
    clear_session_cookie(&mut headers, true);
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
    set_session_cookie(&mut headers, "sess:v1:test", true);
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
    set_session_cookie(&mut headers, "sess:v1:test", false);
    let value = headers.get(SET_COOKIE).expect("set-cookie");
    let text = value.to_str().expect("utf8");
    assert!(
        !text.contains("; Secure"),
        "insecure cookies should skip Secure: {text}"
    );
}

#[test]
fn clear_session_cookie_includes_secure() {
    let mut headers = HeaderMap::new();
    clear_session_cookie(&mut headers, true);
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
    clear_session_cookie(&mut headers, false);
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
    apply_security_headers(&mut headers, &nonce);
    let value = headers
        .get(HEADER_STRICT_TRANSPORT_SECURITY)
        .expect("Strict-Transport-Security header");
    assert_eq!(
        value.to_str().unwrap(),
        "max-age=31536000; includeSubDomains"
    );
}

#[test]
fn normalize_description_replaces_carriage_returns() {
    let normalized = handlers::normalize_description("hello\r\nworld\rgoodbye").expect("ok");
    assert_eq!(normalized, "hello\nworld\ngoodbye");
}

#[test]
fn normalize_description_enforces_limit() {
    let long = "x".repeat(super::DESCRIPTION_MAX_BYTES + 1);
    let err = handlers::normalize_description(&long).unwrap_err();
    assert!(err.contains("2048"), "unexpected message: {err}");
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
    let state = test_app_state(exposure);
    state.cache_snapshot(view);

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
async fn metrics_return_503_when_missing_snapshot() {
    let exposure = Exposure::all();
    let state = test_app_state(exposure);
    let guard = super::security::make_test_guard(super::security::WebRoute::Logs);

    let response = handlers::metrics_export(State(state), guard)
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let text = std::str::from_utf8(&body).expect("utf8");
    assert!(text.contains("describe_me_up 0"));
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

    let state = test_app_state(exposure);
    state.cache_snapshot(view);

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
async fn containers_page_renders_html() {
    let exposure = Exposure::all();
    let state = test_app_state(exposure);
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

fn test_app_state(exposure: Exposure) -> AppState {
    let security = WebSecurity::build(
        WebAccess::default(),
        #[cfg(feature = "config")]
        None,
    )
    .unwrap();
    AppState {
        ctx: Arc::new(crate::application::context::AppContext::in_memory()),
        interval: Duration::from_secs(1),
        #[cfg(feature = "config")]
        config: None,
        web_debug: false,
        security: Arc::new(security),
        exposure,
        shutdown: Arc::new(tokio::sync::Notify::new()),
        updates_cache: UpdatesCache::new(Duration::from_secs(1), Duration::from_secs(1)),
        snapshot_cache: Arc::new(RwLock::new(None)),
        logo: LogoAsset::default(),
        session_cookie_secure: true,
    }
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
