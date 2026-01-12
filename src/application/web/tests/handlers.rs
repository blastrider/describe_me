use super::super::{csp::CspNonce, handlers, security, LogoAsset, WebAccess, WebSecurity};
use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
use crate::application::test_support::{
    dummy_snapshot, make_app_state_with_ctx, make_test_app_state,
};
use crate::domain::{MetadataValidationError, ServerDescription, DESCRIPTION_MAX_BYTES};
use axum::body::to_bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Extension;

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

    let guard = security::make_test_guard(security::WebRoute::Html);

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
    let guard = security::make_test_guard(security::WebRoute::Logs);

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

    let guard = security::make_test_guard(security::WebRoute::Logs);
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

    let params = super::super::services::HistoryQueryParams {
        server: None,
        window: Some(60),
        limit: Some(32),
        ip: "127.0.0.1".into(),
        token: "test".into(),
    };

    let dto = super::super::services::build_history_series_response(&state, params)
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
    let params = super::super::services::HistoryQueryParams {
        server: None,
        window: None,
        limit: None,
        ip: "127.0.0.1".into(),
        token: "test".into(),
    };

    let status = match super::super::services::build_history_series_response(&state, params).await {
        Ok(_) => StatusCode::OK,
        Err(err) => err.into_response().status(),
    };
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn containers_page_renders_html() {
    let exposure = Exposure::all();
    let state = make_test_app_state(exposure);
    let guard = security::make_test_guard(security::WebRoute::Html);
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
    use crate::domain::DescribeError;
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
    use crate::domain::DescribeError;
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
    use crate::domain::DescribeError;
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
