use super::{OriginCheckLayer, OriginPolicy};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tower::Service;

fn build_policy() -> OriginPolicy {
    OriginPolicy::from_allowlist(vec!["https://public.example.com".to_string()])
        .expect("origin policy")
}

fn vary_contains(headers: &HeaderMap, needle: &str) -> bool {
    headers.get_all(header::VARY).iter().any(|value| {
        value
            .to_str()
            .map(|text| {
                text.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(needle))
            })
            .unwrap_or(false)
    })
}

#[tokio::test]
async fn cors_headers_added_for_allowed_origin() {
    let mut app = Router::new()
        .route("/api/x", get(|| async { Response::new(Body::empty()) }))
        .layer(OriginCheckLayer::new(build_policy()));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/x")
        .header(header::HOST, "internal:8080")
        .header(header::ORIGIN, "https://public.example.com")
        .body(Body::empty())
        .unwrap();

    let response = Service::call(&mut app, request).await.expect("response");
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("https://public.example.com"))
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        Some(&HeaderValue::from_static("true"))
    );
    assert!(vary_contains(response.headers(), "Origin"));
}

#[tokio::test]
async fn cors_preflight_returns_no_content() {
    let mut app = Router::new()
        .route(
            "/api/description",
            get(|| async {
                Response::builder()
                    .status(StatusCode::IM_A_TEAPOT)
                    .body(Body::empty())
                    .expect("response")
            }),
        )
        .layer(OriginCheckLayer::new(build_policy()));

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/description")
        .header(header::HOST, "internal:8080")
        .header(header::ORIGIN, "https://public.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .unwrap();

    let response = Service::call(&mut app, request).await.expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS),
        Some(&HeaderValue::from_static("POST"))
    );
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS),
        Some(&HeaderValue::from_static("authorization"))
    );
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("https://public.example.com"))
    );
    assert!(vary_contains(response.headers(), "Origin"));
    assert!(vary_contains(
        response.headers(),
        "Access-Control-Request-Method"
    ));
    assert!(vary_contains(
        response.headers(),
        "Access-Control-Request-Headers"
    ));
}
