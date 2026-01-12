use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::application::logging::LogEvent;

use super::policy::OriginPolicy;

#[derive(Clone)]
pub(crate) struct OriginCheckLayer {
    policy: OriginPolicy,
}

impl OriginCheckLayer {
    pub fn new(policy: OriginPolicy) -> Self {
        Self { policy }
    }
}

impl<S> Layer<S> for OriginCheckLayer {
    type Service = OriginCheckMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OriginCheckMiddleware {
            inner,
            policy: self.policy.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct OriginCheckMiddleware<S> {
    inner: S,
    policy: OriginPolicy,
}

impl<S, B> Service<Request<B>> for OriginCheckMiddleware<S>
where
    B: Send + 'static,
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let policy = self.policy.clone();
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            .map(|value| value.to_string());
        let request_method = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|h| h.to_str().ok())
            .map(|value| value.to_string());
        let request_headers = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|h| h.to_str().ok())
            .map(|value| value.to_string());
        let is_preflight =
            req.method() == Method::OPTIONS && origin.is_some() && request_method.is_some();

        Box::pin(async move {
            if !policy.allows(&req) {
                let origin_val = req
                    .headers()
                    .get(header::ORIGIN)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("<none>");
                let host_val = req
                    .headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("<none>");
                let ip = req
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|info| info.0.ip());
                LogEvent::SecurityIncident {
                    category: Cow::Borrowed("origin_not_allowed"),
                    route: Cow::Owned(req.uri().path().to_string()),
                    request_path: Some(Cow::Owned(req.uri().path().to_string())),
                    ip: ip.map(|value| Cow::Owned(value.to_string())),
                    token: None,
                    detail: Some(Cow::Owned(format!("origin={origin_val} host={host_val}"))),
                }
                .emit();
                let response = (
                    StatusCode::FORBIDDEN,
                    "Requête bloquée par la politique CORS (origin non autorisée).",
                )
                    .into_response();
                return Ok(response);
            }

            if is_preflight {
                let mut response = Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .expect("preflight response");
                if let Some(origin) = origin.as_deref() {
                    apply_preflight_headers(
                        response.headers_mut(),
                        origin,
                        request_method.as_deref(),
                        request_headers.as_deref(),
                    );
                }
                return Ok(response);
            }

            let mut response = inner.call(req).await?;
            if let Some(origin) = origin.as_deref() {
                apply_cors_headers(response.headers_mut(), origin);
            }
            Ok(response)
        })
    }
}

const DEFAULT_CORS_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";
const DEFAULT_CORS_HEADERS: &str = "authorization, content-type, x-describe-me-token";

fn apply_cors_headers(headers: &mut HeaderMap, origin: &str) {
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    append_vary(headers, "Origin");
}

fn apply_preflight_headers(
    headers: &mut HeaderMap,
    origin: &str,
    request_method: Option<&str>,
    request_headers: Option<&str>,
) {
    apply_cors_headers(headers, origin);

    let methods = request_method.unwrap_or(DEFAULT_CORS_METHODS);
    if let Ok(value) = HeaderValue::from_str(methods) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
    }

    let allow_headers = request_headers.unwrap_or(DEFAULT_CORS_HEADERS);
    if let Ok(value) = HeaderValue::from_str(allow_headers) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
    }

    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    append_vary(headers, "Access-Control-Request-Method");
    append_vary(headers, "Access-Control-Request-Headers");
}

fn append_vary(headers: &mut HeaderMap, value: &'static str) {
    headers.append(header::VARY, HeaderValue::from_static(value));
}
