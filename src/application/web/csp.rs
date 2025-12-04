use axum::http::{header, HeaderMap, HeaderValue, Request};
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::future::BoxFuture;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

pub(crate) const HEADER_CONTENT_SECURITY_POLICY: header::HeaderName =
    header::HeaderName::from_static("content-security-policy");
pub(crate) const HEADER_REFERRER_POLICY: header::HeaderName =
    header::HeaderName::from_static("referrer-policy");
pub(crate) const HEADER_X_FRAME_OPTIONS: header::HeaderName =
    header::HeaderName::from_static("x-frame-options");
pub(crate) const HEADER_X_CONTENT_TYPE_OPTIONS: header::HeaderName =
    header::HeaderName::from_static("x-content-type-options");
pub(crate) const HEADER_CROSS_ORIGIN_RESOURCE_POLICY: header::HeaderName =
    header::HeaderName::from_static("cross-origin-resource-policy");
pub(crate) const HEADER_PERMISSIONS_POLICY: header::HeaderName =
    header::HeaderName::from_static("permissions-policy");
pub(crate) const HEADER_STRICT_TRANSPORT_SECURITY: header::HeaderName =
    header::HeaderName::from_static("strict-transport-security");
pub(crate) const HEADER_CROSS_ORIGIN_OPENER_POLICY: header::HeaderName =
    header::HeaderName::from_static("cross-origin-opener-policy");
pub(crate) const HEADER_CROSS_ORIGIN_EMBEDDER_POLICY: header::HeaderName =
    header::HeaderName::from_static("cross-origin-embedder-policy");

#[derive(Clone)]
pub(crate) struct CspNonce(Arc<str>);

impl CspNonce {
    pub fn new(value: String) -> Self {
        Self(Arc::<str>::from(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Middleware layer appliquant les en-têtes de sécurité et injectant un nonce CSP.
#[derive(Clone, Default)]
pub struct SecurityHeadersLayer;

impl SecurityHeadersLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for SecurityHeadersMiddleware<S>
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

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let csp_nonce = CspNonce::new(generate_csp_nonce());
        req.extensions_mut().insert(csp_nonce.clone());

        Box::pin(async move {
            let mut response = inner.call(req).await?;
            apply_security_headers(response.headers_mut(), &csp_nonce);
            Ok(response)
        })
    }
}

pub(crate) fn apply_security_headers(headers: &mut HeaderMap, nonce: &CspNonce) {
    let csp_value = format!(
        "default-src 'none'; connect-src 'self'; img-src 'self'; font-src 'self'; \
         style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; script-src-attr 'none'; base-uri 'none'; form-action 'self'; \
         frame-ancestors 'none'; object-src 'none'; block-all-mixed-content; upgrade-insecure-requests",
        nonce = nonce.as_str()
    );

    if let Ok(value) = HeaderValue::from_str(&csp_value) {
        headers.insert(HEADER_CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(
        HEADER_REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(HEADER_X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HEADER_X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_RESOURCE_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HEADER_PERMISSIONS_POLICY,
        HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );
    headers.insert(
        HEADER_STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_OPENER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HEADER_CROSS_ORIGIN_EMBEDDER_POLICY,
        HeaderValue::from_static("require-corp"),
    );
}

fn generate_csp_nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
