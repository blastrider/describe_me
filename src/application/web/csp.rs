use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Request};
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::future::BoxFuture;
use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
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
use super::state::StaticWebConfig;

#[derive(Clone)]
pub struct SecurityHeadersLayer {
    static_cfg: Arc<StaticWebConfig>,
}

impl SecurityHeadersLayer {
    pub fn new(static_cfg: Arc<StaticWebConfig>) -> Self {
        Self { static_cfg }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware {
            inner,
            static_cfg: self.static_cfg.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
    static_cfg: Arc<StaticWebConfig>,
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
        let is_https = is_request_https(&req, &self.static_cfg);

        Box::pin(async move {
            let mut response = inner.call(req).await?;
            apply_security_headers(response.headers_mut(), &csp_nonce, is_https);
            Ok(response)
        })
    }
}

pub(crate) fn apply_security_headers(headers: &mut HeaderMap, nonce: &CspNonce, is_https: bool) {
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
    if is_https {
        headers.insert(
            HEADER_STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
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

pub(crate) fn is_request_https<B>(req: &Request<B>, cfg: &StaticWebConfig) -> bool {
    if cfg.tls_enabled {
        return true;
    }

    if req
        .uri()
        .scheme_str()
        .map(|scheme| scheme.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
    {
        return true;
    }

    let remote_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());

    let Some(ip) = remote_ip else { return false };
    if !cfg.security.is_trusted_proxy(ip) {
        return false;
    }

    if let Some(forwarded) = req.headers().get(header::FORWARDED) {
        if forwarded_proto_is_https(forwarded) {
            return true;
        }
    }

    if proto_header_is_https(req.headers().get("x-forwarded-proto")) {
        return true;
    }

    false
}

fn proto_header_is_https(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|val| val.to_str().ok())
        .map(|text| {
            text.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("https"))
        })
        .unwrap_or(false)
}

fn forwarded_proto_is_https(value: &HeaderValue) -> bool {
    let Ok(text) = value.to_str() else {
        return false;
    };
    for segment in text.split(',') {
        for directive in segment.split(';') {
            let mut kv = directive.splitn(2, '=');
            let key = kv.next().map(|k| k.trim().to_ascii_lowercase());
            if key.as_deref() != Some("proto") {
                continue;
            }
            if let Some(raw_val) = kv.next() {
                let trimmed = raw_val.trim().trim_matches('"').trim_matches('\'');
                if trimmed.eq_ignore_ascii_case("https") {
                    return true;
                }
            }
        }
    }
    false
}
