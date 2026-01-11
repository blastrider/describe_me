use crate::application::logging::LogEvent;
use crate::application::web::security::IpMatcher;
use crate::domain::DescribeError;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::debug;

#[derive(Clone, Debug, Default)]
pub(crate) struct OriginPolicy {
    allowed: Arc<[AllowedOrigin]>,
    trusted_proxies: Arc<[IpMatcher]>,
    default_scheme: OriginScheme,
}

impl OriginPolicy {
    pub fn from_allowlist(raw: Vec<String>) -> Result<Self, DescribeError> {
        let mut seen = HashSet::new();
        let mut allow = Vec::with_capacity(raw.len());
        for value in raw {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }
            let origin = AllowedOrigin::parse(trimmed)
                .map_err(|err| DescribeError::Config(format!("origin \"{trimmed}\": {err}")))?;
            if seen.insert(origin.clone()) {
                allow.push(origin);
            }
        }
        Ok(Self {
            allowed: allow.into(),
            trusted_proxies: Vec::new().into(),
            default_scheme: OriginScheme::Http,
        })
    }

    pub fn from_access(access: &super::WebAccess) -> Result<Self, DescribeError> {
        let mut policy = Self::from_allowlist(access.allow_origins.clone())?;
        let mut trusted = Vec::new();
        for raw in &access.trusted_proxies {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let matcher = IpMatcher::parse(trimmed)
                .map_err(|err| DescribeError::Config(format!("web.trusted_proxies: {err}")))?;
            if !trusted.contains(&matcher) {
                trusted.push(matcher);
            }
        }
        policy.trusted_proxies = trusted.into();
        policy.default_scheme = if access.tls.is_some() {
            OriginScheme::Https
        } else {
            OriginScheme::Http
        };
        Ok(policy)
    }

    pub(crate) fn cors_allowlist(&self) -> Arc<[String]> {
        self.allowed
            .iter()
            .map(AllowedOrigin::as_origin)
            .collect::<Vec<_>>()
            .into()
    }

    fn is_trusted_proxy<B>(&self, req: &Request<B>) -> bool {
        if self.trusted_proxies.is_empty() {
            return false;
        }
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let Some(ip) = ip else { return false };
        self.trusted_proxies.iter().any(|rule| rule.matches(ip))
    }

    pub fn allows<B>(&self, req: &Request<B>) -> bool {
        let origin_header = match req.headers().get(header::ORIGIN) {
            Some(origin) => origin,
            None => {
                if !self.allowed.is_empty() && !is_idempotent_method(req.method()) {
                    return false;
                }
                return true;
            }
        };
        let origin_str = match origin_header.to_str() {
            Ok(value) => value,
            Err(_) => return false,
        };
        if origin_str.eq_ignore_ascii_case("null") {
            return false;
        }
        let origin_uri: Uri = match origin_str.parse() {
            Ok(uri) => uri,
            Err(_) => return false,
        };

        let host_authority = match effective_host(req, self) {
            Some(auth) => auth,
            None => return false,
        };
        let origin_host = match origin_uri.host() {
            Some(host) => host,
            None => return false,
        };

        if !self.allowed.is_empty() {
            return self
                .allowed
                .iter()
                .any(|allowed| allowed.matches(&origin_uri));
        }

        let request_scheme = request_scheme(req, self);
        origin_uri
            .scheme_str()
            .map(|scheme| scheme.eq_ignore_ascii_case(&request_scheme))
            .unwrap_or(false)
            && origin_host.eq_ignore_ascii_case(host_authority.host())
            && origin_uri
                .port_u16()
                .or_else(|| default_port(origin_uri.scheme_str()))
                == host_authority
                    .port_u16()
                    .or_else(|| default_port(Some(request_scheme.as_str())))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AllowedOrigin {
    scheme: OriginScheme,
    host: String,
    port: Option<u16>,
}

impl AllowedOrigin {
    fn parse(input: &str) -> Result<Self, String> {
        let uri: Uri = input.parse::<Uri>().map_err(|err| err.to_string())?;
        let scheme = match uri.scheme_str() {
            Some(value) => OriginScheme::parse(value)
                .ok_or_else(|| format!("schéma non supporté: {value} (attendu http ou https)"))?,
            None => {
                return Err("origin incomplet: schéma requis (http ou https)".into());
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| "origin incomplet: hôte requis".to_string())?
            .to_owned();
        let port = uri.port_u16();
        if uri.path() != "/" && !uri.path().is_empty() {
            return Err("origin ne doit pas contenir de chemin".into());
        }
        if uri.query().is_some() {
            return Err("origin ne doit pas contenir de query string".into());
        }
        Ok(Self { scheme, host, port })
    }

    fn as_origin(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme.as_str(), host, port),
            None => format!("{}://{}", self.scheme.as_str(), host),
        }
    }

    fn matches(&self, candidate: &Uri) -> bool {
        let Some(host) = candidate.host() else {
            return false;
        };
        if !host.eq_ignore_ascii_case(&self.host) {
            return false;
        }
        match candidate.scheme_str() {
            Some(value) if self.scheme.matches(value) => {}
            _ => return false,
        }
        let candidate_port = candidate
            .port_u16()
            .or_else(|| default_port(candidate.scheme_str()));
        match self.port {
            Some(port) => candidate_port == Some(port),
            None => candidate_port == default_port(Some(self.scheme.as_str())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
enum OriginScheme {
    #[default]
    Http,
    Https,
}

impl OriginScheme {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "http" | "HTTP" => Some(OriginScheme::Http),
            "https" | "HTTPS" => Some(OriginScheme::Https),
            _ => None,
        }
    }

    fn matches(&self, other: &str) -> bool {
        match self {
            OriginScheme::Http => other.eq_ignore_ascii_case("http"),
            OriginScheme::Https => other.eq_ignore_ascii_case("https"),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            OriginScheme::Http => "http",
            OriginScheme::Https => "https",
        }
    }
}

fn effective_host<B>(
    req: &Request<B>,
    policy: &OriginPolicy,
) -> Option<axum::http::uri::Authority> {
    let has_forwarded = req.headers().contains_key("x-forwarded-host")
        || req.headers().contains_key(header::FORWARDED);
    if policy.is_trusted_proxy(req) {
        if let Some(auth) = forwarded_host(req.headers().get(header::FORWARDED)) {
            return Some(auth);
        }
        if let Some(auth) = host_header_value(req.headers().get("x-forwarded-host")) {
            return Some(auth);
        }
    } else if has_forwarded {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        debug!(?ip, "forwarded_host_ignored_untrusted");
    }

    if let Some(host) = req.headers().get(header::HOST) {
        if let Ok(host_str) = host.to_str() {
            if let Ok(auth) = host_str.parse() {
                return Some(auth);
            }
        }
    }
    if let Some(authority) = req.headers().get(":authority") {
        if let Ok(val) = authority.to_str() {
            if let Ok(auth) = val.parse() {
                return Some(auth);
            }
        }
    }
    if let Some(auth) = req.uri().authority().cloned() {
        return Some(auth);
    }
    None
}

fn host_header_value(value: Option<&HeaderValue>) -> Option<axum::http::uri::Authority> {
    value
        .and_then(|val| val.to_str().ok())
        .and_then(|text| text.split(',').next())
        .map(|part| part.trim().trim_matches('"').trim_matches('\''))
        .filter(|part| !part.is_empty())
        .and_then(|part| part.parse().ok())
}

fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}

fn request_scheme<B>(req: &Request<B>, policy: &OriginPolicy) -> String {
    if let Some(scheme) = req.uri().scheme_str() {
        return scheme.to_ascii_lowercase();
    }

    let has_forwarded = req.headers().contains_key("x-forwarded-proto")
        || req.headers().contains_key(header::FORWARDED);
    if policy.is_trusted_proxy(req) {
        if let Some(proto) = forwarded_proto(req.headers().get(header::FORWARDED)) {
            return proto;
        }
        if let Some(proto) = proto_header_value(req.headers().get("x-forwarded-proto")) {
            return proto;
        }
    } else if has_forwarded {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        debug!(?ip, "forwarded_proto_ignored_untrusted");
    }

    policy.default_scheme.as_str().to_string()
}

fn proto_header_value(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(|val| val.to_str().ok())
        .and_then(|text| text.split(',').next())
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
}

fn forwarded_proto(value: Option<&HeaderValue>) -> Option<String> {
    let text = value.and_then(|val| val.to_str().ok())?;
    for segment in text.split(',') {
        for directive in segment.split(';') {
            let mut kv = directive.splitn(2, '=');
            let key = kv.next().map(|k| k.trim().to_ascii_lowercase());
            if key.as_deref() != Some("proto") {
                continue;
            }
            if let Some(raw_val) = kv.next() {
                let trimmed = raw_val.trim().trim_matches('"').trim_matches('\'');
                if !trimmed.is_empty() {
                    return Some(trimmed.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

fn forwarded_host(value: Option<&HeaderValue>) -> Option<axum::http::uri::Authority> {
    let text = value.and_then(|val| val.to_str().ok())?;
    for segment in text.split(',') {
        for directive in segment.split(';') {
            let mut kv = directive.splitn(2, '=');
            let key = kv.next().map(str::trim);
            if key.map(|value| value.eq_ignore_ascii_case("host")) != Some(true) {
                continue;
            }
            if let Some(raw_val) = kv.next() {
                let trimmed = raw_val.trim().trim_matches('"').trim_matches('\'');
                if trimmed.is_empty()
                    || trimmed.eq_ignore_ascii_case("unknown")
                    || trimmed.starts_with('_')
                {
                    return None;
                }
                return trimmed.parse().ok();
            }
        }
    }
    None
}

fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::GET
            | &Method::HEAD
            | &Method::PUT
            | &Method::DELETE
            | &Method::OPTIONS
            | &Method::TRACE
    )
}

#[cfg(test)]
pub(crate) fn is_origin_allowed<B>(req: &Request<B>, policy: &OriginPolicy) -> bool {
    policy.allows(req)
}

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
