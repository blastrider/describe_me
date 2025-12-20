use crate::application::logging::LogEvent;
use crate::application::web::security::IpMatcher;
use crate::domain::DescribeError;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode, Uri};
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
            None => return true,
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

        let host_authority = match effective_host(req) {
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
            None => true,
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

fn effective_host<B>(req: &Request<B>) -> Option<axum::http::uri::Authority> {
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

#[allow(dead_code)]
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
                LogEvent::SecurityIncident {
                    category: Cow::Borrowed("origin_not_allowed"),
                    route: Cow::Owned(req.uri().path().to_string()),
                    ip: None,
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

            inner.call(req).await
        })
    }
}
