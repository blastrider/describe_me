use crate::application::logging::LogEvent;
use crate::domain::DescribeError;
use axum::extract::Request;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone, Debug, Default)]
pub(crate) struct OriginPolicy {
    allowed: Arc<[AllowedOrigin]>,
}

impl OriginPolicy {
    pub fn from_allowlist(raw: Vec<String>) -> Result<Self, DescribeError> {
        if raw.is_empty() {
            return Ok(Self::default());
        }
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
        })
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

        let same_origin = origin_host.eq_ignore_ascii_case(host_authority.host())
            && origin_uri
                .port_u16()
                .or_else(|| default_port(origin_uri.scheme_str()))
                == host_authority
                    .port_u16()
                    .or_else(|| default_port(origin_uri.scheme_str()));

        if !self.allowed.is_empty() {
            if self
                .allowed
                .iter()
                .any(|allowed| allowed.matches(&origin_uri))
            {
                return true;
            }
            return same_origin;
        }

        same_origin
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum OriginScheme {
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
