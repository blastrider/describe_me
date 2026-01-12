use super::allowed::{default_port, AllowedOrigin, OriginScheme};
use crate::application::web::security::IpMatcher;
use crate::domain::DescribeError;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, Uri};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
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

    pub fn from_access(access: &super::super::WebAccess) -> Result<Self, DescribeError> {
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
