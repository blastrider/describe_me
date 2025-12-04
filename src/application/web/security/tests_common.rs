use super::*;
use axum::{extract::ConnectInfo, http::Request};
use std::net::IpAddr;
use std::sync::OnceLock;

pub(super) fn make_access(token: Option<&str>) -> WebAccess {
    WebAccess {
        token: token.map(|t| t.to_string()),
        allow_ips: Vec::new(),
        allow_origins: Vec::new(),
        trusted_proxies: Vec::new(),
        tls: None,
        session_cookie_secure: true,
    }
}

pub(super) fn bcrypt_hash(token: &str) -> String {
    bcrypt::hash(token, bcrypt::DEFAULT_COST).expect("bcrypt hash")
}

pub(super) fn cached_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| bcrypt_hash("secret"))
}

#[cfg(feature = "config")]
pub(super) fn build_security(token: Option<&str>) -> WebSecurity {
    WebSecurity::build(make_access(token), None).unwrap()
}

#[cfg(not(feature = "config"))]
pub(super) fn build_security(token: Option<&str>) -> WebSecurity {
    WebSecurity::build(make_access(token)).unwrap()
}

pub(super) fn make_parts(path: &str, ip: IpAddr, token: Option<&str>) -> Parts {
    let request = Request::builder().uri(path).body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    if let Some(token) = token {
        parts.headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
    }
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((ip, 4242))));
    parts
}
