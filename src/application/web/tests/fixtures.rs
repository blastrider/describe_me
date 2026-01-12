use super::super::{AxumRequest, LogoAsset, WebAccess, WebSecurity};
use crate::application::exposure::Exposure;
use crate::application::web::state::StaticWebConfig;
use crate::domain::SessionCookieSameSite;
use axum::http::{header, Method};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn build_request(
    origin: Option<&str>,
    host: &str,
    uri: &str,
    method: Method,
) -> AxumRequest {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host);
    if let Some(origin_value) = origin {
        builder = builder.header(header::ORIGIN, origin_value);
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

pub(crate) fn build_request_with_headers(
    origin: Option<&str>,
    host: &str,
    scheme: &str,
) -> AxumRequest {
    build_request(origin, host, &format!("{scheme}://internal/"), Method::GET)
}

pub(crate) fn test_static_cfg(
    trusted_proxies: Vec<String>,
    tls_enabled: bool,
) -> Arc<StaticWebConfig> {
    let access = WebAccess {
        trusted_proxies,
        ..WebAccess::default()
    };
    let security = WebSecurity::build(
        access,
        #[cfg(feature = "config")]
        None,
    )
    .expect("security");

    Arc::new(StaticWebConfig {
        interval: Duration::from_secs(1),
        #[cfg(feature = "config")]
        config: None,
        web_debug: false,
        security: Arc::new(security),
        exposure: Exposure::all(),
        logo: LogoAsset::default(),
        session_cookie_secure: false,
        session_cookie_same_site: SessionCookieSameSite::Lax,
        session_ttl: Duration::from_secs(60),
        updates_refresh_ttl: Duration::from_secs(60),
        tls_enabled,
    })
}
