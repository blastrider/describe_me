use axum::http::{header, request::Parts};
use std::time::Duration;
use tokio::time::sleep;

use super::WebRoute;

pub(super) fn accepts_html(parts: &Parts, route: WebRoute) -> bool {
    let accept = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let wants_html =
        accept.map(|raw| raw.contains("text/html") || raw.contains("application/xhtml+xml"));
    let is_api_request = matches!(route, WebRoute::History | WebRoute::Metrics)
        || parts.uri.path().starts_with("/api/");

    if is_api_request {
        return wants_html.unwrap_or(false);
    }

    wants_html.unwrap_or(false) || accept.map(|raw| raw.contains("*/*")).unwrap_or(true)
}

pub(super) fn jitter(delay: Duration) -> Duration {
    let extra = Duration::from_millis(fastrand::u32(0..=750) as u64);
    delay.saturating_add(extra)
}

pub(super) fn retry_after_seconds(delay: Duration) -> u64 {
    let secs = delay.as_secs();
    let mut total = if secs == 0 && delay.subsec_nanos() > 0 {
        1
    } else if delay.subsec_nanos() > 0 {
        secs.saturating_add(1)
    } else {
        secs
    };
    if total == 0 {
        total = 1;
    }
    total
}

pub(super) async fn uniform_auth_delay() {
    let base = 120;
    let jitter = fastrand::u64(0..=120);
    sleep(Duration::from_millis(base + jitter)).await;
}
