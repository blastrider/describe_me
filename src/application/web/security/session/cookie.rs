use axum::http::{header, HeaderMap, HeaderValue};
use percent_encoding::percent_decode_str;
use std::time::Duration;

use crate::domain::SessionCookieSameSite;

pub const SESSION_COOKIE_NAME: &str = "describe_me_session";

pub(super) fn session_id_from_cookie_header(raw_cookie_header: &str) -> Option<String> {
    let mut encoded_cookie = None;
    for pair in raw_cookie_header.split(';') {
        let mut kv = pair.trim().splitn(2, '=');
        let name = kv.next().map(str::trim);
        let Some(raw_value) = kv.next() else {
            continue;
        };
        if name != Some(SESSION_COOKIE_NAME) {
            continue;
        }
        let trimmed = raw_value.trim();
        if trimmed.is_empty() {
            return None;
        }
        encoded_cookie = Some(trimmed);
        break;
    }

    let encoded = encoded_cookie?;
    let decoded = percent_decode_str(encoded).decode_utf8().ok()?;
    decoded
        .strip_prefix(super::SESSION_COOKIE_PREFIX)
        .map(str::to_string)
}

fn same_site_attr(value: SessionCookieSameSite) -> &'static str {
    match value {
        SessionCookieSameSite::Lax => "Lax",
        SessionCookieSameSite::Strict => "Strict",
        SessionCookieSameSite::None => "None",
    }
}

pub fn set_session_cookie(
    headers: &mut HeaderMap,
    value: &str,
    max_age: Duration,
    secure: bool,
    same_site: SessionCookieSameSite,
) {
    if value.is_empty() {
        return;
    }

    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let mut suffix = format!("; HttpOnly; SameSite={}", same_site_attr(same_site));
    if secure {
        suffix.push_str("; Secure");
    }
    let max_age_secs = max_age.as_secs().clamp(1, u64::from(u32::MAX));
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}{suffix}",
        name = SESSION_COOKIE_NAME,
        value = encoded,
        max_age = max_age_secs,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub fn clear_session_cookie(
    headers: &mut HeaderMap,
    secure: bool,
    same_site: SessionCookieSameSite,
) {
    let mut suffix = format!("; HttpOnly; SameSite={}", same_site_attr(same_site));
    if secure {
        suffix.push_str("; Secure");
    }
    let cookie = format!(
        "{name}=deleted; Path=/; Max-Age=0{suffix}",
        name = SESSION_COOKIE_NAME,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}
