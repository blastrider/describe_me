use super::super::{IpMatcher, WebRoute};
use super::logging::log_forwarded_error;
use axum::http::{header::FORWARDED, request::Parts};
use std::net::IpAddr;

const MAX_FORWARDED_HEADER_LEN: usize = 1024;
const MAX_FORWARDED_HOPS: usize = 32;

pub(super) fn resolve_client_ip(
    source_ip: IpAddr,
    trusted: &[IpMatcher],
    parts: &Parts,
    route: WebRoute,
) -> (IpAddr, bool) {
    if trusted.is_empty() || !ip_matches(source_ip, trusted) {
        return (source_ip, false);
    }

    if let Some(header_value) = parts.headers.get("x-forwarded-for") {
        let Ok(header_str) = header_value.to_str() else {
            log_forwarded_error(
                "forwarded_for_invalid",
                route,
                Some(parts.uri.path()),
                source_ip,
                "non_utf8",
            );
            return (source_ip, false);
        };
        if header_str.len() > MAX_FORWARDED_HEADER_LEN {
            log_forwarded_error(
                "forwarded_for_too_long",
                route,
                Some(parts.uri.path()),
                source_ip,
                "too_long",
            );
            return (source_ip, false);
        }

        let mut ip_chain = Vec::new();
        for segment in header_str.split(',') {
            let token = segment.trim();
            if token.is_empty() {
                continue;
            }
            if ip_chain.len() >= MAX_FORWARDED_HOPS {
                log_forwarded_error(
                    "forwarded_for_too_many",
                    route,
                    Some(parts.uri.path()),
                    source_ip,
                    "too_many_hops",
                );
                return (source_ip, false);
            }
            match token.parse::<IpAddr>() {
                Ok(ip) => ip_chain.push(ip),
                Err(_) => {
                    log_forwarded_error(
                        "forwarded_for_invalid",
                        route,
                        Some(parts.uri.path()),
                        source_ip,
                        token,
                    );
                    return (source_ip, false);
                }
            }
        }

        if ip_chain.is_empty() {
            return (source_ip, false);
        }

        if ip_chain.last() != Some(&source_ip) {
            log_forwarded_error(
                "forwarded_for_source_mismatch",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }

        if ip_chain.iter().skip(1).any(|ip| !ip_matches(*ip, trusted)) {
            log_forwarded_error(
                "forwarded_for_untrusted_chain",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }

        let client_ip = ip_chain[0];
        return (client_ip, true);
    }

    let header_value = match parts.headers.get(FORWARDED) {
        Some(value) => value,
        None => return (source_ip, false),
    };

    let Ok(header_str) = header_value.to_str() else {
        log_forwarded_error(
            "forwarded_header_invalid",
            route,
            Some(parts.uri.path()),
            source_ip,
            "non_utf8",
        );
        return (source_ip, false);
    };
    if header_str.len() > MAX_FORWARDED_HEADER_LEN {
        log_forwarded_error(
            "forwarded_header_too_long",
            route,
            Some(parts.uri.path()),
            source_ip,
            "too_long",
        );
        return (source_ip, false);
    }

    let (ip_chain, by_ip) = match parse_forwarded_chain(header_str, MAX_FORWARDED_HOPS) {
        Ok(value) => value,
        Err(detail) => {
            log_forwarded_error(
                "forwarded_header_invalid",
                route,
                Some(parts.uri.path()),
                source_ip,
                &detail,
            );
            return (source_ip, false);
        }
    };

    if ip_chain.is_empty() {
        return (source_ip, false);
    }

    if let Some(by_ip) = by_ip {
        if by_ip != source_ip {
            log_forwarded_error(
                "forwarded_header_source_mismatch",
                route,
                Some(parts.uri.path()),
                source_ip,
                header_str,
            );
            return (source_ip, false);
        }
    }

    if ip_chain.iter().skip(1).any(|ip| !ip_matches(*ip, trusted)) {
        log_forwarded_error(
            "forwarded_header_untrusted_chain",
            route,
            Some(parts.uri.path()),
            source_ip,
            header_str,
        );
        return (source_ip, false);
    }

    let client_ip = ip_chain[0];
    (client_ip, true)
}

fn parse_forwarded_chain(
    header_str: &str,
    max_hops: usize,
) -> Result<(Vec<IpAddr>, Option<IpAddr>), String> {
    let mut chain = Vec::new();
    let mut last_by = None;

    for segment in header_str.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if chain.len() >= max_hops {
            return Err("too_many_hops".to_string());
        }

        let mut for_ip = None;
        let mut by_ip = None;
        for directive in segment.split(';') {
            let mut kv = directive.splitn(2, '=');
            let key = kv.next().map(str::trim);
            let Some(raw_val) = kv.next() else {
                continue;
            };
            let raw_val = raw_val.trim();
            if raw_val.is_empty() {
                continue;
            }

            if key.map(|value| value.eq_ignore_ascii_case("for")) == Some(true) {
                let ip = parse_forwarded_ip(raw_val).ok_or_else(|| raw_val.to_string())?;
                for_ip = Some(ip);
            } else if key.map(|value| value.eq_ignore_ascii_case("by")) == Some(true) {
                if let Some(ip) = parse_forwarded_ip(raw_val) {
                    by_ip = Some(ip);
                }
            }
        }

        let Some(ip) = for_ip else {
            return Err(segment.to_string());
        };
        chain.push(ip);
        last_by = by_ip;
    }

    if chain.is_empty() {
        return Err(header_str.trim().to_string());
    }

    Ok((chain, last_by))
}

fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") || trimmed.starts_with('_') {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip_str = &rest[..end];
        return ip_str.parse().ok();
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        return host.parse::<IpAddr>().ok();
    }

    None
}

fn ip_matches(ip: IpAddr, rules: &[IpMatcher]) -> bool {
    rules.iter().any(|rule| rule.matches(ip))
}
