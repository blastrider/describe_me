use super::super::{session::SessionError, TokenKey, WebRoute};
use super::request::AuthRequest;
use crate::application::logging::LogEvent;
use std::{borrow::Cow, net::IpAddr};

pub(super) fn log_forwarded_error(
    category: &'static str,
    route: WebRoute,
    request_path: Option<&str>,
    source_ip: IpAddr,
    detail: &str,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
        ip: Some(Cow::Owned(source_ip.to_string())),
        token: None,
        detail: Some(Cow::Owned(detail.to_string())),
    }
    .emit();
}

pub(super) fn log_session_error(err: &SessionError, request: &AuthRequest) {
    log_session_error_raw(
        err,
        request.route,
        Some(request.request_path.as_ref()),
        request.remote_ip,
        request.token_key,
    );
}

pub(super) fn log_session_error_raw(
    err: &SessionError,
    route: WebRoute,
    request_path: Option<&str>,
    ip: IpAddr,
    token: TokenKey,
) {
    let (category, include_details) = match err {
        SessionError::InvalidFormat => ("session_invalid_format", true),
        SessionError::Unknown => ("session_unknown", true),
        SessionError::Expired => ("session_expired", true),
        SessionError::BindingMismatch => ("session_binding_mismatch", false),
    };
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
        ip: if include_details {
            Some(Cow::Owned(ip.to_string()))
        } else {
            None
        },
        token: if include_details {
            Some(Cow::Owned(token.to_string()))
        } else {
            None
        },
        detail: None,
    }
    .emit();
}

pub(super) fn log_session_token_mismatch(route: WebRoute, request_path: Option<&str>, ip: IpAddr) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed("session_token_mismatch"),
        route: Cow::Borrowed(route.as_str()),
        request_path: request_path.map(Cow::Borrowed),
        ip: Some(Cow::Owned(ip.to_string())),
        token: None,
        detail: None,
    }
    .emit();
}
