use std::borrow::Cow;

use crate::application::logging::LogEvent;

use super::auth::AuthRequest;

pub(super) fn emit_security_incident(
    category: &'static str,
    request: &AuthRequest,
    detail: Option<String>,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Borrowed(request.route.as_str()),
        request_path: Some(Cow::Borrowed(request.request_path.as_ref())),
        ip: Some(Cow::Owned(request.remote_ip.to_string())),
        token: Some(Cow::Owned(request.token_key.to_string())),
        detail: detail.map(Cow::Owned),
    }
    .emit();
}
