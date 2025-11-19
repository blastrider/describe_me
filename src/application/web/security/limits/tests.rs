use super::{enforce_rate_limits, ensure_not_blocked, SecurityPolicy, SecurityState};
use crate::application::web::security::{
    auth::{AuthRequest, Credential},
    TokenKey, WebRoute,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn request(route: WebRoute, require_token: bool) -> AuthRequest {
    AuthRequest {
        route,
        remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        credential: Credential::None,
        token_key: TokenKey::Anonymous,
        require_token,
        trusted_ip: false,
    }
}

#[tokio::test]
async fn ensure_not_blocked_respects_cooldown() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let req = request(WebRoute::Html, false);
    let now = Instant::now();

    for _ in 0..policy.brute_force().threshold() {
        let _ = state
            .note_failure(req.remote_ip, req.token_key, now, &policy, req.route)
            .await;
    }

    assert!(
        ensure_not_blocked(&state, &policy, &req, now)
            .await
            .is_err(),
        "cooldown should trigger rejection"
    );
}

#[tokio::test]
async fn enforce_rate_limits_blocks_after_threshold() {
    let state = SecurityState::new();

    let mut policy = SecurityPolicy::default();
    policy.override_html(super::policy::RoutePolicy::new(
        Duration::from_secs(60),
        1,
        1,
        2,
    ));

    let req = request(WebRoute::Html, false);
    let now = Instant::now();

    assert!(enforce_rate_limits(&state, &policy, &req, now)
        .await
        .is_ok());
    assert!(
        enforce_rate_limits(&state, &policy, &req, now)
            .await
            .is_err(),
        "second hit should trigger rate limit"
    );
}
