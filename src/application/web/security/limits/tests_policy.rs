use super::{enforce_rate_limits, ensure_not_blocked, SecurityPolicy, SecurityState};
use crate::application::web::security::{
    auth::{AuthRequest, Credential},
    TokenKey, WebRoute,
};
#[cfg(feature = "config")]
use crate::domain::WebSecurityConfig;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn request(route: WebRoute, require_token: bool) -> AuthRequest {
    AuthRequest {
        route,
        request_path: Arc::from(route.as_str()),
        remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        credential: Credential::None,
        token_key: TokenKey::Anonymous,
        require_token,
        trusted_ip: false,
        purge_session_cookie: false,
        client_claim: None,
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

#[tokio::test]
async fn per_token_does_not_global_throttle_anonymous_clients() {
    let state = SecurityState::new();

    let mut policy = SecurityPolicy::default();
    policy.override_html(super::policy::RoutePolicy::new(
        Duration::from_secs(60),
        0,
        1,
        0,
    ));

    let now = Instant::now();

    let mut req1 = request(WebRoute::Html, false);
    req1.remote_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    req1.token_key = TokenKey::Anonymous;

    let mut req2 = request(WebRoute::Html, false);
    req2.remote_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    req2.token_key = TokenKey::Anonymous;

    assert!(enforce_rate_limits(&state, &policy, &req1, now)
        .await
        .is_ok());
    assert!(enforce_rate_limits(&state, &policy, &req2, now)
        .await
        .is_ok());
    assert!(
        enforce_rate_limits(&state, &policy, &req1, now)
            .await
            .is_err(),
        "second hit from same anonymous IP should be rate limited"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn token_affinity_limit_zero_disables_affinity() {
    let state = SecurityState::new();
    let cfg = WebSecurityConfig {
        token_ip_affinity_limit: 0,
        ..WebSecurityConfig::default()
    };
    let policy = SecurityPolicy::from_config(&cfg);
    let now = Instant::now();
    let token = TokenKey::Fingerprint(42);

    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

    assert!(
        state
            .ensure_token_affinity(WebRoute::Html, token, ip1, &policy, false, now)
            .await
    );
    assert!(
        state
            .ensure_token_affinity(WebRoute::Html, token, ip2, &policy, false, now)
            .await
    );
}

#[test]
fn history_route_defaults_are_generous_enough() {
    let policy = SecurityPolicy::default();
    let history = policy.route_policy(WebRoute::History);

    assert_eq!(history.ip_limit(1, false), 24);
    assert_eq!(history.token_limit(), 16);
    assert_eq!(history.global_limit(), 120);
}
