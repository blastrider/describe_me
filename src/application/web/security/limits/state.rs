use std::{
    borrow::Cow,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use super::super::{auth::AuthRequest, sse::SsePermit, SecurityRejection, TokenKey, WebRoute};
use super::policy::SecurityPolicy;
use super::{
    brute_force_guard::{BruteForceGuard, FailureOutcome},
    rate_limiter::RateLimiter,
    token_affinity::TokenAffinity,
    GlobalSlots, SseAdmission,
};
use crate::application::logging::LogEvent;

/// Stocke les composants d'exécution utilisés pour faire appliquer
/// les politiques de sécurité web.
#[derive(Debug)]
pub(crate) struct SecurityState {
    rate_limiter: RateLimiter,
    brute_force: BruteForceGuard,
    token_affinity: TokenAffinity,
    sse_admission: SseAdmission,
    global_slots: GlobalSlots,
}

#[derive(Debug)]
pub(crate) struct GlobalPermit {
    state: Arc<SecurityState>,
}

impl GlobalPermit {
    fn new(state: Arc<SecurityState>) -> Self {
        Self { state }
    }
}

impl Drop for GlobalPermit {
    fn drop(&mut self) {
        self.state.release_global();
    }
}

impl SecurityState {
    pub(crate) fn new() -> Self {
        Self {
            rate_limiter: RateLimiter::new(),
            brute_force: BruteForceGuard::new(),
            token_affinity: TokenAffinity::new(),
            sse_admission: SseAdmission::new(),
            global_slots: GlobalSlots::new(),
        }
    }

    fn try_acquire_global(&self, limit: u32) -> Result<(), ()> {
        self.global_slots.try_acquire(limit)
    }

    fn release_global(&self) {
        self.global_slots.release();
    }

    pub(crate) fn acquire_global_permit(
        self: &Arc<Self>,
        route: WebRoute,
        policy: &SecurityPolicy,
    ) -> Result<Option<GlobalPermit>, SecurityRejection> {
        let limit = policy.route_policy(route).global_limit();
        if limit == 0 {
            return Ok(None);
        }
        self.try_acquire_global(limit).map_err(|_| {
            emit_security_incident(
                "rate_limit_global",
                route,
                None,
                None,
                Some(format!("limit={limit}")),
            );
            SecurityRejection::rate_limited(Duration::from_secs(1))
        })?;
        Ok(Some(GlobalPermit::new(Arc::clone(self))))
    }

    pub(super) async fn register_ip_hit(
        &self,
        route: WebRoute,
        ip: IpAddr,
        policy: &SecurityPolicy,
        trusted: bool,
        now: Instant,
    ) -> Option<Duration> {
        let decision = self
            .rate_limiter
            .register_ip_hit(route, ip, policy, trusted, now)
            .await;
        match decision {
            dec if dec.is_allowed() => None,
            dec => dec.retry_after(),
        }
    }

    pub(super) async fn register_token_hit(
        &self,
        route: WebRoute,
        token: TokenKey,
        policy: &SecurityPolicy,
        now: Instant,
    ) -> Option<Duration> {
        let decision = self
            .rate_limiter
            .register_token_hit(route, token, policy, now)
            .await;
        match decision {
            dec if dec.is_allowed() => None,
            dec => dec.retry_after(),
        }
    }

    pub(crate) async fn ensure_token_affinity(
        &self,
        route: WebRoute,
        token: TokenKey,
        ip: IpAddr,
        policy: &SecurityPolicy,
        trusted: bool,
        now: Instant,
    ) -> bool {
        let limit = policy.token_affinity_limit(trusted);
        if limit == 0 {
            return true;
        }
        let window = policy.route_policy(route).window();
        self.token_affinity
            .ensure(route, token, ip, window, limit, now)
            .await
    }

    pub(super) async fn check_existing_block(
        &self,
        ip: IpAddr,
        token: TokenKey,
        now: Instant,
        policy: &SecurityPolicy,
    ) -> Option<Duration> {
        self.brute_force
            .existing_block(ip, token, now, policy.brute_force())
            .await
    }

    pub(crate) async fn note_failure(
        &self,
        ip: IpAddr,
        token: TokenKey,
        now: Instant,
        policy: &SecurityPolicy,
        route: WebRoute,
    ) -> FailureOutcome {
        let outcome = self
            .brute_force
            .note_failure(ip, token, now, policy.brute_force(), route)
            .await;

        FailureOutcome {
            retry_after: outcome.retry_after().map(|d| policy.adjust_retry(route, d)),
        }
    }

    pub(crate) async fn note_success(&self, ip: IpAddr, token: TokenKey) {
        self.brute_force.note_success(ip, token).await;
    }

    pub(crate) fn acquire_sse(
        &self,
        ip: IpAddr,
        token: TokenKey,
        policy: &SecurityPolicy,
    ) -> Result<Option<SsePermit>, Duration> {
        self.sse_admission.try_acquire(ip, token, policy)
    }
}

pub(crate) async fn ensure_not_blocked(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    if let Some(delay) = state
        .check_existing_block(request.remote_ip, request.token_key, now, policy)
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "cooldown_active",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::cooldown(delay));
    }
    Ok(())
}

pub(crate) async fn enforce_rate_limits(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    if let Some(delay) = state
        .register_ip_hit(
            request.route,
            request.remote_ip,
            policy,
            request.trusted_ip,
            now,
        )
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "rate_limit_ip",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    if let Some(delay) = state
        .register_token_hit(request.route, request.token_key, policy, now)
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "rate_limit_token",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    Ok(())
}

fn emit_security_incident(
    category: &'static str,
    route: WebRoute,
    ip: Option<IpAddr>,
    token: Option<TokenKey>,
    detail: Option<String>,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Owned(route.as_str().to_string()),
        ip: ip.map(|addr| Cow::Owned(addr.to_string())),
        token: token.map(|key| Cow::Owned(key.to_string())),
        detail: detail.map(Cow::Owned),
    }
    .emit();
}
