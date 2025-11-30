use super::{
    brute_force_guard::BruteForceGuard, global_slots::GlobalSlots, rate_limiter::RateLimiter,
    sse_admission::SseAdmission, token_affinity::TokenAffinity, SecurityPolicy,
};

#[allow(dead_code)]
/// Orchestrateur de sécurité (esquisse, branché progressivement).
#[derive(Debug)]
pub(crate) struct WebSecurityEngine {
    pub(crate) policy: SecurityPolicy,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) brute_force: BruteForceGuard,
    pub(crate) affinity: TokenAffinity,
    pub(crate) sse: SseAdmission,
    pub(crate) global: GlobalSlots,
}

impl WebSecurityEngine {
    #[allow(dead_code)]
    pub(crate) fn new(policy: SecurityPolicy) -> Self {
        Self {
            policy,
            rate_limiter: RateLimiter::new(),
            brute_force: BruteForceGuard::new(),
            affinity: TokenAffinity::new(),
            sse: SseAdmission::new(),
            global: GlobalSlots::new(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }
}
