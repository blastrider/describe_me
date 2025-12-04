//! Limitation et politiques de sécurité Web.
//!
//! Cette hiérarchie est découpée en plusieurs sous-modules:
//! - `policy` : définit la configuration des limites.
//! - `state` : implémente les compteurs et garde-fous associés.
//! - `rate_limiter`, `brute_force_guard`, `token_affinity`, `sse_admission`, `global_slots`
//!   : composants spécialisés réutilisables.
//! - `engine` : orchestrateur interne (prépare la refactorisation).

mod brute_force_guard;
mod engine;
mod global_slots;
mod policy;
mod rate_limiter;
mod sse_admission;
mod state;
mod token_affinity;

#[allow(unused_imports)]
pub(crate) use brute_force_guard::{BruteForceGuard, FailureOutcome};
#[allow(unused_imports)]
pub(crate) use engine::WebSecurityEngine;
#[allow(unused_imports)]
pub(crate) use global_slots::GlobalSlots;
pub(crate) use policy::{SecurityPolicy, SsePolicy};
#[allow(unused_imports)]
pub(crate) use rate_limiter::{RateLimitDecision, RateLimitScope, RateLimiter};
#[allow(unused_imports)]
pub(crate) use sse_admission::SseAdmission;
pub(crate) use state::{enforce_rate_limits, ensure_not_blocked, GlobalPermit, SecurityState};
#[allow(unused_imports)]
pub(crate) use token_affinity::TokenAffinity;

#[cfg(test)]
mod tests_policy;
