//! Limitation et politiques de sécurité Web.
//!
//! Cette hiérarchie est découpée en plusieurs sous-modules:
//! - `policy` : définit la configuration des limites.
//! - `state` : implémente les compteurs et garde-fous associés.
//! - `rate_limiter`, `brute_force_guard`, `sliding`, `token_affinity`, `sse_admission`, `global_slots`
//!   : composants spécialisés réutilisables.
//! - `engine` : orchestrateur interne (prépare la refactorisation).
//! - `global_slots` : cap de concurrence par route; un flux SSE conserve un slot jusqu'à fermeture.

mod brute_force_guard;
mod engine;
mod global_slots;
mod policy;
mod rate_limiter;
mod sliding;
mod sse_admission;
mod state;
mod token_affinity;

#[allow(unused_imports)]
pub(crate) use brute_force_guard::{BruteForceGuard, FailureOutcome};
#[allow(unused_imports)]
pub(crate) use engine::WebSecurityEngine;
#[allow(unused_imports)]
pub(crate) use global_slots::{GlobalSlots, GlobalSlotsByRoute};
pub(crate) use policy::{SecurityPolicy, SsePolicy};
#[allow(unused_imports)]
pub(crate) use rate_limiter::{RateLimitDecision, RateLimiter};
#[allow(unused_imports)]
pub(crate) use sse_admission::SseAdmission;
pub(crate) use state::{enforce_rate_limits, ensure_not_blocked, GlobalPermit, SecurityState};
#[allow(unused_imports)]
pub(crate) use token_affinity::TokenAffinity;

#[cfg(test)]
mod tests_policy;
