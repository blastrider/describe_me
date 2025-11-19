//! Limitation et politiques de sécurité Web.
//!
//! Cette hiérarchie est découpée en deux sous-modules:
//! - `policy` : définit la configuration des limites.
//! - `state` : implémente les compteurs et garde-fous associés.

mod policy;
mod state;

pub(crate) use policy::{SecurityPolicy, SsePolicy};
pub(crate) use state::{enforce_rate_limits, ensure_not_blocked, GlobalPermit, SecurityState};

#[cfg(test)]
mod tests;
