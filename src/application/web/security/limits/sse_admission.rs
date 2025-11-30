use std::net::IpAddr;
use std::sync::Arc;

use super::policy::SecurityPolicy;
use crate::application::web::security::sse::{ActiveSseState, SsePermit};
use crate::application::web::security::TokenKey;

/// Admission wrapper around `ActiveSseState`.
#[derive(Debug)]
pub(crate) struct SseAdmission {
    inner: Arc<ActiveSseState>,
}

impl SseAdmission {
    pub(crate) fn new() -> Self {
        Self {
            inner: ActiveSseState::new(),
        }
    }

    pub(crate) fn try_acquire(
        &self,
        ip: IpAddr,
        token: TokenKey,
        policy: &SecurityPolicy,
    ) -> Result<Option<SsePermit>, std::time::Duration> {
        self.inner.try_acquire(ip, token, policy.sse_limits())
    }
}

impl Default for SseAdmission {
    fn default() -> Self {
        Self::new()
    }
}
