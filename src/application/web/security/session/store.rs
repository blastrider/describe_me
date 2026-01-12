use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::super::{TokenFingerprint, TokenKey};
use super::claim::ClientClaim;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const SESSION_STORE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug)]
pub(super) struct SessionStore {
    pub(super) entries: HashMap<String, SessionEntry>,
    last_cleanup: Instant,
}

impl SessionStore {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub(super) fn cleanup(&mut self, now: Instant) {
        if now.duration_since(self.last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.last_cleanup = now;
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SessionEntry {
    pub(super) token: TokenKey,
    pub(super) token_fingerprint: TokenFingerprint,
    pub(super) client_claim: Option<ClientClaim>,
    pub(super) issued_at: Instant,
    pub(super) expires_at: Instant,
}
