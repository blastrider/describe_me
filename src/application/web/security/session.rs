use super::TokenKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::application::web::WEB_SESSION_SECONDS;

pub(super) const SESSION_COOKIE_PREFIX: &str = "sess:v1:";
const SESSION_TTL_DEFAULT: Duration = Duration::from_secs(WEB_SESSION_SECONDS);
const SESSION_TTL_MIN: Duration = Duration::from_secs(60);
const SESSION_TTL_MAX: Duration = Duration::from_secs(WEB_SESSION_SECONDS);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub(super) struct SessionManager {
    inner: Arc<Mutex<SessionStore>>,
    session_ttl: Duration,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self::with_ttl(SESSION_TTL_DEFAULT)
    }

    pub(super) fn with_ttl(session_ttl: Duration) -> Self {
        let ttl = clamp_session_ttl(session_ttl);
        Self {
            inner: Arc::new(Mutex::new(SessionStore::new())),
            session_ttl: ttl,
        }
    }

    pub(super) fn issue(&self, token: TokenKey, now: Instant) -> String {
        let mut store = self.inner.lock().expect("session store poisoned");
        store.cleanup(now);

        let mut raw = [0u8; 24];
        let id = loop {
            OsRng.fill_bytes(&mut raw);
            let candidate = URL_SAFE_NO_PAD.encode(raw);
            if !store.entries.contains_key(&candidate) {
                break candidate;
            }
        };

        store.entries.insert(
            id.clone(),
            SessionEntry {
                token,
                expires_at: now.checked_add(self.session_ttl).unwrap_or(now),
            },
        );

        format!("{SESSION_COOKIE_PREFIX}{id}")
    }

    pub(super) fn lookup(
        &self,
        cookie: &str,
        now: Instant,
    ) -> Result<SessionCandidate, SessionError> {
        let Some(id) = cookie.strip_prefix(SESSION_COOKIE_PREFIX) else {
            return Err(SessionError::InvalidFormat);
        };

        let mut store = self.inner.lock().expect("session store poisoned");
        store.cleanup(now);

        match store.entries.get(id) {
            Some(entry) => {
                if entry.expires_at <= now {
                    store.entries.remove(id);
                    return Err(SessionError::Expired);
                }
                Ok(SessionCandidate {
                    id: id.to_owned(),
                    token: entry.token,
                })
            }
            None => Err(SessionError::Unknown),
        }
    }

    pub(super) fn consume(&self, id: &str, now: Instant) -> Result<(), SessionError> {
        let mut store = self.inner.lock().expect("session store poisoned");
        store.cleanup(now);
        match store.entries.get_mut(id) {
            Some(entry) => {
                if entry.expires_at <= now {
                    store.entries.remove(id);
                    return Err(SessionError::Expired);
                }
                entry.expires_at = now.checked_add(self.session_ttl).unwrap_or(now);
                Ok(())
            }
            None => Err(SessionError::Unknown),
        }
    }

    pub(super) fn ttl(&self) -> Duration {
        self.session_ttl
    }

    #[cfg(test)]
    pub(super) fn ttl_for_tests(&self) -> Duration {
        self.session_ttl
    }
}

#[derive(Debug)]
struct SessionStore {
    entries: HashMap<String, SessionEntry>,
    last_cleanup: Instant,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    fn cleanup(&mut self, now: Instant) {
        if now.duration_since(self.last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.last_cleanup = now;
    }
}

#[derive(Clone, Copy, Debug)]
struct SessionEntry {
    token: TokenKey,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct SessionCandidate {
    id: String,
    token: TokenKey,
}

impl SessionCandidate {
    pub(super) fn token_key(&self) -> TokenKey {
        self.token
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug)]
pub(super) enum SessionError {
    InvalidFormat,
    Unknown,
    Expired,
}

fn clamp_session_ttl(ttl: Duration) -> Duration {
    if ttl < SESSION_TTL_MIN {
        SESSION_TTL_MIN
    } else if ttl > SESSION_TTL_MAX {
        SESSION_TTL_MAX
    } else {
        ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_can_be_reused_until_expiry() {
        let ttl = Duration::from_secs(120);
        let manager = SessionManager::with_ttl(ttl);
        let start = Instant::now();
        let cookie = manager.issue(TokenKey::Anonymous, start);

        // first usage
        let t1 = start + Duration::from_secs(30);
        let candidate1 = manager.lookup(&cookie, t1).expect("lookup 1");
        manager.consume(candidate1.id(), t1).expect("consume 1");

        // reuse same session id
        let t2 = t1 + Duration::from_secs(30);
        let candidate2 = manager.lookup(&cookie, t2).expect("lookup 2");
        manager.consume(candidate2.id(), t2).expect("consume 2");

        // still valid shortly before expiry
        let t3 = t2 + Duration::from_secs(40);
        let candidate3 = manager.lookup(&cookie, t3).expect("lookup 3");
        manager.consume(candidate3.id(), t3).expect("consume 3");

        // long after ttl, session must expire
        let late = start + Duration::from_secs(500);
        assert!(manager.lookup(&cookie, late).is_err());
    }

    #[test]
    fn consume_extends_expiry_sliding_window() {
        let ttl = Duration::from_secs(90);
        let manager = SessionManager::with_ttl(ttl);
        let start = Instant::now();
        let cookie = manager.issue(TokenKey::Anonymous, start);

        // Touch near the end of the first window to extend it.
        let near_expiry = start + Duration::from_secs(80);
        let candidate = manager
            .lookup(&cookie, near_expiry)
            .expect("lookup before expiry");
        manager
            .consume(candidate.id(), near_expiry)
            .expect("consume refresh");

        // After refresh, the session should still be valid well past the original expiry.
        let refreshed = start + Duration::from_secs(150);
        manager
            .lookup(&cookie, refreshed)
            .expect("lookup after sliding refresh");
    }
}
