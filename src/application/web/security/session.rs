use super::TokenKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SESSION_TTL: Duration = Duration::from_secs(180);
const REPLAY_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
pub(super) const SESSION_COOKIE_PREFIX: &str = "sess:v1:";

#[derive(Debug, Clone)]
pub(super) struct SessionManager {
    inner: Arc<Mutex<SessionStore>>,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionStore {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
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
                expires_at: now.checked_add(SESSION_TTL).unwrap_or(now),
                used: false,
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
                if entry.used {
                    return Err(SessionError::Replay);
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
                if entry.used {
                    return Err(SessionError::Replay);
                }
                entry.used = true;
                entry.expires_at = now.checked_add(REPLAY_TTL).unwrap_or(now);
                Ok(())
            }
            None => Err(SessionError::Unknown),
        }
    }
}

#[derive(Debug)]
struct SessionStore {
    entries: HashMap<String, SessionEntry>,
    last_cleanup: Instant,
}

impl SessionStore {
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
    used: bool,
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
    Replay,
}
