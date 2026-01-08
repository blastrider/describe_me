use super::{TokenFingerprint, TokenKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use rand_core::{OsRng, RngCore};
use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    hash::Hasher,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use axum::http::{header, HeaderMap, HeaderValue};
use tracing::warn;

use crate::application::web::WEB_SESSION_SECONDS;
use crate::domain::SessionCookieSameSite;

pub(super) const SESSION_COOKIE_PREFIX: &str = "sess:v1:";
const SESSION_TTL_DEFAULT: Duration = Duration::from_secs(WEB_SESSION_SECONDS);
const SESSION_TTL_MIN: Duration = Duration::from_secs(60);
const SESSION_TTL_MAX: Duration = Duration::from_secs(WEB_SESSION_SECONDS);
const SESSION_MAX_AGE_DEFAULT: Duration =
    Duration::from_secs(WEB_SESSION_SECONDS.saturating_mul(4));
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const SESSION_UA_MAX_LEN: usize = 256;
const SESSION_STORE_MAX_ENTRIES: usize = 10_000;
pub const SESSION_COOKIE_NAME: &str = "describe_me_session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientClaim(u64);

fn compute_client_claim(ip: IpAddr, user_agent: Option<&str>) -> ClientClaim {
    let mut hasher = DefaultHasher::new();
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            hasher.write_u8(4);
            hasher.write(&octets[..3]);
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            hasher.write_u8(6);
            for segment in segments.iter().take(4) {
                hasher.write_u16(*segment);
            }
        }
    }

    let ua = user_agent.unwrap_or("").trim();
    let mut ua_bytes = Vec::with_capacity(SESSION_UA_MAX_LEN.min(ua.len()));
    for byte in ua.as_bytes().iter().take(SESSION_UA_MAX_LEN) {
        ua_bytes.push(byte.to_ascii_lowercase());
    }
    hasher.write_usize(ua_bytes.len());
    hasher.write(&ua_bytes);

    ClientClaim(hasher.finish())
}

#[derive(Debug, Clone)]
pub(crate) struct SessionManager {
    inner: Arc<Mutex<SessionStore>>,
    session_ttl: Duration,
    session_max_age: Duration,
    bind_to_client: bool,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self::with_ttl(SESSION_TTL_DEFAULT)
    }

    pub(super) fn with_ttl(session_ttl: Duration) -> Self {
        Self::with_limits(session_ttl, SESSION_MAX_AGE_DEFAULT, false)
    }

    fn with_limits(session_ttl: Duration, session_max_age: Duration, bind_to_client: bool) -> Self {
        let ttl_requested = session_ttl;
        let ttl_effective = clamp_session_ttl(ttl_requested);
        if ttl_effective != ttl_requested {
            warn!(
                event = "web_session_ttl_clamped",
                requested_s = ttl_requested.as_secs(),
                effective_s = ttl_effective.as_secs(),
                min_s = SESSION_TTL_MIN.as_secs(),
                max_s = SESSION_TTL_MAX.as_secs(),
                "session_ttl_seconds is outside bounds; using effective value"
            );
        }
        let max_age = session_max_age.max(ttl_effective);
        Self {
            inner: Arc::new(Mutex::new(SessionStore::new())),
            session_ttl: ttl_effective,
            session_max_age: max_age,
            bind_to_client,
        }
    }

    pub(super) async fn issue(
        &self,
        token: TokenKey,
        token_fingerprint: TokenFingerprint,
        client_claim: Option<ClientClaim>,
        now: Instant,
    ) -> String {
        let mut store = self.inner.lock().await;
        store.cleanup(now);

        let issued_at = now;
        let absolute_deadline = issued_at
            .checked_add(self.session_max_age)
            .unwrap_or(issued_at);
        let sliding_deadline = now.checked_add(self.session_ttl).unwrap_or(now);
        let expires_at = if sliding_deadline < absolute_deadline {
            sliding_deadline
        } else {
            absolute_deadline
        };
        let client_claim = if self.bind_to_client {
            client_claim
        } else {
            None
        };
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
                token_fingerprint,
                client_claim,
                issued_at,
                expires_at,
            },
        );
        store.cleanup(now);
        if store.entries.len() > SESSION_STORE_MAX_ENTRIES {
            let over = store.entries.len() - SESSION_STORE_MAX_ENTRIES;
            if over > 0 {
                let mut entries: Vec<(String, Instant)> = store
                    .entries
                    .iter()
                    .map(|(id, entry)| (id.clone(), entry.expires_at))
                    .collect();
                entries.sort_by_key(|(_, expires_at)| *expires_at);
                for (id, _) in entries.into_iter().take(over) {
                    store.entries.remove(&id);
                }
            }
        }

        format!("{SESSION_COOKIE_PREFIX}{id}")
    }

    pub(super) async fn lookup(
        &self,
        cookie: &str,
        client_claim: Option<ClientClaim>,
        now: Instant,
    ) -> Result<SessionCandidate, SessionError> {
        let Some(id) = cookie.strip_prefix(SESSION_COOKIE_PREFIX) else {
            return Err(SessionError::InvalidFormat);
        };

        let mut store = self.inner.lock().await;
        store.cleanup(now);

        match store.entries.get(id) {
            Some(entry) => {
                if self.bind_to_client {
                    match (entry.client_claim, client_claim) {
                        (None, _) => {}
                        (Some(expected), Some(actual)) if expected == actual => {}
                        _ => {
                            store.entries.remove(id);
                            return Err(SessionError::BindingMismatch);
                        }
                    }
                }
                let absolute_deadline = entry
                    .issued_at
                    .checked_add(self.session_max_age)
                    .unwrap_or(entry.issued_at);
                if now >= absolute_deadline || entry.expires_at <= now {
                    store.entries.remove(id);
                    return Err(SessionError::Expired);
                }
                Ok(SessionCandidate {
                    id: id.to_owned(),
                    token: entry.token,
                    token_fingerprint: entry.token_fingerprint,
                })
            }
            None => Err(SessionError::Unknown),
        }
    }

    pub(super) async fn consume(&self, id: &str, now: Instant) -> Result<(), SessionError> {
        let mut store = self.inner.lock().await;
        store.cleanup(now);
        match store.entries.get_mut(id) {
            Some(entry) => {
                let absolute_deadline = entry
                    .issued_at
                    .checked_add(self.session_max_age)
                    .unwrap_or(entry.issued_at);
                if now >= absolute_deadline || entry.expires_at <= now {
                    store.entries.remove(id);
                    return Err(SessionError::Expired);
                }
                let sliding_deadline = now.checked_add(self.session_ttl).unwrap_or(now);
                entry.expires_at = if sliding_deadline < absolute_deadline {
                    sliding_deadline
                } else {
                    absolute_deadline
                };
                Ok(())
            }
            None => Err(SessionError::Unknown),
        }
    }

    pub(super) async fn revoke(&self, id: &str) {
        let mut store = self.inner.lock().await;
        store.entries.remove(id);
    }

    pub(super) fn ttl(&self) -> Duration {
        self.session_ttl
    }

    pub(super) fn client_claim(&self, ip: IpAddr, user_agent: Option<&str>) -> Option<ClientClaim> {
        if !self.bind_to_client {
            return None;
        }
        Some(compute_client_claim(ip, user_agent))
    }

    #[cfg(test)]
    pub(super) fn bind_to_client_for_tests(&self) -> bool {
        self.bind_to_client
    }

    #[cfg(test)]
    pub(super) fn ttl_for_tests(&self) -> Duration {
        self.session_ttl
    }

    #[cfg(test)]
    pub(super) async fn len_for_tests(&self) -> usize {
        let store = self.inner.lock().await;
        store.entries.len()
    }

    #[cfg(test)]
    pub(super) fn with_limits_for_tests(session_ttl: Duration, session_max_age: Duration) -> Self {
        Self::with_limits(session_ttl, session_max_age, false)
    }

    #[cfg(test)]
    pub(super) fn with_limits_and_binding_for_tests(
        session_ttl: Duration,
        session_max_age: Duration,
        bind_to_client: bool,
    ) -> Self {
        Self::with_limits(session_ttl, session_max_age, bind_to_client)
    }
}

pub struct WebSession<'a> {
    pub manager: &'a SessionManager,
}

impl<'a> WebSession<'a> {
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_for(
        &self,
        token_key: TokenKey,
        token_fingerprint: TokenFingerprint,
        client_claim: Option<ClientClaim>,
        headers: &mut HeaderMap,
        now: Instant,
        secure: bool,
        same_site: SessionCookieSameSite,
    ) {
        let cookie = self
            .manager
            .issue(token_key, token_fingerprint, client_claim, now)
            .await;
        set_session_cookie(headers, &cookie, self.manager.ttl(), secure, same_site);
    }

    pub async fn revoke_from_cookie_header(&self, raw_cookie_header: &str, _now: Instant) -> bool {
        let mut encoded_cookie = None;
        for pair in raw_cookie_header.split(';') {
            let mut kv = pair.trim().splitn(2, '=');
            let name = kv.next().map(str::trim);
            let Some(raw_value) = kv.next() else {
                continue;
            };
            if name != Some(SESSION_COOKIE_NAME) {
                continue;
            }
            let trimmed = raw_value.trim();
            if trimmed.is_empty() {
                return false;
            }
            encoded_cookie = Some(trimmed);
            break;
        }

        let Some(encoded) = encoded_cookie else {
            return false;
        };
        let decoded = match percent_decode_str(encoded).decode_utf8() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let Some(id) = decoded.strip_prefix(SESSION_COOKIE_PREFIX) else {
            return false;
        };
        self.manager.revoke(id).await;
        true
    }

    pub fn clear(&self, headers: &mut HeaderMap, secure: bool, same_site: SessionCookieSameSite) {
        clear_session_cookie(headers, secure, same_site);
    }
}

fn same_site_attr(value: SessionCookieSameSite) -> &'static str {
    match value {
        SessionCookieSameSite::Lax => "Lax",
        SessionCookieSameSite::Strict => "Strict",
        SessionCookieSameSite::None => "None",
    }
}

pub fn set_session_cookie(
    headers: &mut HeaderMap,
    value: &str,
    max_age: Duration,
    secure: bool,
    same_site: SessionCookieSameSite,
) {
    if value.is_empty() {
        return;
    }

    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let mut suffix = format!("; HttpOnly; SameSite={}", same_site_attr(same_site));
    if secure {
        suffix.push_str("; Secure");
    }
    let max_age_secs = max_age.as_secs().clamp(1, u64::from(u32::MAX));
    let cookie = format!(
        "{name}={value}; Path=/; Max-Age={max_age}{suffix}",
        name = SESSION_COOKIE_NAME,
        value = encoded,
        max_age = max_age_secs,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub fn clear_session_cookie(
    headers: &mut HeaderMap,
    secure: bool,
    same_site: SessionCookieSameSite,
) {
    let mut suffix = format!("; HttpOnly; SameSite={}", same_site_attr(same_site));
    if secure {
        suffix.push_str("; Secure");
    }
    let cookie = format!(
        "{name}=deleted; Path=/; Max-Age=0{suffix}",
        name = SESSION_COOKIE_NAME,
        suffix = suffix
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
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
    token_fingerprint: TokenFingerprint,
    client_claim: Option<ClientClaim>,
    issued_at: Instant,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct SessionCandidate {
    id: String,
    token: TokenKey,
    token_fingerprint: TokenFingerprint,
}

impl SessionCandidate {
    pub(super) fn token_key(&self) -> TokenKey {
        self.token
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn token_fingerprint(&self) -> TokenFingerprint {
        self.token_fingerprint
    }
}

#[derive(Debug)]
pub(super) enum SessionError {
    InvalidFormat,
    Unknown,
    Expired,
    BindingMismatch,
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
    fn session_ttl_is_clamped_to_bounds() {
        let min = SessionManager::with_ttl(Duration::from_secs(1));
        assert_eq!(min.ttl_for_tests(), Duration::from_secs(60));

        let max = SessionManager::with_ttl(Duration::from_secs(WEB_SESSION_SECONDS + 1));
        assert_eq!(
            max.ttl_for_tests(),
            Duration::from_secs(WEB_SESSION_SECONDS)
        );
    }

    #[tokio::test]
    async fn session_can_be_reused_until_expiry() {
        let ttl = Duration::from_secs(120);
        let manager = SessionManager::with_ttl(ttl);
        let start = Instant::now();
        let cookie = manager
            .issue(TokenKey::Anonymous, [0u8; 16], None, start)
            .await;

        // first usage
        let t1 = start + Duration::from_secs(30);
        let candidate1 = manager.lookup(&cookie, None, t1).await.expect("lookup 1");
        manager
            .consume(candidate1.id(), t1)
            .await
            .expect("consume 1");

        // reuse same session id
        let t2 = t1 + Duration::from_secs(30);
        let candidate2 = manager.lookup(&cookie, None, t2).await.expect("lookup 2");
        manager
            .consume(candidate2.id(), t2)
            .await
            .expect("consume 2");

        // still valid shortly before expiry
        let t3 = t2 + Duration::from_secs(40);
        let candidate3 = manager.lookup(&cookie, None, t3).await.expect("lookup 3");
        manager
            .consume(candidate3.id(), t3)
            .await
            .expect("consume 3");

        // long after ttl, session must expire
        let late = start + Duration::from_secs(500);
        assert!(manager.lookup(&cookie, None, late).await.is_err());
    }

    #[tokio::test]
    async fn consume_extends_expiry_sliding_window() {
        let ttl = Duration::from_secs(90);
        let manager = SessionManager::with_ttl(ttl);
        let start = Instant::now();
        let cookie = manager
            .issue(TokenKey::Anonymous, [0u8; 16], None, start)
            .await;

        // Touch near the end of the first window to extend it.
        let near_expiry = start + Duration::from_secs(80);
        let candidate = manager
            .lookup(&cookie, None, near_expiry)
            .await
            .expect("lookup before expiry");
        manager
            .consume(candidate.id(), near_expiry)
            .await
            .expect("consume refresh");

        // After refresh, the session should still be valid well past the original expiry.
        let refreshed = start + Duration::from_secs(150);
        manager
            .lookup(&cookie, None, refreshed)
            .await
            .expect("lookup after sliding refresh");
    }

    #[tokio::test]
    async fn session_store_eviction_caps_entries() {
        let ttl = Duration::from_secs(120_000);
        let manager = SessionManager::with_ttl(ttl);
        let start = Instant::now();
        let mut first_cookie = None;

        for i in 0..(SESSION_STORE_MAX_ENTRIES + 20) {
            let now = start + Duration::from_secs(i as u64);
            let cookie = manager
                .issue(TokenKey::Anonymous, [0u8; 16], None, now)
                .await;
            if i == 0 {
                first_cookie = Some(cookie);
            }
        }

        assert!(manager.len_for_tests().await <= SESSION_STORE_MAX_ENTRIES);

        let first_cookie = first_cookie.expect("first cookie");
        let now = start + Duration::from_secs((SESSION_STORE_MAX_ENTRIES + 30) as u64);
        let err = manager
            .lookup(&first_cookie, None, now)
            .await
            .expect_err("first cookie should be evicted");
        assert!(matches!(err, SessionError::Unknown | SessionError::Expired));
    }

    #[tokio::test]
    async fn session_expires_after_absolute_max_age() {
        let ttl = Duration::from_secs(60);
        let max_age = Duration::from_secs(180);
        let manager = SessionManager::with_limits_for_tests(ttl, max_age);
        let start = Instant::now();
        let cookie = manager
            .issue(TokenKey::Anonymous, [0u8; 16], None, start)
            .await;

        let t1 = start + Duration::from_secs(50);
        let candidate1 = manager.lookup(&cookie, None, t1).await.expect("lookup 1");
        manager
            .consume(candidate1.id(), t1)
            .await
            .expect("consume 1");

        let t2 = start + Duration::from_secs(109);
        let candidate2 = manager.lookup(&cookie, None, t2).await.expect("lookup 2");
        manager
            .consume(candidate2.id(), t2)
            .await
            .expect("consume 2");

        let t3 = start + Duration::from_secs(168);
        let candidate3 = manager.lookup(&cookie, None, t3).await.expect("lookup 3");
        manager
            .consume(candidate3.id(), t3)
            .await
            .expect("consume 3");

        let expired = start + Duration::from_secs(181);
        let err = manager
            .lookup(&cookie, None, expired)
            .await
            .expect_err("should expire after max age");
        assert!(matches!(err, SessionError::Expired | SessionError::Unknown));
    }

    #[tokio::test]
    async fn binding_enabled_accepts_same_ip_ua() {
        let ttl = Duration::from_secs(120);
        let max_age = Duration::from_secs(300);
        let manager = SessionManager::with_limits_and_binding_for_tests(ttl, max_age, true);
        assert!(manager.bind_to_client_for_tests());

        let ip = "192.0.2.10".parse::<std::net::IpAddr>().expect("ip");
        let claim = manager.client_claim(ip, Some("Agent/1.0")).expect("claim");
        let start = Instant::now();
        let cookie = manager
            .issue(TokenKey::Anonymous, [0u8; 16], Some(claim), start)
            .await;

        let candidate = manager
            .lookup(&cookie, Some(claim), start + Duration::from_secs(5))
            .await
            .expect("lookup");
        assert_eq!(candidate.token_key(), TokenKey::Anonymous);
    }

    #[tokio::test]
    async fn binding_enabled_rejects_different_claim() {
        let ttl = Duration::from_secs(120);
        let max_age = Duration::from_secs(300);
        let manager = SessionManager::with_limits_and_binding_for_tests(ttl, max_age, true);

        let ip = "192.0.2.10".parse::<std::net::IpAddr>().expect("ip");
        let claim_a = manager
            .client_claim(ip, Some("Agent/1.0"))
            .expect("claim a");
        let claim_b = manager
            .client_claim(ip, Some("Agent/2.0"))
            .expect("claim b");
        let start = Instant::now();
        let cookie = manager
            .issue(TokenKey::Anonymous, [0u8; 16], Some(claim_a), start)
            .await;

        let err = manager
            .lookup(&cookie, Some(claim_b), start + Duration::from_secs(5))
            .await
            .expect_err("mismatch should reject");
        assert!(matches!(err, SessionError::BindingMismatch));
        let err = manager
            .lookup(&cookie, Some(claim_a), start + Duration::from_secs(5))
            .await
            .expect_err("entry should be revoked");
        assert!(matches!(err, SessionError::Unknown | SessionError::Expired));
    }
}
