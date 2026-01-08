use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::rate_limiter::RouteKey;
use crate::application::web::security::{TokenKey, WebRoute};

const MAX_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
// Guardrail against unbounded key floods; keep comfortably above typical traffic.
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug)]
pub(crate) struct TokenAffinity {
    inner: Mutex<TokenAffinityState>,
}

#[derive(Debug)]
struct TokenAffinityState {
    entries: HashMap<(RouteKey, TokenKey), TokenAffinityRecord>,
    last_cleanup: Instant,
}

impl TokenAffinity {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(TokenAffinityState {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }

    pub(crate) async fn ensure(
        &self,
        route: WebRoute,
        token: TokenKey,
        ip: IpAddr,
        window: Duration,
        limit: u32,
        now: Instant,
    ) -> bool {
        if token == TokenKey::Anonymous {
            return true;
        }
        if limit == 0 {
            return true;
        }

        let mut guard = self.inner.lock().await;
        self.cleanup_if_needed(&mut guard, now, window);
        let len = {
            let record = guard
                .entries
                .entry((route.into(), token))
                .or_insert_with(|| TokenAffinityRecord::new(now, window));
            record.purge(now, window);
            record.register(ip, now);
            record.expires_at = now + window;
            record.len()
        };
        self.enforce_cap(&mut guard);
        (len as u32) <= limit
    }

    fn cleanup_if_needed(&self, state: &mut TokenAffinityState, now: Instant, window: Duration) {
        let interval = cleanup_interval(window);
        if now
            .checked_duration_since(state.last_cleanup)
            .map(|elapsed| elapsed < interval)
            .unwrap_or(false)
        {
            return;
        }

        state.last_cleanup = now;
        state
            .entries
            .retain(|_, record| record.expires_at > now && !record.ips.is_empty());
    }

    fn enforce_cap(&self, state: &mut TokenAffinityState) {
        while state.entries.len() > MAX_ENTRIES {
            let Some(key) = state.entries.keys().next().copied() else {
                break;
            };
            state.entries.remove(&key);
        }
    }
}

#[derive(Debug)]
struct TokenAffinityRecord {
    ips: HashMap<IpAddr, Instant>,
    expires_at: Instant,
}

impl TokenAffinityRecord {
    fn new(now: Instant, window: Duration) -> Self {
        Self {
            ips: HashMap::new(),
            expires_at: now + window,
        }
    }

    fn purge(&mut self, now: Instant, window: Duration) {
        self.ips
            .retain(|_, ts| now.saturating_duration_since(*ts) <= window);
    }

    fn register(&mut self, ip: IpAddr, now: Instant) {
        self.ips.insert(ip, now);
    }

    fn len(&self) -> usize {
        self.ips.len()
    }
}

fn cleanup_interval(window: Duration) -> Duration {
    let interval = window / 2;
    interval.min(MAX_CLEANUP_INTERVAL)
}

#[cfg(test)]
impl TokenAffinity {
    async fn len(&self) -> usize {
        let guard = self.inner.lock().await;
        guard.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn token_affinity_cleanup_expires_old_entries() {
        let affinity = TokenAffinity::new();
        let now = Instant::now();
        let window = Duration::from_secs(1);
        let limit = 100;

        for i in 0..50u32 {
            let token = TokenKey::Fingerprint(i as u64);
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            assert!(
                affinity
                    .ensure(WebRoute::Html, token, ip, window, limit, now)
                    .await
            );
        }

        assert!(affinity.len().await >= 50);

        let later = now + Duration::from_secs(3);
        let hot_token = TokenKey::Fingerprint(999);
        let hot_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(
            affinity
                .ensure(WebRoute::Html, hot_token, hot_ip, window, limit, later)
                .await
        );

        assert_eq!(affinity.len().await, 1);
    }

    #[tokio::test]
    async fn token_affinity_enforces_max_entries() {
        let affinity = TokenAffinity::new();
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let limit = 100;

        for i in 0..(MAX_ENTRIES as u32 + 25) {
            let token = TokenKey::Fingerprint(i as u64);
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = affinity
                .ensure(WebRoute::Html, token, ip, window, limit, now)
                .await;
        }

        assert!(affinity.len().await <= MAX_ENTRIES);
    }
}
