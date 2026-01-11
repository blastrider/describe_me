use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::super::WebRoute;
use super::policy::SecurityPolicy;
use super::sliding::SlidingWindowQueue;
use crate::application::web::security::TokenKey;

const MAX_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
// Guardrail against unbounded key floods; keep comfortably above typical traffic.
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RouteKey {
    Html,
    Sse,
    History,
    Logs,
    Metrics,
}

impl From<WebRoute> for RouteKey {
    fn from(route: WebRoute) -> Self {
        match route {
            WebRoute::Html => RouteKey::Html,
            WebRoute::Sse => RouteKey::Sse,
            WebRoute::History => RouteKey::History,
            WebRoute::Logs => RouteKey::Logs,
            WebRoute::Metrics => RouteKey::Metrics,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    ip_counters: SlidingWindowCounters<IpAddr>,
    token_counters: SlidingWindowCounters<TokenRateKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TokenRateKey {
    Token(TokenKey),
    AnonymousIp(IpAddr),
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            ip_counters: SlidingWindowCounters::new(),
            token_counters: SlidingWindowCounters::new(),
        }
    }

    pub(crate) async fn register_ip_hit(
        &self,
        route: WebRoute,
        ip: IpAddr,
        policy: &SecurityPolicy,
        trusted: bool,
        now: Instant,
    ) -> RateLimitDecision {
        let limits = policy.route_policy(route);
        let cap = limits.ip_limit(policy.allow_multiplier(), trusted);
        if cap == 0 {
            return RateLimitDecision::allowed();
        }
        let window = limits.window();
        let delay = self.ip_counters.register(route, ip, now, window, cap).await;
        match delay {
            Some(wait) => RateLimitDecision::denied(wait),
            None => RateLimitDecision::allowed(),
        }
    }

    pub(crate) async fn register_token_hit(
        &self,
        route: WebRoute,
        token: TokenKey,
        ip: IpAddr,
        policy: &SecurityPolicy,
        now: Instant,
    ) -> RateLimitDecision {
        let limits = policy.route_policy(route);
        let cap = limits.token_limit();
        if cap == 0 {
            return RateLimitDecision::allowed();
        }
        let window = limits.window();
        let key = match token {
            TokenKey::Anonymous => TokenRateKey::AnonymousIp(ip),
            _ => TokenRateKey::Token(token),
        };
        let delay = self
            .token_counters
            .register(route, key, now, window, cap)
            .await;
        match delay {
            Some(wait) => RateLimitDecision::denied(wait),
            None => RateLimitDecision::allowed(),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateLimitDecision {
    allowed: bool,
    retry_after: Option<Duration>,
}

impl RateLimitDecision {
    pub(crate) fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after: None,
        }
    }

    pub(crate) fn denied(retry_after: Duration) -> Self {
        Self {
            allowed: false,
            retry_after: Some(retry_after),
        }
    }

    pub(crate) fn is_allowed(&self) -> bool {
        self.allowed
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

#[derive(Debug)]
struct SlidingWindowCounters<K> {
    inner: Mutex<SlidingWindowState<K>>,
}

#[derive(Debug)]
struct SlidingWindowState<K> {
    entries: HashMap<(RouteKey, K), RateCounter>,
    last_cleanup: Instant,
}

impl<K> SlidingWindowCounters<K>
where
    K: Eq + Hash + Copy + Send + 'static,
{
    fn new() -> Self {
        Self {
            inner: Mutex::new(SlidingWindowState {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }

    async fn register(
        &self,
        route: WebRoute,
        key: K,
        now: Instant,
        window: Duration,
        limit: u32,
    ) -> Option<Duration> {
        let mut guard = self.inner.lock().await;
        self.cleanup_if_needed(&mut guard, now, window);
        let route_key = route.into();
        let (delay, is_empty) = {
            let entry = guard
                .entries
                .entry((route_key, key))
                .or_insert_with(|| RateCounter::new(window, now));
            let delay = entry.register(now, window, limit);
            (delay, entry.is_empty())
        };
        if is_empty {
            guard.entries.remove(&(route_key, key));
        }
        self.enforce_cap(&mut guard);
        delay
    }

    fn cleanup_if_needed(&self, state: &mut SlidingWindowState<K>, now: Instant, window: Duration) {
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
            .retain(|_, counter| counter.expires_at > now && !counter.is_empty());
    }

    fn enforce_cap(&self, state: &mut SlidingWindowState<K>) {
        while state.entries.len() > MAX_ENTRIES {
            let Some(key) = state.entries.keys().next().copied() else {
                break;
            };
            state.entries.remove(&key);
        }
    }
}

#[derive(Debug)]
struct RateCounter {
    hits: SlidingWindowQueue,
    expires_at: Instant,
}

impl RateCounter {
    fn new(window: Duration, now: Instant) -> Self {
        Self {
            hits: SlidingWindowQueue::new(window),
            expires_at: now + window,
        }
    }

    fn register(&mut self, now: Instant, window: Duration, limit: u32) -> Option<Duration> {
        if limit == 0 {
            return None;
        }
        self.hits.set_window(window);
        self.hits.purge(now);
        if self.hits.len() as u32 >= limit {
            if let Some(oldest) = self.hits.oldest() {
                let elapsed = now.duration_since(oldest);
                let wait = window.saturating_sub(elapsed);
                self.expires_at = now + window;
                return Some(wait);
            }
            self.expires_at = now + window;
            return Some(window);
        }
        self.hits.push(now);
        self.expires_at = now + window;
        None
    }

    fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

fn cleanup_interval(window: Duration) -> Duration {
    let interval = window / 2;
    interval.min(MAX_CLEANUP_INTERVAL)
}

#[cfg(test)]
impl<K> SlidingWindowCounters<K>
where
    K: Eq + Hash + Copy + Send + 'static,
{
    async fn len(&self) -> usize {
        let guard = self.inner.lock().await;
        guard.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{RateCounter, SlidingWindowCounters, MAX_ENTRIES};
    use crate::application::web::security::WebRoute;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn counter_does_not_register_when_limit_reached() {
        let now = Instant::now();
        let window = Duration::from_secs(10);
        let mut counter = RateCounter::new(window, now);

        assert!(counter.register(now, window, 1).is_none());
        assert!(counter
            .register(now + Duration::from_secs(1), window, 1)
            .is_some());
        assert_eq!(counter.hits.len(), 1);
    }

    #[tokio::test]
    async fn counters_cleanup_expires_old_entries() {
        let counters = SlidingWindowCounters::<IpAddr>::new();
        let now = Instant::now();
        let window = Duration::from_secs(1);

        for i in 0..50u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            let _ = counters
                .register(WebRoute::Html, ip, now, window, 100)
                .await;
        }

        assert!(counters.len().await >= 50);

        let later = now + Duration::from_secs(3);
        let hot_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let _ = counters
            .register(WebRoute::Html, hot_ip, later, window, 100)
            .await;

        assert_eq!(counters.len().await, 1);
    }

    #[tokio::test]
    async fn counters_enforce_max_entries() {
        let counters = SlidingWindowCounters::<IpAddr>::new();
        let now = Instant::now();
        let window = Duration::from_secs(60);

        for i in 0..(MAX_ENTRIES as u32 + 25) {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = counters
                .register(WebRoute::Html, ip, now, window, 100)
                .await;
        }

        assert!(counters.len().await <= MAX_ENTRIES);
    }
}
