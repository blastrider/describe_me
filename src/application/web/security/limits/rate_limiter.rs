use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::super::WebRoute;
use super::policy::SecurityPolicy;
use crate::application::web::security::TokenKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RouteKey {
    Html,
    Sse,
    History,
    Logs,
}

impl From<WebRoute> for RouteKey {
    fn from(route: WebRoute) -> Self {
        match route {
            WebRoute::Html => RouteKey::Html,
            WebRoute::Sse => RouteKey::Sse,
            WebRoute::History => RouteKey::History,
            WebRoute::Logs => RouteKey::Logs,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct RateLimiter {
    ip_counters: SlidingWindowCounters<IpAddr>,
    token_counters: SlidingWindowCounters<TokenKey>,
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            ip_counters: SlidingWindowCounters::new(),
            token_counters: SlidingWindowCounters::new(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn default() -> Self {
        Self::new()
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
            Some(wait) => RateLimitDecision::denied(RateLimitScope::Ip, wait),
            None => RateLimitDecision::allowed(),
        }
    }

    pub(crate) async fn register_token_hit(
        &self,
        route: WebRoute,
        token: TokenKey,
        policy: &SecurityPolicy,
        now: Instant,
    ) -> RateLimitDecision {
        let limits = policy.route_policy(route);
        let cap = limits.token_limit();
        if cap == 0 {
            return RateLimitDecision::allowed();
        }
        let window = limits.window();
        let delay = self
            .token_counters
            .register(route, token, now, window, cap)
            .await;
        match delay {
            Some(wait) => RateLimitDecision::denied(RateLimitScope::Token, wait),
            None => RateLimitDecision::allowed(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateLimitScope {
    Ip,
    Token,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateLimitDecision {
    allowed: bool,
    retry_after: Option<Duration>,
    scope: Option<RateLimitScope>,
}

impl RateLimitDecision {
    pub(crate) fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after: None,
            scope: None,
        }
    }

    pub(crate) fn denied(scope: RateLimitScope, retry_after: Duration) -> Self {
        Self {
            allowed: false,
            retry_after: Some(retry_after),
            scope: Some(scope),
        }
    }

    pub(crate) fn is_allowed(&self) -> bool {
        self.allowed
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    #[allow(dead_code)]
    pub(crate) fn scope(&self) -> Option<RateLimitScope> {
        self.scope
    }
}

#[derive(Debug)]
struct SlidingWindowCounters<K> {
    inner: Mutex<HashMap<(RouteKey, K), RateCounter>>,
}

impl<K> SlidingWindowCounters<K>
where
    K: Eq + Hash + Copy + Send + 'static,
{
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
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
        let entry = guard.entry((route.into(), key)).or_default();
        let delay = entry.register(now, window, limit);
        if entry.is_empty() {
            guard.remove(&(route.into(), key));
        }
        delay
    }
}

#[derive(Debug, Default)]
struct RateCounter {
    hits: VecDeque<Instant>,
}

impl RateCounter {
    fn register(&mut self, now: Instant, window: Duration, limit: u32) -> Option<Duration> {
        if limit == 0 {
            return None;
        }
        while let Some(front) = self.hits.front() {
            if now.duration_since(*front) >= window {
                self.hits.pop_front();
            } else {
                break;
            }
        }
        if self.hits.len() as u32 >= limit {
            if let Some(oldest) = self.hits.front() {
                let elapsed = now.duration_since(*oldest);
                let wait = window.saturating_sub(elapsed);
                return Some(wait);
            }
            return Some(window);
        }
        self.hits.push_back(now);
        None
    }

    fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}
