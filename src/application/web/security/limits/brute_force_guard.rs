use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::policy::BruteForcePolicy;
use crate::application::logging::LogEvent;
use crate::application::web::security::{TokenKey, WebRoute};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FailureOutcome {
    pub(crate) retry_after: Option<Duration>,
}

impl FailureOutcome {
    pub(crate) fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

#[derive(Debug)]
pub(crate) struct BruteForceGuard {
    failures_ip: FailureTracker<IpAddr>,
    failures_token: FailureTracker<TokenKey>,
    token_spread: TokenSpreadTracker,
}

impl BruteForceGuard {
    pub(crate) fn new() -> Self {
        Self {
            failures_ip: FailureTracker::new(),
            failures_token: FailureTracker::new(),
            token_spread: TokenSpreadTracker::new(),
        }
    }

    pub(crate) async fn existing_block(
        &self,
        ip: IpAddr,
        token: TokenKey,
        now: Instant,
    ) -> Option<Duration> {
        let mut delay = self.failures_ip.existing_block(ip, now).await;

        if token != TokenKey::Anonymous {
            delay = combine_delay(delay, self.failures_token.existing_block(token, now).await);
            delay = combine_delay(delay, self.token_spread.existing_block(token, now).await);
        }

        delay
    }

    pub(crate) async fn note_failure(
        &self,
        ip: IpAddr,
        token: TokenKey,
        now: Instant,
        policy: &BruteForcePolicy,
        route: WebRoute,
    ) -> FailureOutcome {
        let mut delay = None;

        delay = combine_delay(delay, self.failures_ip.register(ip, now, policy).await);

        if token != TokenKey::Anonymous {
            delay = combine_delay(
                delay,
                self.failures_token.register(token, now, policy).await,
            );

            let spread = self.token_spread.register(token, ip, now, policy).await;
            if let TokenSpreadOutcome::Locked(_, fails, ips) = spread {
                emit_security_incident(
                    "token_spread_locked",
                    route,
                    Some(ip),
                    Some(token),
                    Some(format!("failures={} distinct_ips={}", fails, ips)),
                );
            }
            delay = combine_delay(delay, spread.as_delay(now));
        }

        FailureOutcome { retry_after: delay }
    }

    pub(crate) async fn note_success(&self, ip: IpAddr, token: TokenKey) {
        self.failures_ip.clear(ip).await;
        if token != TokenKey::Anonymous {
            self.failures_token.clear(token).await;
            self.token_spread.clear(token).await;
        }
    }
}

#[derive(Debug)]
struct FailureTracker<K> {
    inner: Mutex<HashMap<K, FailureRecord>>,
}

impl<K> FailureTracker<K>
where
    K: Eq + std::hash::Hash + Copy + Send + 'static,
{
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn register(&self, key: K, now: Instant, policy: &BruteForcePolicy) -> Option<Duration> {
        let mut guard = self.inner.lock().await;
        let record = guard.entry(key).or_default();
        let delay = record
            .register(now, policy)
            .map(|until| until.saturating_duration_since(now));
        if record.is_clear() {
            guard.remove(&key);
        }
        delay
    }

    async fn existing_block(&self, key: K, now: Instant) -> Option<Duration> {
        let guard = self.inner.lock().await;
        guard.get(&key).and_then(|record| record.blocked_delay(now))
    }

    async fn clear(&self, key: K) {
        let mut guard = self.inner.lock().await;
        guard.remove(&key);
    }
}

#[derive(Debug, Default)]
struct FailureRecord {
    attempts: VecDeque<Instant>,
    blocked_until: Option<Instant>,
    current_backoff: Duration,
}

impl FailureRecord {
    fn register(&mut self, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
        self.purge(now, policy.window());
        if let Some(until) = self.blocked_until {
            if until > now {
                return Some(until);
            } else {
                self.blocked_until = None;
            }
        }

        self.attempts.push_back(now);
        if self.attempts.len() as u32 >= policy.threshold() {
            return self.apply_penalty(now, policy);
        }
        None
    }

    fn apply_penalty(&mut self, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
        if let Some(until) = self.blocked_until {
            if until > now {
                return Some(until);
            }
        }

        if !self.current_backoff.is_zero() && self.current_backoff >= policy.ceiling() {
            let until = now + policy.quarantine();
            self.blocked_until = Some(until);
            self.current_backoff = policy.initial_backoff();
            self.attempts.clear();
            return Some(until);
        }

        let next_backoff = if self.current_backoff.is_zero() {
            policy.initial_backoff()
        } else {
            let scaled = (self.current_backoff.as_secs_f32() * policy.multiplier()).ceil() as u64;
            let base = policy.initial_backoff().as_secs().max(1);
            Duration::from_secs(scaled.max(base)).min(policy.ceiling())
        };

        if next_backoff.is_zero() {
            return None;
        }

        self.current_backoff = next_backoff;
        let until = now + next_backoff;
        self.blocked_until = Some(until);
        Some(until)
    }

    fn purge(&mut self, now: Instant, window: Duration) {
        while let Some(front) = self.attempts.front() {
            if now.duration_since(*front) >= window {
                self.attempts.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_clear(&self) -> bool {
        self.attempts.is_empty() && self.blocked_until.is_none()
    }

    fn blocked_delay(&self, now: Instant) -> Option<Duration> {
        self.blocked_until
            .filter(|until| *until > now)
            .map(|until| until.saturating_duration_since(now))
    }
}

#[derive(Debug)]
struct TokenSpreadTracker {
    inner: Mutex<HashMap<TokenKey, TokenSpread>>,
}

impl TokenSpreadTracker {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn register(
        &self,
        token: TokenKey,
        ip: IpAddr,
        now: Instant,
        policy: &BruteForcePolicy,
    ) -> TokenSpreadOutcome {
        let mut guard = self.inner.lock().await;
        let spread = guard.entry(token).or_default();
        spread.register(ip, now, policy)
    }

    async fn existing_block(&self, token: TokenKey, now: Instant) -> Option<Duration> {
        let guard = self.inner.lock().await;
        guard
            .get(&token)
            .and_then(|spread| spread.locked_delay(now))
    }

    async fn clear(&self, token: TokenKey) {
        let mut guard = self.inner.lock().await;
        guard.remove(&token);
    }
}

#[derive(Debug, Default)]
struct TokenSpread {
    ips: HashSet<IpAddr>,
    failure_count: u32,
    locked_until: Option<Instant>,
}

impl TokenSpread {
    fn register(
        &mut self,
        ip: IpAddr,
        now: Instant,
        policy: &BruteForcePolicy,
    ) -> TokenSpreadOutcome {
        if let Some(until) = self.locked_until {
            if until > now {
                return TokenSpreadOutcome::AlreadyLocked(until);
            } else {
                self.locked_until = None;
                self.failure_count = 0;
                self.ips.clear();
            }
        }

        self.failure_count = self.failure_count.saturating_add(1);
        self.ips.insert(ip);
        if self.ips.len() > 32 {
            if let Some(first) = self.ips.iter().next().copied() {
                self.ips.remove(&first);
            }
        }

        if self.failure_count >= policy.token_failure_threshold()
            && self.ips.len() as u32 >= policy.token_ip_spread()
        {
            let until = now + policy.quarantine();
            self.locked_until = Some(until);
            TokenSpreadOutcome::Locked(until, self.failure_count, self.ips.len() as u32)
        } else {
            TokenSpreadOutcome::Tracking(self.failure_count, self.ips.len() as u32)
        }
    }

    fn locked_delay(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| *until > now)
            .map(|until| until.saturating_duration_since(now))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSpreadOutcome {
    Tracking(u32, u32),
    Locked(Instant, u32, u32),
    AlreadyLocked(Instant),
}

impl TokenSpreadOutcome {
    fn as_delay(self, now: Instant) -> Option<Duration> {
        match self {
            TokenSpreadOutcome::Locked(until, _, _) | TokenSpreadOutcome::AlreadyLocked(until) => {
                Some(until.saturating_duration_since(now))
            }
            TokenSpreadOutcome::Tracking(_, _) => None,
        }
    }
}

fn combine_delay(current: Option<Duration>, new_delay: Option<Duration>) -> Option<Duration> {
    match new_delay {
        Some(delay) if !delay.is_zero() => Some(match current {
            Some(existing) => existing.max(delay),
            None => delay,
        }),
        _ => current,
    }
}

fn emit_security_incident(
    category: &'static str,
    route: WebRoute,
    ip: Option<IpAddr>,
    token: Option<TokenKey>,
    detail: Option<String>,
) {
    use std::borrow::Cow;

    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Owned(route.as_str().to_string()),
        ip: ip.map(|addr| Cow::Owned(addr.to_string())),
        token: token.map(|key| Cow::Owned(key.to_string())),
        detail: detail.map(Cow::Owned),
    }
    .emit();
}
