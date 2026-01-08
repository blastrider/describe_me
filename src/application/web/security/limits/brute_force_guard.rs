use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::policy::{BruteForcePolicy, TOKEN_IP_SPREAD_MAX_IPS};
use super::sliding::SlidingWindowQueue;
use crate::application::logging::LogEvent;
use crate::application::web::security::{TokenKey, WebRoute};

const MAX_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
// Guardrail against unbounded key floods; keep comfortably above typical traffic.
const MAX_ENTRIES: usize = 10_000;

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
        policy: &BruteForcePolicy,
    ) -> Option<Duration> {
        let mut delay = self.failures_ip.existing_block(ip, now, policy).await;

        if token != TokenKey::Anonymous {
            delay = combine_delay(
                delay,
                self.failures_token.existing_block(token, now, policy).await,
            );
            delay = combine_delay(
                delay,
                self.token_spread.existing_block(token, now, policy).await,
            );
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
    inner: Mutex<FailureState<K>>,
}

#[derive(Debug)]
struct FailureState<K> {
    entries: HashMap<K, FailureRecord>,
    last_cleanup: Instant,
}

impl<K> FailureTracker<K>
where
    K: Eq + std::hash::Hash + Copy + Send + 'static,
{
    fn new() -> Self {
        Self {
            inner: Mutex::new(FailureState {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }

    async fn register(&self, key: K, now: Instant, policy: &BruteForcePolicy) -> Option<Duration> {
        let mut guard = self.inner.lock().await;
        self.cleanup_if_needed(&mut guard, now, policy);
        let (delay, is_clear) = {
            let record = guard
                .entries
                .entry(key)
                .or_insert_with(|| FailureRecord::new(policy.window()));
            let delay = record
                .register(now, policy)
                .map(|until| until.saturating_duration_since(now));
            (delay, record.is_clear())
        };
        if is_clear {
            guard.entries.remove(&key);
        }
        self.enforce_cap(&mut guard);
        delay
    }

    async fn existing_block(
        &self,
        key: K,
        now: Instant,
        policy: &BruteForcePolicy,
    ) -> Option<Duration> {
        let mut guard = self.inner.lock().await;
        self.cleanup_if_needed(&mut guard, now, policy);
        self.enforce_cap(&mut guard);
        guard
            .entries
            .get(&key)
            .and_then(|record| record.blocked_delay(now))
    }

    async fn clear(&self, key: K) {
        let mut guard = self.inner.lock().await;
        guard.entries.remove(&key);
    }

    fn cleanup_if_needed(
        &self,
        state: &mut FailureState<K>,
        now: Instant,
        policy: &BruteForcePolicy,
    ) {
        let interval = cleanup_interval(policy.window());
        if now
            .checked_duration_since(state.last_cleanup)
            .map(|elapsed| elapsed < interval)
            .unwrap_or(false)
        {
            return;
        }

        state.last_cleanup = now;
        state.entries.retain(|_, record| {
            record.cleanup(now, policy);
            !record.is_clear()
        });
    }

    fn enforce_cap(&self, state: &mut FailureState<K>) {
        while state.entries.len() > MAX_ENTRIES {
            let Some(key) = state.entries.keys().next().copied() else {
                break;
            };
            state.entries.remove(&key);
        }
    }
}

#[cfg(test)]
impl<K> FailureTracker<K>
where
    K: Eq + std::hash::Hash + Copy + Send + 'static,
{
    async fn len(&self) -> usize {
        let guard = self.inner.lock().await;
        guard.entries.len()
    }
}

#[derive(Debug)]
struct FailureRecord {
    attempts: SlidingWindowQueue,
    blocked_until: Option<Instant>,
    current_backoff: Duration,
}

impl FailureRecord {
    fn new(window: Duration) -> Self {
        Self {
            attempts: SlidingWindowQueue::new(window),
            blocked_until: None,
            current_backoff: Duration::default(),
        }
    }

    fn register(&mut self, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
        self.attempts.set_window(policy.window());
        self.attempts.purge(now);
        if let Some(until) = self.blocked_until {
            if until > now {
                return Some(until);
            } else {
                self.blocked_until = None;
            }
        }

        self.attempts.push(now);
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

    fn cleanup(&mut self, now: Instant, policy: &BruteForcePolicy) {
        self.attempts.set_window(policy.window());
        self.attempts.purge(now);
        if let Some(until) = self.blocked_until {
            if until <= now {
                self.blocked_until = None;
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
    inner: Mutex<TokenSpreadState>,
}

#[derive(Debug)]
struct TokenSpreadState {
    entries: HashMap<TokenKey, TokenSpreadEntry>,
    last_cleanup: Instant,
}

impl TokenSpreadTracker {
    fn new() -> Self {
        Self {
            inner: Mutex::new(TokenSpreadState {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }

    async fn register(
        &self,
        token: TokenKey,
        ip: IpAddr,
        now: Instant,
        policy: &BruteForcePolicy,
    ) -> TokenSpreadOutcome {
        let mut state = self.inner.lock().await;
        self.cleanup_if_needed(&mut state, now, policy);
        let entry = state
            .entries
            .entry(token)
            .or_insert_with(|| TokenSpreadEntry {
                spread: TokenSpread::default(),
                last_seen: now,
            });
        entry.last_seen = now;
        let outcome = entry.spread.register(ip, now, policy);
        if entry.spread.is_clear() {
            state.entries.remove(&token);
        }
        outcome
    }

    async fn existing_block(
        &self,
        token: TokenKey,
        now: Instant,
        policy: &BruteForcePolicy,
    ) -> Option<Duration> {
        let mut state = self.inner.lock().await;
        self.cleanup_if_needed(&mut state, now, policy);
        state
            .entries
            .get(&token)
            .and_then(|entry| entry.spread.locked_delay(now))
    }

    async fn clear(&self, token: TokenKey) {
        let mut state = self.inner.lock().await;
        state.entries.remove(&token);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        let state = self.inner.lock().await;
        state.entries.len()
    }

    fn cleanup_if_needed(
        &self,
        state: &mut TokenSpreadState,
        now: Instant,
        policy: &BruteForcePolicy,
    ) {
        if now
            .checked_duration_since(state.last_cleanup)
            .map(|elapsed| elapsed < policy.token_spread_cleanup_interval())
            .unwrap_or(false)
        {
            return;
        }

        state.last_cleanup = now;
        let ttl = policy.token_spread_ttl();
        state.entries.retain(|_, entry| {
            let stale = now
                .checked_duration_since(entry.last_seen)
                .map(|elapsed| elapsed >= ttl)
                .unwrap_or(false);
            !stale && !entry.spread.is_clear()
        });
    }
}

#[derive(Debug, Default)]
struct TokenSpread {
    ips: HashSet<IpAddr>,
    failure_count: u32,
    locked_until: Option<Instant>,
}

#[derive(Debug)]
struct TokenSpreadEntry {
    spread: TokenSpread,
    last_seen: Instant,
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
        if self.ips.len() > TOKEN_IP_SPREAD_MAX_IPS as usize {
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

    fn is_clear(&self) -> bool {
        self.failure_count == 0 && self.locked_until.is_none() && self.ips.is_empty()
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
        route: Cow::Borrowed(route.as_str()),
        request_path: None,
        ip: ip.map(|addr| Cow::Owned(addr.to_string())),
        token: token.map(|key| Cow::Owned(key.to_string())),
        detail: detail.map(Cow::Owned),
    }
    .emit();
}

fn cleanup_interval(window: Duration) -> Duration {
    let interval = window / 2;
    interval.min(MAX_CLEANUP_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn token_spread_cleanup_expires_old_entries() {
        let tracker = TokenSpreadTracker::new();
        let policy = BruteForcePolicy::default()
            .with_token_spread(Duration::from_secs(1), Duration::from_millis(1));
        let now = Instant::now();

        for i in 0..50u8 {
            let token = TokenKey::Fingerprint(i as u64);
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            let _ = tracker.register(token, ip, now, &policy).await;
        }
        assert!(tracker.len().await >= 50);

        let later = now + Duration::from_secs(2);
        let _ = tracker
            .existing_block(TokenKey::Fingerprint(0), later, &policy)
            .await;

        assert_eq!(tracker.len().await, 0);
    }

    #[tokio::test]
    async fn token_spread_preserves_recent_entry() {
        let tracker = TokenSpreadTracker::new();
        let policy = BruteForcePolicy::default()
            .with_token_spread(Duration::from_secs(1), Duration::from_millis(1));
        let now = Instant::now();
        for i in 0..10u8 {
            let token = TokenKey::Fingerprint(i as u64);
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
            let _ = tracker.register(token, ip, now, &policy).await;
        }

        let hot_token = TokenKey::Fingerprint(999);
        let hot_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let _ = tracker.register(hot_token, hot_ip, now, &policy).await;
        let later = now + Duration::from_secs(2);
        let _ = tracker.register(hot_token, hot_ip, later, &policy).await;

        assert_eq!(tracker.len().await, 1);
        assert!(tracker
            .existing_block(hot_token, later, &policy)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn failure_tracker_cleanup_expires_old_entries() {
        let tracker = FailureTracker::<IpAddr>::new();
        let policy = BruteForcePolicy::default();
        let now = Instant::now();

        for i in 0..100u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = tracker.register(ip, now, &policy).await;
        }

        assert!(tracker.len().await >= 100);

        let later = now + policy.window() + policy.window();
        let _ = tracker
            .existing_block(IpAddr::V4(Ipv4Addr::from(0)), later, &policy)
            .await;

        assert_eq!(tracker.len().await, 0);
    }

    #[tokio::test]
    async fn failure_tracker_enforces_max_entries() {
        let tracker = FailureTracker::<IpAddr>::new();
        let policy = BruteForcePolicy::default();
        let now = Instant::now();

        for i in 0..(MAX_ENTRIES as u32 + 25) {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = tracker.register(ip, now, &policy).await;
        }

        assert!(tracker.len().await <= MAX_ENTRIES);
    }

    #[test]
    fn failure_record_applies_backoff_after_threshold() {
        let policy = BruteForcePolicy::default();
        let threshold = policy.threshold();
        assert!(threshold > 0);

        let now = Instant::now();
        let mut record = FailureRecord::new(policy.window());

        for _ in 1..threshold {
            assert!(record.register(now, &policy).is_none());
        }

        let until = record.register(now, &policy);
        assert!(until.is_some());
        assert!(record.blocked_delay(now).is_some());
    }
}
