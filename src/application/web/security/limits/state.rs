use std::sync::atomic::{AtomicU32, Ordering};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::super::{
    auth::AuthRequest,
    sse::{ActiveSseState, SsePermit},
    SecurityRejection, TokenKey, WebRoute,
};
use super::policy::{BruteForcePolicy, SecurityPolicy};
use crate::application::logging::LogEvent;

/// Stocke les compteurs et fenêtres glissantes utilisés pour faire appliquer
/// les politiques de sécurité web.
#[derive(Debug)]
pub(crate) struct SecurityState {
    ip_counters: SlidingWindowCounters<IpAddr>,
    token_counters: SlidingWindowCounters<TokenKey>,
    failures_ip: FailureTracker<IpAddr>,
    failures_token: FailureTracker<TokenKey>,
    token_spread: TokenSpreadTracker,
    token_affinity: TokenAffinityTracker,
    sse_active: Arc<ActiveSseState>,
    global_active: AtomicU32,
}

#[derive(Debug)]
pub(crate) struct GlobalPermit {
    state: Arc<SecurityState>,
}

impl GlobalPermit {
    fn new(state: Arc<SecurityState>) -> Self {
        Self { state }
    }
}

impl Drop for GlobalPermit {
    fn drop(&mut self) {
        self.state.release_global();
    }
}

impl SecurityState {
    pub(crate) fn new() -> Self {
        Self {
            ip_counters: SlidingWindowCounters::new(),
            token_counters: SlidingWindowCounters::new(),
            failures_ip: FailureTracker::new(),
            failures_token: FailureTracker::new(),
            token_spread: TokenSpreadTracker::new(),
            token_affinity: TokenAffinityTracker::new(),
            sse_active: ActiveSseState::new(),
            global_active: AtomicU32::new(0),
        }
    }

    fn try_acquire_global(&self, limit: u32) -> Result<(), ()> {
        if limit == 0 {
            return Ok(());
        }
        let mut current = self.global_active.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return Err(());
            }
            match self.global_active.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    fn release_global(&self) {
        self.global_active
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
                if value == 0 {
                    Some(0)
                } else {
                    Some(value - 1)
                }
            })
            .ok();
    }

    pub(crate) fn acquire_global_permit(
        self: &Arc<Self>,
        route: WebRoute,
        policy: &SecurityPolicy,
    ) -> Result<Option<GlobalPermit>, SecurityRejection> {
        let limit = policy.route_policy(route).global_limit();
        if limit == 0 {
            return Ok(None);
        }
        self.try_acquire_global(limit).map_err(|_| {
            emit_security_incident(
                "rate_limit_global",
                route,
                None,
                None,
                Some(format!("limit={limit}")),
            );
            SecurityRejection::rate_limited(Duration::from_secs(1))
        })?;
        Ok(Some(GlobalPermit::new(Arc::clone(self))))
    }

    pub(super) async fn register_ip_hit(
        &self,
        route: WebRoute,
        ip: IpAddr,
        policy: &SecurityPolicy,
        trusted: bool,
        now: Instant,
    ) -> Option<Duration> {
        let limits = policy.route_policy(route);
        let cap = limits.ip_limit(policy.allow_multiplier(), trusted);
        if cap == 0 {
            return None;
        }
        let window = limits.window();
        self.ip_counters.register(route, ip, now, window, cap).await
    }

    pub(super) async fn register_token_hit(
        &self,
        route: WebRoute,
        token: TokenKey,
        policy: &SecurityPolicy,
        now: Instant,
    ) -> Option<Duration> {
        let limits = policy.route_policy(route);
        let cap = limits.token_limit();
        if cap == 0 {
            return None;
        }
        let window = limits.window();
        self.token_counters
            .register(route, token, now, window, cap)
            .await
    }

    pub(crate) async fn ensure_token_affinity(
        &self,
        route: WebRoute,
        token: TokenKey,
        ip: IpAddr,
        policy: &SecurityPolicy,
        trusted: bool,
        now: Instant,
    ) -> bool {
        if token == TokenKey::Anonymous {
            return true;
        }
        let limit = policy.token_affinity_limit(trusted);
        if limit == 0 {
            return true;
        }
        let window = policy.route_policy(route).window();
        self.token_affinity
            .register(route.into(), token, ip, now, window, limit)
            .await
    }

    pub(super) async fn check_existing_block(
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
        policy: &SecurityPolicy,
        route: WebRoute,
    ) -> FailureOutcome {
        let mut delay = None;

        delay = combine_delay(
            delay,
            self.failures_ip
                .register(ip, now, policy.brute_force())
                .await,
        );

        if token != TokenKey::Anonymous {
            delay = combine_delay(
                delay,
                self.failures_token
                    .register(token, now, policy.brute_force())
                    .await,
            );

            let spread = self
                .token_spread
                .register(token, ip, now, policy.brute_force())
                .await;
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

        FailureOutcome {
            retry_after: delay.map(|d| policy.adjust_retry(route, d)),
        }
    }

    pub(crate) async fn note_success(&self, ip: IpAddr, token: TokenKey) {
        self.failures_ip.clear(ip).await;
        if token != TokenKey::Anonymous {
            self.failures_token.clear(token).await;
            self.token_spread.clear(token).await;
        }
    }

    pub(crate) fn acquire_sse(
        &self,
        ip: IpAddr,
        token: TokenKey,
        policy: &SecurityPolicy,
    ) -> Result<Option<SsePermit>, Duration> {
        self.sse_active.try_acquire(ip, token, policy.sse_limits())
    }
}

pub(crate) async fn ensure_not_blocked(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    if let Some(delay) = state
        .check_existing_block(request.remote_ip, request.token_key, now)
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "cooldown_active",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::cooldown(delay));
    }
    Ok(())
}

pub(crate) async fn enforce_rate_limits(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
    now: Instant,
) -> Result<(), SecurityRejection> {
    if let Some(delay) = state
        .register_ip_hit(
            request.route,
            request.remote_ip,
            policy,
            request.trusted_ip,
            now,
        )
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "rate_limit_ip",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    if let Some(delay) = state
        .register_token_hit(request.route, request.token_key, policy, now)
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        emit_security_incident(
            "rate_limit_token",
            request.route,
            Some(request.remote_ip),
            Some(request.token_key),
            Some(format!("retry_after_s={:.3}", delay.as_secs_f32())),
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    Ok(())
}

pub(crate) struct FailureOutcome {
    pub(super) retry_after: Option<Duration>,
}

impl FailureOutcome {
    pub(crate) fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RouteKey {
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

#[derive(Debug, Default)]
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
struct FailureTracker<K> {
    inner: Mutex<HashMap<K, FailureRecord>>,
}

impl<K> FailureTracker<K>
where
    K: Eq + Hash + Copy + Send + 'static,
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
struct TokenAffinityTracker {
    inner: Mutex<HashMap<(RouteKey, TokenKey), TokenAffinityRecord>>,
}

impl TokenAffinityTracker {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn register(
        &self,
        route: RouteKey,
        token: TokenKey,
        ip: IpAddr,
        now: Instant,
        window: Duration,
        limit: u32,
    ) -> bool {
        let mut guard = self.inner.lock().await;
        let record = guard
            .entry((route, token))
            .or_insert_with(TokenAffinityRecord::new);
        record.purge(now, window);
        record.register(ip, now);
        (record.len() as u32) <= limit
    }
}

#[derive(Debug, Default)]
struct TokenAffinityRecord {
    ips: HashMap<IpAddr, Instant>,
}

impl TokenAffinityRecord {
    fn new() -> Self {
        Self {
            ips: HashMap::new(),
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

fn emit_security_incident(
    category: &'static str,
    route: WebRoute,
    ip: Option<IpAddr>,
    token: Option<TokenKey>,
    detail: Option<String>,
) {
    LogEvent::SecurityIncident {
        category: Cow::Borrowed(category),
        route: Cow::Owned(route.as_str().to_string()),
        ip: ip.map(|addr| Cow::Owned(addr.to_string())),
        token: token.map(|key| Cow::Owned(key.to_string())),
        detail: detail.map(Cow::Owned),
    }
    .emit();
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
