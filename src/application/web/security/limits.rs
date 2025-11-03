use super::{
    auth::AuthRequest,
    sse::{ActiveSseState, SsePermit},
    SecurityRejection, TokenKey, WebRoute,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Debug)]
pub(crate) struct SecurityPolicy {
    html: RoutePolicy,
    sse: SsePolicy,
    allow_multiplier: u32,
    brute_force: BruteForcePolicy,
}

impl SecurityPolicy {
    pub(crate) fn default() -> Self {
        Self {
            html: RoutePolicy::new(Duration::from_secs(60), 60, 15),
            sse: SsePolicy::default(),
            allow_multiplier: 4,
            brute_force: BruteForcePolicy::default(),
        }
    }

    #[cfg(feature = "config")]
    pub(super) fn from_config(cfg: &crate::domain::WebSecurityConfig) -> Self {
        let html = RoutePolicy::new(
            duration_from_secs(cfg.html.window_seconds, 60),
            cfg.html.per_ip,
            cfg.html.per_token,
        );
        let sse = SsePolicy::from_config(&cfg.sse);
        let brute_force = BruteForcePolicy::from_config(&cfg.brute_force);

        Self {
            html,
            sse,
            allow_multiplier: cfg.allowlist_multiplier.max(1),
            brute_force,
        }
    }

    fn route_policy(&self, route: WebRoute) -> &RoutePolicy {
        match route {
            WebRoute::Html => &self.html,
            WebRoute::Sse => &self.sse.route,
        }
    }

    fn brute_force(&self) -> &BruteForcePolicy {
        &self.brute_force
    }

    pub(super) fn allow_multiplier(&self) -> u32 {
        self.allow_multiplier.max(1)
    }

    pub(super) fn adjust_retry(&self, route: WebRoute, mut delay: Duration) -> Duration {
        if route == WebRoute::Sse {
            let min = self.brute_force.sse_min_retry;
            if min > Duration::ZERO && delay < min {
                delay = min;
            }
        }
        if delay < Duration::from_millis(250) {
            delay = Duration::from_secs(1);
        }
        delay
    }

    pub(crate) fn sse_min_event_interval(&self) -> Duration {
        self.sse.min_event_interval()
    }

    pub(crate) fn sse_max_payload_bytes(&self) -> usize {
        self.sse.max_payload_bytes()
    }

    pub(crate) fn sse_max_stream_duration(&self) -> Duration {
        self.sse.max_stream()
    }
}

#[derive(Debug, Clone)]
struct RoutePolicy {
    window: Duration,
    per_ip: u32,
    per_token: u32,
}

impl RoutePolicy {
    fn new(window: Duration, per_ip: u32, per_token: u32) -> Self {
        Self {
            window: if window.is_zero() {
                Duration::from_secs(1)
            } else {
                window
            },
            per_ip,
            per_token,
        }
    }

    fn ip_limit(&self, multiplier: u32, trusted: bool) -> u32 {
        if self.per_ip == 0 {
            return 0;
        }
        if trusted {
            self.per_ip.saturating_mul(multiplier.max(1))
        } else {
            self.per_ip
        }
    }

    fn token_limit(&self) -> u32 {
        self.per_token
    }
}

#[derive(Debug, Clone)]
pub(super) struct SsePolicy {
    route: RoutePolicy,
    max_active_per_ip: u32,
    max_active_per_token: u32,
    max_stream: Duration,
    min_event_interval: Duration,
    max_payload_bytes: usize,
}

impl SsePolicy {
    fn default() -> Self {
        Self {
            route: RoutePolicy::new(Duration::from_secs(60), 20, 12),
            max_active_per_ip: 2,
            max_active_per_token: 2,
            max_stream: Duration::from_secs(20 * 60),
            min_event_interval: Duration::from_secs(1),
            max_payload_bytes: 48 * 1024,
        }
    }

    #[cfg(feature = "config")]
    fn from_config(cfg: &crate::domain::SseLimitConfig) -> Self {
        Self {
            route: RoutePolicy::new(
                duration_from_secs(cfg.window_seconds, 60),
                cfg.per_ip,
                cfg.per_token,
            ),
            max_active_per_ip: cfg.max_active_per_ip,
            max_active_per_token: cfg.max_active_per_token,
            max_stream: duration_from_secs(cfg.max_stream_seconds, 20 * 60),
            min_event_interval: duration_from_millis(cfg.min_event_interval_ms, 1000),
            max_payload_bytes: cfg.max_payload_bytes as usize,
        }
    }

    pub(super) fn min_event_interval(&self) -> Duration {
        self.min_event_interval
    }

    pub(super) fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    pub(super) fn max_stream(&self) -> Duration {
        self.max_stream
    }

    pub(crate) fn max_active_per_ip(&self) -> u32 {
        self.max_active_per_ip
    }

    pub(crate) fn max_active_per_token(&self) -> u32 {
        self.max_active_per_token
    }
}

#[derive(Debug, Clone)]
struct BruteForcePolicy {
    window: Duration,
    threshold: u32,
    initial_backoff: Duration,
    multiplier: f32,
    ceiling: Duration,
    quarantine: Duration,
    token_failure_threshold: u32,
    token_ip_spread: u32,
    sse_min_retry: Duration,
}

impl BruteForcePolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            threshold: 5,
            initial_backoff: Duration::from_secs(5),
            multiplier: 2.0,
            ceiling: Duration::from_secs(60),
            quarantine: Duration::from_secs(20 * 60),
            token_failure_threshold: 12,
            token_ip_spread: 3,
            sse_min_retry: Duration::from_secs(2),
        }
    }

    #[cfg(feature = "config")]
    fn from_config(cfg: &crate::domain::BruteForceConfig) -> Self {
        Self {
            window: duration_from_secs(cfg.window_seconds, 300),
            threshold: cfg.threshold,
            initial_backoff: duration_from_secs(cfg.initial_backoff_seconds, 5),
            multiplier: if cfg.backoff_multiplier <= 1.0 {
                2.0
            } else {
                cfg.backoff_multiplier
            },
            ceiling: duration_from_secs(cfg.backoff_ceiling_seconds, 60),
            quarantine: duration_from_secs(cfg.quarantine_seconds, 20 * 60),
            token_failure_threshold: cfg.token_failure_threshold,
            token_ip_spread: cfg.token_ip_spread,
            sse_min_retry: duration_from_secs(cfg.sse_min_retry_seconds, 2),
        }
    }
}

#[derive(Debug)]
pub(super) struct SecurityState {
    ip_counters: SlidingWindowCounters<IpAddr>,
    token_counters: SlidingWindowCounters<TokenKey>,
    failures_ip: FailureTracker<IpAddr>,
    failures_token: FailureTracker<TokenKey>,
    token_spread: TokenSpreadTracker,
    sse_active: Arc<ActiveSseState>,
}

impl SecurityState {
    pub(crate) fn new() -> Self {
        Self {
            ip_counters: SlidingWindowCounters::new(),
            token_counters: SlidingWindowCounters::new(),
            failures_ip: FailureTracker::new(),
            failures_token: FailureTracker::new(),
            token_spread: TokenSpreadTracker::new(),
            sse_active: ActiveSseState::new(),
        }
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
        let window = limits.window;
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
        let window = limits.window;
        self.token_counters
            .register(route, token, now, window, cap)
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

    pub(super) async fn note_failure(
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

            delay = combine_delay(
                delay,
                self.token_spread
                    .register(token, ip, now, policy.brute_force())
                    .await,
            );
        }

        FailureOutcome {
            retry_after: delay.map(|d| policy.adjust_retry(route, d)),
        }
    }

    pub(super) async fn note_success(&self, ip: IpAddr, token: TokenKey) {
        self.failures_ip.clear(ip).await;
        if token != TokenKey::Anonymous {
            self.failures_token.clear(token).await;
            self.token_spread.clear(token).await;
        }
    }

    pub(super) fn acquire_sse(
        &self,
        ip: IpAddr,
        token: TokenKey,
        policy: &SecurityPolicy,
    ) -> Result<Option<SsePermit>, Duration> {
        self.sse_active.try_acquire(ip, token, &policy.sse)
    }
}

pub(super) async fn ensure_not_blocked(
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
        warn!(
            ip = %request.remote_ip,
            route = request.route.as_str(),
            retry_after = %delay.as_secs_f32(),
            "Refus (cooldown en cours)"
        );
        return Err(SecurityRejection::cooldown(delay));
    }
    Ok(())
}

pub(super) async fn enforce_rate_limits(
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
        warn!(
            ip = %request.remote_ip,
            route = request.route.as_str(),
            retry_after = %delay.as_secs_f32(),
            "Rate limit IP dépassé"
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    if let Some(delay) = state
        .register_token_hit(request.route, request.token_key, policy, now)
        .await
    {
        let delay = policy.adjust_retry(request.route, delay);
        warn!(
            ip = %request.remote_ip,
            route = request.route.as_str(),
            token = %request.token_key,
            retry_after = %delay.as_secs_f32(),
            "Rate limit token dépassé"
        );
        return Err(SecurityRejection::rate_limited(delay));
    }

    Ok(())
}

pub(super) struct FailureOutcome {
    pub(super) retry_after: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RouteKey {
    Html,
    Sse,
}

impl From<WebRoute> for RouteKey {
    fn from(route: WebRoute) -> Self {
        match route {
            WebRoute::Html => RouteKey::Html,
            WebRoute::Sse => RouteKey::Sse,
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
        let route_key: RouteKey = route.into();
        let mut guard = self.inner.lock().await;
        let counter = guard.entry((route_key, key)).or_default();
        let wait = counter.register(now, window, limit);
        if counter.is_empty() {
            guard.remove(&(route_key, key));
        }
        wait
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
    ) -> Option<Duration> {
        let mut guard = self.inner.lock().await;
        let spread = guard.entry(token).or_default();
        let delay = spread
            .register(ip, now, policy)
            .map(|until| until.saturating_duration_since(now));
        if spread.is_clear() {
            guard.remove(&token);
        }
        delay
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
        self.purge(now, policy.window);
        if let Some(until) = self.blocked_until {
            if until > now {
                return Some(until);
            } else {
                self.blocked_until = None;
            }
        }

        self.attempts.push_back(now);
        if self.attempts.len() as u32 >= policy.threshold {
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

        if !self.current_backoff.is_zero() && self.current_backoff >= policy.ceiling {
            let until = now + policy.quarantine;
            self.blocked_until = Some(until);
            self.current_backoff = policy.initial_backoff;
            self.attempts.clear();
            return Some(until);
        }

        let next_backoff = if self.current_backoff.is_zero() {
            policy.initial_backoff
        } else {
            let scaled = (self.current_backoff.as_secs_f32() * policy.multiplier).ceil() as u64;
            let base = policy.initial_backoff.as_secs().max(1);
            Duration::from_secs(scaled.max(base)).min(policy.ceiling)
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
    fn register(&mut self, ip: IpAddr, now: Instant, policy: &BruteForcePolicy) -> Option<Instant> {
        if let Some(until) = self.locked_until {
            if until > now {
                return Some(until);
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

        if self.failure_count >= policy.token_failure_threshold
            && self.ips.len() as u32 >= policy.token_ip_spread
        {
            let until = now + policy.quarantine;
            self.locked_until = Some(until);
            return Some(until);
        }
        None
    }

    fn is_clear(&self) -> bool {
        self.failure_count == 0 && self.locked_until.is_none()
    }

    fn locked_delay(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| *until > now)
            .map(|until| until.saturating_duration_since(now))
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

#[cfg(feature = "config")]
fn duration_from_secs(value: u64, fallback: u64) -> Duration {
    let secs = if value == 0 { fallback } else { value };
    Duration::from_secs(secs.max(1))
}

#[cfg(feature = "config")]
fn duration_from_millis(value: u64, fallback: u64) -> Duration {
    let ms = if value == 0 { fallback } else { value };
    Duration::from_millis(ms.max(1))
}

#[cfg(test)]
mod tests {
    use super::TokenKey;
    use super::*;
    use std::net::Ipv4Addr;

    fn request(route: WebRoute, require_token: bool) -> AuthRequest {
        AuthRequest {
            route,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            provided_token: None,
            token_key: TokenKey::Anonymous,
            require_token,
            trusted_ip: false,
        }
    }

    #[tokio::test]
    async fn ensure_not_blocked_respects_cooldown() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let req = request(WebRoute::Html, false);
        let now = Instant::now();

        for _ in 0..policy.brute_force.threshold {
            let _ = state
                .note_failure(req.remote_ip, req.token_key, now, &policy, req.route)
                .await;
        }

        assert!(
            ensure_not_blocked(&state, &policy, &req, now)
                .await
                .is_err(),
            "cooldown should trigger rejection"
        );
    }

    #[tokio::test]
    async fn enforce_rate_limits_blocks_after_threshold() {
        let state = SecurityState::new();

        let mut policy = SecurityPolicy::default();
        policy.html = RoutePolicy::new(Duration::from_secs(60), 1, 1);

        let req = request(WebRoute::Html, false);
        let now = Instant::now();

        assert!(enforce_rate_limits(&state, &policy, &req, now)
            .await
            .is_ok());
        assert!(
            enforce_rate_limits(&state, &policy, &req, now)
                .await
                .is_err(),
            "second hit should trigger rate limit"
        );
    }
}
