use std::time::Duration;

use super::super::WebRoute;

const DEFAULT_TOKEN_AFFINITY_LIMIT: u32 = 2;
pub(crate) const TOKEN_IP_SPREAD_MAX_IPS: u32 = 32;

#[derive(Debug)]
pub(crate) struct SecurityPolicy {
    html: RoutePolicy,
    sse: SsePolicy,
    history: RoutePolicy,
    logs: RoutePolicy,
    metrics: RoutePolicy,
    allow_multiplier: u32,
    brute_force: BruteForcePolicy,
    token_affinity_limit: u32,
}

impl SecurityPolicy {
    pub(crate) fn default() -> Self {
        Self {
            html: RoutePolicy::new(Duration::from_secs(60), 30, 10, 120),
            sse: SsePolicy::default(),
            history: RoutePolicy::new(Duration::from_secs(60), 24, 16, 120),
            logs: RoutePolicy::new(Duration::from_secs(60), 6, 4, 40),
            metrics: RoutePolicy::new(Duration::from_secs(60), 24, 16, 120),
            allow_multiplier: 2,
            brute_force: BruteForcePolicy::default(),
            token_affinity_limit: DEFAULT_TOKEN_AFFINITY_LIMIT,
        }
    }

    #[cfg(feature = "config")]
    pub(crate) fn from_config(cfg: &crate::domain::WebSecurityConfig) -> Self {
        let html = RoutePolicy::new(
            duration_from_secs(cfg.html.window_seconds, 60),
            cfg.html.per_ip,
            cfg.html.per_token,
            cfg.html.global,
        );
        let sse = SsePolicy::from_config(&cfg.sse);
        let history = RoutePolicy::new(
            duration_from_secs(cfg.history.window_seconds, 60),
            cfg.history.per_ip,
            cfg.history.per_token,
            cfg.history.global,
        );
        let logs = RoutePolicy::new(
            duration_from_secs(cfg.logs.window_seconds, 60),
            cfg.logs.per_ip,
            cfg.logs.per_token,
            cfg.logs.global,
        );
        let metrics = RoutePolicy::new(
            duration_from_secs(cfg.history.window_seconds, 60),
            cfg.history.per_ip,
            cfg.history.per_token,
            cfg.history.global,
        );
        let brute_force = BruteForcePolicy::from_config(&cfg.brute_force);
        let affinity_limit = cfg.token_ip_affinity_limit;

        Self {
            html,
            sse,
            history,
            logs,
            metrics,
            allow_multiplier: cfg.allowlist_multiplier.max(1),
            brute_force,
            token_affinity_limit: affinity_limit,
        }
    }

    pub(crate) fn route_policy(&self, route: WebRoute) -> &RoutePolicy {
        match route {
            WebRoute::Html => &self.html,
            WebRoute::Sse => &self.sse.route,
            WebRoute::History => &self.history,
            WebRoute::Logs => &self.logs,
            WebRoute::Metrics => &self.metrics,
        }
    }

    pub(crate) fn allow_multiplier(&self) -> u32 {
        self.allow_multiplier.max(1)
    }

    pub(crate) fn token_affinity_limit(&self, trusted: bool) -> u32 {
        if self.token_affinity_limit == 0 {
            return 0;
        }
        if trusted {
            let multiplier = self.allow_multiplier().max(1);
            self.token_affinity_limit
                .saturating_mul(multiplier)
                .max(self.token_affinity_limit)
        } else {
            self.token_affinity_limit
        }
    }

    pub(crate) fn adjust_retry(&self, route: WebRoute, mut delay: Duration) -> Duration {
        if route == WebRoute::Sse {
            let min = self.brute_force.sse_min_retry();
            if min > Duration::ZERO && delay < min {
                delay = min;
            }
        }
        if delay < Duration::from_millis(250) {
            delay = Duration::from_secs(1);
        }
        delay
    }

    pub(crate) fn brute_force(&self) -> &BruteForcePolicy {
        &self.brute_force
    }

    pub(crate) fn sse_limits(&self) -> &SsePolicy {
        &self.sse
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

    pub(crate) fn sse_max_stream_bytes(&self) -> usize {
        self.sse.max_stream_bytes()
    }

    #[cfg(test)]
    pub(crate) fn override_html(&mut self, policy: RoutePolicy) {
        self.html = policy;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RoutePolicy {
    window: Duration,
    per_ip: u32,
    per_token: u32,
    global: u32,
}

impl RoutePolicy {
    pub(crate) fn new(window: Duration, per_ip: u32, per_token: u32, global: u32) -> Self {
        Self {
            window: if window.is_zero() {
                Duration::from_secs(1)
            } else {
                window
            },
            per_ip,
            per_token,
            global,
        }
    }

    pub(crate) fn window(&self) -> Duration {
        self.window
    }

    pub(crate) fn ip_limit(&self, multiplier: u32, trusted: bool) -> u32 {
        if self.per_ip == 0 {
            return 0;
        }
        if trusted {
            self.per_ip.saturating_mul(multiplier.max(1))
        } else {
            self.per_ip
        }
    }

    pub(crate) fn token_limit(&self) -> u32 {
        self.per_token
    }

    pub(crate) fn global_limit(&self) -> u32 {
        self.global
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SsePolicy {
    route: RoutePolicy,
    max_active_per_ip: u32,
    max_active_per_token: u32,
    max_stream: Duration,
    min_event_interval: Duration,
    max_payload_bytes: usize,
    max_stream_bytes: usize,
}

impl SsePolicy {
    pub(crate) fn default() -> Self {
        Self {
            route: RoutePolicy::new(Duration::from_secs(60), 10, 6, 40),
            max_active_per_ip: 1,
            max_active_per_token: 1,
            max_stream: Duration::from_secs(20 * 60),
            min_event_interval: Duration::from_secs(1),
            max_payload_bytes: 48 * 1024,
            max_stream_bytes: 4 * 1024 * 1024,
        }
    }

    #[cfg(feature = "config")]
    fn from_config(cfg: &crate::domain::SseLimitConfig) -> Self {
        Self {
            route: RoutePolicy::new(
                duration_from_secs(cfg.window_seconds, 60),
                cfg.per_ip,
                cfg.per_token,
                cfg.global,
            ),
            max_active_per_ip: cfg.max_active_per_ip,
            max_active_per_token: cfg.max_active_per_token,
            max_stream: duration_from_secs(cfg.max_stream_seconds, 20 * 60),
            min_event_interval: duration_from_millis(cfg.min_event_interval_ms, 1000),
            max_payload_bytes: cfg.max_payload_bytes as usize,
            max_stream_bytes: cfg.max_stream_bytes as usize,
        }
    }

    pub(crate) fn min_event_interval(&self) -> Duration {
        self.min_event_interval
    }

    pub(crate) fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    pub(crate) fn max_stream(&self) -> Duration {
        self.max_stream
    }

    pub(crate) fn max_stream_bytes(&self) -> usize {
        self.max_stream_bytes
    }

    pub(crate) fn max_active_per_ip(&self) -> u32 {
        self.max_active_per_ip
    }

    pub(crate) fn max_active_per_token(&self) -> u32 {
        self.max_active_per_token
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BruteForcePolicy {
    window: Duration,
    threshold: u32,
    initial_backoff: Duration,
    multiplier: f32,
    ceiling: Duration,
    quarantine: Duration,
    token_failure_threshold: u32,
    token_ip_spread: u32,
    sse_min_retry: Duration,
    token_spread_ttl: Duration,
    token_spread_cleanup_interval: Duration,
}

impl BruteForcePolicy {
    pub(crate) fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            threshold: 3,
            initial_backoff: Duration::from_secs(15),
            multiplier: 3.0,
            ceiling: Duration::from_secs(5 * 60),
            quarantine: Duration::from_secs(45 * 60),
            token_failure_threshold: 6,
            token_ip_spread: 2,
            sse_min_retry: Duration::from_secs(2),
            token_spread_ttl: Duration::from_secs(45 * 60),
            token_spread_cleanup_interval: Duration::from_secs(60),
        }
    }

    #[cfg(feature = "config")]
    fn from_config(cfg: &crate::domain::BruteForceConfig) -> Self {
        // Thresholds must be >= 1 to avoid immediate lock on first failure.
        let threshold = cfg.threshold.max(1);
        let token_failure_threshold = cfg.token_failure_threshold.max(1);
        let token_ip_spread = cfg.token_ip_spread.clamp(1, TOKEN_IP_SPREAD_MAX_IPS);

        Self {
            window: duration_from_secs(cfg.window_seconds, 300),
            threshold,
            initial_backoff: duration_from_secs(cfg.initial_backoff_seconds, 15),
            multiplier: if cfg.backoff_multiplier <= 1.0 {
                3.0
            } else {
                cfg.backoff_multiplier
            },
            ceiling: duration_from_secs(cfg.backoff_ceiling_seconds, 5 * 60),
            quarantine: duration_from_secs(cfg.quarantine_seconds, 45 * 60),
            token_failure_threshold,
            token_ip_spread,
            sse_min_retry: duration_from_secs(cfg.sse_min_retry_seconds, 2),
            token_spread_ttl: duration_from_secs(cfg.token_spread_ttl_seconds, 45 * 60),
            token_spread_cleanup_interval: duration_from_secs(cfg.token_spread_cleanup_seconds, 60),
        }
    }

    pub(crate) fn window(&self) -> Duration {
        self.window
    }

    pub(crate) fn threshold(&self) -> u32 {
        self.threshold
    }

    pub(crate) fn initial_backoff(&self) -> Duration {
        self.initial_backoff
    }

    pub(crate) fn multiplier(&self) -> f32 {
        self.multiplier
    }

    pub(crate) fn ceiling(&self) -> Duration {
        self.ceiling
    }

    pub(crate) fn quarantine(&self) -> Duration {
        self.quarantine
    }

    pub(crate) fn token_failure_threshold(&self) -> u32 {
        self.token_failure_threshold
    }

    pub(crate) fn token_ip_spread(&self) -> u32 {
        self.token_ip_spread
    }

    pub(crate) fn sse_min_retry(&self) -> Duration {
        self.sse_min_retry
    }

    pub(crate) fn token_spread_ttl(&self) -> Duration {
        self.token_spread_ttl
    }

    pub(crate) fn token_spread_cleanup_interval(&self) -> Duration {
        self.token_spread_cleanup_interval
    }

    #[cfg(test)]
    pub(crate) fn with_token_spread(self, ttl: Duration, cleanup: Duration) -> Self {
        Self {
            token_spread_ttl: ttl,
            token_spread_cleanup_interval: cleanup,
            ..self
        }
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

#[cfg(all(test, feature = "config"))]
mod tests {
    use super::{SecurityPolicy, DEFAULT_TOKEN_AFFINITY_LIMIT, TOKEN_IP_SPREAD_MAX_IPS};
    use crate::domain::WebSecurityConfig;

    #[test]
    fn token_affinity_limit_allows_zero_from_config() {
        let cfg = WebSecurityConfig {
            token_ip_affinity_limit: 0,
            ..WebSecurityConfig::default()
        };

        let policy = SecurityPolicy::from_config(&cfg);

        assert_eq!(policy.token_affinity_limit(false), 0);
        assert_eq!(policy.token_affinity_limit(true), 0);
    }

    #[test]
    fn token_affinity_limit_uses_default_when_unspecified() {
        let cfg = WebSecurityConfig::default();
        let policy = SecurityPolicy::from_config(&cfg);

        assert_eq!(
            policy.token_affinity_limit(false),
            DEFAULT_TOKEN_AFFINITY_LIMIT
        );
    }

    #[test]
    fn brute_force_threshold_is_clamped_to_one() {
        let cfg = WebSecurityConfig {
            brute_force: crate::domain::BruteForceConfig {
                threshold: 0,
                ..crate::domain::BruteForceConfig::default()
            },
            ..WebSecurityConfig::default()
        };

        let policy = SecurityPolicy::from_config(&cfg);

        assert_eq!(policy.brute_force().threshold(), 1);
    }

    #[test]
    fn token_failure_threshold_is_clamped_to_one() {
        let cfg = WebSecurityConfig {
            brute_force: crate::domain::BruteForceConfig {
                token_failure_threshold: 0,
                ..crate::domain::BruteForceConfig::default()
            },
            ..WebSecurityConfig::default()
        };

        let policy = SecurityPolicy::from_config(&cfg);

        assert_eq!(policy.brute_force().token_failure_threshold(), 1);
    }

    #[test]
    fn token_ip_spread_is_clamped_to_bounds() {
        let cfg_low = WebSecurityConfig {
            brute_force: crate::domain::BruteForceConfig {
                token_ip_spread: 0,
                ..crate::domain::BruteForceConfig::default()
            },
            ..WebSecurityConfig::default()
        };
        let policy_low = SecurityPolicy::from_config(&cfg_low);
        assert_eq!(policy_low.brute_force().token_ip_spread(), 1);

        let cfg_high = WebSecurityConfig {
            brute_force: crate::domain::BruteForceConfig {
                token_ip_spread: TOKEN_IP_SPREAD_MAX_IPS + 10,
                ..crate::domain::BruteForceConfig::default()
            },
            ..WebSecurityConfig::default()
        };
        let policy_high = SecurityPolicy::from_config(&cfg_high);
        assert_eq!(
            policy_high.brute_force().token_ip_spread(),
            TOKEN_IP_SPREAD_MAX_IPS
        );
    }

    #[test]
    fn token_ip_spread_default_matches_config_default() {
        let policy_default = SecurityPolicy::default();
        let policy_cfg = SecurityPolicy::from_config(&WebSecurityConfig::default());

        assert_eq!(
            policy_default.brute_force().token_ip_spread(),
            policy_cfg.brute_force().token_ip_spread()
        );
        assert_eq!(policy_default.brute_force().token_ip_spread(), 2);
    }
}
