use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use super::rate_limiter::RouteKey;
use crate::application::web::security::{TokenKey, WebRoute};

#[derive(Debug, Default)]
pub(crate) struct TokenAffinity {
    inner: Mutex<HashMap<(RouteKey, TokenKey), TokenAffinityRecord>>,
}

impl TokenAffinity {
    pub(crate) fn new() -> Self {
        Self::default()
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
        let record = guard
            .entry((route.into(), token))
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
