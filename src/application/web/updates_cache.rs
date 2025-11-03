use crate::domain::UpdatesInfo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct UpdatesCache {
    inner: Arc<Inner>,
    success_ttl: Duration,
    failure_retry: Duration,
}

struct Inner {
    state: Mutex<State>,
    notify: Notify,
}

#[derive(Default)]
struct State {
    data: Option<UpdatesInfo>,
    last_refresh: Option<Instant>,
    last_success: Option<Instant>,
    refreshing: bool,
}

impl UpdatesCache {
    pub fn new(success_ttl: Duration, failure_retry: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                notify: Notify::new(),
            }),
            success_ttl,
            failure_retry,
        }
    }

    pub async fn peek(&self) -> Option<UpdatesInfo> {
        let state = self.inner.state.lock().await;
        state.data.clone()
    }

    pub async fn ensure_fresh(&self) {
        let now = Instant::now();
        {
            let mut state = self.inner.state.lock().await;
            if state.refreshing {
                return;
            }
            let has_data = state.data.is_some();
            let success_stale = state
                .last_success
                .map(|ts| now.duration_since(ts) > self.success_ttl)
                .unwrap_or(true);
            let cooldown_active = state
                .last_refresh
                .map(|ts| now.duration_since(ts) < self.failure_retry)
                .unwrap_or(false);

            if has_data && !success_stale {
                return;
            }
            if cooldown_active {
                return;
            }

            state.refreshing = true;
        }

        let inner = self.inner.clone();
        tokio::spawn(async move {
            let result =
                tokio::task::spawn_blocking(crate::infrastructure::updates::gather_updates).await;
            let now = Instant::now();
            let mut state = inner.state.lock().await;
            state.refreshing = false;
            match result {
                Ok(updates) => {
                    if let Some(ref info) = updates {
                        debug!(pending = info.pending, "updates_cache_refresh_success");
                        state.last_success = Some(now);
                    } else {
                        debug!("updates_cache_refresh_empty");
                    }
                    state.data = updates;
                }
                Err(err) => {
                    warn!(error = ?err, "updates_cache_refresh_failed");
                }
            }
            state.last_refresh = Some(now);
            drop(state);
            inner.notify.notify_waiters();
        });
    }

    pub async fn refresh_blocking(&self) -> Option<UpdatesInfo> {
        loop {
            let wait_for_refresh = {
                let mut state = self.inner.state.lock().await;
                if let Some(data) = state.data.clone() {
                    return Some(data);
                }
                if state.refreshing {
                    true
                } else {
                    state.refreshing = true;
                    false
                }
            };

            if wait_for_refresh {
                self.inner.notify.notified().await;
                continue;
            }

            let result =
                tokio::task::spawn_blocking(crate::infrastructure::updates::gather_updates).await;
            let now = Instant::now();
            let mut state = self.inner.state.lock().await;
            state.refreshing = false;
            let mut return_data = state.data.clone();
            match result {
                Ok(updates) => {
                    if let Some(ref info) = updates {
                        debug!(pending = info.pending, "updates_cache_refresh_success");
                        state.last_success = Some(now);
                    } else {
                        debug!("updates_cache_refresh_empty");
                    }
                    state.data = updates;
                    return_data = state.data.clone();
                }
                Err(err) => {
                    warn!(error = ?err, "updates_cache_refresh_failed");
                }
            }
            state.last_refresh = Some(now);
            drop(state);
            self.inner.notify.notify_waiters();
            return return_data;
        }
    }
}
