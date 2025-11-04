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
            Self::run_refresh(inner).await;
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

            return Self::run_refresh(self.inner.clone()).await;
        }
    }

    async fn run_refresh(inner: Arc<Inner>) -> Option<UpdatesInfo> {
        let result =
            tokio::task::spawn_blocking(crate::infrastructure::updates::gather_updates).await;
        Self::apply_refresh_result(&inner, result).await
    }

    async fn apply_refresh_result(
        inner: &Arc<Inner>,
        result: Result<Option<UpdatesInfo>, tokio::task::JoinError>,
    ) -> Option<UpdatesInfo> {
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
        let data = state.data.clone();
        drop(state);
        inner.notify.notify_waiters();
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::UpdatesInfo;
    use std::time::Instant;
    use tokio::time::{timeout, Duration};

    fn new_inner_with_state(state: State) -> Arc<Inner> {
        Arc::new(Inner {
            state: Mutex::new(state),
            notify: Notify::new(),
        })
    }

    fn sample_updates(pending: u32) -> UpdatesInfo {
        UpdatesInfo {
            pending,
            reboot_required: false,
            packages: None,
        }
    }

    #[tokio::test]
    async fn apply_refresh_result_updates_state_on_success() {
        let inner = new_inner_with_state(State {
            refreshing: true,
            ..State::default()
        });
        let pending = sample_updates(3);
        let notify_future = inner.notify.notified();

        let result = UpdatesCache::apply_refresh_result(&inner, Ok(Some(pending.clone()))).await;
        assert_eq!(result, Some(pending.clone()));

        timeout(Duration::from_millis(50), notify_future)
            .await
            .expect("should notify waiters");

        let state = inner.state.lock().await;
        assert_eq!(state.data, Some(pending));
        assert!(state.last_success.is_some());
        assert!(state.last_refresh.is_some());
        assert!(!state.refreshing);
    }

    #[tokio::test]
    async fn apply_refresh_result_preserves_data_on_error() {
        let existing = sample_updates(1);
        let inner = new_inner_with_state(State {
            data: Some(existing.clone()),
            last_success: Some(Instant::now()),
            refreshing: true,
            ..State::default()
        });

        let notify_future = inner.notify.notified();
        let join_err = tokio::spawn(async { panic!("fail") }).await.unwrap_err();

        let result = UpdatesCache::apply_refresh_result(&inner, Err(join_err)).await;
        assert_eq!(result, Some(existing.clone()));

        timeout(Duration::from_millis(50), notify_future)
            .await
            .expect("should notify waiters after failure");

        let state = inner.state.lock().await;
        assert_eq!(state.data, Some(existing));
        assert!(state.last_refresh.is_some());
        assert!(state.last_success.is_some());
        assert!(!state.refreshing);
    }
}
