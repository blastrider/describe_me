use crate::application::shared::cache::{
    finish_refresh, should_start_refresh, RefreshState, RefreshUpdate,
};
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

pub(crate) struct UpdatesCacheStatus {
    pub data: Option<Arc<UpdatesInfo>>,
    pub fresh: bool,
    pub refreshing: bool,
    pub cooldown_active: bool,
}

struct Inner {
    state: Mutex<RefreshState<Arc<UpdatesInfo>>>,
    notify: Notify,
}

/// Guard that ensures `refreshing` is reset even if the refresh task panics or is cancelled.
struct RefreshGuard {
    inner: Arc<Inner>,
    armed: bool,
}

impl RefreshGuard {
    fn new(inner: Arc<Inner>) -> Self {
        Self { inner, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if reset_refresh(&self.inner) {
            return;
        }

        let inner = Arc::clone(&self.inner);
        let _ = std::thread::Builder::new()
            .name("updates-cache-refresh-reset".to_string())
            .spawn(move || {
                let mut backoff = 1u64;
                loop {
                    if reset_refresh(&inner) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(backoff));
                    backoff = (backoff.saturating_mul(2)).min(10);
                }
            });
    }
}

fn reset_refresh(inner: &Arc<Inner>) -> bool {
    if let Ok(mut state) = inner.state.try_lock() {
        finish_refresh(&mut state, Instant::now(), RefreshUpdate::Retain);
        drop(state);
        inner.notify.notify_waiters();
        return true;
    }
    false
}

type State = RefreshState<Arc<UpdatesInfo>>;

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
        self.peek_shared().await.map(|info| (*info).clone())
    }

    pub(crate) async fn peek_shared(&self) -> Option<Arc<UpdatesInfo>> {
        let state = self.inner.state.lock().await;
        state.data.clone()
    }

    pub(crate) async fn status(&self) -> UpdatesCacheStatus {
        let now = Instant::now();
        let state = self.inner.state.lock().await;
        let data = state.data.clone();
        let fresh = data.is_some()
            && state
                .last_success
                .map(|ts| now.duration_since(ts) <= self.success_ttl)
                .unwrap_or(false);
        let cooldown_active = state
            .last_refresh
            .map(|ts| now.duration_since(ts) < self.failure_retry)
            .unwrap_or(false);
        UpdatesCacheStatus {
            data,
            fresh,
            refreshing: state.refreshing,
            cooldown_active,
        }
    }

    pub async fn ensure_fresh(&self) {
        let now = Instant::now();
        {
            let mut state = self.inner.state.lock().await;
            if !should_start_refresh(&state, now, self.success_ttl, self.failure_retry) {
                return;
            }

            state.refreshing = true;
        }

        let inner = self.inner.clone();
        tokio::spawn(async move {
            Self::run_refresh(inner).await;
        });
    }

    #[allow(dead_code)]
    pub async fn refresh_blocking(&self) -> Option<UpdatesInfo> {
        self.refresh_blocking_shared()
            .await
            .map(|info| (*info).clone())
    }

    pub(crate) async fn refresh_blocking_shared(&self) -> Option<Arc<UpdatesInfo>> {
        loop {
            let notified = self.inner.notify.notified();
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
                notified.await;
                continue;
            }

            return Self::run_refresh(self.inner.clone()).await;
        }
    }

    async fn run_refresh(inner: Arc<Inner>) -> Option<Arc<UpdatesInfo>> {
        let guard = RefreshGuard::new(inner.clone());
        let result =
            tokio::task::spawn_blocking(crate::infrastructure::updates::gather_updates).await;
        let output = Self::apply_refresh_result(&inner, result).await;
        guard.disarm();
        output
    }

    async fn apply_refresh_result(
        inner: &Arc<Inner>,
        result: Result<Option<UpdatesInfo>, tokio::task::JoinError>,
    ) -> Option<Arc<UpdatesInfo>> {
        let now = Instant::now();
        let mut state = inner.state.lock().await;
        let update = match result {
            Ok(updates) => {
                let updates = updates.map(Arc::new);
                if let Some(ref info) = updates {
                    debug!(pending = info.pending, "updates_cache_refresh_success");
                } else {
                    debug!("updates_cache_refresh_empty");
                }
                RefreshUpdate::Replace(updates)
            }
            Err(err) => {
                warn!(error = ?err, "updates_cache_refresh_failed");
                RefreshUpdate::Retain
            }
        };
        let data = finish_refresh(&mut state, now, update);
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
        assert_eq!(result.as_deref(), Some(&pending));

        timeout(Duration::from_millis(50), notify_future)
            .await
            .expect("should notify waiters");

        let state = inner.state.lock().await;
        assert_eq!(state.data.as_deref(), Some(&pending));
        assert!(state.last_success.is_some());
        assert!(state.last_refresh.is_some());
        assert!(!state.refreshing);
    }

    #[tokio::test]
    async fn apply_refresh_result_preserves_data_on_error() {
        let existing = sample_updates(1);
        let inner = new_inner_with_state(State {
            data: Some(Arc::new(existing.clone())),
            last_success: Some(Instant::now()),
            refreshing: true,
            ..State::default()
        });

        let notify_future = inner.notify.notified();
        let join_err = tokio::spawn(async { panic!("fail") }).await.unwrap_err();

        let result = UpdatesCache::apply_refresh_result(&inner, Err(join_err)).await;
        assert_eq!(result.as_deref(), Some(&existing));

        timeout(Duration::from_millis(50), notify_future)
            .await
            .expect("should notify waiters after failure");

        let state = inner.state.lock().await;
        assert_eq!(state.data.as_deref(), Some(&existing));
        assert!(state.last_refresh.is_some());
        assert!(state.last_success.is_some());
        assert!(!state.refreshing);
    }

    #[tokio::test]
    async fn refresh_guard_resets_on_panic() {
        let cache = UpdatesCache::new(Duration::from_secs(1), Duration::from_secs(1));
        {
            let mut state = cache.inner.state.lock().await;
            state.refreshing = true;
        }
        let inner = cache.inner.clone();
        tokio::spawn(async move {
            let guard = super::RefreshGuard::new(inner.clone());
            // Simulate panic before apply_refresh_result
            drop(guard); // drop without disarm
            panic!("simulated panic");
        })
        .await
        .ok();

        // Give the guard time to reset (with timeout to avoid hangs)
        let _ =
            tokio::time::timeout(Duration::from_millis(100), cache.inner.notify.notified()).await;
        let state = cache.inner.state.lock().await;
        assert!(
            !state.refreshing,
            "refreshing should be reset even if task panics"
        );
    }

    #[tokio::test]
    async fn refresh_guard_resets_without_spawn() {
        let cache = UpdatesCache::new(Duration::from_secs(1), Duration::from_secs(1));
        {
            let mut state = cache.inner.state.lock().await;
            state.refreshing = true;
        }
        // Drop the guard on this thread so try_lock succeeds and no spawn is needed.
        {
            let guard = super::RefreshGuard::new(cache.inner.clone());
            drop(guard);
        }
        let state = cache.inner.state.lock().await;
        assert!(
            !state.refreshing,
            "refreshing should reset synchronously even without spawn"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_guard_resets_under_lock_contention() {
        let cache = UpdatesCache::new(Duration::from_secs(1), Duration::from_secs(1));
        let (tx_release, rx_release) = std::sync::mpsc::channel();
        let inner_for_thread = cache.inner.clone();
        let holder = std::thread::spawn(move || {
            let mut state = inner_for_thread.state.blocking_lock();
            state.refreshing = true;
            let _ = rx_release.recv(); // hold lock until signaled
        });

        // Ensure the lock is held by the blocking thread.
        while let Ok(guard) = cache.inner.state.try_lock() {
            drop(guard);
            tokio::task::yield_now().await;
        }

        // Release the lock shortly after dropping the guard so the contention path is exercised.
        let release_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx_release.send(()).ok();
        });

        let guard = super::RefreshGuard::new(cache.inner.clone());
        drop(guard);

        release_task.await.ok();
        holder.join().ok();
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                let state = cache.inner.state.lock().await;
                if !state.refreshing {
                    break;
                }
                drop(state);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("refreshing should reset even when lock was contended");
    }
}
