use std::borrow::Cow;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::application::context::MetadataStoreHealth;
use crate::application::logging::LogEvent;
use crate::application::sync::lock_expect;
use crate::domain::DescribeError;
use crate::infrastructure::storage::{MetadataBackend, MetadataStore};

#[cfg(test)]
const METADATA_RETRY_DELAY: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const METADATA_RETRY_DELAY: Duration = Duration::from_secs(60);

const HEALTH_PERSISTENT: u8 = 1;
const HEALTH_FALLBACK: u8 = 2;

struct MetadataStoreState {
    store: MetadataStore,
    switchable: Arc<SwitchableMetadataBackend>,
}

static METADATA_STORE: OnceLock<Mutex<MetadataStoreState>> = OnceLock::new();

#[derive(Default)]
struct FallbackMetaState {
    description: Option<String>,
    tags: Option<String>,
}

#[derive(Default)]
struct FallbackMetadataBackend {
    state: Mutex<FallbackMetaState>,
}

impl MetadataBackend for FallbackMetadataBackend {
    fn set_description(&self, text: &str) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("FallbackMetadataBackend");
        guard.description = if text.trim().is_empty() {
            None
        } else {
            Some(text.to_owned())
        };
        Ok(())
    }

    fn get_description(&self) -> Result<Option<String>, DescribeError> {
        let guard = self.state.lock().expect("FallbackMetadataBackend");
        Ok(guard.description.clone())
    }

    fn clear_description(&self) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("FallbackMetadataBackend");
        guard.description = None;
        Ok(())
    }

    fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("FallbackMetadataBackend");
        guard.tags = if payload.is_empty() {
            None
        } else {
            Some(payload.to_owned())
        };
        Ok(())
    }

    fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
        let guard = self.state.lock().expect("FallbackMetadataBackend");
        Ok(guard.tags.clone())
    }

    fn clear_tags(&self) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("FallbackMetadataBackend");
        guard.tags = None;
        Ok(())
    }
}

impl FallbackMetadataBackend {
    fn snapshot(&self) -> (Option<String>, Option<String>) {
        let guard = self.state.lock().expect("FallbackMetadataBackend");
        (guard.description.clone(), guard.tags.clone())
    }

    fn clear(&self) {
        let mut guard = self.state.lock().expect("FallbackMetadataBackend");
        guard.description = None;
        guard.tags = None;
    }
}

struct RetryState {
    next_retry_at: Instant,
    upgrade_in_progress: bool,
}

impl RetryState {
    fn new(health: MetadataStoreHealth) -> Self {
        let now = Instant::now();
        let next_retry_at = if health == MetadataStoreHealth::FallbackInMemory {
            now + METADATA_RETRY_DELAY
        } else {
            now
        };
        Self {
            next_retry_at,
            upgrade_in_progress: false,
        }
    }
}

struct SwitchableMetadataBackend {
    inner: RwLock<Arc<dyn MetadataBackend>>,
    fallback: Arc<FallbackMetadataBackend>,
    retry: Mutex<RetryState>,
    health: AtomicU8,
}

impl SwitchableMetadataBackend {
    fn new(
        initial: Arc<dyn MetadataBackend>,
        fallback: Arc<FallbackMetadataBackend>,
        health: MetadataStoreHealth,
    ) -> Self {
        let health_flag = match health {
            MetadataStoreHealth::Persistent => HEALTH_PERSISTENT,
            _ => HEALTH_FALLBACK,
        };
        Self {
            inner: RwLock::new(initial),
            fallback,
            retry: Mutex::new(RetryState::new(health)),
            health: AtomicU8::new(health_flag),
        }
    }

    fn health(&self) -> MetadataStoreHealth {
        match self.health.load(Ordering::Acquire) {
            HEALTH_PERSISTENT => MetadataStoreHealth::Persistent,
            _ => MetadataStoreHealth::FallbackInMemory,
        }
    }

    fn set_backend(&self, backend: Arc<dyn MetadataBackend>, health: MetadataStoreHealth) {
        let mut guard = self.inner.write().expect("SwitchableMetadataBackend");
        *guard = backend;
        let flag = match health {
            MetadataStoreHealth::Persistent => HEALTH_PERSISTENT,
            _ => HEALTH_FALLBACK,
        };
        self.health.store(flag, Ordering::Release);
    }

    fn reset_retry(&self, health: MetadataStoreHealth) {
        let mut guard = self.retry.lock().expect("SwitchableMetadataBackend");
        *guard = RetryState::new(health);
    }

    fn reset_with(&self, backend: Arc<dyn MetadataBackend>, health: MetadataStoreHealth) {
        self.fallback.clear();
        self.set_backend(backend, health);
        self.reset_retry(health);
    }

    fn migrate_fallback(&self, backend: &dyn MetadataBackend) -> (bool, bool) {
        let (description, tags_raw) = self.fallback.snapshot();
        let mut migrated_description = false;
        let mut migrated_tags = false;

        if let Some(description) = description {
            match backend.set_description(&description) {
                Ok(()) => migrated_description = true,
                Err(err) => {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("metadata_store_migrate_description"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                }
            }
        }

        if let Some(tags_raw) = tags_raw {
            match backend.set_tags_raw(&tags_raw) {
                Ok(()) => migrated_tags = true,
                Err(err) => {
                    LogEvent::SystemError {
                        location: Cow::Borrowed("metadata_store_migrate_tags"),
                        error: Cow::Owned(err.to_string()),
                    }
                    .emit();
                }
            }
        }

        (migrated_description, migrated_tags)
    }

    fn maybe_upgrade(&self) {
        if self.health.load(Ordering::Acquire) != HEALTH_FALLBACK {
            return;
        }

        let now = Instant::now();
        {
            let mut retry = self.retry.lock().expect("SwitchableMetadataBackend");
            if retry.upgrade_in_progress || now < retry.next_retry_at {
                return;
            }
            retry.upgrade_in_progress = true;
            retry.next_retry_at = now + METADATA_RETRY_DELAY;
        }

        let result = MetadataStore::open_default();
        match result {
            Ok(store) => {
                let backend = store.backend();
                let (migrated_description, migrated_tags) = self.migrate_fallback(backend.as_ref());
                self.set_backend(backend, MetadataStoreHealth::Persistent);
                LogEvent::MetadataStoreUpgraded {
                    migrated_description,
                    migrated_tags,
                }
                .emit();
            }
            Err(err) => {
                LogEvent::MetadataStoreRetryFailed {
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
            }
        }

        let mut retry = self.retry.lock().expect("SwitchableMetadataBackend");
        retry.upgrade_in_progress = false;
    }
}

impl MetadataBackend for SwitchableMetadataBackend {
    fn set_description(&self, text: &str) -> Result<(), DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.set_description(text)
    }

    fn get_description(&self) -> Result<Option<String>, DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.get_description()
    }

    fn clear_description(&self) -> Result<(), DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.clear_description()
    }

    fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.set_tags_raw(payload)
    }

    fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.get_tags_raw()
    }

    fn clear_tags(&self) -> Result<(), DescribeError> {
        self.maybe_upgrade();
        let backend = self
            .inner
            .read()
            .expect("SwitchableMetadataBackend")
            .clone();
        backend.clear_tags()
    }
}

fn store_lock() -> &'static Mutex<MetadataStoreState> {
    METADATA_STORE.get_or_init(|| Mutex::new(init_store_state()))
}

fn init_store_state() -> MetadataStoreState {
    let fallback = Arc::new(FallbackMetadataBackend::default());
    let (backend, health) = match MetadataStore::open_default() {
        Ok(store) => (store.backend(), MetadataStoreHealth::Persistent),
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("metadata_store_init"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            (
                fallback.clone() as Arc<dyn MetadataBackend>,
                MetadataStoreHealth::FallbackInMemory,
            )
        }
    };
    let switchable = Arc::new(SwitchableMetadataBackend::new(backend, fallback, health));
    let store =
        MetadataStore::new_with_backend(Arc::clone(&switchable) as Arc<dyn MetadataBackend>);
    MetadataStoreState { store, switchable }
}

pub(crate) fn metadata_store() -> MetadataStore {
    let guard = lock_expect(store_lock().lock(), "MetadataStore");
    guard.store.clone()
}

pub(crate) fn metadata_store_health() -> MetadataStoreHealth {
    let guard = lock_expect(store_lock().lock(), "MetadataStore");
    guard.switchable.health()
}

#[cfg(any(test, feature = "internals"))]
pub fn init_metadata_store_for_internals(store: MetadataStore) {
    let lock = store_lock();
    let guard = lock_expect(lock.lock(), "MetadataStore");
    guard
        .switchable
        .reset_with(store.backend(), MetadataStoreHealth::Persistent);
}

#[cfg(any(test, feature = "internals"))]
pub fn reset_metadata_store_for_tests() {
    if let Some(lock) = METADATA_STORE.get() {
        let guard = lock_expect(lock.lock(), "MetadataStore");
        let fallback = guard.switchable.fallback.clone();
        let (backend, health) = match MetadataStore::open_default() {
            Ok(store) => (store.backend(), MetadataStoreHealth::Persistent),
            Err(err) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("metadata_store_reset"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
                (
                    fallback.clone() as Arc<dyn MetadataBackend>,
                    MetadataStoreHealth::FallbackInMemory,
                )
            }
        };
        guard.switchable.reset_with(backend, health);
    }
}
