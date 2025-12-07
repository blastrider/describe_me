use std::sync::{Mutex, OnceLock};

use crate::application::sync::lock_expect;
use crate::infrastructure::storage::MetadataStore;

static METADATA_STORE: OnceLock<Mutex<MetadataStore>> = OnceLock::new();

fn store_lock() -> &'static Mutex<MetadataStore> {
    METADATA_STORE.get_or_init(|| {
        Mutex::new(
            MetadataStore::open_default()
                .expect("MetadataStore default initialization should succeed"),
        )
    })
}

pub fn metadata_store() -> MetadataStore {
    lock_expect(store_lock().lock(), "MetadataStore").clone()
}

pub fn init_metadata_store(store: MetadataStore) {
    let lock = store_lock();
    let mut guard = lock_expect(lock.lock(), "MetadataStore");
    *guard = store;
}

#[cfg(test)]
pub(crate) fn reset_metadata_store_for_tests() {
    if let Some(lock) = METADATA_STORE.get() {
        let mut guard = lock_expect(lock.lock(), "MetadataStore");
        *guard = MetadataStore::open_default().expect("MetadataStore reset");
    }
}
