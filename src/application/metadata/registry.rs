use std::sync::{Mutex, OnceLock};

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
    store_lock()
        .lock()
        .expect("metadata store mutex poisoned")
        .clone()
}

pub fn init_metadata_store(store: MetadataStore) {
    let lock = store_lock();
    let mut guard = lock.lock().expect("metadata store mutex poisoned");
    *guard = store;
}

#[cfg(test)]
pub(crate) fn reset_metadata_store_for_tests() {
    if let Some(lock) = METADATA_STORE.get() {
        let mut guard = lock.lock().expect("metadata store mutex poisoned");
        *guard = MetadataStore::open_default().expect("MetadataStore reset");
    }
}
