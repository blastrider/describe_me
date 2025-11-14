use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use redb::{Database, ReadableTable, TableDefinition, TableError};

use crate::domain::DescribeError;

const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("server_metadata");
const DESCRIPTION_KEY: &str = "server_description";
const TAGS_KEY: &str = "server_tags";
const DB_FILE_NAME: &str = "metadata.redb";
const APP_DIR_NAME: &str = "describe-me";
static STATE_DIR_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
#[cfg(test)]
static STATE_DIR_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) trait MetadataBackend: Send + Sync {
    fn set_description(&self, text: &str) -> Result<(), DescribeError>;
    fn get_description(&self) -> Result<Option<String>, DescribeError>;
    fn clear_description(&self) -> Result<(), DescribeError>;
    fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError>;
    fn get_tags_raw(&self) -> Result<Option<String>, DescribeError>;
    fn clear_tags(&self) -> Result<(), DescribeError>;
}

pub(crate) trait MetadataBackendFactory: Send + Sync {
    fn open_default(&self) -> Result<Box<dyn MetadataBackend>, DescribeError>;
}

pub(crate) struct MetadataStore {
    backend: Arc<dyn MetadataBackend>,
}

impl MetadataStore {
    fn new(backend: Arc<dyn MetadataBackend>) -> Self {
        Self { backend }
    }

    pub(crate) fn open_default() -> Result<Self, DescribeError> {
        Ok(Self::new(acquire_backend()?))
    }

    pub(crate) fn set_description(&self, text: &str) -> Result<(), DescribeError> {
        self.backend.set_description(text)
    }

    pub(crate) fn get_description(&self) -> Result<Option<String>, DescribeError> {
        self.backend.get_description()
    }

    pub(crate) fn clear_description(&self) -> Result<(), DescribeError> {
        self.backend.clear_description()
    }

    pub(crate) fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
        self.backend.set_tags_raw(payload)
    }

    pub(crate) fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
        self.backend.get_tags_raw()
    }

    pub(crate) fn clear_tags(&self) -> Result<(), DescribeError> {
        self.backend.clear_tags()
    }
}

struct BackendRegistry {
    factory: Box<dyn MetadataBackendFactory>,
    backend: Option<Arc<dyn MetadataBackend>>,
}

impl BackendRegistry {
    fn new() -> Self {
        Self {
            factory: default_backend_factory(),
            backend: None,
        }
    }

    fn acquire_backend(&mut self) -> Result<Arc<dyn MetadataBackend>, DescribeError> {
        if let Some(current) = self.backend.as_ref() {
            return Ok(Arc::clone(current));
        }
        let backend = self.factory.open_default()?;
        let backend = Arc::from(backend);
        self.backend = Some(Arc::clone(&backend));
        Ok(backend)
    }

    fn set_factory(&mut self, factory: Box<dyn MetadataBackendFactory>) {
        self.factory = factory;
        self.backend = None;
    }
}

fn backend_registry() -> &'static Mutex<BackendRegistry> {
    static REGISTRY: OnceLock<Mutex<BackendRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BackendRegistry::new()))
}

fn acquire_backend() -> Result<Arc<dyn MetadataBackend>, DescribeError> {
    let mut guard = backend_registry()
        .lock()
        .expect("metadata backend registry mutex poisoned");
    guard.acquire_backend()
}

fn default_backend_factory() -> Box<dyn MetadataBackendFactory> {
    Box::new(RedbBackendFactory)
}

struct RedbBackendFactory;

impl MetadataBackendFactory for RedbBackendFactory {
    fn open_default(&self) -> Result<Box<dyn MetadataBackend>, DescribeError> {
        let path = metadata_db_path();
        let path = path.as_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|err| {
                DescribeError::System(format!(
                    "impossible de créer le répertoire état {}: {err}",
                    dir.display()
                ))
            })?;
        }
        let db = if path.exists() {
            Database::open(path).map_err(map_db_err)?
        } else {
            Database::create(path).map_err(map_db_err)?
        };
        Ok(Box::new(RedbBackend { db }))
    }
}

struct RedbBackend {
    db: Database,
}

impl MetadataBackend for RedbBackend {
    fn set_description(&self, text: &str) -> Result<(), DescribeError> {
        let tx = self.db.begin_write().map_err(map_db_err)?;
        {
            let mut table = tx.open_table(METADATA_TABLE).map_err(map_db_err)?;
            if text.trim().is_empty() {
                table.remove(DESCRIPTION_KEY).map_err(map_storage_err)?;
            } else {
                table
                    .insert(DESCRIPTION_KEY, text)
                    .map_err(map_storage_err)?;
            }
        }
        tx.commit().map_err(map_db_err)?;
        Ok(())
    }

    fn get_description(&self) -> Result<Option<String>, DescribeError> {
        let tx = self.db.begin_read().map_err(map_db_err)?;
        let table = match tx.open_table(METADATA_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(err) => return Err(map_db_err(err)),
        };
        let value = table
            .get(DESCRIPTION_KEY)
            .map_err(map_storage_err)?
            .map(|v| v.value().to_owned());
        Ok(value)
    }

    fn clear_description(&self) -> Result<(), DescribeError> {
        let tx = self.db.begin_write().map_err(map_db_err)?;
        match tx.open_table(METADATA_TABLE) {
            Ok(mut table) => {
                table.remove(DESCRIPTION_KEY).map_err(map_storage_err)?;
            }
            Err(TableError::TableDoesNotExist(_)) => {
                // Nothing persisted yet — nothing to clear.
            }
            Err(err) => return Err(map_db_err(err)),
        }
        tx.commit().map_err(map_db_err)?;
        Ok(())
    }

    fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
        let tx = self.db.begin_write().map_err(map_db_err)?;
        {
            let mut table = tx.open_table(METADATA_TABLE).map_err(map_db_err)?;
            if payload.is_empty() {
                table.remove(TAGS_KEY).map_err(map_storage_err)?;
            } else {
                table.insert(TAGS_KEY, payload).map_err(map_storage_err)?;
            }
        }
        tx.commit().map_err(map_db_err)?;
        Ok(())
    }

    fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
        let tx = self.db.begin_read().map_err(map_db_err)?;
        let table = match tx.open_table(METADATA_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(err) => return Err(map_db_err(err)),
        };
        let value = table
            .get(TAGS_KEY)
            .map_err(map_storage_err)?
            .map(|v| v.value().to_owned());
        Ok(value)
    }

    fn clear_tags(&self) -> Result<(), DescribeError> {
        let tx = self.db.begin_write().map_err(map_db_err)?;
        match tx.open_table(METADATA_TABLE) {
            Ok(mut table) => {
                table.remove(TAGS_KEY).map_err(map_storage_err)?;
            }
            Err(TableError::TableDoesNotExist(_)) => {}
            Err(err) => return Err(map_db_err(err)),
        }
        tx.commit().map_err(map_db_err)?;
        Ok(())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn set_metadata_backend_factory(factory: Box<dyn MetadataBackendFactory>) {
    let lock = backend_registry();
    let mut guard = lock
        .lock()
        .expect("metadata backend registry mutex poisoned");
    guard.set_factory(factory);
}

#[cfg(test)]
pub(crate) fn reset_metadata_backend_factory_for_tests() {
    set_metadata_backend_factory(default_backend_factory());
}

pub(crate) fn metadata_db_path() -> PathBuf {
    if let Some(dir) = env::var_os("DESCRIBE_ME_STATE_DIR") {
        return resolve_db_path(PathBuf::from(dir));
    }
    if let Some(path) = state_dir_override() {
        return resolve_db_path(path);
    }
    if let Some(dir) = env::var_os("STATE_DIRECTORY") {
        if let Some(first) = take_first_path(dir) {
            return resolve_db_path(first);
        }
    }
    resolve_state_dir().join(DB_FILE_NAME)
}

fn resolve_state_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(dir) = env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(dir).join(APP_DIR_NAME);
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join(APP_DIR_NAME);
        }
    }
    #[cfg(not(unix))]
    {
        if let Some(dir) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir).join(APP_DIR_NAME);
        }
        if let Some(dir) = env::var_os("APPDATA") {
            return PathBuf::from(dir).join(APP_DIR_NAME);
        }
    }
    env::temp_dir().join(APP_DIR_NAME)
}

fn resolve_db_path(base: PathBuf) -> PathBuf {
    if base
        .file_name()
        .map(|name| name == DB_FILE_NAME)
        .unwrap_or(false)
        || base.extension().map(|ext| ext == "redb").unwrap_or(false)
    {
        base
    } else {
        base.join(DB_FILE_NAME)
    }
}

fn state_dir_override() -> Option<PathBuf> {
    let lock = STATE_DIR_OVERRIDE.get()?;
    let guard = lock.lock().ok()?;
    guard.as_ref().cloned()
}

pub(crate) fn set_state_dir_override(path: impl Into<PathBuf>) {
    let path = path.into();
    let lock = STATE_DIR_OVERRIDE.get_or_init(|| Mutex::new(None));
    let mut guard = lock.lock().expect("state dir mutex poisoned");
    if path.as_os_str().is_empty() {
        *guard = None;
    } else {
        *guard = Some(path);
    }
}

#[cfg(test)]
pub(crate) fn clear_state_dir_override_for_tests() {
    if let Some(lock) = STATE_DIR_OVERRIDE.get() {
        *lock.lock().expect("state dir mutex poisoned") = None;
    }
}

#[cfg(test)]
pub(crate) fn metadata_db_path_for_tests() -> PathBuf {
    metadata_db_path()
}

#[cfg(test)]
pub(crate) fn state_dir_test_lock() -> std::sync::MutexGuard<'static, ()> {
    STATE_DIR_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("state dir test mutex")
}

fn take_first_path(value: OsString) -> Option<PathBuf> {
    let as_str = value.to_string_lossy();
    for entry in as_str.split(':') {
        let trimmed = entry.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    None
}

fn map_db_err<E: std::fmt::Display>(err: E) -> DescribeError {
    DescribeError::System(format!("stockage redb: {err}"))
}

fn map_storage_err<E: std::fmt::Display>(err: E) -> DescribeError {
    DescribeError::System(format!("stockage redb: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[test]
    fn metadata_path_uses_override_directory() {
        let _guard = state_dir_test_lock();
        clear_state_dir_override_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");
        let dir = tempdir().expect("tempdir");
        set_state_dir_override(dir.path());
        let path = metadata_db_path();
        assert_eq!(path, dir.path().join(DB_FILE_NAME));
        clear_state_dir_override_for_tests();
    }

    #[test]
    fn metadata_path_accepts_file_override() {
        let _guard = state_dir_test_lock();
        clear_state_dir_override_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");
        let dir = tempdir().expect("tempdir");
        let custom = dir.path().join("custom-db.redb");
        set_state_dir_override(&custom);
        let path = metadata_db_path();
        assert_eq!(path, custom);
        clear_state_dir_override_for_tests();
    }

    #[derive(Default)]
    struct InMemoryState {
        description: Option<String>,
        tags: Option<String>,
    }

    #[derive(Clone)]
    struct InMemoryBackend {
        state: Arc<Mutex<InMemoryState>>,
    }

    impl MetadataBackend for InMemoryBackend {
        fn set_description(&self, text: &str) -> Result<(), DescribeError> {
            let mut guard = self.state.lock().unwrap();
            guard.description = if text.trim().is_empty() {
                None
            } else {
                Some(text.to_owned())
            };
            Ok(())
        }

        fn get_description(&self) -> Result<Option<String>, DescribeError> {
            let guard = self.state.lock().unwrap();
            Ok(guard.description.clone())
        }

        fn clear_description(&self) -> Result<(), DescribeError> {
            let mut guard = self.state.lock().unwrap();
            guard.description = None;
            Ok(())
        }

        fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
            let mut guard = self.state.lock().unwrap();
            guard.tags = if payload.is_empty() {
                None
            } else {
                Some(payload.to_owned())
            };
            Ok(())
        }

        fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
            let guard = self.state.lock().unwrap();
            Ok(guard.tags.clone())
        }

        fn clear_tags(&self) -> Result<(), DescribeError> {
            let mut guard = self.state.lock().unwrap();
            guard.tags = None;
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct InMemoryFactory {
        state: Arc<Mutex<InMemoryState>>,
    }

    impl MetadataBackendFactory for InMemoryFactory {
        fn open_default(&self) -> Result<Box<dyn MetadataBackend>, DescribeError> {
            Ok(Box::new(InMemoryBackend {
                state: Arc::clone(&self.state),
            }))
        }
    }

    #[test]
    fn metadata_backend_can_be_overridden() {
        let _guard = state_dir_test_lock();
        reset_metadata_backend_factory_for_tests();
        set_metadata_backend_factory(Box::new(InMemoryFactory::default()));

        let store = MetadataStore::open_default().expect("open");
        store
            .set_description("backend override")
            .expect("set description");
        let description = store.get_description().expect("get description");
        assert_eq!(description.as_deref(), Some("backend override"));

        store
            .set_tags_raw("prod\nweb")
            .expect("set tags raw override");
        assert_eq!(
            store.get_tags_raw().expect("get tags raw").as_deref(),
            Some("prod\nweb")
        );

        store.clear_description().expect("clear description");
        assert!(store.get_description().expect("get description").is_none());

        reset_metadata_backend_factory_for_tests();
    }
}
