use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use redb::{Database, ReadableTable, TableDefinition, TableError};

use crate::domain::DescribeError;

const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("server_metadata");
const DESCRIPTION_KEY: &str = "server_description";
const DB_FILE_NAME: &str = "metadata.redb";
const APP_DIR_NAME: &str = "describe-me";
static STATE_DIR_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
#[cfg(test)]
static STATE_DIR_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) struct MetadataStore {
    db: Database,
}

impl MetadataStore {
    pub(crate) fn open_default() -> Result<Self, DescribeError> {
        let path = metadata_db_path();
        Self::open_at(path)
    }

    pub(crate) fn open_at(path: impl AsRef<Path>) -> Result<Self, DescribeError> {
        let path = path.as_ref();
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
        Ok(Self { db })
    }

    pub(crate) fn set_description(&self, text: &str) -> Result<(), DescribeError> {
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

    pub(crate) fn get_description(&self) -> Result<Option<String>, DescribeError> {
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

    pub(crate) fn clear_description(&self) -> Result<(), DescribeError> {
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
}
