use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableTable, TableDefinition, TableError};

use crate::domain::DescribeError;

const METADATA_TABLE: TableDefinition<&str, &str> = TableDefinition::new("server_metadata");
const DESCRIPTION_KEY: &str = "server_description";
const DB_FILE_NAME: &str = "metadata.redb";
const APP_DIR_NAME: &str = "describe-me";

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
    resolve_state_dir().join(DB_FILE_NAME)
}

fn resolve_state_dir() -> PathBuf {
    if let Some(dir) = env::var_os("DESCRIBE_ME_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = env::var_os("STATE_DIRECTORY") {
        if let Some(first) = take_first_path(dir) {
            return first;
        }
    }
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
