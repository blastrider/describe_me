use crate::application::history::HistoryBackend;
use crate::application::sync::lock_expect;
use crate::domain::DescribeError;
use crate::infrastructure::storage::metadata_db_path;
use rand_core::{OsRng, RngCore};
use redb::{Database, ReadableTable, TableDefinition, TableError};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::warn;

const HISTORY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("history_samples");
const HISTORY_DB_FILE: &str = "history.redb";
const SERVER_ID_FILE: &str = "history.identity";
const ENCODING_VERSION: u8 = 1;
const NO_VALUE: u16 = u16::MAX;
const HISTORY_MAX_ITEMS: usize = 10_000;

#[derive(Debug, Clone, Default)]
pub(crate) struct HistorySample {
    pub timestamp: u64,
    pub cpu_pct: Option<f32>,
    pub mem_pct: Option<f32>,
    pub disk_pct: Option<f32>,
}

#[derive(Debug, Default)]
pub(crate) struct MemoryStorage {
    buffers: Mutex<HashMap<String, HistoryBuffer>>,
}

impl MemoryStorage {
    fn append(
        &self,
        server_id: &str,
        sample: &HistorySample,
        retention: usize,
    ) -> Result<(), DescribeError> {
        if retention == 0 {
            return Ok(());
        }
        let mut guard = lock_expect(self.buffers.lock(), "HistoryMemoryStorage");
        let buffer = guard.entry(server_id.to_owned()).or_default();
        buffer.push(sample.clone(), retention);
        Ok(())
    }

    fn read(&self, server_id: &str) -> Vec<HistorySample> {
        let guard = lock_expect(self.buffers.lock(), "HistoryMemoryStorage");
        guard
            .get(server_id)
            .map(|buffer| buffer.points.clone())
            .unwrap_or_default()
    }
}

impl HistoryBackend for MemoryStorage {
    fn append(
        &self,
        server_id: &str,
        sample: &HistorySample,
        retention: usize,
    ) -> Result<(), DescribeError> {
        MemoryStorage::append(self, server_id, sample, retention)
    }

    fn read(&self, server_id: &str) -> Result<Vec<HistorySample>, DescribeError> {
        Ok(MemoryStorage::read(self, server_id))
    }
}

#[derive(Debug)]
pub(crate) struct DiskStorage {
    db: Database,
}

impl DiskStorage {
    pub(crate) fn open_or_create() -> Result<Self, DescribeError> {
        let path = history_db_path();
        if let Some(dir) = path.parent() {
            ensure_not_symlink(dir, "répertoire histoire")?;
            fs::create_dir_all(dir).map_err(|err| {
                DescribeError::System(format!(
                    "impossible de créer le répertoire histoire {}: {err}",
                    dir.display()
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        ensure_not_symlink(path.as_path(), "fichier history")?;
        let db = if path.exists() {
            Database::builder()
                .open(path.as_path())
                .map_err(|err| map_db_err(err.into()))?
        } else {
            Database::builder()
                .create(path.as_path())
                .map_err(|err| map_db_err(err.into()))?
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path.as_path(), fs::Permissions::from_mode(0o600));
        }
        Ok(Self { db })
    }

    fn append(
        &self,
        server_id: &str,
        sample: &HistorySample,
        retention: usize,
    ) -> Result<(), DescribeError> {
        if retention == 0 {
            return Ok(());
        }
        let tx = self
            .db
            .begin_write()
            .map_err(|err| map_db_err(err.into()))?;
        {
            let mut table = tx.open_table(HISTORY_TABLE).map_err(map_table_err)?;
            let mut buffer = match table.get(server_id).map_err(map_storage_err)? {
                Some(value) => HistoryBuffer::from_slice(value.value()),
                None => HistoryBuffer::default(),
            };
            buffer.push(sample.clone(), retention);
            let blob = buffer.encode();
            table
                .insert(server_id, blob.as_slice())
                .map_err(map_storage_err)?;
        }
        tx.commit().map_err(|err| map_db_err(err.into()))?;
        Ok(())
    }

    fn read(&self, server_id: &str) -> Result<Vec<HistorySample>, DescribeError> {
        let tx = self.db.begin_read().map_err(|err| map_db_err(err.into()))?;
        let table = match tx.open_table(HISTORY_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(err) => return Err(map_table_err(err)),
        };
        let blob = {
            let guard = table.get(server_id).map_err(map_storage_err)?;
            guard.map(|value| value.value().to_vec())
        };
        match blob {
            Some(bytes) => {
                let buffer = HistoryBuffer::from_slice(&bytes);
                Ok(buffer.into_points())
            }
            None => Ok(Vec::new()),
        }
    }
}

impl HistoryBackend for DiskStorage {
    fn append(
        &self,
        server_id: &str,
        sample: &HistorySample,
        retention: usize,
    ) -> Result<(), DescribeError> {
        DiskStorage::append(self, server_id, sample, retention)
    }

    fn read(&self, server_id: &str) -> Result<Vec<HistorySample>, DescribeError> {
        DiskStorage::read(self, server_id)
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct DisabledHistoryBackend;

impl HistoryBackend for DisabledHistoryBackend {
    fn append(
        &self,
        _server_id: &str,
        _sample: &HistorySample,
        _retention: usize,
    ) -> Result<(), DescribeError> {
        Ok(())
    }

    fn read(&self, _server_id: &str) -> Result<Vec<HistorySample>, DescribeError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default, Clone)]
struct HistoryBuffer {
    points: Vec<HistorySample>,
}

impl HistoryBuffer {
    fn push(&mut self, sample: HistorySample, limit: usize) {
        if limit == 0 {
            self.points.clear();
            return;
        }
        self.points.push(sample);
        if self.points.len() > limit {
            let excess = self.points.len() - limit;
            self.points.drain(0..excess);
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.points.len() * 14);
        buf.push(ENCODING_VERSION);
        buf.extend_from_slice(&(self.points.len() as u32).to_le_bytes());
        for sample in &self.points {
            buf.extend_from_slice(&sample.timestamp.to_le_bytes());
            buf.extend_from_slice(&encode_pct(sample.cpu_pct).to_le_bytes());
            buf.extend_from_slice(&encode_pct(sample.mem_pct).to_le_bytes());
            buf.extend_from_slice(&encode_pct(sample.disk_pct).to_le_bytes());
        }
        buf
    }

    fn from_slice(data: &[u8]) -> Self {
        if data.len() < 5 {
            warn!("history buffer corrompu (longueur insuffisante)");
            return Self::default();
        }
        if data[0] != ENCODING_VERSION {
            warn!(version = data[0], "version de buffer history inconnue");
            return Self::default();
        }
        let claimed = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
        let max_by_len = data.len().saturating_sub(5) / 14;
        let capped = claimed.min(HISTORY_MAX_ITEMS).min(max_by_len);
        let mut offset = 5;
        // Corrupted storage hardening: cap allocation and parse length.
        let mut points = Vec::with_capacity(capped);
        for _ in 0..capped {
            if data.len() < offset + 14 {
                warn!(
                    expected_bytes = 14,
                    remaining = data.len().saturating_sub(offset),
                    "history buffer tronqué, points ignorés"
                );
                break;
            }
            let ts_bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
            offset += 8;
            let cpu = decode_pct(u16::from_le_bytes(
                data[offset..offset + 2].try_into().unwrap(),
            ));
            offset += 2;
            let mem = decode_pct(u16::from_le_bytes(
                data[offset..offset + 2].try_into().unwrap(),
            ));
            offset += 2;
            let disk = decode_pct(u16::from_le_bytes(
                data[offset..offset + 2].try_into().unwrap(),
            ));
            offset += 2;
            points.push(HistorySample {
                timestamp: u64::from_le_bytes(ts_bytes),
                cpu_pct: cpu,
                mem_pct: mem,
                disk_pct: disk,
            });
        }
        Self { points }
    }

    fn into_points(self) -> Vec<HistorySample> {
        self.points
    }
}

fn encode_pct(value: Option<f32>) -> u16 {
    match value {
        Some(v) => {
            let clamped = v.clamp(0.0, 100.0);
            let scaled = (clamped * 100.0).round();
            scaled.min((NO_VALUE - 1) as f32) as u16
        }
        None => NO_VALUE,
    }
}

fn decode_pct(raw: u16) -> Option<f32> {
    if raw == NO_VALUE {
        None
    } else {
        Some((raw as f32) / 100.0)
    }
}

fn map_db_err(err: redb::Error) -> DescribeError {
    DescribeError::System(format!("history db error: {err}"))
}

fn map_storage_err(err: redb::StorageError) -> DescribeError {
    DescribeError::System(format!("history storage error: {err}"))
}

fn map_table_err(err: TableError) -> DescribeError {
    DescribeError::System(format!("history table error: {err}"))
}

fn history_db_path() -> PathBuf {
    let metadata_path = metadata_db_path();
    match metadata_path.parent() {
        Some(dir) => dir.join(HISTORY_DB_FILE),
        None => metadata_path.with_file_name(HISTORY_DB_FILE),
    }
}

pub(crate) fn history_identity_path() -> PathBuf {
    let metadata_path = metadata_db_path();
    match metadata_path.parent() {
        Some(dir) => dir.join(SERVER_ID_FILE),
        None => metadata_path.with_file_name(SERVER_ID_FILE),
    }
}

pub(crate) fn generate_identity_string() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub(crate) fn load_or_create_identity() -> Result<String, DescribeError> {
    let path = history_identity_path();
    if let Some(parent) = path.parent() {
        ensure_not_symlink(parent, "répertoire histoire")?;
        fs::create_dir_all(parent).map_err(map_io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    ensure_not_symlink(&path, "fichier identity")?;
    if let Some(existing) = read_identity(&path)? {
        return Ok(existing);
    }

    let id = generate_identity_string();

    match write_identity(&path, &id, true) {
        Ok(()) => Ok(id),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            // Lost the race: re-read the value written by the winner.
            if let Some(existing) = read_identity_with_retry(&path)? {
                return Ok(existing);
            }
            // Invalid existing value: rewrite with a fresh ID.
            write_identity(&path, &id, false).map_err(map_io_err)?;
            Ok(id)
        }
        Err(err) => Err(map_io_err(err)),
    }
}

fn read_identity(path: &PathBuf) -> Result<Option<String>, DescribeError> {
    match fs::read_to_string(path) {
        Ok(existing) => match validate_identity(existing.trim()) {
            Ok(id) => Ok(Some(id)),
            Err(reason) => {
                warn!(%reason, path=%path.display(), "history identity invalid, regenerating");
                Ok(None)
            }
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(map_io_err(err)),
    }
}

fn read_identity_with_retry(path: &PathBuf) -> Result<Option<String>, DescribeError> {
    for _ in 0..3 {
        if let Some(id) = read_identity(path)? {
            return Ok(Some(id));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Ok(None)
}

fn ensure_not_symlink(path: &Path, context: &str) -> Result<(), DescribeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(map_io_err(io::Error::other(format!(
            "{context} ne doit pas être un lien symbolique: {}",
            path.display()
        )))),
        _ => Ok(()),
    }
}

fn write_identity(path: &PathBuf, id: &str, create_new: bool) -> Result<(), io::Error> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut file = opts.open(path)?;
    file.write_all(id.as_bytes())?;
    let _ = file.sync_all();
    Ok(())
}

fn validate_identity(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("identity vide".into());
    }
    if raw.len() != 32 {
        return Err("identity doit faire 32 caractères hex".into());
    }
    if !raw.is_ascii() {
        return Err("identity doit être ASCII".into());
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("identity doit être hexadécimal".into());
    }
    Ok(raw.to_ascii_lowercase())
}

fn map_io_err(err: io::Error) -> DescribeError {
    DescribeError::System(format!("history identity error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::storage::{clear_state_dir_override_for_tests, state_dir_test_lock};
    use std::env;
    use tempfile::tempdir;

    #[test]
    fn buffer_roundtrips_points() {
        let mut buffer = HistoryBuffer::default();
        buffer.push(
            HistorySample {
                timestamp: 42,
                cpu_pct: Some(12.5),
                mem_pct: None,
                disk_pct: Some(80.0),
            },
            10,
        );
        buffer.push(
            HistorySample {
                timestamp: 43,
                cpu_pct: Some(55.0),
                mem_pct: Some(22.4),
                disk_pct: Some(0.0),
            },
            10,
        );

        let encoded = buffer.encode();
        let decoded = HistoryBuffer::from_slice(&encoded);
        assert_eq!(decoded.points.len(), 2);
        assert_eq!(decoded.points[0].timestamp, 42);
        assert_eq!(decoded.points[0].cpu_pct, Some(12.5));
        assert_eq!(decoded.points[0].mem_pct, None);
        assert_eq!(decoded.points[0].disk_pct, Some(80.0));
        assert_eq!(decoded.points[1].cpu_pct, Some(55.0));
    }

    #[test]
    fn buffer_caps_allocation_on_corrupted_count() {
        let mut data = Vec::new();
        data.push(ENCODING_VERSION);
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        let decoded = HistoryBuffer::from_slice(&data);
        assert!(decoded.points.is_empty());
        assert!(decoded.points.capacity() <= HISTORY_MAX_ITEMS);
    }

    #[test]
    fn buffer_parses_with_capped_count() {
        let mut buffer = HistoryBuffer::default();
        buffer.push(
            HistorySample {
                timestamp: 1,
                cpu_pct: Some(10.0),
                mem_pct: None,
                disk_pct: Some(20.0),
            },
            4,
        );
        let mut encoded = buffer.encode();
        encoded[1..5].copy_from_slice(&(u32::MAX).to_le_bytes());
        let decoded = HistoryBuffer::from_slice(&encoded);
        assert_eq!(decoded.points.len(), 1);
        assert_eq!(decoded.points[0].timestamp, 1);
    }

    #[test]
    fn identity_creation_is_stable_under_race() {
        let _guard = state_dir_test_lock();
        let tmp = tempdir().expect("tmpdir");
        env::set_var("DESCRIBE_ME_STATE_DIR", tmp.path());

        let t1 = std::thread::spawn(|| load_or_create_identity().expect("id1"));
        let t2 = std::thread::spawn(|| load_or_create_identity().expect("id2"));

        let id1 = t1.join().expect("join1");
        let id2 = t2.join().expect("join2");
        assert_eq!(id1, id2);

        clear_state_dir_override_for_tests();
        env::remove_var("DESCRIBE_ME_STATE_DIR");
    }

    #[test]
    fn invalid_identity_is_regenerated() {
        let _guard = state_dir_test_lock();
        let tmp = tempdir().expect("tmpdir");
        env::set_var("DESCRIBE_ME_STATE_DIR", tmp.path());

        let path = history_identity_path();
        fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        fs::write(&path, "not-hex").expect("write invalid identity");

        let id = load_or_create_identity().expect("regen");
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        clear_state_dir_override_for_tests();
        env::remove_var("DESCRIBE_ME_STATE_DIR");
    }
}
