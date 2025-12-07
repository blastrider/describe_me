use crate::application::history::HistoryBackend;
use crate::application::sync::lock_expect;
use crate::domain::DescribeError;
use crate::infrastructure::storage::metadata_db_path;
use fastrand;
use redb::{Database, ReadableTable, TableDefinition, TableError};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

const HISTORY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("history_samples");
const HISTORY_DB_FILE: &str = "history.redb";
const SERVER_ID_FILE: &str = "history.identity";
const ENCODING_VERSION: u8 = 1;
const NO_VALUE: u16 = u16::MAX;

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
            fs::create_dir_all(dir).map_err(|err| {
                DescribeError::System(format!(
                    "impossible de créer le répertoire histoire {}: {err}",
                    dir.display()
                ))
            })?;
        }
        let db = if path.exists() {
            Database::builder()
                .open(path.as_path())
                .map_err(|err| map_db_err(err.into()))?
        } else {
            Database::builder()
                .create(path.as_path())
                .map_err(|err| map_db_err(err.into()))?
        };
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
            return Self::default();
        }
        if data[0] != ENCODING_VERSION {
            return Self::default();
        }
        let count = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
        let mut offset = 5;
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < offset + 14 {
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

pub(crate) fn load_or_create_identity() -> Result<String, DescribeError> {
    let path = history_identity_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(map_io_err)?;
    }
    if let Ok(existing) = fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    let mut bytes = [0u8; 16];
    fastrand::fill(&mut bytes);
    let id = hex::encode(bytes);
    fs::write(&path, &id).map_err(map_io_err)?;
    Ok(id)
}

fn map_io_err(err: io::Error) -> DescribeError {
    DescribeError::System(format!("history identity error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
