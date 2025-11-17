use crate::application::logging::LogEvent;
use crate::domain::{DescribeError, HistoryProfile, SystemSnapshot};
use crate::infrastructure::history::{HistorySample, HistoryStorage};
use hex;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIN_RETENTION_POINTS: u32 = 16;
const MAX_RETENTION_POINTS: u32 = 4096;
static SERVER_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct HistorySettings {
    pub enabled: bool,
    pub profile: HistoryProfile,
    pub retention_points: u32,
    pub max_window_seconds: u32,
    pub rounding_seconds: u64,
    pub mode: HistoryMode,
    pub paranoid_mode: bool,
}

impl HistorySettings {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            profile: HistoryProfile::Default,
            retention_points: 0,
            max_window_seconds: 900,
            rounding_seconds: 60,
            mode: HistoryMode::Disabled,
            paranoid_mode: false,
        }
    }

    pub fn for_profile(profile: HistoryProfile) -> Self {
        let paranoid_mode = matches!(profile, HistoryProfile::Paranoid);
        match profile {
            HistoryProfile::Default => Self {
                enabled: true,
                profile,
                retention_points: 120,
                max_window_seconds: 3600,
                rounding_seconds: 60,
                mode: HistoryMode::Persistent,
                paranoid_mode,
            },
            HistoryProfile::Ops => Self {
                enabled: true,
                profile,
                retention_points: 720,
                max_window_seconds: 3600,
                rounding_seconds: 60,
                mode: HistoryMode::Persistent,
                paranoid_mode,
            },
            HistoryProfile::Paranoid => Self {
                enabled: true,
                profile,
                retention_points: 60,
                max_window_seconds: 900,
                rounding_seconds: 120,
                mode: HistoryMode::InMemory,
                paranoid_mode,
            },
        }
    }

    pub fn is_active(&self) -> bool {
        self.enabled && self.retention_points > 0 && !matches!(self.mode, HistoryMode::Disabled)
    }

    pub fn set_retention_points(&mut self, points: u32) {
        if points == 0 {
            self.disable();
            return;
        }
        self.retention_points = points.clamp(MIN_RETENTION_POINTS, MAX_RETENTION_POINTS);
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        self.mode = HistoryMode::Disabled;
        self.retention_points = 0;
        self.paranoid_mode = false;
    }

    pub fn set_mode(&mut self, mode: HistoryMode) {
        self.mode = mode;
        if matches!(mode, HistoryMode::Disabled) {
            self.enabled = false;
            self.retention_points = 0;
        } else if self.enabled && self.retention_points == 0 {
            self.retention_points = MIN_RETENTION_POINTS;
        }
    }
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    Disabled,
    Persistent,
    InMemory,
}

struct HistoryContext {
    settings: HistorySettings,
    storage: Arc<HistoryStorage>,
}

impl HistoryContext {
    fn disabled() -> Self {
        Self {
            settings: HistorySettings::disabled(),
            storage: Arc::new(HistoryStorage::disabled()),
        }
    }
}

fn context() -> &'static RwLock<HistoryContext> {
    static CONTEXT: OnceLock<RwLock<HistoryContext>> = OnceLock::new();
    CONTEXT.get_or_init(|| RwLock::new(HistoryContext::disabled()))
}

pub fn configure_history(mut settings: HistorySettings) -> Result<(), DescribeError> {
    let storage = if settings.is_active() {
        match settings.mode {
            HistoryMode::Persistent => Arc::new(HistoryStorage::persistent()?),
            HistoryMode::InMemory => Arc::new(HistoryStorage::in_memory()),
            HistoryMode::Disabled => Arc::new(HistoryStorage::disabled()),
        }
    } else {
        settings.disable();
        Arc::new(HistoryStorage::disabled())
    };
    let mut guard = context().write().expect("history context poisoned");
    guard.settings = settings;
    guard.storage = storage;
    Ok(())
}

pub fn record_snapshot(snapshot: &SystemSnapshot) {
    let (settings, storage) = {
        let guard = context().read().expect("history context poisoned");
        if !guard.settings.is_active() {
            return;
        }
        (guard.settings.clone(), Arc::clone(&guard.storage))
    };

    let Some(sample) = build_sample(snapshot) else {
        return;
    };

    let server_id = resolve_server_id(&snapshot.hostname);
    remember_server_id(&server_id);
    if let Err(err) = storage.append(&server_id, &sample, settings.retention_points as usize) {
        LogEvent::SystemError {
            location: std::borrow::Cow::Borrowed("history_append"),
            error: std::borrow::Cow::Owned(err.to_string()),
        }
        .emit();
    }
}

fn build_sample(snapshot: &SystemSnapshot) -> Option<HistorySample> {
    let cpu_pct = estimate_cpu_pct(snapshot);
    let mem_pct = estimate_memory_pct(snapshot);
    let disk_pct = estimate_disk_pct(snapshot);
    if cpu_pct.is_none() && mem_pct.is_none() && disk_pct.is_none() {
        return None;
    }
    Some(HistorySample {
        timestamp: current_unix_seconds(),
        cpu_pct,
        mem_pct,
        disk_pct,
    })
}

fn estimate_cpu_pct(snapshot: &SystemSnapshot) -> Option<f32> {
    let cpu_count = snapshot.cpu_count.max(1) as f64;
    let la = snapshot.load_average.0;
    let ratio = (la / cpu_count).clamp(0.0, 1.0);
    Some((ratio * 100.0) as f32)
}

fn estimate_memory_pct(snapshot: &SystemSnapshot) -> Option<f32> {
    let total = snapshot.total_memory_bytes;
    if total == 0 {
        return None;
    }
    let used = snapshot.used_memory_bytes.min(total);
    Some(((used as f64 / total as f64) * 100.0) as f32)
}

fn estimate_disk_pct(snapshot: &SystemSnapshot) -> Option<f32> {
    let usage = snapshot.disk_usage.as_ref()?;
    if usage.total_bytes == 0 {
        return None;
    }
    let used = usage.used_bytes.min(usage.total_bytes);
    Some(((used as f64 / usage.total_bytes as f64) * 100.0) as f32)
}

fn resolve_server_id(hostname: &str) -> String {
    let normalized = hostname.trim().to_ascii_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let short = &digest[..16];
    format!("srv:{}", hex::encode(short))
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn remember_server_id(id: &str) {
    let _ = SERVER_ID.set(id.to_owned());
}

pub fn default_server_id() -> Option<String> {
    SERVER_ID.get().cloned()
}

pub fn settings_snapshot() -> HistorySettings {
    let guard = context().read().expect("history context poisoned");
    guard.settings.clone()
}

pub fn query_series(
    server_id: &str,
    requested_window: Duration,
    limit: usize,
    rounding_secs: u64,
) -> Result<HistorySeries, HistoryQueryError> {
    if server_id.trim().is_empty() {
        return Err(HistoryQueryError::InvalidServer);
    }
    if limit == 0 {
        return Err(HistoryQueryError::InvalidLimit);
    }
    let (settings, storage) = {
        let guard = context().read().expect("history context poisoned");
        (guard.settings.clone(), Arc::clone(&guard.storage))
    };
    if !settings.is_active() {
        return Err(HistoryQueryError::Disabled);
    }
    let max_window = Duration::from_secs(settings.max_window_seconds.max(1) as u64);
    let window = requested_window.max(Duration::from_secs(1)).min(max_window);
    let max_limit = settings.retention_points.max(MIN_RETENTION_POINTS) as usize;
    let limit = limit.min(max_limit);
    let samples = storage
        .read(server_id)
        .map_err(HistoryQueryError::Storage)?;
    if samples.is_empty() {
        return Err(HistoryQueryError::NotFound);
    }
    let latest_ts = samples.last().map(|s| s.timestamp).unwrap_or(0);
    let cutoff = latest_ts.saturating_sub(window.as_secs());
    let mut filtered: Vec<_> = samples
        .into_iter()
        .filter(|sample| sample.timestamp >= cutoff)
        .collect();
    if filtered.is_empty() {
        return Err(HistoryQueryError::NotFound);
    }
    let truncated = if filtered.len() > limit {
        let excess = filtered.len() - limit;
        filtered.drain(0..excess);
        true
    } else {
        false
    };
    let rounded = filtered
        .into_iter()
        .map(|sample| HistoryPoint {
            timestamp: round_timestamp(sample.timestamp, rounding_secs),
            cpu_pct: sample.cpu_pct,
            mem_pct: sample.mem_pct,
            disk_pct: sample.disk_pct,
        })
        .collect();
    Ok(HistorySeries {
        server_id: server_id.to_string(),
        points: rounded,
        truncated,
        window_seconds: window.as_secs(),
    })
}

fn round_timestamp(ts: u64, precision_secs: u64) -> u64 {
    if precision_secs <= 1 {
        return ts;
    }
    let bucket = precision_secs;
    let remainder = ts % bucket;
    ts - remainder
}

#[derive(Debug)]
pub struct HistorySeries {
    pub server_id: String,
    pub points: Vec<HistoryPoint>,
    pub truncated: bool,
    pub window_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct HistoryPoint {
    pub timestamp: u64,
    pub cpu_pct: Option<f32>,
    pub mem_pct: Option<f32>,
    pub disk_pct: Option<f32>,
}

#[derive(Debug)]
pub enum HistoryQueryError {
    Disabled,
    NotFound,
    InvalidLimit,
    InvalidServer,
    Storage(DescribeError),
}

impl From<DescribeError> for HistoryQueryError {
    fn from(err: DescribeError) -> Self {
        HistoryQueryError::Storage(err)
    }
}

#[cfg(test)]
mod tests {
    use super::round_timestamp;

    #[test]
    fn round_timestamp_aligns_floor() {
        assert_eq!(round_timestamp(0, 60), 0);
        assert_eq!(round_timestamp(59, 60), 0);
        assert_eq!(round_timestamp(60, 60), 60);
        assert_eq!(round_timestamp(125, 60), 120);
        assert_eq!(round_timestamp(120, 1), 120);
    }
}
