use crate::application::logging::LogEvent;
use crate::domain::{DescribeError, HistoryProfile, SystemSnapshot};
use crate::infrastructure::history::{self, HistorySample, HistoryStorage};
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

    let server_id = match server_identity() {
        Ok(id) => id.clone(),
        Err(err) => {
            LogEvent::SystemError {
                location: std::borrow::Cow::Borrowed("history_identity"),
                error: std::borrow::Cow::Owned(err.to_string()),
            }
            .emit();
            return;
        }
    };
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

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn server_identity() -> Result<&'static String, DescribeError> {
    if let Some(id) = SERVER_ID.get() {
        return Ok(id);
    }
    let created = history::load_or_create_identity()?;
    Ok(SERVER_ID.get_or_init(|| created))
}

pub fn default_server_id() -> Option<String> {
    server_identity().ok().cloned()
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
    let window_secs = window.as_secs();
    let max_limit = settings.retention_points.max(MIN_RETENTION_POINTS) as usize;
    let limit = limit.min(max_limit);
    let samples = storage
        .read(server_id)
        .map_err(HistoryQueryError::Storage)?;
    if samples.is_empty() {
        return Err(HistoryQueryError::NotFound);
    }
    let latest_ts = samples.last().map(|s| s.timestamp).unwrap_or(0);
    let cutoff = latest_ts.saturating_sub(window_secs);
    let mut filtered: Vec<_> = samples
        .into_iter()
        .filter(|sample| sample.timestamp >= cutoff)
        .collect();
    if filtered.is_empty() {
        return Err(HistoryQueryError::NotFound);
    }
    let mut truncated = false;
    let mut bucket_seconds = rounding_secs.max(1);
    let mut aggregated = false;
    let downsample_threshold = (settings.max_window_seconds.max(1) as u64 / 4).max(1);
    let should_downsample = window_secs > downsample_threshold;
    let points = if should_downsample {
        aggregated = true;
        let desired_buckets = limit.max(1) as u64;
        bucket_seconds = (window_secs / desired_buckets).max(1);
        truncated = filtered.len() > limit;
        downsample_points(&filtered, cutoff, bucket_seconds)
    } else {
        if filtered.len() > limit {
            let excess = filtered.len() - limit;
            filtered.drain(0..excess);
            truncated = true;
        }
        filtered
            .into_iter()
            .map(|sample| HistoryPoint {
                timestamp: round_timestamp(sample.timestamp, bucket_seconds),
                span_seconds: bucket_seconds,
                cpu: MetricAggregate::from_value(sample.cpu_pct),
                mem: MetricAggregate::from_value(sample.mem_pct),
                disk: MetricAggregate::from_value(sample.disk_pct),
            })
            .collect()
    };
    Ok(HistorySeries {
        server_id: server_id.to_string(),
        points,
        truncated,
        window_seconds: window_secs,
        bucket_seconds,
        aggregated,
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
    pub bucket_seconds: u64,
    pub aggregated: bool,
}

#[derive(Debug, Clone)]
pub struct HistoryPoint {
    pub timestamp: u64,
    pub span_seconds: u64,
    pub cpu: MetricAggregate,
    pub mem: MetricAggregate,
    pub disk: MetricAggregate,
}

#[derive(Debug, Clone, Default)]
pub struct MetricAggregate {
    pub avg: Option<f32>,
    pub min: Option<f32>,
    pub max: Option<f32>,
}

impl MetricAggregate {
    fn from_value(value: Option<f32>) -> Self {
        match value {
            Some(v) => Self {
                avg: Some(v),
                min: Some(v),
                max: Some(v),
            },
            None => Self::default(),
        }
    }
}

fn downsample_points(
    samples: &[HistorySample],
    cutoff: u64,
    bucket_seconds: u64,
) -> Vec<HistoryPoint> {
    if bucket_seconds == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut current_idx: Option<u64> = None;
    let mut bucket = BucketAccum::default();
    for sample in samples {
        let idx = (sample.timestamp.saturating_sub(cutoff)) / bucket_seconds;
        if let Some(cur) = current_idx {
            if idx != cur {
                if let Some(point) = bucket.finalize(cutoff, cur, bucket_seconds) {
                    result.push(point);
                }
                bucket.clear();
                current_idx = Some(idx);
            }
        } else {
            current_idx = Some(idx);
        }
        bucket.add(sample);
    }
    if let Some(idx) = current_idx {
        if let Some(point) = bucket.finalize(cutoff, idx, bucket_seconds) {
            result.push(point);
        }
    }
    result
}

#[derive(Default)]
struct MetricStats {
    count: u32,
    sum: f64,
    min: f32,
    max: f32,
}

impl MetricStats {
    fn add(&mut self, value: f32) {
        if self.count == 0 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.count = self.count.saturating_add(1);
        self.sum += value as f64;
    }

    fn aggregate(&self) -> MetricAggregate {
        if self.count == 0 {
            MetricAggregate::default()
        } else {
            let avg = (self.sum / f64::from(self.count)) as f32;
            MetricAggregate {
                avg: Some(avg),
                min: Some(self.min),
                max: Some(self.max),
            }
        }
    }

    fn clear(&mut self) {
        self.count = 0;
        self.sum = 0.0;
        self.min = 0.0;
        self.max = 0.0;
    }
}

#[derive(Default)]
struct BucketAccum {
    cpu: MetricStats,
    mem: MetricStats,
    disk: MetricStats,
}

impl BucketAccum {
    fn add(&mut self, sample: &HistorySample) {
        if let Some(value) = sample.cpu_pct {
            self.cpu.add(value);
        }
        if let Some(value) = sample.mem_pct {
            self.mem.add(value);
        }
        if let Some(value) = sample.disk_pct {
            self.disk.add(value);
        }
    }

    fn clear(&mut self) {
        self.cpu.clear();
        self.mem.clear();
        self.disk.clear();
    }

    fn finalize(&self, cutoff: u64, idx: u64, span: u64) -> Option<HistoryPoint> {
        let cpu = self.cpu.aggregate();
        let mem = self.mem.aggregate();
        let disk = self.disk.aggregate();
        if cpu.avg.is_none() && mem.avg.is_none() && disk.avg.is_none() {
            return None;
        }
        Some(HistoryPoint {
            timestamp: cutoff + idx * span,
            span_seconds: span,
            cpu,
            mem,
            disk,
        })
    }
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
