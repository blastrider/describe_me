mod backend;
mod service;

use crate::domain::{DescribeError, HistoryProfile, SystemSnapshot};
use crate::infrastructure::history::HistorySample;
pub(crate) use backend::HistoryBackend;
pub use service::HistoryService;
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_RETENTION_POINTS: u32 = 16;
const MAX_RETENTION_POINTS: u32 = 4096;

/// Configuration complète d'un profil d'historique (points, fenêtre, granularité, mode).
#[derive(Debug, Clone, Copy)]
pub struct HistoryProfileConfig {
    pub retention_points: u32,
    pub max_window_seconds: u32,
    pub rounding_seconds: u64,
    pub mode: HistoryMode,
}

const DEFAULT_RETENTION_POINTS: u32 = 120;
const DEFAULT_MAX_WINDOW_SECONDS: u32 = 3600;
const DEFAULT_ROUNDING_SECONDS: u64 = 60;
const OPS_RETENTION_POINTS: u32 = 720;
const PARANOID_RETENTION_POINTS: u32 = 60;
const PARANOID_MAX_WINDOW_SECONDS: u32 = 900;
const PARANOID_ROUNDING_SECONDS: u64 = 120;

/// Source unique des paramètres par profil :
/// - `Default` : 120 points sur 1h, stockage persistant.
/// - `Ops` : 720 points sur 1h, stockage persistant.
/// - `Paranoid` : 60 points sur 15 min, stockage mémoire uniquement.
pub fn profile_config(profile: HistoryProfile) -> HistoryProfileConfig {
    let (retention_points, max_window_seconds, rounding_seconds, mode) = match profile {
        HistoryProfile::Default => (
            DEFAULT_RETENTION_POINTS,
            DEFAULT_MAX_WINDOW_SECONDS,
            DEFAULT_ROUNDING_SECONDS,
            HistoryMode::Persistent,
        ),
        HistoryProfile::Ops => (
            OPS_RETENTION_POINTS,
            DEFAULT_MAX_WINDOW_SECONDS,
            DEFAULT_ROUNDING_SECONDS,
            HistoryMode::Persistent,
        ),
        HistoryProfile::Paranoid => (
            PARANOID_RETENTION_POINTS,
            PARANOID_MAX_WINDOW_SECONDS,
            PARANOID_ROUNDING_SECONDS,
            HistoryMode::InMemory,
        ),
    };

    HistoryProfileConfig {
        retention_points: retention_points.clamp(MIN_RETENTION_POINTS, MAX_RETENTION_POINTS),
        max_window_seconds,
        rounding_seconds,
        mode,
    }
}

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
            max_window_seconds: PARANOID_MAX_WINDOW_SECONDS,
            rounding_seconds: DEFAULT_ROUNDING_SECONDS,
            mode: HistoryMode::Disabled,
            paranoid_mode: false,
        }
    }

    pub fn for_profile(profile: HistoryProfile) -> Self {
        let paranoid_mode = matches!(profile, HistoryProfile::Paranoid);
        let cfg = profile_config(profile);
        Self {
            enabled: true,
            profile,
            retention_points: cfg.retention_points,
            max_window_seconds: cfg.max_window_seconds,
            rounding_seconds: cfg.rounding_seconds,
            mode: cfg.mode,
            paranoid_mode,
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
        if !(MIN_RETENTION_POINTS..=MAX_RETENTION_POINTS).contains(&points) {
            tracing::warn!(
                "history.retention_points={} hors bornes [{}, {}], valeur clampée",
                points,
                MIN_RETENTION_POINTS,
                MAX_RETENTION_POINTS
            );
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

pub(crate) fn build_sample(snapshot: &SystemSnapshot) -> Option<HistorySample> {
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

pub(crate) fn round_timestamp(ts: u64, precision_secs: u64) -> u64 {
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

pub(crate) fn downsample_points(
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
