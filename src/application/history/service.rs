use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use crate::application::logging::LogEvent;
use crate::domain::{DescribeError, SystemSnapshot};
use crate::infrastructure::history::{self, HistoryStorage};

use super::{
    build_sample, downsample_points, round_timestamp, HistoryMode, HistoryPoint, HistoryQueryError,
    HistorySeries, HistorySettings, MetricAggregate, MIN_RETENTION_POINTS,
};

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

#[derive(Clone)]
pub struct HistoryService {
    ctx: Arc<RwLock<HistoryContext>>,
    server_id: Arc<OnceLock<String>>,
}

impl HistoryService {
    pub fn new() -> Self {
        Self {
            ctx: Arc::new(RwLock::new(HistoryContext::disabled())),
            server_id: Arc::new(OnceLock::new()),
        }
    }

    pub fn configure(&self, mut settings: HistorySettings) -> Result<(), DescribeError> {
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
        let mut guard = self.ctx.write().expect("history context poisoned");
        guard.settings = settings;
        guard.storage = storage;
        Ok(())
    }

    pub fn record_snapshot(&self, snapshot: &SystemSnapshot) {
        let (settings, storage) = {
            let guard = self.ctx.read().expect("history context poisoned");
            if !guard.settings.is_active() {
                return;
            }
            (guard.settings.clone(), Arc::clone(&guard.storage))
        };

        let Some(sample) = build_sample(snapshot) else {
            return;
        };

        let server_id = match self.server_identity() {
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

    pub fn settings_snapshot(&self) -> HistorySettings {
        let guard = self.ctx.read().expect("history context poisoned");
        guard.settings.clone()
    }

    pub fn default_server_id(&self) -> Option<String> {
        self.server_identity().ok().cloned()
    }

    pub fn query_series(
        &self,
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
            let guard = self.ctx.read().expect("history context poisoned");
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

    fn server_identity(&self) -> Result<&String, DescribeError> {
        if let Some(id) = self.server_id.get() {
            return Ok(id);
        }
        let created = history::load_or_create_identity()?;
        Ok(self.server_id.get_or_init(|| created))
    }
}

impl Default for HistoryService {
    fn default() -> Self {
        Self::new()
    }
}
