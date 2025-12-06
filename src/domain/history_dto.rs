#[cfg(feature = "serde")]
use serde::Serialize;

use crate::application::history::{HistorySeries, MetricAggregate};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HistoryMetricDto {
    pub avg: Option<f32>,
    pub min: Option<f32>,
    pub max: Option<f32>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HistoryPointDto {
    pub ts: u64,
    pub span_seconds: u64,
    pub cpu: HistoryMetricDto,
    pub mem: HistoryMetricDto,
    pub disk: HistoryMetricDto,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HistorySeriesDto {
    pub server_id: String,
    pub window_seconds: u64,
    pub bucket_seconds: u64,
    pub truncated: bool,
    pub aggregated: bool,
    pub points: Vec<HistoryPointDto>,
}

impl HistorySeriesDto {
    pub fn from_series_with_filter(series: HistorySeries, allow_disk: bool) -> Self {
        let points = series
            .points
            .into_iter()
            .map(|point| HistoryPointDto {
                ts: point.timestamp,
                span_seconds: point.span_seconds,
                cpu: map_metric(&point.cpu, true),
                mem: map_metric(&point.mem, true),
                disk: map_metric(&point.disk, allow_disk),
            })
            .collect();

        HistorySeriesDto {
            server_id: series.server_id,
            window_seconds: series.window_seconds,
            bucket_seconds: series.bucket_seconds,
            truncated: series.truncated,
            aggregated: series.aggregated,
            points,
        }
    }
}

impl From<HistorySeries> for HistorySeriesDto {
    fn from(series: HistorySeries) -> Self {
        HistorySeriesDto::from_series_with_filter(series, true)
    }
}

fn map_metric(metric: &MetricAggregate, allow: bool) -> HistoryMetricDto {
    if allow {
        HistoryMetricDto {
            avg: metric.avg,
            min: metric.min,
            max: metric.max,
        }
    } else {
        HistoryMetricDto {
            avg: None,
            min: None,
            max: None,
        }
    }
}
