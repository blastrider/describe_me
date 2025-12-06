use std::{borrow::Cow, time::Duration};

use axum::http::StatusCode;

use crate::{
    application::{
        history::{self, HistoryQueryError},
        logging::LogEvent,
        logs::{self, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES},
        metrics::render_prometheus_metrics,
    },
    domain::HostLogsPage,
};

use super::{error::WebError, state::AppState};

#[derive(serde::Serialize)]
pub struct HistoryMetricResponse {
    pub avg: Option<f32>,
    pub min: Option<f32>,
    pub max: Option<f32>,
}

#[derive(serde::Serialize)]
pub struct HistoryPointResponse {
    pub ts: u64,
    pub span_seconds: u64,
    pub cpu: HistoryMetricResponse,
    pub mem: HistoryMetricResponse,
    pub disk: HistoryMetricResponse,
}

#[derive(serde::Serialize)]
pub struct HistoryResponse {
    pub server_id: String,
    pub window_seconds: u64,
    pub bucket_seconds: u64,
    pub truncated: bool,
    pub aggregated: bool,
    pub points: Vec<HistoryPointResponse>,
}

#[derive(Clone)]
pub struct HistoryQueryParams {
    pub server: Option<String>,
    pub window: Option<u64>,
    pub limit: Option<usize>,
    pub ip: String,
    pub token: String,
}

#[derive(Clone)]
pub struct LogsQueryParams {
    pub lines: Option<usize>,
}

pub async fn build_history_series_response(
    state: &AppState,
    params: HistoryQueryParams,
) -> Result<HistoryResponse, WebError> {
    if state.exposure().redacted {
        return Err(WebError::forbidden(
            "L'historique est masqué lorsque l'exposition est redacted.",
        ));
    }

    let settings = state.ctx().history().settings_snapshot();
    if !settings.is_active() {
        return Err(WebError::service_unavailable(
            "L'historique n'est pas activé sur cette instance.",
        ));
    }

    if settings.paranoid_mode {
        return Err(WebError::forbidden(
            "Mode paranoïaque actif : l'historique n'est consultable que depuis la CLI locale.",
        ));
    }

    let requested_server = if let Some(id) = params.server.clone() {
        id
    } else if let Some(default_id) = state.ctx().history().default_server_id() {
        default_id
    } else {
        return Err(WebError::not_found(
            "Aucune donnée historique disponible pour ce serveur.",
        ));
    };

    let max_window_secs = settings.max_window_seconds.max(1) as u64;
    let requested_window = params.window.filter(|v| *v > 0).unwrap_or(max_window_secs);
    let window_secs = requested_window.min(max_window_secs);
    let retention_cap = settings.retention_points.max(16) as usize;
    let default_limit = retention_cap.min(256);
    let limit = params
        .limit
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
        .min(retention_cap);

    let rounding = settings.rounding_seconds.max(1);
    let series = match state.ctx().history().query_series(
        &requested_server,
        Duration::from_secs(window_secs),
        limit,
        rounding,
    ) {
        Ok(series) => series,
        Err(HistoryQueryError::Disabled) => {
            return Err(WebError::service_unavailable(
                "L'historique n'est pas actif sur cette instance.",
            ))
        }
        Err(HistoryQueryError::InvalidLimit | HistoryQueryError::InvalidServer) => {
            return Err(WebError::bad_request("Paramètres history invalides."))
        }
        Err(HistoryQueryError::NotFound) => {
            return Err(WebError::not_found(
                "Aucune donnée historique disponible pour ce serveur.",
            ))
        }
        Err(HistoryQueryError::Storage(err)) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("history_query"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            return Err(WebError::internal(
                "Lecture de l'historique impossible pour le moment.",
            ));
        }
    };

    let allow_disk = state.exposure().disk_partitions();
    let points = series
        .points
        .into_iter()
        .map(|point| HistoryPointResponse {
            ts: point.timestamp,
            span_seconds: point.span_seconds,
            cpu: to_metric_response(&point.cpu, true),
            mem: to_metric_response(&point.mem, true),
            disk: to_metric_response(&point.disk, allow_disk),
        })
        .collect::<Vec<_>>();

    LogEvent::HistoryQuery {
        ip: Cow::Owned(params.ip.clone()),
        token: Cow::Owned(params.token.clone()),
        server: Cow::Owned(series.server_id.clone()),
        points: points.len() as u32,
        window_seconds: series.window_seconds,
        truncated: series.truncated,
    }
    .emit();

    Ok(HistoryResponse {
        server_id: series.server_id,
        window_seconds: series.window_seconds,
        bucket_seconds: series.bucket_seconds,
        truncated: series.truncated,
        aggregated: series.aggregated,
        points,
    })
}

pub fn build_metrics_text(
    view: &crate::application::exposure::SnapshotView,
    age_secs: u64,
) -> String {
    render_prometheus_metrics(view, age_secs)
}

pub async fn build_host_logs_response(params: LogsQueryParams) -> Result<HostLogsPage, WebError> {
    let requested = params
        .lines
        .unwrap_or(HOST_LOGS_DEFAULT_LINES)
        .clamp(1, HOST_LOGS_MAX_LINES);

    let logs = tokio::task::spawn_blocking(move || logs::tail_host_logs(requested)).await;

    match logs {
        Ok(Ok(page)) => Ok(page),
        Ok(Err(err)) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("logs_read"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            Err(WebError::new(
                StatusCode::BAD_GATEWAY,
                format!("Impossible de lire les logs journald: {err}"),
            ))
        }
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("logs_join"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            Err(WebError::internal(
                "Erreur interne lors de la lecture des logs.",
            ))
        }
    }
}

fn to_metric_response(metric: &history::MetricAggregate, allow: bool) -> HistoryMetricResponse {
    if allow {
        HistoryMetricResponse {
            avg: metric.avg,
            min: metric.min,
            max: metric.max,
        }
    } else {
        HistoryMetricResponse {
            avg: None,
            min: None,
            max: None,
        }
    }
}
