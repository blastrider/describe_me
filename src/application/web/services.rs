use std::{borrow::Cow, time::Duration};

use axum::http::StatusCode;

use crate::{
    application::{
        history::HistoryQueryError,
        logging::LogEvent,
        logs::{self, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES},
        metrics::render_prometheus_metrics_with_state,
    },
    domain::{DescribeError, HistorySeriesDto, HostLogsPage},
};

use super::{error::WebError, state::AppState};

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
) -> Result<HistorySeriesDto, WebError> {
    enum HistoryFetchError {
        Disabled,
        Paranoid,
        InvalidLimit,
        InvalidServer,
        NotFound,
        Storage(DescribeError),
        Identity(DescribeError),
    }

    let HistoryQueryParams {
        server,
        window,
        limit,
        ip,
        token,
    } = params;
    if state.exposure().redacted {
        return Err(WebError::forbidden(
            "L'historique est masqué lorsque l'exposition est redacted.",
        ));
    }

    let history = state.ctx().history().clone();
    let series = tokio::task::spawn_blocking(move || {
        let settings = history.settings_snapshot();
        if !settings.is_active() {
            return Err(HistoryFetchError::Disabled);
        }
        if settings.paranoid_mode {
            return Err(HistoryFetchError::Paranoid);
        }

        let requested_server = match server {
            Some(id) => id,
            None => history
                .default_server_id()
                .map_err(HistoryFetchError::Identity)?,
        };

        let max_window_secs = settings.max_window_seconds.max(1) as u64;
        let requested_window = window.filter(|v| *v > 0).unwrap_or(max_window_secs);
        let window_secs = requested_window.min(max_window_secs);
        let retention_cap = settings.retention_points.max(16) as usize;
        let default_limit = retention_cap.min(256);
        let limit = limit
            .filter(|v| *v > 0)
            .unwrap_or(default_limit)
            .min(retention_cap);

        let rounding = settings.rounding_seconds.max(1);
        history
            .query_series(
                &requested_server,
                Duration::from_secs(window_secs),
                limit,
                rounding,
            )
            .map_err(|err| match err {
                HistoryQueryError::Disabled => HistoryFetchError::Disabled,
                HistoryQueryError::InvalidLimit => HistoryFetchError::InvalidLimit,
                HistoryQueryError::InvalidServer => HistoryFetchError::InvalidServer,
                HistoryQueryError::NotFound => HistoryFetchError::NotFound,
                HistoryQueryError::Storage(err) => HistoryFetchError::Storage(err),
            })
    })
    .await;

    let series =
        match series {
            Ok(Ok(series)) => series,
            Ok(Err(HistoryFetchError::Disabled)) => {
                return Err(WebError::service_unavailable(
                    "L'historique n'est pas activé sur cette instance.",
                ))
            }
            Ok(Err(HistoryFetchError::Paranoid)) => return Err(WebError::forbidden(
                "Mode paranoïaque actif : l'historique n'est consultable que depuis la CLI locale.",
            )),
            Ok(Err(HistoryFetchError::InvalidLimit | HistoryFetchError::InvalidServer)) => {
                return Err(WebError::bad_request("Paramètres history invalides."))
            }
            Ok(Err(HistoryFetchError::NotFound)) => {
                return Err(WebError::not_found(
                    "Aucune donnée historique disponible pour ce serveur.",
                ))
            }
            Ok(Err(HistoryFetchError::Storage(err))) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("history_query"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
                return Err(WebError::internal(
                    "Lecture de l'historique impossible pour le moment.",
                ));
            }
            Ok(Err(HistoryFetchError::Identity(err))) => {
                return Err(WebError::service_unavailable(format!(
                    "Impossible de récupérer l'identité du serveur: {err}"
                )))
            }
            Err(err) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("history_query_task"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
                return Err(WebError::internal(
                    "Lecture de l'historique impossible pour le moment.",
                ));
            }
        };

    let allow_disk = state.exposure().disk_partitions();
    let point_count = series.points.len() as u32;
    let window_seconds = series.window_seconds;
    let truncated = series.truncated;
    let dto = HistorySeriesDto::from_series_with_filter(series, allow_disk);

    LogEvent::HistoryQuery {
        ip: Cow::Owned(ip),
        token: Cow::Owned(token),
        server: Cow::Borrowed(dto.server_id.as_str()),
        points: point_count,
        window_seconds,
        truncated,
    }
    .emit();

    Ok(dto)
}

pub fn build_metrics_text(
    view: &crate::application::exposure::SnapshotView,
    age_secs: u64,
    metrics_state: &crate::application::metrics::ExtensionMetricsState,
) -> String {
    render_prometheus_metrics_with_state(view, age_secs, Some(metrics_state))
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
                "Impossible de lire les logs hôte.".to_string(),
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
