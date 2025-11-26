//! Gestionnaires HTTP pour l'interface Web et les structures de données
//! associées. Ce module est dédié à la logique par route afin de garder
//! `mod.rs` centré sur l'initialisation du serveur.

use std::{borrow::Cow, time::Duration};

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::{
        history::{self, HistoryQueryError},
        logging::LogEvent,
        logs::{self, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES},
        metadata::{
            add_server_tags, clear_server_tags, remove_server_tags, set_server_description,
            set_server_tags,
        },
    },
    domain::{ContainersSnapshot, DescribeError},
};

use super::{
    mark_response_no_store,
    security::AuthGuard,
    set_session_cookie,
    template::{render_index, render_logs_page, render_updates_page},
    AppState, CspNonce,
};

#[derive(Deserialize)]
pub(super) struct DescriptionPayload {
    text: String,
}

#[derive(Serialize)]
struct DescriptionResponse {
    description: String,
}

#[derive(Serialize)]
struct ApiErrorResponse {
    error: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum TagOperation {
    #[default]
    Set,
    Add,
    Remove,
    Clear,
}

#[derive(Deserialize)]
pub(super) struct TagsPayload {
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    op: TagOperation,
}

#[derive(Serialize)]
struct TagsResponse {
    tags: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct HistoryRequestQuery {
    server: Option<String>,
    window: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct LogsRequestQuery {
    lines: Option<usize>,
}

#[derive(Serialize)]
struct HistoryMetricResponse {
    avg: Option<f32>,
    min: Option<f32>,
    max: Option<f32>,
}

#[derive(Serialize)]
struct HistoryPointResponse {
    ts: u64,
    span_seconds: u64,
    cpu: HistoryMetricResponse,
    mem: HistoryMetricResponse,
    disk: HistoryMetricResponse,
}

#[derive(Serialize)]
struct HistoryResponse {
    server_id: String,
    window_seconds: u64,
    bucket_seconds: u64,
    truncated: bool,
    aggregated: bool,
    points: Vec<HistoryPointResponse>,
}

#[derive(Serialize)]
struct ContainersApiResponse {
    age_ms: u64,
    containers: ContainersSnapshot,
}

pub(super) async fn logo_asset(State(state): State<AppState>) -> Response {
    state.logo.response()
}

pub(super) async fn index(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let mut response = Html(render_index(state.web_debug, csp_nonce.as_str())).into_response();
    if let Some(token) = session.session_cookie() {
        set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
    }
    mark_response_no_store(response.headers_mut());
    response
}

pub(super) async fn updates_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let cookie_token = session.session_cookie().map(str::to_owned);

    if !state.exposure.updates() {
        let message = "L'exposition des mises à jour est désactivée pour cette instance.";
        let html = render_updates_page(None, Some(message), csp_nonce.as_str());
        let mut response = Html(html).into_response();
        if let Some(token) = cookie_token.as_deref() {
            set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
        }
        return response;
    }

    state.updates_cache.ensure_fresh().await;
    let updates = match state.updates_cache.peek().await {
        Some(info) => Some(info),
        None => state.updates_cache.refresh_blocking().await,
    };

    let html = render_updates_page(updates.as_ref(), None, csp_nonce.as_str());
    let mut response = Html(html).into_response();
    if let Some(token) = cookie_token.as_deref() {
        set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
    }
    response
}

pub(super) async fn update_description(
    _guard: AuthGuard,
    Json(payload): Json<DescriptionPayload>,
) -> impl IntoResponse {
    let text = match normalize_description(&payload.text) {
        Ok(value) => value,
        Err(msg) => return json_error(StatusCode::BAD_REQUEST, msg),
    };

    if let Err(err) = set_server_description(&text) {
        LogEvent::SystemError {
            location: Cow::Borrowed("web_description_update"),
            error: Cow::Owned(err.to_string()),
        }
        .emit();
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Impossible d'enregistrer la description.",
        );
    }

    (
        StatusCode::OK,
        Json(DescriptionResponse { description: text }),
    )
        .into_response()
}

pub(super) async fn update_tags(
    _guard: AuthGuard,
    Json(payload): Json<TagsPayload>,
) -> impl IntoResponse {
    if let Some(error) = validate_tags_payload(&payload) {
        return json_error(StatusCode::BAD_REQUEST, error);
    }

    let tags = payload
        .tags
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .take(super::TAGS_MAX_PER_REQUEST)
        .collect::<Vec<_>>();

    let op = payload.op;
    let result = match op {
        TagOperation::Set => set_server_tags(tags.iter().map(|s| s.as_str())),
        TagOperation::Add => add_server_tags(tags.iter().map(|s| s.as_str())),
        TagOperation::Remove => remove_server_tags(tags.iter().map(|s| s.as_str())),
        TagOperation::Clear => clear_server_tags().map(|_| Vec::new()),
    };

    match result {
        Ok(list) => (StatusCode::OK, Json(TagsResponse { tags: list.clone() })).into_response(),
        Err(DescribeError::System(msg)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, msg),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

pub(super) async fn history_series(
    State(state): State<AppState>,
    guard: AuthGuard,
    Query(query): Query<HistoryRequestQuery>,
) -> impl IntoResponse {
    if state.exposure.redacted {
        return json_error(
            StatusCode::FORBIDDEN,
            "L'historique est masqué lorsque l'exposition est redacted.",
        );
    }

    let settings = history::settings_snapshot();
    if !settings.is_active() {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "L'historique n'est pas activé sur cette instance.",
        );
    }

    if settings.paranoid_mode {
        return json_error(
            StatusCode::FORBIDDEN,
            "Mode paranoïaque actif : l'historique n'est consultable que depuis la CLI locale.",
        );
    }

    let requested_server = if let Some(id) = query.server.clone() {
        id
    } else if let Some(default_id) = history::default_server_id() {
        default_id
    } else {
        return json_error(
            StatusCode::NOT_FOUND,
            "Aucune donnée historique disponible pour ce serveur.",
        );
    };

    let session = guard.into_session();
    let cookie_token = session.session_cookie().map(str::to_owned);

    let max_window_secs = settings.max_window_seconds.max(1) as u64;
    let requested_window = query.window.filter(|v| *v > 0).unwrap_or(max_window_secs);
    let window_secs = requested_window.min(max_window_secs);
    let retention_cap = settings.retention_points.max(16) as usize;
    let default_limit = retention_cap.min(256);
    let limit = query
        .limit
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
        .min(retention_cap);

    let rounding = settings.rounding_seconds.max(1);
    let series = match history::query_series(
        &requested_server,
        Duration::from_secs(window_secs),
        limit,
        rounding,
    ) {
        Ok(series) => series,
        Err(HistoryQueryError::Disabled) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "L'historique n'est pas actif sur cette instance.",
            )
        }
        Err(HistoryQueryError::InvalidLimit | HistoryQueryError::InvalidServer) => {
            return json_error(StatusCode::BAD_REQUEST, "Paramètres history invalides.")
        }
        Err(HistoryQueryError::NotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "Aucune donnée historique disponible pour ce serveur.",
            )
        }
        Err(HistoryQueryError::Storage(err)) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("history_query"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Lecture de l'historique impossible pour le moment.",
            );
        }
    };

    let allow_disk = state.exposure.disk_partitions();
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
        ip: Cow::Owned(session.ip().to_string()),
        token: Cow::Owned(session.token_key().to_string()),
        server: Cow::Owned(series.server_id.clone()),
        points: points.len() as u32,
        window_seconds: series.window_seconds,
        truncated: series.truncated,
    }
    .emit();

    let payload = HistoryResponse {
        server_id: series.server_id,
        window_seconds: series.window_seconds,
        bucket_seconds: series.bucket_seconds,
        truncated: series.truncated,
        aggregated: series.aggregated,
        points,
    };

    let mut response = Json(payload).into_response();
    if let Some(token) = cookie_token.as_deref() {
        set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
    }
    response
}

pub(super) async fn containers_api(
    State(state): State<AppState>,
    _guard: AuthGuard,
) -> impl IntoResponse {
    let cached = match state.latest_snapshot() {
        Some(value) => value,
        None => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Aucun snapshot disponible pour le moment.",
            )
        }
    };

    let Some(containers) = cached.view.containers else {
        return json_error(
            StatusCode::FORBIDDEN,
            "Les conteneurs ne sont pas exposés ou non capturés.",
        );
    };

    let age_ms = cached
        .captured_at
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;

    (
        StatusCode::OK,
        Json(ContainersApiResponse { age_ms, containers }),
    )
        .into_response()
}

pub(super) async fn logs_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let mut response = Html(render_logs_page(csp_nonce.as_str())).into_response();
    if let Some(token) = session.session_cookie() {
        set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
    }
    mark_response_no_store(response.headers_mut());
    response
}

pub(super) async fn host_logs(
    State(state): State<AppState>,
    guard: AuthGuard,
    Query(query): Query<LogsRequestQuery>,
) -> impl IntoResponse {
    let requested = query
        .lines
        .unwrap_or(HOST_LOGS_DEFAULT_LINES)
        .clamp(1, HOST_LOGS_MAX_LINES);

    let logs = tokio::task::spawn_blocking(move || logs::tail_host_logs(requested)).await;

    match logs {
        Ok(Ok(page)) => {
            let session = guard.into_session();
            let mut response = Json(page).into_response();
            if let Some(token) = session.session_cookie() {
                set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
            }
            response
        }
        Ok(Err(err)) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("logs_read"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            json_error(
                StatusCode::BAD_GATEWAY,
                format!("Impossible de lire les logs journald: {err}"),
            )
        }
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("logs_join"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur interne lors de la lecture des logs.",
            )
        }
    }
}

pub(super) fn normalize_description(input: &str) -> Result<String, &'static str> {
    let sanitized = {
        let crlf_folded = input.replace("\r\n", "\n");
        crlf_folded.replace('\r', "\n")
    };
    if sanitized.len() > super::DESCRIPTION_MAX_BYTES {
        return Err("La description ne peut pas dépasser 2048 caractères.");
    }
    Ok(sanitized)
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn validate_tags_payload(payload: &TagsPayload) -> Option<&'static str> {
    match payload.op {
        TagOperation::Clear => None,
        _ => {
            if payload.tags.is_empty() {
                return Some("Merci de fournir au moins un tag.");
            }
            if payload.tags.len() > super::TAGS_MAX_PER_REQUEST {
                return Some("Trop de tags fournis.");
            }
            if payload
                .tags
                .iter()
                .any(|tag| tag.chars().count() > super::TAG_LENGTH_LIMIT)
            {
                return Some("Un tag dépasse la longueur maximale autorisée.");
            }
            None
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
