//! Gestionnaires HTTP pour l'interface Web et les structures de données associées.
//! Ce module se limite au routage/parsing et délègue la logique métier aux services.

use std::borrow::Cow;

use axum::{
    body::Body,
    extract::{Extension, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::logging::LogEvent,
    application::metadata::{
        add_server_tags_with, clear_server_tags_with, remove_server_tags_with,
        set_server_description_with, set_server_tags_with,
    },
    domain::{ContainersSnapshot, DescribeError, ServerDescription, TagsBatch},
};

use super::{
    error::WebError,
    mark_response_no_store,
    security::{attach_session_cookie, AuthGuard},
    services::{
        build_history_series_response, build_host_logs_response, build_metrics_text,
        HistoryQueryParams, LogsQueryParams,
    },
    template::{render_containers_page, render_index, render_logs_page, render_updates_page},
    views::{ContainersViewModel, IndexViewModel, LogsViewModel, UpdatesViewModel},
    AppState,
};
use crate::application::web::csp::CspNonce;

#[derive(Deserialize)]
pub(super) struct DescriptionPayload {
    text: String,
}

#[derive(Serialize)]
struct DescriptionResponse {
    description: String,
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
struct ContainersApiResponse {
    age_ms: u64,
    containers: ContainersSnapshot,
}

pub(super) async fn logo_asset(State(state): State<AppState>) -> Response {
    state.logo().response()
}

pub(super) async fn index(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let vm = IndexViewModel {
        web_debug: state.web_debug(),
        csp_nonce: csp_nonce.as_str(),
    };
    let mut response = Html(render_index(&vm)).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    mark_response_no_store(response.headers_mut());
    response
}

pub(super) async fn updates_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();

    if !state.exposure().updates() {
        let message = "L'exposition des mises à jour est désactivée pour cette instance.";
        let vm = UpdatesViewModel {
            updates: None,
            message: Some(message),
            csp_nonce: csp_nonce.as_str(),
        };
        let html = render_updates_page(&vm);
        let mut response = Html(html).into_response();
        attach_session_cookie(response.headers_mut(), &session, &state);
        return response;
    }

    state.updates_cache().ensure_fresh().await;
    let updates = match state.updates_cache().peek_shared().await {
        Some(info) => Some(info),
        None => state.updates_cache().refresh_blocking_shared().await,
    };

    let vm = UpdatesViewModel {
        updates: updates.as_deref(),
        message: None,
        csp_nonce: csp_nonce.as_str(),
    };
    let html = render_updates_page(&vm);
    let mut response = Html(html).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    response
}

pub(super) async fn update_description(
    guard: AuthGuard,
    State(state): State<AppState>,
    Json(payload): Json<DescriptionPayload>,
) -> Result<Response, WebError> {
    let session = guard.into_session();
    let description = ServerDescription::try_from(payload.text.as_str())
        .map_err(|err| WebError::bad_request(err.to_string()))?;
    match set_server_description_with(&state.ctx(), description.as_ref()) {
        Ok(()) => {
            let mut response = (
                StatusCode::OK,
                Json(DescriptionResponse {
                    description: description.into_inner(),
                }),
            )
                .into_response();
            attach_session_cookie(response.headers_mut(), &session, &state);
            Ok(response)
        }
        Err(err) => {
            LogEvent::SystemError {
                location: Cow::Borrowed("web_description_update"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
            Err(WebError::internal(
                "Impossible d'enregistrer la description.",
            ))
        }
    }
}

pub(super) async fn update_tags(
    guard: AuthGuard,
    State(state): State<AppState>,
    Json(payload): Json<TagsPayload>,
) -> Result<Response, WebError> {
    let session = guard.into_session();
    let result = match payload.op {
        TagOperation::Clear => clear_server_tags_with(&state.ctx()).map(|_| Vec::new()),
        op => {
            let batch = TagsBatch::try_from(payload.tags)
                .map_err(|err| WebError::bad_request(err.to_string()))?;
            let tags = batch.into_strings();
            match op {
                TagOperation::Set => {
                    set_server_tags_with(&state.ctx(), tags.iter().map(|t| t.as_str()))
                }
                TagOperation::Add => {
                    add_server_tags_with(&state.ctx(), tags.iter().map(|t| t.as_str()))
                }
                TagOperation::Remove => {
                    remove_server_tags_with(&state.ctx(), tags.iter().map(|t| t.as_str()))
                }
                TagOperation::Clear => unreachable!("handled earlier"),
            }
        }
    };
    let mut response = match result {
        Ok(list) => (StatusCode::OK, Json(TagsResponse { tags: list.clone() })).into_response(),
        Err(DescribeError::System(msg)) => return Err(WebError::internal(msg)),
        Err(err) => return Err(WebError::internal(err.to_string())),
    };
    attach_session_cookie(response.headers_mut(), &session, &state);
    Ok(response)
}

pub(super) async fn history_series(
    State(state): State<AppState>,
    guard: AuthGuard,
    Query(query): Query<HistoryRequestQuery>,
) -> Result<impl IntoResponse, WebError> {
    let session = guard.into_session();
    let params = HistoryQueryParams {
        server: query.server,
        window: query.window,
        limit: query.limit,
        ip: session.ip().to_string(),
        token: session.token_key().to_string(),
    };
    let payload = build_history_series_response(&state, params).await?;
    let mut response = Json(payload).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    Ok(response)
}

pub(super) async fn containers_api(
    State(state): State<AppState>,
    guard: AuthGuard,
) -> Result<Response, WebError> {
    let session = guard.into_session();
    let mut response = match state.latest_snapshot() {
        Some(value) => {
            let Some(containers) = value.view.containers.as_ref() else {
                return Err(WebError::forbidden(
                    "Les conteneurs ne sont pas exposés ou non capturés.",
                ));
            };

            let age_ms = value
                .captured_at
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;

            (
                StatusCode::OK,
                Json(ContainersApiResponse {
                    age_ms,
                    containers: containers.clone(),
                }),
            )
                .into_response()
        }
        None => Err(WebError::service_unavailable(
            "Aucun snapshot disponible pour le moment.",
        ))?,
    };
    attach_session_cookie(response.headers_mut(), &session, &state);
    Ok(response)
}

pub(super) async fn metrics_export(State(state): State<AppState>, guard: AuthGuard) -> Response {
    let session = guard.into_session();
    let content_type = HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");
    let unavailable = "\
# HELP describe_me_up 1 if last snapshot is available
# TYPE describe_me_up gauge
describe_me_up 0
";

    let mut response = match state.latest_snapshot() {
        Some(cached) => {
            let age_secs = cached.captured_at.elapsed().as_secs();
            let payload = build_metrics_text(
                &cached.view,
                age_secs,
                state.runtime.extension_metrics.as_ref(),
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(payload))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        None => Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, content_type.clone())
            .body(Body::from(unavailable))
            .unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response()),
    };
    attach_session_cookie(response.headers_mut(), &session, &state);
    response
}

pub(super) async fn logs_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let vm = LogsViewModel {
        csp_nonce: csp_nonce.as_str(),
    };
    let mut response = Html(render_logs_page(&vm)).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    mark_response_no_store(response.headers_mut());
    response
}

pub(super) async fn containers_page(
    State(state): State<AppState>,
    guard: AuthGuard,
    Extension(csp_nonce): Extension<CspNonce>,
) -> impl IntoResponse {
    let session = guard.into_session();
    let vm = ContainersViewModel {
        csp_nonce: csp_nonce.as_str(),
    };
    let mut response = Html(render_containers_page(&vm)).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    mark_response_no_store(response.headers_mut());
    response
}

pub(super) async fn host_logs(
    State(state): State<AppState>,
    guard: AuthGuard,
    Query(query): Query<LogsRequestQuery>,
) -> Result<impl IntoResponse, WebError> {
    let page = build_host_logs_response(LogsQueryParams { lines: query.lines }).await?;
    let session = guard.into_session();
    let mut response = Json(page).into_response();
    attach_session_cookie(response.headers_mut(), &session, &state);
    Ok(response)
}
