use std::borrow::Cow;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(serde::Serialize)]
pub struct ApiErrorResponse {
    pub error: Cow<'static, str>,
}

pub fn json_error(status: StatusCode, msg: impl Into<Cow<'static, str>>) -> Response {
    (status, Json(ApiErrorResponse { error: msg.into() })).into_response()
}

#[derive(Debug, Clone)]
pub struct WebError {
    pub status: StatusCode,
    pub message: Cow<'static, str>,
}

impl WebError {
    pub fn new(status: StatusCode, msg: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }

    pub fn bad_request(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn forbidden(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    pub fn not_found(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }

    pub fn service_unavailable(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, msg)
    }

    pub fn internal(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        json_error(self.status, self.message)
    }
}
