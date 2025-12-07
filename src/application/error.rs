use std::borrow::Cow;

#[derive(serde::Serialize)]
pub struct ErrorBody {
    pub error: Cow<'static, str>,
}

pub fn serialize_error_body(body: ErrorBody) -> String {
    serde_json::to_string(&body).unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.into())
}
